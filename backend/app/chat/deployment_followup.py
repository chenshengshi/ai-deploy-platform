"""Generate evidence-backed AI follow-up for an existing deployment."""

from __future__ import annotations

import hashlib
import json
import re
import shlex
from datetime import datetime, timezone

from fastapi import HTTPException
from sqlalchemy.orm import Session

from ..ai import deployment_followup, reconcile_followup_live_state
from ..config import decrypt
from ..deployment.integrations import environment_values
from ..deployment.runtime_snapshot import runtime_snapshot
from ..deployment.view_service import deployment_view
from ..models import DeployStatus, Deployment, DeploymentSettings, Node, Project, User
from ..ssh import SSHNode

def deployment_ai_followup_service(item_id: str, db: Session, user: User):
    item = db.get(Deployment, item_id)
    if not item:
        raise HTTPException(404, "部署不存在")
    project = db.get(Project, item.project_id)
    node = db.get(Node, item.node_id)
    view = deployment_view(item, db)
    steps = view.get("pipeline_steps", [])
    active = next((x for x in steps if x["status"] in ("running", "failed", "stopped")), None) or (steps[-1] if steps else {"title": view["current_step"], "log": ""})
    live = None
    if item.status in (DeployStatus.running, DeployStatus.success, DeployStatus.stopped):
        try:
            live = runtime_snapshot(item, db)
        except Exception:
            live = None
    live_states = ",".join(sorted(f"{x.get('name')}={x.get('status')}" for x in (live or {}).get("containers", [])))
    data_service_evidence = ""
    initial_evidence = active.get("log", "") + "\n" + (item.error or "")
    if item.status == DeployStatus.failed and re.search(
        r"PipeTimeout|数据服务检查|项目级数据服务|MySQL/Redis",
        initial_evidence,
        re.I,
    ):
        runtime_policy = db.get(DeploymentSettings, "default")
        runtime_namespace = (runtime_policy.registry_namespace if runtime_policy else "yunzhou") or "yunzhou"
        safe_namespace = re.sub(r"[^a-z0-9-]", "-", str(runtime_namespace).lower()).strip("-") or "yunzhou"
        data_project = f"{safe_namespace}-{project.slug}-data"
        try:
            with SSHNode(node) as ssh:
                _, data_service_evidence = ssh.run(
                    "ids=$(docker ps -aq --filter "
                    + shlex.quote(f"label=com.docker.compose.project={data_project}")
                    + "); for id in $ids; do "
                    + "printf '\n--- %s ---\n' \"$(docker inspect -f '{{.Name}} image={{.Config.Image}} state={{.State.Status}} health={{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' $id 2>/dev/null)\"; "
                    + "docker logs --tail 160 $id 2>&1; done",
                    timeout=45,
                )
        except Exception as exc:
            data_service_evidence = f"[数据服务实时诊断采集失败] {type(exc).__name__}"
    data_signature = hashlib.sha256(data_service_evidence.encode("utf-8", errors="ignore")).hexdigest()[:12] if data_service_evidence else "-"
    marker = "[AI跟进] "
    evidence = active.get("log", "") + ("\n[实时运行状态]\n" + json.dumps((live or {}).get("containers", []), ensure_ascii=False) if live is not None else "")
    if data_service_evidence:
        evidence += "\n[项目级数据服务实时日志]\n" + data_service_evidence[-12000:]
    combined_evidence = evidence + "\n" + (item.error or "")
    evidence_signature = hashlib.sha256(combined_evidence.encode("utf-8", errors="ignore")).hexdigest()[:12]
    # Include both evidence and the diagnosis policy version. A previously
    # cached generic AI answer must not hide a newer deterministic diagnosis.
    cache_key = f"diagnosis-v2|{item.status.value}|{active['title']}|{item.access_url or '-'}|{live_states}|{data_signature}|{evidence_signature}"
    project_values = environment_values(decrypt(project.env_text_encrypted) or "") if project else {}
    external_mysql_env_error = (
        project_values.get("YUNZHOU_MYSQL_MODE", "managed").lower() == "external"
        and bool(re.search(r"YUNZHOU_MYSQL_(?:HOST|PORT|DATABASE).*not set|项目级 MySQL 数据服务", combined_evidence, re.I | re.S))
    )
    access_verified = bool(re.search(r"访问验证通过：HTTP\s+2\d\d", combined_evidence, re.I))
    for line in reversed((item.log_text or "").splitlines()):
        if line.startswith(marker):
            try:
                cached = json.loads(line[len(marker):])
                if not external_mysql_env_error and not access_verified and cached.get("cache_key") == cache_key and cached.get("source") == "ai":
                    return cached
            except Exception:
                pass
            break
    # Platform interpreter errors are deterministic and must not be handed to
    # a language model that could guess a later stage such as "验证访问".
    # The pipeline parser above is the source of truth for the actual stage.
    platform_name_error = re.search(r"name ['\"]([^'\"]+)['\"] is not defined", combined_evidence, re.I)
    mysql_init_error = re.search(
        r"ERROR\s+(\d+)\s+\(([^)]+)\)(?:\s+at line\s+(\d+))?:\s*([^\r\n]+)",
        combined_evidence,
        re.I,
    )
    if mysql_init_error:
        error_code, sql_state, sql_line, sql_message = mysql_init_error.groups()
        location = f"第 {sql_line} 行" if sql_line else "初始化脚本"
        result = {
            "source": "system",
            "summary": f"已定位为 MySQL 初始化 SQL 错误：init.sql {location}执行失败（ERROR {error_code} / {sql_state}），因此平台停止创建应用容器。",
            "advice": f"修正该行 SQL 后拉取最新源码；由于当前数据卷可能只完成了部分初始化，需要确认无保留数据后重置该项目的新建数据库，再重新发布。错误内容：{sql_message[:300]}",
            "scope": "source",
            "confidence": "high",
            "evidence": [mysql_init_error.group(0)[:500]],
            "retry_safe": False,
            "fix_plan": ["修正 init.sql 中不兼容当前 MySQL 版本的语法", "确认后重置本次未完整初始化的数据卷", "拉取最新源码并重新发布，验证数据库、应用启动和访问地址"],
            "next_step": "源码已经修正后，先确认是否允许清空本次新建且未完整初始化的 CRM 数据卷，再重新发布。",
        }
    elif access_verified and item.status == DeployStatus.running:
        verified_url = re.search(r"访问验证通过：HTTP\s+2\d\d\s*[·，,]?\s*(https?://\S+)", combined_evidence, re.I)
        result = {
            "source": "system",
            "summary": "访问验证已通过，平台正在完成版本切换和成功状态提交。",
            "advice": "无需处理；该阶段通常只持续数秒，完成后会自动显示运行中和正式访问地址。",
            "fix_plan": [],
            "next_step": "等待平台提交成功状态并刷新项目卡片。" + (f" 已验证地址：{verified_url.group(1)}" if verified_url else ""),
            "scope": "platform",
            "confidence": "high",
            "retry_safe": False,
        }
    elif external_mysql_env_error:
        result = {
            "source": "system",
            "summary": "已确认不是用户漏填数据库配置，而是平台生成发布环境时提前展开了外接 MySQL 变量，导致已保存的值在 Compose 中变成空值。",
            "advice": "平台将调整环境变量生成顺序，先写入 MySQL 地址、端口、库名和账号，再生成应用连接串；发布前还会校验这些值已完整写入，并跳过项目内置 MySQL 的创建与健康检查。",
            "fix_plan": [
                "重新生成本次发布环境，保留项目已保存的外接 MySQL 配置",
                "校验外接数据库参数已注入 Compose，且不在日志中输出密码",
                "仅启动项目实际需要的 Redis 与应用服务",
            ],
            "next_step": "平台修复上线后重新发布当前源码，并依次验证数据库连接、容器健康和访问地址。",
            "scope": "platform",
            "confidence": "high",
            "retry_safe": True,
        }
    elif platform_name_error:
        variable = platform_name_error.group(1)
        result = {
            "source": "system",
            "summary": f"平台在“{active['title']}”阶段发生内部变量错误（{variable} 未定义），任务已失败；后续步骤未执行。",
            "advice": "这是平台程序问题，与项目源码、依赖、数据库和访问地址无关。修复平台后可直接重新发布。",
            "scope": "platform",
            "confidence": "high",
            "evidence": [f"name '{variable}' is not defined"],
            "retry_safe": False,
            "fix_plan": ["修复平台内部变量引用", "部署平台修复", "重新发布并验证原项目"],
            "next_step": "平台修复完成后重新发布；无需修改项目源码或数据库配置。",
        }
    elif re.search(r"COPY failed:.*(?:not found in build context|excluded by \.dockerignore)", combined_evidence, re.I | re.S):
        result = {
            "source": "system",
            "summary": "平台生成的 Dockerfile 引用了构建上下文之外的源码路径；源码文件本身存在，不需要用户补文件。",
            "advice": "平台会重新定位上传源码的真实根目录，校正 Dockerfile 的 COPY 相对路径后自动重新发布一次。",
            "scope": "platform",
            "confidence": "high",
            "retry_safe": True,
            "fix_plan": ["校正重复的上传目录包装层", "重新生成构建上下文", "重新发布并验证启动与访问"],
            "next_step": "平台正在自动校正构建上下文并重新发布，无需手工修改源码。",
        }
    else:
        try:
            result = deployment_followup(db, item, project, node, active["title"], evidence)
        except Exception as exc:
            lower = evidence.lower()
            if "jctree$jcimport" in lower and "qualid" in lower:
                summary = "已定位为 Java 编译环境不兼容：项目中的旧版编译器或注解处理器访问了 JDK 21 已变化的 javac 内部字段，sc-common 因此编译失败。"
                advice = "优先按项目原要求改用兼容的 JDK（常见为 8、11 或 17）；也可以升级 Lombok、Maven Compiler Plugin 等注解处理依赖后再用 JDK 21。平台仍会继续尝试调用 AI 给出项目化建议。"
            elif "non-resolvable" in lower or "could not resolve dependencies" in lower:
                summary = "构建失败在依赖解析阶段，Maven 未能取得项目所需依赖。"
                advice = "检查私有仓库凭据、镜像源和目标服务器网络；平台会继续调用 AI 分析具体依赖。"
            elif "compilation failure" in lower or "fatal error compiling" in lower:
                summary = "构建失败在源码编译阶段，已排除容器启动和端口问题。"
                advice = "需要根据最早的编译错误核对源码、JDK 与构建插件版本；平台会继续调用 AI 提炼具体修复项。"
            else:
                unresolved = re.search(r'Could not resolve\s+["\']([^"\']+)["\']\s+from\s+["\']([^"\']+)', evidence, re.I)
                if unresolved:
                    summary = f"构建时无法解析模块 {unresolved.group(1)}，引用位置为 {unresolved.group(2)}。"
                    advice = "平台将先核对生成的 Dockerfile 是否完整复制了跨目录依赖；若构建上下文完整，则归类为源码缺文件、路径或大小写问题，不会自动修改业务源码。"
                else:
                    summary = f"正在重新分析“{active['title']}”阶段的异常。"
                    advice = "AI 请求暂未完成，平台将在 15 秒后自动重试。"
            result = {"source": "system", "summary": summary, "advice": advice, "retryable": True, "retry_reason": str(exc)}
    if not result.get("fix_plan") and result.get("advice"):
        result["fix_plan"] = [str(result["advice"])]
    if not result.get("next_step"):
        result["next_step"] = (
            "平台正在继续分析并准备可验证的处理方案。"
            if item.status == DeployStatus.running
            else str(result.get("advice") or "按修复方案处理后重新发布，并由平台完成启动和访问验证。")
        )
    result, reconciled_stage = reconcile_followup_live_state(result, item, active["title"], combined_evidence)
    result.update({"cache_key": cache_key, "stage": reconciled_stage, "status": item.status.value, "generated_at": datetime.now(timezone.utc).isoformat()})
    if result.get("source") == "ai":
        item.log_text = ((item.log_text or "") + "\n" + marker + json.dumps(result, ensure_ascii=False) + "\n")[-200_000:]
        db.commit()
    return result


