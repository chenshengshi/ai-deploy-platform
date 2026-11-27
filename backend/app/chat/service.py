"""AI conversation orchestration with explicit, injected platform actions."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import time
from datetime import datetime, timezone

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..ai import deployment_followup, understand
from ..audit import audit
from ..config import decrypt, encrypt
from ..deployment.runtime_snapshot import runtime_snapshot
from ..deployment.view_service import deployment_view, make_deployment_plan
from ..deployer import remove_project_managed_data_service
from ..models import AiConfig, ChatMessage, ChatSession, DeployStatus, Deployment, Node, Project, ProjectAccess, Role, User
from ..project_data.database_operations import _execute_project_data_change, _execute_project_migrations, _project_migration_plan, _query_project_database
from ..project_data.integration_analysis import _runtime_service_versions
from ..project_data.sql_safety import extract_direct_sql, is_high_risk_sql, sql_kind
from ..schemas import ChatIn, ChatOut
from .diagnostics import deployment_from_message_url, diagnose_blank_frontend
from .external_services import extract_external_mysql_config
from .intents import explicit_project_match, fallback_action_from_message, fuzzy_project_match, is_confirmation, normalize_message
from .responses import format_failure_diagnosis
from .sessions import chat_session_for_user
from .status_queries import asks_active_deployment_summary


def _user_can_access_project(db: Session, user: User, project_id: str) -> bool:
    if user.role == Role.admin:
        return True
    return bool(db.scalar(select(Project.id).where(
        Project.id == project_id,
        (Project.owner_id == user.id) | Project.id.in_(select(ProjectAccess.project_id).where(ProjectAccess.user_id == user.id)),
    )))

def chat_service(
    body: ChatIn,
    db: Session,
    user: User,
    *,
    restart_deployment_runtime,
    plan_log,
    require_reachable_node,
    rollback_deployment,
    start_stopped_deployment,
    stop_deployment_action,
    validate_external_integrations_for_deploy,
):
    chat_started = time.perf_counter()
    session = chat_session_for_user(db, body.session_id, user) if body.session_id else None
    requested_ai = db.get(AiConfig, body.ai_config_id) if body.ai_config_id else None
    if requested_ai and not requested_ai.enabled:
        requested_ai = None
    if not session:
        title = re.sub(r"\s+", " ", body.message).strip()[:48] or "新对话"
        initial_project = db.get(Project, body.project_id) if body.project_id else None
        if initial_project and not _user_can_access_project(db, user, initial_project.id):
            raise HTTPException(404, "项目不存在")
        initial_node = db.get(Node, body.node_id) if body.node_id else None
        session = ChatSession(
            owner_id=user.id,
            project_id=initial_project.id if initial_project else None,
            node_id=initial_node.id if initial_node else None,
            ai_config_id=requested_ai.id if requested_ai else None,
            title=title,
        )
        db.add(session)
        db.flush()
    elif session.archived:
        # Continuing an archived conversation is an explicit restore action.
        session.archived = False
    if requested_ai:
        session.ai_config_id = requested_ai.id
    stored_history = db.scalars(
        select(ChatMessage)
        .where(ChatMessage.session_id == session.id)
        .order_by(ChatMessage.created_at.desc())
        .limit(12)
    ).all()
    ai_history = [
        {"role": item.role, "content": item.content}
        for item in reversed(stored_history)
        if item.role in ("user", "assistant")
    ]
    if not ai_history and body.history:
        ai_history = body.history[-10:]
    db.add(ChatMessage(session_id=session.id, role="user", content=body.message))
    session.updated_at = datetime.now(timezone.utc)
    db.commit()

    def respond(reply: str, *, deployment_id: str | None = None, action: str | None = None,
                project_id: str | None = None, node_id: str | None = None,
                intent: str | None = None) -> ChatOut:
        session.project_id = project_id if project_id and db.get(Project, project_id) else session.project_id
        session.node_id = node_id if node_id and db.get(Node, node_id) else session.node_id
        session.updated_at = datetime.now(timezone.utc)
        elapsed_ms = max(0, round((time.perf_counter() - chat_started) * 1000))
        assistant_message = ChatMessage(
            session_id=session.id,
            role="assistant",
            content=reply,
            action=action,
            deployment_id=deployment_id,
            elapsed_ms=elapsed_ms,
        )
        db.add(assistant_message)
        db.commit()
        return ChatOut(
            reply=reply, message_id=assistant_message.id,
            deployment_id=deployment_id, action=action,
            project_id=project_id, node_id=node_id, intent=intent,
            session_id=session.id, elapsed_ms=elapsed_ms,
        )

    # Platform state questions must come from the database, not from model
    # context. This keeps answers exact even in a new conversation and avoids
    # an LLM incorrectly claiming that no task information was supplied.
    if asks_active_deployment_summary(body.message):
        active_items = db.scalars(
            select(Deployment)
            .where(Deployment.status.in_([DeployStatus.queued, DeployStatus.running]))
            .order_by(Deployment.created_at.asc())
        ).all()
        active_items = [
            item for item in active_items
            if _user_can_access_project(db, user, item.project_id)
        ]
        if not active_items:
            return respond(
                "结论：当前没有正在执行或排队中的发布任务。",
                action="status", intent="active_deployments",
            )
        project_names = {
            item.id: item.name for item in db.scalars(
                select(Project).where(Project.id.in_({row.project_id for row in active_items}))
            ).all()
        }
        lines = [f"结论：当前共有 {len(active_items)} 个正在执行或排队中的发布任务。"]
        for item in active_items:
            status_text = "正在执行" if item.status == DeployStatus.running else "排队中"
            progress = f"，进度 {int(item.progress or 0)}%" if item.status == DeployStatus.running else ""
            lines.append(
                f"- {project_names.get(item.project_id, item.project_id)}：{status_text}{progress}，版本 {item.release or '待生成'}"
            )
        return respond(
            "\n".join(lines), action="status", intent="active_deployments",
        )

    direct_sql = extract_direct_sql(body.message)
    try:
        decision = ({
            "action": "answer", "project_id": body.project_id or session.project_id,
            "node_id": body.node_id or session.node_id, "reply": "",
        } if direct_sql else understand(db, body.message, body.project_id or session.project_id, body.node_id or session.node_id, session.ai_config_id, ai_history))
    except Exception as exc:
        # Keep the assistant usable when the configured model is temporarily
        # unavailable.  Fuzzy matching is deliberately limited to known,
        # confirmation-gated platform actions; project/node selection and the
        # current chat context are still resolved below in the normal flow.
        fallback_action = fallback_action_from_message(body.message)
        if fallback_action == "none":
            return respond(
                f"AI 服务调用失败：{exc}\n本次错误已保存到对话历史，请稍后重试。",
                action="ai_error", project_id=body.project_id or session.project_id,
                node_id=body.node_id or session.node_id, intent=body.intent,
            )
        decision = {
            "action": fallback_action,
            "project_id": body.project_id or session.project_id,
            "node_id": body.node_id or session.node_id,
            "reply": "AI 暂时不可用，平台已结合当前对话和任务状态识别你的操作意图。",
        }
    projects = db.scalars(select(Project)).all()
    nodes = db.scalars(select(Node).where(Node.enabled.is_(True))).all()
    project_id = decision.get("project_id") or body.project_id
    node_id = decision.get("node_id") or body.node_id
    # Resolve a pasted public URL before fuzzy project-name matching.
    referenced_deployment = deployment_from_message_url(
        db,
        body.message,
        lambda candidate_project_id: _user_can_access_project(db, user, candidate_project_id),
    )
    if referenced_deployment:
        project_id = referenced_deployment.project_id
        node_id = referenced_deployment.node_id
    if not db.get(Project, project_id) if project_id else False:
        project_id = None
    if not db.get(Node, node_id) if node_id else False:
        node_id = None
    project_match = explicit_project_match(projects, body.message)
    node_match = next((x for x in nodes if x.name in body.message), None)
    project_id = project_match.id if project_match else project_id
    node_id = node_match.id if node_match else node_id
    normalized = normalize_message(body.message)
    external_mysql_changes = extract_external_mysql_config(body.message)
    cleanup_managed_mysql = bool(
        external_mysql_changes
        and any(word in body.message for word in ("清理", "删除", "移除"))
        and any(word in body.message for word in ("托管", "创建", "额外", "数据卷", "数据券"))
    )
    if external_mysql_changes:
        decision = {
            **decision,
            "action": "configure",
            "config_changes": external_mysql_changes,
            "project_id": project_id,
            "node_id": node_id,
        }
    # Model semantics and the explicitly associated project remain the primary
    # signals.  If neither resolved a project, tolerate one-character typos in
    # conversational names (for example “仓除” -> “仓储系统”).  This only
    # selects the target for a confirmation prompt; it never executes an
    # operation without the existing second confirmation.
    if not project_id and projects:
        fuzzy_project = fuzzy_project_match(projects, body.message)
        project_id = fuzzy_project.id if fuzzy_project else None
    confirmed = is_confirmation(body.message)
    repair_frontend_deployment_id = (
        body.intent.split(":", 1)[1]
        if body.intent and body.intent.startswith("repair_frontend_path:")
        else None
    )
    if repair_frontend_deployment_id and confirmed:
        source_deployment = db.get(Deployment, repair_frontend_deployment_id)
        target = db.get(Project, source_deployment.project_id) if source_deployment else None
        target_node = db.get(Node, source_deployment.node_id) if source_deployment else None
        if not source_deployment or not target or not target_node or not _user_can_access_project(db, user, target.id):
            raise HTTPException(409, "待修复的项目版本已经变化，请重新诊断")
        active = db.scalar(select(Deployment).where(
            Deployment.project_id == target.id,
            Deployment.node_id == target_node.id,
            Deployment.status.in_([DeployStatus.queued, DeployStatus.running]),
        ).order_by(Deployment.created_at.desc()))
        if active:
            return respond(
                f"“{target.name}”已有进行中的发布任务，平台不会重复创建。",
                deployment_id=active.id, action="existing_deployment",
                project_id=target.id, node_id=target_node.id, intent=None,
            )
        plan = make_deployment_plan(target, target_node, db, allocate_port=True)
        item = Deployment(
            project_id=target.id, node_id=target_node.id, requested_by=user.id,
            status=DeployStatus.queued, trigger="ai_autofix_1", host_port=plan["host_port"],
            log_text=plan_log(plan) + "[修复问题] frontend_public_base_mismatch：前端静态资源基础路径与平台根路径不一致\n",
        )
        db.add(item)
        db.flush()
        audit(db, user, "ai_repair_and_deploy", "deployment", item.id, "frontend_public_base_mismatch")
        db.commit()
        return respond(
            f"已开始修复“{target.name}”的项目工作区并重新发布；验证成功后会保留本次修改记录。",
            deployment_id=item.id, action="repair_deploy", project_id=target.id,
            node_id=target_node.id, intent=None,
        )
    delete_intent_id = body.intent.split(":", 1)[1] if body.intent and body.intent.startswith("delete:") else None
    wants_delete = (
        decision.get("action") == "delete_project"
        or delete_intent_id is not None
        or any(phrase in normalized for phrase in ("删除项目", "删掉项目", "移除项目", "删除这个项目", "删掉这个项目"))
    )
    if wants_delete:
        target = db.get(Project, delete_intent_id or project_id) if (delete_intent_id or project_id) else None
        if not target:
            return respond(
                "请先选择或告诉我要删除的项目。平台不会仅凭模糊名称执行删除。",
                action="none", project_id=project_id, node_id=node_id, intent="delete",
            )
        return respond(
            f"尚未删除“{target.name}”。请点击下方“查看并确认删除”，核对容器、镜像、发布目录和数据卷后再决定。",
            action="confirm_delete_project", project_id=target.id, node_id=node_id,
            intent=f"delete:{target.id}",
        )
    if direct_sql:
        target = db.get(Project, project_id) if project_id else None
        if not target:
            return respond("请先关联要查询或修改数据库的项目，再发送 SQL。", action="none", project_id=project_id, node_id=node_id, intent=None)
        kind = sql_kind(direct_sql)
        if kind == "query":
            try:
                result = _query_project_database(target, direct_sql, db, user, session.id)
            except HTTPException as exc:
                audit(db, user, "ai_query_database", "project", target.id, json.dumps({
                    "status": "failed", "sql": direct_sql,
                    "sha256": hashlib.sha256(direct_sql.encode()).hexdigest(),
                    "error": str(exc.detail)[:1000], "chat_session_id": session.id,
                    "requested_via": "AI 对话",
                }, ensure_ascii=False))
                db.commit()
                raise
            content = "\n".join(result["lines"]) or "（查询成功，没有返回数据）"
            suffix = "\n结果较多，已截取前 100 行。" if result["truncated"] else ""
            return respond(
                f"结论：已在“{target.name}”的 {result['engine']} 数据库执行只读查询。\n"
                f"查询结果：{result['row_count']} 行 · {result['column_count']} 列\n"
                f"```table\n{content}\n```{suffix}",
                action="queried_database", project_id=target.id, node_id=node_id, intent=None,
            )
        if kind == "schema":
            digest = hashlib.sha256(direct_sql.encode()).hexdigest()
            risk = "high" if is_high_risk_sql(direct_sql) else "low"
            expected = [{
                "path": f"AI 直接 SQL {digest[:8]}", "sha256": digest,
                "risk": risk, "sql": direct_sql,
            }]
            payload = base64.urlsafe_b64encode(json.dumps({
                "project_id": target.id, "node_id": node_id, "files": expected,
            }, ensure_ascii=False).encode()).decode()
            confirmation = "确认执行高风险表结构" if risk == "high" else "确认执行表结构"
            return respond(
                f"结论：已接收你提供的表结构 SQL，平台不会改写内容。\n"
                f"风险：{'高风险（包含删除或清空操作）' if risk == 'high' else '常规表结构变更'}。\n"
                f"SQL 校验值：{digest[:12]}\n下一步：回复“{confirmation}”，平台将先备份当前表结构，再原样执行。",
                action="confirm_migration", project_id=target.id, node_id=node_id,
                intent="migrate:" + payload,
            )
        if kind == "data_change":
            digest = hashlib.sha256(direct_sql.encode()).hexdigest()
            operation = direct_sql.lstrip().split(None, 1)[0].upper()
            high_risk = bool(operation in {"UPDATE", "DELETE"} and not re.search(r"(?i)\bwhere\b", direct_sql))
            payload = base64.urlsafe_b64encode(json.dumps({
                "project_id": target.id, "node_id": node_id, "sql": direct_sql,
                "sha256": digest, "high_risk": high_risk,
            }, ensure_ascii=False).encode()).decode()
            confirmation = "确认执行高风险数据变更" if high_risk else "确认执行数据变更"
            return respond(
                f"结论：已识别到一条 {operation} 数据变更语句，将在“{target.name}”数据库中执行。\n"
                f"风险：{'高风险，语句没有 WHERE 条件，可能影响整张表。' if high_risk else '执行前需要你明确确认。'}\n"
                f"SQL 校验值：{digest[:12]}\n下一步：回复“{confirmation}”后执行；结果会写入操作记录。",
                action="confirm_data_change", project_id=target.id, node_id=node_id, intent="datachange:" + payload,
            )
        return respond("SQL 包含多语句混合操作或不受支持的命令，平台已拒绝执行。请一次只提交一类 SQL。", action="none", project_id=target.id, node_id=node_id, intent=None)
    migrate_payload = None
    if body.intent and body.intent.startswith("migrate:"):
        try:
            migrate_payload = json.loads(base64.urlsafe_b64decode(body.intent.split(":", 1)[1].encode()).decode())
        except Exception:
            migrate_payload = None
    if migrate_payload and confirmed:
        target = db.get(Project, migrate_payload.get("project_id"))
        expected = migrate_payload.get("files") or []
        if not target or not isinstance(expected, list):
            raise HTTPException(409, "待执行的表结构清单已失效，请重新发起")
        has_high_risk = any(item.get("risk") == "high" for item in expected)
        if has_high_risk and normalized != "确认执行高风险表结构":
            return respond(
                "检测到删除表、清空表或删除字段等高风险 SQL。请明确回复“确认执行高风险表结构”后平台才会继续。",
                action="confirm_high_risk_migration", project_id=target.id,
                node_id=migrate_payload.get("node_id"), intent=body.intent,
            )
        result = _execute_project_migrations(target, expected, db, user, session.id)
        files_text = "、".join(result["files"])
        return respond(
            f"结论：已完成“{target.name}”的表结构更新。\n关键依据：已先备份 {result['engine']} 表结构；成功执行 {len(result['files'])} 个迁移文件：{files_text}。\n执行结果和文件校验值已写入操作记录，后续不会重复执行同一版本。",
            action="migrated", project_id=target.id,
            node_id=migrate_payload.get("node_id"), intent=None,
        )
    data_change_payload = None
    if body.intent and body.intent.startswith("datachange:"):
        try:
            data_change_payload = json.loads(base64.urlsafe_b64decode(body.intent.split(":", 1)[1].encode()).decode())
        except Exception:
            data_change_payload = None
    if data_change_payload and confirmed:
        target = db.get(Project, data_change_payload.get("project_id"))
        sql = str(data_change_payload.get("sql") or "")
        digest = hashlib.sha256(sql.encode()).hexdigest()
        if not target or not sql or digest != data_change_payload.get("sha256"):
            raise HTTPException(409, "待执行的数据变更已失效，请重新发送 SQL")
        if data_change_payload.get("high_risk") and normalized != "确认执行高风险数据变更":
            return respond(
                "该语句没有 WHERE 条件，可能修改或删除整张表。请明确回复“确认执行高风险数据变更”后平台才会继续。",
                action="confirm_high_risk_data_change", project_id=target.id,
                node_id=data_change_payload.get("node_id"), intent=body.intent,
            )
        try:
            result = _execute_project_data_change(target, sql, db, user, session.id)
        except HTTPException as exc:
            audit(db, user, "ai_update_database", "project", target.id, json.dumps({
                "status": "failed", "sql": sql, "sha256": digest,
                "error": str(exc.detail)[:1000], "chat_session_id": session.id,
                "requested_via": "AI 对话",
            }, ensure_ascii=False))
            db.commit()
            raise
        return respond(
            f"结论：已在“{target.name}”的 {result['engine']} 数据库完成数据变更。\n"
            f"执行结果：{result['result']}\n说明：完整 SQL、操作人、时间和执行结果已写入操作记录。",
            action="updated_database", project_id=target.id,
            node_id=data_change_payload.get("node_id"), intent=None,
        )
    configure_payload = None
    if body.intent and body.intent.startswith("configure:"):
        try:
            configure_payload = json.loads(base64.urlsafe_b64decode(body.intent.split(":", 1)[1].encode()).decode())
        except Exception:
            configure_payload = None
    if configure_payload and confirmed:
        target = db.get(Project, configure_payload.get("project_id"))
        changes = configure_payload.get("changes") or {}
        if not target or not isinstance(changes, dict):
            raise HTTPException(400, "待应用的项目配置已失效")
        current_lines = (decrypt(target.env_text_encrypted) or "").splitlines()
        positions = {line.split("=", 1)[0].strip(): index for index, line in enumerate(current_lines) if "=" in line and not line.lstrip().startswith("#")}
        for key, value in changes.items():
            key = str(key).strip()
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,127}", key):
                raise HTTPException(400, f"配置名称不正确：{key}")
            line = f"{key}={value}"
            if key in positions:
                current_lines[positions[key]] = line
            else:
                current_lines.append(line)
        target.env_text_encrypted = encrypt("\n".join(current_lines).strip() + "\n")
        state = dict(target.source_analysis or {})
        if state.get("status") == "completed":
            state["runtime_services"] = _runtime_service_versions(
                target,
                state.get("deployment_plan") or {},
                db,
                state.get("workspace_path") or state.get("repository_cache_path"),
            )
            target.integration_analysis_json = json.dumps(state, ensure_ascii=False)
        audit(db, user, "ai_update_project_config", "project", target.id, detail=",".join(sorted(changes)))
        db.commit()
        cleanup_result = ""
        if configure_payload.get("cleanup_managed_mysql"):
            cleanup_node_id = configure_payload.get("node_id") or node_id
            cleanup_node = db.get(Node, cleanup_node_id) if cleanup_node_id else None
            if not cleanup_node:
                latest_deployment = db.scalar(select(Deployment).where(
                    Deployment.project_id == target.id,
                ).order_by(Deployment.created_at.desc()))
                cleanup_node = db.get(Node, latest_deployment.node_id) if latest_deployment else None
            if not cleanup_node:
                raise HTTPException(409, "已保存外接 MySQL 配置，但找不到原托管数据库所在服务器，未执行清理")
            cleanup_result = remove_project_managed_data_service(target, cleanup_node, "mysql", db)
            audit(db, user, "ai_remove_managed_mysql", "project", target.id, cleanup_result)
            db.commit()
        reply = f"已更新“{target.name}”的 {len(changes)} 项配置。"
        if cleanup_result:
            reply += f"\n清理结果：{cleanup_result}。"
        reply += "\n配置将在下一次发布或重新发布时生效；如需立即应用，请告诉我重新部署到哪个服务器。"
        return respond(reply, action="configured", project_id=target.id, node_id=(cleanup_node.id if cleanup_result else node_id), intent=None)
    if decision.get("action") == "configure":
        changes = decision.get("config_changes") or {}
        target = db.get(Project, project_id) if project_id else None
        if not target:
            return respond("请先选择要修改配置的项目。", action="none", project_id=project_id, node_id=node_id, intent="configure")
        if not isinstance(changes, dict) or not changes:
            return respond(decision.get("reply") or "请告诉我要修改的配置名称和值，例如：为这个项目设置 REDIS_HOST=192.168.1.20。", action="none", project_id=target.id, node_id=node_id, intent="configure")
        safe_changes = {str(key): str(value) for key, value in changes.items()}
        payload = base64.urlsafe_b64encode(json.dumps({
            "project_id": target.id,
            "node_id": node_id,
            "changes": safe_changes,
            "cleanup_managed_mysql": cleanup_managed_mysql,
        }, ensure_ascii=False).encode()).decode()
        secret_words = ("password", "secret", "token", "key")
        preview = "\n".join(f"- {key}={'******' if any(word in key.lower() for word in secret_words) else value}" for key, value in safe_changes.items())
        cleanup_preview = "\n确认后还会删除该项目原托管 MySQL 容器及其私有数据卷；不会删除 Redis、其他项目或外置数据库。" if cleanup_managed_mysql else ""
        return respond(f"准备修改“{target.name}”的项目配置：\n{preview}\n\n这些配置只会写入项目的加密配置，不会立即修改正在运行的容器。{cleanup_preview}\n回复“确认”后保存。", action="confirm_config", project_id=target.id, node_id=node_id, intent="configure:" + payload)
    wants_migrate = decision.get("action") == "migrate" or any(
        phrase in body.message for phrase in ("执行表结构", "更新表结构", "同步表结构", "应用迁移", "执行迁移", "更新数据库结构")
    )
    if wants_migrate:
        target = db.get(Project, project_id) if project_id else None
        if not target:
            return respond("请先选择要执行表结构更新的项目。", action="none", project_id=project_id, node_id=node_id, intent="migrate")
        plan = _project_migration_plan(target, db)
        pending = [item for item in plan["files"] if not item["applied"]]
        if not pending:
            return respond(
                f"结论：“{target.name}”当前没有待执行的 SQL 迁移文件。\n关键依据：线上版本中的迁移文件均已执行，或源码中没有发现 SQL 文件。",
                action="none", project_id=target.id, node_id=plan["node"].id, intent=None,
            )
        payload = base64.urlsafe_b64encode(json.dumps({
            "project_id": target.id, "node_id": plan["node"].id,
            "files": [{"path": item["path"], "sha256": item["sha256"], "risk": item["risk"]} for item in pending],
        }, ensure_ascii=False).encode()).decode()
        lines = []
        for item in pending[:20]:
            level = "高风险" if item["risk"] == "high" else "常规"
            lines.append(f"- {item['path']}（{item['statements']} 条语句，{level}）")
        if len(pending) > 20:
            lines.append(f"- 另有 {len(pending) - 20} 个文件")
        high_count = sum(1 for item in pending if item["risk"] == "high")
        confirmation = "确认执行高风险表结构" if high_count else "确认执行表结构"
        return respond(
            f"结论：已找到“{target.name}”待执行的 {len(pending)} 个表结构迁移文件。\n"
            + "\n".join(lines)
            + f"\n\n平台会先备份当前表结构，再按文件名顺序执行；文件变化时会自动中止。"
            + (f"其中 {high_count} 个包含删除或清空操作。" if high_count else "")
            + f"\n下一步：回复“{confirmation}”后执行。",
            action="confirm_migration", project_id=target.id, node_id=plan["node"].id,
            intent="migrate:" + payload,
        )
    stop_deployment_id = body.intent.split(":", 1)[1] if body.intent and body.intent.startswith("stop:") else None
    wants_stop = decision.get("action") == "stop" or any(word in body.message for word in ("停止部署", "暂停部署", "中止部署", "取消部署", "停掉部署"))
    if stop_deployment_id and confirmed:
        target_deployment = db.get(Deployment, stop_deployment_id)
        if not target_deployment or (project_id and target_deployment.project_id != project_id):
            raise HTTPException(409, "待停止的部署任务已经变化，请重新发起停止")
        if target_deployment.status not in (DeployStatus.queued, DeployStatus.running):
            return respond("结论：该部署任务已经结束，无需再次停止。", action="none", project_id=target_deployment.project_id, node_id=target_deployment.node_id, intent=None)
        result = stop_deployment_action(target_deployment.id, db, user)
        target_project = db.get(Project, target_deployment.project_id)
        return respond(
            f"结论：已停止“{target_project.name if target_project else '当前项目'}”的部署任务。\n关键依据：平台已终止构建/发布进程并完成残留检查。",
            deployment_id=target_deployment.id, action="stopped", project_id=target_deployment.project_id,
            node_id=target_deployment.node_id, intent=None,
        )
    if wants_stop:
        target_project = db.get(Project, project_id) if project_id else None
        if not target_project:
            return respond("结论：请先选择要停止部署的项目。", action="none", project_id=project_id, node_id=node_id, intent="stop")
        query = select(Deployment).where(
            Deployment.project_id == target_project.id,
            Deployment.status.in_([DeployStatus.queued, DeployStatus.running]),
        )
        if node_id:
            query = query.where(Deployment.node_id == node_id)
        target_deployment = db.scalar(query.order_by(Deployment.created_at.desc()))
        if not target_deployment:
            return respond(f"结论：“{target_project.name}”当前没有进行中的部署任务。", action="none", project_id=target_project.id, node_id=node_id, intent=None)
        target_node = db.get(Node, target_deployment.node_id)
        return respond(
            f"结论：可以停止“{target_project.name}”当前的部署任务。\n关键依据：任务位于 {target_node.name if target_node else '当前服务器'}，当前状态为部署中；停止后现有已上线版本会保留。\n下一步：回复“确认停止”后执行。",
            deployment_id=target_deployment.id, action="confirm_stop", project_id=target_project.id,
            node_id=target_deployment.node_id, intent=f"stop:{target_deployment.id}",
        )
    rollback_deployment_id = body.intent.split(":", 1)[1] if body.intent and body.intent.startswith("rollback:") else None
    wants_rollback = decision.get("action") == "rollback" or any(word in body.message for word in ("回滚", "上个版本", "上一版本", "历史版本", "恢复版本"))
    if rollback_deployment_id and confirmed:
        target_deployment = db.get(Deployment, rollback_deployment_id)
        if not target_deployment or (project_id and target_deployment.project_id != project_id):
            raise HTTPException(409, "待回滚的历史版本已经变化，请重新发起回滚")
        result = rollback_deployment(target_deployment.id, db, user)
        target_project = db.get(Project, target_deployment.project_id)
        return respond(
            f"结论：已将“{target_project.name if target_project else '当前项目'}”回滚到版本 {result['release']}。\n关键依据：平台复用了已验证镜像，完成服务切换并通过访问验证。\n访问地址：{result['access_url']}",
            deployment_id=target_deployment.id, action="rolled_back", project_id=target_deployment.project_id,
            node_id=target_deployment.node_id, intent=None,
        )
    if wants_rollback:
        target_project = db.get(Project, project_id) if project_id else None
        if not target_project:
            return respond("结论：请先选择要回滚的项目。", action="none", project_id=project_id, node_id=node_id, intent="rollback")
        current_query = select(Deployment).where(
            Deployment.project_id == target_project.id,
            Deployment.status == DeployStatus.success,
        )
        if node_id:
            current_query = current_query.where(Deployment.node_id == node_id)
        current_deployment = db.scalar(current_query.order_by(Deployment.created_at.desc()))
        if not current_deployment:
            return respond(f"结论：“{target_project.name}”当前没有在线版本，不能执行回滚；可以重新启用已验证版本。", action="none", project_id=target_project.id, node_id=node_id, intent=None)
        verified_markers = ("[完成] 部署成功", "[启用确认]", "[回滚完成]")
        candidates = db.scalars(select(Deployment).where(
            Deployment.project_id == target_project.id,
            Deployment.node_id == current_deployment.node_id,
            Deployment.id != current_deployment.id,
            Deployment.status == DeployStatus.stopped,
        ).order_by(Deployment.created_at.desc())).all()
        candidates = [item for item in candidates if item.release and item.access_url and any(marker in (item.log_text or "") for marker in verified_markers)]
        requested_release = next((item for item in candidates if item.release and item.release in body.message), None)
        target_deployment = requested_release or (candidates[0] if candidates else None)
        if not target_deployment:
            return respond(f"结论：“{target_project.name}”没有可回滚的已验证历史版本。\n关键依据：失败、构建中止或未通过访问验证的版本不会用于回滚。", action="none", project_id=target_project.id, node_id=current_deployment.node_id, intent=None)
        return respond(
            f"结论：可以将“{target_project.name}”从版本 {current_deployment.release or current_deployment.id[:8]} 回滚到 {target_deployment.release}。\n关键依据：目标是曾成功上线并通过访问验证的版本；平台将直接复用镜像，不重新构建，失败会自动恢复当前线上版本。\n下一步：回复“确认回滚”后执行。",
            deployment_id=target_deployment.id, action="confirm_rollback", project_id=target_project.id,
            node_id=current_deployment.node_id, intent=f"rollback:{target_deployment.id}",
        )
    restart_deployment_id = body.intent.split(":", 1)[1] if body.intent and body.intent.startswith("restart:") else None
    reenable_deployment_id = body.intent.split(":", 1)[1] if body.intent and body.intent.startswith("reenable:") else None
    wants_restart = decision.get("action") == "restart" or "重启" in body.message.lower() or any(word in body.message.lower() for word in ("restart", "重启 pod", "重启pod"))
    if reenable_deployment_id and confirmed:
        target_deployment = db.get(Deployment, reenable_deployment_id)
        if not target_deployment or (project_id and target_deployment.project_id != project_id):
            raise HTTPException(409, "待启用的运行版本已经变化，请重新发起")
        target_project = db.get(Project, target_deployment.project_id)
        target_node = db.get(Node, target_deployment.node_id)
        start_stopped_deployment(target_deployment.id, db, user)
        return respond(
            f"结论：已重新启用“{target_project.name if target_project else '当前项目'}”。\n"
            f"关键依据：平台复用了原发布版本，没有重新构建镜像；运行服务已恢复并通过启动检查。",
            action="reenabled", project_id=target_deployment.project_id,
            node_id=target_deployment.node_id, intent=None,
        )
    if restart_deployment_id and confirmed:
        target_deployment = db.get(Deployment, restart_deployment_id)
        if not target_deployment or (project_id and target_deployment.project_id != project_id):
            raise HTTPException(409, "待重启的运行版本已经变化，请重新发起重启")
        result = restart_deployment_runtime(target_deployment.id, "", db, user)
        target_project = db.get(Project, target_deployment.project_id)
        return respond(
            f"结论：{result['message']}。\n关键依据：平台已在目标服务器执行受控重启，并确认容器恢复运行。",
            action="restarted", project_id=target_deployment.project_id,
            node_id=target_deployment.node_id, intent=None,
        )
    if wants_restart:
        target_project = db.get(Project, project_id) if project_id else None
        if not target_project:
            return respond("结论：请先选择要重启的项目。", action="none", project_id=project_id, node_id=node_id, intent="restart")
        query = select(Deployment).where(
            Deployment.project_id == target_project.id,
            Deployment.status.in_([DeployStatus.success, DeployStatus.stopped]),
        )
        if node_id:
            query = query.where(Deployment.node_id == node_id)
        target_deployment = db.scalar(query.order_by(Deployment.created_at.desc()))
        if not target_deployment:
            return respond(f"结论：没有找到“{target_project.name}”可重启的运行版本。", action="none", project_id=target_project.id, node_id=node_id, intent=None)
        target_node = db.get(Node, target_deployment.node_id)
        snapshot = runtime_snapshot(target_deployment, db)
        containers = [str(row.get("name") or "") for row in snapshot.get("containers", []) if row.get("name")]
        if not containers:
            verified_markers = ("[完成] 部署成功", "[启用确认]", "[回滚完成]")
            can_reenable = (
                target_deployment.status == DeployStatus.stopped
                and bool(target_deployment.release and target_deployment.access_url)
                and any(marker in (target_deployment.log_text or "") for marker in verified_markers)
            )
            if can_reenable:
                return respond(
                    f"结论：“{target_project.name}”当前已停止，不能直接重启，但可以重新启用原版本。\n"
                    f"关键依据：目标服务器为 {target_node.name if target_node else '原服务器'}；平台将复用已验证版本 {target_deployment.release}，不重新构建镜像。\n"
                    "下一步：回复“确认重启”后，平台将按重新启用方式恢复服务。",
                    action="confirm_reenable", project_id=target_project.id,
                    node_id=target_deployment.node_id, intent=f"reenable:{target_deployment.id}",
                )
            return respond(f"结论：“{target_project.name}”当前没有可重启的运行容器。\n下一步：如需重新创建容器，请说“重新部署 {target_project.name}”。", action="none", project_id=target_project.id, node_id=target_deployment.node_id, intent=None)
        return respond(
            f"结论：可以重启“{target_project.name}”。\n关键依据：目标服务器为 {target_node.name if target_node else '当前服务器'}，将重启 {len(containers)} 个运行容器。\n下一步：回复“确认重启”后执行，服务会短暂中断，但不会重新构建镜像或覆盖配置。",
            action="confirm_restart", project_id=target_project.id,
            node_id=target_deployment.node_id, intent=f"restart:{target_deployment.id}",
        )
    status_words = (
        "状态", "怎么样", "正常", "成功了吗", "进度", "访问", "地址", "版本", "运行情况",
        "失败", "原因", "为什么", "为啥", "报错", "错误", "空白", "白屏", "打不开",
        "无法访问", "加载不出来", "页面没内容", "耗时", "多久", "服务器", "节点",
    )
    wants_project_status = (
        project_id
        and decision.get("action") in ("answer", "none", None, "")
        and any(word in body.message for word in status_words)
    )
    if wants_project_status:
        target_project = db.get(Project, project_id)
        recent = db.scalars(select(Deployment).where(
            Deployment.project_id == project_id,
        ).order_by(Deployment.created_at.desc()).limit(20)).all()
        active = next((item for item in recent if item.status in (DeployStatus.queued, DeployStatus.running)), None)
        online = next((item for item in recent if item.status == DeployStatus.success), None)
        latest = recent[0] if recent else None
        if not latest:
            return respond(
                f"结论：“{target_project.name}”还没有发布记录。\n下一步：选择目标服务器后，可以让我发布这个项目。",
                action="answer", project_id=project_id, node_id=node_id, intent=None,
            )
        asks_blank_page = any(word in body.message.lower() for word in (
            "空白", "白屏", "打不开", "无法访问", "加载不出来", "页面没内容", "blank page",
        ))
        if asks_blank_page:
            measured = (
                referenced_deployment
                if referenced_deployment and referenced_deployment.project_id == project_id
                and referenced_deployment.status == DeployStatus.success
                else online
            )
            if not measured or not measured.access_url:
                return respond(
                    f"结论：“{target_project.name}”目前没有可检测的成功版本访问地址。\n"
                    "下一步：请先完成一次发布，平台才能检查页面和静态资源。",
                    action="answer", project_id=project_id, node_id=node_id, intent=None,
                )
            measured_node = db.get(Node, measured.node_id)
            diagnostic_url = (
                f"http://{measured_node.host}:{int(measured.host_port)}"
                if measured_node and measured.host_port
                else measured.access_url
            )
            frontend_issue = diagnose_blank_frontend(diagnostic_url)
            if frontend_issue:
                evidence = frontend_issue["evidence"][0]
                working = evidence.get("working_path") or "未找到"
                return respond(
                    f"结论：“{target_project.name}”空白页的根因已确认，不是服务未启动。\n"
                    "问题类型：项目前端构建配置问题。\n"
                    f"关键依据：页面引用 {evidence['reference']}，请求返回 {evidence['content_type']}；"
                    f"去掉错误前缀后的资源 {working} 可以正常读取。\n"
                    f"根因：{frontend_issue['summary']}\n"
                    "下一步：可以让我直接修正项目工作区中的前端基础路径并重新发布；修改会记录并参与后续代码合并。",
                    deployment_id=measured.id, action="diagnose_frontend_path",
                    project_id=project_id, node_id=measured.node_id,
                    intent=f"repair_frontend_path:{measured.id}",
                )
            return respond(
                f"结论：“{target_project.name}”入口可访问，但平台没有发现 JS/CSS 返回 HTML 的基础路径错误。\n"
                "下一步：请查看浏览器控制台首条错误，平台会继续按具体资源或运行时错误诊断。",
                deployment_id=measured.id, action="answer", project_id=project_id,
                node_id=measured.node_id, intent=None,
            )
        asks_failure = any(word in body.message for word in ("失败", "原因", "为什么", "报错", "错误"))
        if asks_failure:
            failed = next((item for item in recent if item.status == DeployStatus.failed), None)
            if not failed:
                return respond(
                    f"结论：“{target_project.name}”最近没有失败的发布记录。\n"
                    f"当前状态：{'运行中' if online else ('正在部署' if active else '已停止')}。",
                    action="answer", project_id=project_id,
                    node_id=(online or active or latest).node_id, intent=None,
                )
            failed_node = db.get(Node, failed.node_id)
            try:
                # Keep chat answers identical to the deployment detail page.
                # The public follow-up path applies deterministic, high-confidence
                # rules (missing secrets, platform errors, SQL failures, etc.)
                # before asking the model.  Calling the model directly here used
                # to turn an exact ``AUTH_TOKEN_SECRET`` diagnosis into a generic
                # "runtime issue" and could encourage a pointless retry.
                diagnosis = deployment_ai_followup(failed.id, db, user)
            except Exception:
                diagnosis = {
                    "summary": (failed.error or "平台没有记录明确错误").strip().splitlines()[0][:500],
                    "scope": "unknown", "evidence": [],
                    "advice": "请查看完整发布日志后处理。",
                }
            return respond(
                format_failure_diagnosis(
                    target_project.name,
                    failed_node.name if failed_node else "服务器记录已移除",
                    failed.release,
                    diagnosis,
                ),
                deployment_id=failed.id, action="answer", project_id=project_id,
                node_id=failed.node_id, intent=None,
            )
        asks_duration = any(word in body.message for word in ("耗时", "多久", "多长时间"))
        if asks_duration:
            measured = active or latest
            started_at = measured.started_at or measured.created_at
            ended_at = measured.finished_at or datetime.now(timezone.utc)
            seconds = max(0, int((ended_at - started_at).total_seconds())) if started_at else 0
            duration_text = f"{seconds // 60}分{seconds % 60}秒" if seconds >= 60 else f"{seconds}秒"
            duration_state = "已用时" if measured.status in (DeployStatus.queued, DeployStatus.running) else "部署耗时"
            return respond(
                f"结论：“{target_project.name}”{duration_state} {duration_text}。\n"
                f"状态：{measured.status.value}；版本：{measured.release or '尚未生成'}。",
                deployment_id=measured.id, action="answer", project_id=project_id,
                node_id=measured.node_id, intent=None,
            )
        focus = active or online or latest
        target_node = db.get(Node, focus.node_id) if focus else None
        if active:
            view = deployment_view(active, db, include_log=False)
            return respond(
                f"结论：“{target_project.name}”正在部署，当前进度 {view.get('progress', 0)}%。\n"
                f"当前步骤：{view.get('current_step') or '正在处理'}。\n"
                f"目标服务器：{target_node.name if target_node else '服务器记录已移除'}。",
                deployment_id=active.id, action="answer", project_id=project_id,
                node_id=active.node_id, intent=None,
            )
        if online:
            extra = ""
            if latest.id != online.id and latest.status == DeployStatus.failed:
                extra = "\n说明：最近一次新版本发布失败，当前成功版本未被覆盖。"
            return respond(
                f"结论：“{target_project.name}”当前运行中。\n"
                f"服务器：{target_node.name if target_node else '服务器记录已移除'}；版本：{online.release or '未记录'}。\n"
                f"访问地址：{online.access_url or '尚未生成'}。{extra}",
                deployment_id=online.id, action="answer", project_id=project_id,
                node_id=online.node_id, intent=None,
            )
        status_label = {
            DeployStatus.failed: "最近一次发布失败",
            DeployStatus.stopped: "当前已停止",
            DeployStatus.queued: "正在等待部署",
            DeployStatus.running: "正在部署",
        }.get(latest.status, latest.status.value)
        error_hint = f"\n失败原因：{(latest.error or '').splitlines()[0][:240]}" if latest.status == DeployStatus.failed and latest.error else ""
        return respond(
            f"结论：“{target_project.name}”{status_label}。\n"
            f"服务器：{target_node.name if target_node else '服务器记录已移除'}；版本：{latest.release or '尚未生成'}。{error_hint}",
            deployment_id=latest.id, action="answer", project_id=project_id,
            node_id=latest.node_id, intent=None,
        )
    # A status question such as “部署成功了吗/发布用了多久” contains the
    # same nouns as an execution request.  Trust the model's explicit answer
    # intent first; only use keyword fallback when it could not classify the
    # message at all.
    fallback_deploy_request = (
        decision.get("action") in (None, "", "none")
        and any(x in body.message for x in ("帮我部署", "开始部署", "确认部署", "重新部署", "发布这个", "上线这个"))
    )
    wants_deploy = decision.get("action") == "deploy" or body.intent in ("deploy", "confirm") or fallback_deploy_request
    next_intent = body.intent
    if wants_deploy and (not project_id or not node_id):
        next_intent = "deploy"
        decision["action"] = "none"
        missing = "项目和目标服务器" if not project_id and not node_id else ("项目" if not project_id else "目标服务器")
        decision["reply"] = f"我已记住当前选择，还缺少{missing}。请直接选择或告诉我名称。"
    elif wants_deploy and project_id and node_id:
        # Deploy is a reversible, explicitly requested action. Once both
        # selections are known, enqueue it immediately; validation remains in
        # the controlled deployment pipeline and reports only real blockers.
        decision["action"] = "deploy"
        next_intent = None
    elif body.intent == "confirm" and confirmed and project_id and node_id:
        decision["action"] = "deploy"
        next_intent = None
    deployment_id = None
    if decision.get("action") == "deploy":
        project, node = db.get(Project, project_id), db.get(Node, node_id)
        if project and node:
            require_reachable_node(node, db)
            active = db.scalar(
                select(Deployment).where(
                    Deployment.project_id == project.id,
                    Deployment.node_id == node.id,
                    Deployment.status.in_([DeployStatus.queued, DeployStatus.running]),
                ).order_by(Deployment.created_at.desc())
            )
            if active:
                return respond(
                    f"该项目在此服务器已有进行中的部署任务 {active.id[:8]}，我没有重复创建。请等待完成或先停止原任务。",
                    deployment_id=active.id,
                    action="existing_deployment",
                    project_id=project.id,
                    node_id=node.id,
                    intent=None,
                )
            validate_external_integrations_for_deploy(project, node)
            plan = make_deployment_plan(project, node, db, allocate_port=True)
            item = Deployment(project_id=project.id, node_id=node.id, requested_by=user.id, status=DeployStatus.queued, trigger="ai", host_port=plan["host_port"], log_text=plan_log(plan))
            db.add(item)
            db.flush()
            deployment_id = item.id
            audit(db, user, "ai_deploy", "deployment", item.id, body.message)
            db.commit()
            decision["reply"] = f"已开始部署“{plan['project']}”到“{plan['node']}”，可查看实时进度。"
    return respond(decision.get("reply", "已处理"), deployment_id=deployment_id, action=decision.get("action"), project_id=project_id, node_id=node_id, intent=next_intent)

