"""Build deployment plans and API views without coupling them to FastAPI routes."""

from __future__ import annotations

import json
import re
from pathlib import Path

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..models import DeployStatus, Deployment, DeploymentPortReservation, Node, Project, ProjectReplica, SourceType, User
from ..schemas import DeploymentOut
from .lifecycle import can_switch_to_release
from .logs import read_deployment_log
from .naming import deployment_compose_project_name, project_directory
from .pipeline_view import render_pipeline_steps
from .ports import choose_port
from .source_paths import git_source_location


def pipeline_steps(log_text: str, status: DeployStatus, selected_key: str | None = None, is_compose: bool = False) -> list[dict]:
    return render_pipeline_steps(log_text, status, selected_key, is_compose)

def make_deployment_plan(
    project: Project, node: Node, db: Session, reserved_host_port: int | None = None,
    *, allocate_port: bool = False,
) -> dict:
    root = Path(project.source_path) if project.source_path else None
    compose_names = ("compose.yaml", "compose.yml", "docker-compose.yml", "docker-compose.yaml")
    compose_file = next((name for name in compose_names if root and (root / name).exists()), None)
    is_compose = project.build_type == "compose" or (project.build_type == "auto" and bool(compose_file))
    container_port = project.container_port
    detected_from = "项目配置"
    if not container_port and root:
        dockerfile = root / "Dockerfile"
        if dockerfile.exists():
            match = re.search(r"(?im)^\s*EXPOSE\s+(\d+)", dockerfile.read_text(errors="ignore"))
            if match:
                container_port, detected_from = int(match.group(1)), "Dockerfile EXPOSE"
        if not container_port and (root / "package.json").exists():
            container_port, detected_from = 3000, "Node 项目默认值"
        elif not container_port and ((root / "requirements.txt").exists() or (root / "pyproject.toml").exists()):
            container_port, detected_from = 8000, "Python 项目默认值"
        elif not container_port and (root / "pom.xml").exists():
            container_port, detected_from = 8080, "Java 项目默认值"
        elif not container_port and (root / "index.html").exists():
            container_port, detected_from = 80, "静态站点默认值"
    host_port = None if is_compose else (
        reserved_host_port or project.host_port or (choose_port(db, None) if allocate_port else None)
    )
    address = node.public_address or node.host
    access_url = f"https://{project.domain}" if project.domain else (None if is_compose or not host_port else f"http://{address}:{host_port}")
    build_mode = "Docker Compose" if is_compose else ("Dockerfile" if project.build_type == "dockerfile" else "自动识别并生成 Dockerfile")
    git_url, git_branch, git_path = git_source_location(project.git_url or "", project.git_branch)
    repositories = project.git_repositories
    repository_details = [
        f"{row.get('role') or '源码'}：{row.get('git_url') or '未填写'} · {row.get('git_branch') or 'main'} → {row.get('target_dir') or row.get('role') or 'source'}"
        for row in repositories
    ]
    source_step = (
        {"title": "拉取多个 Git 源码", "detail": f"共 {len(repository_details)} 个仓库；" + "；".join(repository_details)}
        if repository_details else
        {"title": "拉取 Git 源码", "detail": f"从 {git_url or '已配置仓库'} 的 {git_branch or '默认'} 分支读取源码，项目目录为 {'/' + git_path if git_path else '仓库根目录（拉取后自动扫描）'}"}
        if project.source_type == SourceType.git else
        {"title": "读取上传源码", "detail": "读取用户已上传并保存到平台的项目文件，不访问 Git 仓库"}
    )
    if is_compose:
        execution_steps = [
            {"title": "识别 Compose", "detail": f"读取 {compose_file or 'Compose 配置'}，识别服务、依赖、端口和构建项"},
            {"title": "上传服务器", "detail": f"上传到 {node.work_dir.rstrip('/')}/{project_directory(project)}/版本号"},
            {"title": "拉取服务镜像", "detail": "只拉取 Compose 中直接引用的镜像，本地构建的服务进入下一步"},
            {"title": "构建应用服务", "detail": "构建 Compose 中带 build 的服务并记录每个服务的日志"},
            {"title": "启动全部服务", "detail": "按 Compose 依赖关系启动服务并应用环境变量、端口和重启策略"},
            {"title": "检查服务关系", "detail": "逐个核对容器状态、服务依赖和 Compose 对外端口"},
        ]
    else:
        execution_steps = [
            {"title": "识别项目", "detail": f"使用 {build_mode}，识别运行命令、容器端口和依赖"},
            {"title": "上传服务器", "detail": f"上传到 {node.work_dir.rstrip('/')}/{project_directory(project)}/版本号"},
            {"title": "拉取基础镜像", "detail": "解析 Dockerfile 的 FROM，并逐个拉取实际需要的基础镜像"},
            {"title": "构建应用镜像", "detail": "执行 Docker 构建，在镜像中安装项目依赖并保留完整日志"},
            {"title": "启动应用容器", "detail": f"使用已预留端口 {host_port} 启动容器并应用环境变量和重启策略"},
            {"title": "检查运行状态", "detail": "确认容器确实处于 running 状态后生成访问地址"},
        ]
    return {
        "project": project.name,
        "node": node.name,
        "node_address": address,
        "source": (
            f"{len(repository_details)} 个 Git 仓库"
            if repository_details else "Git 仓库"
        ) if project.source_type == SourceType.git else "已上传源码",
        "build_mode": build_mode,
        "container_port": container_port,
        "container_port_source": detected_from if container_port else "执行时继续识别",
        "host_port": host_port,
        "port_mode": "由 Compose 配置管理" if is_compose else ("已预留，不会分配给其他任务" if host_port else "部署时自动分配"),
        "source_repositories": repository_details,
        "access_url": access_url,
        "steps": [source_step, *execution_steps],
    }


def deployment_view(
    item: Deployment, db: Session, include_log: bool = True, stage: str | None = None,
    port_reservations: list[DeploymentPortReservation] | None = None,
    requester_by_id: dict[str, User] | None = None,
) -> dict:
    data = DeploymentOut.model_validate(item).model_dump()
    project, node = db.get(Project, item.project_id), db.get(Node, item.node_id)
    requester = (
        requester_by_id.get(item.requested_by)
        if requester_by_id is not None
        else db.get(User, item.requested_by)
    )
    database_log_text = item.log_text or ""
    log_text = database_log_text
    # The database value is deliberately a compact live window and can lose a
    # tail fragment when background diagnostics finish at the same time as the
    # deployment transaction.  The append-only file is the authoritative,
    # ordered source for detail pages and includes every stage boundary.
    if include_log:
        full_log_text = read_deployment_log(item.id)
        if full_log_text:
            log_text = full_log_text
    if item.status == DeployStatus.failed and item.error and item.error not in log_text:
        log_text = (log_text + "\n[失败] " + item.error).strip()
    # Rollback used to exist only as free-form log lines.  That made a release
    # which was activated by rollback indistinguishable from an ordinary
    # running release in collection views.  Expose the latest version switch
    # as structured metadata so both the history list and detail view can show
    # where the running version came from without loading the full log.
    # Runtime operations (start/stop/rollback) are appended to the database
    # window after the immutable pipeline log file has been written, so use
    # both sources when extracting lifecycle metadata for detail responses.
    lifecycle_log_text = database_log_text if log_text == database_log_text else f"{log_text}\n{database_log_text}"
    rollback_events: list[tuple[int, dict]] = []
    rollback_starts = list(re.finditer(
        r"\[回滚开始\]\s*正在从版本\s+([^\s，,。]+)\s+切换到\s+([^\s，,。]+)",
        lifecycle_log_text,
    ))
    if rollback_starts:
        rollback_start = rollback_starts[-1]
        rollback_complete_at = lifecycle_log_text.find("[回滚完成]", rollback_start.end())
        if rollback_complete_at >= 0:
            rollback_events.append((rollback_complete_at, {
                "kind": "rollback_target",
                "from_release": rollback_start.group(1),
                "to_release": rollback_start.group(2),
            }))
    rollback_sources = list(re.finditer(
        r"\[版本切换\]\s*已回滚至版本\s+([^。\r\n]+)",
        lifecycle_log_text,
    ))
    if rollback_sources:
        rollback_source = rollback_sources[-1]
        rollback_events.append((rollback_source.start(), {
            "kind": "rollback_source",
            "from_release": item.release,
            "to_release": rollback_source.group(1).strip(),
        }))
    rollback_transition = max(rollback_events, key=lambda event: event[0])[1] if rollback_events else None
    # Auto-repair metadata is assembled before the progress parser below.
    # A freshly running repair may not have emitted a stage marker yet, so it
    # still needs a valid status label instead of raising UnboundLocalError.
    current_step = "修复任务正在执行"
    auto_repair = None
    if include_log and (str(item.trigger or "").startswith("ai_autofix_") or "[修复问题]" in lifecycle_log_text):
        def latest_marker(name: str) -> str:
            matches = re.findall(rf"(?m)^\[{re.escape(name)}\]\s*(.+?)\s*$", lifecycle_log_text)
            return matches[-1].strip() if matches else ""

        problem = latest_marker("修复问题")
        source_match = re.search(r"\[AI自动修复\].*?任务\s+([0-9a-f]{8})", lifecycle_log_text)
        change_rows = [row.strip() for row in re.findall(
            r"(?m)^\[(?:修复变更|识别|配置预检)\]\s*(.+?)\s*$",
            lifecycle_log_text,
        ) if any(word in row for word in ("修复", "调整", "修改", "变化"))]
        if "[AI自动修复] 构建前变化校验通过：" in lifecycle_log_text:
            verified = re.findall(r"(?m)^\[AI自动修复\]\s*构建前变化校验通过：(.+?)\s*$", lifecycle_log_text)
            if verified:
                change_rows.insert(0, verified[-1].strip())
        change_rows = list(dict.fromkeys(change_rows))[-8:]
        if item.status == DeployStatus.success:
            verification = "修复后的版本已完成构建、启动和访问验证"
        elif item.status == DeployStatus.failed:
            verification = "修复后仍未通过验证，平台已保留新的失败证据"
        elif item.status == DeployStatus.running:
            verification = current_step
        elif item.status == DeployStatus.queued:
            verification = "修复任务已创建，正在等待执行"
        else:
            verification = "修复验证已停止"
        auto_repair = {
            "active": True,
            "attempt": int(str(item.trigger).rsplit("_", 1)[-1]) if str(item.trigger).rsplit("_", 1)[-1].isdigit() else None,
            "source_deployment": source_match.group(1) if source_match else None,
            "problem": problem or "平台正在从上一轮失败日志中提取具体问题",
            "changes": change_rows,
            "verification": verification,
            "has_verified_change": bool(change_rows),
        }
    stage_definitions = [
        (("方案",), 10, "正在读取方案"),
        (("准备", "源码", "依赖分析", "架构分析", "识别", "上传", "镜像"), 25, "正在准备运行环境"),
        (("构建", "平台构建", "AI构建"), 45, "正在构建应用"),
        (("启动",), 75, "正在启动服务"),
        (("检查", "完成"), 92, "正在验证访问"),
    ]
    if item.status == DeployStatus.queued:
        ahead = db.scalar(select(func.count()).select_from(Deployment).where(Deployment.status.in_([DeployStatus.queued, DeployStatus.running]), Deployment.created_at < item.created_at)) or 0
        progress, current_step = 5, (f"队列等待，前方 {ahead} 个任务" if ahead else "等待执行器领取任务")
    elif item.status == DeployStatus.success:
        progress, current_step = 100, "部署完成，服务运行中"
    elif item.status == DeployStatus.failed:
        progress, current_step = 100, "部署失败"
    elif item.status == DeployStatus.stopped:
        progress, stopped_stage = 10, "准备部署"
        for tags, stage_progress, label in stage_definitions:
            if any(f"[{tag}]" in log_text for tag in tags):
                progress, stopped_stage = stage_progress, label.replace("正在", "")
        current_step = f"已停止（停在{stopped_stage}）"
    else:
        progress, current_step = 10, "正在启动部署流程"
        latest_stage = None
        for tags, stage_progress, label in stage_definitions:
            position = max((log_text.rfind(f"[{tag}]") for tag in tags), default=-1)
            if position >= 0 and (latest_stage is None or position > latest_stage[0]):
                latest_stage = (position, stage_progress, label)
        if latest_stage:
            _, progress, current_step = latest_stage
        lower = log_text.lower()
        queue_position = log_text.rfind("[构建队列]")
        package_position = max(
            log_text.rfind("[镜像封装]"),
            log_text.rfind("[平台构建]"),
        )
        build_stage_position = log_text.rfind("[阶段开始] build")
        start_stage_position = max(
            log_text.rfind("[阶段开始] start"),
            log_text.rfind("[启动]"),
        )
        verify_stage_position = max(
            log_text.rfind("[阶段开始] verify"),
            log_text.rfind("[检查]"),
            log_text.rfind("[完成]"),
        )
        later_stage_position = max(start_stage_position, verify_stage_position)
        packaging_is_active = build_stage_position > later_stage_position
        # Explicit pipeline boundaries are more reliable than incidental
        # Chinese/Docker log words.  Use them first so a real build never sits
        # at 10% until the first image-packaging message appears.
        analyze_started = log_text.rfind("[阶段开始] analyze")
        prepare_started = log_text.rfind("[阶段开始] prepare")
        if verify_stage_position >= 0:
            progress, current_step = 90, "正在验证访问"
        elif start_stage_position >= 0:
            progress, current_step = 75, "正在启动服务"
        elif build_stage_position >= 0:
            channel_started = set(re.findall(
                r"(?m)^\[构建通道\]\s+([^|\s]+)\|[^|]+\|开始\|", log_text
            ))
            channel_done = set(re.findall(
                r"(?m)^\[构建通道\]\s+([^|\s]+)\|[^|]+\|(?:完成|失败)\|", log_text
            ))
            if channel_started:
                progress = 35 + round(20 * len(channel_done) / len(channel_started))
            else:
                progress = 35
            current_step = "正在并发构建应用"
        elif prepare_started >= 0:
            progress, current_step = 22, "正在准备运行环境"
        elif analyze_started >= 0:
            progress, current_step = 10, "正在读取并校验方案"
        # Older workers and a few recovery paths do not emit an explicit
        # ``[阶段开始] build`` boundary.  Derive the same monotonic progress
        # from real compiler/package completion events instead of leaving the
        # deployment card at 25% for several minutes.
        compiler_started = any(marker in log_text for marker in (
            "[并发构建]", "[平台构建]", "[构建通道]", "[即时封装]", "[构建:web]", "[构建:api]",
        )) or bool(re.search(r"\[构建:[^\]]+\]", log_text))
        compiler_done = {
            role for role, marker in (
                ("api", "Maven 已使用公共缓存"),
                ("api", "后端产物已由并发 Maven 构建生成"),
                ("web", "Node 已使用默认公共缓存生成运行产物"),
                ("web", "前端产物已生成"),
            ) if marker in log_text
        }
        eager_started = set(re.findall(r"\[即时封装\]\s+([^\s]+)\s+构建产物已就绪", log_text))
        eager_done = set(re.findall(r"\[即时封装\]\s+([^\s]+)\s+运行镜像已完成", log_text))
        if later_stage_position < 0 and compiler_started:
            progress = max(progress, 32 + 9 * len(compiler_done))
            current_step = "正在并发构建应用"
            if eager_started:
                progress = max(progress, 52 + 8 * len(eager_done))
                current_step = "正在封装运行镜像"
        if packaging_is_active and queue_position > package_position:
            progress, current_step = 55, "依赖编译完成，排队封装镜像"
        elif packaging_is_active and package_position >= 0:
            package_matches = re.findall(r"\[镜像封装\]\s*服务\s+(\d+)/(\d+)", log_text)
            if package_matches:
                package_index, package_total = map(int, package_matches[-1])
                progress = 58 + round(12 * max(0, package_index - 1) / max(1, package_total))
            else:
                progress = 58
            current_step = "正在封装运行镜像"
        elif log_text.rfind("[数据服务检查]") > log_text.rfind("[启动] 使用平台构建镜像"):
            progress, current_step = 72, "正在检查数据服务"
        elif progress == 10 and any(word in lower for word in ("load build definition", "building", "docker:default", "transferring context")):
            progress, current_step = 45, "正在构建镜像并安装依赖"
        elif progress == 10 and any(word in lower for word in ("pulling", "pull complete", "downloading")):
            progress, current_step = 30, "正在拉取项目所需镜像"
    # Collection views only need the assigned ports. Rebuilding the complete
    # deployment plan for every row caused an N+1 query/CPU spike and returned
    # 100+ KB every few seconds on the project and history pages.
    plan = make_deployment_plan(project, node, db, item.host_port) if include_log and project and node else (
        {"container_port": project.container_port, "host_port": item.host_port} if project else None
    )
    image_states = {}
    if include_log:
        for image_name, image_status in re.findall(r"(?m)^\[镜像项\]\s*(.+?)\|(pulling|ready|local|failed)\s*$", log_text):
            image_states[image_name.strip()] = image_status
    login_info = None
    login_payload = item.login_info_json
    if not login_payload:
        login_matches = re.findall(r"(?m)^\[登录信息\]\s*(\{.*\})\s*$", log_text)
        login_payload = login_matches[-1] if login_matches else None
    if include_log and login_payload:
        try:
            login_info = json.loads(login_payload)
            path = str(login_info.get("login_url_path") or "/")
            if item.access_url:
                login_info["login_url"] = item.access_url.rstrip("/") + "/" + path.lstrip("/")
        except (TypeError, ValueError, json.JSONDecodeError):
            login_info = None
    replica_rows = db.scalars(select(ProjectReplica).where(
        ProjectReplica.deployment_id == item.id,
        ProjectReplica.status == "running",
    ).order_by(ProjectReplica.created_at)).all() if include_log else []
    if port_reservations is None:
        port_reservations = db.scalars(select(DeploymentPortReservation).where(
            DeploymentPortReservation.deployment_id == item.id,
            DeploymentPortReservation.status.in_(["reserved", "active"]),
        ).order_by(DeploymentPortReservation.created_at)).all()
    service_ports = [{"service": row.service_name, "port": row.host_port, "status": row.status}
                     for row in port_reservations if row.service_name != "__gateway__"]
    internal_instances = []
    if node and item.host_port:
        internal_instances.append({
            "name": item.container_name or f"yz-{project.slug if project else item.project_id[:8]}",
            "url": f"http://{node.host}:{item.host_port}", "port": item.host_port, "primary": True,
        })
        internal_instances.extend({
            "name": replica.container_name, "url": f"http://{node.host}:{replica.host_port}",
            "port": replica.host_port, "primary": False,
        } for replica in replica_rows)
    data.update({
        "project_name": project.name if project else "未知项目",
        "project_slug": project.slug if project else "",
        "project_domain": project.domain if project else None,
        "node_name": node.name if node else "未知节点",
        "node_address": node.host if node else "",
        "requested_by_username": requester.username if requester else None,
        "requested_by_display_name": (requester.display_name or requester.username) if requester else None,
        "progress": progress,
        "current_step": current_step,
        "pipeline_steps": pipeline_steps(log_text, DeployStatus.success if "[完成]" in log_text else item.status, stage, bool(plan and plan["build_mode"] == "Docker Compose")) if include_log else [],
        "deployment_plan": plan,
        "image_items": [{"name": name, "status": state} for name, state in image_states.items()],
        "node_access_url": (f"http://{node.host}:{item.host_port}" if node and item.host_port else None),
        "internal_instances": internal_instances,
        "service_ports": service_ports,
        "ready_replicas": len(internal_instances) if item.status == DeployStatus.success else 0,
        "platform_access_url": item.access_url,
        "login_info": login_info,
        "rollback_transition": rollback_transition,
        "auto_repair": auto_repair,
        "rollback_allowed": can_switch_to_release(item),
    })
    data["log_text"] = ""
    return data


