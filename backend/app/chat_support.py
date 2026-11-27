from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import ChatSession, DeployStatus, Deployment, Project


_ACTIVE_ANALYSIS_STATES = {"queued", "running"}
_ACTIVE_DEPLOYMENT_STATES = {DeployStatus.queued, DeployStatus.running}


def session_task_state(db: Session, session: ChatSession, latest_action: str | None) -> tuple[bool, str]:
    """Return the visible task state for one chat without trusting its last message alone."""
    if not session.project_id:
        return False, ""
    project = db.get(Project, session.project_id)
    analysis = project.source_analysis if project else None
    analysis_running = str((analysis or {}).get("status") or "").lower() in _ACTIVE_ANALYSIS_STATES
    deployment_running = bool(db.scalar(select(Deployment.id).where(
        Deployment.project_id == session.project_id,
        Deployment.status.in_(_ACTIVE_DEPLOYMENT_STATES),
    ).limit(1)))
    workflow_running = bool(
        latest_action
        and latest_action.startswith("workflow_")
        and not latest_action.startswith(("workflow_success", "workflow_failed"))
    )
    if not (analysis_running or deployment_running or workflow_running):
        return False, ""
    latest_session_id = db.scalar(select(ChatSession.id).where(
        ChatSession.project_id == session.project_id,
        ChatSession.archived.is_(False),
    ).order_by(ChatSession.updated_at.desc()).limit(1))
    if not workflow_running and latest_session_id != session.id:
        return False, ""
    if analysis_running and not deployment_running:
        return True, "正在分析"
    return True, "正在执行任务"


def format_failure_diagnosis(project_name: str, node_name: str, release: str | None, diagnosis: dict) -> str:
    scope_labels = {
        "platform": "平台问题",
        "dependency_network": "依赖网络问题",
        "source": "项目代码问题",
        "configuration": "环境配置问题",
        "credentials": "凭据问题",
        "runtime": "运行环境问题",
        "server": "服务器资源问题",
        "unknown": "尚未确定",
    }
    evidence = next((str(item).strip() for item in diagnosis.get("evidence", []) if str(item).strip()), "")
    lines = [
        f"结论：“{project_name}”最近一次发布失败。",
        f"问题类型：{scope_labels.get(str(diagnosis.get('scope') or 'unknown'), '尚未确定')}。",
        f"失败原因：{str(diagnosis.get('summary') or '暂未提取到明确根因').strip()}",
    ]
    if evidence:
        lines.append(f"关键依据：{evidence[:500]}")
    lines.extend([
        f"服务器：{node_name}；版本：{release or '构建前失败'}。",
        f"下一步：{str(diagnosis.get('next_step') or diagnosis.get('advice') or '请查看完整日志后处理').strip()}",
    ])
    return "\n".join(lines)
