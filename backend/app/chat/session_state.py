"""Derive visible AI-chat task state from persisted platform state."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import ChatSession, DeployStatus, Deployment, Project


_ACTIVE_ANALYSIS_STATES = {"queued", "running"}
_ACTIVE_DEPLOYMENT_STATES = {DeployStatus.queued, DeployStatus.running}


def session_task_state(db: Session, session: ChatSession, latest_action: str | None) -> tuple[bool, str]:
    """Return task animation state without trusting the latest message alone."""
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
