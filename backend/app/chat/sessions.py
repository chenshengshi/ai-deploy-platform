"""Chat-session access control and API projection helpers."""

from __future__ import annotations

from fastapi import HTTPException
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..models import ChatMessage, ChatSession, Project, Role, User
from .session_state import session_task_state


def chat_session_for_user(db: Session, session_id: str, user: User) -> ChatSession:
    session = db.get(ChatSession, session_id)
    if not session or (user.role != Role.admin and session.owner_id != user.id):
        raise HTTPException(404, "对话不存在或无权访问")
    return session


def chat_session_dict(db: Session, session: ChatSession) -> dict:
    project = db.get(Project, session.project_id) if session.project_id else None
    message_count = db.scalar(select(func.count(ChatMessage.id)).where(ChatMessage.session_id == session.id)) or 0
    latest_message = db.scalar(
        select(ChatMessage)
        .where(ChatMessage.session_id == session.id)
        .order_by(ChatMessage.created_at.desc())
        .limit(1)
    )
    has_active_task, active_task_label = session_task_state(
        db,
        session,
        latest_message.action if latest_message else None,
    )
    return {
        "id": session.id,
        "title": session.title,
        "project_id": session.project_id,
        "project_name": project.name if project else "全局助手",
        "node_id": session.node_id,
        "ai_config_id": session.ai_config_id,
        "visibility": session.visibility,
        "archived": session.archived,
        "latest_action": latest_message.action if latest_message else None,
        "has_active_task": has_active_task,
        "active_task_label": active_task_label,
        "message_count": message_count,
        "created_at": session.created_at,
        "updated_at": session.updated_at,
    }
