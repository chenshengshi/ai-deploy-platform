"""Saved AI chat workflows and conversation lifecycle routes."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..audit import audit
from ..auth import current_user, require
from ..database import get_db
from ..models import ChatMessage, ChatSession, Deployment, Node, Project, ProjectAccess, Role, User
from .sessions import chat_session_dict, chat_session_for_user

router = APIRouter()


def _user_can_access_project(db: Session, user: User, project_id: str) -> bool:
    if user.role == Role.admin:
        return True
    return bool(db.scalar(select(Project.id).where(
        Project.id == project_id,
        (Project.owner_id == user.id) | Project.id.in_(select(ProjectAccess.project_id).where(ProjectAccess.user_id == user.id)),
    )))

@router.post("/api/chat/workflow")
def save_chat_workflow(body: dict, db: Session = Depends(get_db), user: User = Depends(require(Role.admin, Role.deployer))):
    project_id = str(body.get("project_id") or "").strip()
    project = db.get(Project, project_id) if project_id else None
    if not project or not _user_can_access_project(db, user, project.id):
        raise HTTPException(404, "项目不存在或无权访问")
    session_id = str(body.get("session_id") or "").strip()
    session = chat_session_for_user(db, session_id, user) if session_id else None
    if not session:
        session = ChatSession(
            owner_id=user.id,
            project_id=project.id,
            node_id=str(body.get("node_id") or "").strip() or None,
            ai_config_id=str(body.get("ai_config_id") or "").strip() or None,
            title=f"部署 · {project.name}"[:160],
        )
        db.add(session)
        db.flush()
    session.project_id = project.id
    if body.get("node_id") and db.get(Node, str(body["node_id"])):
        session.node_id = str(body["node_id"])
    session.archived = False
    session.updated_at = datetime.now(timezone.utc)
    message_id = str(body.get("message_id") or "").strip()
    message = db.get(ChatMessage, message_id) if message_id else None
    if message and message.session_id != session.id:
        raise HTTPException(409, "任务消息不属于当前对话")
    if not message:
        message = db.scalar(
            select(ChatMessage).where(
                ChatMessage.session_id == session.id,
                ChatMessage.role == "assistant",
                ChatMessage.action.like("workflow_%"),
            ).order_by(ChatMessage.created_at.desc()).limit(1)
        )
    if not message:
        message = ChatMessage(session_id=session.id, role="assistant", content="")
        db.add(message)
        db.flush()
    message.content = str(body.get("content") or "正在读取任务状态")[:20_000]
    message.action = str(body.get("action") or "workflow_running")[:64]
    deployment_id = str(body.get("deployment_id") or "").strip()
    message.deployment_id = deployment_id if deployment_id and db.get(Deployment, deployment_id) else message.deployment_id
    duplicates = db.scalars(select(ChatMessage).where(
        ChatMessage.session_id == session.id,
        ChatMessage.role == "assistant",
        ChatMessage.id != message.id,
        ChatMessage.deployment_id == message.deployment_id,
    )).all() if message.deployment_id else []
    for duplicate in duplicates:
        db.delete(duplicate)
    db.commit()
    return {
        "session": chat_session_dict(db, session),
        "message": {
            "id": message.id, "role": message.role, "content": message.content,
            "action": message.action, "deployment_id": message.deployment_id,
            "created_at": message.created_at,
        },
    }


@router.get("/api/chat/sessions")
def chat_sessions(project_id: str | None = None, archived: bool = False, db: Session = Depends(get_db), user: User = Depends(current_user)):
    query = select(ChatSession).where(ChatSession.archived == archived)
    if user.role != Role.admin:
        query = query.where(ChatSession.owner_id == user.id)
    if project_id:
        query = query.where(ChatSession.project_id == project_id)
    return [chat_session_dict(db, item) for item in db.scalars(query.order_by(ChatSession.updated_at.desc()).limit(200)).all()]


@router.get("/api/chat/sessions/{session_id}/messages")
def chat_session_messages(session_id: str, db: Session = Depends(get_db), user: User = Depends(current_user)):
    session = chat_session_for_user(db, session_id, user)
    messages = db.scalars(select(ChatMessage).where(ChatMessage.session_id == session.id).order_by(ChatMessage.created_at)).all()
    return {
        "session": chat_session_dict(db, session),
        "messages": [
            {"id": item.id, "role": item.role, "content": item.content, "action": item.action,
             "deployment_id": item.deployment_id, "elapsed_ms": item.elapsed_ms, "created_at": item.created_at}
            for item in messages
        ],
    }


@router.post("/api/chat/sessions/{session_id}/archive")
def archive_chat_session(session_id: str, db: Session = Depends(get_db), user: User = Depends(current_user)):
    session = chat_session_for_user(db, session_id, user)
    session.archived = True
    audit(db, user, "archive_chat_session", "chat_session", session.id, session.title)
    db.commit()
    return {"ok": True}


@router.post("/api/chat/sessions/{session_id}/restore")
def restore_chat_session(session_id: str, db: Session = Depends(get_db), user: User = Depends(current_user)):
    session = chat_session_for_user(db, session_id, user)
    session.archived = False
    audit(db, user, "restore_chat_session", "chat_session", session.id, session.title)
    db.commit()
    return {"ok": True}


@router.delete("/api/chat/sessions/{session_id}")
def delete_chat_session(session_id: str, db: Session = Depends(get_db), user: User = Depends(current_user)):
    session = chat_session_for_user(db, session_id, user)
    if chat_session_dict(db, session)["has_active_task"]:
        raise HTTPException(409, "该对话仍有任务正在执行，任务结束后才能删除")
    title = session.title
    db.delete(session)
    audit(db, user, "delete_chat_session", "chat_session", session_id, title)
    db.commit()
    return {"ok": True}


@router.post("/api/chat/sessions/archive-all")
def archive_all_chat_sessions(body: dict, db: Session = Depends(get_db), user: User = Depends(current_user)):
    query = select(ChatSession).where(ChatSession.archived.is_(False))
    if user.role != Role.admin or body.get("scope") != "platform":
        query = query.where(ChatSession.owner_id == user.id)
    if body.get("project_id"):
        query = query.where(ChatSession.project_id == str(body["project_id"]))
    items = db.scalars(query).all()
    for item in items:
        item.archived = True
    audit(db, user, "archive_chat_sessions", "chat_session", detail=f"count={len(items)},scope={body.get('scope', 'mine')}")
    db.commit()
    return {"ok": True, "count": len(items)}


@router.post("/api/chat/sessions/purge")
def purge_chat_sessions(body: dict, db: Session = Depends(get_db), user: User = Depends(current_user)):
    if body.get("confirm") != "永久清理对话":
        raise HTTPException(400, "请输入“永久清理对话”确认")
    scope = str(body.get("scope") or "mine")
    if scope == "platform" and user.role != Role.admin:
        raise HTTPException(403, "只有管理员可以清理全平台对话")
    query = select(ChatSession)
    if scope != "platform":
        query = query.where(ChatSession.owner_id == user.id)
    if body.get("project_id"):
        query = query.where(ChatSession.project_id == str(body["project_id"]))
    if body.get("archived_only", True):
        query = query.where(ChatSession.archived.is_(True))
    items = db.scalars(query).all()
    ids = [item.id for item in items]
    for item in items:
        db.delete(item)
    audit(db, user, "purge_chat_sessions", "chat_session", detail=f"count={len(ids)},scope={scope}")
    db.commit()
    return {"ok": True, "count": len(ids)}

