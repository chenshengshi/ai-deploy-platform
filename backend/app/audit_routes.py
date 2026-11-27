"""Audit logs, AI experience review, retention settings, and retained data cleanup."""

from __future__ import annotations

import json
import shlex
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from sqlalchemy import desc, func, or_, select
from sqlalchemy.orm import Session

from .audit import audit, cleanup_audit_logs as _cleanup_audit_logs
from .auth import require
from .database import get_db
from .experience import contains_corruption, portable_experience
from .models import AuditLog, DeploymentExperience, Node, Project, Role, SecurityConfig, User
from .ssh import SSHNode

router = APIRouter()


def get_security_config(db: Session) -> SecurityConfig:
    row = db.get(SecurityConfig, "default")
    if not row:
        row = SecurityConfig(id="default")
        db.add(row)
        db.commit()
        db.refresh(row)
    elif row.china_ip_source_url in {
        "https://www.ipdeny.com/ipblocks/data/countries/cn.zone",
        "http://www.ipdeny.com/ipblocks/data/countries/cn.zone",
    }:
        row.china_ip_source_url = "https://ispip.clang.cn/all_cn_cidr.html"
        db.commit()
        db.refresh(row)
    return row

@router.get("/api/audit")
def audit_logs(
    q: str = "", action: str = "", category: str = "", paged: bool = False,
    page: int = 1, page_size: int = 20,
    db: Session = Depends(get_db), _: User = Depends(require(Role.admin)),
):
    page = max(1, page)
    page_size = min(100, max(20, page_size))
    auth_actions = {"login", "login_failed", "logout"}
    if paged:
        query = select(AuditLog).outerjoin(User, User.id == AuditLog.user_id)
        conditions = []
        if action:
            conditions.append(AuditLog.action == action)
        if category == "auth":
            conditions.append(AuditLog.action.in_(auth_actions))
        elif category == "operation":
            conditions.append(AuditLog.action.not_in(auth_actions))
        keyword = q.strip().lower()
        if keyword:
            pattern = f"%{keyword}%"
            conditions.append(or_(
                func.lower(func.coalesce(User.display_name, "")).like(pattern),
                func.lower(func.coalesce(User.username, "")).like(pattern),
                func.lower(func.coalesce(AuditLog.action, "")).like(pattern),
                func.lower(func.coalesce(AuditLog.target_type, "")).like(pattern),
                func.lower(func.coalesce(AuditLog.target_id, "")).like(pattern),
                func.lower(func.coalesce(AuditLog.detail, "")).like(pattern),
            ))
        if conditions:
            query = query.where(*conditions)
        total = db.scalar(select(func.count()).select_from(query.order_by(None).subquery())) or 0
        pages = max(1, (total + page_size - 1) // page_size)
        page = min(page, pages)
        items = db.scalars(query.order_by(desc(AuditLog.created_at)).offset((page - 1) * page_size).limit(page_size)).all()
        users = {user.id: (user.display_name or user.username) for user in db.scalars(select(User)).all()}
        rows = [{"id": x.id, "user_id": x.user_id, "user_name": users.get(x.user_id, "系统任务"), "action": x.action, "target_type": x.target_type, "target_id": x.target_id, "detail": x.detail, "created_at": x.created_at} for x in items]
        return {"items": rows, "total": total, "page": page, "page_size": page_size, "pages": pages}
    items = db.scalars(select(AuditLog).order_by(desc(AuditLog.created_at)).limit(1000)).all()
    users = {user.id: (user.display_name or user.username) for user in db.scalars(select(User)).all()}
    if action:
        items = [item for item in items if item.action == action]
    if category == "auth":
        items = [item for item in items if item.action in auth_actions]
    elif category == "operation":
        items = [item for item in items if item.action not in auth_actions]
    keyword = q.strip().lower()
    if keyword:
        items = [item for item in items if keyword in " ".join((
            users.get(item.user_id, "系统任务"), item.action or "", item.target_type or "",
            item.target_id or "", item.detail or "",
        )).lower()]
    return [{"id": x.id, "user_id": x.user_id, "user_name": users.get(x.user_id, "系统任务"), "action": x.action, "target_type": x.target_type, "target_id": x.target_id, "detail": x.detail, "created_at": x.created_at} for x in items[:200]]


def _experience_view(item: DeploymentExperience) -> dict:
    try:
        tags = json.loads(item.scope_tags or "[]")
    except (TypeError, ValueError):
        tags = []
    return {
        "id": item.id,
        "category": item.category,
        "stage": item.stage,
        "state": item.state,
        "enabled": item.enabled,
        "verified": item.verified,
        "confidence": item.confidence,
        "scope_tags": tags,
        "error_sample": item.error_sample,
        "repair_summary": item.repair_summary,
        "occurrences": item.occurrences,
        "successful_repairs": item.successful_repairs,
        "failed_repairs": item.failed_repairs,
        "use_count": item.use_count,
        "last_used_at": item.last_used_at,
        "last_verified_at": item.last_verified_at,
        "updated_at": item.updated_at,
    }


@router.get("/api/ai-experiences")
def ai_experiences(
    q: str = "", state: str = "", stage: str = "",
    db: Session = Depends(get_db), _: User = Depends(require(Role.admin)),
):
    rows = db.scalars(select(DeploymentExperience).order_by(
        DeploymentExperience.verified.desc(),
        DeploymentExperience.confidence.desc(),
        DeploymentExperience.updated_at.desc(),
    )).all()
    keyword = q.strip().lower()
    if state:
        rows = [row for row in rows if row.state == state]
    if stage:
        rows = [row for row in rows if row.stage == stage]
    if keyword:
        rows = [row for row in rows if keyword in " ".join((
            row.category or "", row.stage or "", row.scope_tags or "",
            row.error_sample or "", row.repair_summary or "",
        )).lower()]
    all_rows = db.scalars(select(DeploymentExperience)).all()
    return {
        "summary": {
            "total": len(all_rows),
            "verified": sum(1 for row in all_rows if row.state == "verified" and row.enabled),
            "candidate": sum(1 for row in all_rows if row.state == "candidate" and row.enabled),
            "disabled": sum(1 for row in all_rows if not row.enabled),
            "quarantined": sum(1 for row in all_rows if row.state == "quarantined"),
        },
        "items": [_experience_view(row) for row in rows[:500]],
    }


@router.patch("/api/ai-experiences/{experience_id}")
def update_ai_experience(
    experience_id: str, body: dict,
    db: Session = Depends(get_db), user: User = Depends(require(Role.admin)),
):
    item = db.get(DeploymentExperience, experience_id)
    if not item:
        raise HTTPException(404, "经验不存在")
    if "state" in body:
        state = str(body.get("state") or "").strip().lower()
        if state not in {"candidate", "verified", "deprecated", "quarantined"}:
            raise HTTPException(400, "经验状态不正确")
        if state == "verified" and not item.verified:
            raise HTTPException(400, "候选经验必须经过真实部署验证，不能手工标记为已验证")
        item.state = state
        if state in {"deprecated", "quarantined"}:
            item.enabled = False
    if "enabled" in body:
        enabled = bool(body.get("enabled"))
        if enabled and (item.state == "quarantined" or contains_corruption(item.error_sample) or contains_corruption(item.repair_summary)):
            raise HTTPException(400, "隔离或乱码经验不能启用")
        item.enabled = enabled
        if enabled and item.state == "deprecated":
            item.state = "verified" if item.verified else "candidate"
    item.updated_at = datetime.now(timezone.utc)
    audit(db, user, "update_ai_experience", "deployment_experience", item.id, json.dumps({
        "category": item.category, "state": item.state, "enabled": item.enabled,
    }, ensure_ascii=False))
    db.commit()
    return _experience_view(item)


@router.get("/api/ai-experiences/export")
def export_ai_experiences(db: Session = Depends(get_db), user: User = Depends(require(Role.admin))):
    rows = db.scalars(select(DeploymentExperience).order_by(DeploymentExperience.created_at)).all()
    payload = [portable_experience(row) for row in rows if not contains_corruption(row.error_sample) and not contains_corruption(row.repair_summary)]
    audit(db, user, "export_ai_experiences", "system", detail=json.dumps({"count": len(payload)}, ensure_ascii=False))
    db.commit()
    content = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
    return Response(
        content=content.encode("utf-8"), media_type="application/json; charset=utf-8",
        headers={"Content-Disposition": "attachment; filename=deployment-experiences.json"},
    )


@router.get("/api/audit/settings")
def audit_settings(db: Session = Depends(get_db), _: User = Depends(require(Role.admin))):
    return {"retention_days": get_security_config(db).audit_retention_days}


@router.put("/api/audit/settings")
def update_audit_settings(body: dict, db: Session = Depends(get_db), user: User = Depends(require(Role.admin))):
    try:
        days = int(body.get("retention_days", 180))
    except (TypeError, ValueError):
        raise HTTPException(400, "操作记录保留天数不正确")
    if days < 0 or days > 3650:
        raise HTTPException(400, "操作记录保留天数必须为 0 到 3650；0 表示永久保留")
    config = get_security_config(db)
    config.audit_retention_days = days
    audit(db, user, "update_audit_retention", "system", detail=json.dumps({"retention_days": days}, ensure_ascii=False))
    db.commit()
    removed = _cleanup_audit_logs(db)
    return {"retention_days": days, "removed": removed}


@router.get("/api/retained-data")
def retained_data(db: Session = Depends(get_db), _: User = Depends(require(Role.admin))):
    items = db.scalars(select(AuditLog).where(AuditLog.action == "delete_project").order_by(desc(AuditLog.created_at))).all()
    result = []
    for entry in items:
        try:
            detail = json.loads(entry.detail or "{}")
        except Exception:
            continue
        volumes = detail.get("retained_volumes") or []
        if detail.get("data_state") != "retained" or not volumes:
            continue
        result.append({"id": entry.id, "project": detail.get("project", "已删除项目"), "project_slug": detail.get("project_slug", ""), "volumes": volumes, "count": len(volumes), "retained_at": entry.created_at})
    recorded = {
        (volume.get("node_id"), volume.get("name"))
        for item in result for volume in item["volumes"]
    }
    active_slugs = {project.slug for project in db.scalars(select(Project)).all()}
    for node in db.scalars(select(Node).where(Node.enabled == True)).all():
        try:
            with SSHNode(node) as ssh:
                _, output = ssh.run("docker volume ls -q", timeout=20)
                groups: dict[str, list[dict]] = {}
                for name in filter(None, map(str.strip, output.splitlines())):
                    if not name.startswith("yz-") or (node.id, name) in recorded:
                        continue
                    _, label = ssh.run(
                        "docker volume inspect -f " + shlex.quote('{{index .Labels "com.docker.compose.project"}}') + " " + shlex.quote(name),
                        timeout=10,
                    )
                    compose_project = label.strip()
                    inferred = (compose_project[3:] if compose_project.startswith("yz-") else name[3:].split("_", 1)[0])
                    if inferred in active_slugs:
                        continue
                    _, used = ssh.run("docker ps -aq --filter " + shlex.quote(f"volume={name}"), timeout=10)
                    groups.setdefault(inferred or "历史项目", []).append({
                        "name": name,
                        "node_id": node.id,
                        "node": node.name,
                        "in_use": bool(used.strip()),
                    })
                for slug, volumes in groups.items():
                    result.append({
                        "id": f"orphan:{node.id}:{slug}",
                        "project": slug,
                        "project_slug": slug,
                        "volumes": volumes,
                        "count": len(volumes),
                        "retained_at": None,
                        "discovered": True,
                        "in_use": any(volume["in_use"] for volume in volumes),
                    })
        except Exception:
            # One offline node must not hide retained records from other nodes.
            continue
    return result


@router.delete("/api/retained-data/{audit_id}")
def purge_retained_data(audit_id: str, db: Session = Depends(get_db), user: User = Depends(require(Role.admin))):
    if audit_id.startswith("orphan:"):
        try:
            _, node_id, slug = audit_id.split(":", 2)
        except ValueError:
            raise HTTPException(404, "遗留数据记录不存在")
        node = db.get(Node, node_id)
        if not node:
            raise HTTPException(404, "原部署服务器不存在")
        if db.scalar(select(Project).where(Project.slug == slug)):
            raise HTTPException(409, "该项目仍然存在，不能在遗留数据中删除其数据卷")
        prefix = f"yz-{slug}"
        removed = []
        try:
            with SSHNode(node) as ssh:
                _, output = ssh.run("docker volume ls -q", timeout=20)
                for name in filter(None, map(str.strip, output.splitlines())):
                    if not (name == prefix or name.startswith(prefix + "_") or name.startswith(prefix + "-")):
                        _, label = ssh.run("docker volume inspect -f " + shlex.quote('{{index .Labels "com.docker.compose.project"}}') + " " + shlex.quote(name), timeout=10)
                        if label.strip() != prefix:
                            continue
                    _, used = ssh.run("docker ps -aq --filter " + shlex.quote(f"volume={name}"), timeout=10)
                    if used.strip():
                        raise RuntimeError(f"数据卷 {name} 仍被容器使用，请先停止或删除对应容器")
                    code, output = ssh.run("docker volume rm " + shlex.quote(name), timeout=30)
                    if code:
                        raise RuntimeError(output or f"数据卷 {name} 删除失败")
                    removed.append({"name": name, "node": node.name})
        except Exception as exc:
            raise HTTPException(502, f"遗留数据未全部清理：{exc}")
        # AuditLog.target_id is limited to 36 characters.  The synthetic
        # orphan key also contains the project slug, so record the real node
        # id here and keep the complete identity in the JSON detail.
        audit(db, user, "purge_retained_data", "retained_data", node.id, json.dumps({"project": slug, "orphan_id": audit_id, "volumes": removed, "discovered": True}, ensure_ascii=False))
        db.commit()
        return {"ok": True, "summary": f"已彻底删除 {len(removed)} 个遗留数据卷，并完成占用复查"}
    entry = db.get(AuditLog, audit_id)
    if not entry or entry.action != "delete_project":
        raise HTTPException(404, "保留数据记录不存在")
    try:
        detail = json.loads(entry.detail or "{}")
    except Exception:
        raise HTTPException(409, "保留数据记录格式无效")
    volumes = detail.get("retained_volumes") or []
    if detail.get("data_state") != "retained" or not volumes:
        raise HTTPException(409, "这些托管数据已经清理或不存在")
    grouped = {}
    for volume in volumes:
        grouped.setdefault(volume.get("node_id"), []).append(volume.get("name"))
    removed = []
    try:
        for node_id, names in grouped.items():
            node = db.get(Node, node_id)
            if not node:
                raise RuntimeError("原部署服务器已删除，无法执行远程清理")
            safe_names = [name for name in names if name]
            with SSHNode(node) as ssh:
                command = "; ".join(f"docker volume rm -f {shlex.quote(name)}" for name in safe_names) or "true"
                code, output = ssh.run("set -e; " + command, timeout=60)
                if code:
                    raise RuntimeError(output or f"{node.name} 数据卷清理失败")
                verify = "; ".join(f"docker volume inspect {shlex.quote(name)} >/dev/null 2>&1 && exit 23 || true" for name in safe_names) or "true"
                verify_code, verify_output = ssh.run(verify, timeout=30)
                if verify_code:
                    raise RuntimeError(verify_output or f"{node.name} 清理后复查失败")
            removed.extend({"name": name, "node": node.name} for name in safe_names)
    except Exception as exc:
        raise HTTPException(502, f"保留数据未全部清理：{exc}")
    detail["data_state"] = "deleted"
    detail["purged_at"] = datetime.now(timezone.utc).isoformat()
    detail["purged_by"] = user.display_name or user.username
    entry.detail = json.dumps(detail, ensure_ascii=False)
    audit(db, user, "purge_retained_data", "retained_data", entry.id, json.dumps({"project": detail.get("project"), "volumes": removed}, ensure_ascii=False))
    db.commit()
    return {"ok": True, "summary": f"已彻底删除 {len(removed)} 个平台托管数据卷，并完成复查"}

