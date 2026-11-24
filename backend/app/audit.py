import json
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import AuditLog, SecurityConfig, User


def audit(
    db: Session,
    user: User | None,
    action: str,
    target_type: str = "",
    target_id: str | None = None,
    detail: str = "",
) -> None:
    """Append one audit event to the caller's current transaction."""
    db.add(
        AuditLog(
            user_id=user.id if user else None,
            action=action,
            target_type=target_type,
            target_id=target_id,
            detail=detail,
        )
    )


def cleanup_audit_logs(db: Session) -> int:
    """Apply the configured retention policy without deleting retained-volume evidence."""
    policy = db.get(SecurityConfig, "default")
    days = int(policy.audit_retention_days if policy else 180)
    if days <= 0:
        return 0
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    rows = db.scalars(select(AuditLog).where(AuditLog.created_at < cutoff)).all()
    removed = 0
    for row in rows:
        # Retained Docker volumes are discovered from the delete-project audit
        # record, so preserve that record until the retained data is removed.
        if row.action == "delete_project":
            try:
                detail = json.loads(row.detail or "{}")
                if detail.get("data_state") == "retained" and detail.get("retained_volumes"):
                    continue
            except (TypeError, ValueError):
                pass
        db.delete(row)
        removed += 1
    if removed:
        db.commit()
    return removed
