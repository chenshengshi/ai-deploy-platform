"""Cancellation boundary shared by long-running deployment stages."""

from __future__ import annotations

from ..database import SessionLocal
from ..models import DeployStatus, Deployment


class DeploymentCancelled(RuntimeError):
    pass


def ensure_active(deployment_id: str) -> None:
    with SessionLocal() as db:
        deployment = db.get(Deployment, deployment_id)
        if not deployment or deployment.status == DeployStatus.stopped:
            raise DeploymentCancelled("部署已由用户停止")
