"""Persistent deployment defaults shared by API and background services."""

from sqlalchemy.orm import Session

from ..models import DeploymentSettings


def get_deployment_settings(db: Session) -> DeploymentSettings:
    row = db.get(DeploymentSettings, "default")
    if not row:
        row = DeploymentSettings(id="default")
        db.add(row)
        db.commit()
        db.refresh(row)
    return row
