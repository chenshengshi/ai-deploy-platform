"""Stable names for Compose projects and release-owned containers."""

from __future__ import annotations

import re

from ..models import Deployment, Project


def compose_project_name(project_slug: str, release: str | None = None, namespace: str = "yunzhou") -> str:
    safe_slug = re.sub(r"[^a-z0-9-]", "-", str(project_slug).lower()).strip("-") or "project"
    safe_release = re.sub(r"[^a-z0-9-]", "-", str(release or "").lower()).strip("-")
    safe_namespace = re.sub(r"[^a-z0-9-]", "-", str(namespace).lower()).strip("-") or "yunzhou"
    return f"{safe_namespace}-{safe_slug}-{safe_release}" if safe_release else f"{safe_namespace}-{safe_slug}"


def deployment_compose_project_name(deployment: Deployment, project: Project, namespace: str = "yunzhou") -> str:
    """Recover immutable ownership even if the global namespace later changes."""
    release = str(deployment.release or "")
    marker = f"-{project.slug}-{release}"
    recorded = str(deployment.container_name or "")
    if release and marker in recorded:
        prefix = recorded.split(marker, 1)[0]
        if prefix:
            return compose_project_name(project.slug, release, prefix)
    return compose_project_name(project.slug, release, namespace)


def service_container_name(
    project_slug: str,
    service_name: str,
    sequence: int = 1,
    release: str | None = None,
    namespace: str = "yunzhou",
) -> str:
    safe_service = re.sub(r"[^a-z0-9-]", "-", str(service_name).lower()).strip("-") or "app"
    safe_namespace = re.sub(r"[^a-z0-9-]", "-", str(namespace).lower()).strip("-") or "yunzhou"
    safe_release = re.sub(r"[^a-z0-9-]", "-", str(release or "").lower()).strip("-")
    version = f"-{safe_release}" if safe_release else ""
    return f"{safe_namespace}-{project_slug}{version}-{safe_service}-{max(1, int(sequence))}"
