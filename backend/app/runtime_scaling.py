"""Runtime instance naming and deterministic scale-down selection."""

import re

from .models import ProjectReplica

def _service_instance_prefix(
    project_slug: str, service_name: str, release: str | None = None, namespace: str = "yunzhou",
) -> str:
    safe_service = re.sub(r"[^a-z0-9-]", "-", str(service_name).lower()).strip("-") or "app"
    safe_namespace = re.sub(r"[^a-z0-9-]", "-", str(namespace).lower()).strip("-") or "yunzhou"
    safe_release = re.sub(r"[^a-z0-9-]", "-", str(release or "").lower()).strip("-")
    version = f"-{safe_release}" if safe_release else ""
    return f"{safe_namespace}-{project_slug}{version}-{safe_service}"


def _service_instance_sequence(
    name: str, project_slug: str, service_name: str, release: str | None = None, namespace: str = "yunzhou",
) -> int | None:
    matched = re.fullmatch(re.escape(_service_instance_prefix(project_slug, service_name, release, namespace)) + r"-([1-9][0-9]*)", name or "")
    return int(matched.group(1)) if matched else None


def _next_service_instance_name(
    project_slug: str,
    service_name: str,
    existing_names: set[str],
    minimum: int = 2,
    release: str | None = None,
    namespace: str = "yunzhou",
) -> str:
    """Reserve the smallest free sequence; sequence 1 belongs to the primary."""
    prefix = _service_instance_prefix(project_slug, service_name, release, namespace)
    sequence = max(1, int(minimum))
    while f"{prefix}-{sequence}" in existing_names:
        sequence += 1
    name = f"{prefix}-{sequence}"
    existing_names.add(name)
    return name


def _replicas_for_scale_down(
    replicas: list[ProjectReplica],
    project_slug: str,
    service_name: str,
    release: str | None = None,
    namespace: str = "yunzhou",
) -> list[ProjectReplica]:
    """Remove legacy random names first, then the highest numeric sequence."""
    numbered: list[tuple[int, ProjectReplica]] = []
    legacy: list[ProjectReplica] = []
    for replica in replicas:
        sequence = _service_instance_sequence(replica.container_name, project_slug, service_name, release, namespace)
        if sequence is None:
            legacy.append(replica)
        else:
            numbered.append((sequence, replica))
    return list(reversed(legacy)) + [replica for _, replica in sorted(numbered, key=lambda item: item[0], reverse=True)]

