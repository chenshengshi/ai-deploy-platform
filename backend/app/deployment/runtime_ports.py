from __future__ import annotations

import re


def project_traffic_plan(project, deployment_plan: dict | None = None) -> dict:
    for candidate in (deployment_plan, getattr(project, "source_analysis", None)):
        if not isinstance(candidate, dict):
            continue
        nested = candidate.get("traffic_plan")
        if isinstance(nested, dict):
            return nested
        saved = candidate.get("deployment_plan")
        if isinstance(saved, dict) and isinstance(saved.get("traffic_plan"), dict):
            return saved["traffic_plan"]
    return {}


def traffic_service_roles(traffic_plan: dict) -> dict[str, tuple[str, bool]]:
    roles: dict[str, tuple[str, bool]] = {}
    for row in traffic_plan.get("service_roles") or []:
        if not isinstance(row, dict):
            continue
        service = str(row.get("service") or "").strip()
        role = str(row.get("role") or "app").strip().lower()
        if service:
            roles[service] = (role, True) if role in {"frontend", "backend", "app", "web", "api"} else (role, bool(row.get("scalable", False)))
    return roles


def compose_port_number(value) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if 1 <= value <= 65535 else None
    target = str(value or "").strip().split("/", 1)[0].rsplit(":", 1)[-1]
    match = re.search(r"(\d{1,5})$", target)
    port = int(match.group(1)) if match else None
    return port if port and 1 <= port <= 65535 else None


def compose_published_port(value, environment: dict[str, str] | None = None) -> int | None:
    if isinstance(value, dict):
        published = str(value.get("published") or "").strip()
    else:
        raw = str(value or "").strip().split("/", 1)[0]
        match = re.search(r"(?P<published>\$\{[^}]+\}|\d+):\d+$", raw)
        if not match:
            return None
        published = match.group("published")
    if not published.isdigit() and environment:
        variable = re.fullmatch(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?:(?::-|-)([^}]*))?\}", published)
        if variable:
            published = str(environment.get(variable.group(1), variable.group(2) or "")).strip()
    return int(published) if published.isdigit() and 1 <= int(published) <= 65535 else None


def replace_compose_published_port(value, published: int):
    if isinstance(value, dict):
        return {**value, "published": published}
    raw = str(value)
    base, separator, protocol = raw.partition("/")
    parts = base.rsplit(":", 2)
    if len(parts) < 2:
        return value
    parts[-2] = str(published)
    replaced = ":".join(parts)
    return replaced + (separator + protocol if separator else "")
"""Deployment package component."""

