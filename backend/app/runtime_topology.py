"""Runtime service classification and gateway topology rules."""

import json
import re

from .models import Project

_NON_SCALABLE_SERVICES = re.compile(
    r"(?:^|[-_.])(mysql|mariadb|postgres|postgresql|redis|mongo|mongodb|oracle|"
    r"minio|elastic|elasticsearch|kafka|rabbitmq|zookeeper|worker|scheduler|"
    r"cron|job|sync)(?:$|[-_.])", re.I,
)


def _runtime_entry_is_data(container: dict) -> bool:
    # Join only present fields with a separator recognised by the classifier.
    # Padding empty values with spaces made a plain service name such as
    # ``mysql`` fail its end-of-name boundary check and appear scalable.
    identity = "-".join(
        str(container.get(key) or "").strip()
        for key in ("service", "name", "image")
        if str(container.get(key) or "").strip()
    ).lower()
    return bool(_NON_SCALABLE_SERVICES.search(identity))


def _runtime_entry_is_running(container: dict) -> bool:
    state = f"{container.get('state') or ''} {container.get('status') or ''}".lower()
    return "running" in state or state.startswith("up") or " up " in state or "healthy" in state


def _traffic_plan(project: Project) -> dict:
    try:
        analysis = json.loads(project.integration_analysis_json or "{}")
    except (TypeError, ValueError):
        analysis = {}
    plan = analysis.get("traffic_plan") if isinstance(analysis, dict) else None
    if isinstance(plan, dict):
        return plan
    deployment_plan = analysis.get("deployment_plan") if isinstance(analysis, dict) else None
    if isinstance(deployment_plan, dict):
        nested = deployment_plan.get("traffic_plan")
        return nested if isinstance(nested, dict) else deployment_plan
    return analysis if isinstance(analysis, dict) else {}


def _service_role(project: Project, service: str) -> tuple[str, bool]:
    plan = _traffic_plan(project)
    roles = plan.get("service_roles") or []
    for row in roles:
        if isinstance(row, dict) and str(row.get("service") or "") == service:
            role = str(row.get("role") or "app").lower()
            # Application services are always eligible for horizontal scaling.
            # Older AI analyses occasionally persisted scalable=false for a
            # backend, which made the UI mislabel a healthy API as a fixed
            # dependency. Only data/background roles are true singletons.
            if role in {"frontend", "backend", "app", "web", "api"}:
                return role, True
            return role, bool(row.get("scalable", False))
    lowered = service.lower()
    if _NON_SCALABLE_SERVICES.search(lowered):
        return ("worker" if re.search(r"worker|scheduler|cron|job|sync", lowered) else "data"), False
    if re.search(r"front|web|ui", lowered):
        return "frontend", True
    if re.search(r"back|api|server", lowered):
        return "backend", True
    return "app", True


def _route_groups_for_services(project: Project, service_targets: dict[str, list[tuple[str, int]]]) -> list[dict]:
    """Translate the versioned AI traffic plan into auditable Nginx routes."""
    plan = _traffic_plan(project)
    routes = plan.get("traffic_routes") or plan.get("routes") or []
    default_service = str(plan.get("default_service") or plan.get("entry_service") or "")
    if not default_service:
        default_service = next((name for name in service_targets if _service_role(project, name)[0] == "frontend"), "")
    if not default_service and service_targets:
        default_service = next(iter(service_targets))
    paths_by_service: dict[str, list[dict]] = {}
    for route in routes:
        if not isinstance(route, dict):
            continue
        service = str(route.get("service") or route.get("target_service") or "")
        path = str(route.get("path") or "/")
        if service in service_targets and path.startswith("/"):
            paths_by_service.setdefault(service, []).append({
                "path": path,
                "strip_prefix": bool(route.get("strip_prefix", False)),
            })
    if default_service in service_targets and default_service not in paths_by_service:
        paths_by_service.setdefault(default_service, []).append({"path": "/", "strip_prefix": False})
    # Compatibility fallback for analyses created before traffic_routes was
    # introduced.  Reuse only paths recorded by source analysis.  A missing
    # path is safer than inventing /api and silently routing a project whose
    # actual production prefix is /prod-api, /gateway, or something custom.
    if not routes:
        backend = next((name for name in service_targets if _service_role(project, name)[0] == "backend"), "")
        frontend = next((name for name in service_targets if _service_role(project, name)[0] == "frontend"), "")
        if frontend:
            paths_by_service.setdefault(frontend, []).append({"path": "/", "strip_prefix": False})
        api_paths = plan.get("api_paths") or []
        for path in api_paths:
            if backend and str(path).startswith("/"):
                canonical_path = str(path)
                if canonical_path != "/" and not canonical_path.endswith("/"):
                    canonical_path += "/"
                paths_by_service.setdefault(backend, []).append({
                    "path": canonical_path,
                    "strip_prefix": bool(plan.get("strip_api_prefix", True)),
                })
    groups = []
    for service, paths in paths_by_service.items():
        unique_paths = list({(row["path"], row["strip_prefix"]): row for row in paths}.values())
        if service_targets.get(service) and unique_paths:
            groups.append({
                "name": service,
                "paths": unique_paths,
                "targets": service_targets[service],
                "strategy": project.load_balance_strategy,
            })
    return groups



