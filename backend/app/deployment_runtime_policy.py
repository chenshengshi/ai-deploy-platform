from __future__ import annotations

import re


def safe_runtime_namespace(namespace: str | None) -> str:
    return re.sub(r"[^a-z0-9-]", "-", str(namespace or "yunzhou").lower()).strip("-") or "yunzhou"


def data_compose_project(namespace: str | None, project_slug: str) -> str:
    return f"{safe_runtime_namespace(namespace)}-{project_slug}-data"


def validate_release(release: str | None) -> str:
    value = (release or "").strip()
    if value and not re.fullmatch(r"[A-Za-z0-9_.-]+", value):
        raise RuntimeError("发布版本号不安全，已拒绝操作")
    return value


def release_directories(work_dir: str, project_directory_name: str, project_slug: str, release: str | None) -> list[str]:
    value = validate_release(release)
    if not value:
        return []
    base = work_dir.rstrip("/")
    return list(dict.fromkeys((
        f"{base}/{project_directory_name}/{value}",
        f"{base}/{project_slug}/{value}",
    )))
