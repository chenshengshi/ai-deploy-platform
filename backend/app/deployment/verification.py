"""Pure rules for deployment reachability and startup verification."""

from __future__ import annotations


_FATAL_STARTUP_MARKERS = (
    "application run failed",
    "could not resolve placeholder",
    "failed to start web server",
    "exception encountered during context initialization",
    "exec format error",
)


def http_status_accepted(status: str) -> bool:
    return status.isdigit() and (200 <= int(status) < 400 or int(status) in {401, 403})


def required_route_accepted(exit_code: int, status: str) -> bool:
    return exit_code == 0 and status.isdigit() and int(status) < 500


def frontend_code_warning(issue: dict) -> str:
    evidence = issue["evidence"][0]
    return (
        "frontend_public_base_mismatch："
        f"页面引用 {evidence['reference']}，但返回 {evidence['content_type']}；"
        f"实际资源位于 {evidence.get('working_path') or '其他路径'}"
    )


def has_fatal_startup_error(diagnostics: str) -> bool:
    lowered = str(diagnostics or "").lower()
    return any(marker in lowered for marker in _FATAL_STARTUP_MARKERS)
