from pathlib import Path

from .config import settings


def deployment_log_path(deployment_id: str) -> Path:
    return Path(settings.upload_root) / "deployment-logs" / f"{deployment_id}.log"


def read_deployment_log(deployment_id: str) -> str:
    """Return the authoritative append-only log, or an empty string."""
    try:
        path = deployment_log_path(deployment_id)
        return path.read_text(encoding="utf-8", errors="replace") if path.is_file() else ""
    except OSError:
        return ""


def append_deployment_log(deployment_id: str, content: str) -> None:
    """Append a log fragment without making deployment progress depend on disk I/O."""
    try:
        path = deployment_log_path(deployment_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(content)
    except OSError:
        pass
