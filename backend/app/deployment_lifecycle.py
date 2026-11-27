from .deployment_logs import read_deployment_log
from .models import Deployment, DeployStatus


VERIFIED_RELEASE_MARKERS = ("[完成] 部署成功", "[启用确认]", "[回滚完成]")


def release_verification_text(item: Deployment) -> str:
    """Combine the compact database window with the authoritative retained log."""
    database_text = item.log_text or ""
    retained_text = read_deployment_log(item.id)
    return database_text if not retained_text else f"{database_text}\n{retained_text}"


def is_verified_release(item: Deployment) -> bool:
    return any(marker in release_verification_text(item) for marker in VERIFIED_RELEASE_MARKERS)


def can_switch_to_release(item: Deployment) -> bool:
    return bool(
        item.status == DeployStatus.stopped
        and item.release
        and item.access_url
        and item.host_port
        and is_verified_release(item)
    )
