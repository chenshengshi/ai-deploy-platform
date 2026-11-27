"""Port allocation and ownership policy for deployment lifecycle operations."""

from datetime import datetime, timezone
import re
import shlex

from sqlalchemy import select, text
import yaml

from ..models import (
    DeployStatus,
    Deployment,
    DeploymentPortReservation,
    DeploymentSettings,
    Node,
    Project,
    ProjectReplica,
)
from ..ssh import SSHNode
from .runtime_ports import (
    compose_published_port as _compose_published_port,
    replace_compose_published_port as _replace_compose_published_port,
)


def stopped_reservation_status(*, release_ports: bool) -> str:
    """Return the reservation state after stopping a runtime."""
    return "released" if release_ports else "reserved"


def stopped_port_message(*, release_ports: bool) -> str:
    return "端口已释放" if release_ports else "原端口已为该项目保留"


def choose_port(db, preferred: int | None, exclude_deployment_id: str | None = None) -> int:
    """Allocate a database-free internal port under a transaction lock."""
    db.execute(text("SELECT pg_advisory_xact_lock(hashtext('node-port-allocation'))"))
    policy = db.get(DeploymentSettings, "default")
    internal_start = policy.internal_port_start if policy else 30000
    internal_end = policy.internal_port_end if policy else 39999
    external_start = policy.external_port_start if policy else 20000
    external_end = policy.external_port_end if policy else 21000
    filters = [Deployment.status.in_([DeployStatus.queued, DeployStatus.running, DeployStatus.success])]
    if exclude_deployment_id:
        filters.append(Deployment.id != exclude_deployment_id)
    used = set(db.scalars(select(Deployment.host_port).where(*filters)).all())
    used.update(db.scalars(select(ProjectReplica.host_port).where(ProjectReplica.status == "running")).all())
    used.update(db.scalars(select(DeploymentPortReservation.host_port).where(
        DeploymentPortReservation.status.in_(["reserved", "active"]),
        *([DeploymentPortReservation.deployment_id != exclude_deployment_id] if exclude_deployment_id else []),
    )).all())
    used.discard(None)
    if preferred:
        if external_start <= preferred <= external_end:
            raise RuntimeError("项目指定的服务器端口占用了公网网关端口段，请改用内网实例端口段")
        if preferred not in used:
            return preferred
    for port in range(internal_start, internal_end + 1):
        if port not in used:
            return port
    raise RuntimeError("内网实例端口池已用完，请在系统设置中扩大端口范围")


def choose_node_port(
    db,
    node,
    preferred: int | None,
    *,
    ssh_factory=SSHNode,
    reserved: set[int] | None = None,
    exclude_deployment_id: str | None = None,
) -> int:
    """Choose a port free in both platform state and the real target node."""
    policy = db.get(DeploymentSettings, "default")
    internal_end = policy.internal_port_end if policy else 39999
    candidate = choose_port(db, preferred, exclude_deployment_id)
    filters = [Deployment.status.in_([DeployStatus.queued, DeployStatus.running, DeployStatus.success])]
    if exclude_deployment_id:
        filters.append(Deployment.id != exclude_deployment_id)
    used = set(db.scalars(select(Deployment.host_port).where(*filters)).all())
    used.update(db.scalars(select(ProjectReplica.host_port).where(ProjectReplica.status == "running")).all())
    used.update(db.scalars(select(DeploymentPortReservation.host_port).where(
        DeploymentPortReservation.status.in_(["reserved", "active"]),
        *([DeploymentPortReservation.deployment_id != exclude_deployment_id] if exclude_deployment_id else []),
    )).all())
    locally_reserved = {int(port) for port in (reserved or set()) if port}
    used.update(locally_reserved)
    with ssh_factory(node) as ssh:
        while candidate <= internal_end:
            code, _ = ssh.run(
                "(ss -ltnH 2>/dev/null | awk '{print $4}' | "
                f"grep -Eq ':{candidate}$') || "
                "(docker ps --format '{{.Ports}}' 2>/dev/null | "
                f"grep -Eq '(^|[^0-9]){candidate}->')"
            )
            if code != 0 and candidate not in locally_reserved and candidate not in used:
                return candidate
            candidate += 1
    raise RuntimeError("目标服务器内网实例端口池已被占满")


def reserve_reactivation_port(db, deployment, node, service: str, port: int) -> None:
    reservation = db.scalar(select(DeploymentPortReservation).where(
        DeploymentPortReservation.node_id == node.id,
        DeploymentPortReservation.host_port == port,
    ))
    if reservation:
        if reservation.status in {"reserved", "active"} and reservation.deployment_id != deployment.id:
            raise RuntimeError(f"端口 {port} 已被其他发布任务占用")
        reservation.deployment_id = deployment.id
        reservation.service_name = service
        reservation.status = "reserved"
        reservation.created_at = datetime.now(timezone.utc)
    else:
        db.add(DeploymentPortReservation(
            deployment_id=deployment.id,
            node_id=node.id,
            service_name=service,
            host_port=port,
            status="reserved",
        ))


def prepare_stopped_release_ports(
    deployment: Deployment, project: Project, node: Node, actual_dir: str, db,
) -> str:
    """Validate and restore the ports retained by a stopped release.

    A user-initiated stop keeps the release's reservations, so an ordinary
    restart normally receives exactly the same addresses.  The reconciliation
    below remains necessary for legacy records and for ports occupied by an
    unmanaged process outside the platform.
    """
    if db is None:
        return ""
    old_entry_port = int(deployment.host_port or 0)
    changes: list[tuple[str, int, int]] = []
    reserved: set[int] = set()
    try:
        if deployment.image_name:
            allocated = choose_node_port(
                db, node, old_entry_port or None,
                reserved=reserved, exclude_deployment_id=deployment.id,
            )
            reserved.add(allocated)
            reserve_reactivation_port(db, deployment, node, "app", allocated)
            if allocated != old_entry_port:
                changes.append(("app", old_entry_port, allocated))
            deployment.host_port = allocated
        else:
            app_file = ".yunzhou.app.yml"
            remote_path = actual_dir.rstrip("/") + "/" + app_file
            with SSHNode(node) as ssh:
                if ssh.run(f"test -f {shlex.quote(remote_path)}", timeout=20)[0] != 0:
                    # Legacy releases cannot be safely rewritten because their
                    # source Compose file may still mix application and data.
                    return ""
                sftp = ssh.client.open_sftp()
                try:
                    with sftp.open(remote_path) as handle:
                        original = handle.read().decode("utf-8", "replace")
                    document = yaml.safe_load(original) or {}
                    services = document.get("services") if isinstance(document, dict) else None
                    if not isinstance(services, dict):
                        raise RuntimeError("历史版本应用配置无效，无法重新分配端口")
                    # Older managed releases interpolate published ports from
                    # the release-local .env (for example
                    # ${YUNZHOU_HOST_PORT}:80). Resolve those values before
                    # deciding whether the historical port is still free. The
                    # rewritten application file uses the newly allocated
                    # number directly, so a stale .env value cannot reclaim it.
                    compose_environment: dict[str, str] = {}
                    for env_name in (".env.runtime", ".env"):
                        try:
                            with sftp.open(actual_dir.rstrip("/") + "/" + env_name) as handle:
                                env_text = handle.read().decode("utf-8", "replace")
                        except OSError:
                            continue
                        for line in env_text.splitlines():
                            stripped = line.strip()
                            if not stripped or stripped.startswith("#") or "=" not in stripped:
                                continue
                            key, env_value = stripped.split("=", 1)
                            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key.strip()):
                                compose_environment[key.strip()] = env_value.strip().strip('"').strip("'")
                    remapped_entry = None
                    for service_name, service in services.items():
                        if not isinstance(service, dict):
                            continue
                        mappings = list(service.get("ports") or [])
                        updated = []
                        for mapping in mappings:
                            old_port = _compose_published_port(mapping, compose_environment)
                            if not old_port:
                                updated.append(mapping)
                                continue
                            allocated = choose_node_port(
                                db, node, old_port,
                                reserved=reserved, exclude_deployment_id=deployment.id,
                            )
                            reserved.add(allocated)
                            reserve_reactivation_port(db, deployment, node, str(service_name), allocated)
                            updated.append(_replace_compose_published_port(mapping, allocated))
                            if allocated != old_port:
                                changes.append((str(service_name), old_port, allocated))
                            if old_port == old_entry_port:
                                remapped_entry = allocated
                        if mappings:
                            service["ports"] = updated
                    if old_entry_port and remapped_entry is None:
                        raise RuntimeError("历史版本入口端口不在应用配置中，无法安全回滚")
                    if remapped_entry:
                        deployment.host_port = remapped_entry
                    if changes:
                        temporary = remote_path + ".port-remap"
                        with sftp.open(temporary, "w") as handle:
                            handle.write(yaml.safe_dump(document, allow_unicode=True, sort_keys=False))
                        code, output = ssh.run(
                            f"mv -f -- {shlex.quote(temporary)} {shlex.quote(remote_path)}",
                            timeout=20,
                        )
                        if code:
                            raise RuntimeError("写入历史版本端口映射失败：" + output[-300:])
                finally:
                    sftp.close()
        db.commit()
    except Exception:
        db.rollback()
        raise
    if not changes:
        return "历史端口仍可用，已重新登记"
    detail = "、".join(f"{service} {old or '未分配'}→{new}" for service, old, new in changes)
    return "历史端口已自动重新分配：" + detail
