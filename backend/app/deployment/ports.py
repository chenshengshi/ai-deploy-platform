"""Port allocation and ownership policy for deployment lifecycle operations."""

from datetime import datetime, timezone

from sqlalchemy import select, text

from ..models import (
    DeployStatus,
    Deployment,
    DeploymentPortReservation,
    DeploymentSettings,
    ProjectReplica,
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
    ssh_factory,
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
