"""Scale project application services independently from HTTP routing."""

from __future__ import annotations

import json
import re
import shlex
import time

from fastapi import HTTPException
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from ..audit import audit
from ..config import decrypt
from ..models import DeployStatus, Deployment, DeploymentSettings, Node, Project, ProjectDomainConfig, ProjectReplica, User
from ..runtime_cache import invalidate_runtime_cache
from ..runtime_scaling import _next_service_instance_name, _replicas_for_scale_down, _service_instance_prefix
from ..runtime_topology import _NON_SCALABLE_SERVICES, _route_groups_for_services, _service_role
from ..schemas import ScaleProjectIn
from ..ssh import SSHNode
from .gateway import configure_platform_gateway
from .naming import deployment_compose_project_name
from .ports import choose_port

def scale_project_service_all(item_id: str, body: ScaleProjectIn, db: Session, user: User):
    project = db.get(Project, item_id)
    if not project:
        raise HTTPException(404, "项目不存在")
    deployment = db.scalar(select(Deployment).where(
        Deployment.project_id == item_id,
        Deployment.status == DeployStatus.success,
        Deployment.host_port.is_not(None),
    ).order_by(desc(Deployment.created_at)))
    if not deployment:
        raise HTTPException(409, "项目尚无可扩容的运行版本")
    node = db.get(Node, deployment.node_id)
    if not node:
        raise HTTPException(404, "部署节点不存在")
    all_replicas = db.scalars(select(ProjectReplica).where(
        ProjectReplica.project_id == item_id,
    ).order_by(ProjectReplica.created_at)).all()
    replicas = [item for item in all_replicas if item.deployment_id == deployment.id]
    stale_replicas = [item for item in all_replicas if item.deployment_id != deployment.id]
    created: list[ProjectReplica] = []
    removed: list[ProjectReplica] = []
    runtime_policy = db.get(DeploymentSettings, "default")
    runtime_namespace = (runtime_policy.registry_namespace if runtime_policy else "yunzhou") or "yunzhou"
    with SSHNode(node) as ssh:
        names_code, names_output = ssh.run("docker ps -a --format '{{.Names}}'", timeout=30)
        if names_code:
            raise HTTPException(502, "读取现有容器名称失败，不能安全分配实例序号")
        existing_names = set(filter(None, map(str.strip, names_output.splitlines())))
        # Reconcile physical replica containers as well as database rows. A
        # deployment record may have been deleted by an older platform version
        # while its replica container kept running and holding a host port.
        configured_base_name = deployment.container_name or f"yz-{project.slug}"
        known_names = {configured_base_name, *(item.container_name for item in all_replicas)}
        modern_replica_pattern = (
            "^" + re.escape(_service_instance_prefix(
                project.slug, "SERVICE", deployment.release, runtime_namespace,
            ).replace("-service", "-")) + ".+-([2-9]|[1-9][0-9]+)$"
        )
        _, discovered_output = ssh.run(
            "docker ps -a --format '{{.Names}}' | grep -E " + shlex.quote(
                "(^" + re.escape("yz-" + project.slug + "-replica-") +
                "[0-9]+$)|(" + modern_replica_pattern + ")"
            ) + " || true"
        )
        for discovered_name in filter(None, map(str.strip, discovered_output.splitlines())):
            if discovered_name not in known_names:
                ssh.run(f"docker rm -f {shlex.quote(discovered_name)} >/dev/null 2>&1 || true")
        # A new release owns a new primary container. Retire replicas cloned from an
        # older image before creating the new replica set, while leaving databases
        # and other Compose dependencies untouched.
        for stale in stale_replicas:
            ssh.run(f"docker rm -f {shlex.quote(stale.container_name)} >/dev/null 2>&1 || true")
            db.delete(stale)
        if stale_replicas:
            db.flush()
        # If the original primary was stopped outside the platform but a
        # healthy replica is still serving traffic, promote that replica. A
        # scale-down to one must never fail merely because the old primary is
        # gone; the surviving application container becomes the new primary.
        base_running_code, _ = ssh.run(
            f"docker inspect -f '{{{{.State.Running}}}}' {shlex.quote(configured_base_name)} 2>/dev/null | grep -qx true"
        )
        promoted = None
        if base_running_code != 0:
            for candidate in replicas:
                running_code, _ = ssh.run(
                    f"docker inspect -f '{{{{.State.Running}}}}' {shlex.quote(candidate.container_name)} 2>/dev/null | grep -qx true"
                )
                if running_code == 0:
                    promoted = candidate
                    break
            if promoted:
                deployment.container_name = promoted.container_name
                deployment.host_port = promoted.host_port
                replicas.remove(promoted)
                db.delete(promoted)
                db.flush()
                configured_base_name = deployment.container_name
        base_name = configured_base_name
        # Always inspect the complete Compose release first.  Inspecting only
        # `deployment.container_name` sees the entry Web container but misses
        # sibling API services.  A custom route such as /frapi/ -> server then
        # fails validation even though the server container is healthy.
        compose_name = deployment_compose_project_name(deployment, project)
        ps_code, ps_output = ssh.run(
            f"docker ps --filter label=com.docker.compose.project={shlex.quote(compose_name)} --format '{{{{json .}}}}'"
        )
        if ps_code or not ps_output.strip():
            ps_code, ps_output = ssh.run(
                f"docker ps --filter name=^/{shlex.quote(base_name)}$ --format '{{{{json .}}}}'"
            )
        if ps_code or not ps_output.strip():
            raise HTTPException(409, "未找到当前运行的应用容器")
        rows = []
        for line in ps_output.splitlines():
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        inspected = []
        for row in rows:
            candidate_name = row.get("Names") or row.get("Name")
            if not candidate_name:
                continue
            code, output = ssh.run(f"docker inspect {shlex.quote(candidate_name)}")
            if code:
                continue
            try:
                candidate = json.loads(output)[0]
            except (json.JSONDecodeError, IndexError):
                continue
            bindings = candidate.get("NetworkSettings", {}).get("Ports") or {}
            published_ports = {
                int(binding.get("HostPort"))
                for values in bindings.values() if values
                for binding in values if str(binding.get("HostPort", "")).isdigit()
            }
            inspected.append((candidate_name, candidate, published_ports))
        selected = next((item for item in inspected if deployment.host_port in item[2]), None)
        if not selected:
            raise HTTPException(409, "未识别到可扩容的对外应用服务；依赖容器不会被复制")
        base_name, spec, _ = selected
        base_service = str((spec.get("Config", {}).get("Labels") or {}).get("com.docker.compose.service") or "app")
        base_role, _ = _service_role(project, base_service)
        image = spec.get("Config", {}).get("Image")
        env = [value for value in (spec.get("Config", {}).get("Env") or []) if not value.startswith("HOSTNAME=")]
        networks = list((spec.get("NetworkSettings", {}).get("Networks") or {}).keys())
        network = networks[0] if networks else "bridge"
        container_port = 0
        for port_key, values in (spec.get("NetworkSettings", {}).get("Ports") or {}).items():
            if any(int(value.get("HostPort", 0)) == deployment.host_port for value in (values or [])):
                container_port = int(str(port_key).split("/")[0])
                break
        container_port = container_port or int(project.container_port or 0)
        if not image or not container_port:
            raise HTTPException(409, "应用镜像或容器端口无法识别，已拒绝盲目扩容")
        current = 1 + len(replicas)
        try:
            if body.replicas > current:
                policy = db.get(DeploymentSettings, "default")
                port_end = policy.internal_port_end if policy else 39999
                for _ in range(body.replicas - current):
                    name = _next_service_instance_name(
                        project.slug, base_service, existing_names, minimum=2,
                        release=deployment.release, namespace=runtime_namespace,
                    )
                    port = choose_port(db, None)
                    while port <= port_end:
                        occupied, _ = ssh.run(
                            "(ss -ltnH 2>/dev/null | awk '{print $4}' | "
                            f"grep -Eq ':{port}$') || "
                            "(docker ps --format '{{.Ports}}' 2>/dev/null | "
                            f"grep -Eq '(^|[^0-9]){port}->')"
                        )
                        if occupied != 0:
                            break
                        port += 1
                    if port > port_end:
                        raise RuntimeError("目标服务器内网实例端口池已被占满")
                    env_args = " ".join("-e " + shlex.quote(value) for value in env)
                    mount_args = []
                    for mount in spec.get("Mounts") or []:
                        destination = mount.get("Destination")
                        source = mount.get("Name") if mount.get("Type") == "volume" else mount.get("Source")
                        if not source or not destination:
                            continue
                        mode = "" if mount.get("RW", True) else ",readonly"
                        mount_args.append("--mount " + shlex.quote(f"type={mount.get('Type')},src={source},dst={destination}{mode}"))
                    command = (
                        f"docker rm -f {shlex.quote(name)} >/dev/null 2>&1 || true; "
                        f"docker run -d --name {shlex.quote(name)} --restart unless-stopped "
                        f"--network {shlex.quote(network)} {env_args} {' '.join(mount_args)} "
                        f"-p {port}:{container_port} {shlex.quote(image)}"
                    )
                    code, output = ssh.run(command, timeout=60)
                    if code:
                        raise RuntimeError(output)
                    ready = False
                    for _ in range(20):
                        check, status = ssh.run(f"curl -sS -o /dev/null -w '%{{http_code}}' --connect-timeout 2 --max-time 5 http://127.0.0.1:{port}/")
                        if check == 0 and status.strip().isdigit() and int(status.strip()) < 500:
                            ready = True
                            break
                        time.sleep(2)
                    if not ready:
                        ssh.run(f"docker rm -f {shlex.quote(name)} >/dev/null 2>&1 || true")
                        raise RuntimeError(f"新副本 {name} 健康检查未通过")
                    replica = ProjectReplica(
                        project_id=item_id, deployment_id=deployment.id, node_id=node.id,
                        container_name=name, host_port=port, service_name=base_service,
                        pool_role=base_role, container_port=container_port, status="running",
                    )
                    db.add(replica)
                    db.flush()
                    created.append(replica)
            elif body.replicas < current:
                remove_count = current - body.replicas
                removed = _replicas_for_scale_down(
                    replicas, project.slug, base_service, deployment.release, runtime_namespace,
                )[:remove_count]

            active = [x for x in replicas if x not in removed] + created
            targets = [(node.host, deployment.host_port)] + [(node.host, x.host_port) for x in active]
            # The legacy project-level scale endpoint is still called by some
            # clients to reconcile a displayed value (including 1 -> 1).  For
            # a Compose project it must not collapse the gateway to the single
            # selected entry container: doing so removes backend API routes
            # that were generated from the source traffic plan.  Rebuild the
            # complete service map from every inspected Compose container and
            # then add replicas to the service they actually belong to.
            service_targets: dict[str, list[tuple[str, int]]] = {}
            for _, candidate, published_ports in inspected:
                labels = candidate.get("Config", {}).get("Labels") or {}
                service_name = str(labels.get("com.docker.compose.service") or labels.get("yunzhou.service") or "").strip()
                if service_name:
                    for published in sorted(published_ports):
                        service_targets.setdefault(service_name, []).append((node.host, int(published)))
            for replica in active:
                service_name = str(replica.service_name or base_service).strip()
                if service_name:
                    service_targets.setdefault(service_name, []).append((node.host, int(replica.host_port)))
            service_targets = {
                service: list(dict.fromkeys(values))
                for service, values in service_targets.items() if values
            }
            route_groups = _route_groups_for_services(project, service_targets)
            domain_config = db.get(ProjectDomainConfig, project.id)
            defaults = db.get(DeploymentSettings, "default")
            deployment.access_url = configure_platform_gateway(
                db, deployment, node, deployment.host_port, project.domain,
                http_port=domain_config.http_port if domain_config else (defaults.default_domain_http_port if defaults else 80),
                https_enabled=domain_config.https_enabled if domain_config else False,
                https_port=domain_config.https_port if domain_config else (defaults.default_domain_https_port if defaults else 443),
                redirect_https=domain_config.redirect_https if domain_config else True,
                certificate=decrypt(domain_config.certificate_encrypted) if domain_config else None,
                private_key=decrypt(domain_config.private_key_encrypted) if domain_config else None,
                upstreams=targets,
                route_groups=route_groups or None,
                strategy=project.load_balance_strategy,
            )
            for replica in removed:
                ssh.run(f"docker rm -f {shlex.quote(replica.container_name)} >/dev/null 2>&1 || true")
                db.delete(replica)
            project.replica_count = body.replicas
            project.load_balance_enabled = body.replicas > 1
            deployment.container_name = base_name
            if promoted:
                deployment.log_text = ((deployment.log_text or "") +
                    f"\n[实例接管] 原主实例已停止，健康副本 {base_name} 已提升为主实例。\n"
                )[-200_000:]
            audit(db, user, "scale_project", "project", project.id,
                  f"replicas={current}->{body.replicas}; services={service_targets}")
            db.commit()
            invalidate_runtime_cache(deployment.id)
        except Exception as exc:
            db.rollback()
            for replica in created:
                ssh.run(f"docker rm -f {shlex.quote(replica.container_name)} >/dev/null 2>&1 || true")
            raise HTTPException(502, f"扩缩容未完成，原有实例继续运行：{exc}") from exc
    return {"ok": True, "desired": body.replicas, "ready": body.replicas, "access_url": deployment.access_url,
            "instances": [{"name": base_name, "port": deployment.host_port, "status": "running"}] +
                         [{"name": x.container_name, "port": x.host_port, "status": x.status} for x in active]}


def scale_single_service(item_id: str, service_name: str, body: ScaleProjectIn, db: Session, user: User):
    project = db.get(Project, item_id)
    if not project:
        raise HTTPException(404, "项目不存在")
    service_name = service_name.strip()
    role, scalable = _service_role(project, service_name)
    if not service_name or not scalable or role in {"data", "worker"} or _NON_SCALABLE_SERVICES.search(service_name):
        raise HTTPException(409, "该服务属于数据或后台任务服务，不能使用普通实例扩缩容")
    deployment = db.scalar(select(Deployment).where(
        Deployment.project_id == item_id,
        Deployment.status == DeployStatus.success,
    ).order_by(desc(Deployment.created_at)))
    if not deployment:
        raise HTTPException(409, "项目尚无可扩容的运行版本")
    node = db.get(Node, deployment.node_id)
    if not node:
        raise HTTPException(404, "部署节点不存在")
    compose_project = deployment_compose_project_name(deployment, project)
    all_rows = db.scalars(select(ProjectReplica).where(
        ProjectReplica.project_id == item_id,
        ProjectReplica.deployment_id == deployment.id,
    ).order_by(ProjectReplica.created_at)).all()
    known_replica_names = {row.container_name for row in all_rows}
    created: list[ProjectReplica] = []
    removed: list[ProjectReplica] = []
    runtime_policy = db.get(DeploymentSettings, "default")
    runtime_namespace = (runtime_policy.registry_namespace if runtime_policy else "yunzhou") or "yunzhou"
    with SSHNode(node) as ssh:
        names_code, names_output = ssh.run("docker ps -a --format '{{.Names}}'", timeout=30)
        if names_code:
            raise HTTPException(502, "读取现有容器名称失败，不能安全分配实例序号")
        existing_names = set(filter(None, map(str.strip, names_output.splitlines())))
        code, output = ssh.run(
            "docker ps --filter " + shlex.quote("label=com.docker.compose.project=" + compose_project) +
            " --format '{{json .}}'"
        )
        if code:
            raise HTTPException(502, "读取运行服务失败")
        service_specs: dict[str, tuple[str, dict, int, int]] = {}
        for line in output.splitlines():
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            name = str(row.get("Names") or row.get("Name") or "")
            if not name:
                continue
            inspect_code, inspect_output = ssh.run(f"docker inspect {shlex.quote(name)}")
            if inspect_code:
                continue
            try:
                spec = json.loads(inspect_output)[0]
            except (json.JSONDecodeError, IndexError):
                continue
            labels = spec.get("Config", {}).get("Labels") or {}
            service = str(labels.get("com.docker.compose.service") or labels.get("yunzhou.service") or "")
            if not service:
                continue
            published_port = 0
            container_port = 0
            for port_key, bindings in (spec.get("NetworkSettings", {}).get("Ports") or {}).items():
                for binding in bindings or []:
                    if str(binding.get("HostPort") or "").isdigit():
                        published_port = int(binding["HostPort"])
                        container_port = int(str(port_key).split("/")[0])
                        break
                if published_port:
                    break
            # A later request must continue using the Compose-owned primary,
            # not one of the numbered instances created by this endpoint.
            current_spec = service_specs.get(service)
            if current_spec is None or (current_spec[0] in known_replica_names and name not in known_replica_names):
                service_specs[service] = (name, spec, published_port, container_port)
        if service_name not in service_specs:
            raise HTTPException(404, "当前运行版本中没有找到该服务")
        base_name, spec, base_port, container_port = service_specs[service_name]
        if not base_port or not container_port:
            raise HTTPException(409, "该服务尚未由平台分配独立入口端口，请重新发布后再扩容")
        replicas = [row for row in all_rows if row.service_name == service_name]
        current = 1 + len(replicas)
        image = spec.get("Config", {}).get("Image")
        env = [value for value in (spec.get("Config", {}).get("Env") or []) if not value.startswith("HOSTNAME=")]
        networks = list((spec.get("NetworkSettings", {}).get("Networks") or {}).keys())
        network = networks[0] if networks else "bridge"
        if not image:
            raise HTTPException(409, "服务镜像无法识别，已拒绝盲目扩容")
        try:
            if body.replicas > current:
                policy = db.get(DeploymentSettings, "default")
                port_end = policy.internal_port_end if policy else 39999
                for _ in range(body.replicas - current):
                    name = _next_service_instance_name(
                        project.slug, service_name, existing_names, minimum=2,
                        release=deployment.release, namespace=runtime_namespace,
                    )
                    port = choose_port(db, None)
                    while port <= port_end:
                        occupied, _ = ssh.run(
                            "(ss -ltnH 2>/dev/null | awk '{print $4}' | "
                            f"grep -Eq ':{port}$') || "
                            "(docker ps --format '{{.Ports}}' 2>/dev/null | "
                            f"grep -Eq '(^|[^0-9]){port}->')"
                        )
                        if occupied != 0:
                            break
                        port += 1
                    if port > port_end:
                        raise RuntimeError("目标服务器内网实例端口池已被占满")
                    env_args = " ".join("-e " + shlex.quote(value) for value in env)
                    mount_args = []
                    for mount in spec.get("Mounts") or []:
                        destination = mount.get("Destination")
                        source = mount.get("Name") if mount.get("Type") == "volume" else mount.get("Source")
                        if not source or not destination:
                            continue
                        mode = "" if mount.get("RW", True) else ",readonly"
                        mount_args.append("--mount " + shlex.quote(f"type={mount.get('Type')},src={source},dst={destination}{mode}"))
                    command = (
                        f"docker create --name {shlex.quote(name)} --restart unless-stopped "
                        f"--label {shlex.quote('com.docker.compose.project=' + compose_project)} "
                        f"--label {shlex.quote('com.docker.compose.service=' + service_name)} "
                        f"--label {shlex.quote('yunzhou.service=' + service_name)} "
                        f"--network {shlex.quote(network)} {env_args} {' '.join(mount_args)} "
                        f"-p {port}:{container_port} {shlex.quote(image)}"
                    )
                    run_code, run_output = ssh.run(command, timeout=60)
                    if run_code:
                        raise RuntimeError(run_output)
                    # Compose application services may join both a release
                    # network and a stable data-service network. Copy every
                    # network from the primary before starting the candidate;
                    # otherwise a healthy process can wait forever for Redis
                    # or MySQL while its published HTTP port stays closed.
                    for extra_network in networks[1:]:
                        connect_code, connect_output = ssh.run(
                            f"docker network connect {shlex.quote(extra_network)} {shlex.quote(name)}",
                            timeout=30,
                        )
                        if connect_code:
                            ssh.run(f"docker rm -f {shlex.quote(name)} >/dev/null 2>&1 || true")
                            raise RuntimeError(f"副本接入网络 {extra_network} 失败：{connect_output.strip()}")
                    start_code, start_output = ssh.run(f"docker start {shlex.quote(name)}", timeout=30)
                    if start_code:
                        ssh.run(f"docker rm -f {shlex.quote(name)} >/dev/null 2>&1 || true")
                        raise RuntimeError(start_output)
                    ready = False
                    # Runtime images may legitimately declare a 60-90 second
                    # health-check start period. The old 40 second HTTP-only
                    # probe removed a sound backend before Docker could mark it
                    # healthy. Honour both signals and keep the old instance in
                    # service while the candidate warms up.
                    for _ in range(60):
                        check, status = ssh.run(
                            f"curl -sS -o /dev/null -w '%{{http_code}}' --connect-timeout 2 --max-time 5 http://127.0.0.1:{port}/"
                        )
                        if check == 0 and status.strip().isdigit() and int(status.strip()) < 500:
                            ready = True
                            break
                        _, health = ssh.run(
                            "docker inspect --format "
                            + shlex.quote("{{if .State.Health}}{{.State.Health.Status}}{{else}}none:{{.State.Status}}{{end}}")
                            + " " + shlex.quote(name)
                        )
                        if health.strip().lower() == "healthy":
                            ready = True
                            break
                        if health.strip().lower() in {"exited", "dead", "none:exited", "none:dead"}:
                            break
                        time.sleep(2)
                    if not ready:
                        _, failure_state = ssh.run(
                            "docker inspect --format "
                            + shlex.quote("status={{.State.Status}} exit={{.State.ExitCode}} oom={{.State.OOMKilled}} error={{.State.Error}} health={{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}")
                            + " " + shlex.quote(name)
                        )
                        ssh.run(f"docker rm -f {shlex.quote(name)} >/dev/null 2>&1 || true")
                        evidence = failure_state.strip() or "状态无法读取"
                        raise RuntimeError(f"新实例 {name} 健康检查未通过（{evidence}）")
                    replica = ProjectReplica(
                        project_id=item_id, deployment_id=deployment.id, node_id=node.id,
                        container_name=name, host_port=port, service_name=service_name,
                        pool_role=role, container_port=container_port, status="running",
                    )
                    db.add(replica)
                    db.flush()
                    replicas.append(replica)
                    created.append(replica)
            elif body.replicas < current:
                remove_count = current - body.replicas
                removed = _replicas_for_scale_down(
                    replicas, project.slug, service_name, deployment.release, runtime_namespace,
                )[:remove_count]
            active = [row for row in replicas if row not in removed]
            service_targets: dict[str, list[tuple[str, int]]] = {}
            for service, (_, _, published, _) in service_specs.items():
                if published:
                    service_targets.setdefault(service, []).append((node.host, published))
            for row in all_rows + created:
                if row not in removed and row.service_name:
                    service_targets.setdefault(row.service_name, []).append((node.host, row.host_port))
            groups = _route_groups_for_services(project, service_targets)
            domain_config = db.get(ProjectDomainConfig, project.id)
            defaults = db.get(DeploymentSettings, "default")
            deployment.access_url = configure_platform_gateway(
                db, deployment, node, deployment.host_port or base_port, project.domain,
                http_port=domain_config.http_port if domain_config else (defaults.default_domain_http_port if defaults else 80),
                https_enabled=domain_config.https_enabled if domain_config else False,
                https_port=domain_config.https_port if domain_config else (defaults.default_domain_https_port if defaults else 443),
                redirect_https=domain_config.redirect_https if domain_config else True,
                certificate=decrypt(domain_config.certificate_encrypted) if domain_config else None,
                private_key=decrypt(domain_config.private_key_encrypted) if domain_config else None,
                route_groups=groups or None,
                strategy=project.load_balance_strategy,
            )
            for row in removed:
                ssh.run(f"docker rm -f {shlex.quote(row.container_name)} >/dev/null 2>&1 || true")
                db.delete(row)
            audit(db, user, "scale_project_service", "project", project.id,
                  f"service={service_name}; role={role}; replicas={current}->{body.replicas}")
            db.commit()
            invalidate_runtime_cache(deployment.id)
        except HTTPException:
            raise
        except Exception as exc:
            db.rollback()
            for row in created:
                ssh.run(f"docker rm -f {shlex.quote(row.container_name)} >/dev/null 2>&1 || true")
            raise HTTPException(502, f"扩缩容未完成，原有实例继续运行：{exc}") from exc
    return {
        "ok": True, "service": service_name, "role": role,
        "desired": body.replicas, "ready": body.replicas,
        "access_url": deployment.access_url,
        "instances": [{"name": base_name, "port": base_port, "status": "running", "primary": True}] + [
            {"name": row.container_name, "port": row.host_port, "status": row.status, "primary": False}
            for row in active
        ],
    }


