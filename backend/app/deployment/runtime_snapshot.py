"""Read live container, dependency and resource state for a deployment."""

from __future__ import annotations

import copy
import json
import re
import shlex

from fastapi import HTTPException
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from ..models import DeployStatus, Deployment, DeploymentSettings, Node, Project, ProjectReplica
from ..runtime_cache import (
    read_runtime_cache as _runtime_cache_read,
    runtime_cache_key as _runtime_cache_key,
    runtime_cache_lock,
    write_runtime_cache as _runtime_cache_write,
)
from ..runtime_topology import _service_role
from ..ssh import SSHNode
from .naming import deployment_compose_project_name, project_directory

def _docker_size_bytes(value: str) -> float:
    match = re.match(r"\s*([0-9.]+)\s*([kmgt]?i?b)", value or "", re.I)
    if not match:
        return 0
    units = {"b": 1, "kb": 1000, "kib": 1024, "mb": 1000**2, "mib": 1024**2, "gb": 1000**3, "gib": 1024**3, "tb": 1000**4, "tib": 1024**4}
    return float(match.group(1)) * units.get(match.group(2).lower(), 1)

def _human_bytes(value: float) -> str:
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if value < 1024 or unit == "TiB":
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024
    return "0 B"

def _runtime_snapshot_uncached(item: Deployment, db: Session) -> dict:
    project, node = db.get(Project, item.project_id), db.get(Node, item.node_id)
    if not project or not node:
        raise HTTPException(404, "��Ŀ��ڵ㲻����")
    release_dir = f"{node.work_dir.rstrip('/')}/{project_directory(project)}/{item.release}" if item.release else ""
    compose_project = deployment_compose_project_name(item, project)
    runtime_policy = db.get(DeploymentSettings, "default")
    runtime_namespace = (runtime_policy.registry_namespace if runtime_policy else "yunzhou") or "yunzhou"
    safe_namespace = re.sub(r"[^a-z0-9-]", "-", str(runtime_namespace).lower()).strip("-") or "yunzhou"
    data_compose_project = f"{safe_namespace}-{project.slug}-data"
    # Historical records never attach to the current runtime. New releases also
    # have a distinct Compose project name, which makes this ownership explicit.
    latest_success = db.scalar(select(Deployment).where(
        Deployment.project_id == item.project_id,
        Deployment.node_id == item.node_id,
        Deployment.status == DeployStatus.success,
    ).order_by(desc(Deployment.created_at)).limit(1))
    latest_runtime_record = db.scalar(select(Deployment).where(
        Deployment.project_id == item.project_id,
        Deployment.node_id == item.node_id,
        Deployment.status.in_([DeployStatus.success, DeployStatus.stopped]),
        Deployment.release.is_not(None),
        Deployment.access_url.is_not(None),
    ).order_by(desc(Deployment.created_at)).limit(1))
    owns_live_runtime = (
        item.status == DeployStatus.running
        or (item.status == DeployStatus.success and latest_success is not None and latest_success.id == item.id)
    )
    # When the application is stopped, the latest verified release remains the
    # anchor for project-shared MySQL/Redis inspection. Failed candidates must
    # not hide those still-running data containers from the project runtime.
    owns_project_data_runtime = owns_live_runtime or (
        item.status == DeployStatus.stopped
        and latest_success is None
        and latest_runtime_record is not None
        and latest_runtime_record.id == item.id
    )
    if not owns_project_data_runtime:
        return {
            "deployment_id": item.id,
            "project": {"id": project.id, "name": project.name, "slug": project.slug, "build_type": project.build_type},
            "node": {"id": node.id, "name": node.name, "host": node.host, "public_address": node.public_address, "work_dir": node.work_dir},
            "release": item.release,
            "release_dir": release_dir,
            "dependencies": {},
            "containers": [],
            "application_instances": 0,
            "ready_application_instances": 0,
            "resources": {"cpu_percent": 0, "cpu": "0.00%", "memory_bytes": 0, "memory_usage": "0 B"},
            "live_runtime": False,
            "runtime_message": "������ʷ������¼����������ǰ�������е�������",
        }
    containers, dependencies = [], {}
    replica_rows = db.scalars(select(ProjectReplica).where(
        ProjectReplica.deployment_id == item.id,
    ).order_by(ProjectReplica.created_at)).all()
    replica_names = {replica.container_name for replica in replica_rows}
    replica_by_name = {replica.container_name: replica for replica in replica_rows}
    with SSHNode(node) as ssh:
        if release_dir and not item.image_name:
            legacy_dir = f"{node.work_dir.rstrip('/')}/{project.slug}/{item.release}"
            _, resolved = ssh.run(f"if [ -d {shlex.quote(release_dir)} ]; then printf %s {shlex.quote(release_dir)}; elif [ -d {shlex.quote(legacy_dir)} ]; then printf %s {shlex.quote(legacy_dir)}; fi")
            if resolved.strip():
                release_dir = resolved.strip()
        # The database is the source of truth for the active application
        # instance.  After failover a healthy standalone replica may have been
        # promoted to primary even though the old Compose file still names the
        # stopped container.  Resolve the recorded container first, then fall
        # back to Compose discovery for ordinary multi-service releases.
        direct_code, direct_output = (1, "")
        # A recorded container name identifies the primary application, but a
        # Compose release can still own backend, Redis, MySQL and other sibling
        # services. Only standalone image deployments should short-circuit to
        # the single recorded container; Compose releases must enumerate the
        # complete Compose project.
        if item.container_name and item.image_name:
            direct_cmd = f"docker ps -a --filter name=^/{shlex.quote(item.container_name)}$ --format '{{{{json .}}}}'"
            direct_code, direct_output = ssh.run(direct_cmd)
        if item.image_name and direct_code == 0 and direct_output.strip():
            code, output = direct_code, direct_output
        elif item.image_name:
            code, output = direct_code, direct_output
        else:
            cmd = f"cd {shlex.quote(release_dir)} && docker compose -p {shlex.quote(compose_project)} ps --all --format json" if release_dir else "false"
            code, output = ssh.run(cmd)
            if code != 0:
                code, output = ssh.run(
                    f"docker ps -a --filter label=com.docker.compose.project={shlex.quote(compose_project)} --format '{{{{json .}}}}'"
                )
            config_cmd = f"cd {shlex.quote(release_dir)} && docker compose -p {shlex.quote(compose_project)} config --format json" if release_dir else "false"
            cfg_code, cfg_output = ssh.run(config_cmd)
            if cfg_code == 0:
                try:
                    cfg = json.loads(cfg_output)
                    for service, spec in cfg.get("services", {}).items():
                        raw = spec.get("depends_on", {})
                        dependencies[service] = list(raw.keys()) if isinstance(raw, dict) else list(raw or [])
                except Exception:
                    pass
        if code == 0 and output.strip():
            try:
                parsed = json.loads(output)
                rows = parsed if isinstance(parsed, list) else [parsed]
            except Exception:
                rows = []
                for line in output.splitlines():
                    try:
                        rows.append(json.loads(line))
                    except Exception:
                        continue
            for row in rows:
                containers.append({
                    "id": row.get("ID") or row.get("Id") or "",
                    "name": row.get("Name") or row.get("Names") or item.container_name or "",
                    "service": row.get("Service") or project.slug,
                    "image": row.get("Image") or item.image_name or "",
                    "state": row.get("State") or row.get("Status") or "unknown",
                    "status": row.get("Status") or row.get("State") or "unknown",
                    "ports": row.get("Ports") or row.get("Publishers") or "",
                })
        # Stateful dependencies live in a stable Compose project so upgrades
        # can replace the application without recreating its database volumes.
        # Include those containers in the same runtime snapshot; the frontend
        # presents them separately under Data Resources.
        data_code, data_output = ssh.run(
            f"docker ps -a --filter label=com.docker.compose.project={shlex.quote(data_compose_project)} --format '{{{{json .}}}}'"
        )
        if data_code == 0:
            for line in data_output.splitlines():
                try:
                    row = json.loads(line)
                except Exception:
                    continue
                name = row.get("Names") or row.get("Name") or ""
                if not name or any(current["name"] == name for current in containers):
                    continue
                labels = str(row.get("Labels") or "")
                matched_service = re.search(r"(?:^|,)com\.docker\.compose\.service=([^,]+)", labels)
                containers.append({
                    "id": row.get("ID") or row.get("Id") or "",
                    "name": name,
                    "service": matched_service.group(1) if matched_service else "data",
                    "image": row.get("Image") or "",
                    "state": row.get("State") or row.get("Status") or "unknown",
                    "status": row.get("Status") or row.get("State") or "unknown",
                    "ports": row.get("Ports") or "",
                })
        if replica_names:
            replica_cmd = "docker ps -a --format '{{json .}}' " + " ".join(
                f"--filter {shlex.quote('name=^/' + name + '$')}" for name in replica_names
            )
            replica_code, replica_output = ssh.run(replica_cmd)
            if replica_code == 0:
                for line in replica_output.splitlines():
                    try:
                        row = json.loads(line)
                    except Exception:
                        continue
                    name = row.get("Names") or row.get("Name") or ""
                    if name and not any(current["name"] == name for current in containers):
                        replica = replica_by_name.get(name)
                        containers.append({
                            "id": row.get("ID") or row.get("Id") or "",
                            "name": name, "service": (replica.service_name if replica else "") or project.slug,
                            "image": row.get("Image") or "",
                            "state": row.get("State") or row.get("Status") or "unknown",
                            "status": row.get("Status") or row.get("State") or "unknown",
                            "ports": row.get("Ports") or "",
                        })
        for container in containers:
            if container["name"] in replica_names:
                container["instance_role"] = "replica"
                replica = replica_by_name[container["name"]]
                container["service_role"] = replica.pool_role or _service_role(project, container["service"])[0]
                container["scalable"] = True
            elif _service_role(project, str(container.get("service") or ""))[1]:
                container["instance_role"] = "primary"
                container["service_role"] = _service_role(project, str(container.get("service") or ""))[0]
                container["scalable"] = True
            else:
                container["instance_role"] = "dependency"
                container["service_role"] = _service_role(project, str(container.get("service") or ""))[0]
                container["scalable"] = False
        running_names = [x["name"] for x in containers if x["name"] and ("running" in str(x["state"]).lower() or str(x["status"]).lower().startswith("up"))]
        stats_by_name = {}
        if running_names:
            stats_cmd = "docker stats --no-stream --format '{{json .}}' " + " ".join(shlex.quote(name) for name in running_names)
            stats_code, stats_output = ssh.run(stats_cmd, timeout=25)
            if stats_code == 0:
                for line in stats_output.splitlines():
                    try:
                        stat = json.loads(line)
                    except Exception:
                        continue
                    name = stat.get("Name") or stat.get("Container") or ""
                    usage, _, limit = (stat.get("MemUsage") or "").partition("/")
                    cpu_text = (stat.get("CPUPerc") or "0%").strip()
                    stats_by_name[name] = {
                        "cpu_percent": float(cpu_text.rstrip("%") or 0),
                        "cpu": cpu_text,
                        "memory_usage": usage.strip() or "0 B",
                        "memory_limit": limit.strip() or "��",
                        "memory_percent": (stat.get("MemPerc") or "0%").strip(),
                        "memory_bytes": _docker_size_bytes(usage),
                        "network_io": stat.get("NetIO") or "��",
                        "block_io": stat.get("BlockIO") or "��",
                        "pids": stat.get("PIDs") or "0",
                    }
        for container in containers:
            container["resources"] = stats_by_name.get(container["name"], {
                "cpu_percent": 0, "cpu": "0%", "memory_usage": "0 B", "memory_limit": "��",
                "memory_percent": "0%", "memory_bytes": 0, "network_io": "��", "block_io": "��", "pids": "0",
            })
    total_cpu = sum(x["resources"]["cpu_percent"] for x in containers)
    total_memory = sum(x["resources"]["memory_bytes"] for x in containers)
    application_instances = [x for x in containers if x.get("instance_role") in ("primary", "replica")]
    return {
        "deployment_id": item.id,
        "project": {"id": project.id, "name": project.name, "slug": project.slug, "build_type": project.build_type},
        "node": {"id": node.id, "name": node.name, "host": node.host, "public_address": node.public_address, "work_dir": node.work_dir},
        "release": item.release,
        "release_dir": release_dir,
        "dependencies": dependencies,
        "containers": containers,
        "application_instances": len(application_instances),
        "ready_application_instances": sum(1 for x in application_instances if "running" in str(x["state"]).lower() or str(x["status"]).lower().startswith("up")),
        "resources": {"cpu_percent": round(total_cpu, 2), "cpu": f"{total_cpu:.2f}%", "memory_bytes": total_memory, "memory_usage": _human_bytes(total_memory)},
        "live_runtime": bool(containers),
        "application_runtime": owns_live_runtime,
        "runtime_message": (
            "��ǰ����ӵ��ʵʱ���л�����" if owns_live_runtime
            else "Ӧ����ֹͣ����ǰ����ʾ��Ŀ�������ݷ���"
        ),
    }

def runtime_snapshot(item: Deployment, db: Session, force: bool = False) -> dict:
    """Return live Docker state with short-lived cross-endpoint deduplication."""
    key = _runtime_cache_key(item)
    if not force:
        cached = _runtime_cache_read(key)
        if cached is not None:
            return cached
    key_lock = runtime_cache_lock(key)
    # Project runtime and deployment runtime can arrive concurrently. Only one
    # request performs SSH/Docker discovery; the other waits for and reuses it.
    with key_lock:
        if not force:
            cached = _runtime_cache_read(key)
            if cached is not None:
                return cached
        result = _runtime_snapshot_uncached(item, db)
        _runtime_cache_write(key, result)
        return copy.deepcopy(result)

