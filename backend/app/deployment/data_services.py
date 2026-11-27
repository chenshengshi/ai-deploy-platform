"""Lifecycle management for stable project-owned data services."""

import re
import shlex

import yaml

from ..config import decrypt
from .integrations import data_service_names, environment_values
from .runtime_policy import data_compose_project
from ..models import DeploymentSettings, Node, Project
from ..ssh import SSHNode

def stop_project_data_services(project: Project, node: Node, db=None) -> str:
    """Stop a project's shared data containers without deleting their data.

    Release switching deliberately does not call this helper. It is reserved
    for an explicit project/service stop, where the user expects every runtime
    container (application, MySQL, Redis, and similar dependencies) to stop.
    """
    policy = db.get(DeploymentSettings, "default") if db is not None else None
    runtime_namespace = (policy.registry_namespace if policy else "yunzhou") or "yunzhou"
    data_project = data_compose_project(runtime_namespace, project.slug)
    with SSHNode(node) as ssh:
        label = shlex.quote(f"label=com.docker.compose.project={data_project}")
        _, existing = ssh.run(f"docker ps -aq --filter {label}", timeout=30)
        ids = [value for value in existing.split() if re.fullmatch(r"[0-9a-f]{12,64}", value)]
        if not ids:
            return "项目共享数据服务未运行"
        words = " ".join(shlex.quote(value) for value in ids)
        code, output = ssh.run(f"docker stop -t 30 {words}", timeout=max(60, 45 * len(ids)))
        if code:
            raise RuntimeError("项目共享数据服务停止失败：" + output[-800:])
        verify_code, running = ssh.run(f"docker ps -q --filter {label}", timeout=30)
        if verify_code or running.strip():
            raise RuntimeError("停止后复查发现 MySQL/Redis 等项目共享数据服务仍在运行")
    return f"已停止 {len(ids)} 个项目共享数据容器；数据卷和容器配置均已保留"


def remove_project_managed_data_service(project: Project, node: Node, service: str, db=None) -> str:
    """Remove one project-owned managed data service and its private volumes."""
    family = str(service or "").lower().strip()
    if family not in {"mysql", "redis", "postgres"}:
        raise ValueError("不支持的托管数据服务")
    policy = db.get(DeploymentSettings, "default") if db is not None else None
    runtime_namespace = (policy.registry_namespace if policy else "yunzhou") or "yunzhou"
    data_project = data_compose_project(runtime_namespace, project.slug)
    aliases = {"mysql": {"mysql", "mariadb", "db", "database"}, "redis": {"redis", "cache"}, "postgres": {"postgres", "postgresql"}}[family]
    with SSHNode(node) as ssh:
        project_label = shlex.quote(f"label=com.docker.compose.project={data_project}")
        _, rows = ssh.run(
            "for id in $(docker ps -aq --filter " + project_label + "); do "
            "svc=$(docker inspect -f '{{index .Config.Labels \"com.docker.compose.service\"}}' $id 2>/dev/null); "
            "printf '%s|%s\\n' \"$id\" \"$svc\"; done",
            timeout=30,
        )
        ids = []
        for row in rows.splitlines():
            container_id, _, service_name = row.partition("|")
            if re.fullmatch(r"[0-9a-f]{12,64}", container_id) and service_name.lower() in aliases:
                ids.append(container_id)
        if not ids:
            return f"未发现该项目的托管 {family.title()} 容器或数据卷"
        words = " ".join(shlex.quote(value) for value in ids)
        _, volume_rows = ssh.run(
            "for id in " + words + "; do docker inspect -f '{{range .Mounts}}{{if eq .Type \"volume\"}}{{.Name}}{{\"\\n\"}}{{end}}{{end}}' $id; done",
            timeout=30,
        )
        volumes = sorted({value.strip() for value in volume_rows.splitlines() if re.fullmatch(r"[A-Za-z0-9_.-]+", value.strip())})
        code, output = ssh.run(f"docker rm -f {words}", timeout=max(60, 45 * len(ids)))
        if code:
            raise RuntimeError(f"托管 {family.title()} 容器删除失败：" + output[-800:])
        removed_volumes = 0
        for volume in volumes:
            volume_code, _ = ssh.run(f"docker volume rm {shlex.quote(volume)}", timeout=30)
            if volume_code == 0:
                removed_volumes += 1
        inspect_code, _ = ssh.run(f"docker inspect {words}", timeout=20)
        if inspect_code == 0:
            raise RuntimeError(f"托管 {family.title()} 清理后复查发现仍有容器残留")
    return f"已删除该项目的托管 {family.title()} 容器 {len(ids)} 个、私有数据卷 {removed_volumes} 个；未影响其他数据服务"


def start_project_data_services(
    project: Project,
    node: Node,
    directory: str,
    db=None,
) -> str:
    """Start and verify the stable project data stack when a release needs it."""
    data_file = ".yunzhou.data.yml"
    policy = db.get(DeploymentSettings, "default") if db is not None else None
    runtime_namespace = (policy.registry_namespace if policy else "yunzhou") or "yunzhou"
    data_project = data_compose_project(runtime_namespace, project.slug)
    with SSHNode(node) as ssh:
        if ssh.run(f"test -f {shlex.quote(directory + '/' + data_file)}", timeout=20)[0] != 0:
            return "该版本没有独立的项目共享数据服务"
        _, data_yaml = ssh.run(f"cat {shlex.quote(directory + '/' + data_file)}", timeout=20)
        data_document = yaml.safe_load(data_yaml) or {}
        data_services = data_document.get("services") if isinstance(data_document, dict) else {}
        if not isinstance(data_services, dict):
            data_services = {}
        allowed_services = set(data_services)
        user_values = environment_values(decrypt(project.env_text_encrypted) or "")
        external_modes = {
            "mysql": user_values.get("YUNZHOU_MYSQL_MODE", "managed").lower() == "external",
            "redis": user_values.get("YUNZHOU_REDIS_MODE", "managed").lower() == "external",
            "postgres": user_values.get("YUNZHOU_POSTGRES_MODE", "managed").lower() == "external",
        }
        for family, external in external_modes.items():
            if external:
                allowed_services.difference_update(data_service_names(data_services, family))
        if not allowed_services:
            return "当前项目数据服务均已切换为外接，不启动历史版本的托管数据容器"
        service_args = " ".join(shlex.quote(value) for value in sorted(allowed_services))
        label = shlex.quote(f"label=com.docker.compose.project={data_project}")
        compose_prefix = (
            f"cd {shlex.quote(directory)} && docker compose -p {shlex.quote(data_project)} "
            f"-f {shlex.quote(data_file)}"
        )
        _, all_output = ssh.run(f"{compose_prefix} ps -aq {service_args}", timeout=20)
        all_ids = [value for value in all_output.split() if re.fullmatch(r"[0-9a-f]{12,64}", value)]
        _, running_output = ssh.run(f"{compose_prefix} ps -q {service_args}", timeout=20)
        running_ids = [value for value in running_output.split() if re.fullmatch(r"[0-9a-f]{12,64}", value)]
        if running_ids and len(running_ids) == len(all_ids):
            words = " ".join(shlex.quote(value) for value in running_ids)
            check_code, unhealthy = ssh.run(
                "bad=0; for id in " + words + "; do "
                "state=$(docker inspect -f '{{.State.Status}}' $id 2>/dev/null); "
                "health=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' $id 2>/dev/null); "
                "[ \"$state\" = running ] || bad=1; "
                "[ \"$health\" = none ] || [ \"$health\" = healthy ] || bad=1; done; "
                "exit $bad",
                timeout=30,
            )
            if check_code == 0:
                # Release rollback/start must not reconcile an already healthy
                # data stack with a historical Compose file. Even an innocent
                # `up -d` can recreate MySQL when old service metadata differs.
                return f"已复用健康的项目共享数据服务（{len(running_ids)} 个容器），未重建或重启"
        expected_services = sorted(allowed_services)
        reuse_stopped = bool(all_ids) and len(all_ids) == len(expected_services)
        if reuse_stopped:
            words = " ".join(shlex.quote(value) for value in all_ids)
            command = f"docker start {words}"
        else:
            command = (
                f"cd {shlex.quote(directory)} && "
                f"docker compose -p {shlex.quote(data_project)} -f {shlex.quote(data_file)} "
                f"up -d --no-build {service_args}"
            )
        code, output = ssh.run(command, timeout=300)
        if code:
            clean = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", output)
            raise RuntimeError("项目共享数据服务启动失败：" + clean[-800:])
        health = (
            f"cd {shlex.quote(directory)} && ok=0; "
            "for i in $(seq 1 60); do bad=0; "
            f"ids=$(docker compose -p {shlex.quote(data_project)} -f {shlex.quote(data_file)} ps -q {service_args}); "
            "[ -n \"$ids\" ] || bad=1; for id in $ids; do "
            "state=$(docker inspect -f '{{.State.Status}}' $id 2>/dev/null); "
            "health=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' $id 2>/dev/null); "
            "[ \"$state\" = running ] || bad=1; "
            "[ \"$health\" = none ] || [ \"$health\" = healthy ] || bad=1; done; "
            "[ \"$bad\" -eq 0 ] && { ok=1; break; }; sleep 2; done; "
            "[ \"$ok\" -eq 1 ]"
        )
        code, output = ssh.run(health, timeout=150)
        if code:
            raise RuntimeError("项目共享数据服务启动后未就绪：" + output[-800:])
        _, count = ssh.run(
            f"{compose_prefix} ps -q {service_args} | wc -l",
            timeout=20,
        )
    mode = "原有数据容器已重新启动" if reuse_stopped else "缺失的数据容器已按配置恢复"
    return f"{mode}并通过检查（{count.strip() or '0'} 个容器）"



