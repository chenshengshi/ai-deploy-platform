"""Release-scoped runtime resource cleanup."""

import shlex

from .runtime_policy import release_directories, validate_release
from ..models import Deployment, Node, Project
from ..ssh import SSHNode
from .compose_runtime import compose_file_args, remote_compose_files
from .naming import compose_project_name, deployment_compose_project_name, project_directory


def delete_deployment_resources(
    deployment: Deployment,
    project: Project,
    node: Node,
    *,
    remove_compose_images: bool = False,
    remove_persistent_data: bool = False,
    preserve_runtime: bool = False,
) -> str:
    """Remove only the resources owned by one deployment release.

    Base/pulled images are deliberately retained. Compose build images use a
    project-wide name, so they are removed only when no other deployment for
    the same project/node remains.
    """
    if not project or not node:
        raise RuntimeError("项目或部署服务器已不存在，无法核验远端资源")
    release = validate_release(deployment.release)
    release_compose_project = deployment_compose_project_name(deployment, project)
    legacy_compose_project = compose_project_name(project.slug, namespace="yz")
    with SSHNode(node) as ssh:
        pid_file = f"/tmp/yunzhou-deploy-{deployment.id}.pid"
        commands = [
            f"if [ -s {shlex.quote(pid_file)} ]; then p=$(cat {shlex.quote(pid_file)}); "
            f"kill -TERM -- -$p 2>/dev/null || true; sleep 1; kill -KILL -- -$p 2>/dev/null || true; fi",
            f"rm -f -- {shlex.quote(pid_file)}",
        ]
        if deployment.container_name and not preserve_runtime:
            commands.append(f"docker rm -f {shlex.quote(deployment.container_name)} >/dev/null 2>&1 || true")
        if release and not preserve_runtime:
            # Failed/stopped Compose records from older platform versions may
            # not contain a primary container name and their release folder
            # may already be gone.  The Compose config-files label still ties
            # every residual container to the exact release, so remove only
            # those containers instead of touching a newer runtime.
            commands.append(
                "{ docker ps -a --filter " + shlex.quote(f"label=com.docker.compose.project={release_compose_project}") +
                " --format '{{.Names}}'; docker ps -a --filter " + shlex.quote(f"label=com.docker.compose.project={legacy_compose_project}") +
                " --format '{{.Names}}|{{.Label \"com.docker.compose.project.config_files\"}}' | "
                f"awk -F'|' -v r={shlex.quote('/' + release + '/')} 'index($2,r) {{print $1}}' | "
                "cut -d'|' -f1; } | sort -u | xargs -r docker rm -f >/dev/null 2>&1 || true"
            )
        release_dirs = release_directories(
            node.work_dir,
            project_directory(project),
            project.slug,
            release,
        )
        if release:
            if not deployment.image_name and not preserve_runtime:
                for path in dict.fromkeys(release_dirs):
                    volume_flag = " -v" if remove_persistent_data else ""
                    files = remote_compose_files(ssh, path)
                    if files:
                        commands.append(
                            f"cd {shlex.quote(path)} && docker compose -p {shlex.quote(release_compose_project)} "
                            f"{compose_file_args(files)} down{volume_flag} --remove-orphans"
                        )
            # A release folder is unique to this record. Remove both current and
            # legacy naming variants, but never the whole project directory.
            commands.extend(f"rm -rf -- {shlex.quote(path)}" for path in dict.fromkeys(release_dirs))
        if deployment.image_name:
            # Dockerfile deployments are tagged per release and are safe to remove exactly.
            commands.append(f"docker image rm -f {shlex.quote(deployment.image_name)} >/dev/null 2>&1 || true")
        elif release:
            # Compose application images are immutable per release too. Delete
            # only the exact tag owned by this record even when newer records
            # of the same project remain; the old all-or-nothing rule leaked
            # every deleted historical tag until the final record vanished.
            prefixes = (
                f"yunzhou/{project.slug}-", f"yz-{project.slug}-",
                f"{project.slug}-",
            )
            commands.append(
                "refs=$(docker images --format '{{.Repository}}|{{.Tag}}' | "
                f"awk -F'|' -v t={shlex.quote(release)} "
                + " ".join(f"-v p{index}={shlex.quote(prefix)}" for index, prefix in enumerate(prefixes, start=1))
                + " '$2==t && (index($1,p1)==1 || index($1,p2)==1 || index($1,p3)==1) {print $1\":\"$2}'); "
                "[ -z \"$refs\" ] || printf '%s\n' \"$refs\" | xargs -r docker image rm -f >/dev/null 2>&1 || true"
            )
            commands.append("docker image prune -f >/dev/null 2>&1 || true")
        if remove_compose_images:
            # Only locally built Compose images use this prefix. Directly pulled
            # images such as nginx/postgres/python are never selected. Compose
            # may use an explicit image name, so prefer its ownership label.
            prefix = f"yz-{project.slug}-"
            central_prefix = f"yunzhou/{project.slug}-"
            compose_project = release_compose_project
            commands.append(
                "(docker images -q --filter " + shlex.quote(f"label=com.docker.compose.project={compose_project}") + "; "
                "docker images --format '{{.Repository}}:{{.Tag}}' | "
                f"awk -v p={shlex.quote(prefix)} -v c={shlex.quote(central_prefix)} "
                "'index($0,p)==1 || index($0,c)==1 {print}') | "
                "sort -u | xargs -r docker image rm -f >/dev/null 2>&1 || true"
            )
            commands.append("docker image prune -f >/dev/null 2>&1 || true")
            # The last release owns no remaining release directory. Remove the
            # human-readable and legacy project parents only when they are empty.
            parent_dirs = [
                f"{node.work_dir.rstrip('/')}/{project_directory(project)}",
                f"{node.work_dir.rstrip('/')}/{project.slug}",
            ]
            commands.extend(f"rmdir -- {shlex.quote(path)} 2>/dev/null || true" for path in dict.fromkeys(parent_dirs))
        code, output = ssh.run("set -e; " + "; ".join(commands))
        if code:
            raise RuntimeError(output or "服务器资源清理失败")
        checks = []
        if deployment.container_name and not preserve_runtime:
            checks.append(
                f"docker ps -aq --filter {shlex.quote('name=^/' + deployment.container_name + '$')} | grep -q . && exit 21 || true"
            )
        checks.extend(f"test ! -e {shlex.quote(path)} || exit 22" for path in release_dirs)
        if deployment.image_name:
            checks.append(f"docker image inspect {shlex.quote(deployment.image_name)} >/dev/null 2>&1 && exit 23 || true")
        elif release:
            checks.append(
                "docker images --format '{{.Repository}}|{{.Tag}}' | "
                f"awk -F'|' -v t={shlex.quote(release)} "
                f"-v p1={shlex.quote('yunzhou/' + project.slug + '-')} "
                f"-v p2={shlex.quote('yz-' + project.slug + '-')} "
                f"-v p3={shlex.quote(project.slug + '-')} "
                "'$2==t && (index($1,p1)==1 || index($1,p2)==1 || index($1,p3)==1) {found=1} END {exit !found}' "
                "&& exit 23 || true"
            )
        if remove_compose_images:
            checks.append(
                "{ docker images -q --filter " + shlex.quote(f"label=com.docker.compose.project={release_compose_project}") + "; "
                "docker images --format '{{.Repository}}' | "
                f"awk -v p={shlex.quote('yz-' + project.slug + '-')} -v c={shlex.quote('yunzhou/' + project.slug + '-')} "
                "'index($0,p)==1 || index($0,c)==1 {print}'; } | grep -q . && exit 23 || true"
            )
        verify_code, verify_output = ssh.run("; ".join(checks) if checks else "true")
        if verify_code:
            label = {21: "容器", 22: "发布目录", 23: "应用镜像"}.get(verify_code, "远端资源")
            raise RuntimeError(f"清理后复查发现{label}仍然存在：{verify_output.strip()}")
    removed = ["部署进程", "发布目录"]
    if not preserve_runtime:
        removed.append("容器")
    if deployment.image_name:
        removed.append("该版本应用镜像")
    elif release:
        removed.append("该版本 Compose 应用镜像")
    elif remove_compose_images:
        removed.append("该项目未被其他版本使用的 Compose 构建镜像")
    if remove_persistent_data:
        removed.append("Compose 持久化卷")
    return "、".join(removed) + "已清理并复查"




