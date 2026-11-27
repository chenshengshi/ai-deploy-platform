"""Start and reactivate existing deployment releases."""

import re
import shlex

from sqlalchemy import select

from ..database import SessionLocal
from .runtime_policy import release_directories
from ..models import Deployment, DeploymentPortReservation, Node, Project
from ..ssh import SSHNode
from .compose_runtime import compose_file_args, remote_compose_files
from .data_services import start_project_data_services
from .gateway import platform_gateway_node
from .image_restore import restore_release_images
from .naming import compose_project_name, deployment_compose_project_name, project_directory
from .ports import prepare_stopped_release_ports, stopped_port_message, stopped_reservation_status
from .process_control import stop_tracked_process_groups


def stop_deployment(
    deployment: Deployment,
    project: Project,
    node: Node,
    *,
    preserve_runtime: bool = False,
    release_ports: bool = False,
) -> str:
    # A central image build may run on the platform server rather than the
    # target node. Stop that process group as part of the same user action.
    builder_stop = "平台构建节点无跟踪进程"
    with SessionLocal() as lookup_db:
        builder = platform_gateway_node(lookup_db)
    if builder:
        with SSHNode(builder) as builder_ssh:
            builder_stop = stop_tracked_process_groups(builder_ssh, deployment.id)
    with SSHNode(node) as ssh:
        target_stop = stop_tracked_process_groups(ssh, deployment.id)
        if preserve_runtime:
            # This branch cancels an unfinished candidate while an older
            # verified release keeps serving traffic. A candidate can already
            # have reached ``compose up`` (and can have pre-empted an old app
            # that owns an exclusive project volume), so it is incorrect to
            # assume that it owns no runtime. Remove only this release-scoped
            # Compose project. The caller then verifies/restarts the protected
            # successful release. Never use a project-wide name here.
            compose_project = deployment_compose_project_name(deployment, project)
            candidate_name = shlex.quote(deployment.container_name or "")
            compose_label = shlex.quote(f"com.docker.compose.project={compose_project}")
            code, cleanup_output = ssh.run(
                f"ids=$(docker ps -aq --filter label={compose_label}); "
                f"[ -z \"$ids\" ] || docker rm -f $ids >/dev/null; "
                + (f"docker rm -f {candidate_name} >/dev/null 2>&1 || true; " if deployment.container_name else "")
                + "true",
                timeout=120,
            )
            if code:
                raise RuntimeError("候选版本容器清理失败：" + cleanup_output[-800:])
            # Candidate reservations must also be released or later
            # deployments gradually exhaust the node's port pool.
            with SessionLocal() as reservation_db:
                for reservation in reservation_db.scalars(select(DeploymentPortReservation).where(
                    DeploymentPortReservation.deployment_id == deployment.id,
                    DeploymentPortReservation.status.in_(["reserved", "active"]),
                )).all():
                    reservation.status = "released"
                reservation_db.commit()
            return f"已终止本记录的部署进程并清理候选版本容器；线上版本不受影响（构建节点 {builder_stop}；目标节点 {target_stop}）"
        if deployment.image_name:
            code, out = ssh.run(f"docker rm -f {shlex.quote(deployment.container_name or '')} 2>&1 || true")
        else:
            compose_project = deployment_compose_project_name(deployment, project)
            legacy_project = compose_project_name(project.slug, namespace="yz")
            base = f"{node.work_dir.rstrip('/')}/{project_directory(project)}/{deployment.release}"
            legacy_base = f"{node.work_dir.rstrip('/')}/{project.slug}/{deployment.release}"
            _, resolved = ssh.run(
                f"if [ -d {shlex.quote(base)} ]; then printf %s {shlex.quote(base)}; "
                f"elif [ -d {shlex.quote(legacy_base)} ]; then printf %s {shlex.quote(legacy_base)}; fi"
            )
            actual_dir = resolved.strip()
            files = remote_compose_files(ssh, actual_dir) if actual_dir else []
            args = compose_file_args(files)
            if files:
                code, out = ssh.run(
                    f"cd {shlex.quote(actual_dir)} && docker compose -p {shlex.quote(compose_project)} {args} down"
                )
            else:
                # A failed cleanup or legacy release may leave labeled Compose
                # containers after its config directory has disappeared. Stop
                # the real runtime by ownership label so restart=unless-stopped
                # cannot keep it alive. Volumes and images remain untouched.
                compose_label = shlex.quote(f"com.docker.compose.project={compose_project}")
                code, out = ssh.run(
                    f"ids=$(docker ps -q --filter label={compose_label}); "
                    "[ -z \"$ids\" ] || docker stop $ids"
                )
            # Compatibility cleanup for releases created before project names
            # included their release. Match the exact config directory so an
            # unrelated legacy release cannot be stopped accidentally.
            legacy_release_path = shlex.quote("/" + str(deployment.release or "") + "/")
            _, legacy_out = ssh.run(
                "ids=$(docker ps --filter " + shlex.quote(f"label=com.docker.compose.project={legacy_project}") +
                " --format '{{.ID}}|{{.Label \"com.docker.compose.project.config_files\"}}' | "
                f"awk -F'|' -v r={legacy_release_path} 'index($2,r) {{print $1}}'); "
                "[ -z \"$ids\" ] || docker stop $ids"
            )
            out = (out or "") + (legacy_out or "")
        if code:
            raise RuntimeError(out)
        container = shlex.quote(deployment.container_name or '')
        project_name = shlex.quote(deployment_compose_project_name(deployment, project))
        verify = (
            f"running=$(docker ps -q --filter name=^{container}$); "
            f"compose=$(docker ps -q --filter label=com.docker.compose.project={project_name}); "
            "printf 'container=%s compose=%s process=0' \"$running\" \"$compose\""
        )
        verify_code, state = ssh.run(verify)
        if verify_code or "process=1" in state or re.search(r"container=\S+", state) or re.search(r"compose=\S+", state):
            raise RuntimeError("停止后复查发现仍有部署进程或容器运行：" + state.strip())
        with SessionLocal() as reservation_db:
            for reservation in reservation_db.scalars(select(DeploymentPortReservation).where(
                DeploymentPortReservation.deployment_id == deployment.id,
                DeploymentPortReservation.status.in_(["reserved", "active"]),
            )).all():
                # A normal user stop is a pause: keep every assigned port owned
                # by this release so another platform project cannot claim it.
                # Replacement versions, failed candidates and project deletion
                # opt into release_ports=True and return the ports to the pool.
                reservation.status = stopped_reservation_status(release_ports=release_ports)
            reservation_db.commit()
        port_result = stopped_port_message(release_ports=release_ports)
        return f"已终止部署进程并关闭容器，复查确认无残留，{port_result}（构建节点 {builder_stop}；目标节点 {target_stop}）"



def start_deployment(deployment: Deployment, project: Project, node: Node, db=None) -> str:
    """Start an existing stopped release and verify that Docker really runs it."""
    with SSHNode(node) as ssh:
        compose_project = deployment_compose_project_name(deployment, project)
        directories = release_directories(
            node.work_dir,
            project_directory(project),
            project.slug,
            deployment.release,
        )
        release_dir, legacy_dir = directories
        _, resolved = ssh.run(
            f"if [ -d {shlex.quote(release_dir)} ]; then printf %s {shlex.quote(release_dir)}; "
            f"elif [ -d {shlex.quote(legacy_dir)} ]; then printf %s {shlex.quote(legacy_dir)}; fi"
        )
        actual_dir = resolved.strip()
        if not actual_dir:
            raise RuntimeError("原发布目录不存在，无法重新启用；请重新部署项目")
        # A stopped release no longer owns the port numbers saved in its
        # historical Compose file.  Reconcile every published application
        # port against current reservations and the real node before any
        # container is started.  This covers both ordinary reactivation and
        # rollback and prevents Docker's "port is already allocated" error.
        port_update = prepare_stopped_release_ports(
            deployment, project, node, actual_dir, db,
        )
        data_start = start_project_data_services(project, node, actual_dir, db)
        if deployment.image_name:
            restore_release_images(db, deployment, project, node, ssh, [deployment.image_name])
            port = project.container_port
            if not port:
                code, exposed = ssh.run(f"docker image inspect -f '{{{{json .Config.ExposedPorts}}}}' {shlex.quote(deployment.image_name)}")
                match = re.search(r'\"(\d+)/(?:tcp|udp)\"', exposed) if code == 0 else None
                port = int(match.group(1)) if match else None
            if not port or not deployment.host_port:
                raise RuntimeError("缺少容器端口或外部端口，无法重新启用；请重新部署项目")
            env_file = actual_dir + "/.env.runtime"
            env_args = f"--env-file {shlex.quote(env_file)}" if ssh.run(f"test -f {shlex.quote(env_file)}")[0] == 0 else ""
            name = deployment.container_name or f"yz-{project.slug}"
            cmd = (
                f"docker rm -f {shlex.quote(name)} >/dev/null 2>&1 || true; "
                f"docker run -d --name {shlex.quote(name)} --restart unless-stopped {env_args} "
                f"-p {deployment.host_port}:{port} {shlex.quote(deployment.image_name)}"
            )
            code, output = ssh.run(cmd)
            if code:
                raise RuntimeError(output)
            code, state = ssh.run(f"docker inspect -f '{{{{.State.Status}}}}' {shlex.quote(name)}")
            if code or state.strip() != "running":
                raise RuntimeError("容器启动后状态异常：" + state.strip())
        else:
            files = remote_compose_files(ssh, actual_dir)
            if not files:
                raise RuntimeError("原发布目录中未找到 Compose 配置")
            code, configured_images = ssh.run(
                f"cd {shlex.quote(actual_dir)} && docker compose -p {shlex.quote(compose_project)} "
                f"{compose_file_args(files)} config --images"
            )
            if code:
                raise RuntimeError("无法读取历史版本镜像清单，请重新发布该项目")
            restored = restore_release_images(
                db, deployment, project, node, ssh,
                [line.strip() for line in configured_images.splitlines() if line.strip()],
            )
            code, output = ssh.run(
                f"cd {shlex.quote(actual_dir)} && docker compose -p {shlex.quote(compose_project)} "
                f"{compose_file_args(files)} up -d --no-build --remove-orphans"
            )
            if code:
                clean = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", output)
                raise RuntimeError("历史版本容器启动失败：" + clean[-800:])
            code, running = ssh.run(f"docker ps -q --filter label=com.docker.compose.project={shlex.quote(compose_project)}")
            if code or not running.strip():
                raise RuntimeError("Compose 执行完成，但未发现运行中的服务容器")
            # A running container is not yet a ready application (Spring Boot
            # commonly needs 10-30 seconds). Keep the start action pending
            # until the published port actually answers, so the UI cannot
            # report a false successful recovery followed by a 502.
            if deployment.host_port:
                probe = (
                    f"for i in $(seq 1 45); do "
                    f"code=$(curl -sS -o /dev/null -w '%{{http_code}}' --max-time 2 "
                    f"http://127.0.0.1:{int(deployment.host_port)}/ 2>/dev/null || true); "
                    f"case \"$code\" in 2*|3*|4*) exit 0;; esac; sleep 1; done; exit 1"
                )
                code, _ = ssh.run(probe, timeout=55)
                if code:
                    raise RuntimeError("容器已启动，但应用在 45 秒内未就绪；请查看容器日志")
        if db is not None:
            for reservation in db.scalars(select(DeploymentPortReservation).where(
                DeploymentPortReservation.deployment_id == deployment.id,
                DeploymentPortReservation.status == "reserved",
            )).all():
                reservation.status = "active"
            db.commit()
        restored_text = f"；已从平台仓库恢复 {len(restored)} 个旧镜像" if 'restored' in locals() and restored else ""
        port_text = f"；{port_update}" if port_update else ""
        return data_start + port_text + "；应用服务已启动，并确认容器处于运行状态" + restored_text




