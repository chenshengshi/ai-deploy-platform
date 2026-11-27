"""Project deletion preview and verified project-wide resource cleanup."""

from __future__ import annotations

import json
import shlex
import shutil
from pathlib import Path
from urllib.parse import quote, urlsplit

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from ..audit import audit
from ..auth import current_user, require
from ..config import settings
from ..database import get_db
from ..deployer import compose_project_name, platform_gateway_node, project_directory, stop_deployment
from ..deployment.registry import _delete_project_registry_repositories, _project_registry_repositories, _registry_request
from ..models import DeployStatus, Deployment, DeploymentSettings, Node, Project, ProjectReplica, Role, SourceType, User
from ..ssh import SSHNode

router = APIRouter()

@router.get("/api/projects/{item_id}/delete-preview")
def project_delete_preview(item_id: str, db: Session = Depends(get_db), _: User = Depends(current_user)):
    item = db.get(Project, item_id)
    if not item:
        raise HTTPException(404, "项目不存在")
    deployments = db.scalars(select(Deployment).where(Deployment.project_id == item_id).order_by(desc(Deployment.created_at))).all()
    nodes = {x.node_id: db.get(Node, x.node_id) for x in deployments}
    # Persistent volumes can outlive deployment records or remain on a node
    # after a project is moved. Scan every enabled deployment node so the
    # deletion preview is complete.
    for node in db.scalars(select(Node).where(Node.enabled == True)).all():
        nodes.setdefault(node.id, node)
    resources = {"deployments": [], "containers": [], "images": [], "registry_images": [], "directories": [], "volumes": [], "gateway_files": [], "source_origin": [], "source": []}
    runtime_policy = db.get(DeploymentSettings, "default")
    runtime_namespace = (runtime_policy.registry_namespace if runtime_policy else "yunzhou") or "yunzhou"
    runtime_project = compose_project_name(item.slug, namespace=runtime_namespace)
    if item.source_type == SourceType.git:
        parsed_source = urlsplit(item.git_url or "")
        safe_repository = (
            f"{parsed_source.scheme}://{parsed_source.hostname or ''}"
            f"{':' + str(parsed_source.port) if parsed_source.port else ''}{parsed_source.path}"
            if parsed_source.scheme and parsed_source.hostname else "Git 仓库"
        )
        resources["source_origin"].append({"name": f"Git 仓库 · {safe_repository}（仅解除关联，不删除远端仓库）"})
    else:
        resources["source_origin"].append({"name": "平台上传源码（删除项目时一并清理）"})
    gateway_candidates = []
    gateway_candidates.extend([
        f"/data/yunzhou-control/data/gateway/conf.d/project-{item.id}.conf",
        f"/data/yunzhou-control/data/gateway/certs/project-{item.id}.crt",
        f"/data/yunzhou-control/data/gateway/certs/project-{item.id}.key",
    ])
    warnings = []
    try:
        for repository in _project_registry_repositories(db, item):
            tags = _registry_request("GET", f"/{quote(repository, safe='/')}/tags/list").json().get("tags") or []
            resources["registry_images"].extend({"name": f"{repository}:{tag}", "node": "平台镜像仓库"} for tag in tags)
    except Exception as exc:
        warnings.append(f"平台镜像仓库查询失败：{exc}")
    for dep in deployments:
        node = nodes.get(dep.node_id)
        resources["deployments"].append({"id": dep.id, "release": dep.release, "status": dep.status.value, "node": node.name if node else "节点已删除"})
        if dep.container_name:
            resources["containers"].append({"name": dep.container_name, "node": node.name if node else "未知节点"})
        if dep.image_name:
            resources["images"].append({"name": dep.image_name, "node": node.name if node else "未知节点"})
        if node and dep.release:
            resources["directories"].append({"path": f"{node.work_dir.rstrip('/')}/{project_directory(item)}/{dep.release}", "node": node.name})
        gateway_candidates.extend([
            f"/data/yunzhou-control/data/gateway/conf.d/{dep.id}.conf",
            f"/data/yunzhou-control/data/gateway/certs/{dep.id}.crt",
            f"/data/yunzhou-control/data/gateway/certs/{dep.id}.key",
        ])
    for node_id, node in nodes.items():
        if not node:
            continue
        try:
            with SSHNode(node) as ssh:
                _, compose_images = ssh.run("docker images --format '{{.Repository}}:{{.Tag}}' --filter " + shlex.quote(f"label=com.docker.compose.project=yz-{item.slug}"), timeout=20)
                for name in filter(None, map(str.strip, compose_images.splitlines())):
                    entry = {"name": name, "node": node.name}
                    if entry not in resources["images"]:
                        resources["images"].append(entry)
                # Central builds and imported target images keep the stable
                # yunzhou namespace even when deployment records or Compose
                # labels no longer exist. Always scan the real image store.
                _, named_images = ssh.run("docker images --format '{{.Repository}}:{{.Tag}}'", timeout=20)
                image_root = f"yunzhou/{item.slug}"
                for name in filter(None, map(str.strip, named_images.splitlines())):
                    repository = name.rsplit(":", 1)[0]
                    if repository != image_root and not repository.startswith(image_root + "-"):
                        continue
                    entry = {"name": name, "node": node.name}
                    if entry not in resources["images"]:
                        resources["images"].append(entry)
                _, compose_containers = ssh.run("docker ps -a --format '{{.Names}}' --filter " + shlex.quote(f"label=com.docker.compose.project=yz-{item.slug}"), timeout=20)
                for name in filter(None, map(str.strip, compose_containers.splitlines())):
                    entry = {"name": name, "node": node.name}
                    if entry not in resources["containers"]:
                        resources["containers"].append(entry)
                _, named_containers = ssh.run("docker ps -a --format '{{.Names}}'", timeout=20)
                container_prefix = f"yz-{item.slug}-"
                for name in filter(None, map(str.strip, named_containers.splitlines())):
                    if not name.startswith(container_prefix):
                        continue
                    entry = {"name": name, "node": node.name}
                    if entry not in resources["containers"]:
                        resources["containers"].append(entry)
                _, current_containers = ssh.run(
                    "docker ps -a --format '{{.Names}}|{{.Label \"com.docker.compose.project\"}}'",
                    timeout=20,
                )
                for row in filter(None, map(str.strip, current_containers.splitlines())):
                    name, _, owner = row.partition("|")
                    if not (
                        name.startswith(runtime_project + "-")
                        or owner == runtime_project + "-data"
                        or owner.startswith(runtime_project + "-")
                    ):
                        continue
                    entry = {"name": name, "node": node.name}
                    if entry not in resources["containers"]:
                        resources["containers"].append(entry)
                _, volumes = ssh.run("docker volume ls -q", timeout=20)
                prefixes = (f"yz-{item.slug}", runtime_project)
                for name in filter(None, map(str.strip, volumes.splitlines())):
                    if not any(name == prefix or name.startswith(prefix + "_") or name.startswith(prefix + "-") for prefix in prefixes):
                        _, label = ssh.run("docker volume inspect -f " + shlex.quote('{{index .Labels "com.docker.compose.project"}}') + " " + shlex.quote(name), timeout=10)
                        if label.strip() not in prefixes and not label.strip().startswith(runtime_project + "-"):
                            continue
                    resources["volumes"].append({"name": name, "node": node.name})
        except Exception as exc:
            warnings.append(f"{node.name} 查询失败：{exc}")
    gateway = platform_gateway_node(db)
    if gateway and gateway_candidates:
        try:
            with SSHNode(gateway) as ssh:
                checks = "; ".join(f"test -e {shlex.quote(path)} && printf '%s\\n' {shlex.quote(path)} || true" for path in gateway_candidates)
                _, existing = ssh.run(checks, timeout=20)
                resources["gateway_files"] = list(dict.fromkeys(filter(None, map(str.strip, existing.splitlines()))))
        except Exception as exc:
            warnings.append(f"平台网关文件查询失败：{exc}")
    source_root = Path(settings.upload_root) / item.id
    if source_root.exists():
        resources["source"].append(str(source_root))
    return {
        "project": {"id": item.id, "name": item.name, "slug": item.slug},
        "resources": resources,
        "counts": {key: len(value) for key, value in resources.items()},
        "warnings": warnings,
        "ai_summary": (
            f"系统已查询到 {len(deployments)} 条发布记录、{len(resources['containers'])} 个容器、"
            f"{len(resources['images'])} 个节点应用镜像、{len(resources['registry_images'])} 个镜像仓库版本。"
            "删除项目会先停止运行服务，再逐项清理并复查。"
        ),
    }


@router.delete("/api/projects/{item_id}")
def delete_project(item_id: str, remove_data: bool = False, delete_volumes: str | None = None, keep_project: bool = False, db: Session = Depends(get_db), user: User = Depends(require(Role.admin, Role.deployer))):
    item = db.get(Project, item_id)
    if not item:
        raise HTTPException(404, "项目不存在")
    deployments = db.scalars(select(Deployment).where(Deployment.project_id == item_id).order_by(Deployment.created_at)).all()
    replicas = db.scalars(select(ProjectReplica).where(ProjectReplica.project_id == item_id)).all()
    cleanup_results = []
    retained_volumes = []
    discovered_volumes = []
    runtime_policy = db.get(DeploymentSettings, "default")
    runtime_namespace = (runtime_policy.registry_namespace if runtime_policy else "yunzhou") or "yunzhou"
    runtime_project = compose_project_name(item.slug, namespace=runtime_namespace)
    try:
        selected_volume_names = set(json.loads(delete_volumes)) if delete_volumes is not None else None
        if selected_volume_names is not None and not all(isinstance(name, str) for name in selected_volume_names):
            raise ValueError
    except Exception:
        raise HTTPException(400, "数据卷选择无效，请重新打开删除窗口")
    try:
        # Replica containers are platform-created resources and are not part of
        # the original Compose release. Remove both recorded replicas and any
        # matching orphan discovered on every node used by this project.
        replica_names_by_node: dict[str, set[str]] = {}
        for replica in replicas:
            replica_names_by_node.setdefault(replica.node_id, set()).add(replica.container_name)
        for dep in deployments:
            replica_names_by_node.setdefault(dep.node_id, set())
        for node_id, recorded_names in replica_names_by_node.items():
            node = db.get(Node, node_id)
            if not node:
                continue
            with SSHNode(node) as ssh:
                _, discovered = ssh.run(
                    "docker ps -a --format '{{.Names}}' --filter "
                    + shlex.quote(f"name=^/yz-{item.slug}-replica-")
                )
                names = recorded_names | {name.strip() for name in discovered.splitlines() if name.strip()}
                for name in sorted(names):
                    ssh.run(f"docker rm -f {shlex.quote(name)} >/dev/null 2>&1 || true")
                if names:
                    _, remaining = ssh.run(
                        "docker ps -aq " + " ".join(
                            f"--filter {shlex.quote('name=^/' + name + '$')}" for name in sorted(names)
                        )
                    )
                    if remaining.strip():
                        raise RuntimeError("应用副本容器清理后仍然存在：" + ", ".join(sorted(names)))
                    cleanup_results.append(f"{len(names)} 个应用副本容器已清理并复查")
        # Inventory persistent data before stopping releases.  Historical
        # Compose versions did not always leave ownership labels behind, so a
        # safe platform name prefix is also recognised.
        volume_nodes = {dep.node_id: db.get(Node, dep.node_id) for dep in deployments}
        for node in db.scalars(select(Node).where(Node.enabled == True)).all():
            volume_nodes.setdefault(node.id, node)
        for node in volume_nodes.values():
            if not node:
                continue
            with SSHNode(node) as ssh:
                _, output = ssh.run("docker volume ls -q", timeout=20)
                prefixes = (f"yz-{item.slug}", runtime_project)
                names = []
                for name in filter(None, map(str.strip, output.splitlines())):
                    owned = any(name == prefix or name.startswith(prefix + "_") or name.startswith(prefix + "-") for prefix in prefixes)
                    if not owned:
                        _, label = ssh.run("docker volume inspect -f " + shlex.quote('{{index .Labels "com.docker.compose.project"}}') + " " + shlex.quote(name), timeout=10)
                        owned = label.strip() in prefixes or label.strip().startswith(runtime_project + "-")
                    if owned:
                        names.append(name)
            discovered_volumes.extend({"name": name, "node_id": node.id, "node": node.name} for name in names)
        if selected_volume_names is None:
            selected_volume_names = {volume["name"] for volume in discovered_volumes} if remove_data else set()
        known_names = {volume["name"] for volume in discovered_volumes}
        if not selected_volume_names.issubset(known_names):
            raise RuntimeError("数据卷清单已经变化，请关闭窗口后重新核实")
        retained_volumes = [volume for volume in discovered_volumes if volume["name"] not in selected_volume_names]
        # Deleting a project is a project-wide operation.  Only queued/running
        # jobs need the normal stop path (task cancellation and port release).
        # Successful historical releases are removed by the single node sweep
        # below; cleaning every historical release first made deletion repeat
        # the same Docker/SSH work many times.
        for dep in deployments:
            node = db.get(Node, dep.node_id)
            if node and dep.status in (DeployStatus.queued, DeployStatus.running):
                cleanup_results.append(stop_deployment(dep, item, node, release_ports=True))
            if dep.status in (DeployStatus.queued, DeployStatus.running, DeployStatus.success):
                dep.status = DeployStatus.stopped
        db.flush()
        # A release record can be removed independently or an interrupted
        # operation can fail before it is committed. Reconcile the real Docker
        # state on every node instead of trusting database records alone.
        for cleanup_node in db.scalars(select(Node).where(Node.enabled == True)).all():
            with SSHNode(cleanup_node) as ssh:
                image_root = f"yunzhou/{item.slug}"
                container_prefix = f"yz-{item.slug}-"
                compose_project = f"yz-{item.slug}"
                project_dirs = list(dict.fromkeys([
                    f"{cleanup_node.work_dir.rstrip('/')}/{project_directory(item)}",
                    f"{cleanup_node.work_dir.rstrip('/')}/{item.slug}",
                ]))
                command = (
                    "ids=$(docker ps -aq --filter " + shlex.quote(f"label=com.docker.compose.project={compose_project}") + "); "
                    "current=$(docker ps -a --format '{{.ID}}|{{.Label \"com.docker.compose.project\"}}' | "
                    f"awk -F'|' -v p={shlex.quote(runtime_project)} '$2==p\"-data\" || index($2,p\"-\")==1 {{print $1}}'); "
                    f"named=$(docker ps -a --format '{{{{.Names}}}}' | awk -v p={shlex.quote(container_prefix)} -v q={shlex.quote(runtime_project + '-')} 'index($0,p)==1 || index($0,q)==1 {{print}}'); "
                    "all=$(printf '%s\\n%s\\n%s\\n' \"$ids\" \"$current\" \"$named\" | sed '/^$/d' | sort -u); "
                    "[ -z \"$all\" ] || docker rm -f $all >/dev/null; "
                    "networks=$(docker network ls --format '{{.ID}}|{{.Label \"com.docker.compose.project\"}}' | "
                    f"awk -F'|' -v p={shlex.quote(runtime_project)} '$2==p\"-data\" || index($2,p\"-\")==1 {{print $1}}'); "
                    "[ -z \"$networks\" ] || docker network rm $networks >/dev/null 2>&1 || true; "
                    "images=$(docker images --format '{{.Repository}}:{{.Tag}}' | "
                    f"awk -F: -v r={shlex.quote(image_root)} '$1==r || index($1,r\"-\")==1 {{print}}'); "
                    "[ -z \"$images\" ] || printf '%s\\n' \"$images\" | xargs -r docker image rm -f >/dev/null; "
                    + "; ".join(f"rm -rf -- {shlex.quote(path)}" for path in project_dirs) + "; "
                    "docker image prune -f >/dev/null 2>&1 || true; "
                    "left_images=$(docker images --format '{{.Repository}}' | "
                    f"awk -v r={shlex.quote(image_root)} '$1==r || index($1,r\"-\")==1 {{print}}'); "
                    "left_containers=$(docker ps -a --format '{{.Names}}|{{.Label \"com.docker.compose.project\"}}' | "
                    f"awk -F'|' -v p={shlex.quote(container_prefix)} -v q={shlex.quote(runtime_project)} 'index($1,p)==1 || $2==q\"-data\" || index($2,q\"-\")==1 {{print}}'); "
                    "[ -z \"$left_images$left_containers\" ]"
                )
                code, output = ssh.run(command, timeout=180)
                if code:
                    raise RuntimeError(output or f"{cleanup_node.name} 项目镜像或容器清理后仍有残留")
                cleanup_results.append(f"{cleanup_node.name} 的真实容器、项目镜像和发布目录已清理并复查")
        deleted_volumes = [volume for volume in discovered_volumes if volume["name"] in selected_volume_names]
        if deleted_volumes:
            by_node: dict[str, list[str]] = {}
            for volume in deleted_volumes:
                by_node.setdefault(volume["node_id"], []).append(volume["name"])
            for node_id, names in by_node.items():
                node = db.get(Node, node_id)
                if not node:
                    continue
                with SSHNode(node) as ssh:
                    command = "; ".join(
                        f"docker volume rm -f {shlex.quote(name)} >/dev/null && ! docker volume inspect {shlex.quote(name)} >/dev/null 2>&1"
                        for name in names
                    )
                    code, output = ssh.run(command or "true", timeout=60)
                    if code:
                        raise RuntimeError(output or f"{node.name} 数据卷清理后复查失败")
            cleanup_results.append(f"{len(deleted_volumes)} 个平台数据卷已清理")
        if retained_volumes:
            cleanup_results.append(
                f"按用户选择保留 {len(retained_volumes)} 个数据卷："
                + "、".join(volume["name"] for volume in retained_volumes)
            )
        gateway = platform_gateway_node(db)
        if gateway:
            gateway_keys = [f"project-{item.id}", *(dep.id for dep in deployments)]
            ids = " ".join(shlex.quote(value) for value in gateway_keys)
            with SSHNode(gateway) as ssh:
                code, output = ssh.run(
                    "for id in " + ids + "; do rm -f -- /data/yunzhou-control/data/gateway/conf.d/$id.conf /data/yunzhou-control/data/gateway/certs/$id.crt /data/yunzhou-control/data/gateway/certs/$id.key; done; "
                    "docker exec yunzhou-platform-gateway nginx -t && docker exec yunzhou-platform-gateway nginx -s reload; "
                    "for id in " + ids + "; do test ! -e /data/yunzhou-control/data/gateway/conf.d/$id.conf && test ! -e /data/yunzhou-control/data/gateway/certs/$id.crt && test ! -e /data/yunzhou-control/data/gateway/certs/$id.key || exit 45; done",
                    timeout=30,
                )
                if code:
                    raise RuntimeError(output or "平台网关文件清理失败")
                cleanup_results.append("平台网关配置、证书和监听已清理并复查")
        # Images are built centrally on the platform host before being copied
        # to a target node. They are not represented by target deployment
        # records, so remove them explicitly when the project is deleted.
        if gateway:
            with SSHNode(gateway) as ssh:
                central_prefix = f"yunzhou/{item.slug}-"
                builder_project_root = settings.build_data_root.rstrip('/') + '/builder/projects/' + item.slug
                builder_cleanup = (
                    f"rm -rf -- {shlex.quote(builder_project_root + '/runs')}; mkdir -p {shlex.quote(builder_project_root + '/runs')}"
                    if keep_project else
                    f"rm -rf -- {shlex.quote(builder_project_root)}"
                )
                code, output = ssh.run(
                    "images=$(docker images --format '{{.Repository}}:{{.Tag}}' | "
                    f"awk -v p={shlex.quote(central_prefix)} 'index($0,p)==1 {{print}}'); "
                    "if [ -n \"$images\" ]; then printf '%s\\n' \"$images\" | xargs -r docker image rm -f; fi; "
                    + builder_cleanup + "; "
                    "docker image prune -f >/dev/null 2>&1 || true; "
                    "docker images --format '{{.Repository}}' | "
                    f"awk -v p={shlex.quote(central_prefix)} 'index($0,p)==1 {{found=1}} END {{exit found ? 1 : 0}}'",
                    timeout=120,
                )
                if code:
                    raise RuntimeError(output or "平台构建镜像清理失败")
                cleanup_results.append(
                    "平台构建机上的项目镜像和临时运行目录已清理，源码及依赖缓存已保留"
                    if keep_project else
                    "平台构建机上的项目镜像及悬空镜像已清理并复查"
                )
        registry_cleanup = _delete_project_registry_repositories(db, item)
        if registry_cleanup["tags"]:
            cleanup_results.append(
                f"平台镜像仓库中的 {len(registry_cleanup['repositories'])} 个项目仓库、"
                f"{len(registry_cleanup['tags'])} 个镜像版本已清理并复查"
            )
        # A reset keeps the project definition and source credentials so the
        # user can immediately re-analyse or redeploy from a clean runtime.
        # Uploaded source belongs to that retained definition and must not be
        # removed in reset mode.
        if not keep_project:
            uploaded_source = Path(settings.upload_root) / item.id
            had_uploaded_source = uploaded_source.exists()
            shutil.rmtree(uploaded_source, ignore_errors=True)
            if had_uploaded_source:
                cleanup_results.append("平台上传的项目源码已删除")
    except Exception as exc:
        db.rollback()
        raise HTTPException(502, f"项目尚未删除，资源清理失败：{exc}")
    audit(db, user, "reset_project" if keep_project else "delete_project", "project", item_id, json.dumps({
        "project": item.name,
        "project_slug": item.slug,
        "deployment_count": len(deployments),
        "managed_volumes": "deleted" if not retained_volumes else ("preserved" if not selected_volume_names else "partially_preserved"),
        "retained_volumes": retained_volumes,
        "data_state": "retained" if retained_volumes else ("deleted" if discovered_volumes else "none"),
        "external_data": "preserved",
        "resources": [result.get("summary", str(result)) if isinstance(result, dict) else str(result) for result in cleanup_results],
    }, ensure_ascii=False))
    if keep_project:
        for replica in replicas:
            db.delete(replica)
        for deployment in deployments:
            db.delete(deployment)
        # Runtime-derived fields must not make the retained project appear to
        # be online. Source/build/integration configuration remains intact.
        cleanup_results.append("项目配置、源码、分支、凭据和外部集成设置已保留")
    else:
        db.delete(item)
    db.commit()
    return {
        "ok": True,
        "project_retained": keep_project,
        "summary": (
            f"项目运行资源及 {len(deployments)} 条发布记录已清空，项目配置已保留"
            if keep_project else
            f"项目及 {len(deployments)} 条发布记录已删除，远端资源已清理并复查"
        ),
        "details": cleanup_results,
    }

