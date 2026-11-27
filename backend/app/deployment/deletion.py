"""Deployment deletion preview and verified release resource cleanup."""

from __future__ import annotations

import json
import shlex

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..ai import analyze_delete_scope
from ..audit import audit
from ..auth import current_user, require
from ..database import get_db
from ..deployer import compose_project_name, delete_deployment_resources, deployment_compose_project_name, platform_gateway_node, project_directory
from ..models import DeployStatus, Deployment, Node, Project, ProjectReplica, Role, User
from ..ssh import SSHNode

router = APIRouter()

@router.get("/api/deployments/{item_id}/delete-preview")
def deployment_delete_preview(item_id: str, db: Session = Depends(get_db), _: User = Depends(current_user)):
    item = db.get(Deployment, item_id)
    if not item:
        raise HTTPException(404, "部署记录不存在")
    project, node = db.get(Project, item.project_id), db.get(Node, item.node_id)
    if not project or not node:
        raise HTTPException(409, "项目或部署服务器已不存在，无法核实资源")
    resources = {"containers": [], "images": [], "directories": [], "gateway_files": [], "records": []}
    warnings = []
    release_dirs = list(dict.fromkeys([
        f"{node.work_dir.rstrip('/')}/{project_directory(project)}/{item.release}",
        f"{node.work_dir.rstrip('/')}/{project.slug}/{item.release}",
    ])) if item.release else []
    def scan_images(scan_node: Node):
        with SSHNode(scan_node) as ssh:
            # Compose releases contain several images and older failed records
            # did not persist every image name.  Inspect the actual daemon by
            # release/project identity instead of trusting only the DB column.
            # Both conditions must match.  The previous grep used OR and made
            # every historical record claim all current project images.
            _, value = ssh.run(
                "docker images --no-trunc --format '{{.Repository}}:{{.Tag}}'",
                timeout=30,
            )
            for name in filter(None, map(str.strip, value.splitlines())):
                if ":" not in name:
                    continue
                repository, tag = name.rsplit(":", 1)
                repository_name = repository.rsplit("/", 1)[-1]
                project_match = repository_name == project.slug or repository_name.startswith(project.slug + "-")
                release_match = bool(item.release) and tag == item.release
                if not (project_match and release_match):
                    continue
                entry = {"name": name, "node": scan_node.name}
                if entry not in resources["images"]:
                    resources["images"].append(entry)

    try:
        with SSHNode(node) as ssh:
            if item.container_name:
                _, value = ssh.run(f"docker inspect {shlex.quote(item.container_name)} >/dev/null 2>&1 && printf '%s' {shlex.quote(item.container_name)} || true", timeout=20)
                if value.strip():
                    resources["containers"].append({"name": value.strip(), "node": node.name})
            if item.release:
                release_compose_project = deployment_compose_project_name(item, project)
                _, value = ssh.run(
                    "{ docker ps -a --filter " + shlex.quote(f"label=com.docker.compose.project={release_compose_project}") +
                    " --format '{{.Names}}'; docker ps -a --filter " + shlex.quote(f"label=com.docker.compose.project={compose_project_name(project.slug, namespace='yz')}") +
                    " --format '{{.Names}}|{{.Label \"com.docker.compose.project.config_files\"}}' | "
                    f"awk -F'|' -v r={shlex.quote('/' + item.release + '/')} 'index($2,r) {{print $1}}'; }} | sort -u",
                    timeout=20,
                )
                for name in filter(None, map(str.strip, value.splitlines())):
                    entry = {"name": name, "node": node.name}
                    if entry not in resources["containers"]:
                        resources["containers"].append(entry)
            if item.image_name:
                _, value = ssh.run(f"docker image inspect {shlex.quote(item.image_name)} >/dev/null 2>&1 && printf '%s' {shlex.quote(item.image_name)} || true", timeout=20)
                if value.strip():
                    resources["images"].append({"name": value.strip(), "node": node.name})
            else:
                _, value = ssh.run("docker images --format '{{.Repository}}:{{.Tag}}' --filter " + shlex.quote(f"label=com.docker.compose.project={deployment_compose_project_name(item, project)}"), timeout=20)
                resources["images"].extend({"name": name, "node": node.name} for name in filter(None, map(str.strip, value.splitlines())))
            for path in release_dirs:
                _, value = ssh.run(f"test -e {shlex.quote(path)} && printf '%s' {shlex.quote(path)} || true", timeout=20)
                if value.strip():
                    resources["directories"].append({"path": value.strip(), "node": node.name})
        scan_images(node)
    except Exception as exc:
        warnings.append(f"{node.name} 资源查询失败：{exc}")
    gateway = platform_gateway_node(db)
    if gateway:
        candidates = [f"/data/yunzhou-control/data/gateway/conf.d/{item.id}.conf", f"/data/yunzhou-control/data/gateway/certs/{item.id}.crt", f"/data/yunzhou-control/data/gateway/certs/{item.id}.key"]
        serving_release = db.scalar(select(Deployment.id).where(
            Deployment.project_id == item.project_id,
            Deployment.id != item.id,
            Deployment.status == DeployStatus.success,
        ).limit(1))
        if not serving_release:
            project_service = f"project-{item.project_id}"
            candidates.extend([
                f"/data/yunzhou-control/data/gateway/conf.d/{project_service}.conf",
                f"/data/yunzhou-control/data/gateway/certs/{project_service}.crt",
                f"/data/yunzhou-control/data/gateway/certs/{project_service}.key",
            ])
        try:
            with SSHNode(gateway) as ssh:
                checks = "; ".join(f"test -e {shlex.quote(path)} && printf '%s\\n' {shlex.quote(path)} || true" for path in candidates)
                _, existing = ssh.run(checks, timeout=20)
                resources["gateway_files"] = list(filter(None, map(str.strip, existing.splitlines())))
        except Exception as exc:
            warnings.append(f"平台网关查询失败：{exc}")
        if gateway.id != node.id:
            try:
                scan_images(gateway)
            except Exception as exc:
                warnings.append(f"平台构建镜像查询失败：{exc}")
    if item.status == DeployStatus.failed and not resources["images"]:
        if "[后台清理完成]" in (item.log_text or ""):
            warnings.append("该失败版本曾完成镜像构建，但镜像已被旧版后台清理策略回收；本次只删除发布记录与日志。")
        else:
            warnings.append("该失败版本当前未找到可清理镜像；可能尚未完成镜像构建，或已按镜像保留策略回收。")
    resources["records"].append({"name": f"发布记录、流水线日志 · {item.release or item.id[:8]}"})
    inventory = {
        "project": project.name,
        "release": item.release,
        "node": node.name,
        "resources": resources,
        "counts": {key: len(value) for key, value in resources.items()},
        "preserved": ["数据库、Redis 等持久化数据", "项目配置与上传源码", "其他发布版本"],
    }
    analysis = analyze_delete_scope(db, inventory)
    return {**inventory, "warnings": warnings, "ai": analysis, "ai_summary": analysis["summary"]}


@router.delete("/api/deployments/{item_id}")
def delete_deployment(item_id: str, remove_data: bool = False, db: Session = Depends(get_db), user: User = Depends(require(Role.admin, Role.deployer))):
    item = db.get(Deployment, item_id)
    if not item:
        raise HTTPException(404, "部署记录不存在")
    if item.status in (DeployStatus.queued, DeployStatus.running):
        raise HTTPException(409, "部署任务仍在执行，请先停止并确认无残留后再删除")
    if item.status == DeployStatus.success:
        raise HTTPException(409, "服务仍在运行，请先停止服务并确认无残留后再删除")
    project, node = db.get(Project, item.project_id), db.get(Node, item.node_id)
    other_count = db.scalar(
        select(func.count()).select_from(Deployment).where(
            Deployment.project_id == item.project_id,
            Deployment.node_id == item.node_id,
            Deployment.id != item.id,
        )
    ) or 0
    if remove_data and other_count:
        raise HTTPException(409, "同一项目在这台服务器还有其他发布版本，为避免误删共享数据，不能删除持久化卷")
    pending_replacement = db.scalar(
        select(Deployment).where(
            Deployment.project_id == item.project_id,
            Deployment.node_id == item.node_id,
            Deployment.id != item.id,
            Deployment.created_at > item.created_at,
            Deployment.status.in_([DeployStatus.queued, DeployStatus.running]),
        ).order_by(Deployment.created_at.desc())
    )
    if pending_replacement:
        raise HTTPException(409, f"新版本 {pending_replacement.id[:8]} 仍在部署中，旧版本可能还在提供服务；请等待新版本完成后再删除")
    replacement = db.scalar(
        select(Deployment).where(
            Deployment.project_id == item.project_id,
            Deployment.node_id == item.node_id,
            Deployment.id != item.id,
            Deployment.created_at > item.created_at,
            Deployment.status == DeployStatus.success,
        ).order_by(Deployment.created_at.desc())
    )
    serving_release = db.scalar(select(Deployment).where(
        Deployment.project_id == item.project_id,
        Deployment.node_id == item.node_id,
        Deployment.id != item.id,
        Deployment.status == DeployStatus.success,
    ).order_by(Deployment.created_at.desc()))
    try:
        # Remove replica containers before their rows are cascaded with the
        # deployment record.  Otherwise they become invisible to the platform
        # while continuing to occupy ports on the node.
        deployment_replicas = db.scalars(select(ProjectReplica).where(
            ProjectReplica.deployment_id == item.id,
        )).all()
        if node and deployment_replicas:
            with SSHNode(node) as replica_ssh:
                for replica in deployment_replicas:
                    replica_ssh.run(
                        f"docker rm -f {shlex.quote(replica.container_name)} >/dev/null 2>&1 || true"
                    )
                    db.delete(replica)
            db.flush()
        cleanup = delete_deployment_resources(
            item,
            project,
            node,
            remove_compose_images=other_count == 0,
            remove_persistent_data=remove_data,
            preserve_runtime=bool(replacement),
        )
        # The build node keeps its own local copy after pushing to the central
        # registry. A deleted release must lose that exact local tag on both
        # the runtime node and the builder, while newer releases and shared
        # base images remain untouched.
        builder = platform_gateway_node(db)
        if builder and node and builder.id != node.id and item.release:
            prefixes = (
                f"yunzhou/{project.slug}-", f"yz-{project.slug}-", f"{project.slug}-",
            )
            image_cleanup = (
                "refs=$(docker images --format '{{.Repository}}|{{.Tag}}' | "
                f"awk -F'|' -v t={shlex.quote(item.release)} "
                + " ".join(f"-v p{index}={shlex.quote(prefix)}" for index, prefix in enumerate(prefixes, start=1))
                + " '$2==t && (index($1,p1)==1 || index($1,p2)==1 || index($1,p3)==1) {print $1\":\"$2}'); "
                "[ -z \"$refs\" ] || printf '%s\n' \"$refs\" | xargs -r docker image rm -f >/dev/null 2>&1; "
                "docker image prune -f >/dev/null 2>&1 || true"
            )
            with SSHNode(builder) as builder_ssh:
                cleanup_code, cleanup_output = builder_ssh.run(image_cleanup, timeout=180)
                if cleanup_code:
                    raise RuntimeError("构建节点历史镜像清理失败：" + cleanup_output[-500:])
            cleanup += "；构建节点同版本镜像标签已清理"
        gateway = platform_gateway_node(db)
        if gateway:
            gateway_keys = [item.id]
            if not serving_release:
                gateway_keys.append(f"project-{item.project_id}")
            gateway_paths = [
                f"/data/yunzhou-control/data/gateway/{folder}/{key}.{suffix}"
                for key in gateway_keys
                for folder, suffix in (("conf.d", "conf"), ("certs", "crt"), ("certs", "key"))
            ]
            path_words = " ".join(shlex.quote(path) for path in gateway_paths)
            verify_words = "; ".join(f"test ! -e {shlex.quote(path)} || exit 45" for path in gateway_paths)
            with SSHNode(gateway) as ssh:
                code, output = ssh.run(
                    f"rm -f -- {path_words}; "
                    "docker exec yunzhou-platform-gateway nginx -t && "
                    "docker exec yunzhou-platform-gateway nginx -s reload; "
                    + verify_words,
                    timeout=30,
                )
                if code:
                    raise RuntimeError(output or "平台网关文件清理失败")
            cleanup += (
                "；该发布记录的旧网关文件已清理，当前线上版本网关保持不变"
                if serving_release else
                "；该发布记录及项目级 Nginx 配置、证书与监听已清理并复查"
            )
    except Exception as exc:
        raise HTTPException(502, f"部署记录未删除：{exc}")
    audit(db, user, "delete_deployment", "deployment", item.id, json.dumps({
        "project": project.name if project else item.project_id,
        "release": item.release,
        "node": node.name if node else item.node_id,
        "status_before_delete": item.status.value,
        "persistent_data": "deleted" if remove_data else "preserved",
        "cleanup": cleanup,
    }, ensure_ascii=False))
    db.delete(item)
    db.commit()
    return {"ok": True, "cleanup": cleanup}

