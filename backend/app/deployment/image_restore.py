"""Restore immutable historical release images during rollback or restart."""

import shlex
import tempfile
from pathlib import Path

from ..models import Deployment, DeploymentSettings, Node, Project
from ..ssh import SSHNode
from .gateway import platform_gateway_node


def restore_release_images(
    db,
    deployment: Deployment,
    project: Project,
    node: Node,
    target_ssh: SSHNode,
    images: list[str],
) -> list[str]:
    """Restore missing release images through the builder, not target proxies."""
    release = (deployment.release or "").strip()
    candidates: list[str] = []
    for image in images:
        image = image.strip()
        repository, separator, tag = image.rpartition(":")
        if separator and tag == release and repository.startswith("yunzhou/"):
            candidates.append(image)
    if not candidates:
        return []

    missing = [
        image
        for image in dict.fromkeys(candidates)
        if target_ssh.run(f"docker image inspect {shlex.quote(image)} >/dev/null 2>&1")[0] != 0
    ]
    if not missing:
        return []
    if db is None:
        raise RuntimeError("历史版本镜像已不在目标服务器，请通过平台回滚以便从中央仓库恢复")

    builder = platform_gateway_node(db)
    if not builder:
        raise RuntimeError("平台构建节点不可用，暂时无法从中央仓库恢复历史镜像")
    policy = db.get(DeploymentSettings, "default")
    endpoint = (policy.registry_endpoint if policy else "yunzhou.hub:5000").strip().rstrip("/")
    namespace = (policy.registry_namespace if policy else "yunzhou").strip("/")
    archive = f"/tmp/yunzhou-rollback-{deployment.id}.tar.gz"

    def pull_and_tag(ssh: SSHNode) -> None:
        for image in missing:
            repository, _, tag = image.rpartition(":")
            repository_tail = repository.split("/", 1)[-1]
            registry_reference = f"{endpoint}/{namespace}/{repository_tail}:{tag}"
            code, _ = ssh.run(
                f"docker pull {shlex.quote(registry_reference)} && "
                f"docker tag {shlex.quote(registry_reference)} {shlex.quote(image)}",
                timeout=900,
            )
            if code:
                raise RuntimeError(
                    f"平台仓库中无法恢复历史镜像 {repository_tail}:{tag}，请检查该版本是否仍在保留范围内"
                )

    if builder.id == node.id:
        pull_and_tag(target_ssh)
        return missing

    with SSHNode(builder) as builder_ssh:
        pull_and_tag(builder_ssh)
        image_args = " ".join(shlex.quote(image) for image in missing)
        code, output = builder_ssh.run(
            f"docker save {image_args} | gzip -1 > {shlex.quote(archive)}",
            timeout=1800,
        )
        if code:
            raise RuntimeError("历史镜像恢复包生成失败：" + output[-500:])
        with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as handle:
            local_archive = handle.name
        try:
            builder_ssh.download_file(archive, local_archive)
            remote_archive = f"/tmp/yunzhou-rollback-images-{deployment.id}.tar.gz"
            target_ssh.upload_file(local_archive, remote_archive)
            code, output = target_ssh.run(
                f"gzip -dc {shlex.quote(remote_archive)} | docker load; rm -f {shlex.quote(remote_archive)}",
                timeout=1800,
            )
            if code:
                raise RuntimeError("历史镜像传送到目标服务器失败：" + output[-500:])
        finally:
            Path(local_archive).unlink(missing_ok=True)
            builder_ssh.run(f"rm -f -- {shlex.quote(archive)}", timeout=30)
    return missing
