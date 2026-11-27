"""Release-scoped image retention and failed-build cleanup."""

import re
import shlex
import time
from urllib.parse import quote

import httpx
from sqlalchemy import select

from ..models import DeployStatus, Deployment, DeploymentSettings, Node, Project
from ..ssh import SSHNode
from .gateway import platform_gateway_node
from .naming import deployment_compose_project_name


def cleanup_old_project_images(db, deployment: Deployment, project: Project, target: Node) -> str:
    """Keep one builder copy and two target copies for rollback."""
    history = db.scalars(
        select(Deployment).where(
            Deployment.project_id == project.id,
            Deployment.release.is_not(None),
            Deployment.status.in_([DeployStatus.success, DeployStatus.stopped]),
        ).order_by(Deployment.created_at.desc())
    ).all()
    keep_releases = []
    for item in history:
        release = (item.release or "").strip()
        if release and release not in keep_releases:
            keep_releases.append(release)
        if len(keep_releases) == 2:
            break
    if deployment.release and deployment.release not in keep_releases:
        keep_releases.insert(0, deployment.release)
        keep_releases = keep_releases[:2]

    builder = platform_gateway_node(db)
    nodes = [target] + ([builder] if builder else [])
    unique_nodes = {}
    for node in nodes:
        key = (node.host, node.port, node.username)
        unique_nodes[key] = node

    repository = f"yunzhou/{project.slug}"
    reports = []
    target_key = (target.host, target.port, target.username)
    builder_key = (builder.host, builder.port, builder.username) if builder else None
    for key, node in unique_nodes.items():
        # A dedicated build server only needs the latest successful image. If
        # it is also the runtime target, retain the previous release as well.
        node_keep_releases = keep_releases[:1] if key == builder_key and key != target_key else keep_releases[:2]
        keep_words = " " + " ".join(node_keep_releases) + " "
        script = (
            "removed=0; skipped=0; "
            "docker images --format '{{.Repository}}|{{.Tag}}|{{.ID}}' | "
            "while IFS='|' read -r repo tag iid; do "
            f"case \"$repo\" in {shlex.quote(repository)}|{shlex.quote(repository + '-')}*) ;; *) continue ;; esac; "
            "[ \"$tag\" != '<none>' ] || continue; "
            f"case {shlex.quote(keep_words)} in *\" $tag \"*) skipped=$((skipped+1)); continue ;; esac; "
            "if docker ps -aq --filter ancestor=\"$iid\" | grep -q .; then skipped=$((skipped+1)); continue; fi; "
            "docker image rm \"$repo:$tag\" >/dev/null 2>&1 && removed=$((removed+1)) || true; "
            "done; "
            # Only old dangling images are pruned. Fresh layers may belong to a
            # concurrent build and BuildKit's reusable cache is not touched.
            "dangling=$(docker image prune -f --filter dangling=true --filter until=24h 2>/dev/null | "
            "awk '/Total reclaimed space:/ {print $4 \" \" $5}'); "
            "printf 'retained=%s dangling_reclaimed=%s' " + shlex.quote(",".join(node_keep_releases)) + " \"${dangling:-0B}\""
        )
        with SSHNode(node) as ssh:
            code, output = ssh.run(script, timeout=180)
        if code:
            raise RuntimeError(f"{node.name} 镜像清理失败：{output[-500:]}")
        reports.append(f"{node.name}：{output.strip()}")
    return "；".join(reports)


def cleanup_incomplete_release_images(
    db, deployment: Deployment, project: Project, target: Node, release: str | None,
) -> str:
    """Delete and verify images created by a failed or cancelled release."""
    release = (release or deployment.release or "").strip()
    if not release:
        return "本次任务尚未生成版本镜像"
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", release):
        raise RuntimeError("发布版本号不安全，已拒绝镜像清理")
    builder = platform_gateway_node(db)
    nodes = [target] + ([builder] if builder else [])
    unique_nodes = {(node.host, node.port, node.username): node for node in nodes if node}
    repository = f"yunzhou/{project.slug}"
    reports = []
    for node in unique_nodes.values():
        script = (
            # Compose can leave stopped containers whose images have already
            # lost their repository tag. Match the exact release through the
            # config-files label, remove those containers, then remove only
            # their platform-built images. Never touch another release that
            # shares the same Compose project label.
            f"project_label={shlex.quote('com.docker.compose.project=' + deployment_compose_project_name(deployment, project))}; "
            "owned_images=''; owned_containers=0; "
            "for cid in $(docker ps -aq --filter label=\"$project_label\"); do "
            "cfg=$(docker inspect -f '{{index .Config.Labels \"com.docker.compose.project.config_files\"}}' \"$cid\" 2>/dev/null); "
            f"case \"$cfg\" in */{release}/*) ;; *) continue ;; esac; "
            "iid=$(docker inspect -f '{{.Image}}' \"$cid\" 2>/dev/null); "
            "builder=$(docker image inspect -f '{{index .Config.Labels \"com.docker.compose.image.builder\"}}' \"$iid\" 2>/dev/null); "
            "[ \"$builder\" = classic ] && owned_images=\"$owned_images $iid\"; "
            "docker rm -f \"$cid\" >/dev/null 2>&1 || true; owned_containers=$((owned_containers+1)); done; "
            "for iid in $(printf '%s\n' $owned_images | sort -u); do "
            "docker ps -aq --filter ancestor=\"$iid\" | grep -q . || docker image rm -f \"$iid\" >/dev/null 2>&1 || true; done; "
            "refs=$(docker images --format '{{.Repository}}|{{.Tag}}' | "
            f"awk -F'|' -v r={shlex.quote(repository)} -v t={shlex.quote(release)} "
            "'$2==t && ($1==r || index($1,r\"-\")==1) {print $1\":\"$2}'); "
            "count=$(printf '%s\\n' \"$refs\" | sed '/^$/d' | wc -l); "
            "if [ -n \"$refs\" ]; then printf '%s\\n' \"$refs\" | xargs -r docker image rm -f >/dev/null; fi; "
            "docker image prune -f >/dev/null 2>&1 || true; "
            "left=$(docker images --format '{{.Repository}}|{{.Tag}}' | "
            f"awk -F'|' -v r={shlex.quote(repository)} -v t={shlex.quote(release)} "
            "'$2==t && ($1==r || index($1,r\"-\")==1) {print}'); "
            "[ -z \"$left\" ] || { printf 'remaining=%s' \"$left\"; exit 31; }; "
            "printf 'removed=%s stopped_containers=%s verified=clean' \"$count\" \"$owned_containers\""
        )
        locked_script = (
            "flock -w 1200 /tmp/yunzhou-image-commit.lock sh -lc "
            + shlex.quote(script)
        )
        with SSHNode(node) as ssh:
            code, output = ssh.run(locked_script, timeout=3660)
        if code:
            raise RuntimeError(f"{node.name} 本次版本镜像清理后仍有残留：{output[-800:]}")
        reports.append(f"{node.name}：{output.strip()}")
    return "；".join(reports)



def cleanup_registry_versions(db, project: Project | None, repository: str) -> list[str]:
    policy = db.get(DeploymentSettings, "default")
    if not policy or not policy.registry_auto_cleanup:
        return []
    keep = max(1, int(policy.registry_retention_count or 5))
    base = "http://registry:5000/v2"
    headers = {"Accept": ", ".join((
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.docker.distribution.manifest.v2+json",
        "application/vnd.oci.image.manifest.v1+json",
    ))}
    # A successful deployment is historical evidence, not proof that its image
    # is still active. Protecting every successful release made retention a
    # no-op forever. The newest successful release is the restart/active
    # candidate; older releases are governed by the configured keep count.
    protected: set[str] = set()
    if project is not None:
        active_release = db.scalar(select(Deployment.release).where(
            Deployment.project_id == project.id,
            Deployment.status == DeployStatus.success,
            Deployment.release.is_not(None),
        ).order_by(Deployment.finished_at.desc(), Deployment.created_at.desc()).limit(1))
        if active_release:
            protected.add(active_release)
    removed = []
    with httpx.Client(timeout=20, trust_env=False) as client:
        response = client.get(f"{base}/{repository}/tags/list")
        if response.status_code != 200:
            return []
        tags = sorted(response.json().get("tags") or [], reverse=True)
        retained = set(tags[:keep]) | protected
        for tag in tags:
            if tag in retained:
                continue
            manifest = client.head(f"{base}/{repository}/manifests/{tag}", headers=headers)
            digest = manifest.headers.get("Docker-Content-Digest")
            if digest and client.delete(f"{base}/{repository}/manifests/{digest}").status_code in {200, 202}:
                removed.append(tag)
    return removed
def verify_registry_tag(repository: str, tag: str, attempts: int = 5) -> bool:
    """Confirm that a pushed tag is visible in the platform's central registry."""
    url = f"http://registry:5000/v2/{quote(repository, safe='/')}/tags/list"
    with httpx.Client(timeout=20, trust_env=False) as client:
        for attempt in range(attempts):
            try:
                response = client.get(url)
                if response.status_code == 200 and tag in (response.json().get("tags") or []):
                    return True
            except (httpx.HTTPError, ValueError):
                pass
            if attempt + 1 < attempts:
                time.sleep(1)
    return False

