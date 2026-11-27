"""Central image registry listing, access control, retention protection, and deletion."""

from __future__ import annotations

import copy
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

import httpx
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from ..audit import audit
from ..auth import current_user, require
from ..database import get_db
from ..models import DeployStatus, Deployment, Node, Project, ProjectAccess, Role, User
from ..ssh import SSHNode
from .settings import get_deployment_settings

router = APIRouter()
REGISTRY_API = "http://registry:5000/v2"
_REGISTRY_CACHE_TTL = 30.0
_registry_catalog_cache: tuple[float, dict] | None = None
_registry_catalog_guard = threading.Lock()
REGISTRY_MANIFEST_ACCEPT = ", ".join((
    "application/vnd.docker.distribution.manifest.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.index.v1+json",
))


def _user_can_access_project(db: Session, user: User, project_id: str) -> bool:
    if user.role == Role.admin:
        return True
    return bool(db.scalar(select(Project.id).where(
        Project.id == project_id,
        (Project.owner_id == user.id) | Project.id.in_(select(ProjectAccess.project_id).where(ProjectAccess.user_id == user.id)),
    )))

def _registry_request(method: str, path: str, **kwargs):
    try:
        # Registry is an internal Compose service.  Never route it through the
        # system HTTP proxy configured for external package downloads.
        with httpx.Client(timeout=20, trust_env=False) as client:
            response = client.request(method, REGISTRY_API + path, **kwargs)
    except httpx.HTTPError as exc:
        raise HTTPException(503, f"镜像仓库暂时不可用：{exc}")
    if response.status_code >= 400:
        raise HTTPException(response.status_code, "镜像仓库请求失败")
    return response


def _invalidate_registry_catalog_cache() -> None:
    global _registry_catalog_cache
    with _registry_catalog_guard:
        _registry_catalog_cache = None


def _registry_result_for_user(result: dict, db: Session, user: User) -> dict:
    """Apply project authorization after reading the shared registry cache."""
    scoped = copy.deepcopy(result)
    if user.role != Role.admin:
        accessible_ids = set(db.scalars(select(Project.id).where(
            (Project.owner_id == user.id) |
            Project.id.in_(select(ProjectAccess.project_id).where(ProjectAccess.user_id == user.id))
        )).all())
        scoped["repositories"] = [
            item for item in scoped.get("repositories", [])
            if item.get("project_id") in accessible_ids
        ]
    repositories = scoped.get("repositories", [])
    scoped["repository_count"] = len(repositories)
    scoped["project_count"] = len({item.get("project_id") for item in repositories if item.get("project_id")})
    scoped["tag_count"] = sum(int(item.get("tag_count") or 0) for item in repositories)
    return scoped


def _registry_project_for_name(db: Session, repository: str) -> Project | None:
    tail = repository.split("/", 1)[-1]
    projects = db.scalars(select(Project).where(Project.slug.is_not(None))).all()
    return next((
        project for project in sorted(projects, key=lambda item: len(item.slug or ""), reverse=True)
        if tail == project.slug or tail.startswith((project.slug or "") + "-")
    ), None)


def _require_registry_write_access(db: Session, user: User, repository: str) -> None:
    if user.role == Role.admin:
        return
    if user.role != Role.deployer:
        raise HTTPException(403, "只读账号不能删除镜像")
    project = _registry_project_for_name(db, repository)
    if not project or not _user_can_access_project(db, user, project.id):
        raise HTTPException(403, "无权删除其他项目的镜像")


def _registry_version_detail(name: str, tag: str) -> dict:
    response = _registry_request("GET", f"/{quote(name, safe='/')}/manifests/{quote(tag, safe='')}", headers={"Accept": REGISTRY_MANIFEST_ACCEPT})
    manifest = response.json()
    size = sum(int(x.get("size") or 0) for x in manifest.get("layers") or []) + int((manifest.get("config") or {}).get("size") or 0)
    created_at = None
    config_digest = (manifest.get("config") or {}).get("digest")
    if config_digest:
        try:
            image_config = _registry_request("GET", f"/{quote(name, safe='/')}/blobs/{quote(config_digest, safe=':')}").json()
            created_at = image_config.get("created")
        except HTTPException:
            pass
    if not created_at and re.fullmatch(r"\d{12}(?:\d{2}|-\d{2})?", tag):
        try:
            stamp = tag.split("-", 1)[0]
            pattern = "%Y%m%d%H%M%S" if len(stamp) == 14 else "%Y%m%d%H%M"
            created_at = datetime.strptime(stamp, pattern).replace(tzinfo=timezone(timedelta(hours=8))).isoformat()
        except ValueError:
            pass
    return {"tag": tag, "digest": response.headers.get("Docker-Content-Digest", ""), "size_bytes": size, "created_at": created_at}


@router.get("/api/images")
def list_image_repository(refresh: bool = False, db: Session = Depends(get_db), user: User = Depends(current_user)):
    global _registry_catalog_cache
    if not refresh:
        with _registry_catalog_guard:
            cached = _registry_catalog_cache
            if cached and time.monotonic() - cached[0] <= _REGISTRY_CACHE_TTL:
                return _registry_result_for_user(cached[1], db, user)
    names = _registry_request("GET", "/_catalog?n=100").json().get("repositories") or []
    tags_by_name = {}
    with ThreadPoolExecutor(max_workers=min(12, max(1, len(names)))) as pool:
        futures = {pool.submit(_registry_request, "GET", f"/{quote(name, safe='/')}/tags/list"): name for name in names}
        for future in as_completed(futures):
            name = futures[future]
            tags_by_name[name] = future.result().json().get("tags") or []
    versions_by_name = {name: [] for name, tags in tags_by_name.items() if tags}
    version_jobs = [(name, tag) for name, tags in tags_by_name.items() for tag in tags]
    with ThreadPoolExecutor(max_workers=min(12, max(1, len(version_jobs)))) as pool:
        futures = {pool.submit(_registry_version_detail, name, tag): name for name, tag in version_jobs}
        for future in as_completed(futures):
            versions_by_name[futures[future]].append(future.result())
    projects = db.scalars(select(Project)).all()
    project_by_slug = {str(project.slug): project for project in projects if project.slug}
    repositories = []
    for name, versions in sorted(versions_by_name.items()):
        repository_tail = name.split("/", 1)[-1]
        matching_slug = next(
            (
                slug for slug in sorted(project_by_slug, key=len, reverse=True)
                if repository_tail == slug or repository_tail.startswith(slug + "-")
            ),
            None,
        )
        project = project_by_slug.get(matching_slug) if matching_slug else None
        service_name = (
            repository_tail[len(matching_slug) + 1:]
            if matching_slug and repository_tail.startswith(matching_slug + "-")
            else "app"
        )
        repositories.append({
            "name": name,
            "tags": sorted(versions, key=lambda item: item["tag"], reverse=True),
            "tag_count": len(versions),
            "project_id": project.id if project else None,
            "project_name": project.name if project else None,
            "project_slug": matching_slug,
            "service_name": service_name,
        })
    policy = get_deployment_settings(db)
    project_count = len({item["project_slug"] or item["name"] for item in repositories})
    result = {"repositories": repositories, "repository_count": len(repositories), "project_count": project_count, "tag_count": sum(x["tag_count"] for x in repositories), "endpoint": policy.registry_endpoint}
    with _registry_catalog_guard:
        _registry_catalog_cache = (time.monotonic(), copy.deepcopy(result))
    return _registry_result_for_user(result, db, user)


@router.delete("/api/images")
def delete_image_tag(body: dict, db: Session = Depends(get_db), user: User = Depends(require(Role.admin, Role.deployer))):
    repository, tag = str(body.get("repository") or "").strip(), str(body.get("tag") or "").strip()
    if not re.fullmatch(r"[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*", repository) or not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}", tag):
        raise HTTPException(400, "仓库或标签无效")
    _require_registry_write_access(db, user, repository)
    protected_releases, running_refs = _protected_registry_releases(db)
    reason = _registry_tag_protection_reason(repository, tag, protected_releases, running_refs)
    if reason:
        raise HTTPException(409, f"该镜像受保护，不能删除：{reason}")
    manifest = _registry_request("HEAD", f"/{quote(repository, safe='/')}/manifests/{quote(tag, safe='')}", headers={"Accept": REGISTRY_MANIFEST_ACCEPT})
    digest = manifest.headers.get("Docker-Content-Digest")
    if not digest:
        raise HTTPException(409, "仓库未返回镜像摘要，无法安全删除")
    _registry_request("DELETE", f"/{quote(repository, safe='/')}/manifests/{quote(digest, safe=':')}")
    _invalidate_registry_catalog_cache()
    audit(db, user, "delete_registry_tag", "registry_image", None, f"{repository}:{tag}")
    db.commit()
    return {"ok": True, "message": f"已从仓库删除 {repository}:{tag}"}


def _protected_registry_releases(db: Session) -> tuple[dict[str, set[str]], set[tuple[str, str]]]:
    """Return releases that must remain pullable for restart/rollback safety."""
    protected: dict[str, set[str]] = {}
    projects = {item.id: item for item in db.scalars(select(Project)).all()}
    # Active work may already reference a release before it becomes the latest
    # successful deployment, so always protect queued/running releases.
    active = db.scalars(select(Deployment).where(
        Deployment.status.in_([DeployStatus.queued, DeployStatus.running]),
        Deployment.release.is_not(None),
    )).all()
    for deployment in active:
        project = projects.get(deployment.project_id)
        if project and deployment.release:
            protected.setdefault(project.slug, set()).add(deployment.release)
    # Protect exactly the newest successful release for every project. Older
    # successful records are history and may be deliberately cleaned.
    for project in projects.values():
        latest = db.scalar(select(Deployment).where(
            Deployment.project_id == project.id,
            Deployment.status == DeployStatus.success,
            Deployment.release.is_not(None),
        ).order_by(desc(Deployment.finished_at), desc(Deployment.created_at)).limit(1))
        if latest and latest.release:
            protected.setdefault(project.slug, set()).add(latest.release)
    running_refs: set[tuple[str, str]] = set()
    policy = get_deployment_settings(db)
    endpoint = (policy.registry_endpoint or "yunzhou.hub:5000").strip().rstrip("/")
    for node in db.scalars(select(Node).where(Node.enabled == True)).all():
        try:
            with SSHNode(node) as ssh:
                code, output = ssh.run("docker ps --format '{{.Image}}'", timeout=15)
            if code:
                continue
            for value in output.splitlines():
                image = value.strip()
                if image.startswith(endpoint + "/"):
                    image = image[len(endpoint) + 1:]
                if "@" in image or ":" not in image:
                    continue
                repository, tag = image.rsplit(":", 1)
                if repository.startswith((policy.registry_namespace or "yunzhou").strip("/") + "/"):
                    running_refs.add((repository, tag))
        except Exception:
            # Database protection remains active if one node is temporarily
            # unreachable; the preview reports conservatively from available
            # nodes instead of making repository listing fail.
            continue
    return protected, running_refs


def _registry_tag_protection_reason(repository: str, tag: str, protected: dict[str, set[str]], running_refs: set[tuple[str, str]]) -> str | None:
    if (repository, tag) in running_refs:
        return "节点上仍有运行容器使用该版本"
    tail = repository.split("/", 1)[-1]
    for slug, releases in protected.items():
        if (tail == slug or tail.startswith(slug + "-")) and tag in releases:
            return "当前项目最新在线或正在发布的版本"
    return None


@router.post("/api/images/bulk-delete")
def bulk_delete_image_repositories(body: dict, db: Session = Depends(get_db), user: User = Depends(require(Role.admin, Role.deployer))):
    raw_names = body.get("repositories") or []
    if not isinstance(raw_names, list) or not raw_names or len(raw_names) > 100:
        raise HTTPException(400, "请选择 1 至 100 个镜像仓库")
    repositories = list(dict.fromkeys(str(name or "").strip() for name in raw_names))
    repository_pattern = re.compile(r"[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*")
    if any(not repository_pattern.fullmatch(name) for name in repositories):
        raise HTTPException(400, "包含无效的镜像仓库名称")
    for repository in repositories:
        _require_registry_write_access(db, user, repository)
    catalog = set(_registry_request("GET", "/_catalog?n=1000").json().get("repositories") or [])
    missing = [name for name in repositories if name not in catalog]
    protected_releases, running_refs = _protected_registry_releases(db)
    deletable, protected_tags = [], []
    for repository in repositories:
        if repository not in catalog:
            continue
        tags = _registry_request("GET", f"/{quote(repository, safe='/')}/tags/list").json().get("tags") or []
        for tag in tags:
            reason = _registry_tag_protection_reason(repository, tag, protected_releases, running_refs)
            row = {"repository": repository, "tag": tag}
            if reason:
                protected_tags.append({**row, "reason": reason})
            else:
                deletable.append(row)
    preview = {
        "repository_count": len(repositories),
        "tag_count": len(deletable) + len(protected_tags),
        "deletable_count": len(deletable),
        "protected_count": len(protected_tags),
        "deletable": deletable,
        "protected": protected_tags,
        "missing": missing,
    }
    if not body.get("confirm"):
        return {"ok": True, "preview": preview}
    removed, failed = [], []
    for row in deletable:
        repository, tag = row["repository"], row["tag"]
        try:
            manifest = _registry_request("HEAD", f"/{quote(repository, safe='/')}/manifests/{quote(tag, safe='')}", headers={"Accept": REGISTRY_MANIFEST_ACCEPT})
            digest = manifest.headers.get("Docker-Content-Digest")
            if not digest:
                raise RuntimeError("仓库未返回镜像摘要")
            _registry_request("DELETE", f"/{quote(repository, safe='/')}/manifests/{quote(digest, safe=':')}")
            removed.append(f"{repository}:{tag}")
        except Exception as exc:
            failed.append({"image": f"{repository}:{tag}", "error": str(exc)[:300]})
    if removed:
        _invalidate_registry_catalog_cache()
    audit(db, user, "bulk_delete_registry_repositories", "registry", None,
          f"repositories={len(repositories)},removed={len(removed)},protected={len(protected_tags)},failed={len(failed)}")
    db.commit()
    return {
        "ok": not failed,
        "message": f"已删除 {len(removed)} 个镜像版本；保护 {len(protected_tags)} 个在线版本" + (f"；{len(failed)} 个删除失败" if failed else ""),
        "removed": removed,
        "protected": protected_tags,
        "failed": failed,
    }


def _project_registry_repositories(db: Session, project: Project) -> list[str]:
    policy = get_deployment_settings(db)
    namespace = (policy.registry_namespace or "yunzhou").strip("/")
    prefix = f"{namespace}/{project.slug}"
    catalog = _registry_request("GET", "/_catalog?n=1000").json().get("repositories") or []
    return sorted(name for name in catalog if name == prefix or name.startswith(prefix + "-"))


def _delete_project_registry_repositories(db: Session, project: Project) -> dict:
    """Delete every central-registry manifest owned by one deleted project."""
    repositories = _project_registry_repositories(db, project)
    removed_tags = []
    for repository in repositories:
        tags = _registry_request("GET", f"/{quote(repository, safe='/')}/tags/list").json().get("tags") or []
        digests = []
        for tag in tags:
            manifest = _registry_request(
                "HEAD",
                f"/{quote(repository, safe='/')}/manifests/{quote(tag, safe='')}",
                headers={"Accept": REGISTRY_MANIFEST_ACCEPT},
            )
            digest = manifest.headers.get("Docker-Content-Digest")
            if digest and digest not in digests:
                digests.append(digest)
            removed_tags.append(f"{repository}:{tag}")
        for digest in digests:
            _registry_request("DELETE", f"/{quote(repository, safe='/')}/manifests/{quote(digest, safe=':')}")
        remaining = _registry_request("GET", f"/{quote(repository, safe='/')}/tags/list").json().get("tags") or []
        if remaining:
            raise RuntimeError(f"镜像仓库 {repository} 清理后仍有 {len(remaining)} 个版本")
    return {"repositories": repositories, "tags": removed_tags}

