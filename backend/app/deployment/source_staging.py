"""Upload and Git source acquisition for isolated deployment workspaces."""

import hashlib
import json
import os
import re
import shutil
import tempfile
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import quote, urlsplit, urlunsplit

from git import Repo

from ..config import decrypt, settings
from ..models import GitCredential, Project, SourceType
from ..proxy import get_proxy_config, proxy_with_auth
from .architecture import has_project_marker as _has_project_marker
from .source_cache import source_cache_guard
from .source_paths import discover_source_root, git_source_location
from .workspace import WORKSPACE_BRANCH


def stage_source(project: Project, db, workspace_key: str | None = None) -> tuple[str, str, str | None, str]:
    builder_root = Path(settings.build_data_root) / "builder"
    workspace_root = builder_root / "projects" / project.slug
    workspace_root.mkdir(parents=True, exist_ok=True)
    run_root = workspace_root / "runs"
    run_root.mkdir(parents=True, exist_ok=True)
    safe_key = re.sub(r"[^a-zA-Z0-9_.-]+", "-", workspace_key or "analysis")[:64]
    temp = tempfile.mkdtemp(prefix=f"{safe_key}-", dir=run_root)
    if project.source_type == SourceType.upload:
        if not project.source_path or not Path(project.source_path).exists():
            raise RuntimeError("项目还没有上传源码")
        shutil.copytree(project.source_path, temp, dirs_exist_ok=True)
        return temp, "upload", temp, ""

    repositories = list(getattr(project, "git_repositories", None) or [])
    if repositories:
        revisions: list[str] = []
        used_targets: set[str] = set()
        staged_repositories: dict[tuple[str, str, str], tuple[str, str, str | None]] = {}
        cleanup_roots: set[str] = set()
        try:
            for index, row in enumerate(repositories, start=1):
                raw_url = str(row.get("git_url") or "").strip()
                if not raw_url:
                    raise RuntimeError(f"第 {index} 个 Git 仓库地址为空")
                role = str(row.get("role") or "other").strip().lower()
                requested_target = str(row.get("target_dir") or role or f"source-{index}").strip()
                target_dir = re.sub(r"[^a-zA-Z0-9_.-]+", "-", requested_target).strip(".-")
                if not target_dir:
                    target_dir = f"source-{index}"
                if target_dir in used_targets:
                    target_dir = f"{target_dir}-{index}"
                used_targets.add(target_dir)

                base_url, branch, requested_path = git_source_location(
                    raw_url, str(row.get("git_branch") or "main").strip() or "main",
                )
                credential_id = str(row.get("credential_id") or project.git_credential_id or "")
                cache_key = (base_url, branch, credential_id)
                staged = staged_repositories.get(cache_key)
                if staged is None:
                    repository_key = hashlib.sha1("\0".join(cache_key).encode()).hexdigest()[:12]
                    child = SimpleNamespace(
                        id=f"{project.id}-{repository_key}",
                        slug=f"{project.slug}-repo-{repository_key}",
                        source_type=SourceType.git,
                        source_path=None,
                        git_url=base_url,
                        git_branch=branch,
                        git_credential_id=credential_id or None,
                        strict_source_path=False,
                    )
                    source_root, revision, child_root, _ = stage_source(
                        child, db, workspace_key=f"{safe_key}-repo-{repository_key}",
                    )
                    staged = (source_root, revision, child_root)
                    staged_repositories[cache_key] = staged
                    if child_root:
                        cleanup_roots.add(child_root)

                source_root, revision, child_root = staged
                selected_root = Path(source_root)
                if requested_path:
                    selected_root = (Path(child_root or source_root) / requested_path).resolve()
                    try:
                        selected_root.relative_to(Path(child_root or source_root).resolve())
                    except ValueError as exc:
                        raise RuntimeError(f"第 {index} 个 Git 项目子目录不安全") from exc
                    if not selected_root.is_dir() or not _has_project_marker(selected_root):
                        raise RuntimeError(f"第 {index} 个 Git 仓库中不存在可构建目录 /{requested_path}")
                shutil.copytree(selected_root, Path(temp) / target_dir, dirs_exist_ok=True)
                revisions.append(f"{target_dir}:{revision}")
        finally:
            for child_root in cleanup_roots:
                shutil.rmtree(child_root, ignore_errors=True)
        (Path(temp) / ".yunzhou-sources.json").write_text(
            json.dumps(repositories, ensure_ascii=False, indent=2), encoding="utf-8",
        )
        return temp, ",".join(revisions), temp, ""

    if not project.git_url:
        raise RuntimeError("Git 地址为空")
    url, branch, requested_path = git_source_location(project.git_url, project.git_branch)
    safe_url = url
    env = None
    credential = db.get(GitCredential, project.git_credential_id) if project.git_credential_id else None
    if credential:
        secret = decrypt(credential.secret_encrypted) or ""
        if credential.auth_type in ("token", "password") and url.startswith(("http://", "https://")):
            parts = urlsplit(url)
            username = quote(credential.username or "oauth2", safe="")
            auth = f"{username}:{quote(secret, safe='')}@{parts.netloc}"
            url = urlunsplit((parts.scheme, auth, parts.path, parts.query, parts.fragment))
        elif credential.auth_type == "ssh_key":
            key_path = Path(temp).parent / f"key-{project.id}"
            key_path.write_text(secret)
            key_path.chmod(0o600)
            env = {"GIT_SSH_COMMAND": f"ssh -i {key_path} -o StrictHostKeyChecking=no"}
    proxy_config = get_proxy_config(db)
    proxy_env = {}
    if proxy_config and proxy_config.enabled:
        proxy_password = decrypt(proxy_config.proxy_password_encrypted) if proxy_config.proxy_password_encrypted else ""
        http_proxy = proxy_with_auth(
            proxy_config.http_proxy or proxy_config.https_proxy,
            proxy_config.proxy_username or "",
            proxy_password or "",
        )
        https_proxy = proxy_with_auth(
            proxy_config.https_proxy or proxy_config.http_proxy,
            proxy_config.proxy_username or "",
            proxy_password or "",
        )
        proxy_env = {
            "HTTP_PROXY": http_proxy,
            "HTTPS_PROXY": https_proxy,
            "NO_PROXY": proxy_config.no_proxy,
            "http_proxy": http_proxy,
            "https_proxy": https_proxy,
            "no_proxy": proxy_config.no_proxy,
        }
    old_env = {}
    import os
    for key, value in proxy_env.items():
        old_env[key] = os.environ.get(key)
        if value:
            os.environ[key] = value
    if env:
        old_env["GIT_SSH_COMMAND"] = os.environ.get("GIT_SSH_COMMAND")
        os.environ.update(env)
    key_path = locals().get("key_path")
    try:
        with source_cache_guard(project.id, workspace_root):
            # Keep one shallow persistent project workspace. Verified AI
            # repairs are committed to WORKSPACE_BRANCH; fresh remote changes
            # are rebased underneath those commits before each build.
            checkout = workspace_root / "source-cache"
            shallow_marker = checkout / ".git" / "shallow"
            if checkout.exists() and not shallow_marker.exists():
                shutil.rmtree(checkout, ignore_errors=True)
            if not (checkout / ".git").exists():
                shutil.rmtree(checkout, ignore_errors=True)
                repo = Repo.clone_from(
                    url, str(checkout), branch=branch or None, depth=1, single_branch=True,
                )
                fetch_branch = branch or repo.active_branch.name
                repo.git.config("yunzhou.remoteBranch", fetch_branch)
                repo.git.checkout("-B", WORKSPACE_BRANCH)
                repo.remote("origin").set_url(safe_url)
            else:
                repo = Repo(str(checkout))
                origin = repo.remote("origin")
                origin.set_url(url)
                try:
                    try:
                        saved_branch = repo.git.config("--get", "yunzhou.remoteBranch").strip()
                    except Exception:
                        saved_branch = ""
                    current_branch = repo.active_branch.name
                    fetch_branch = branch or saved_branch or (current_branch if current_branch != WORKSPACE_BRANCH else "main")
                    repo.git.config("yunzhou.remoteBranch", fetch_branch)
                    origin.fetch(
                        refspec=f"+refs/heads/{fetch_branch}:refs/remotes/origin/{fetch_branch}",
                        depth=50,
                        prune=True,
                    )
                    if WORKSPACE_BRANCH in {head.name for head in repo.heads}:
                        repo.git.checkout(WORKSPACE_BRANCH)
                        try:
                            repo.git.rebase(f"origin/{fetch_branch}")
                        except Exception as exc:
                            repo.git.rebase("--abort")
                            raise RuntimeError(
                                "远端新代码与平台 AI 修复提交发生冲突；工作区已保持原状，等待 AI 合并冲突"
                            ) from exc
                    else:
                        repo.git.checkout("-B", WORKSPACE_BRANCH, f"origin/{fetch_branch}")
                    repo.git.clean("-fdx")
                finally:
                    origin.set_url(safe_url)
            revision = repo.head.commit.hexsha[:12]
            run_repo = Repo.clone_from(str(checkout), temp, shared=True, no_hardlinks=True)
            run_repo.git.checkout("--detach", revision)
    finally:
        for key, value in old_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        if key_path:
            Path(key_path).unlink(missing_ok=True)
    if requested_path and getattr(project, "strict_source_path", False):
        source_root = (Path(temp) / requested_path).resolve()
        try:
            source_root.relative_to(Path(temp).resolve())
        except ValueError as exc:
            raise RuntimeError("Git 项目子目录不安全") from exc
        if not source_root.is_dir() or not _has_project_marker(source_root):
            raise RuntimeError(f"Git 仓库中不存在可构建的项目目录 /{requested_path}")
        source_path = requested_path
    else:
        source_root, source_path = discover_source_root(Path(temp), requested_path)
    return str(source_root), revision, temp, source_path

