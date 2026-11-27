"""Persist verified AI source changes in the project's single working tree."""

from __future__ import annotations

import shutil
from pathlib import Path

from git import Repo

from ..config import settings
from ..models import Project, SourceType
from .source_cache import source_cache_guard


WORKSPACE_BRANCH = "yunzhou-workspace"


def _safe_destination(root: Path, relative: str) -> Path:
    destination = (root / relative).resolve()
    try:
        destination.relative_to(root.resolve())
    except ValueError as exc:
        raise RuntimeError(f"修复文件路径不安全：{relative}") from exc
    return destination


def persist_verified_changes(
    project: Project,
    work: str,
    source_subpath: str,
    changed_files: list[str],
    deployment_id: str,
) -> str:
    """Copy verified changes into upload source or commit them to the Git workspace."""
    changed = list(dict.fromkeys(str(item).replace("\\", "/") for item in changed_files if str(item).strip()))
    if not changed:
        return ""
    source_root = Path(work).resolve()
    if project.source_type == SourceType.upload:
        if not project.source_path:
            raise RuntimeError("上传项目缺少持久源码目录，无法保存 AI 修复")
        destination_root = Path(project.source_path).resolve()
        for relative in changed:
            source = _safe_destination(source_root, relative)
            destination = _safe_destination(destination_root, relative)
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)
        return f"已将 {len(changed)} 个验证成功的修改写回上传项目源码"

    if list(getattr(project, "git_repositories", None) or []):
        raise RuntimeError("多仓库项目暂不能自动写回工作区，请在对应仓库中处理修复")
    workspace_root = Path(settings.build_data_root) / "builder" / "projects" / project.slug
    checkout = workspace_root / "source-cache"
    with source_cache_guard(project.id, workspace_root):
        if not (checkout / ".git").is_dir():
            raise RuntimeError("项目 Git 工作区不存在，无法保存 AI 修复")
        repo = Repo(checkout)
        if repo.active_branch.name != WORKSPACE_BRANCH:
            repo.git.checkout(WORKSPACE_BRANCH)
        destination_root = (checkout / source_subpath).resolve() if source_subpath else checkout.resolve()
        for relative in changed:
            source = _safe_destination(source_root, relative)
            destination = _safe_destination(destination_root, relative)
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)
        repo.index.add([str(_safe_destination(destination_root, relative).relative_to(checkout)) for relative in changed])
        if not repo.is_dirty(untracked_files=True):
            return "验证成功，但项目工作区内容未发生变化"
        repo.index.commit(f"yunzhou: verified AI repair {deployment_id[:8]}")
        return f"已在 {WORKSPACE_BRANCH} 提交 {len(changed)} 个验证成功的修改"
