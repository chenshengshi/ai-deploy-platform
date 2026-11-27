"""Git browser-URL normalization and repository source-root discovery."""

from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from ..deployment_architecture import fullstack_roots, has_project_marker


def git_source_location(raw_url: str, configured_branch: str | None = None) -> tuple[str, str, str]:
    """Turn a TFS/Azure DevOps browser URL into clone URL, branch and subdirectory."""
    parts = urlsplit((raw_url or "").strip())
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    source_path = (query.get("path") or "").replace("\\", "/").strip("/")
    if source_path and (source_path == ".." or source_path.startswith("../") or "/../" in f"/{source_path}/"):
        raise RuntimeError("Git 项目子目录不安全")
    version = (query.get("version") or "").strip()
    url_branch = version[2:] if version.startswith("GB") and len(version) > 2 else ""
    branch = url_branch or (configured_branch or "").strip()
    clone_query = [
        (key, value)
        for key, value in parse_qsl(parts.query, keep_blank_values=True)
        if key not in {"path", "version", "_a"}
    ]
    clone_url = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(clone_query), ""))
    return clone_url, branch, source_path


def discover_source_root(repo_root: Path, requested_path: str = "") -> tuple[Path, str]:
    if requested_path:
        selected = (repo_root / requested_path).resolve()
        try:
            selected.relative_to(repo_root.resolve())
        except ValueError as exc:
            raise RuntimeError("Git 项目子目录不安全") from exc
        if not selected.is_dir():
            raise RuntimeError(f"Git 仓库中不存在项目目录 /{requested_path}")
        if not has_project_marker(selected):
            raise RuntimeError(f"目录 /{requested_path} 中未找到 package.json、pom.xml 或其他项目入口文件")
        frontend_roots, backend_roots = fullstack_roots(repo_root)
        if frontend_roots and backend_roots and (selected in frontend_roots or selected in backend_roots):
            counterpart = backend_roots[0] if selected in frontend_roots else frontend_roots[0]
            common = Path(os.path.commonpath([str(selected), str(counterpart)])).resolve()
            relative = common.relative_to(repo_root.resolve()).as_posix()
            return common, "" if relative == "." else relative
        return selected, requested_path
    if has_project_marker(repo_root):
        return repo_root, ""
    ignored = {".git", "node_modules", "target", "dist", "build", "vendor", ".idea", ".vscode"}
    candidates = []
    for path in repo_root.rglob("*"):
        if not path.is_dir() or any(part in ignored for part in path.relative_to(repo_root).parts):
            continue
        relative = path.relative_to(repo_root)
        if len(relative.parts) <= 3 and has_project_marker(path):
            candidates.append(path)
    if len(candidates) == 1:
        relative = candidates[0].relative_to(repo_root).as_posix()
        return candidates[0], relative
    completed = [
        path for path in candidates
        if path.name.lower() in {"complete", "completed", "final", "solution"}
    ]
    frontend_roots, backend_roots = fullstack_roots(repo_root)
    if len(completed) == 1 and not (frontend_roots and backend_roots):
        relative = completed[0].relative_to(repo_root).as_posix()
        return completed[0], relative
    return repo_root, ""
