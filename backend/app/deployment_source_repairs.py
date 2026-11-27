"""Persist compact, auditable source-repair candidates without cloning source trees."""
from __future__ import annotations

import difflib
import json
import os
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path


TEXT_SUFFIXES = {
    ".c", ".conf", ".config", ".cs", ".css", ".dockerfile", ".env", ".go", ".gradle",
    ".h", ".html", ".ini", ".java", ".js", ".json", ".jsx", ".kt", ".kts", ".lock",
    ".mjs", ".php", ".properties", ".py", ".rb", ".rs", ".scss", ".sh", ".sql",
    ".toml", ".ts", ".tsx", ".vue", ".xml", ".yaml", ".yml",
}
TEXT_NAMES = {"Dockerfile", "Makefile", "Procfile", "pom.xml", "package.json"}
IGNORED_PARTS = {".git", ".venv", "venv", "node_modules", "target", "dist", "build", "vendor"}


def _eligible(path: Path, root: Path) -> bool:
    relative = path.relative_to(root)
    if any(part in IGNORED_PARTS or part.startswith(".yunzhou") for part in relative.parts):
        return False
    return path.name in TEXT_NAMES or path.suffix.lower() in TEXT_SUFFIXES or path.name.startswith("Dockerfile")


def snapshot_text_sources(root: Path, *, max_file_bytes: int = 2_000_000, max_total_bytes: int = 20_000_000) -> dict[str, str]:
    """Capture a bounded text baseline in memory before isolated repairs run."""
    result: dict[str, str] = {}
    total = 0
    for path in sorted(root.rglob("*")):
        try:
            if not path.is_file() or not _eligible(path, root):
                continue
            size = path.stat().st_size
            if size > max_file_bytes or total + size > max_total_bytes:
                continue
            result[path.relative_to(root).as_posix()] = path.read_text(encoding="utf-8", errors="replace")
            total += size
        except OSError:
            continue
    return result


def build_source_patch(before: dict[str, str], root: Path) -> str:
    """Return a standard unified patch for changed eligible source files."""
    after = snapshot_text_sources(root)
    chunks: list[str] = []
    for relative in sorted(set(before) | set(after)):
        old = before.get(relative, "").splitlines(keepends=True)
        new = after.get(relative, "").splitlines(keepends=True)
        if old == new:
            continue
        chunks.extend(difflib.unified_diff(old, new, f"a/{relative}", f"b/{relative}", lineterm=""))
    return "\n".join(line.rstrip("\n") for line in chunks).strip() + ("\n" if chunks else "")


def _safe_slug(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", value).strip("-.") or "project"


def persist_repair_bundle(
    storage_root: Path, *, project_slug: str, deployment_id: str, patch: str,
    verified: bool, report: dict, verification_lines: list[str],
) -> Path | None:
    """Atomically replace the project's verified or latest-failed repair slot."""
    if not patch.strip():
        return None
    project_root = storage_root / _safe_slug(project_slug)
    slot = "verified" if verified else "latest-failed"
    destination = project_root / slot
    temporary = project_root / f".{slot}-{deployment_id[:8]}.tmp"
    shutil.rmtree(temporary, ignore_errors=True)
    temporary.mkdir(parents=True, exist_ok=True)
    metadata = {
        **report,
        "deployment_id": deployment_id,
        "project_slug": project_slug,
        "status": "verified" if verified else "failed",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "patch_bytes": len(patch.encode("utf-8")),
    }
    (temporary / "changes.patch").write_text(patch, encoding="utf-8")
    (temporary / "report.json").write_text(json.dumps(metadata, ensure_ascii=False, indent=2), encoding="utf-8")
    (temporary / "verification.log").write_text("\n".join(verification_lines[-100:]).strip() + "\n", encoding="utf-8")
    backup = project_root / f".{slot}.old"
    shutil.rmtree(backup, ignore_errors=True)
    if destination.exists():
        os.replace(destination, backup)
    os.replace(temporary, destination)
    shutil.rmtree(backup, ignore_errors=True)
    return destination


def repair_bundle_summary(storage_root: Path, project_slug: str) -> list[dict]:
    result = []
    for slot in ("verified", "latest-failed"):
        report_path = storage_root / _safe_slug(project_slug) / slot / "report.json"
        if not report_path.is_file():
            continue
        try:
            report = json.loads(report_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        report["slot"] = slot
        result.append(report)
    return result
