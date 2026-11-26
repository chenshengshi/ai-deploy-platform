import re
import shutil
import zipfile
from pathlib import Path, PurePosixPath


def safe_extract_zip(archive: zipfile.ZipFile, destination: Path) -> None:
    """Extract a ZIP while accepting Windows separators and blocking escapes."""
    root = destination.resolve()
    seen: set[str] = set()
    for member in archive.infolist():
        normalized = member.filename.replace("\\", "/")
        if "\x00" in normalized or normalized.startswith("/") or re.match(r"^[A-Za-z]:/", normalized):
            raise ValueError("ZIP 包含不安全路径")
        relative = PurePosixPath(normalized)
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("ZIP 包含不安全路径")
        parts = tuple(part for part in relative.parts if part not in ("", "."))
        if not parts:
            continue
        key = "/".join(parts)
        if key in seen:
            raise ValueError("ZIP 包含重复路径")
        seen.add(key)
        output = root.joinpath(*parts)
        resolved = output.resolve()
        if root not in resolved.parents and resolved != root:
            raise ValueError("ZIP 包含不安全路径")
        if (member.external_attr >> 16) & 0o170000 == 0o120000:
            raise ValueError("ZIP 包含不安全的符号链接")
        if member.is_dir() or normalized.endswith("/"):
            output.mkdir(parents=True, exist_ok=True)
            continue
        output.parent.mkdir(parents=True, exist_ok=True)
        with archive.open(member) as source, output.open("wb") as target:
            shutil.copyfileobj(source, target)
