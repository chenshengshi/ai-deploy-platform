from dataclasses import dataclass
from pathlib import Path
import re


@dataclass(frozen=True)
class BuildProfile:
    key: str
    language: str
    markers: tuple[str, ...]


BUILD_PROFILES = (
    BuildProfile("node", "Node.js", ("package.json",)),
    BuildProfile("java_maven", "Java", ("pom.xml",)),
    BuildProfile("java_gradle", "Java", ("build.gradle", "build.gradle.kts")),
    BuildProfile("python", "Python", ("requirements.txt", "pyproject.toml")),
    BuildProfile("go", "Go", ("go.mod",)),
    BuildProfile("dotnet", ".NET", ("*.csproj", "*.sln")),
)


def detect_build_profiles(root: str | Path) -> list[BuildProfile]:
    source = Path(root)
    detected: list[BuildProfile] = []
    for profile in BUILD_PROFILES:
        found = False
        for marker in profile.markers:
            if "*" in marker:
                found = next(source.rglob(marker), None) is not None
            else:
                found = (source / marker).is_file() or next(source.rglob(marker), None) is not None
            if found:
                break
        if found:
            detected.append(profile)
    return detected


def primary_build_profile(root: str | Path) -> BuildProfile | None:
    profiles = detect_build_profiles(root)
    return profiles[0] if profiles else None


def compatible_node_image(root: str | Path, current_image: str) -> str:
    """Raise an obsolete Node builder to the minimum required by manifests."""
    source = Path(root)
    current = re.search(r"(?i)node:(\d+)", str(current_image or ""))
    current_major = int(current.group(1)) if current else 22
    required = current_major
    for name in ("package.json", "package-lock.json"):
        manifest = source / name
        if not manifest.is_file():
            continue
        text = manifest.read_text(encoding="utf-8", errors="replace")
        for match in re.finditer(r'"node"\s*:\s*"[^"\d]*(?:>=|\^|~)?\s*(\d{2})', text, re.I):
            required = max(required, int(match.group(1)))
    selected = 20 if required <= 20 else 22 if required <= 22 else 24
    if selected <= current_major:
        return current_image
    return re.sub(r"(?i)(node:)\d+", rf"\g<1>{selected}", current_image, count=1)
