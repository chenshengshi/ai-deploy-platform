from dataclasses import dataclass
from pathlib import Path


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
