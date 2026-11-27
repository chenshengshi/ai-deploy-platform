import re
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from .architecture import find_compose


@dataclass(frozen=True)
class BuildSelection:
    build_type: str
    build_file: str


class BuildHandler(Protocol):
    build_type: str

    def detect(self, root: Path) -> BuildSelection | None: ...


class ComposeBuildHandler:
    build_type = "compose"

    def detect(self, root: Path) -> BuildSelection | None:
        compose = find_compose(root)
        return BuildSelection(self.build_type, compose.relative_to(root).as_posix()) if compose else None


class DockerfileBuildHandler:
    build_type = "dockerfile"

    def detect(self, root: Path) -> BuildSelection | None:
        dockerfile = root / "Dockerfile"
        return BuildSelection(self.build_type, "Dockerfile") if dockerfile.is_file() else None


BUILD_HANDLERS: tuple[BuildHandler, ...] = (ComposeBuildHandler(), DockerfileBuildHandler())


def detect_build(path: str, requested: str) -> tuple[str, str | None]:
    root = Path(path)
    detected = {handler.build_type: handler.detect(root) for handler in BUILD_HANDLERS}
    if requested in detected and requested != "auto":
        selection = detected[requested]
        if not selection:
            label = "Compose 文件" if requested == "compose" else "Dockerfile"
            raise RuntimeError(f"未找到 {label}")
        return selection.build_type, selection.build_file
    for handler in BUILD_HANDLERS:
        selection = detected[handler.build_type]
        if selection:
            return selection.build_type, selection.build_file
    raise RuntimeError("未找到 Dockerfile 或 Docker Compose 文件")


def detect_container_port(path: str, dockerfile_name: str = "Dockerfile") -> int | None:
    dockerfile = Path(path) / dockerfile_name
    if dockerfile.exists():
        match = re.search(r"(?im)^\s*EXPOSE\s+(\d+)", dockerfile.read_text(errors="ignore"))
        if match:
            return int(match.group(1))
    return None
"""Deployment package component."""

