"""Build-type-specific topology handlers.

Each handler validates only one release shape.  Adding support for another
shape must register a new handler instead of extending the central deployer.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

import yaml


@dataclass(frozen=True)
class TopologyContext:
    root: Path
    build_file: str
    frontend_roots: tuple[Path, ...]
    backend_roots: tuple[Path, ...]


class TopologyHandler(Protocol):
    build_types: frozenset[str]

    def apply(self, context: TopologyContext, plan: dict) -> dict:
        """Add build-specific evidence and errors to ``plan``."""


class ComposeTopologyHandler:
    build_types = frozenset({"compose"})

    def apply(self, context: TopologyContext, plan: dict) -> dict:
        compose_path = (context.root / context.build_file).resolve()
        try:
            compose_path.relative_to(context.root)
        except ValueError:
            plan["errors"].append("Compose 文件超出仓库目录")
            return plan
        try:
            document = yaml.safe_load(compose_path.read_text(errors="ignore")) or {}
        except Exception as exc:
            plan["errors"].append(f"Compose 无法解析：{exc}")
            return plan
        services = document.get("services") or {}
        if not services:
            plan["errors"].append("Compose 中没有服务")
        for name, raw_service in services.items():
            service = raw_service or {}
            build = service.get("build")
            image = service.get("image")
            context_value = build if isinstance(build, str) else (build or {}).get("context")
            dockerfile_value = None if isinstance(build, str) else (build or {}).get("dockerfile")
            if context_value:
                build_context = (compose_path.parent / str(context_value)).resolve()
                if not build_context.exists():
                    plan["errors"].append(f"服务 {name} 的构建目录不存在：{context_value}")
                elif dockerfile_value and not (build_context / str(dockerfile_value)).is_file():
                    plan["errors"].append(f"服务 {name} 的 Dockerfile 不存在：{dockerfile_value}")
            volumes = service.get("volumes") or []
            plan["persistent_mounts"].extend(str(value) for value in volumes)
            depends_on = service.get("depends_on") or {}
            plan["services"].append({
                "name": name,
                "build": context_value,
                "dockerfile": dockerfile_value,
                "image": image,
                "ports": service.get("ports") or [],
                "depends_on": list(depends_on.keys()) if isinstance(depends_on, dict) else depends_on,
            })
        return plan


class DockerfileTopologyHandler:
    build_types = frozenset({"dockerfile"})

    def apply(self, context: TopologyContext, plan: dict) -> dict:
        plan["services"].append({
            "name": "app",
            "build": ".",
            "dockerfile": context.build_file,
            "image": None,
            "ports": [],
        })
        dockerfile_path = (context.root / context.build_file).resolve()
        integrated_single_runtime = False
        if dockerfile_path.is_file() and context.root in dockerfile_path.parents:
            dockerfile_text = dockerfile_path.read_text(encoding="utf-8", errors="replace")
            stages = re.findall(r"(?im)^\s*FROM\s+\S+(?:\s+AS\s+\S+)?\s*$", dockerfile_text)
            integrates_build_output = bool(re.search(
                r"(?im)^\s*COPY\s+--from=\S+\s+", dockerfile_text
            ))
            frontend_evidence = bool(re.search(
                r"(?i)(?:\bfrontend/|package(?:-lock)?\.json|npm\s+(?:run\s+)?build|/dist\b)",
                dockerfile_text,
            ))
            backend_evidence = bool(re.search(
                r"(?i)(?:\bbackend/|requirements\.txt|pyproject\.toml|pom\.xml|\.jar\b)",
                dockerfile_text,
            ))
            runtime_entrypoint = bool(re.search(
                r"(?im)^\s*(?:CMD|ENTRYPOINT)\b", dockerfile_text
            ))
            integrated_single_runtime = (
                len(stages) >= 2
                and integrates_build_output
                and frontend_evidence
                and backend_evidence
                and runtime_entrypoint
            )
            if integrated_single_runtime:
                plan["single_container_evidence"] = (
                    "Dockerfile 多阶段构建已将前端产物合并到最终后端运行镜像"
                )
        if context.frontend_roots and context.backend_roots and not integrated_single_runtime:
            plan["errors"].append("同时发现前端和后端源码，但当前方案只有一个普通应用容器")
        return plan


_HANDLERS: tuple[TopologyHandler, ...] = (
    ComposeTopologyHandler(),
    DockerfileTopologyHandler(),
)


def handler_for(build_type: str) -> TopologyHandler:
    normalized = str(build_type or "").strip().lower()
    for handler in _HANDLERS:
        if normalized in handler.build_types:
            return handler
    raise ValueError(f"不支持的构建类型：{build_type or '空'}")
"""Deployment package component."""

