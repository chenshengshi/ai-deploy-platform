"""Source-layout discovery and release-topology validation.

This module is deliberately side-effect free: it inspects a local source tree
and returns evidence, but it never mutates project files or remote runtimes.
Keeping these decisions separate makes architecture recognition independently
testable and prevents a project-specific build repair from changing discovery.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from .topology_handlers import TopologyContext, handler_for
from ..source_inspection import detect_frontend_api_routes


COMPOSE_NAMES = (
    "compose.yaml",
    "compose.yml",
    "docker-compose.yml",
    "docker-compose.yaml",
    ".yunzhou.compose.yml",
    ".yunzhou.ai.compose.yml",
)

IGNORED_SOURCE_PARTS = {
    ".git", "node_modules", "target", "dist", "build", "vendor", ".venv"
}


@dataclass(frozen=True)
class DependencyRule:
    name: str
    active_markers: tuple[str, ...]
    library_markers: tuple[str, ...]


DEPENDENCY_RULES = (
    DependencyRule("MySQL", ("jdbc:mysql", "mysql://"), ("mysql-connector", "pymysql", "mysql2")),
    DependencyRule("PostgreSQL", ("jdbc:postgresql", "postgresql://", "postgres://"), ("postgresql", "psycopg", "pg")),
    DependencyRule("Redis", ("spring.redis", "spring:\n  redis", "redis://", "redis_host", "redis.host"), ("starter-data-redis", "sa-token-dao-redis", "ioredis", '"redis"')),
    DependencyRule("RabbitMQ", ("spring.rabbitmq", "amqp://", "rabbitmq_host"), ("starter-amqp", "rabbitmq")),
    DependencyRule("Elasticsearch", ("spring.elasticsearch", "elasticsearch.uris", "elasticsearch_host"), ("elasticsearch",)),
    DependencyRule("MinIO", ("minio.endpoint", "minio:\n", "minio_endpoint"), ("<artifactid>minio", '"minio"')),
    DependencyRule("MongoDB", ("spring.data.mongodb", "mongodb://"), ("starter-data-mongodb", "mongodb")),
    DependencyRule("Kafka", ("spring.kafka", "kafka.bootstrap", "kafka_brokers"), ("spring-kafka", "kafkajs")),
)


def has_project_marker(path: Path) -> bool:
    names = {
        "package.json", "pom.xml", "pyproject.toml", "requirements.txt",
        "index.html", "Dockerfile", *COMPOSE_NAMES,
    }
    return any((path / name).is_file() for name in names)


def fullstack_roots(root: Path) -> tuple[list[Path], list[Path]]:
    ignored = {".git", "node_modules", "target", "dist", "build", "vendor"}
    frontends: list[Path] = []
    backends: list[Path] = []
    for manifest in root.rglob("package.json"):
        if any(part in ignored for part in manifest.relative_to(root).parts):
            continue
        folder = manifest.parent
        text = manifest.read_text(errors="ignore").lower()
        frontend_markers = (
            '"vite"', '"react"', '"vue"', '"@vue/cli-service"',
            '"@angular/core"', '"svelte"', '"next"', '"nuxt"',
        )
        config_markers = (
            "vite.config.ts", "vite.config.js", "vue.config.js",
            "angular.json", "svelte.config.js", "next.config.js", "nuxt.config.ts",
        )
        if any(marker in text for marker in frontend_markers) or any(
            (folder / name).exists() for name in config_markers
        ):
            frontends.append(folder)
    for manifest in root.rglob("pom.xml"):
        if not any(part in ignored for part in manifest.relative_to(root).parts):
            backends.append(manifest.parent)
    return frontends, backends


def find_compose(root: Path) -> Path | None:
    """Find the most relevant topology file, including shallow deploy dirs."""
    direct = [root / name for name in COMPOSE_NAMES if (root / name).is_file()]
    if direct:
        return direct[0]
    ignored = {".git", "node_modules", "target", "dist", "build", "vendor"}
    candidates: list[Path] = []
    for name in COMPOSE_NAMES:
        for path in root.rglob(name):
            relative = path.relative_to(root)
            if len(relative.parts) <= 4 and not any(part in ignored for part in relative.parts):
                candidates.append(path)
    if not candidates:
        return None

    def rank(path: Path) -> tuple[int, int, int, str]:
        relative = path.relative_to(root).as_posix().lower()
        return (
            0 if relative.startswith("deploy/") else 1,
            1 if "prod" in relative else 0,
            len(path.parts),
            relative,
        )

    return sorted(set(candidates), key=rank)[0]


def analyze_runtime_dependencies(path: str) -> dict:
    """Separate dependencies used by active config from declared libraries."""
    root = Path(path)
    config_text = ""
    manifest_text = ""
    config_names = {
        "application.yml", "application.yaml", "application.properties",
        "bootstrap.yml", "bootstrap.yaml", "bootstrap.properties", ".env",
        ".env.production",
    }
    for file in root.rglob("*"):
        if not file.is_file() or any(
            part in {".git", "node_modules", "target", "dist", "build"}
            for part in file.parts
        ):
            continue
        try:
            if file.name.lower() in config_names:
                config_text += "\n" + file.read_text(errors="ignore").lower()
            elif file.name in {"pom.xml", "package.json", "requirements.txt", "pyproject.toml"}:
                manifest_text += "\n" + file.read_text(errors="ignore").lower()
        except OSError:
            continue
    required: list[str] = []
    candidates: list[str] = []
    for rule in DEPENDENCY_RULES:
        if any(marker in config_text for marker in rule.active_markers):
            required.append(rule.name)
        elif any(marker in manifest_text for marker in rule.library_markers):
            candidates.append(rule.name)
    compose = find_compose(root)
    if compose:
        text = compose.read_text(errors="ignore").lower()
        compose_services = [rule.name for rule in DEPENDENCY_RULES if rule.name.lower() in text]
        required = sorted(set(required + compose_services))
        candidates = [name for name in candidates if name not in required]
    return {
        "required": required,
        "candidates": candidates,
        "policy": "仅按生效配置和 Compose 服务认定必需依赖；仅出现在依赖声明中的中间件不自动安装",
    }


def analyze_repository_topology(path: str, build_type: str, build_file: str) -> dict:
    """Build and validate a whole-repository plan without remote mutation."""
    root = Path(path).resolve()
    manifests: list[str] = []
    for file in root.rglob("*"):
        if not file.is_file() or any(
            part in IGNORED_SOURCE_PARTS for part in file.relative_to(root).parts
        ):
            continue
        if file.name in {
            "package.json", "pom.xml", "requirements.txt", "pyproject.toml",
            "go.mod", "Cargo.toml",
        }:
            manifests.append(file.relative_to(root).as_posix())
    frontend_roots, java_roots = fullstack_roots(root)
    python_roots = sorted({
        candidate.parent
        for name in ("requirements.txt", "pyproject.toml")
        for candidate in root.rglob(name)
        if not any(part in IGNORED_SOURCE_PARTS for part in candidate.relative_to(root).parts)
    })
    database_scripts = [
        candidate.relative_to(root).as_posix()
        for candidate in root.rglob("*.sql")
        if not any(part in IGNORED_SOURCE_PARTS for part in candidate.relative_to(root).parts)
    ][:50]
    config_text = ""
    for file in root.rglob("*"):
        if (
            file.is_file()
            and file.stat().st_size < 1_000_000
            and not any(part in IGNORED_SOURCE_PARTS for part in file.relative_to(root).parts)
            and (
                file.suffix.lower() in {".ts", ".tsx", ".js", ".jsx", ".py", ".java", ".yml", ".yaml", ".env"}
                or file.name.startswith(".env")
            )
        ):
            config_text += "\n" + file.read_text(errors="ignore")
    entry_paths = sorted(set(re.findall(
        r"(?m)^\s*(?:VITE_APP_BASE|PUBLIC_URL|BASE_PATH)\s*=\s*([^\s#]+)",
        config_text,
    )))
    detected_api = detect_frontend_api_routes(path)
    plan = {
        "scan_scope": "整个仓库",
        "manifests": manifests,
        "frontend_roots": [candidate.relative_to(root).as_posix() for candidate in frontend_roots],
        "backend_roots": [candidate.relative_to(root).as_posix() for candidate in [*java_roots, *python_roots]],
        "database_scripts": database_scripts,
        "entry_paths": entry_paths,
        "api_paths": [str(row["path"]) for row in detected_api.get("routes") or []],
        "api_route_evidence": detected_api.get("evidence") or [],
        "build_type": build_type,
        "build_file": build_file,
        "services": [],
        "persistent_mounts": [],
        "errors": [],
    }
    handler = handler_for(build_type)
    handler.apply(
        TopologyContext(
            root=root,
            build_file=build_file,
            frontend_roots=tuple(frontend_roots),
            backend_roots=tuple([*java_roots, *python_roots]),
        ),
        plan,
    )
    plan["persistent_mounts"] = sorted(set(plan["persistent_mounts"]))
    return plan
"""Deployment package component."""

