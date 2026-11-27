import json
import hashlib
import re
from pathlib import Path

from .config import settings
from .models import Project
from .deployment_integration_environment import (
    effective_project_environment,
    environment_values,
    external_integration_preflight,
    store_managed_values,
)


def normalize_service_environment(service: dict, *, create: bool = False) -> dict | None:
    raw = service.get("environment")
    if raw is None and create:
        raw = {}
        service["environment"] = raw
    if isinstance(raw, list):
        raw = {
            value.split("=", 1)[0]: value.split("=", 1)[1]
            for value in raw if isinstance(value, str) and "=" in value
        }
        service["environment"] = raw
    return raw if isinstance(raw, dict) else None


def is_backend_service(name: str) -> bool:
    return any(token in str(name).lower() for token in ("backend", "server", "api", "app"))


def integration_consumers(services: dict, prefix: str) -> list[str]:
    import yaml

    return [
        name for name, service in services.items()
        if isinstance(service, dict) and prefix in yaml.safe_dump(service, allow_unicode=True)
    ]


def data_service_names(services: dict, kind: str) -> set[str]:
    aliases = {
        "mysql": {"mysql", "db", "database"},
        "redis": {"redis", "cache"},
        "postgres": {"postgres", "postgresql", "db", "database"},
    }
    image_pattern = {
        "mysql": r"(?i)^(?:[^/]+/)?mysql(?::|$)",
        "redis": r"(?i)^(?:[^/]+/)?redis(?::|$)",
        "postgres": r"(?i)^(?:[^/]+/)?postgres(?::|$)",
    }
    return {
        name for name, service in services.items()
        if isinstance(service, dict) and (
            re.match(image_pattern[kind], str(service.get("image") or ""))
            or name.lower() in aliases[kind]
        )
    }


def redis_is_required(project: Project, services: dict) -> tuple[bool, str | None]:
    redis_names = data_service_names(services, "redis")
    existing = next(iter(redis_names), None)
    analysis_text = json.dumps(project.source_analysis or {}, ensure_ascii=False)
    required = bool(
        integration_consumers(services, "YUNZHOU_REDIS_")
        or existing
        or re.search(r'"(?:service|services)"[^\n]{0,500}Redis', analysis_text, re.I)
        or re.search(r"\b(?:requires?|uses?|needs?)\s+Redis\b", analysis_text, re.I)
    )
    return required, existing


def managed_redis_values(project: Project) -> dict[str, str]:
    password = hashlib.sha256(f"{settings.app_secret}:{project.id}:redis".encode()).hexdigest()[:32]
    return {
        "YUNZHOU_REDIS_HOST": "redis",
        "YUNZHOU_REDIS_PORT": "6379",
        "YUNZHOU_REDIS_DATABASE": "0",
        "YUNZHOU_REDIS_PASSWORD": password,
    }


def managed_mysql_values(project: Project) -> dict[str, str]:
    digest = hashlib.sha256(f"{settings.app_secret}:{project.id}:mysql-managed".encode()).hexdigest()
    database = re.sub(r"[^a-zA-Z0-9_]", "_", project.slug)[:48] or "app"
    return {
        "YUNZHOU_MYSQL_HOST": "mysql",
        "YUNZHOU_MYSQL_PORT": "3306",
        "YUNZHOU_MYSQL_DATABASE": database,
        "YUNZHOU_MYSQL_USERNAME": "yunzhou",
        "YUNZHOU_MYSQL_PASSWORD": digest[:32],
        "YUNZHOU_MYSQL_ROOT_PASSWORD": hashlib.sha256((digest + ":root").encode()).hexdigest()[:32],
    }


def remove_empty_command_arguments(services: dict) -> list[str]:
    changes: list[str] = []
    for service in services.values():
        if not isinstance(service, dict):
            continue
        command = service.get("command")
        if isinstance(command, list):
            filtered = [
                value for value in command
                if not (isinstance(value, str) and re.fullmatch(r"--[A-Za-z0-9_.-]+=", value.strip()))
            ]
            if filtered != command:
                service["command"] = filtered or None
                changes.append("空启动参数")
        elif isinstance(command, str):
            filtered = re.sub(r"(?<!\S)--[A-Za-z0-9_.-]+=(?=\s|$)", "", command)
            filtered = re.sub(r"\s{2,}", " ", filtered).strip()
            if filtered != command.strip():
                service["command"] = filtered or None
                changes.append("空启动参数")
    return changes


def managed_mysql_image_for_source(
    source_path: str,
    project: Project | None = None,
    default_image: str = "mysql:8.4",
) -> tuple[str, str]:
    root = Path(source_path)
    analysis_text = json.dumps((project.source_analysis or {}) if project else {}, ensure_ascii=False)
    if re.search(r"(?:Java|JDK)[^0-9]{0,12}(?:1\.)?8\b", analysis_text, re.I) or re.search(
        r"Spring\s*Boot[^0-9]{0,12}[12]\.", analysis_text, re.I
    ):
        return "mysql:8.0", "源码分析识别为旧 Java/Spring 兼容线"
    for pom in root.rglob("pom.xml"):
        if any(part in {"target", ".git", "node_modules"} for part in pom.parts):
            continue
        text = pom.read_text(encoding="utf-8", errors="ignore")[:500_000]
        spring = re.search(r"spring-boot(?:-dependencies|-starter-parent)?[\s\S]{0,300}?<version>\s*([0-9]+)\.", text, re.I)
        java = re.search(r"<(?:java\.version|maven\.compiler\.source)>\s*(?:1\.)?([0-9]+)", text, re.I)
        spring_major = int(spring.group(1)) if spring else None
        java_major = int(java.group(1)) if java else None
        if (spring_major is not None and spring_major < 3) or (java_major is not None and java_major <= 11):
            details = []
            if spring_major is not None:
                details.append(f"Spring Boot {spring_major}.x")
            if java_major is not None:
                details.append(f"Java {java_major}")
            return "mysql:8.0", "、".join(details) + " 使用兼容线"
    return default_image, "平台默认"
