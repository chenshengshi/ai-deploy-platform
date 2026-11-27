import re
import json
import base64
import copy
import shlex
import shutil
import subprocess
import tempfile
import hashlib
import os
import threading
import time
import traceback
import zipfile
from types import SimpleNamespace
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo
from urllib.parse import quote, urlsplit, urlunsplit

from git import Repo
import httpx
import yaml
from sqlalchemy import select, text

from .config import decrypt, encrypt, settings
from .ai import analyze_project_deployment, deployment_followup, reconcile_followup_live_state
from .build_planning import (
    PLATFORM_NGINX_IMAGE,
    detect_java_log_directories,
    ensure_java_runtime_directories,
    normalize_inline_dockerfile,
    optimize_maven_dependency_layer,
    optimize_node_dependency_layer,
    platform_spa_runtime_dockerfile,
    runtime_stage_from_prebuilt_artifact,
    source_declares_environment_optional,
    strip_generated_code_fence,
    valid_generated_dockerfile,
)
from .chat.diagnostics import diagnose_blank_frontend
from .database import SessionLocal
from .deployment.logs import append_deployment_log, read_deployment_log
from .deployment.verification import frontend_code_warning, has_fatal_startup_error, http_status_accepted, required_route_accepted
from .deployment.source_paths import discover_source_root, git_source_location
from .deployment.source_cache import source_cache_guard, source_cache_lock
from .deployment.naming import compose_project_name, deployment_compose_project_name, project_directory, service_container_name as _service_container_name
from .deployment.process_control import stop_tracked_process_groups
from .deployment.compose_runtime import compose_file_args, remote_compose_files
from .deployment.image_restore import restore_release_images
from .deployment.image_cleanup import (
    cleanup_incomplete_release_images,
    cleanup_old_project_images,
    cleanup_registry_versions,
    verify_registry_tag,
)
from .deployment.execution_log import ANSI_RE, log, log_stage, tracked_run
from .deployment.release_runtime import start_deployment, stop_deployment
from .deployment.release_cleanup import delete_deployment_resources
from .deployment.source_repair import apply_safe_build_repairs
from .deployment.compose_split import split_compose_runtime
from .deployment.build_preparation import prepare_build
from .deployment.compose_plan import (
    _compose_route_groups,
    _compose_service_container_port,
    _dockerfile_exposed_port,
    compose_service_mapping as _compose_service_mapping,
    prepare_compose_image_override,
)
from .deployment.integration_reconcile import reconcile_managed_integrations
from .deployment.source_staging import stage_source
from .deployment.build_context import (
    ensure_context_ignore,
    ensure_generated_copy_inputs,
    prepare_runtime_bundle,
    snapshot_deployment_files,
    source_manifests,
    validate_runtime_only_dockerfiles,
)
from .deployment.build_execution import central_build_and_distribute
from .deployment.ai_plan import (
    _complete_source_compose,
    canonical_docker_image,
    materialize_ai_deployment_plan,
    prune_undeclared_development_services,
    reconcile_compose_build_targets,
)
from .deployment.workspace import WORKSPACE_BRANCH, persist_verified_changes
from .deployment.ports import (
    choose_node_port as _choose_node_port,
    choose_port,
    prepare_stopped_release_ports,
    stopped_port_message,
    stopped_reservation_status,
)
from .deployment.runtime_environment import application_environment
from .deployment.data_services import remove_project_managed_data_service, start_project_data_services, stop_project_data_services
from .deployment.gateway import configure_platform_gateway, platform_gateway_node, reconcile_runtime_frontend_routes, restore_platform_gateway, snapshot_platform_gateway
from .deployment.integrations import (
    effective_project_environment as _effective_project_environment,
    environment_values as _environment_values,
    external_integration_preflight as _external_integration_preflight,
    store_managed_values as _store_managed_values,
    managed_mysql_image_for_source as _managed_mysql_image_for_source,
    data_service_names,
    integration_consumers,
    is_backend_service,
    normalize_service_environment,
    managed_redis_values,
    redis_is_required,
    managed_mysql_values,
    remove_empty_command_arguments,
)
from .deployment.source_optimization import optimize_staged_sources as _optimize_staged_sources
from .deployment.build_repairs import apply_dockerfile_text_repairs
from .deployment.build_handlers import detect_build as _detect_build, detect_container_port as _detect_container_port
from .deployment.build_profiles import compatible_node_image, detect_build_profiles
from .deployment.build_generators import generate_profile_build, generate_static_build
from .deployment.topology import add_unambiguous_nginx_aliases, repair_generated_node_dependency_copy
from .deployment.runtime_policy import data_compose_project, release_directories, validate_release
from .deployment.runtime_ports import (
    compose_port_number as _compose_port_number,
    compose_published_port as _compose_published_port,
    project_traffic_plan as _project_traffic_plan,
    replace_compose_published_port as _replace_compose_published_port,
    traffic_service_roles as _traffic_service_roles,
)
from .deployment.architecture import (
    COMPOSE_NAMES,
    analyze_repository_topology,
    analyze_runtime_dependencies,
    find_compose as _find_compose,
    fullstack_roots as _fullstack_roots,
    has_project_marker as _has_project_marker,
)
from .models import AiConfig, DeployStatus, Deployment, DeploymentPortReservation, DeploymentSettings, GitCredential, Node, Project, ProjectDomainConfig, ProjectReplica, SourceType
from .proxy import get_proxy_config, proxy_with_auth
from .source_inspection import (
    _FRONTEND_API_ENV_KEYS,
    _executable_jar_score,
    _select_runnable_jar,
    _public_path_from_value,
    detect_frontend_api_routes,
    detect_frontend_public_base,
    detect_java_version,
    detect_spring_boot_version,
    dockerfile_base_images,
    enforce_nginx_pid_compatibility,
)
from .ssh import SSHNode


PLATFORM_MYSQL_IMAGE = "mysql:8.4"






_NON_OPERATIONAL_PLAN_KEYS = {
    "provider", "requested_model", "model", "summary", "mode_decision",
    "reasoning", "analysis", "analysis_notes", "confidence",
}


def actionable_plan_fingerprint(plan: dict | None) -> str:
    """Fingerprint only plan fields that can change the deployed result.

    AI explanations often vary between calls even when the effective build,
    runtime and routing plan is identical. Those prose-only differences must
    never authorize another expensive build.
    """
    if not isinstance(plan, dict):
        return ""

    def normalize(value):
        if isinstance(value, dict):
            return {
                key: normalize(item)
                for key, item in sorted(value.items())
                if key not in _NON_OPERATIONAL_PLAN_KEYS
            }
        if isinstance(value, list):
            return [normalize(item) for item in value]
        return value

    payload = json.dumps(normalize(plan), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()




class DeploymentCancelled(RuntimeError):
    pass


def normalize_login_info(work: Path | str, ai_plan: dict) -> dict:
    """Correct conservative AI auth results when the repository clearly exposes self-registration."""
    work = Path(work)
    info = {
        "auth_mode": str(ai_plan.get("auth_mode") or "unknown")[:40],
        "login_url_path": str(ai_plan.get("login_url_path") or "/")[:300],
        "username": str(ai_plan.get("login_username") or "")[:300],
        "password": str(ai_plan.get("login_password") or "")[:300],
        "note": str(ai_plan.get("login_note") or "未发现可确认的默认登录账号，请查看项目首次使用说明。")[:1000],
    }
    if info["username"] or info["password"] or info["auth_mode"] in {"default_credentials", "external_auth", "none"}:
        return info
    registration_evidence = False
    inspected = 0
    for path in work.rglob("*"):
        if inspected >= 300 or not path.is_file() or path.suffix.lower() not in {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".py", ".html", ".md"}:
            continue
        try:
            if path.stat().st_size > 1_000_000:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
            inspected += 1
            if "/api/auth/register" in text and ("/register" in text or "注册" in text):
                registration_evidence = True
                break
        except OSError:
            continue
    if registration_evidence:
        info.update({
            "auth_mode": "first_register",
            "login_url_path": "/register",
            "username": "",
            "password": "",
            "note": "项目没有默认账号密码，请打开注册页面创建首个账号；密码规则以注册页面提示为准。",
        })
    return info


def ensure_active(deployment_id: str) -> None:
    with SessionLocal() as check_db:
        current = check_db.get(Deployment, deployment_id)
        if not current or current.status == DeployStatus.stopped:
            raise DeploymentCancelled("部署已由用户停止")






def detect_build(path: str, requested: str) -> tuple[str, str | None]:
    return _detect_build(path, requested)


def detect_container_port(path: str, dockerfile_name: str = "Dockerfile") -> int | None:
    return _detect_container_port(path, dockerfile_name)
















def optimize_staged_sources(path: str) -> list[str]:
    """Rewrite only the isolated release copy so nested build files use reachable mirrors."""
    return _optimize_staged_sources(path)




























def compose_pull_images(path: str, compose_file: str) -> list[str]:
    """Return image-only Compose services; locally-built services are excluded."""
    try:
        document = yaml.safe_load((Path(path) / compose_file).read_text(encoding="utf-8", errors="ignore")) or {}
    except (OSError, yaml.YAMLError):
        return []
    images = []
    for service in (document.get("services") or {}).values():
        if isinstance(service, dict) and service.get("image") and not service.get("build"):
            image = str(service["image"]).strip()
            if image and "${" not in image and image not in images:
                images.append(image)
    return images


def required_compose_variables(path: str, compose_file: str, env_text: str | None = None) -> list[dict]:
    """Find Compose variables that explicitly require a value before Docker runs."""
    source = (Path(path) / compose_file).read_text(encoding="utf-8", errors="ignore")
    supplied = {
        line.split("=", 1)[0].strip()
        for line in (env_text or "").splitlines()
        if "=" in line and not line.lstrip().startswith("#") and line.split("=", 1)[1].strip()
    }
    supplied.update({"COMPOSE_PROJECT_NAME", "YUNZHOU_HOST_PORT", "CRM_DB_PASSWORD", "CRM_DB_ROOT_PASSWORD", "CRM_JWT_SECRET"})
    found = []
    pattern = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::?\?)([^}]*)\}")
    for match in pattern.finditer(source):
        name, hint = match.group(1), match.group(2).strip()
        if name not in supplied and not any(item["name"] == name for item in found):
            found.append({"name": name, "hint": hint or "Compose 声明为必填项"})
    return found


def ensure_managed_build_variables(project: Project, source_path: str, compose_file: str) -> list[str]:
    """Fill variables emitted by the platform's own generated build files.

    These values are build implementation details, not deployment credentials.
    They must therefore never be presented to the user as missing configuration.
    Prefer the exact package-manager version declared by the repository and use
    the same conservative version as the generated Dockerfile fallback.
    """
    compose_source = (Path(source_path) / compose_file).read_text(encoding="utf-8", errors="ignore")
    referenced = set(re.findall(r"\$\{([A-Za-z_][A-Za-z0-9_]*)[^}]*\}", compose_source))
    current_lines = (project.managed_env_text or "").splitlines()
    current_values = environment_values(project.managed_env_text)
    generated = []

    if "YUNZHOU_PNPM_VERSION" in referenced and not current_values.get("YUNZHOU_PNPM_VERSION"):
        version = "8.15.9"
        candidates = sorted(Path(source_path).rglob("package.json"), key=lambda item: len(item.parts))
        for package_file in candidates:
            try:
                package_meta = json.loads(package_file.read_text(encoding="utf-8", errors="ignore"))
            except (OSError, json.JSONDecodeError):
                continue
            manager = str(package_meta.get("packageManager") or "").strip()
            match = re.fullmatch(r"pnpm@([0-9]+(?:\.[0-9]+){1,2})(?:\+.*)?", manager, re.I)
            if match:
                version = match.group(1)
                break
        current_lines.append(f"YUNZHOU_PNPM_VERSION={version}")
        generated.append(f"YUNZHOU_PNPM_VERSION={version}")

    if generated:
        project.managed_env_text = "\n".join(current_lines).strip() + "\n"
    return generated


def effective_project_environment(project: Project) -> str:
    """Render one deterministic Compose environment with dependencies first.

    Compose expands values in an env file while reading it.  A derived value
    such as ``SPRING_DATASOURCE_URL=${YUNZHOU_MYSQL_HOST}...`` must therefore
    appear after the YUNZHOU connection fields.  Concatenating the managed and
    user files used to put derived values first and silently expanded a valid
    external database configuration to empty strings.
    """
    return _effective_project_environment(project)


def external_integration_preflight(project: Project, env_text: str) -> list[str]:
    """Validate saved external integrations before build or container startup."""
    return _external_integration_preflight(project, env_text)


def environment_values(text: str | None) -> dict[str, str]:
    return _environment_values(text)


def adapt_plan_to_current_integrations(plan: dict, project: Project) -> tuple[dict, list[str]]:
    """Apply the form's current integration choices to a saved AI plan.

    Source analysis is reusable, while external credentials and managed versus
    external choices can change immediately before deployment.  The current
    submitted configuration is authoritative and must not be shadowed by an
    older managed-service Compose plan.
    """
    adapted = json.loads(json.dumps(plan))
    values = environment_values(decrypt(project.env_text_encrypted) or "")
    changes: list[str] = []
    if project.deployment_mode != "preserve_integrations":
        return adapted, changes
    if values.get("YUNZHOU_MYSQL_MODE", "managed").lower() != "external":
        return adapted, changes
    compose_text = str(adapted.get("compose_yaml") or "")
    try:
        compose = yaml.safe_load(compose_text)
    except yaml.YAMLError:
        return adapted, changes
    services = compose.get("services") if isinstance(compose, dict) else None
    if not isinstance(services, dict):
        return adapted, changes
    mysql_services = {
        name for name, service in services.items()
        if isinstance(service, dict) and re.match(r"(?i)^(?:[^/]+/)?mysql(?::|$)", str(service.get("image") or ""))
    }
    for name in mysql_services:
        services.pop(name, None)
    variable_map = {
        "DB_HOST": "YUNZHOU_MYSQL_HOST", "MYSQL_HOST": "YUNZHOU_MYSQL_HOST",
        "DB_PORT": "YUNZHOU_MYSQL_PORT", "MYSQL_PORT": "YUNZHOU_MYSQL_PORT",
        "DB_NAME": "YUNZHOU_MYSQL_DATABASE", "DB_DATABASE": "YUNZHOU_MYSQL_DATABASE",
        "MYSQL_DATABASE": "YUNZHOU_MYSQL_DATABASE",
        "DB_USERNAME": "YUNZHOU_MYSQL_USERNAME", "DB_USER": "YUNZHOU_MYSQL_USERNAME",
        "MYSQL_USER": "YUNZHOU_MYSQL_USERNAME",
        "DB_PASSWORD": "YUNZHOU_MYSQL_PASSWORD", "MYSQL_PASSWORD": "YUNZHOU_MYSQL_PASSWORD",
    }
    for service in services.values():
        if not isinstance(service, dict):
            continue
        depends = service.get("depends_on")
        if isinstance(depends, dict):
            for name in mysql_services:
                depends.pop(name, None)
        elif isinstance(depends, list):
            service["depends_on"] = [name for name in depends if name not in mysql_services]
        env = service.get("environment")
        if isinstance(env, dict):
            for key, source in variable_map.items():
                if key in env:
                    env[key] = "${" + source + "}"
            # Frameworks frequently expose one complete JDBC URL instead of
            # separate DB_HOST/DB_PORT variables (for example Spring/Druid).
            # Rewrite the endpoint generically while preserving driver query
            # parameters, then bind matching credentials to the user's saved
            # external integration values.
            for key, current in list(env.items()):
                rendered = str(current or "")
                if re.search(r"(?i)jdbc:mysql://", rendered):
                    env[key] = re.sub(
                        r"(?i)jdbc:mysql://[^/:?\s]+(?::\d+)?/[^?\s]+",
                        "jdbc:mysql://${YUNZHOU_MYSQL_HOST}:${YUNZHOU_MYSQL_PORT}/${YUNZHOU_MYSQL_DATABASE}",
                        rendered,
                        count=1,
                    )
                    prefix = re.sub(r"(?i)(?:URL|JDBC_URL)$", "", key)
                    username_key = prefix + "USERNAME"
                    password_key = prefix + "PASSWORD"
                    if username_key in env:
                        env[username_key] = "${YUNZHOU_MYSQL_USERNAME}"
                    if password_key in env:
                        env[password_key] = "${YUNZHOU_MYSQL_PASSWORD}"
            # Spring Boot does not understand the platform's YUNZHOU_* names
            # by itself.  Older RuoYi/Druid projects commonly keep a complete
            # datasource URL in application-druid.yml, so merely passing the
            # generic values leaves the baked-in address active.  Bind both
            # the standard Spring datasource keys and the Druid master keys
            # whenever this looks like a Spring/Java application.  Environment
            # variables have higher precedence than the packaged YAML and the
            # actual secrets remain in the deployment .env file.
            spring_service = any(
                key in env for key in ("SPRING_PROFILES_ACTIVE", "SERVER_PORT", "JAVA_OPTS")
            ) or str(service.get("image") or "").lower().startswith(("openjdk", "eclipse-temurin"))
            if spring_service:
                jdbc = "jdbc:mysql://${YUNZHOU_MYSQL_HOST}:${YUNZHOU_MYSQL_PORT}/${YUNZHOU_MYSQL_DATABASE}"
                env.update({
                    "SPRING_DATASOURCE_URL": jdbc,
                    "SPRING_DATASOURCE_USERNAME": "${YUNZHOU_MYSQL_USERNAME}",
                    "SPRING_DATASOURCE_PASSWORD": "${YUNZHOU_MYSQL_PASSWORD}",
                    "SPRING_DATASOURCE_DRUID_MASTER_URL": jdbc,
                    "SPRING_DATASOURCE_DRUID_MASTER_USERNAME": "${YUNZHOU_MYSQL_USERNAME}",
                    "SPRING_DATASOURCE_DRUID_MASTER_PASSWORD": "${YUNZHOU_MYSQL_PASSWORD}",
                    "SPRING_REDIS_HOST": "${YUNZHOU_REDIS_HOST:-redis}",
                    "SPRING_REDIS_PORT": "${YUNZHOU_REDIS_PORT:-6379}",
                    "SPRING_REDIS_DATABASE": "${YUNZHOU_REDIS_DATABASE:-0}",
                    "SPRING_REDIS_PASSWORD": "${YUNZHOU_REDIS_PASSWORD:-}",
                })
    adapted["compose_yaml"] = yaml.safe_dump(compose, allow_unicode=True, sort_keys=False)
    adapted["services"] = [name for name in (adapted.get("services") or []) if name not in mysql_services and "mysql" not in str(name).lower()]
    adapted["inferred_config"] = [
        row for row in (adapted.get("inferred_config") or [])
        if str(row.get("key") or "") not in variable_map
    ]
    changes.append("已按当前表单绑定外部 MySQL 到应用实际读取的运行参数，并移除平台托管 MySQL 服务")
    return adapted, changes


def store_managed_values(project: Project, values: dict[str, str]) -> list[str]:
    """Store platform-owned connection values in readable project configuration."""
    return _store_managed_values(project, values)


def apply_ai_inferred_config(project: Project, plan: dict) -> list[dict]:
    """Persist only high-confidence, non-secret AI findings without overwriting user values."""
    current_lines = (project.managed_env_text or "").splitlines()
    user_keys = {
        line.split("=", 1)[0].strip() for line in (decrypt(project.env_text_encrypted) or "").splitlines()
        if "=" in line and not line.lstrip().startswith("#")
    }
    positions = {line.split("=", 1)[0].strip(): index for index, line in enumerate(current_lines) if "=" in line and not line.lstrip().startswith("#")}
    applied = []
    secret_words = ("password", "secret", "token", "private", "access_key", "credential")
    allowed_suffixes = ("_URL", "_URI", "_ENDPOINT", "_HOST", "_PORT", "_BUCKET", "_REGION", "_PREFIX", "_ISSUER")
    for item in plan.get("inferred_config") or []:
        if not isinstance(item, dict) or str(item.get("confidence", "")).lower() != "high":
            continue
        key, value = str(item.get("key") or "").strip(), str(item.get("value") or "").strip()
        lower = key.lower()
        if (not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", key) or key in positions or key in user_keys or
                any(word in lower for word in secret_words) or not key.endswith(allowed_suffixes) or
                not value or len(value) > 2048 or any(marker in value.lower() for marker in ("...", "<", ">", "your_", "example.com"))):
            continue
        current_lines.append(f"{key}={value}")
        positions[key] = len(current_lines) - 1
        applied.append({"key": key, "value": value, "source": str(item.get("source") or "AI 源码分析")})
    if applied:
        project.managed_env_text = "\n".join(current_lines).strip() + "\n"
    return applied


def ensure_managed_secrets(project: Project, compose_path: str, compose_file: str) -> list[str]:
    """Generate credentials owned by a fresh managed stack, never third-party credentials."""
    effective_env = "\n".join(filter(None, (project.managed_env_text or "", decrypt(project.env_text_encrypted) or "")))
    missing = required_compose_variables(compose_path, compose_file, effective_env)
    external_prefixes = ("OIDC_", "OAUTH_", "PAYMENT_", "SMS_", "SMTP_", "S3_EXTERNAL_")
    secret_markers = (
        "PASSWORD", "SECRET", "TOKEN", "ACCESS_KEY",
        # ASP.NET commonly maps nested configuration keys with ``__`` and
        # names its JWT secret ``Jwt__SigningKey``.  It is just as much a
        # platform-owned credential as JWT_SECRET and must never require the
        # user to invent a value during a managed-fresh deployment.
        "SIGNINGKEY", "SIGNING_KEY", "PRIVATE_KEY", "ENCRYPTION_KEY",
        "ENC_KEY", "HASH_SALT",
    )
    # Compose permits `${JWT_SECRET:-}` and similar optional-empty defaults.
    # They are syntactically valid but almost never operationally valid for a
    # managed application.  Treat every referenced platform-owned secret as a
    # value that needs generation, even when Compose itself would accept an
    # empty default.  External integrations remain user-owned below.
    supplied_values = environment_values(effective_env)
    compose_source = (Path(compose_path) / compose_file).read_text(encoding="utf-8", errors="ignore")
    referenced_names = re.findall(r"\$\{([A-Za-z_][A-Za-z0-9_]*)[^}]*\}", compose_source)
    known_missing = {item["name"] for item in missing}
    for name in referenced_names:
        upper_name = name.upper()
        if (name not in known_missing and not supplied_values.get(name)
                and any(marker in upper_name for marker in secret_markers)):
            missing.append({"name": name, "hint": "Compose 引用了可为空的敏感配置，平台将生成非空安全值"})
            known_missing.add(name)
    current_lines = (project.managed_env_text or "").splitlines()
    generated = []
    for item in missing:
        key = item["name"]
        upper_key = key.upper()
        is_username = upper_key in {"USER", "USERNAME"} or upper_key.endswith(("_USER", "_USERNAME"))
        is_secret = any(marker in upper_key for marker in secret_markers)
        if key.startswith(external_prefixes) or not (is_username or is_secret):
            continue
        digest = hashlib.sha256(f"{settings.app_secret}:{project.id}:{key}".encode()).hexdigest()
        if is_username:
            safe_slug = re.sub(r"[^a-z0-9]+", "_", project.slug.lower()).strip("_")[:20] or "app"
            value = f"yz_{safe_slug}_{digest[:6]}"
        elif upper_key.endswith("ACCESS_KEY"):
            value = "yz" + digest[:18]
        else:
            value = digest[:48]
        current_lines.append(f"{key}={value}")
        generated.append(key)
    if generated:
        project.managed_env_text = "\n".join(current_lines).strip() + "\n"
    return generated


def managed_mysql_image_for_source(source_path: str, project: Project | None = None) -> tuple[str, str]:
    """Choose a managed MySQL line that matches the application's framework era."""
    return _managed_mysql_image_for_source(source_path, project, PLATFORM_MYSQL_IMAGE)




def infer_verified_access_path(source_path: str, ai_plan: dict | None) -> tuple[str, str]:
    """Choose a source-backed HTTP path when the model leaves it at `/`.

    Only explicit routes found in source or project documentation are
    considered. Parameterized/detail routes are excluded because they require
    data. The returned evidence is written to the deployment log so a later
    successful access check can promote it to verified experience.
    """
    configured = str((ai_plan or {}).get("access_path") or "/").strip()
    safe_path = re.compile(r"^/[A-Za-z0-9._~!$&*+,;=:@%/-]*$")
    if configured and configured != "/" and safe_path.fullmatch(configured):
        return (configured if configured.startswith("/") else "/" + configured), "AI 部署方案"
    # A generated healthcheck is stronger evidence than a model's generic
    # access_path="/". API-only services commonly return 404 at the root while
    # their explicit readiness endpoint is healthy (for example /api/tags).
    # Reuse only the URL path; host and port remain owned by the gateway.
    compose_evidence = str((ai_plan or {}).get("compose_yaml") or "")
    for match in re.finditer(r"https?://[^/\s'\"\]]+(?P<path>/[A-Za-z0-9._~!$&*+,;=:@%/-]*)", compose_evidence):
        health_path = match.group("path").rstrip(".,;:") or "/"
        if health_path != "/" and safe_path.fullmatch(health_path):
            return health_path, "生成方案健康检查"
    root = Path(source_path)
    candidates: list[tuple[int, str, str]] = []
    route_pattern = re.compile(r"(?<![A-Za-z0-9_])(/(?:api|actuator)/[A-Za-z0-9_.~!$&*+,;=:@%/-]+)")
    preferred_names = {"README.md", "README", "readme.md"}
    files = [p for p in root.rglob("*") if p.is_file() and (
        p.name in preferred_names or p.suffix.lower() in {".java", ".kt", ".py", ".js", ".ts", ".cs", ".md"}
    )]
    # ASP.NET projects often apply a global prefix through an MVC convention
    # and keep controller routes relative (for example prefix `api` plus
    # `[Route("tags")]`). Resolve that convention once before inspecting the
    # individual controllers so API-only applications are not rejected just
    # because their root path intentionally returns 404.
    csharp_prefix = ""
    for candidate_file in files:
        if candidate_file.suffix.lower() != ".cs":
            continue
        candidate_text = candidate_file.read_text(encoding="utf-8", errors="replace")[:300_000]
        prefix_match = re.search(
            r"ApiRoutePrefixConvention\s*\([^)]*?\?\?\s*[\"']([^\"']+)[\"']",
            candidate_text,
            re.S,
        ) or re.search(r"UsePathBase\s*\(\s*[\"']([^\"']+)[\"']", candidate_text)
        if prefix_match:
            csharp_prefix = prefix_match.group(1).strip("/")
            break
    for file in files[:500]:
        if any(part in {".git", "node_modules", "target", "dist", "build"} for part in file.relative_to(root).parts):
            continue
        text = file.read_text(encoding="utf-8", errors="replace")[:300_000]
        relative_file = file.relative_to(root).as_posix()
        if file.suffix.lower() == ".cs":
            controller_route = re.search(r"\[Route\s*\(\s*[\"']([^\"']+)[\"']\s*\)\s*\]", text)
            route_root = controller_route.group(1).strip("/") if controller_route else ""
            for method_path in re.findall(r"\[HttpGet(?:\s*\(\s*[\"']([^\"']*)[\"']\s*\))?\s*\]", text):
                if "{" in method_path or "}" in method_path:
                    continue
                route = "/" + "/".join(
                    part for part in (csharp_prefix, route_root, method_path.strip("/")) if part
                )
                route = re.sub(r"/+", "/", route)
                if route != "/" and safe_path.fullmatch(route):
                    route_rank = 0 if re.search(r"/(?:tags|list|health|status)(?:/|$)", route, re.I) else 1
                    candidates.append((route_rank, route, relative_file))
        # Spring controllers commonly split a route between the class and the
        # method, for example `/api/device` + `list/{pageNum}/{pageSize}`.  A
        # class-level mapping is only a namespace and often returns 404, so
        # build a concrete GET probe from both annotations before considering
        # generic string matches.  Path variables use harmless deterministic
        # values because this probe only verifies routing/readiness.
        if file.suffix.lower() in {".java", ".kt"}:
            class_match = re.search(
                r"@RequestMapping\s*\(\s*(?:value\s*=\s*)?[\"']([^\"']+)[\"'][^)]*\)\s*(?:public\s+)?class\s+",
                text,
                re.S,
            )
            class_path = class_match.group(1).strip("/") if class_match else ""
            method_pattern = re.compile(
                r"@(GetMapping|RequestMapping)\s*\((.*?)\)\s*"
                r"(?:@[A-Za-z_][A-Za-z0-9_.]*(?:\([^)]*\))?\s*)*"
                r"(?:public|protected|private)\s+",
                re.S,
            )
            for annotation, arguments in method_pattern.findall(text):
                if annotation == "RequestMapping" and "RequestMethod.GET" not in arguments:
                    continue
                value_match = re.search(r"(?:value|path)\s*=\s*[\"']([^\"']+)[\"']|^[\s]*[\"']([^\"']+)[\"']", arguments)
                method_path = next((value for value in (value_match.groups() if value_match else ()) if value), "")
                if not method_path:
                    continue
                joined = "/" + "/".join(part for part in (class_path, method_path.strip("/")) if part)
                joined = re.sub(r"\{[^}/]+\}", "1", joined)
                if safe_path.fullmatch(joined):
                    # Prefer collection/list/health endpoints over mutations or
                    # detail endpoints when several concrete GET routes exist.
                    route_rank = 0 if re.search(r"/(?:list|health|status)(?:/|$)", joined, re.I) else 1
                    candidates.append((route_rank, joined, relative_file))
        for match in route_pattern.finditer(text):
            route = match.group(1).rstrip("/.,;:`'\"")
            if not route or "{" in route or "}" in route:
                continue
            candidates.append((2, route, relative_file))
    if not candidates:
        return "/", "默认根路径"
    # Collection and health endpoints are safer than deep resource paths.
    candidates.sort(key=lambda item: (item[0], item[1].count("/"), len(item[1]), item[1]))
    _, route, evidence = candidates[0]
    return route, f"源码证据 {evidence}"


def preflight_ai_deployment_plan(
    source_path: str, plan: dict, project: Project, db=None, previous_error: str = ""
) -> dict:
    """Materialize and validate an AI plan in a disposable source copy."""
    source = Path(source_path).resolve()
    preflight_root = Path(settings.build_data_root) / "builder" / "preflight"
    preflight_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="yunzhou-analysis-", dir=preflight_root) as temporary:
        rehearsal = Path(temporary) / "source"
        shutil.copytree(
            source,
            rehearsal,
            symlinks=True,
            ignore=shutil.ignore_patterns(
                ".git", ".agents", "node_modules", "target", "dist", "build", "__pycache__"
            ),
        )
        effective_plan, automatic_repairs = adapt_plan_to_current_integrations(plan, project)
        build_type, build_file, detected_port = materialize_ai_deployment_plan(
            str(rehearsal), effective_plan, getattr(project, "release_strategy", "auto") or "auto"
        )
        # Reuse only bounded repair classifiers implemented by the platform.
        # The previous failure is evidence, never a command or model prompt.
        safe_repairs = apply_safe_build_repairs(str(rehearsal), previous_error, project.deployment_mode)
        managed_integrations: list[str] = []
        generated_secrets: list[str] = []
        if build_type == "compose":
            # Analysis must exercise the same integration reconciliation as a
            # real deployment for every deployment mode. In particular, an
            # external MySQL selection is a final decision: an AI/source plan
            # must not reintroduce a mysql/db service during preflight. This
            # also keeps the stored preflight topology consistent with the
            # files that are eventually deployed.
            managed_integrations = reconcile_managed_integrations(project, str(rehearsal), build_file)
            # This helper generates only platform-owned credentials and skips
            # third-party integration prefixes, so it is safe for a mixed
            # preserve-integrations plan (for example external MySQL plus a
            # platform-managed Redis) as well as managed-fresh deployments.
            generated_secrets = ensure_managed_secrets(project, str(rehearsal), build_file)
        missing = required_compose_variables(
            str(rehearsal), build_file, effective_project_environment(project)
        ) if build_type == "compose" else []
        topology = analyze_repository_topology(str(rehearsal), build_type, build_file)
        if topology.get("errors"):
            raise RuntimeError("；".join(topology["errors"]))
        generated = rehearsal / build_file
        result = {
            "status": "passed" if not missing else "needs_configuration",
            "build_type": build_type,
            "build_file": build_file,
            "container_port": detected_port,
            "service_count": len(topology.get("services") or []),
            "services": topology.get("services") or [],
            "missing_configuration": missing,
            "automatic_repairs": (
                automatic_repairs
                + [f"经验修复：{name}" for name in safe_repairs]
                + [f"托管依赖：{name}" for name in managed_integrations]
                + [f"自动凭据：{name}" for name in generated_secrets]
            ),
            "generated_sha256": hashlib.sha256(generated.read_bytes()).hexdigest() if generated.is_file() else None,
            "source_untouched": True,
        }
        if db is not None and not missing:
            # Source analysis must not compile the same application twice.
            # The generated files, topology, variables, ports, integrations,
            # database initialization assets and known failure classifiers are
            # validated here. The real build remains the single authoritative
            # compilation during deployment, where its image/cache is retained.
            result["execution"] = {
                "status": "static_validated",
                "mode": "analysis_only",
                "reason": "静态架构与配置校验通过；镜像将在发布阶段仅构建一次",
            }
            result["status"] = "passed"
        return result


def _run_temporary_privileged_preflight(db, rehearsal: Path, build_type: str, build_file: str, project: Project) -> dict:
    """Build and start an isolated disposable release on the platform builder."""
    values = environment_values(effective_project_environment(project))
    external = [
        service for service in ("MYSQL", "REDIS")
        if project.deployment_mode == "preserve_integrations"
        and values.get(f"YUNZHOU_{service}_MODE", "").lower() == "external"
    ]
    if external:
        return {
            "status": "skipped_external_integration",
            "mode": "temporary_privileged",
            "reason": "外部集成不会在预演中使用生产凭据：" + "、".join(external),
        }
    node = platform_gateway_node(db)
    if not node:
        return {"status": "skipped_no_builder", "mode": "temporary_privileged", "reason": "没有可用的平台构建节点"}
    compose_project = "yz-preflight-" + hashlib.sha256(f"{project.id}:{time.time_ns()}".encode()).hexdigest()[:12]
    started = time.monotonic()
    environment = {
        **values,
        "YUNZHOU_HOST_PORT": "",
        "CRM_DB_PASSWORD": hashlib.sha256(f"{compose_project}:db".encode()).hexdigest()[:32],
        "CRM_DB_ROOT_PASSWORD": hashlib.sha256(f"{compose_project}:root".encode()).hexdigest()[:40],
        "YUNZHOU_REDIS_PASSWORD": hashlib.sha256(f"{compose_project}:redis".encode()).hexdigest()[:32],
        "CRM_JWT_SECRET": hashlib.sha256(f"{compose_project}:jwt".encode()).hexdigest(),
    }
    env_file = rehearsal / ".yunzhou.preflight.env"
    compose_path = rehearsal / build_file
    container_name = compose_project + "-app"
    image_name = compose_project + ":test"
    base = ""
    logs = ""
    try:
        with SSHNode(node) as ssh:
            code, port_output = ssh.run(
                "for p in $(seq 45000 45999); do "
                "if ! ss -ltn 2>/dev/null | awk '{print $4}' | grep -q \":${p}$\"; "
                "then echo $p; break; fi; done",
                timeout=15,
            )
            port = port_output.strip().splitlines()[-1] if code == 0 and port_output.strip() else ""
            if not port.isdigit():
                raise RuntimeError("没有可用的临时预演端口")
            environment["YUNZHOU_HOST_PORT"] = port
            env_file.write_text("\n".join(f"{key}={value}" for key, value in environment.items() if value is not None) + "\n", encoding="utf-8")
            env_file.chmod(0o600)
            if build_type == "compose":
                base = (
                    f"cd {shlex.quote(str(rehearsal))} && "
                    "export DOCKER_BUILDKIT=0 COMPOSE_DOCKER_CLI_BUILD=0 COMPOSE_BAKE=false && "
                    f"docker compose --env-file {shlex.quote(env_file.name)} -p {shlex.quote(compose_project)} -f {shlex.quote(compose_path.name)}"
                )
                preflight_command = base + " up -d --build"
            else:
                container_port = detect_container_port(str(rehearsal), build_file) or project.container_port or 80
                preflight_command = (
                    f"cd {shlex.quote(str(rehearsal))} && export DOCKER_BUILDKIT=0 && "
                    f"docker build -f {shlex.quote(build_file)} -t {shlex.quote(image_name)} . && "
                    f"docker run -d --name {shlex.quote(container_name)} --env-file {shlex.quote(env_file.name)} "
                    f"-p 127.0.0.1:{port}:{int(container_port)} {shlex.quote(image_name)}"
                )
            # ``cd`` is a shell builtin, so timeout must wrap a shell rather
            # than trying to execute ``cd`` as a binary.
            code, output = ssh.run(
                "timeout 900 sh -lc " + shlex.quote(preflight_command),
                timeout=930,
            )
            logs = output[-20_000:]
            if code:
                raise RuntimeError("预演构建或启动失败：" + (output[-4000:] or "未返回日志"))
            verified = False
            last_status = ""
            for _ in range(36):
                check_code, check_output = ssh.run(
                    f"curl -sS -o /dev/null -w '%{{http_code}}' --connect-timeout 3 --max-time 8 http://127.0.0.1:{port}/",
                    timeout=12,
                )
                last_status = check_output.strip()[-3:]
                if check_code == 0 and last_status.isdigit() and 200 <= int(last_status) < 500:
                    verified = True
                    break
                time.sleep(5)
            if not verified:
                if build_type == "compose":
                    _, service_logs = ssh.run(base + " logs --no-color --tail 160", timeout=30)
                else:
                    _, service_logs = ssh.run(f"docker logs --tail 160 {shlex.quote(container_name)}", timeout=30)
                logs = service_logs[-20_000:]
                raise RuntimeError(f"预演访问验证失败（HTTP {last_status or '无响应'}）：" + logs[-4000:])
            return {
                "status": "passed", "mode": "temporary_privileged",
                "builder": node.name, "http_status": int(last_status),
                "duration_seconds": round(time.monotonic() - started, 1),
                "cleanup": "attempted_after_verification",
            }
    except Exception as exc:
        return {
            "status": "failed", "mode": "temporary_privileged",
            "builder": node.name, "error": str(exc)[:6000], "log_tail": logs[-6000:],
            "duration_seconds": round(time.monotonic() - started, 1),
        }
    finally:
        try:
            with SSHNode(node) as ssh:
                if build_type == "compose":
                    cleanup = (
                        f"cd {shlex.quote(str(rehearsal))} && export DOCKER_BUILDKIT=0 COMPOSE_DOCKER_CLI_BUILD=0 COMPOSE_BAKE=false && "
                        f"docker compose --env-file {shlex.quote(env_file.name)} -p {shlex.quote(compose_project)} "
                        f"-f {shlex.quote(compose_path.name)} down --volumes --rmi local --remove-orphans"
                    )
                else:
                    cleanup = (
                        f"docker rm -f {shlex.quote(container_name)} >/dev/null 2>&1 || true; "
                        f"docker image rm -f {shlex.quote(image_name)} >/dev/null 2>&1 || true"
                    )
                ssh.run(cleanup, timeout=180)
        except Exception:
            pass


def choose_node_port(
    db, node: Node, preferred: int | None, reserved: set[int] | None = None,
    exclude_deployment_id: str | None = None,
) -> int:
    return _choose_node_port(
        db,
        node,
        preferred,
        ssh_factory=SSHNode,
        reserved=reserved,
        exclude_deployment_id=exclude_deployment_id,
    )


def ai_checkpoint(deployment_id: str, stage: str, evidence: str) -> None:
    """Run the AI observer beside the deployment so AI latency never blocks it."""
    def follow():
        try:
            with SessionLocal() as db:
                dep = db.get(Deployment, deployment_id)
                if not dep:
                    return
                result = deployment_followup(db, dep, db.get(Project, dep.project_id), db.get(Node, dep.node_id), stage, evidence[-5000:])
                db.expire_all()
                dep = db.get(Deployment, deployment_id)
                live_log = read_deployment_log(deployment_id) or evidence
                result, live_stage = reconcile_followup_live_state(result, dep, stage, live_log)
                result.update({"stage": live_stage, "status": dep.status.value, "generated_at": datetime.now(timezone.utc).isoformat()})
                log(deployment_id, "[AI跟进] " + json.dumps(result, ensure_ascii=False) + "\n")
        except Exception as exc:
            log(deployment_id, "[AI跟进] " + json.dumps({"source": "system", "stage": stage, "summary": "AI 分析暂时不可用，部署继续执行。", "advice": str(exc)[:300]}, ensure_ascii=False) + "\n")
    threading.Thread(target=follow, name=f"ai-follow-{deployment_id[:8]}", daemon=True).start()


def verify_access(db, deployment_id: str, access_url: str, required_paths: list[str] | None = None) -> str:
    """Do not mark a deployment complete until its public entry is reachable."""
    gateway = platform_gateway_node(db)
    if not gateway:
        raise RuntimeError("没有可用于访问验证的平台网关节点")
    last_output = ""
    ai_checkpoint(deployment_id, "验证访问地址", f"开始持续验证 {access_url}")
    parsed = urlsplit(access_url)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    # Public-IP hairpin is commonly disabled by routers. Test the exact gateway
    # listener locally while preserving the public Host header and request path.
    if parsed.scheme == "https":
        curl_target = access_url
        route_args = f"--resolve {shlex.quote(parsed.hostname + ':' + str(port) + ':127.0.0.1')}"
    else:
        curl_target = f"http://127.0.0.1:{port}{path}"
        host_header = parsed.hostname + ((":" + str(port)) if port != 80 else "")
        route_args = f"-H {shlex.quote('Host: ' + host_header)}"

    def collect_diagnostics() -> str:
        try:
            dep = db.get(Deployment, deployment_id)
            project = db.get(Project, dep.project_id) if dep else None
            node = db.get(Node, dep.node_id) if dep else None
            if not dep or not project or not node:
                return ""
            compose_project = shlex.quote(deployment_compose_project_name(dep, project))
            direct_path = shlex.quote(path)
            with SSHNode(node) as node_ssh:
                _, text = node_ssh.run(
                    f"echo '--- 节点直连 ---'; curl -i -sS --max-time 8 http://127.0.0.1:{int(dep.host_port or 0)}{direct_path} | head -40; "
                    "echo '--- 端口监听 ---'; ss -lntp 2>/dev/null | grep -E ':" + str(int(dep.host_port or 0)) + "\\b' || true; "
                    "ids=$( { docker ps -aq --filter label=com.docker.compose.project=" + compose_project + "; "
                    "docker ps -aq --filter name=" + shlex.quote(project.slug) + "; "
                    "docker ps -q --filter publish=" + str(int(dep.host_port or 0)) + "; } | sort -u); "
                    "echo '--- 容器状态 ---'; for id in $ids; do docker inspect -f '{{.Name}} {{.State.Status}} {{.RestartCount}} {{json .NetworkSettings.Ports}}' $id; done; "
                    "echo '--- 容器日志 ---'; for id in $ids; do "
                    "echo \"### $(docker inspect -f '{{.Name}}' $id | sed 's#^/##')\"; docker logs --tail 200 $id 2>&1; done",
                    timeout=90,
                )
            return text
        except Exception as exc:
            log(deployment_id, f"[访问诊断] 诊断采集失败：{exc}\n")
            return ""

    max_attempts = 6
    with SSHNode(gateway) as gateway_ssh:
        attempt = 0
        while attempt < max_attempts:
            attempt += 1
            ensure_active(deployment_id)
            code, output = gateway_ssh.run(
                "curl -L -sS -o /dev/null --connect-timeout 4 --max-time 10 "
                f"{route_args} -w '%{{http_code}}' {shlex.quote(curl_target)}"
            )
            status = output.strip()[-3:] if output.strip() else "000"
            # A missing route is not a successful application verification.
            # Protected endpoints may legitimately answer 401/403; otherwise
            # require a normal success or redirect response.
            accepted = http_status_accepted(status)
            route_failures: list[str] = []
            if code == 0 and accepted:
                for required_path in dict.fromkeys(required_paths or []):
                    required_path = "/" + str(required_path or "").lstrip("/")
                    if required_path == "/":
                        continue
                    probe_target = (
                        urlunsplit((parsed.scheme, parsed.netloc, required_path, "", ""))
                        if parsed.scheme == "https" else f"http://127.0.0.1:{port}{required_path}"
                    )
                    probe_code, probe_output = gateway_ssh.run(
                        "curl -sS -o /dev/null --connect-timeout 4 --max-time 10 "
                        f"{route_args} -w '%{{http_code}}' {shlex.quote(probe_target)}"
                    )
                    probe_status = probe_output.strip()[-3:] if probe_output.strip() else "000"
                    probe_ok = required_route_accepted(probe_code, probe_status)
                    if not probe_ok:
                        route_failures.append(f"{required_path}=HTTP {probe_status}")
                if route_failures:
                    last_output = "；".join(route_failures)
                    log(deployment_id, f"[检查] 前端入口可达，但后端路由尚未就绪：{last_output}\n")
                    accepted = False
                else:
                    frontend_issue = diagnose_blank_frontend(access_url)
                    if frontend_issue:
                        detail = frontend_code_warning(frontend_issue)
                        # The platform has successfully built, started and
                        # exposed the service. A wrong SPA public base is a
                        # project-code defect, so keep the release successful
                        # and surface it as a precise diagnostic warning.
                        log(deployment_id, f"[前端代码提示] 发布服务可达，但页面可能空白：{detail}\n")
                    qualifier = "（服务可达，需要鉴权）" if int(status) in {401, 403} else ""
                    log(deployment_id, f"[检查] 第 {attempt} 次访问验证通过：HTTP {status}{qualifier} · {access_url}\n")
                    ai_checkpoint(deployment_id, "验证访问地址", f"访问验证通过：HTTP {status}{qualifier}，地址 {access_url}")
                    return access_url
            # Model/source inference is useful for API-only services, but a
            # concrete business endpoint is not a readiness contract.  It may
            # legitimately be unavailable before seed data exists, or contain
            # a repository-level bug, while the application's explicit root
            # entry is already healthy.  For any failed inferred sub-path,
            # probe `/` immediately.  A passing root proves deployment
            # reachability; the original status remains in the audit log as a
            # business-route warning instead of incorrectly failing the whole
            # deployment.  Authentication responses are accepted above and
            # therefore never enter this fallback.
            if not accepted and path != "/" and not required_paths:
                root_url = urlunsplit((parsed.scheme, parsed.netloc, "/", "", ""))
                root_target = root_url if parsed.scheme == "https" else f"http://127.0.0.1:{port}/"
                root_code, root_output = gateway_ssh.run(
                    "curl -L -sS -o /dev/null --connect-timeout 4 --max-time 10 "
                    f"{route_args} -w '%{{http_code}}' {shlex.quote(root_target)}"
                )
                root_status = root_output.strip()[-3:] if root_output.strip() else "000"
                root_accepted = http_status_accepted(root_status)
                if root_code == 0 and root_accepted:
                    log(
                        deployment_id,
                        f"[访问路径修正] 推断业务路径 {path} 返回 HTTP {status}，"
                        f"根入口验证通过 HTTP {root_status}；已采用 {root_url}，"
                        "原业务路径异常已保留为诊断证据。\n",
                    )
                    ai_checkpoint(
                        deployment_id,
                        "验证访问地址",
                        f"推断业务路径 {path} 返回 HTTP {status}，根入口通过 HTTP {root_status}，"
                        f"部署可达地址 {root_url}；业务路径异常需单独诊断",
                    )
                    return root_url.rstrip("/")
            if not route_failures:
                last_output = output.strip() or f"curl exit={code}, HTTP {status}"
            log(deployment_id, f"[检查] 第 {attempt}/{max_attempts} 次访问尚未就绪：{last_output[-300:]}\n")
            if attempt in (2, 4, 6):
                diagnostic_text = collect_diagnostics()
                if has_fatal_startup_error(diagnostic_text):
                    log(deployment_id, "[访问诊断] 已发现确定性启动错误，停止无意义的重复 HTTP 检查。\n")
                    ai_checkpoint(deployment_id, "访问失败诊断", diagnostic_text[-5000:])
                    raise RuntimeError(
                        "服务启动日志已出现确定性错误，访问验证提前停止：\n" + diagnostic_text[-10000:]
                    )
                ai_checkpoint(deployment_id, "验证访问地址", f"第 {attempt} 次仍不可访问：{last_output[-1200:]}")
            if attempt < max_attempts:
                time.sleep(15)
    # Preserve the evidence before the failed release is cleaned. Without the
    # application logs, an HTTP 502 only tells the AI that the gateway could
    # not connect and leads to blind retries.
    diagnostic_text = collect_diagnostics()
    if diagnostic_text:
        log(deployment_id, "[访问诊断] 清理前已采集节点直连、端口监听和容器日志：\n" + diagnostic_text[-24000:] + "\n")
        ai_checkpoint(deployment_id, "访问失败诊断", diagnostic_text[-5000:])
    evidence = ("；清理前诊断：\n" + diagnostic_text[-10000:]) if diagnostic_text else ""
    raise RuntimeError(f"服务已启动，但按每 15 秒一次、共 {attempt} 次的规则验证后仍不可访问：{last_output}{evidence}")


def node_platform(node: Node) -> str:
    with SSHNode(node) as ssh:
        code, output = ssh.run("uname -m", timeout=20)
    if code:
        raise RuntimeError("无法识别目标服务器 CPU 架构：" + output)
    machine = output.strip().lower()
    return "linux/arm64" if machine in {"aarch64", "arm64"} else "linux/amd64"












def execute(deployment_id: str) -> None:
    work = None
    cleanup_root = None
    runtime_bundle = None
    gateway_snapshot = None
    gateway_switched = False
    public_access = None
    preempted_shared_containers: list[str] = []
    verification_paths: list[str] = []
    workspace_repaired_files: list[str] = []
    with SessionLocal() as db:
        dep = db.get(Deployment, deployment_id)
        if not dep:
            return
        dep.status = DeployStatus.running
        dep.started_at = datetime.now(timezone.utc)
        db.commit()

        project = db.get(Project, dep.project_id)
        node = db.get(Node, dep.node_id)
        current_stage = "analyze"
        def restore_preempted_runtime(reason: str) -> None:
            if not preempted_shared_containers or not node:
                return
            with SSHNode(node) as restore_ssh:
                container_ids = " ".join(shlex.quote(value) for value in preempted_shared_containers)
                code, output = restore_ssh.run(f"docker start {container_ids}", timeout=120)
            if code:
                log(dep.id, f"[版本回退] 新版本{reason}，但旧应用容器恢复失败：{output[-800:]}\n")
            else:
                log(dep.id, f"[版本回退] 新版本{reason}，旧应用容器已恢复；固定卷未变更。\n")
                preempted_shared_containers.clear()
        try:
            log_stage(dep.id, "开始", "analyze")
            log(dep.id, "[准备] 正在获取项目源码...\n")
            ensure_active(dep.id)
            work, revision, cleanup_root, source_subpath = stage_source(project, db, dep.id)
            ensure_active(dep.id)
            previous_error = (
                dep.log_text or ""
                if str(dep.trigger or "").startswith("ai_autofix_") and "[修复问题]" in (dep.log_text or "")
                else ""
            )
            # A user-requested retry must receive the same bounded repair
            # context as an automatic retry.  Previously only ai_autofix
            # carried the last error, so clicking "retry" repeated a known
            # deterministic failure without applying the learned repair.
            # The next manual release after a failure is also a retry from the
            # platform's point of view. Carry forward repair evidence when the
            # immediately preceding release on this node failed; do not require
            # a special trigger string and do not resurrect an older failure
            # after an intervening successful/stopped release.
            previous_rows = db.scalars(
                select(Deployment)
                .where(
                    Deployment.project_id == dep.project_id,
                    Deployment.node_id == dep.node_id,
                    Deployment.created_at < dep.created_at,
                )
                .order_by(Deployment.created_at.desc())
                .limit(12)
            ).all()
            failure_evidence = []
            for previous in previous_rows:
                if previous.status == DeployStatus.success:
                    break
                if previous.status == DeployStatus.failed:
                    # The compact error column often contains only Docker's
                    # final non-zero command.  The immediately preceding log
                    # contains the actionable line (404, TLS issuer, missing
                    # file, compiler error).  Feed both to deterministic
                    # repair and AI analysis so a manual retry is not blind.
                    detail = "\n".join(value for value in (
                        previous.error or "",
                        (previous.log_text or "")[-12_000:],
                    ) if value)
                    if detail:
                        failure_evidence.append(detail)
            previous_error = "\n\n".join(value for value in (
                previous_error,
                "\n\n".join(failure_evidence),
            ) if value)
            if source_subpath:
                log(dep.id, f"[源码] 已定位仓库项目目录 /{source_subpath}\n")
            optimized_files = optimize_staged_sources(work)
            if optimized_files:
                log(dep.id, "[源码] 已将发布副本中的国外依赖源替换为国内镜像：" + "、".join(optimized_files) + "\n")
            dependency_analysis = analyze_runtime_dependencies(work)
            log(dep.id, "[依赖分析] " + json.dumps(dependency_analysis, ensure_ascii=False) + "\n")
            ai_plan = None
            integration_changes: list[str] = []
            repair_analysis = False
            repair_plan_changed = False
            if project.build_type == "auto":
                source_analysis = project.source_analysis or {}
                saved_plan = source_analysis.get("deployment_plan")
                analyzed_revision = str(source_analysis.get("revision") or "").strip()
                current_revision = str(revision or "").strip()
                repair_analysis = bool(previous_error and str(dep.trigger or "").startswith("ai_autofix_"))
                if (
                    source_analysis.get("status") == "completed"
                    and isinstance(saved_plan, dict)
                    and saved_plan
                    and analyzed_revision
                    and analyzed_revision == current_revision
                    and not repair_analysis
                ):
                    ai_plan, integration_changes = adapt_plan_to_current_integrations(saved_plan, project)
                    log(dep.id, f"[方案] 已复用源码管理中的全量 AI 分析（版本 {current_revision[:12]}），无需重复分析。\n")
                    if integration_changes:
                        log(dep.id, "[方案] " + "；".join(integration_changes) + "。\n")
                else:
                    if repair_analysis:
                        reason = "上一轮部署失败，AI 正在根据真实错误生成修复方案"
                    else:
                        reason = "尚未保存完整 AI 方案" if not saved_plan else "源码版本已变化"
                    log(dep.id, f"[方案] {reason}，平台正在根据本次最新源码自动刷新部署方案，无需手动重新分析。\n")
                    try:
                        refreshed_plan = analyze_project_deployment(
                            db,
                            project,
                            work,
                            failure_context=previous_error if repair_analysis else "",
                            previous_plan=saved_plan if repair_analysis and isinstance(saved_plan, dict) else None,
                            # A repair already has a complete prior plan and
                            # concrete failure evidence. It must not leave the
                            # release stuck in “读取方案” for the full initial
                            # repository-analysis timeout.
                            timeout_seconds=90 if repair_analysis else 360,
                        )
                    except Exception as analysis_exc:
                        refreshed_plan = None
                        if repair_analysis and isinstance(saved_plan, dict) and saved_plan:
                            detail = "已复用上一版完整方案并继续执行平台确定性修复"
                        else:
                            detail = "已切换平台本地识别器继续发布"
                        log(
                            dep.id,
                            "[方案] AI 上游未在限定时间内返回可用方案，"
                            f"{detail}；本次发布不会被 AI 服务阻塞：{analysis_exc}\n",
                        )
                    if not isinstance(refreshed_plan, dict) or not refreshed_plan:
                        if isinstance(saved_plan, dict) and saved_plan:
                            ai_plan, integration_changes = adapt_plan_to_current_integrations(saved_plan, project)
                            log(dep.id, "[方案] AI 暂未返回新方案，先复用上一版已验证架构处理本次业务代码更新。\n")
                        else:
                            ai_plan = None
                            log(dep.id, "[方案] 未发现可复用 AI 方案，平台将依据源码、锁文件和构建描述生成确定性部署方案。\n")
                    else:
                        if repair_analysis and isinstance(saved_plan, dict):
                            repair_plan_changed = (
                                actionable_plan_fingerprint(refreshed_plan)
                                != actionable_plan_fingerprint(saved_plan)
                            )
                        ai_plan, integration_changes = adapt_plan_to_current_integrations(refreshed_plan, project)
                        refreshed_state = dict(source_analysis)
                        refreshed_state.update({
                            "status": "completed",
                            "phase": "completed",
                            "progress": 100,
                            "revision": current_revision,
                            "deployment_plan": refreshed_plan,
                            "summary": str(refreshed_plan.get("mode_decision") or refreshed_plan.get("summary") or "已根据最新源码自动刷新部署方案"),
                            "finished_at": datetime.now(timezone.utc).isoformat(),
                            "auto_refreshed_by_deployment": dep.id,
                        })
                        project.integration_analysis_json = json.dumps(refreshed_state, ensure_ascii=False)
                        db.commit()
                        log(dep.id, f"[方案] 已按最新源码版本 {current_revision[:12]} 自动刷新并保存部署方案。\n")
                    if integration_changes:
                        log(dep.id, "[方案] " + "；".join(integration_changes) + "。\n")
            if ai_plan:
                inferred_config = apply_ai_inferred_config(project, ai_plan)
                if inferred_config:
                    db.commit()
                    log(dep.id, "[配置预填] AI 已从源码确认并保存非敏感配置：" + json.dumps(inferred_config, ensure_ascii=False) + "\n")
                required_user_config = ai_plan.get("required_user_config") or []
                if required_user_config:
                    log(dep.id, "[配置清单] 以下配置不能安全自动填写：" + json.dumps(required_user_config, ensure_ascii=False) + "\n")
                build_type, build_file, detected_port = materialize_ai_deployment_plan(
                    work, ai_plan, getattr(project, "release_strategy", "auto") or "auto"
                )
                log(dep.id, "[AI规划] " + json.dumps({
                    "provider": ai_plan.get("provider"), "requested_model": ai_plan.get("requested_model"),
                    "actual_model": ai_plan.get("model"), "summary": ai_plan.get("summary"),
                    "deployment_kind": build_type, "services": ai_plan.get("services"),
                    "access_path": ai_plan.get("access_path"), "build_file": build_file,
                }, ensure_ascii=False) + "\n")
                login_info = normalize_login_info(work, ai_plan)
                dep.login_info_json = json.dumps(login_info, ensure_ascii=False)
                db.commit()
                log(dep.id, "[登录信息] " + json.dumps(login_info, ensure_ascii=False) + "\n")
            else:
                log(dep.id, "[AI规划] 当前未配置可用 AI，使用平台本地识别器生成兼容方案。\n")
                release_strategy = getattr(project, "release_strategy", "auto") or "auto"
                source_compose = None if release_strategy == "platform_generated" else _complete_source_compose(Path(work))
                if source_compose or release_strategy == "source_compose":
                    build_type, build_file, detected_port = materialize_ai_deployment_plan(
                        work, {}, release_strategy
                    )
                    log(dep.id, "[发布方式] AI 暂不可用，已按项目设置继续使用完整源码 Compose。\n")
                else:
                    build_type, build_file, detected_port = prepare_build(work, project.build_type)
            if build_type == "compose":
                compose_path = Path(work) / build_file
                compose_source = compose_path.read_text(encoding="utf-8", errors="ignore")
                required_pattern = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*):\?[^}]*\}")
                normalized = compose_source
                for variable in set(required_pattern.findall(compose_source)):
                    if source_declares_environment_optional(work, variable):
                        normalized = re.sub(
                            rf"\$\{{{re.escape(variable)}:\?[^}}]*\}}",
                            "${" + variable + ":-}",
                            normalized,
                        )
                if normalized != compose_source:
                    compose_path.write_text(normalized, encoding="utf-8")
                    log(dep.id, "[配置预检] 已按源码环境示例将可选集成调整为允许留空。\n")
            # Run preflight after the final AI-generated build files exist. It
            # catches foreign package sources and cross-platform lock issues
            # before the first remote pull/build instead of waiting to fail.
            preflight_sources = optimize_staged_sources(work)
            repaired_files = apply_safe_build_repairs(work, previous_error, project.deployment_mode)
            workspace_repaired_files = list(repaired_files)
            preflight_changes = list(dict.fromkeys(preflight_sources + repaired_files))
            if repaired_files:
                repair_detail = "已修改项目工作区中的 " + "、".join(repaired_files)
                lowered_error = (previous_error or "").lower()
                if "find" in lowered_error and "target" in lowered_error and "no such file or directory" in lowered_error:
                    repair_detail += "；将 Maven 根目录 target 查找改为递归查找各模块 target，并选择实际可执行 JAR"
                log(dep.id, "[修复变更] " + repair_detail + "；验证成功后保留修改记录。\n")
            if repair_analysis:
                repair_actions = []
                if repair_plan_changed:
                    repair_actions.append("AI 运行方案已发生有效变化")
                if integration_changes:
                    repair_actions.append("部署集成配置已重新协调")
                if repaired_files:
                    repair_actions.append("平台确定性修复已修改构建文件")
                if not repair_actions:
                    message = (
                        "本轮分析没有产生可验证的运行方案、集成配置或构建文件变化；"
                        "为避免重复消耗资源，平台已在构建前停止本次自动修复。"
                    )
                    log(dep.id, "[AI自动修复] " + message + "\n")
                    raise RuntimeError("[自动修复暂停] " + message)
                log(dep.id, "[AI自动修复] 构建前变化校验通过：" + "；".join(repair_actions) + "。\n")
            # Repairs may replace the final runtime stage (for example a
            # static-server assumption becomes the framework's real preview
            # server). Re-read EXPOSE from the final build artifact instead
            # of carrying forward a port detected from the pre-repair plan.
            if build_type == "dockerfile":
                final_detected_port = detect_container_port(work, build_file)
                if final_detected_port:
                    detected_port = final_detected_port
            if preflight_changes:
                log(dep.id, "[识别] 发布前预检已修复国内软件源及平台原生依赖：" + "、".join(preflight_changes) + "\n")
            else:
                log(dep.id, "[识别] 发布前预检通过：软件源、锁文件和目标平台依赖未发现阻断项\n")
            access_path, access_path_evidence = infer_verified_access_path(work, ai_plan)
            log(dep.id, f"[访问路径] {access_path}（{access_path_evidence}）；将通过真实 HTTP 验证后记为成功经验。\n")
            detected_frontend_routes = detect_frontend_api_routes(work)
            verification_paths = [
                str(route.get("path") or "")
                for route in (detected_frontend_routes.get("routes") or [])
                if isinstance(route, dict) and str(route.get("path") or "").startswith("/")
            ]
            if verification_paths:
                log(dep.id, "[接口验证计划] 发布成功前必须核验：" + "、".join(dict.fromkeys(verification_paths)) + "\n")
            topology = analyze_repository_topology(work, build_type, build_file)
            log(dep.id, "[架构分析] " + json.dumps(topology, ensure_ascii=False) + "\n")
            ai_checkpoint(dep.id, "识别项目", json.dumps({"dependencies": dependency_analysis, "topology": topology}, ensure_ascii=False))
            if topology["errors"]:
                raise RuntimeError("整仓库分析未通过：" + "；".join(topology["errors"]))
            log_stage(dep.id, "完成", "analyze")
            current_stage = "prepare"
            log_stage(dep.id, "开始", "prepare")
            if build_type == "compose":
                managed_integrations = reconcile_managed_integrations(project, work, build_file)
                if managed_integrations:
                    db.commit()
                    log(dep.id, "[托管服务] 未勾选外部服务，平台已自动补齐：" + "、".join(managed_integrations) + "\n")
                managed_build_variables = ensure_managed_build_variables(project, work, build_file)
                if managed_build_variables:
                    db.commit()
                    log(dep.id, "[构建配置] 平台已按源码自动补齐：" + "、".join(managed_build_variables) + "\n")
                generated_secrets = ensure_managed_secrets(project, work, build_file)
                if generated_secrets:
                    db.commit()
                    log(dep.id, "[配置生成] 平台已生成托管服务凭据：" + "、".join(generated_secrets) + "（可在项目配置中查看，值不写入发布日志）\n")
                effective_env = effective_project_environment(project)
                integration_errors = external_integration_preflight(project, effective_env)
                if integration_errors:
                    evidence = "；".join(integration_errors)
                    log(dep.id, "[外接服务预检] " + evidence + "\n")
                    ai_checkpoint(dep.id, "配置预检", evidence)
                    raise RuntimeError("[需要配置] " + evidence)
                external_values = environment_values(decrypt(project.env_text_encrypted) or "")
                if external_values.get("YUNZHOU_MYSQL_MODE", "managed").lower() == "external":
                    external_host = external_values.get("YUNZHOU_MYSQL_HOST", "").strip()
                    external_port = external_values.get("YUNZHOU_MYSQL_PORT", "").strip()
                    with SSHNode(node) as preflight_ssh:
                        reach_code, reach_output = preflight_ssh.run(
                            "timeout 8 bash -c " + shlex.quote(
                                f"exec 3<>/dev/tcp/{external_host}/{external_port}"
                            ), timeout=15,
                        )
                    if reach_code:
                        evidence = f"外接 MySQL {external_host}:{external_port} 无法从部署服务器连接"
                        log(dep.id, "[外接数据库预检] " + evidence + "；已在构建前停止，未创建错误版本。\n")
                        ai_checkpoint(dep.id, "配置预检", evidence)
                        raise RuntimeError("[需要配置] " + evidence + "。请检查地址、防火墙和数据库监听范围")
                    log(
                        dep.id,
                        "[外接数据库] 已采用项目保存的 MySQL 配置："
                        f"{external_values.get('YUNZHOU_MYSQL_HOST')}:{external_values.get('YUNZHOU_MYSQL_PORT')}"
                        f"/{external_values.get('YUNZHOU_MYSQL_DATABASE')}；不会创建项目内置 MySQL。\n",
                    )
                missing_variables = required_compose_variables(work, build_file, effective_env)
                if missing_variables:
                    evidence = json.dumps({"missing_variables": missing_variables, "compose_file": build_file}, ensure_ascii=False)
                    log(dep.id, "[配置预检] AI 已在构建前发现 Compose 必填配置缺失：" + evidence + "\n")
                    ai_checkpoint(dep.id, "配置预检", evidence)
                    names = "、".join(item["name"] for item in missing_variables)
                    raise RuntimeError(f"[需要配置] Compose 必填环境变量缺失：{names}。请在项目设置中补充后重新发布")
            log(dep.id, f"[识别] 项目类型 {build_type}，构建文件 {build_file}\n")
            if build_file == ".yunzhou.Dockerfile":
                log(dep.id, "[AI构建] 已根据源码结构、依赖清单和运行版本重新生成平台 Dockerfile；项目原 Dockerfile 仅作为端口与环境参考。\n")
            # Project image tags are minute based so they remain readable in the
            # registry. Concurrent builds of the same project in one minute get
            # a deterministic suffix instead of racing for the same tag.
            # User-facing release tags follow the platform's China-local time.
            # Database timestamps remain UTC and are converted by the UI.
            release_base = datetime.now(timezone(timedelta(hours=8))).strftime("%Y%m%d%H%M")
            releases_in_minute = set(db.scalars(select(Deployment.release).where(
                Deployment.project_id == project.id,
                Deployment.release.like(f"{release_base}%"),
            )).all())
            release = release_base
            sequence = 2
            while release in releases_in_minute:
                release = f"{release_base}-{sequence:02d}"
                sequence += 1
            runtime_policy = db.get(DeploymentSettings, "default")
            runtime_namespace = (runtime_policy.registry_namespace if runtime_policy else "yunzhou") or "yunzhou"
            compose_project = compose_project_name(project.slug, release, runtime_namespace)
            remote_dir = f"{node.work_dir.rstrip('/')}/{project_directory(project)}/{release}"
            if build_type == "dockerfile":
                container_name = _service_container_name(project.slug, "app", 1, release, runtime_namespace)
            else:
                # Compose services receive their own stable service-aware name
                # in the generated override below.  This placeholder is never
                # used as a physical Compose container name.
                container_name = compose_project
            image_name = f"yunzhou/{project.slug}:{release}"
            host_port = choose_node_port(
                db, node, dep.host_port or project.host_port,
                exclude_deployment_id=dep.id,
            )
            # The final generated/selected Dockerfile is the source of truth.
            # A value saved by an older analysis (commonly the default 80)
            # must not override a newly detected EXPOSE such as Vite's 4300.
            container_port = detected_port or project.container_port
            if container_port and project.container_port != container_port:
                project.container_port = container_port
            dep.release = release
            dep.container_name = container_name
            dep.image_name = image_name if build_type == "dockerfile" else None
            dep.host_port = host_port
            db.commit()
            log(dep.id, f"[源码] 版本 {revision}，发布目录 {remote_dir}\n")

            compose_override = None
            compose_split = None
            exclusive_app_volume_names: list[str] = []
            built_images = []
            target_platform = node_platform(node)
            if build_type == "compose":
                compose_override, built_images = prepare_compose_image_override(
                    work, build_file, project, release, target_platform, node,
                    db=db, primary_host_port=host_port, deployment_plan=ai_plan,
                    deployment_id=dep.id,
                )
                # Image packaging creates a late Compose override. Apply the
                # integration contract again at this final materialization
                # boundary so an override can never reintroduce an internal
                # MySQL service or omit a source-required managed Redis after
                # the user's external/managed choice was already resolved.
                final_integration_changes = reconcile_managed_integrations(project, work, build_file)
                if compose_override:
                    final_integration_changes.extend(
                        reconcile_managed_integrations(project, work, compose_override)
                    )
                if final_integration_changes:
                    db.commit()
                    log(
                        dep.id,
                        "[最终配置裁决] "
                        + "、".join(dict.fromkeys(final_integration_changes))
                        + "；已在封装后重新核对。\n",
                    )
                compose_split = split_compose_runtime(
                    work, build_file, project, runtime_namespace, compose_override,
                )
                if compose_split:
                    log(
                        dep.id,
                        "[服务拆分] 项目级数据服务："
                        + "、".join(compose_split["data_services"])
                        + "；本次版本应用服务："
                        + "、".join(compose_split["app_services"])
                        + "。数据库和数据卷不会随应用版本重建。\n",
                    )
                app_override_name = (
                    compose_split.get("app_override_file") if compose_split else compose_override
                )
                if app_override_name:
                    app_override_document = yaml.safe_load(
                        (Path(work) / app_override_name).read_text(encoding="utf-8", errors="ignore")
                    ) or {}
                    for config in (app_override_document.get("volumes") or {}).values():
                        if isinstance(config, dict) and config.get("name"):
                            exclusive_app_volume_names.append(str(config["name"]))
            runtime_bundle = prepare_runtime_bundle(
                work, build_type, build_file, compose_override,
                [
                    compose_split["data_file"], compose_split["app_file"],
                    *([compose_split["app_override_file"]] if compose_split.get("app_override_file") else []),
                ] if compose_split else None,
            )
            readme = (
                "自助发布平台部署目录说明\n"
                "====================\n\n"
                f"项目名称：{project.name}\n"
                f"项目标识：{project.slug}\n"
                f"发布版本：{release}\n"
                f"源码版本：{revision}\n"
                f"目标服务器：{node.name}（{node.host}）\n"
                f"构建类型：{'Docker Compose' if build_type == 'compose' else 'Dockerfile'}\n"
                f"主配置文件：{build_file}\n\n"
                "本目录只保存运行所需配置，源码和构建缓存保存在平台构建服务器。\n"
                "以 . 开头的是平台生成的内部文件，普通 ls/ll 不显示。\n"
                "查看全部文件：ls -la\n"
                "请勿直接修改 .env 或 .yunzhou.* 文件；请在自助发布平台修改配置并重新发布。\n"
            )
            (Path(runtime_bundle) / "README-部署说明.txt").write_text(readme, encoding="utf-8")
            # Remote image builds may take many minutes. Release PostgreSQL
            # read locks before waiting so API startup and ordinary project
            # reads are never blocked by a long-running build.
            db.commit()
            def build_stream(text):
                log(dep.id, text)
                ensure_active(dep.id)
            log_stage(dep.id, "完成", "prepare")
            current_stage = "build"
            log_stage(dep.id, "开始", "build")
            log(dep.id, "[平台构建] 源码只在平台构建服务器编译，目标服务器将接收构建后的镜像与运行配置。\n")
            ai_checkpoint(dep.id, "平台统一构建", f"正在平台构建服务器生成版本 {release} 镜像")
            builder = central_build_and_distribute(
                db, dep, project, node, work, build_type, build_file, release,
                image_name if build_type == "dockerfile" else None,
                compose_override, built_images, target_platform, build_stream,
            )
            # Packaging may replace AI multi-stage Dockerfiles with
            # runtime-only files and update Compose build entries. Recreate
            # the upload bundle after those final transformations so the
            # release directory and "发布文件" view match what was actually
            # built, rather than the pre-build draft.
            if runtime_bundle:
                shutil.rmtree(runtime_bundle, ignore_errors=True)
            runtime_bundle = prepare_runtime_bundle(
                work, build_type, build_file, compose_override,
                [
                    compose_split["data_file"], compose_split["app_file"],
                    *([compose_split["app_override_file"]] if compose_split.get("app_override_file") else []),
                ] if compose_split else None,
            )
            (Path(runtime_bundle) / "README-部署说明.txt").write_text(readme, encoding="utf-8")
            log(dep.id, f"[平台构建] 镜像构建完成：{builder.name}；目标节点只负责加载并启动。\n")
            log_stage(dep.id, "完成", "build")
            current_stage = "start"
            log_stage(dep.id, "开始", "start")

            with SSHNode(node) as ssh:
                log(dep.id, f"[上传] 正在上传 Compose 与运行配置到 {remote_dir}...\n")
                ssh.upload_tree(runtime_bundle, remote_dir)
                log(dep.id, "[上传] 运行配置上传完成\n")
                ai_checkpoint(dep.id, "上传到服务器", f"版本 {revision} 的镜像与运行配置已送达 {remote_dir}")
                def append(text):
                    log(dep.id, text)
                    ensure_active(dep.id)
                ensure_active(dep.id)
                if build_type == "compose":
                    compose_files = "--env-file .env " + (
                        f"-f {shlex.quote(compose_split['app_file'])}"
                        if compose_split else f"-f {shlex.quote(build_file)}"
                    ) + (
                        f" -f {shlex.quote(compose_split['app_override_file'])}"
                        if compose_split and compose_split.get("app_override_file")
                        else (f" -f {shlex.quote(compose_override)}" if compose_override else "")
                    )
                    env_text = effective_project_environment(project)
                    integration_errors = external_integration_preflight(project, env_text)
                    if integration_errors:
                        raise RuntimeError("[需要配置] " + "；".join(integration_errors))
                    secret_seed = f"{settings.app_secret}:{project.id}".encode()
                    db_password = hashlib.sha256(secret_seed + b":mysql").hexdigest()[:28]
                    root_password = hashlib.sha256(secret_seed + b":mysql-root").hexdigest()[:32]
                    jwt_secret = hashlib.sha256(secret_seed + b":jwt").hexdigest()
                    stored_keys = store_managed_values(project, {
                        "CRM_DB_PASSWORD": db_password,
                        "CRM_DB_ROOT_PASSWORD": root_password,
                        "CRM_JWT_SECRET": jwt_secret,
                    })
                    if stored_keys:
                        db.commit()
                        log(dep.id, "[配置] 已保存平台托管连接信息，可在项目配置中查看\n")
                    env_text = effective_project_environment(project)
                    compose_env = (
                        f"COMPOSE_PROJECT_NAME={compose_project}\n"
                        f"YUNZHOU_HOST_PORT={host_port}\n"
                        f"CRM_DB_PASSWORD={db_password}\n"
                        f"CRM_DB_ROOT_PASSWORD={root_password}\n"
                        f"CRM_JWT_SECRET={jwt_secret}\n"
                        + ((env_text.rstrip() + "\n") if env_text else "")
                    )
                    code, out = ssh.run(f"printf %s {shlex.quote(compose_env)} > {shlex.quote(remote_dir + '/.env')}")
                    if code:
                        raise RuntimeError(out)
                    # Check the generated file itself before any data service is
                    # touched. This catches ordering/interpolation regressions
                    # without exposing credentials in logs.
                    required_external = []
                    external_values = environment_values(decrypt(project.env_text_encrypted) or "")
                    if external_values.get("YUNZHOU_MYSQL_MODE", "managed").lower() == "external":
                        required_external.extend([
                            "YUNZHOU_MYSQL_HOST", "YUNZHOU_MYSQL_PORT",
                            "YUNZHOU_MYSQL_DATABASE", "YUNZHOU_MYSQL_USERNAME",
                            "YUNZHOU_MYSQL_PASSWORD",
                        ])
                    if required_external:
                        checks = " && ".join(
                            "grep -q " + shlex.quote("^" + key + "=.") + " "
                            + shlex.quote(remote_dir + "/.env")
                            for key in required_external
                        )
                        check_code, _ = ssh.run(checks)
                        if check_code:
                            raise RuntimeError("[平台配置错误] 外接数据库配置未完整写入发布环境，平台已在启动前停止")
                        log(dep.id, "[外接数据库] 保存配置已完整注入本次发布环境。\n")
                    if compose_split:
                        data_project = compose_split["data_project"]
                        data_file = compose_split["data_file"]
                        data_args = f"--env-file .env -f {shlex.quote(data_file)}"
                        check_cmd = (
                            f"cd {shlex.quote(remote_dir)} && "
                            f"docker compose -p {shlex.quote(data_project)} {data_args} ps -q"
                        )
                        _, data_ids = ssh.run(check_cmd)
                        if not data_ids.strip():
                            # One-time migration from historical release-level
                            # data containers. Stop only containers that mount
                            # the protected project volumes; never remove the
                            # volumes themselves.
                            volume_filters = " ".join(
                                f"--filter {shlex.quote('volume=' + name)}"
                                for name in compose_split["volume_names"]
                            )
                            if volume_filters:
                                _, legacy_data = ssh.run(
                                    f"docker ps -q {volume_filters} | sort -u"
                                )
                                if legacy_data.strip():
                                    log(dep.id, "[数据服务迁移] 正在停止旧版本中的数据容器；固定数据卷保持不变。\n")
                                    stop_ids = " ".join(shlex.quote(value) for value in legacy_data.split())
                                    stop_code, stop_out = ssh.run(f"docker stop {stop_ids}", timeout=120)
                                    if stop_code:
                                        raise RuntimeError("释放旧数据容器失败：" + stop_out[-800:])
                            log(dep.id, "[数据服务] 首次建立项目级固定数据服务和内部网络。\n")
                            data_pull = (
                                f"cd {shlex.quote(remote_dir)} && "
                                f"docker compose --progress plain -p {shlex.quote(data_project)} {data_args} pull"
                            )
                            pull_code, pull_out = tracked_run(ssh, dep.id, data_pull, stream=append, timeout=900)
                            if pull_code:
                                raise RuntimeError("项目级数据服务镜像拉取失败：" + pull_out[-1200:])
                            data_up = (
                                f"cd {shlex.quote(remote_dir)} && "
                                f"docker compose --progress plain -p {shlex.quote(data_project)} {data_args} up -d --no-build"
                            )
                            up_code, up_out = tracked_run(ssh, dep.id, data_up, stream=append, timeout=300)
                            if up_code:
                                raise RuntimeError("项目级数据服务启动失败：" + up_out[-1200:])
                        else:
                            # A release switch must never restart a healthy
                            # project database merely because Compose rewrote
                            # harmless metadata or labels. Reuse the stable
                            # data stack as-is; reconcile only when a container
                            # is missing, stopped or explicitly unhealthy.
                            healthy_data_probe = (
                                f"ids=$(docker ps -aq --filter label=com.docker.compose.project={shlex.quote(data_project)}); "
                                "[ -n \"$ids\" ] || exit 1; "
                                "for id in $ids; do "
                                "state=$(docker inspect -f '{{.State.Status}}' $id 2>/dev/null); "
                                "health=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{end}}' $id 2>/dev/null); "
                                "[ \"$state\" = running ] || exit 1; "
                                "[ \"$health\" != unhealthy ] || exit 1; "
                                "done"
                            )
                            healthy_code, _ = ssh.run(healthy_data_probe, timeout=30)
                            if healthy_code == 0:
                                log(dep.id, "[数据服务] 已复用健康的项目固定数据服务，本次版本切换不重建数据库或数据卷。\n")
                            else:
                                reconcile_data = (
                                    f"cd {shlex.quote(remote_dir)} && "
                                    f"docker compose --progress plain -p {shlex.quote(data_project)} "
                                    f"{data_args} up -d --no-build"
                                )
                                reconcile_code, reconcile_out = tracked_run(
                                    ssh, dep.id, reconcile_data, stream=append, timeout=300
                                )
                                if reconcile_code:
                                    raise RuntimeError("项目级数据服务配置校验失败：" + reconcile_out[-1200:])
                            log(dep.id, "[数据服务] 已核对项目级固定服务配置；配置有变化时仅重建容器，数据卷保持不变。\n")
                        data_health = (
                            f"cd {shlex.quote(remote_dir)} && ok=0; stable=0; fatal=0; "
                            "for i in $(seq 1 90); do bad=0; "
                            f"ids=$(docker compose -p {shlex.quote(data_project)} {data_args} ps -q); "
                            "[ -n \"$ids\" ] || bad=1; for id in $ids; do "
                            "state=$(docker inspect -f '{{.State.Status}}' $id 2>/dev/null); "
                            "health=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' $id 2>/dev/null); "
                            "image=$(docker inspect -f '{{.Config.Image}}' $id 2>/dev/null); "
                            "[ \"$state\" = running ] || bad=1; "
                            "[ \"$health\" = none ] || [ \"$health\" = healthy ] || bad=1; "
                            # The official MySQL/MariaDB entrypoint starts a
                            # temporary server while importing init scripts.
                            # mysqladmin can report that temporary instance as
                            # healthy, then the entrypoint intentionally stops
                            # it before starting the real server.  Starting the
                            # application in that gap produces an intermittent
                            # "connection refused" on every fresh project.
                            "case \"$image\" in *mysql*|*mariadb*) logs=$(docker logs $id 2>&1); "
                            "printf '%s\\n' \"$logs\" | grep -Eq '^ERROR [0-9]+ \\(' && fatal=1; "
                            "if printf '%s\\n' \"$logs\" | grep -Eqi 'temporary server started'; then "
                            "printf '%s\\n' \"$logs\" | grep -Eqi 'init process done|ready for start up' || bad=1; fi;; esac; "
                            "done; "
                            "[ \"$fatal\" -eq 0 ] || exit 2; "
                            # Require several consecutive healthy samples so
                            # a restart boundary cannot be mistaken for
                            # database readiness even on nonstandard images.
                            "if [ \"$bad\" -eq 0 ]; then stable=$((stable+1)); else stable=0; fi; "
                            "[ \"$stable\" -ge 4 ] && { ok=1; break; }; sleep 2; done; "
                            "[ \"$ok\" -eq 1 ]"
                        )
                        log(dep.id, "[数据服务检查] 正在核验项目级 MySQL/Redis 的运行状态、健康检查与托管凭据。\n")
                        health_code, health_out = ssh.run(data_health, timeout=240)
                        if health_code:
                            diagnostics_cmd = (
                                f"cd {shlex.quote(remote_dir)} && "
                                f"docker compose -p {shlex.quote(data_project)} {data_args} ps -a 2>&1; "
                                f"ids=$(docker compose -p {shlex.quote(data_project)} {data_args} ps -aq); "
                                "for id in $ids; do "
                                "printf '\n--- %s ---\n' \"$(docker inspect -f '{{.Name}} image={{.Config.Image}} state={{.State.Status}} health={{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' $id 2>/dev/null)\"; "
                                "docker inspect -f '{{if .State.Health}}{{json .State.Health.Log}}{{end}}' $id 2>/dev/null; "
                                "docker logs --tail 100 $id 2>&1; done"
                            )
                            _, diagnostics = ssh.run(diagnostics_cmd, timeout=90)
                            clean_diagnostics = ANSI_RE.sub("", diagnostics or health_out or "").strip()
                            postgres_seccomp_error = (
                                re.search(r'postmaster\.pid.*Operation not permitted', clean_diagnostics, re.I | re.S)
                                and re.search(r'pg_wal/xlogtemp\.\d+.*Operation not permitted', clean_diagnostics, re.I | re.S)
                            )
                            repaired_services: list[str] = []
                            if postgres_seccomp_error:
                                for service in compose_split["data_services"]:
                                    service_ids_cmd = (
                                        f"cd {shlex.quote(remote_dir)} && "
                                        f"docker compose -p {shlex.quote(data_project)} {data_args} "
                                        f"ps -aq {shlex.quote(service)}"
                                    )
                                    _, service_ids = ssh.run(service_ids_cmd, timeout=30)
                                    for service_id in service_ids.split():
                                        _, service_image = ssh.run(
                                            f"docker inspect -f '{{{{.Config.Image}}}}' {shlex.quote(service_id)} 2>/dev/null",
                                            timeout=20,
                                        )
                                        if re.search(r'(^|/)postgres(?::|@|$)', service_image.strip(), re.I):
                                            repaired_services.append(service)
                                            break
                            if repaired_services:
                                compat_file = ".yunzhou.data.compat.yml"
                                compat_text = yaml.safe_dump(
                                    {
                                        "services": {
                                            service: {"security_opt": ["seccomp:unconfined"]}
                                            for service in sorted(set(repaired_services))
                                        }
                                    },
                                    allow_unicode=True,
                                    sort_keys=False,
                                )
                                compat_path = remote_dir + "/" + compat_file
                                compat_code, compat_out = ssh.run(
                                    f"printf %s {shlex.quote(compat_text)} > {shlex.quote(compat_path)}",
                                    timeout=30,
                                )
                                if compat_code:
                                    raise RuntimeError("写入 PostgreSQL 兼容配置失败：" + compat_out[-800:])
                                log(
                                    dep.id,
                                    "[数据服务自动修复] 已识别目标内核的 PostgreSQL seccomp 兼容故障，"
                                    "仅重建受影响的数据库容器；数据卷保持不变。\n",
                                )
                                compat_args = f"{data_args} -f {shlex.quote(compat_file)}"
                                repair_services = " ".join(
                                    shlex.quote(value) for value in sorted(set(repaired_services))
                                )
                                repair_cmd = (
                                    f"cd {shlex.quote(remote_dir)} && "
                                    f"docker compose --progress plain -p {shlex.quote(data_project)} "
                                    f"{compat_args} up -d --no-build --force-recreate {repair_services}"
                                )
                                repair_code, repair_out = tracked_run(
                                    ssh,
                                    dep.id,
                                    repair_cmd,
                                    stream=append,
                                    timeout=300,
                                )
                                if repair_code:
                                    raise RuntimeError(
                                        "PostgreSQL seccomp 兼容修复失败：" + ANSI_RE.sub("", repair_out)[-1200:]
                                    )
                                health_code, health_out = ssh.run(data_health, timeout=240)
                                if not health_code:
                                    log(dep.id, "[数据服务自动修复] PostgreSQL 已恢复健康。\n")
                            if health_code:
                                _, diagnostics = ssh.run(diagnostics_cmd, timeout=90)
                                clean_diagnostics = ANSI_RE.sub(
                                    "", diagnostics or health_out or "未获得容器状态与日志"
                                ).strip()
                                raise RuntimeError("项目级数据服务未就绪：\n" + clean_diagnostics[-4000:])
                        # Older releases may have left a release-scoped MySQL/Redis
                        # container mounted on the same persistent volume.  Once the
                        # stable data project is healthy, remove only those duplicate
                        # data-service containers.  Application containers and the
                        # persistent volumes themselves are never touched.
                        volume_filters = " ".join(
                            f"--filter {shlex.quote('volume=' + name)}"
                            for name in compose_split["volume_names"]
                        )
                        data_service_words = " " + " ".join(compose_split["data_services"]) + " "
                        if volume_filters and compose_split["data_services"]:
                            stale_data_cmd = (
                                f"for cid in $(docker ps -q {volume_filters} | sort -u); do "
                                "owner=$(docker inspect -f '{{index .Config.Labels \"com.docker.compose.project\"}}' \"$cid\" 2>/dev/null); "
                                "service=$(docker inspect -f '{{index .Config.Labels \"com.docker.compose.service\"}}' \"$cid\" 2>/dev/null); "
                                f"[ \"$owner\" = {shlex.quote(data_project)} ] && continue; "
                                f"case {shlex.quote(data_service_words)} in *\" $service \"*) printf '%s\\n' \"$cid\" ;; esac; "
                                "done"
                            )
                            stale_code, stale_output = ssh.run(stale_data_cmd, timeout=30)
                            if stale_code:
                                raise RuntimeError("旧数据容器检查失败：" + stale_output[-800:])
                            stale_ids = [value for value in stale_output.split() if re.fullmatch(r"[0-9a-f]{12,64}", value)]
                            if stale_ids:
                                log(dep.id, "[数据服务清理] 发现旧版本数据容器，正在移除重复实例；固定数据卷保持不变。\n")
                                stale_words = " ".join(shlex.quote(value) for value in stale_ids)
                                stale_code, stale_output = ssh.run(
                                    f"docker stop -t 20 {stale_words} && docker rm {stale_words}",
                                    timeout=max(60, 40 * len(stale_ids)),
                                )
                                if stale_code:
                                    raise RuntimeError("旧数据容器清理失败：" + stale_output[-800:])
                    compose_images = compose_pull_images(work, build_file)
                    log(dep.id, f"[镜像] Compose 共识别到 {len(compose_images)} 个服务镜像\n")
                    # Platform-built application images were already pulled
                    # from the private registry and verified by digest during
                    # distribution.  A second plain `compose pull` interprets
                    # their short local tags as Docker Hub repositories and
                    # fails with access denied.  Let `up --pull missing` reuse
                    # verified local images while still fetching any genuine
                    # third-party runtime image that is not present locally.
                    log(dep.id, "[镜像] 平台版本镜像已在分发阶段拉取并校验；启动时仅补齐本地缺失的第三方镜像。\n")
                    # Older single-container releases used the exact
                    # `yz-<slug>` name. A later Compose deployment uses
                    # `yz-<slug>-<service>-1`; leaving the legacy container
                    # alive can silently keep the selected host port mapped
                    # to an obsolete container port (for example 80 instead
                    # of the newly detected 4300).
                    legacy_container = f"yz-{project.slug}"
                    _, legacy_state = ssh.run(
                        f"docker inspect -f '{{{{.Name}}}} {{{{json .NetworkSettings.Ports}}}}' "
                        f"{shlex.quote(legacy_container)} 2>/dev/null || true"
                    )
                    if legacy_state.strip():
                        log(dep.id, f"[迁移清理] 已识别旧版直启容器：{legacy_state.strip()}\n")
                        ssh.run(f"docker rm -f {shlex.quote(legacy_container)} >/dev/null 2>&1 || true")
                    # A project-level application volume may contain an
                    # exclusive process lock (for example an embedded agent
                    # runtime). Two blue/green releases cannot safely mount
                    # and run that same state simultaneously. Stop only the
                    # previous containers that actually mount these
                    # project-namespaced application volumes; database
                    # volumes were split out above and are never touched.
                    if exclusive_app_volume_names:
                        # Stable application volumes are declared external so
                        # every release attaches the same Docker object without
                        # Compose ownership warnings. Create it once before the
                        # first release; `docker volume create` is idempotent.
                        for stable_volume in sorted(set(exclusive_app_volume_names)):
                            volume_code, volume_out = ssh.run(
                                f"docker volume inspect {shlex.quote(stable_volume)} >/dev/null 2>&1 || "
                                f"docker volume create {shlex.quote(stable_volume)}",
                                timeout=30,
                            )
                            if volume_code:
                                raise RuntimeError("创建项目固定卷失败：" + volume_out[-800:])
                        volume_filters = " ".join(
                            f"--filter {shlex.quote('volume=' + name)}"
                            for name in sorted(set(exclusive_app_volume_names))
                        )
                        _, shared_ids = ssh.run(f"docker ps -q {volume_filters} | sort -u")
                        preempted_shared_containers = [value for value in shared_ids.split() if value]
                        if preempted_shared_containers:
                            log(dep.id, "[版本切换] 应用固定卷包含独占运行状态，先暂停旧应用容器；固定卷和数据容器保持不变。\n")
                            stop_ids = " ".join(shlex.quote(value) for value in preempted_shared_containers)
                            stop_code, stop_out = ssh.run(f"docker stop {stop_ids}", timeout=120)
                            if stop_code:
                                raise RuntimeError("暂停旧应用容器失败：" + stop_out[-1000:])
                    cmd = (
                        f"cd {shlex.quote(remote_dir)} && "
                        f"docker compose --progress plain -p {shlex.quote(compose_project)} {compose_files} "
                        "up -d --no-build --pull missing --remove-orphans"
                    )
                    log(dep.id, "[启动] 使用平台构建镜像启动 Docker Compose...\n")
                    ai_checkpoint(dep.id, "启动应用服务", f"Compose 文件 {build_file}，使用平台构建镜像启动完整服务拓扑")
                    code, out = tracked_run(ssh, dep.id, cmd, stream=append)
                    if code and "could not find an available, non-overlapping IPv4 address pool" in out:
                        # Long-running CentOS 7.6 nodes can exhaust Docker's
                        # default bridge subnets after many release-scoped
                        # Compose networks. Prune only networks unused by any
                        # container, then retry this exact start once.
                        log(dep.id, "[网络自愈] Docker 默认地址池已满，正在回收未被任何容器使用的遗留网络后重试。\n")
                        prune_code, prune_out = ssh.run("docker network prune -f", timeout=120)
                        append("[\u7f51\u7edc\u81ea\u6108] " + (prune_out or "\u672a\u53d1\u73b0\u53ef\u56de\u6536\u7f51\u7edc") + "\n")
                        if prune_code == 0:
                            code, retry_out = tracked_run(ssh, dep.id, cmd, stream=append)
                            out = out + "\n[\u7f51\u7edc\u81ea\u6108\u91cd\u8bd5]\n" + retry_out
                    if code:
                        diagnostic_cmd = (
                            f"cd {shlex.quote(remote_dir)} && "
                            f"docker compose -p {shlex.quote(compose_project)} {compose_files} ps -a; "
                            "echo '--- 服务日志 ---'; "
                            f"docker compose -p {shlex.quote(compose_project)} {compose_files} logs --no-color --tail 200; "
                            "echo '--- 健康检查 ---'; "
                            f"for id in $(docker compose -p {shlex.quote(compose_project)} {compose_files} ps -aq); do "
                            "name=$(docker inspect -f '{{.Name}}' $id 2>/dev/null | sed 's#^/##'); "
                            "health=$(docker inspect -f '{{if .State.Health}}{{json .State.Health.Log}}{{end}}' $id 2>/dev/null); "
                            "[ -n \"$health\" ] && printf '\n[%s]\n%s\n' \"$name\" \"$health\"; done"
                        )
                        _, diagnostic = ssh.run(diagnostic_cmd, timeout=90)
                        append("\n[启动诊断] Compose 启动失败，已在清理前采集容器状态、服务日志和健康检查：\n" + diagnostic[-20000:] + "\n")
                        log(dep.id, "[AI学习] 本次诊断证据将用于修复重试；未通过真实部署验证前不会记为成功经验。\n")
                        raise RuntimeError((out + "\n" + diagnostic)[-24000:])
                    ensure_active(dep.id)
                    code, ps = ssh.run(f"cd {shlex.quote(remote_dir)} && docker compose -p {shlex.quote(compose_project)} {compose_files} ps --format json")
                    append("\n[检查] 正在检查 Compose 服务状态...\n" + ps + "\n")
                    ai_checkpoint(dep.id, "启动全部服务", ps)
                    if build_file.startswith(".yunzhou"):
                        readiness_path = access_path if str(access_path).startswith("/") else "/"
                        backend_probe_url = shlex.quote("http://backend:8080" + readiness_path)
                        verify_cmd = (
                            f"cd {shlex.quote(remote_dir)} && expected=$(docker compose -p {shlex.quote(compose_project)} {compose_files} config --services | wc -l); "
                            "ok=0; for i in $(seq 1 40); do running=$(docker compose -p " + shlex.quote(compose_project) + " " + compose_files + " ps --status running --services | wc -l); "
                            "[ \"$running\" -eq \"$expected\" ] && ok=1 && break; sleep 3; done; "
                            "[ \"$ok\" -eq 1 ] || { docker compose -p " + shlex.quote(compose_project) + " " + compose_files + " ps; docker compose -p " + shlex.quote(compose_project) + " " + compose_files + " logs --tail 120; exit 44; }; "
                            "services=$(docker compose -p " + shlex.quote(compose_project) + " " + compose_files + " config --services); "
                            "if printf '%s\\n' \"$services\" | grep -qx frontend && printf '%s\\n' \"$services\" | grep -qx backend; then "
                            # Do not assume Spring Actuator exists. Probe the
                            # concrete source-derived endpoint and treat any
                            # non-5xx HTTP response as application readiness.
                            "api=0; for i in $(seq 1 80); do reply=$(docker compose -p " + shlex.quote(compose_project) + " " + compose_files + " exec -T frontend wget -S -O /dev/null http://backend:8080/ 2>&1 || true); "
                            "printf '%s\\n' \"$reply\" | grep -Eq 'HTTP/[0-9.]+ [234][0-9][0-9]' && api=1 && break; sleep 3; done; "
                            "[ \"$api\" -eq 1 ] || { docker compose -p " + shlex.quote(compose_project) + " " + compose_files + " logs --tail 120 backend; exit 45; }; fi; "
                            # Service names are arbitrary, so also verify every
                            # container in the generated topology. A container
                            # that keeps restarting can briefly appear running
                            # and must never make the deployment look healthy.
                            # A valid service should become healthy promptly.
                            # Do not hide dependency/configuration failures by
                            # waiting for several minutes; the diagnostic logs
                            # below must expose the real startup error.
                            "stable=0; unstable=0; pending=0; for attempt in $(seq 1 10); do unstable=0; pending=0; ids=$(docker compose -p " + shlex.quote(compose_project) + " " + compose_files + " ps -aq); "
                            "for id in $ids; do state=$(docker inspect -f '{{.State.Status}}' $id 2>/dev/null); restarts=$(docker inspect -f '{{.RestartCount}}' $id 2>/dev/null); health=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{end}}' $id 2>/dev/null); "
                            "[ \"$state\" = running ] || unstable=1; [ \"${restarts:-0}\" -eq 0 ] || unstable=1; [ \"$health\" = unhealthy ] && unstable=1; [ \"$health\" = starting ] && pending=1; done; "
                            "[ \"$unstable\" -eq 0 ] || break; [ \"$pending\" -eq 0 ] && stable=1 && break; sleep 3; done; "
                            "[ \"$unstable\" -eq 0 ] || { echo '发现服务退出、反复重启或健康检查明确失败'; docker compose -p " + shlex.quote(compose_project) + " " + compose_files + " ps -a; docker compose -p " + shlex.quote(compose_project) + " " + compose_files + " logs --tail 160; exit 46; }; "
                            "[ \"$pending\" -eq 0 ] || echo '健康检查仍在预热，继续使用真实 HTTP 访问验证'"
                        )
                        # Container presence and backend connectivity remain
                        # strict. A merely `starting` healthcheck gets a short
                        # grace period, then the public HTTP probe below is the
                        # authoritative readiness result.
                        verify_code, verify_output = ssh.run(verify_cmd, timeout=480)
                        append("[检查] 前端、后端和数据库联合检查" + ("通过\n" if verify_code == 0 else "失败\n" + verify_output + "\n"))
                        if verify_code:
                            raise RuntimeError("多服务启动后联合检查未通过：" + verify_output)
                        # The previous mistaken single-container release is
                        # removed only after the replacement topology started.
                        ssh.run(f"docker rm -f {shlex.quote(container_name)} >/dev/null 2>&1 || true")
                    container_name = compose_project
                    # Compose may declare a fixed published port and ignore the
                    # platform's suggested YUNZHOU_HOST_PORT. Docker is the
                    # final source of truth for every service route, not just
                    # whichever publisher happens to be listed first.
                    published_port = None
                    service_targets: dict[str, list[tuple[str, int]]] = {}
                    if code == 0 and ps.strip():
                        try:
                            parsed = json.loads(ps)
                            rows = parsed if isinstance(parsed, list) else [parsed]
                        except Exception:
                            rows = []
                            for line in ps.splitlines():
                                try:
                                    rows.append(json.loads(line))
                                except Exception:
                                    continue
                        for row in rows:
                            service_name = str(row.get("Service") or row.get("service") or "").strip()
                            for publisher in row.get("Publishers", []) or []:
                                if not isinstance(publisher, dict):
                                    continue
                                candidate = publisher.get("PublishedPort")
                                if service_name and candidate:
                                    service_targets.setdefault(service_name, []).append((node.host, int(candidate)))
                        service_targets = {
                            service: list(dict.fromkeys(targets))
                            for service, targets in service_targets.items() if targets
                        }
                        # Docker is authoritative after Compose starts. Persist
                        # every actually published service port, including
                        # ports declared by source Compose that did not pass
                        # through the platform's pre-build allocator.
                        for service_name, targets in service_targets.items():
                            for _host, service_port in targets:
                                reservation = db.scalar(select(DeploymentPortReservation).where(
                                    DeploymentPortReservation.node_id == node.id,
                                    DeploymentPortReservation.host_port == service_port,
                                ))
                                if reservation:
                                    reservation.deployment_id = dep.id
                                    reservation.service_name = service_name
                                    reservation.status = "active"
                                    reservation.created_at = datetime.now(timezone.utc)
                                else:
                                    db.add(DeploymentPortReservation(
                                        deployment_id=dep.id,
                                        node_id=node.id,
                                        service_name=service_name,
                                        host_port=service_port,
                                        status="active",
                                    ))
                        db.flush()
                        # Release reservation/deployment row locks before the
                        # independent progress logger updates this deployment.
                        db.commit()
                        traffic_plan = _project_traffic_plan(project, ai_plan)
                        entry_service = str(traffic_plan.get("default_service") or traffic_plan.get("entry_service") or "")
                        if not entry_service:
                            entry_service = next((
                                str(route.get("service") or route.get("target_service") or "")
                                for route in (traffic_plan.get("traffic_routes") or traffic_plan.get("routes") or [])
                                if isinstance(route, dict) and str(route.get("path") or "/") == "/"
                            ), "")
                        if not entry_service:
                            roles = _traffic_service_roles(traffic_plan)
                            entry_service = next((
                                service for service, (role, _) in roles.items()
                                if role == "frontend" and service in service_targets
                            ), "")
                        if entry_service in service_targets:
                            published_port = service_targets[entry_service][0][1]
                        if not published_port:
                            published_port = next((
                                port for targets in service_targets.values() for _, port in targets
                                if port == host_port
                            ), None)
                        if not published_port:
                            published_port = next((port for targets in service_targets.values() for _, port in targets), None)
                    if published_port:
                        rendered_targets = "、".join(
                            f"{service}={','.join(str(port) for _, port in targets)}"
                            for service, targets in service_targets.items()
                        )
                        log(dep.id, f"[检查] 识别到 Compose 服务入口：{rendered_targets}\n")
                    domain_config = db.get(ProjectDomainConfig, project.id)
                    domain_defaults = db.get(DeploymentSettings, "default")
                    route_groups = _compose_route_groups(project, service_targets, ai_plan)
                    verification_paths.extend([
                        str(path.get("path") or "/")
                        for group in route_groups
                        for path in (group.get("paths") or [])
                        if isinstance(path, dict) and str(path.get("path") or "/") != "/"
                    ])
                    gateway_snapshot = snapshot_platform_gateway(db, project.id)
                    access = configure_platform_gateway(
                        db, dep, node, published_port, project.domain,
                        http_port=domain_config.http_port if domain_config else (domain_defaults.default_domain_http_port if domain_defaults else 80),
                        https_enabled=domain_config.https_enabled if domain_config else False,
                        https_port=domain_config.https_port if domain_config else (domain_defaults.default_domain_https_port if domain_defaults else 443),
                        redirect_https=domain_config.redirect_https if domain_config else True,
                        certificate=decrypt(domain_config.certificate_encrypted) if domain_config else None,
                        private_key=decrypt(domain_config.private_key_encrypted) if domain_config else None,
                        route_groups=route_groups or None,
                        strategy=project.load_balance_strategy,
                    ) if published_port else None
                    public_access = access
                    gateway_switched = bool(access)
                    service_names = {service.get("name") for service in topology.get("services", [])}
                    has_root_route = any(
                        str(path.get("path") or "/") == "/"
                        for group in route_groups
                        for path in (group.get("paths") or [])
                        if isinstance(path, dict)
                    )
                    if access and build_file == ".yunzhou.compose.yml" and {"frontend", "backend"}.issubset(service_names):
                        access = access.rstrip("/") + "/app/"
                        public_access = access
                    elif access and access_path != "/" and (
                        not has_root_route or len(service_targets) == 1
                    ):
                        access = access.rstrip("/") + access_path
                        if not access_path.startswith("/api/"):
                            public_access = access
                    if access:
                        log(dep.id, f"[检查] 平台网关映射完成：{access}\n")
                else:
                    if not container_port:
                        raise RuntimeError("Dockerfile 未声明 EXPOSE，请在项目中填写容器端口")
                    base_images = dockerfile_base_images(work, build_file)
                    ai_checkpoint(dep.id, "拉取基础镜像", "已识别基础镜像：" + (", ".join(base_images) if base_images else "由 Docker 构建自动识别"))
                    log(dep.id, f"[镜像] 基础镜像已由平台构建中心处理：{', '.join(base_images) if base_images else 'Docker 构建自动识别'}\n")
                    log(dep.id, f"[镜像] 平台构建镜像已加载：{image_name}\n")
                    code, out = 0, ""
                    if code and build_file == ".yunzhou.Dockerfile" and "JCTree$JCImport" in out and "qualid" in out:
                        log(dep.id, "\n[AI修复] 识别到旧版 Java 注解处理器与当前 JDK 不兼容，自动切换到 JDK 8 安全重试一次。\n")
                        dockerfile_path = remote_dir + "/" + build_file
                        replace = (
                            f"sed -i -E 's/maven:3\\.9-eclipse-temurin-[0-9]+/maven:3.9-eclipse-temurin-8/g; "
                            f"s/eclipse-temurin:[0-9]+-jre/eclipse-temurin:8-jre/g' {shlex.quote(dockerfile_path)}"
                        )
                        replace_code, replace_out = ssh.run(replace)
                        if replace_code:
                            raise RuntimeError("AI 调整 Java 构建环境失败：" + replace_out)
                        code, out = tracked_run(ssh, dep.id,
                            f"cd {shlex.quote(remote_dir)} && DOCKER_BUILDKIT=0 docker build -f {shlex.quote(build_file)} -t {shlex.quote(image_name)} .",
                            stream=append,
                        )
                    if code:
                        log(dep.id, "\n[构建] 应用镜像编译失败，AI 正在分析并准备安全修复重试。\n")
                        raise RuntimeError(out)
                    ensure_active(dep.id)
                    env_args = ""
                    env_text = effective_project_environment(project)
                    if env_text:
                        env_file = remote_dir + "/.env.runtime"
                        code, out = ssh.run(f"printf %s {shlex.quote(env_text)} > {shlex.quote(env_file)}")
                        if code:
                            raise RuntimeError(out)
                        env_args = f"--env-file {shlex.quote(env_file)}"
                    cmd = (
                        f"docker rm -f {shlex.quote(container_name)} >/dev/null 2>&1 || true; "
                        f"docker run -d --name {shlex.quote(container_name)} --restart unless-stopped "
                        f"-e TZ=Asia/Shanghai -v /etc/localtime:/etc/localtime:ro "
                        f"{env_args} -p {host_port}:{container_port} {shlex.quote(image_name)}"
                    )
                    log(dep.id, f"\n[启动] 宿主机端口 {host_port} → 容器端口 {container_port}\n")
                    code, out = ssh.run(cmd, stream=append)
                    if code:
                        raise RuntimeError(out)
                    ensure_active(dep.id)
                    code, state = ssh.run(f"docker inspect -f '{{{{.State.Status}}}}' {shlex.quote(container_name)}")
                    log(dep.id, f"[检查] 容器状态：{state.strip()}\n")
                    ai_checkpoint(dep.id, "启动应用", f"容器 {container_name} 状态：{state.strip()}")
                    if code or state.strip() != "running":
                        raise RuntimeError("容器启动后状态异常：" + state.strip())
                    domain_config = db.get(ProjectDomainConfig, project.id)
                    domain_defaults = db.get(DeploymentSettings, "default")
                    gateway_snapshot = snapshot_platform_gateway(db, project.id)
                    access = configure_platform_gateway(
                        db, dep, node, host_port, project.domain,
                        http_port=domain_config.http_port if domain_config else (domain_defaults.default_domain_http_port if domain_defaults else 80),
                        https_enabled=domain_config.https_enabled if domain_config else False,
                        https_port=domain_config.https_port if domain_config else (domain_defaults.default_domain_https_port if domain_defaults else 443),
                        redirect_https=domain_config.redirect_https if domain_config else True,
                        certificate=decrypt(domain_config.certificate_encrypted) if domain_config else None,
                        private_key=decrypt(domain_config.private_key_encrypted) if domain_config else None,
                    )
                    public_access = access
                    gateway_switched = True
                    if access_path != "/":
                        access = access.rstrip("/") + access_path
                        if not access_path.startswith("/api/"):
                            public_access = access
                    log(dep.id, f"[检查] 平台网关映射完成：{access}\n")

            log_stage(dep.id, "完成", "start")
            current_stage = "verify"
            log_stage(dep.id, "开始", "verify")
            ensure_active(dep.id)
            if not access:
                raise RuntimeError("部署未生成可验证的访问地址")
            # Frontend assets only exist after the platform build. Re-scan the
            # actual dist here so a route discovered during gateway generation
            # (for example /frapi/) is also a mandatory success probe.
            postbuild_routes = detect_frontend_api_routes(work)
            verification_paths.extend(
                str(route.get("path") or "")
                for route in (postbuild_routes.get("routes") or [])
                if isinstance(route, dict) and str(route.get("path") or "").startswith("/")
            )
            verification_paths = list(dict.fromkeys(verification_paths))
            if verification_paths:
                log(dep.id, "[接口联合验证] " + "、".join(verification_paths) + " 必须同时无 5xx。\n")
            access = verify_access(db, dep.id, access, verification_paths)
            log_stage(dep.id, "完成", "verify")
            ensure_active(dep.id)
            if workspace_repaired_files:
                workspace_result = persist_verified_changes(
                    project,
                    work,
                    source_subpath,
                    workspace_repaired_files,
                    dep.id,
                )
                log(dep.id, f"[工作区提交] {workspace_result}\n")
            dep = db.get(Deployment, deployment_id)
            replaced = db.scalars(
                select(Deployment).where(
                    Deployment.project_id == dep.project_id,
                    Deployment.id != dep.id,
                    Deployment.status == DeployStatus.success,
                ).order_by(Deployment.created_at.desc())
            ).all()
            for old in replaced:
                old.status = DeployStatus.stopped
                old.error = None
                old.log_text = ((old.log_text or "") + f"\n[接管] 已由新版本 {release} 接管；历史记录保留，运行入口已切换到新版本。\n")[-200_000:]
            dep.status = DeployStatus.success
            dep.release = release
            dep.container_name = container_name
            dep.image_name = image_name if build_type == "dockerfile" else None
            dep.host_port = host_port if build_type == "dockerfile" else published_port
            # Keep health/readiness probes internal. The address presented to
            # users must remain the application's browser entry point.
            dep.access_url = public_access or access
            dep.finished_at = datetime.now(timezone.utc)
            for reservation in db.scalars(select(DeploymentPortReservation).where(
                DeploymentPortReservation.deployment_id == dep.id,
                DeploymentPortReservation.status == "reserved",
            )).all():
                reservation.status = "active"
            db.commit()
            # The gateway now targets the verified candidate. Only at this
            # point may the previous runtime be retired. A stop failure is
            # reported but never rolls traffic back to an unverified release.
            for old in replaced:
                try:
                    old_node = db.get(Node, old.node_id)
                    if old_node:
                        stop_deployment(old, project, old_node, release_ports=True)
                        log(dep.id, f"[版本切换] 已停止旧版本 {old.release or old.id[:8]}；固定数据卷继续保留。\n")
                except Exception as stop_exc:
                    log(dep.id, f"[版本切换] 入口已切换，但旧版本 {old.release or old.id[:8]} 自动停止未完成：{stop_exc}\n")
            # Every new release must first prove itself as one healthy instance.
            # Retire replicas from the previous release and keep the new release
            # single-instance until the user explicitly scales it from Runtime.
            try:
                from .main import scale_project
                from .schemas import ScaleProjectIn
                from .models import User
                # Automatic post-deploy work is still part of the original
                # user's operation. Never attribute it to an arbitrary admin.
                operator = db.get(User, dep.requested_by)
                if operator:
                    result = scale_project(project.id, ScaleProjectIn(replicas=1), db, operator)
                    dep = db.get(Deployment, deployment_id)
                    access = result.get("access_url") or access
                    log(dep.id, f"[单实例验证] 已就绪 1/1；如需负载均衡，请在运行服务中手动增加实例。入口 {access}\n")
            except Exception as scale_exc:
                log(dep.id, f"[运行容器] 主版本已发布，但副本同步未完成：{scale_exc}\n")
            try:
                dep = db.get(Deployment, deployment_id)
                cleanup_report = cleanup_old_project_images(db, dep, project, node)
                log(dep.id, "[镜像整理] 已保留当前运行版和上一个成功版；" + cleanup_report + "\n")
            except Exception as cleanup_exc:
                # Image housekeeping must never turn a verified deployment into
                # a failure. The next successful release will retry it.
                log(dep.id, f"[镜像整理] 本次自动整理未完成，将在下次成功发布后重试：{cleanup_exc}\n")
            log(dep.id, f"\n[完成] 部署成功{('，访问地址：' + access) if access else ''}\n")
            ai_checkpoint(dep.id, "检查服务关系", f"部署成功，访问地址：{access or '未生成'}")
        except DeploymentCancelled:
            dep = db.get(Deployment, deployment_id)
            if gateway_switched and gateway_snapshot is not None and project:
                try:
                    restore_platform_gateway(db, project.id, gateway_snapshot)
                    log(dep.id, "[网关回滚] 候选版本已停止，入口已恢复到原在线版本。\n")
                except Exception as gateway_exc:
                    log(dep.id, f"[网关回滚失败] {gateway_exc}\n")
            log_stage(dep.id, "停止", current_stage)
            dep.status = DeployStatus.stopped
            dep.finished_at = datetime.now(timezone.utc)
            db.commit()
            log(dep.id, "\n[停止] 部署任务已由用户停止\n")
            if 'remote_dir' in locals():
                try:
                    with SSHNode(node) as cleanup_ssh:
                        cleanup_ssh.run(f"rm -rf -- {shlex.quote(remote_dir)}")
                    log(dep.id, "[清理] 已删除本次未完成的发布目录\n")
                except Exception as cleanup_exc:
                    log(dep.id, f"[清理] 未完成目录清理失败：{cleanup_exc}\n")
            try:
                report = cleanup_incomplete_release_images(db, dep, project, node, locals().get("release"))
                log(dep.id, f"[清理复查] 本次停止版本镜像已删除：{report}\n")
            except Exception as cleanup_exc:
                dep.error = f"停止成功，但镜像清理复查失败：{cleanup_exc}"
                db.commit()
                log(dep.id, f"[清理失败] {cleanup_exc}\n")
            try:
                restore_preempted_runtime("被停止")
            except Exception as restore_exc:
                log(dep.id, f"[版本回退失败] {restore_exc}\n")
        except Exception as exc:
            # A flush/commit error (notably a concurrent port reservation)
            # leaves SQLAlchemy's transaction unusable until rollback. Always
            # recover the session before recording the deployment failure so
            # one task can never terminate the whole worker.
            db.rollback()
            dep = db.get(Deployment, deployment_id)
            if gateway_switched and gateway_snapshot is not None and project:
                try:
                    restore_platform_gateway(db, project.id, gateway_snapshot)
                    log(dep.id, "[网关回滚] 候选版本验证失败，入口已恢复到原在线版本。\n")
                except Exception as gateway_exc:
                    log(dep.id, f"[网关回滚失败] {gateway_exc}\n")
            if dep.status != DeployStatus.stopped:
                log_stage(dep.id, "失败", current_stage, str(exc)[:500])
                # Keep the server-side traceback in the deployment log.  The
                # UI still shows the concise error, while diagnostics retain
                # the exact failing function/line for automatic repair.
                log(dep.id, "[平台诊断堆栈]\n" + traceback.format_exc()[-12000:] + "\n")
                dep.status = DeployStatus.failed
                dep.error = str(exc)
                dep.finished_at = datetime.now(timezone.utc)
                db.commit()
                log(dep.id, f"\n[失败] {exc}\n")
                ai_checkpoint(dep.id, "部署失败", str(exc))
            for reservation in db.scalars(select(DeploymentPortReservation).where(
                DeploymentPortReservation.deployment_id == dep.id,
                DeploymentPortReservation.status == "reserved",
            )).all():
                reservation.status = "released"
            db.commit()
            if 'remote_dir' in locals():
                # Stop/remove failed runtime containers immediately, but do
                # not touch their image layers while another build may still
                # be committing to the shared Docker store.
                try:
                    release_value = str(locals().get("release") or dep.release or "")
                    with SSHNode(node) as cleanup_ssh:
                        failed_compose_project = deployment_compose_project_name(dep, project)
                        runtime_cleanup = (
                            "ids=$(docker ps -aq --filter "
                            + shlex.quote(f"label=com.docker.compose.project={failed_compose_project}")
                            + "); for cid in $ids; do cfg=$(docker inspect -f "
                            + shlex.quote('{{index .Config.Labels "com.docker.compose.project.config_files"}}')
                            + " \"$cid\" 2>/dev/null); case \"$cfg\" in */"
                            + release_value
                            + "/*) docker rm -f \"$cid\" >/dev/null 2>&1 || true ;; esac; done; "
                            + (f"docker rm -f {shlex.quote(dep.container_name)} >/dev/null 2>&1 || true" if dep.container_name else "true")
                        )
                        cleanup_ssh.run(runtime_cleanup)
                    log(dep.id, "[清理] 已停止并删除本次失败版本容器；镜像等待构建队列空闲后统一清理\n")
                except Exception as runtime_cleanup_exc:
                    log(dep.id, f"[清理] 失败容器将在后台空闲清理时再次处理：{runtime_cleanup_exc}\n")
                try:
                    with SSHNode(node) as cleanup_ssh:
                        cleanup_ssh.run(f"rm -rf -- {shlex.quote(remote_dir)}")
                    log(dep.id, "[清理] 已删除失败部署的发布目录\n")
                except Exception as cleanup_exc:
                    log(dep.id, f"[清理] 失败目录清理失败：{cleanup_exc}\n")
            try:
                restore_preempted_runtime("验证失败")
            except Exception as restore_exc:
                log(dep.id, f"[版本回退失败] {restore_exc}\n")
            # Image deletion/pruning is durable work for the worker's idle
            # cleanup queue. Running it here can race another classic build
            # and corrupt Docker/containerd snapshot metadata.
            dep = db.get(Deployment, deployment_id)
            dep.log_text = ((dep.log_text or "") +
                "[待清理] 已登记本次失败版本镜像；待全部构建任务结束后自动清理并复查\n"
            )[-200_000:]
            db.commit()
        finally:
            # Transfer artifacts are release-specific and can be removed.
            if 'release' in locals() and project:
                try:
                    builder_node = platform_gateway_node(db)
                    if builder_node:
                        builder_archive = f"/tmp/yunzhou-images-{dep.id}.tar.gz"
                        with SSHNode(builder_node) as builder_cleanup:
                            builder_cleanup.run(
                                f"rm -f -- {shlex.quote(builder_archive)}"
                            )
                except Exception as builder_cleanup_exc:
                    if dep:
                        log(dep.id, f"[清理] 平台构建临时目录将在后台再次整理：{builder_cleanup_exc}\n")
            if runtime_bundle:
                shutil.rmtree(runtime_bundle, ignore_errors=True)
            if cleanup_root:
                shutil.rmtree(cleanup_root, ignore_errors=True)


