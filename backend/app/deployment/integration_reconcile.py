"""Reconcile managed and external data integrations in generated Compose."""

import json
import re
from pathlib import Path

import yaml

from ..config import decrypt
from .integrations import (
    data_service_names,
    environment_values,
    integration_consumers,
    is_backend_service,
    managed_mysql_image_for_source,
    managed_mysql_values,
    managed_redis_values,
    normalize_service_environment,
    redis_is_required,
    remove_empty_command_arguments,
    store_managed_values,
)
from ..models import Project

PLATFORM_MYSQL_IMAGE = "mysql:8.4"
PLATFORM_REDIS_IMAGE = "redis:7.4-alpine"

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


def reconcile_managed_integrations(project: Project, compose_path: str, compose_file: str) -> list[str]:
    """Guarantee that every unchecked integration has a real managed Compose service."""
    target = Path(compose_path) / compose_file
    document = yaml.safe_load(target.read_text(encoding="utf-8", errors="ignore")) or {}
    services = document.setdefault("services", {})
    if not isinstance(services, dict):
        return []
    user_values = environment_values(decrypt(project.env_text_encrypted) or "")
    changes = []

    external_mysql = user_values.get("YUNZHOU_MYSQL_MODE", "managed").lower() == "external"
    if external_mysql:
        mysql_names = data_service_names(services, "mysql")
        for name in mysql_names:
            services.pop(name, None)
        spring_project = bool(
            re.search(r"Spring\s*Boot|Java", json.dumps(project.source_analysis or {}, ensure_ascii=False), re.I)
            or next(Path(compose_path).rglob("pom.xml"), None)
        )
        for name, service in services.items():
            if not isinstance(service, dict):
                continue
            depends = service.get("depends_on")
            if isinstance(depends, dict):
                for mysql_name in mysql_names:
                    depends.pop(mysql_name, None)
            elif isinstance(depends, list):
                service["depends_on"] = [value for value in depends if value not in mysql_names]
            backend_like = is_backend_service(name)
            raw_env = normalize_service_environment(service, create=backend_like)
            if not isinstance(raw_env, dict):
                continue
            jdbc = "jdbc:mysql://${YUNZHOU_MYSQL_HOST}:${YUNZHOU_MYSQL_PORT}/${YUNZHOU_MYSQL_DATABASE}"
            aliases = {
                "DB_URL": jdbc,
                "DB_HOST": "${YUNZHOU_MYSQL_HOST}",
                "DB_PORT": "${YUNZHOU_MYSQL_PORT}",
                "DB_NAME": "${YUNZHOU_MYSQL_DATABASE}",
                "DB_DATABASE": "${YUNZHOU_MYSQL_DATABASE}",
                "DB_USERNAME": "${YUNZHOU_MYSQL_USERNAME}",
                "DB_USER": "${YUNZHOU_MYSQL_USERNAME}",
                "DB_PASSWORD": "${YUNZHOU_MYSQL_PASSWORD}",
                "MYSQL_HOST": "${YUNZHOU_MYSQL_HOST}",
                "MYSQL_PORT": "${YUNZHOU_MYSQL_PORT}",
                "MYSQL_DATABASE": "${YUNZHOU_MYSQL_DATABASE}",
                "MYSQL_USER": "${YUNZHOU_MYSQL_USERNAME}",
                "MYSQL_PASSWORD": "${YUNZHOU_MYSQL_PASSWORD}",
            }
            for key, value in aliases.items():
                if backend_like or key in raw_env:
                    raw_env[key] = value
            if backend_like and spring_project:
                raw_env.update({
                    "SPRING_DATASOURCE_URL": jdbc,
                    "SPRING_DATASOURCE_USERNAME": "${YUNZHOU_MYSQL_USERNAME}",
                    "SPRING_DATASOURCE_PASSWORD": "${YUNZHOU_MYSQL_PASSWORD}",
                    "SPRING_DATASOURCE_DRUID_MASTER_URL": jdbc,
                    "SPRING_DATASOURCE_DRUID_MASTER_USERNAME": "${YUNZHOU_MYSQL_USERNAME}",
                    "SPRING_DATASOURCE_DRUID_MASTER_PASSWORD": "${YUNZHOU_MYSQL_PASSWORD}",
                })
        changes.append("外接 MySQL 最终裁决：移除内置数据库并重写应用连接参数")
    else:
        # MySQL 8 uses caching_sha2_password by default.  For platform-managed
        # databases on an isolated Docker network, generated JDBC URLs often
        # disable TLS but omit the connector flag required to retrieve the
        # server public key.  Keep MySQL 8.4 and repair only those managed,
        # non-TLS URLs; external integrations remain entirely user-owned.
        for name, service in services.items():
            if not isinstance(service, dict):
                continue
            raw_env = service.get("environment")
            if isinstance(raw_env, list):
                raw_env = {
                    value.split("=", 1)[0]: value.split("=", 1)[1]
                    for value in raw_env if isinstance(value, str) and "=" in value
                }
                service["environment"] = raw_env
            if not isinstance(raw_env, dict):
                continue
            for key, value in list(raw_env.items()):
                jdbc = str(value or "")
                if not re.search(r"(?i)^jdbc:mysql://", jdbc):
                    continue
                if not re.search(r"(?i)(?:[?&])useSSL=false(?:&|$)", jdbc):
                    continue
                if re.search(r"(?i)(?:[?&])allowPublicKeyRetrieval=", jdbc):
                    continue
                separator = "&" if "?" in jdbc else "?"
                raw_env[key] = jdbc + separator + "allowPublicKeyRetrieval=true"
                changes.append(f"{name} 托管 MySQL 认证参数")

    # Generated/source Compose files sometimes express optional Spring Boot
    # settings as `--property=`. Older Spring versions reject an empty command
    # line option before the application context starts. Environment variables
    # remain available, so omit only syntactically empty `--name=` arguments;
    # never remove a non-empty user value.
    changes.extend(remove_empty_command_arguments(services))

    def consumers(prefix: str) -> list[str]:
        return integration_consumers(services, prefix)

    redis_required, existing_redis_name = redis_is_required(project, services)
    if redis_required and user_values.get("YUNZHOU_REDIS_MODE", "managed").lower() != "external":
        redis_values = managed_redis_values(project)
        password = redis_values["YUNZHOU_REDIS_PASSWORD"]
        redis_name = existing_redis_name
        if not redis_name:
            redis_name = "redis"
            services[redis_name] = {
                "image": PLATFORM_REDIS_IMAGE,
                "command": ["redis-server", "--appendonly", "yes", "--requirepass", "${YUNZHOU_REDIS_PASSWORD}"],
                "volumes": [f"{project.slug}_redis_data:/data"],
                "healthcheck": {"test": ["CMD-SHELL", "redis-cli -a $$YUNZHOU_REDIS_PASSWORD ping | grep PONG"], "interval": "10s", "timeout": "5s", "retries": 10},
                "environment": {"YUNZHOU_REDIS_PASSWORD": "${YUNZHOU_REDIS_PASSWORD}"},
                "restart": "unless-stopped",
            }
            document.setdefault("volumes", {}).setdefault(f"{project.slug}_redis_data", {})
        else:
            # A generated plan may already contain a plain redis:alpine service
            # while the platform has generated YUNZHOU_REDIS_PASSWORD for its
            # consumers.  Configure both sides here so Spring/Node applications
            # never send AUTH to a password-less Redis instance.
            redis_service = services[redis_name]
            redis_service.setdefault("environment", {})
            if isinstance(redis_service["environment"], dict):
                redis_service["environment"]["YUNZHOU_REDIS_PASSWORD"] = "${YUNZHOU_REDIS_PASSWORD}"
                # Source plans commonly call this REDIS_PASSWORD while the
                # platform contract uses YUNZHOU_REDIS_PASSWORD. Keep the
                # source-facing alias, but bind it to the same managed value.
                redis_service["environment"]["REDIS_PASSWORD"] = "${YUNZHOU_REDIS_PASSWORD}"
            command = redis_service.get("command")
            if isinstance(command, str):
                if "requirepass" in command.lower():
                    # AI/source Compose may already contain a hard-coded or
                    # historical password. Presence is not correctness: make
                    # the Redis process, healthcheck and application clients
                    # consume the same platform-managed credential.
                    redis_service["command"] = re.sub(
                        r"(?i)(--requirepass(?:=|\s+))\S+",
                        r'\1"$${YUNZHOU_REDIS_PASSWORD}"',
                        command,
                    )
                else:
                    redis_service["command"] = command.rstrip() + " --requirepass ${YUNZHOU_REDIS_PASSWORD}"
            elif isinstance(command, list):
                normalized_command = list(command)
                require_index = next(
                    (index for index, item in enumerate(normalized_command) if str(item).lower() == "--requirepass"),
                    None,
                )
                if require_index is not None:
                    if require_index + 1 < len(normalized_command):
                        normalized_command[require_index + 1] = "${YUNZHOU_REDIS_PASSWORD}"
                    else:
                        normalized_command.append("${YUNZHOU_REDIS_PASSWORD}")
                    redis_service["command"] = normalized_command
                elif any("requirepass" in str(item).lower() for item in normalized_command):
                    redis_service["command"] = [
                        re.sub(
                            r"(?i)(--requirepass(?:=|\s+))\S+",
                            r'\1"$${YUNZHOU_REDIS_PASSWORD}"',
                            str(item),
                        ) if "requirepass" in str(item).lower() else item
                        for item in normalized_command
                    ]
                else:
                    redis_service["command"] = [*command, "--requirepass", "${YUNZHOU_REDIS_PASSWORD}"]
            else:
                redis_service["command"] = [
                    "redis-server", "--appendonly", "yes", "--requirepass", "${YUNZHOU_REDIS_PASSWORD}",
                ]
            redis_service["healthcheck"] = {
                "test": ["CMD-SHELL", "redis-cli -a $$YUNZHOU_REDIS_PASSWORD ping | grep PONG"],
                "interval": "10s",
                "timeout": "5s",
                "retries": 10,
            }
        # Application releases reuse one stable project-level data stack.  The
        # AI plan may call its Redis service ``frcloud-redis`` (or another
        # release-specific name), while an older data stack is already running
        # as ``redis``.  Always publish the stable DNS alias to applications;
        # split_compose_runtime also adds this alias to newly created Redis
        # services, so both fresh and reused stacks resolve the same hostname.
        store_managed_values(project, redis_values)
        for name, service in services.items():
            if name == redis_name or not isinstance(service, dict):
                continue
            service_uses_redis = "redis" in yaml.safe_dump(service, allow_unicode=True).lower()
            backend_like = is_backend_service(name)
            if not (service_uses_redis or backend_like):
                continue
            raw_env = normalize_service_environment(service, create=True)
            if isinstance(raw_env, dict):
                # Generated/source plans use several Spring generations and
                # aliases (SPRING_REDIS_*, SPRING_DATA_REDIS_*, CRM_*). Bind
                # every Redis connection credential to the one stable
                # project-level managed secret. This is required when the data
                # volume/container is reused by a later application release.
                for env_key in list(raw_env):
                    normalized_key = str(env_key).upper()
                    if "REDIS" not in normalized_key:
                        continue
                    if normalized_key.endswith("PASSWORD"):
                        raw_env[env_key] = "${YUNZHOU_REDIS_PASSWORD}"
                    elif normalized_key.endswith("HOST"):
                        raw_env[env_key] = "${YUNZHOU_REDIS_HOST}"
                    elif normalized_key.endswith("PORT"):
                        raw_env[env_key] = "${YUNZHOU_REDIS_PORT}"
                    elif normalized_key.endswith("DATABASE"):
                        raw_env[env_key] = "${YUNZHOU_REDIS_DATABASE}"
                raw_env.update({
                    "REDIS_HOST": "${YUNZHOU_REDIS_HOST}",
                    "REDIS_PORT": "${YUNZHOU_REDIS_PORT}",
                    "REDIS_PASSWORD": "${YUNZHOU_REDIS_PASSWORD}",
                    "SPRING_REDIS_HOST": "${YUNZHOU_REDIS_HOST}",
                    "SPRING_REDIS_PORT": "${YUNZHOU_REDIS_PORT}",
                    "SPRING_REDIS_DATABASE": "${YUNZHOU_REDIS_DATABASE}",
                    "SPRING_REDIS_PASSWORD": "${YUNZHOU_REDIS_PASSWORD}",
                    "SPRING_DATA_REDIS_HOST": "${YUNZHOU_REDIS_HOST}",
                    "SPRING_DATA_REDIS_PORT": "${YUNZHOU_REDIS_PORT}",
                    "SPRING_DATA_REDIS_DATABASE": "${YUNZHOU_REDIS_DATABASE}",
                    "SPRING_DATA_REDIS_PASSWORD": "${YUNZHOU_REDIS_PASSWORD}",
                })
        changes.append("Redis")

    if consumers("YUNZHOU_MYSQL_") and user_values.get("YUNZHOU_MYSQL_MODE", "managed").lower() != "external":
        mysql_values = managed_mysql_values(project)
        mysql_image, mysql_evidence = managed_mysql_image_for_source(
            compose_path, project, PLATFORM_MYSQL_IMAGE
        )
        services.setdefault("mysql", {
            "image": mysql_image,
            "environment": {"MYSQL_DATABASE": "${YUNZHOU_MYSQL_DATABASE}", "MYSQL_USER": "${YUNZHOU_MYSQL_USERNAME}", "MYSQL_PASSWORD": "${YUNZHOU_MYSQL_PASSWORD}", "MYSQL_ROOT_PASSWORD": "${YUNZHOU_MYSQL_ROOT_PASSWORD}"},
            "volumes": [f"{project.slug}_mysql_data:/var/lib/mysql"],
            "healthcheck": {"test": ["CMD-SHELL", "mysqladmin ping -h 127.0.0.1 -uroot -p$$MYSQL_ROOT_PASSWORD"], "interval": "10s", "timeout": "5s", "retries": 20},
            "restart": "unless-stopped",
        })
        mysql_name = next((name for name, service in services.items() if isinstance(service, dict) and (
            str(service.get("image") or "").lower().startswith("mysql:") or name.lower() in {"mysql", "db"}
        )), None)
        if mysql_name:
            services[mysql_name]["image"] = mysql_image
            changes.append(f"MySQL 版本 {mysql_image}（{mysql_evidence}）")
        document.setdefault("volumes", {}).setdefault(f"{project.slug}_mysql_data", {})
        store_managed_values(project, mysql_values)
        changes.append("MySQL")

    if changes:
        target.write_text(yaml.safe_dump(document, allow_unicode=True, sort_keys=False), encoding="utf-8")
    return list(dict.fromkeys(changes))

