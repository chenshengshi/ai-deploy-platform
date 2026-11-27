"""Source integration analysis independent from the HTTP routing layer."""

from __future__ import annotations

import json
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path

from fastapi import HTTPException
from sqlalchemy.orm import Session

from ..ai import analyze_project_deployment
from ..audit import audit
from ..config import decrypt, encrypt, settings
from ..deployment.ai_plan import _complete_source_compose
from ..deployment.analysis_preflight import preflight_ai_deployment_plan
from ..deployment.settings import get_deployment_settings
from ..deployment.source_staging import stage_source
from ..models import Project, SourceType, User
from ..source_inspection import detect_frontend_api_routes

def _source_workspace_metadata(item: Project) -> tuple[str | None, str | None]:
    """Return the durable source location shown by analysis progress/results.

    Git projects keep a project-level checkout between analysis and deployment
    runs.  Upload projects already have a durable ``current`` source tree, so
    reporting the Git cache path for them would point at a directory that is
    intentionally never created.
    """
    if item.source_type == SourceType.git:
        cache = f"{settings.build_data_root.rstrip('/')}/builder/projects/{item.slug}/source-cache"
        return cache, cache
    source = str(item.source_path or "").strip() or None
    return source, None


def _runtime_service_versions(item: Project, plan: dict | None, db: Session, source_path: str | Path | None = None) -> list[dict]:
    """Build the small, auditable runtime-version summary shown in source management."""
    policy = get_deployment_settings(db)
    defaults = {
        "nginx": policy.default_nginx_image,
        "redis": policy.default_redis_image,
        "mysql": policy.default_mysql_image,
        "postgres": policy.default_postgres_image,
    }
    labels = {"nginx": "Nginx", "redis": "Redis", "mysql": "MySQL", "postgres": "PostgreSQL"}
    text_parts = []
    if plan:
        text_parts.extend([str(plan.get("compose_yaml") or ""), str(plan.get("dockerfile") or "")])
        for row in plan.get("build_environment") or []:
            if isinstance(row, dict):
                text_parts.extend([str(row.get("build_image") or ""), str(row.get("runtime_image") or "")])
    plan_text = "\n".join(text_parts)
    source_text = ""
    root = Path(source_path) if source_path else None
    if root and root.exists():
        source_files = []
        for pattern in (
            "Dockerfile*", "compose*.yml", "compose*.yaml", "docker-compose*.yml", "docker-compose*.yaml",
            "pom.xml", "build.gradle*", "package.json", "requirements*.txt", "application*.yml",
            "application*.yaml", "application*.properties", ".env*",
        ):
            source_files.extend(root.rglob(pattern))
        for path in list(dict.fromkeys(source_files))[:200]:
            if path.is_file() and not any(part in {".git", "node_modules", "dist", "build", "target"} for part in path.relative_to(root).parts):
                source_text += "\n" + path.read_text(encoding="utf-8", errors="ignore")[:100_000]
    explicit: dict[str, str] = {}
    for match in re.finditer(r"(?i)(?<![a-z0-9._/-])(nginx|redis|mysql|postgres(?:ql)?):([a-z0-9][a-z0-9._-]*)", source_text):
        family = "postgres" if match.group(1).lower().startswith("postgres") else match.group(1).lower()
        explicit.setdefault(family, f"{family}:{match.group(2)}")
    detected_text = " ".join(str(value) for value in ((plan or {}).get("services") or [])).lower()
    dependency_text = (source_text + "\n" + plan_text).lower()
    dependency_markers = {
        "mysql": ("mysql-connector", "jdbc:mysql", "pymysql", "mysqlclient"),
        "postgres": ("postgresql", "jdbc:postgres", "psycopg", "pg8000"),
        "redis": ("data-redis", "redis.clients", "spring.redis", "ioredis", "redis://"),
    }
    env_values = {}
    for line in (decrypt(item.env_text_encrypted) or "").splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            key, value = line.split("=", 1)
            env_values[key.strip()] = value.strip().lower()
    rows = []
    overrides = item.runtime_image_overrides
    for family in ("nginx", "redis", "mysql", "postgres"):
        external_key = f"YUNZHOU_{'POSTGRES' if family == 'postgres' else family.upper()}_MODE"
        external = env_values.get(external_key) == "external"
        mentioned = family in detected_text or family in explicit or any(
            marker in dependency_text for marker in dependency_markers.get(family, ())
        )
        if family == "nginx":
            mentioned = mentioned or any(str(row.get("runtime_image") or "").lower().startswith("nginx") for row in ((plan or {}).get("build_environment") or []) if isinstance(row, dict))
        if not mentioned:
            continue
        if external:
            prefix = "POSTGRES" if family == "postgres" else family.upper()
            host = env_values.get(f"YUNZHOU_{prefix}_HOST", "")
            port = env_values.get(f"YUNZHOU_{prefix}_PORT", "")
            database = env_values.get(f"YUNZHOU_{prefix}_DATABASE", "")
            endpoint = ":".join(value for value in (host, port) if value)
            if database:
                endpoint += "/" + database
            rows.append({
                "service": labels[family],
                "image": "",
                "source": "外部依赖",
                "mode": "external",
                "endpoint": endpoint or "已使用项目保存的外接配置",
                "editable": False,
            })
            continue
        selected_image = str(overrides.get(labels[family]) or defaults[family])
        selected_source = "用户修改" if labels[family] in overrides else "平台推荐"
        rows.append({
            "service": labels[family],
            "image": selected_image,
            "source": selected_source,
            "editable": True,
        })
        if plan:
            original_image = explicit.get(family) or defaults[family]
            for field in ("compose_yaml", "dockerfile"):
                value = str(plan.get(field) or "")
                if value and original_image:
                    plan[field] = re.sub(rf"(?<![a-zA-Z0-9._/-]){re.escape(original_image)}(?![a-zA-Z0-9._-])", selected_image, value)
    return rows


def analyze_project_integrations_service(item_id: str, db: Session, user: User):
    item = db.get(Project, item_id)
    if not item:
        raise HTTPException(404, "项目不存在")
    cleanup_root = None
    try:
        previous_state = item.source_analysis or {}
        started_at = previous_state.get("started_at") or datetime.now(timezone.utc).isoformat()
        pulling_summary = "正在拉取 Git 仓库和指定分支。" if item.source_type == SourceType.git else "正在读取已上传的源码。"
        workspace_path, repository_cache_path = _source_workspace_metadata(item)
        item.integration_analysis_json = json.dumps({
            "status": "running", "phase": "pulling", "progress": 25,
            "summary": pulling_summary, "started_at": started_at,
            "workspace_path": workspace_path,
            "repository_cache_path": repository_cache_path,
            "branch": item.git_branch or "默认分支",
        }, ensure_ascii=False)
        db.commit()
        source, revision, cleanup_root, source_subpath = stage_source(item, db)
        item = db.get(Project, item_id)
        workspace_path, repository_cache_path = _source_workspace_metadata(item)
        item.integration_analysis_json = json.dumps({
            "status": "running", "phase": "analyzing", "progress": 65,
            "summary": "源码已准备完成，正在识别技术栈、端口和外部依赖。",
            "started_at": started_at, "source_ready_at": datetime.now(timezone.utc).isoformat(),
            "revision": revision, "source_subpath": source_subpath or "",
            "workspace_path": workspace_path,
            "repository_cache_path": repository_cache_path,
            "branch": item.git_branch or "默认分支",
        }, ensure_ascii=False)
        db.commit()
        # Common infrastructure should be detected locally in seconds. Reserve
        # the slower model call for unusual integrations that static evidence
        # cannot classify.
        root = Path(source)
        source_compose = _complete_source_compose(root)
        config_text = ""
        config_names = {"application.yml", "application.yaml", "application.properties", ".env", ".env.example", "bootstrap.yml", "bootstrap.yaml", "package.json", "pom.xml", "build.gradle", "requirements.txt", "go.mod", "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}
        for path in root.rglob("*"):
            parts = path.relative_to(root).parts
            source_config = path.suffix.lower() in {".ts", ".js", ".mjs", ".cjs", ".py", ".java", ".go"} and any(part.lower() in {"config", "db", "database"} for part in parts[:-1])
            if not path.is_file() or (path.name not in config_names and not source_config) or any(part in {".git", "node_modules", "target", "dist", "build"} for part in parts):
                continue
            try:
                config_text += "\n" + path.read_text(encoding="utf-8", errors="ignore")[:80_000]
            except OSError:
                continue
            if len(config_text) > 600_000:
                break
        lower = config_text.lower()
        services, required, inferred = [], [], []
        if any(token in lower for token in ("jdbc:mysql", "mysql2", "mysql.createpool", "mysql", "druid")):
            services.append("MySQL")
            db_name = ""
            match = re.search(r"jdbc:mysql://[^/\s:'\"]+(?::\d+)?/([A-Za-z0-9_-]+)", config_text, re.I)
            if match:
                db_name = match.group(1)
            required.extend([
                {"key": "YUNZHOU_MYSQL_HOST", "reason": "现有 MySQL 地址", "secret": False},
                {"key": "YUNZHOU_MYSQL_PORT", "reason": "现有 MySQL 端口", "secret": False},
                {"key": "YUNZHOU_MYSQL_DATABASE", "reason": "数据库名称", "secret": False},
                {"key": "YUNZHOU_MYSQL_USERNAME", "reason": "现有 MySQL 用户名", "secret": False},
                {"key": "YUNZHOU_MYSQL_PASSWORD", "reason": "现有 MySQL 密码", "secret": True},
            ])
            inferred.append({"key": "YUNZHOU_MYSQL_PORT", "value": "3306", "source": "MySQL 默认端口", "confidence": "high"})
            if db_name:
                inferred.append({"key": "YUNZHOU_MYSQL_DATABASE", "value": db_name, "source": "源码 JDBC 配置", "confidence": "high"})
        if "redis" in lower:
            services.append("Redis")
            required.extend([
                {"key": "YUNZHOU_REDIS_HOST", "reason": "现有 Redis 地址", "secret": False},
                {"key": "YUNZHOU_REDIS_PORT", "reason": "Redis 端口，通常为 6379", "secret": False},
                {"key": "YUNZHOU_REDIS_PASSWORD", "reason": "Redis 密码；无密码时可留空", "secret": True},
                {"key": "YUNZHOU_REDIS_DATABASE", "reason": "Redis 库编号，通常为 0", "secret": False},
            ])
            inferred.extend([
                {"key": "YUNZHOU_REDIS_PORT", "value": "6379", "source": "Redis 默认端口", "confidence": "high"},
                {"key": "YUNZHOU_REDIS_DATABASE", "value": "0", "source": "Redis 默认库", "confidence": "high"},
            ])
        if any(token in lower for token in ("minio", "s3.endpoint", "aws_s3")):
            services.append("MinIO / S3")
            required.extend([
                {"key": "MINIO_ENDPOINT", "reason": "现有对象存储地址", "secret": False},
                {"key": "MINIO_ACCESS_KEY", "reason": "对象存储 Access Key", "secret": True},
                {"key": "MINIO_SECRET_KEY", "reason": "对象存储 Secret Key", "secret": True},
            ])
        local_services, local_required, local_inferred = services, required, inferred
        plan_error = None
        try:
            plan = analyze_project_deployment(db, item, source)
        except Exception as exc:
            # Model/deployment analysis is allowed to fall back to the local
            # detector.  SQLAlchemy, however, leaves the whole session in a
            # failed transaction after any database error.  Continuing with
            # that poisoned session used to make the later audit INSERT fail
            # and hide the first, useful error from the user.
            plan = None
            plan_error = str(exc)
            db.rollback()
            item = db.get(Project, item_id)
            if not item:
                raise HTTPException(404, "项目不存在")
        # Use the same deterministic Compose decision for analysis display and
        # actual publishing.  Previously publishing could discover a complete
        # source Compose later while the settings page still showed the stale
        # AI conclusion "platform generated".
        if source_compose:
            source_compose_path, _ = source_compose
            source_primary_file = source_compose_path.relative_to(root).as_posix()
            if plan is None:
                plan = {
                    "summary": "检测到完整源码 Compose，发布时保留源码服务拓扑",
                    "deployment_kind": "compose",
                    "services": [],
                }
            plan["deployment_kind"] = "compose"
            plan["primary_file"] = source_primary_file
            plan["source_compose_authoritative"] = True
            plan["safe_repairs"] = list(plan.get("safe_repairs") or []) + [
                f"检测到完整源码 Compose，发布时保留全部服务、依赖、初始化任务和数据卷：{source_primary_file}"
            ]
        # AI is an enhancement, not a single point of failure for publishing.
        # When the configured upstream is unavailable, keep the deterministic
        # source scan (including an empty result) and allow the user to retry
        # the richer analysis later without blocking deployment.
        if plan:
            # Source evidence is authoritative for the public API prefix.  The
            # model identifies service roles, while this deterministic pass
            # selects the effective production/runtime prefix instead of
            # publishing every dev/stage alias or assuming a global /api.
            detected_traffic = detect_frontend_api_routes(source)
            detected_path = str(detected_traffic.get("primary_path") or "")
            traffic_plan = plan.get("traffic_plan") if isinstance(plan.get("traffic_plan"), dict) else {}
            service_roles = list(traffic_plan.get("service_roles") or [])
            role_by_service = {
                str(row.get("service") or ""): str(row.get("role") or "").lower()
                for row in service_roles if isinstance(row, dict)
            }
            planned_services = [str(value) for value in plan.get("services") or []]
            frontend_service = next((name for name, role in role_by_service.items() if role == "frontend"), "")
            backend_service = next((name for name, role in role_by_service.items() if role == "backend"), "")
            if not frontend_service:
                frontend_service = next((name for name in planned_services if re.search(r"front|web|ui", name, re.I)), "")
            if not backend_service:
                backend_service = next((name for name in planned_services if re.search(r"back|api|server", name, re.I)), "")
            if frontend_service and backend_service and detected_path:
                detected_route = (detected_traffic.get("routes") or [{}])[0]
                traffic_plan = {
                    **traffic_plan,
                    "default_service": frontend_service,
                    "api_paths": [str(detected_route.get("path") or detected_path + "/")],
                    "api_route_evidence": detected_traffic.get("evidence") or [],
                    "traffic_routes": [
                        {
                            "path": str(detected_route.get("path") or detected_path + "/"),
                            "service": backend_service,
                            "strip_prefix": bool(detected_route.get("strip_prefix", False)),
                        },
                        {"path": "/", "service": frontend_service, "strip_prefix": False},
                    ],
                }
                plan["traffic_plan"] = traffic_plan
            # A real, non-example .env referenced by the production Compose is
            # executable project configuration, not documentation.  Import it
            # into the platform's encrypted project environment on first
            # analysis so fixed-image applications keep their required public
            # URL and private runtime keys.  Never replace values the user has
            # already saved in the platform.
            existing_env = (decrypt(item.env_text_encrypted) or "").strip()
            source_env_path = root / ".env"
            compose_uses_env_file = any(
                path.is_file() and re.search(r"(?m)^\s*env_file\s*:\s*(?:\n\s*-\s*)?\.?/?\.env\s*$", path.read_text(encoding="utf-8", errors="ignore"))
                for path in (
                    root / "docker-compose.yml", root / "docker-compose.yaml",
                    root / "compose.yml", root / "compose.yaml",
                )
            )
            if not existing_env and source_env_path.is_file() and compose_uses_env_file:
                source_env = source_env_path.read_text(encoding="utf-8", errors="ignore").strip()
                populated = [
                    line for line in source_env.splitlines()
                    if line.strip() and not line.lstrip().startswith("#")
                    and "=" in line and line.split("=", 1)[1].strip()
                ]
                if populated:
                    item.env_text_encrypted = encrypt(source_env + "\n")
                    existing_env = source_env
                    audit(db, user, "import_production_env", "project", item.id, f"encrypted_keys={len(populated)}")
            services = []
            seen_services = set()
            for service in local_services + list(plan.get("services") or []):
                normalized = str(service).strip().lower()
                if normalized and normalized not in seen_services:
                    seen_services.add(normalized)
                    services.append(service)
            required_rows = local_required + list(plan.get("required_user_config") or [])
            inferred_rows = local_inferred + list(plan.get("inferred_config") or [])
            required = list({row.get("key"): row for row in required_rows if row.get("key")}.values())
            inferred = list({row.get("key"): row for row in inferred_rows if row.get("key")}.values())
            configured_keys = {
                line.split("=", 1)[0].strip()
                for line in existing_env.splitlines()
                if "=" in line and not line.lstrip().startswith("#") and line.split("=", 1)[1].strip()
            }
            required = [row for row in required if row.get("key") not in configured_keys]
            if item.deployment_mode == "managed_fresh":
                # Managed databases and their credentials are platform-owned.
                # Do not ask users for an external database or leak generated
                # secret placeholders into the source-analysis form.
                managed_keys = {
                    "YUNZHOU_HOST_PORT",
                    "YUNZHOU_MYSQL_HOST", "YUNZHOU_MYSQL_PORT", "YUNZHOU_MYSQL_DATABASE",
                    "YUNZHOU_MYSQL_USERNAME", "YUNZHOU_MYSQL_PASSWORD",
                    "CRM_DB_PASSWORD", "CRM_DB_ROOT_PASSWORD",
                    "YUNZHOU_REDIS_HOST", "YUNZHOU_REDIS_PORT", "YUNZHOU_REDIS_PASSWORD",
                    "YUNZHOU_REDIS_DATABASE", "CRM_REDIS_PASSWORD",
                    "MINIO_ENDPOINT", "MINIO_ACCESS_KEY", "MINIO_SECRET_KEY",
                    "MINIO_ROOT_USER", "MINIO_ROOT_PASSWORD",
                }
                required = [row for row in required if row.get("key") not in managed_keys]
                inferred = [
                    row for row in inferred
                    if not str(row.get("key") or "").startswith(("YUNZHOU_MYSQL_", "YUNZHOU_REDIS_"))
                ]
            else:
                # Preserve mode is decided per dependency, not as one global
                # "everything is external" switch.  A managed Redis/MySQL is
                # still created and injected by the platform, while only a
                # dependency explicitly selected as external is shown to the
                # user as required connection configuration.
                user_values = {}
                for line in (decrypt(item.env_text_encrypted) or "").splitlines():
                    if "=" in line and not line.lstrip().startswith("#"):
                        key, value = line.split("=", 1)
                        user_values[key.strip()] = value.strip()
                managed_prefixes = []
                if user_values.get("YUNZHOU_MYSQL_MODE", "managed").lower() != "external":
                    managed_prefixes.append("YUNZHOU_MYSQL_")
                if user_values.get("YUNZHOU_REDIS_MODE", "managed").lower() != "external":
                    managed_prefixes.append("YUNZHOU_REDIS_")
                if managed_prefixes:
                    required = [
                        row for row in required
                        if not str(row.get("key") or "").startswith(tuple(managed_prefixes))
                        and not (
                            str(row.get("key") or "") == "CRM_REDIS_PASSWORD"
                            and "YUNZHOU_REDIS_" in managed_prefixes
                        )
                    ]
                    inferred = [
                        row for row in inferred
                        if not str(row.get("key") or "").startswith(tuple(managed_prefixes))
                    ]
                # An explicitly external MySQL is expected to be an existing,
                # initialized business database.  Do not simultaneously ask
                # the user for a schema bootstrap script.
                if user_values.get("YUNZHOU_MYSQL_MODE", "managed").lower() == "external":
                    required = [
                        row for row in required
                        if str(row.get("key") or "") not in {"WMS_DB_SCHEMA_SQL", "DB_SCHEMA_SQL", "MYSQL_SCHEMA_SQL"}
                    ]
            summary = str(plan.get("mode_decision") or plan.get("summary") or "AI 已完成源码分析")
            model = plan.get("model") or plan.get("requested_model") or "平台 AI"
            item.integration_analysis_json = json.dumps({
                "status": "running", "phase": "preflight", "progress": 85,
                "summary": "AI 已生成部署方案，正在隔离副本中检查架构、构建文件和配置。",
                "started_at": started_at, "revision": revision,
            }, ensure_ascii=False)
            db.commit()
            previous_error = str(
                previous_state.get("previous_error")
                or previous_state.get("error")
                or (((previous_state.get("preflight") or {}).get("execution") or {}).get("error"))
                or ""
            )
            preflight = preflight_ai_deployment_plan(source, plan, item, db, previous_error)
        else:
            services, required, inferred = local_services, local_required, local_inferred
            summary = "AI 本次暂不可用，平台已保留本地源码识别结果；稍后可一键重新分析。"
            model = "平台本地兜底"
            preflight = None
        audit(db, user, "analyze_integrations", "project", item.id, f"required={len(required)}; inferred={len(inferred)}")
        db.commit()
        workspace_path, repository_cache_path = _source_workspace_metadata(item)
        result = {
            "status": "completed",
            "phase": "completed",
            "progress": 100,
            "summary": summary,
            "services": services,
            "required": required,
            "inferred": inferred,
            "model": model,
            "build_environment": list(plan.get("build_environment") or []) if plan else [],
            "runtime_services": _runtime_service_versions(item, plan, db, source),
            "deployment_kind": str(plan.get("deployment_kind") or "") if plan else "",
            "container_port": plan.get("container_port") if plan else None,
            "access_path": str(plan.get("access_path") or "/") if plan else "/",
            "ai_completed": bool(plan),
            "ai_error": plan_error if not plan else None,
            # Keep the executable result of the full source analysis. A publish
            # of the same revision can materialize this plan immediately instead
            # of calling the model for the same repository a second time.
            "deployment_plan": plan if plan else None,
            "preflight": preflight,
            "revision": revision,
            "started_at": started_at,
            "finished_at": datetime.now(timezone.utc).isoformat(),
            "workspace_path": workspace_path,
            "repository_cache_path": repository_cache_path,
            "branch": item.git_branch or "默认分支",
        }
        item.integration_analysis_json = json.dumps(result, ensure_ascii=False)
        db.commit()
        return result
    except HTTPException:
        db.rollback()
        raise
    except Exception as exc:
        db.rollback()
        raise HTTPException(502, f"AI 分析现有集成失败：{exc}")
    finally:
        if cleanup_root:
            shutil.rmtree(cleanup_root, ignore_errors=True)


