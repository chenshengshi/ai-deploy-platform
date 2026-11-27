"""Validate and materialize AI deployment plans into platform-owned build files."""

import re
import shlex
from pathlib import Path

import yaml

from ..ai import MANAGED_MINIO_FALLBACK
from ..build_planning import (
    PLATFORM_NGINX_IMAGE,
    normalize_inline_dockerfile,
    optimize_maven_dependency_layer,
    optimize_node_dependency_layer,
    source_declares_environment_optional,
    strip_generated_code_fence,
    valid_generated_dockerfile,
)
from .architecture import COMPOSE_NAMES
from ..source_inspection import (
    _public_path_from_value,
    detect_frontend_api_routes,
    detect_frontend_public_base,
)
from .build_preparation import prepare_build
from .build_handlers import detect_container_port

PLATFORM_REDIS_IMAGE = "redis:7.4-alpine"
PLATFORM_MYSQL_IMAGE = "mysql:8.4"
PLATFORM_POSTGRES_IMAGE = "postgres:16"
PLATFORM_NODE_BUILD_IMAGE = "node:22-bookworm-slim"
PLATFORM_NODE_RUNTIME_IMAGE = "node:22-bookworm-slim"
PLATFORM_PYTHON_IMAGE = "python:3.10-slim-bookworm"
PLATFORM_IMAGE_VARIABLES = {
    "YUNZHOU_NODE_BUILD_IMAGE": PLATFORM_NODE_BUILD_IMAGE,
    "YUNZHOU_NODE_RUNTIME_IMAGE": PLATFORM_NODE_RUNTIME_IMAGE,
    "YUNZHOU_PYTHON_IMAGE": PLATFORM_PYTHON_IMAGE,
}
DOCKER_HUB_MIRROR_HOSTS = {
    "docker.m.daocloud.io", "docker.anyhub.us.kg", "dockerhub.jobcher.com",
    "mirror.ccs.tencentyun.com", "docker.mirrors.ustc.edu.cn",
    "docker.nju.edu.cn", "dockerhub.icu", "docker.ckyl.me",
    "docker.awsl9527.cn", "hub-mirror.c.163.com",
}


def canonical_docker_image(image: str, managed_minio_image: str = MANAGED_MINIO_FALLBACK) -> str:
    """Keep transparent Docker Hub mirrors in daemon.json, not image names."""
    value = image.strip()
    host, separator, remainder = value.partition("/")
    if separator and host.lower() in DOCKER_HUB_MIRROR_HOSTS:
        value = remainder
        if value.startswith("library/"):
            value = value[len("library/"):]
    repository = value.rsplit("@", 1)[0].rsplit(":", 1)[0].lower()
    if repository in {"minio/minio", "quay.io/minio/minio"}:
        return managed_minio_image
    lowered = value.lower()
    if re.match(r"^(?:library/)?nginx(?::[^/]+)?$", lowered):
        return PLATFORM_NGINX_IMAGE
    if re.match(r"^(?:library/)?redis(?::[^/]+)?$", lowered):
        return PLATFORM_REDIS_IMAGE
    if re.match(r"^(?:library/)?mysql(?::[^/]+)?$", lowered):
        return PLATFORM_MYSQL_IMAGE
    if re.match(r"^(?:library/)?postgres(?:ql)?(?::[^/]+)?$", lowered):
        return PLATFORM_POSTGRES_IMAGE
    return value


def reconcile_compose_build_targets(root: Path, compose: dict) -> list[str]:
    """Point Compose targets at the Dockerfile that actually defines them.

    An AI plan can generate a valid multi-stage ``.yunzhou.ai.Dockerfile`` but
    accidentally leave a service pointing at a repository Dockerfile.  Docker
    then reports ``target stage ... could not be found`` even though the stage
    is present in the generated plan.  Resolve only an unambiguous match; never
    invent a stage or silently choose between multiple candidates.
    """
    services = compose.get("services") if isinstance(compose, dict) else None
    if not isinstance(services, dict):
        return []

    def stage_names(path: Path) -> set[str]:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return set()
        return {
            match.group(1)
            for match in re.finditer(r"(?im)^\s*FROM\s+\S+(?:\s+AS\s+([A-Za-z0-9_.-]+))?\s*$", text)
            if match.group(1)
        }

    changes: list[str] = []
    for service_name, service in services.items():
        build = service.get("build") if isinstance(service, dict) else None
        if not isinstance(build, dict) or not build.get("target") or build.get("dockerfile_inline"):
            continue
        target = str(build["target"]).strip()
        context_value = str(build.get("context") or ".")
        context = (root / context_value).resolve()
        if context != root and root not in context.parents:
            continue
        configured = (context / str(build.get("dockerfile") or "Dockerfile")).resolve()
        if target in stage_names(configured):
            continue

        candidates: list[Path] = []
        generated = root / ".yunzhou.ai.Dockerfile"
        search = [generated]
        search.extend(path for path in context.glob("*Dockerfile*") if path.is_file())
        for candidate in search:
            resolved = candidate.resolve()
            if resolved == configured or resolved in candidates:
                continue
            if target in stage_names(resolved):
                candidates.append(resolved)
        if len(candidates) != 1:
            continue
        replacement = candidates[0].relative_to(context).as_posix()
        old = str(build.get("dockerfile") or "Dockerfile")
        build["dockerfile"] = replacement
        changes.append(f"{service_name}: {old} -> {replacement}（target={target}）")
    return changes


def prune_undeclared_development_services(compose: dict, plan: dict) -> list[str]:
    """Remove known local-development helpers omitted by the effective plan.

    The model can correctly exclude tools such as Adminer in its summary and
    ``services`` list while accidentally leaving the service copied from the
    repository's development Compose file.  The explicit effective service
    list is authoritative for these well-known helpers because Yunzhou owns
    the public gateway and exposes data inspection separately.
    """
    services = compose.get("services") if isinstance(compose, dict) else None
    declared = {
        str(name).strip().lower()
        for name in (plan.get("services") or [])
        if str(name).strip()
    }
    if not isinstance(services, dict) or not declared:
        return []

    development_helpers = re.compile(
        r"(?i)(?:^|[/_\s-])(?:adminer|phpmyadmin|pgadmin|mailpit|mailhog|traefik|"
        r"selenium|playwright|cypress)(?=$|[:/_\s-])"
    )
    removed = []
    for name, service in list(services.items()):
        if str(name).strip().lower() in declared or not isinstance(service, dict):
            continue
        identity = " ".join((str(name), str(service.get("image") or "")))
        if development_helpers.search(identity):
            services.pop(name, None)
            removed.append(str(name))

    if not removed:
        return []
    removed_set = set(removed)
    for service in services.values():
        if not isinstance(service, dict):
            continue
        depends = service.get("depends_on")
        if isinstance(depends, dict):
            for name in removed_set:
                depends.pop(name, None)
        elif isinstance(depends, list):
            service["depends_on"] = [name for name in depends if name not in removed_set]
    return removed


def _complete_source_compose(root: Path) -> tuple[Path, str] | None:
    """Return a complete repository-owned Compose topology when available.

    AI remains useful for explaining and repairing a deployment, but it must
    not rename or omit services from a production Compose file supplied by the
    project.  Generated Yunzhou files are deliberately excluded here.
    """
    source_names = COMPOSE_NAMES[:4]
    ignored = {".git", "node_modules", "target", "dist", "build", "vendor"}
    candidates: list[Path] = []
    for name in source_names:
        direct = root / name
        if direct.is_file():
            candidates.append(direct)
        for candidate in root.rglob(name):
            relative = candidate.relative_to(root)
            if len(relative.parts) <= 4 and not any(part in ignored for part in relative.parts):
                candidates.append(candidate)
    for candidate in sorted(set(candidates), key=lambda item: (len(item.relative_to(root).parts), item.as_posix())):
        try:
            document = yaml.safe_load(candidate.read_text(encoding="utf-8", errors="replace")) or {}
        except (OSError, yaml.YAMLError):
            continue
        services = document.get("services") if isinstance(document, dict) else None
        if not isinstance(services, dict) or len(services) < 2:
            continue
        if any(not isinstance(service, dict) or not (service.get("image") or service.get("build")) for service in services.values()):
            continue
        application_services = [
            name for name in services
            if not any(token in str(name).lower() for token in ("mysql", "mariadb", "postgres", "mongo", "redis", "minio", "rustfs", "init"))
        ]
        if not application_services:
            continue
        return candidate, candidate.read_text(encoding="utf-8", errors="replace")
    return None


def materialize_ai_deployment_plan(
    path: str, plan: dict, release_strategy: str = "auto"
) -> tuple[str, str, int | None]:
    """Validate and materialize an AI plan without allowing host-level escape hatches."""
    root = Path(path).resolve()
    detected_api = detect_frontend_api_routes(path)
    detected_frontend_base = detect_frontend_public_base(path)
    frontend_base = str(detected_frontend_base.get("primary_path") or "/")
    managed_api_prefix = str(detected_api.get("primary_path") or "")
    traffic_plan = plan.get("traffic_plan") if isinstance(plan.get("traffic_plan"), dict) else {}
    if traffic_plan and frontend_base != "/":
        roles = {
            str(row.get("service") or ""): str(row.get("role") or "").lower()
            for row in (traffic_plan.get("service_roles") or [])
            if isinstance(row, dict)
        }
        frontend_service = next((name for name, role in roles.items() if role == "frontend"), "")
        frontend_service = frontend_service or str(traffic_plan.get("default_service") or traffic_plan.get("entry_service") or "")
        routes = [dict(row) for row in (traffic_plan.get("traffic_routes") or traffic_plan.get("routes") or []) if isinstance(row, dict)]
        changed = False
        for route in routes:
            if str(route.get("service") or "") == frontend_service and str(route.get("path") or "/") == "/":
                route["path"] = frontend_base
                route["strip_prefix"] = True
                changed = True
        if frontend_service and not any(str(row.get("service") or "") == frontend_service for row in routes):
            routes.append({"path": frontend_base, "service": frontend_service, "strip_prefix": True})
            changed = True
        if changed:
            traffic_plan["traffic_routes"] = routes
            plan["traffic_plan"] = traffic_plan
            plan["access_path"] = frontend_base
            plan["safe_repairs"] = list(plan.get("safe_repairs") or []) + [
                f"依据生产配置保留前端子路径 {frontend_base}（{'、'.join(detected_frontend_base.get('evidence') or [])}）"
            ]
    # The AI plan is advisory; effective production source is authoritative.
    # Reconcile the route again at materialization time so a stale analysis or
    # contradictory model answer cannot generate a broken gateway config.
    detected_routes = {
        str(row.get("path") or ""): bool(row.get("strip_prefix", False))
        for row in (detected_api.get("routes") or [])
        if isinstance(row, dict) and str(row.get("path") or "").startswith("/")
    }
    if traffic_plan and detected_routes:
        reconciled_routes = []
        for route in traffic_plan.get("traffic_routes") or traffic_plan.get("routes") or []:
            if not isinstance(route, dict):
                continue
            normalized = dict(route)
            route_path = str(normalized.get("path") or "")
            if route_path in detected_routes:
                normalized["strip_prefix"] = detected_routes[route_path]
            reconciled_routes.append(normalized)
        if reconciled_routes:
            traffic_plan["traffic_routes"] = reconciled_routes
            plan["traffic_plan"] = traffic_plan
    if not managed_api_prefix:
        for route in traffic_plan.get("traffic_routes") or []:
            candidate = _public_path_from_value(str((route or {}).get("path") or "")) if isinstance(route, dict) else None
            if candidate:
                managed_api_prefix = candidate
                break
    source_compose = None if release_strategy == "platform_generated" else _complete_source_compose(root)
    if release_strategy == "source_compose" and not source_compose:
        raise RuntimeError("项目选择了按源码 Compose 发布，但当前源码中未检测到可直接运行的完整 Docker Compose")
    kind = str(plan.get("deployment_kind") or "").strip().lower()
    if not source_compose and (
        not str(plan.get("summary") or "").strip() or kind not in {"compose", "dockerfile"}
    ):
        raise RuntimeError("AI 返回的部署方案缺少架构结论或部署类型")
    dockerfile_text = strip_generated_code_fence(plan.get("dockerfile") or "")
    compose_text = strip_generated_code_fence(plan.get("compose_yaml") or "")
    if source_compose:
        source_path, compose_text = source_compose
        kind = "compose"
        dockerfile_text = ""
        plan["primary_file"] = source_path.relative_to(root).as_posix()
        plan["source_compose_authoritative"] = True
        plan["safe_repairs"] = list(plan.get("safe_repairs") or []) + [
            f"检测到完整源码 Compose，保留其全部服务、依赖、初始化任务和数据卷：{plan['primary_file']}"
        ]
    resolved_platform_images = []
    for variable, image in PLATFORM_IMAGE_VARIABLES.items():
        pattern = rf"\$\{{{re.escape(variable)}(?::(?:-|\?)[^}}]*)?\}}"
        updated = re.sub(pattern, image, compose_text)
        if updated != compose_text:
            resolved_platform_images.append(f"{variable}={image}")
            compose_text = updated
    if resolved_platform_images:
        plan["safe_repairs"] = list(plan.get("safe_repairs") or []) + [
            "已使用平台推荐的固定运行镜像：" + "、".join(resolved_platform_images)
        ]
    # Some models put a complete Compose document in the `dockerfile` JSON
    # property. Recover it when possible instead of sending YAML to Docker.
    if dockerfile_text and not valid_generated_dockerfile(dockerfile_text):
        try:
            misplaced_compose = yaml.safe_load(dockerfile_text)
        except yaml.YAMLError:
            misplaced_compose = None
        if isinstance(misplaced_compose, dict) and isinstance(misplaced_compose.get("services"), dict):
            if not compose_text:
                compose_text = dockerfile_text
            dockerfile_text = ""
            kind = "compose"
        elif kind == "dockerfile":
            # Do not let malformed AI output reach `docker build`. The local
            # repository detector is deterministic and provides a safe fallback.
            return prepare_build(path, "auto")
    managed_minio_image = str(plan.get("managed_minio_image") or MANAGED_MINIO_FALLBACK)
    if dockerfile_text:
        if re.search(r"(?im)^\s*(?:ADD|COPY)\s+https?://", dockerfile_text):
            raise RuntimeError("AI Dockerfile 包含未经校验的远程文件下载")
        dockerfile_text = re.sub(
            r"(?im)^(\s*FROM\s+(?:--platform=\S+\s+)?)(\S+)",
            lambda match: match.group(1) + canonical_docker_image(match.group(2), managed_minio_image),
            dockerfile_text,
        )
        dockerfile_text = normalize_inline_dockerfile(dockerfile_text)
        unsupported_classic = []
        if re.search(r"(?im)^\s*RUN\s+--mount=", dockerfile_text):
            unsupported_classic.append("RUN --mount")
        if re.search(r"(?im)^\s*(?:COPY|ADD)\s+--link(?:=\S+)?\s+", dockerfile_text):
            unsupported_classic.append("COPY/ADD --link")
        if re.search(r"(?im)^\s*(?:RUN|COPY|ADD)\s+<<[-~]?\w+", dockerfile_text):
            unsupported_classic.append("Dockerfile heredoc")
        if unsupported_classic:
            raise RuntimeError(
                "AI 方案仍依赖 BuildKit 专属语法（" + "、".join(unsupported_classic)
                + "），平台未找到可验证的经典构建等价方案，已停止而不会自动切换 buildx"
            )
        # AI plans sometimes copy only the obvious frontend directories before
        # running a build. Monorepos may legally import shared types or helpers
        # from sibling directories (for example src -> server/src). Ensure the
        # complete repository is present in every Node build stage instead of
        # letting an incomplete generated COPY list look like a source error.
        stages = re.split(r"(?im)(?=^\s*FROM\s+)", dockerfile_text)
        for index, stage in enumerate(stages):
            build_run = re.search(r"(?im)^\s*RUN\s+.*(?:npm|pnpm|yarn)\s+(?:run\s+)?build\b.*$", stage)
            copies_all = re.search(r"(?im)^\s*COPY\s+(?:--\S+\s+)*\.\s+\.\s*$", stage)
            if build_run and not copies_all:
                stages[index] = stage[:build_run.start()] + "COPY . .\n" + stage[build_run.start():]
        dockerfile_text = "".join(stages)
        dockerfile_text = optimize_node_dependency_layer(root, dockerfile_text)
        dockerfile_text = optimize_maven_dependency_layer(root, dockerfile_text)
        (root / ".yunzhou.ai.Dockerfile").write_text(dockerfile_text + "\n", encoding="utf-8")
    try:
        container_port = int(plan["container_port"]) if plan.get("container_port") not in (None, "") else None
    except (TypeError, ValueError):
        container_port = None
        plan["container_port"] = None
        plan["port_fallback_reason"] = "AI 端口不是有效数字，已改用源码与构建文件自动识别"
    if container_port is not None and not 1 <= container_port <= 65535:
        # A model may confuse host:container mapping, concatenate values or
        # return a protocol port outside the valid range. This is advisory
        # metadata, not a reason to make the whole source analysis unusable.
        # EXPOSE/Compose/source detection below is deterministic and wins.
        container_port = None
        plan["container_port"] = None
        plan["port_fallback_reason"] = "AI 端口超出 1-65535，已改用源码与构建文件自动识别"
    if kind == "dockerfile":
        requested_file = str(plan.get("primary_file") or ".yunzhou.ai.Dockerfile").replace("\\", "/").lstrip("/")
        dockerfile = (root / requested_file).resolve()
        if root not in dockerfile.parents:
            raise RuntimeError("AI 返回的 Dockerfile 路径不安全")
        if not dockerfile.exists():
            # A model can correctly select the deployment kind but omit the
            # generated file body. Treat that as incomplete model output, not
            # as a source-code failure: the deterministic detector can build a
            # safe Dockerfile from package manifests and known entry points.
            return prepare_build(path, "auto")
        relative = dockerfile.relative_to(root).as_posix()
        # The materialized Dockerfile is the final executable artifact. If an
        # earlier AI analysis carried a stale port, prefer the explicit EXPOSE
        # from the generated file so runtime mapping cannot point at port 80
        # while the application actually listens on 4300.
        return "dockerfile", relative, detect_container_port(path, relative) or container_port
    if not compose_text:
        return prepare_build(path, "auto")
    # AI may occasionally promote a source-level optional variable to `${VAR:?}`.
    # Source code is authoritative: keep it optional so the application's own
    # fallback executes instead of repeatedly asking the user for fake values.
    required_pattern = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*):\?[^}]*\}")
    for variable in set(required_pattern.findall(compose_text)):
        if source_declares_environment_optional(path, variable):
            compose_text = re.sub(
                rf"\$\{{{re.escape(variable)}:\?[^}}]*\}}",
                "${" + variable + ":-}",
                compose_text,
            )
    # Models occasionally double the inner quotes of a password argument
    # inside a YAML flow-style healthcheck. That makes the whole Compose file
    # unparsable. Quotes are unnecessary for this single environment value;
    # keep Compose's escaped dollar and normalize before parsing.
    compose_text = re.sub(
        r'-p""\$\$([A-Za-z_][A-Za-z0-9_]*)""',
        r'-p$$\1',
        compose_text,
    )
    try:
        compose = yaml.safe_load(compose_text)
    except yaml.YAMLError as exc:
        raise RuntimeError(f"AI 生成的 Compose 语法无效：{exc}") from exc
    services = compose.get("services") if isinstance(compose, dict) else None
    if not isinstance(services, dict) or not services:
        raise RuntimeError("AI 生成的 Compose 没有可运行服务")
    if source_compose:
        # Published ports in repository Compose files are normally intended
        # for a developer workstation and can collide across projects.  Keep
        # every internal port and service relationship, but let the platform
        # publish exactly one verified gateway below.
        for service in services.values():
            if isinstance(service, dict):
                exposed = [str(value) for value in (service.get("expose") or [])]
                for mapping in service.get("ports") or []:
                    if isinstance(mapping, dict):
                        target = str(mapping.get("target") or "").strip()
                    else:
                        raw = str(mapping).split("/", 1)[0]
                        target = raw.rsplit(":", 1)[-1].strip()
                    if target.isdigit() and target not in exposed:
                        exposed.append(target)
                if exposed:
                    service["expose"] = exposed
                service.pop("ports", None)
        gateway = next((name for name in services if str(name).lower() in {"nginx", "gateway", "proxy"}), "")
        if not gateway:
            gateway = max(
                services,
                key=lambda name: (
                    int(any(token in str(name).lower() for token in ("web", "front", "ui"))),
                    int("nginx" in yaml.safe_dump(services[name], allow_unicode=True).lower()),
                ),
            )
        source_roles = []
        for name in services:
            lowered = str(name).lower()
            if name == gateway:
                role = "app"
            elif any(token in lowered for token in ("mysql", "mariadb", "postgres", "mongo", "redis", "minio", "rustfs")) and "init" not in lowered:
                role = "data"
            elif "init" in lowered:
                role = "worker"
            elif any(token in lowered for token in ("web", "front", "ui")):
                role = "frontend"
            else:
                role = "backend"
            source_roles.append({"service": name, "role": role, "scalable": name == gateway})
        traffic_plan = {
            "service_roles": source_roles,
            "default_service": gateway,
            "traffic_routes": [{"path": "/", "service": gateway, "strip_prefix": False}],
        }
        plan["traffic_plan"] = traffic_plan
        # Carry the topology decision with the executable artifact.  Later
        # packaging stages may be resumed with a deployment plan loaded from
        # an older analysis; the materialized Compose is the final authority.
        compose["x-yunzhou-source-compose"] = True
        compose["x-yunzhou-entry-service"] = gateway
    removed_helpers = prune_undeclared_development_services(compose, plan)
    if removed_helpers:
        plan["safe_repairs"] = list(plan.get("safe_repairs") or []) + [
            "已移除未纳入生产方案的开发辅助服务：" + "、".join(removed_helpers)
        ]
        services = compose["services"]
    target_repairs = reconcile_compose_build_targets(root, compose)
    if target_repairs:
        plan["safe_repairs"] = list(plan.get("safe_repairs") or []) + target_repairs
    published = False
    for name, service in services.items():
        if not isinstance(service, dict):
            raise RuntimeError(f"AI Compose 服务 {name} 配置无效")
        if service.get("image"):
            service["image"] = canonical_docker_image(str(service["image"]), managed_minio_image)
            # PostgreSQL 18+ changed the official image's declared data
            # volume from /var/lib/postgresql/data to /var/lib/postgresql so
            # pg_upgrade can work across major versions.  AI plans trained on
            # older examples often combine a current image with the legacy
            # mount, which makes the container exit before application start.
            postgres_match = re.match(r"(?i)^postgres:(?P<tag>[^@]+)(?:@.*)?$", str(service["image"]))
            postgres_tag = postgres_match.group("tag").lower() if postgres_match else ""
            postgres_major = re.match(r"^(\d+)", postgres_tag)
            # Unversioned rolling tags such as postgres:alpine and
            # postgres:bookworm currently follow the newest major just like
            # :latest. They therefore need the 18+ mount layout too. A pinned
            # 17-alpine (or older) retains the legacy /data target.
            postgres_uses_v18_layout = bool(postgres_match) and (
                not postgres_major or int(postgres_major.group(1)) >= 18
            )
            if postgres_uses_v18_layout:
                repaired_volumes = []
                for volume in service.get("volumes") or []:
                    if isinstance(volume, str):
                        parts = volume.split(":")
                        if len(parts) >= 2 and parts[1] == "/var/lib/postgresql/data":
                            parts[1] = "/var/lib/postgresql"
                            volume = ":".join(parts)
                    elif isinstance(volume, dict) and volume.get("target") == "/var/lib/postgresql/data":
                        volume = {**volume, "target": "/var/lib/postgresql"}
                    repaired_volumes.append(volume)
                service["volumes"] = repaired_volumes
                plan["safe_repairs"] = list(plan.get("safe_repairs") or []) + [
                    f"{name}: PostgreSQL 18+ 数据卷调整为 /var/lib/postgresql"
                ]
        if service.get("privileged") is True or service.get("network_mode") == "host":
            raise RuntimeError(f"AI Compose 服务 {name} 请求了不安全的宿主机权限")
        if service.get("devices") or service.get("pid") == "host" or service.get("ipc") == "host":
            raise RuntimeError(f"AI Compose 服务 {name} 请求了不安全的宿主机资源")
        for volume in service.get("volumes") or []:
            source = str(volume).split(":", 1)[0] if isinstance(volume, str) else str((volume or {}).get("source", ""))
            if source.startswith(("/", "\\")) or ".." in Path(source).parts or "docker.sock" in source:
                raise RuntimeError(f"AI Compose 服务 {name} 包含不安全的宿主机挂载")
        for mapping in service.get("ports") or []:
            if "${YUNZHOU_HOST_PORT}" in str(mapping):
                published = True
        # Vue CLI loads repository .env files while building and those files can
        # override a generated Dockerfile ARG/ENV.  A production-local file has
        # the highest dotenv priority.  Use the prefix detected from this
        # repository/traffic plan; never inject a platform-wide fixed path.
        build = service.get("build")
        if frontend_base != "/" and isinstance(build, dict):
            args = build.get("args")
            if isinstance(args, dict) and "VITE_APP_BASE" in args:
                args["VITE_APP_BASE"] = frontend_base
        if isinstance(build, dict) and isinstance(build.get("dockerfile_inline"), str):
            inline = normalize_inline_dockerfile(build["dockerfile_inline"])
            inline = optimize_node_dependency_layer(root, inline)
            inline = optimize_maven_dependency_layer(root, inline)
            # --openssl-legacy-provider is a Node 17/OpenSSL 3 workaround. Some
            # AI plans add it to Node 16 images where Node rejects the option
            # before the project's build script even starts.
            if re.search(r"(?im)^\s*FROM\s+node:(?:[0-9]|1[0-6])(?:[-:@]|$)", inline):
                inline = re.sub(r"(?i)\bNODE_OPTIONS=--openssl-legacy-provider\s+", "", inline)
            if managed_api_prefix and "VUE_APP_BASE_API" in inline and re.search(r"(?im)^\s*RUN\s+.*(?:npm|pnpm|yarn)\s+(?:run\s+)?build\b", inline):
                marker = "RUN printf " + shlex.quote("VUE_APP_BASE_API=" + managed_api_prefix + "\\n") + " > .env.production.local\n"
                if marker not in inline:
                    inline = re.sub(
                        r"(?im)^(\s*RUN\s+.*(?:npm|pnpm|yarn)\s+(?:run\s+)?build\b.*)$",
                        marker + r"\1",
                        inline,
                        count=1,
                    )
            inline = normalize_inline_dockerfile(inline)
            if not valid_generated_dockerfile(inline):
                raise RuntimeError(f"AI Compose 服务 {name} 生成的 Dockerfile 语法无效，平台已在构建前拦截")
            build["dockerfile_inline"] = inline
    if not published:
        # Do not fail a complete plan only because the model used a fixed host
        # port. Select the most likely web gateway and normalize its public
        # mapping to the port allocated by Yunzhou.
        def entry_score(item):
            service_name, service = item
            text = yaml.safe_dump(service, allow_unicode=True).lower()
            score = 0
            if any(word in service_name.lower() for word in ("web", "front", "ui", "gateway", "nginx")):
                score += 20
            if "nginx" in text:
                score += 15
            if service.get("ports"):
                score += 10
            if any(word in service_name.lower() for word in ("mysql", "redis", "cache", "db")):
                score -= 30
            return score

        entry_name, entry_service = max(services.items(), key=entry_score)
        mappings = list(entry_service.get("ports") or [])
        target_port = container_port
        if mappings:
            first = mappings[0]
            if isinstance(first, dict):
                target_port = first.get("target") or target_port
                first["published"] = "${YUNZHOU_HOST_PORT}"
                mappings[0] = first
            else:
                raw = str(first)
                protocol = "/" + raw.rsplit("/", 1)[1] if "/" in raw else ""
                without_protocol = raw.rsplit("/", 1)[0]
                target = without_protocol.rsplit(":", 1)[-1]
                if target.isdigit():
                    target_port = int(target)
                mappings[0] = f"${{YUNZHOU_HOST_PORT}}:{target_port or 80}{protocol}"
        else:
            if not target_port:
                text = yaml.safe_dump(entry_service, allow_unicode=True).lower()
                target_port = 80 if "nginx" in text else 8080
            mappings = [f"${{YUNZHOU_HOST_PORT}}:{target_port}"]
        entry_service["ports"] = mappings
        published = True
    compose_text = yaml.safe_dump(compose, sort_keys=False, allow_unicode=True)
    compose_file = root / ".yunzhou.ai.compose.yml"
    compose_file.write_text(compose_text + "\n", encoding="utf-8")
    return "compose", compose_file.name, None

