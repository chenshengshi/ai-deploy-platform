"""Compose runtime image, route and port planning."""

import copy
import json
import re
import shlex
from datetime import datetime, timezone
from pathlib import Path

import yaml
from sqlalchemy import select

from ..build_planning import PLATFORM_NGINX_IMAGE, detect_java_log_directories
from ..config import decrypt
from .integrations import environment_values
from .runtime_ports import (
    compose_port_number as _compose_port_number,
    project_traffic_plan as _project_traffic_plan,
    traffic_service_roles as _traffic_service_roles,
)
from ..models import DeploymentPortReservation, DeploymentSettings, Node, Project, ProjectDomainConfig
from ..source_inspection import enforce_nginx_pid_compatibility
from .naming import service_container_name as _service_container_name
from .ports import choose_node_port
from .runtime_environment import application_environment


def _compose_service_container_port(root: Path, service: dict) -> int | None:
    for mapping in service.get("ports") or []:
        port = _compose_port_number(mapping.get("target") if isinstance(mapping, dict) else mapping)
        if port:
            return port
    for exposed in service.get("expose") or []:
        port = _compose_port_number(exposed)
        if port:
            return port
    environment = service.get("environment") or {}
    if isinstance(environment, list):
        environment = dict(
            str(value).split("=", 1) for value in environment
            if isinstance(value, str) and "=" in value
        )
    if isinstance(environment, dict):
        for key in ("SERVER_PORT", "PORT"):
            port = _compose_port_number(environment.get(key))
            if port:
                return port
    build = service.get("build")
    if build:
        build_spec = build if isinstance(build, dict) else {"context": build}
        inline = str(build_spec.get("dockerfile_inline") or "")
        target = str(build_spec.get("target") or "").strip()
        port = _dockerfile_exposed_port(inline, target)
        if port:
            return port
        context = (root / str(build_spec.get("context") or ".")).resolve()
        dockerfile = (context / str(build_spec.get("dockerfile") or "Dockerfile")).resolve()
        if dockerfile.is_file() and (dockerfile == root or root in dockerfile.parents):
            text_value = dockerfile.read_text(encoding="utf-8", errors="ignore")
            port = _dockerfile_exposed_port(text_value, target)
            if port:
                return port
    return None


def _dockerfile_exposed_port(text_value: str, target: str = "") -> int | None:
    """Return the runtime port for the requested Docker build stage.

    A shared multi-stage Dockerfile may expose both an API port and nginx port.
    Looking at the final EXPOSE in the entire file incorrectly assigns port 80
    to backend services.  Compose's build target is authoritative when present.
    """
    if not text_value:
        return None
    selected = text_value
    if target:
        stages = list(re.finditer(
            r"(?im)^\s*FROM\s+\S+(?:\s+AS\s+([a-zA-Z0-9_.-]+))?\s*$",
            text_value,
        ))
        wanted = target.lower()
        for index, stage in enumerate(stages):
            if str(stage.group(1) or "").lower() != wanted:
                continue
            end = stages[index + 1].start() if index + 1 < len(stages) else len(text_value)
            selected = text_value[stage.start():end]
            break
    matches = re.findall(r"(?im)^\s*EXPOSE\s+(\d{1,5})(?:/tcp)?(?:\s+.*)?$", selected)
    return int(matches[-1]) if matches else None


def _compose_route_groups(project: Project, service_targets: dict[str, list[tuple[str, int]]], deployment_plan: dict | None = None) -> list[dict]:
    traffic_plan = _project_traffic_plan(project, deployment_plan)
    roles = _traffic_service_roles(traffic_plan)
    routes = traffic_plan.get("traffic_routes") or traffic_plan.get("routes") or []
    default_service = str(traffic_plan.get("default_service") or traffic_plan.get("entry_service") or "")
    if not default_service:
        default_service = next((name for name, (role, _) in roles.items() if role == "frontend" and name in service_targets), "")
    if not default_service:
        default_service = next(iter(service_targets), "")
    paths_by_service: dict[str, list[dict]] = {}
    for route in routes:
        if not isinstance(route, dict):
            continue
        service = str(route.get("service") or route.get("target_service") or "")
        path = str(route.get("path") or "/")
        if service in service_targets and path.startswith("/"):
            paths_by_service.setdefault(service, []).append({
                "path": path,
                "strip_prefix": bool(route.get("strip_prefix", False)),
            })
    if default_service in service_targets:
        paths_by_service.setdefault(default_service, []).append({"path": "/", "strip_prefix": False})
    groups = []
    for service, paths in paths_by_service.items():
        unique_paths = list({(row["path"], row["strip_prefix"]): row for row in paths}.values())
        groups.append({
            "name": service,
            "paths": unique_paths,
            "targets": service_targets[service],
            "strategy": project.load_balance_strategy,
        })
    return groups


def prepare_compose_image_override(
    work: str, build_file: str, project: Project, release: str, platform: str, node: Node,
    db=None, primary_host_port: int | None = None, deployment_plan: dict | None = None,
    deployment_id: str | None = None,
) -> tuple[str | None, list[str]]:
    # Runtime names belong to the platform namespace, not to a local variable
    # created later by execute().  Resolve it inside this helper because the
    # helper is also used during Compose preparation before execute() assigns
    # its release/runtime variables.
    runtime_policy = db.get(DeploymentSettings, "default") if db is not None else None
    runtime_namespace = (runtime_policy.registry_namespace if runtime_policy else "yunzhou") or "yunzhou"
    path = Path(work) / build_file
    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8", errors="ignore")) or {}
    except Exception as exc:
        raise RuntimeError(f"Compose 文件无法解析：{exc}")
    services = {}
    volumes = {}
    images = []
    build_groups: dict[str, str] = {}
    compose_changed = False
    root = Path(work)
    traffic_plan = _project_traffic_plan(project, deployment_plan)
    source_compose_authoritative = bool(document.get("x-yunzhou-source-compose"))
    if source_compose_authoritative:
        actual_services = document.get("services") or {}
        marked_entry = str(document.get("x-yunzhou-entry-service") or "").strip()
        if marked_entry not in actual_services:
            marked_entry = next(
                (name for name in actual_services if str(name).lower() in {"nginx", "gateway", "proxy"}),
                "",
            )
        if not marked_entry and actual_services:
            marked_entry = max(
                actual_services,
                key=lambda name: (
                    int(any(token in str(name).lower() for token in ("web", "front", "ui"))),
                    int("nginx" in yaml.safe_dump(actual_services[name], allow_unicode=True).lower()),
                    -int(any(token in str(name).lower() for token in ("mysql", "postgres", "mongo", "redis", "minio", "rustfs", "init"))),
                ),
            )
        # Only the source gateway is published.  Every other service keeps its
        # original Compose DNS name and remains reachable on the project
        # network, so init jobs and multi-backend applications cannot be
        # mistaken for separate public entry points by stale AI metadata.
        traffic_plan = {
            "service_roles": [
                {"service": name, "role": "app" if name == marked_entry else "internal", "scalable": name == marked_entry}
                for name in actual_services
            ],
            "default_service": marked_entry,
            "traffic_routes": [{"path": "/", "service": marked_entry, "strip_prefix": False}] if marked_entry else [],
        }
        if isinstance(deployment_plan, dict):
            deployment_plan["traffic_plan"] = traffic_plan
    service_roles = _traffic_service_roles(traffic_plan)
    routed_services = {
        str(route.get("service") or route.get("target_service") or "").strip()
        for route in (traffic_plan.get("traffic_routes") or traffic_plan.get("routes") or [])
        if isinstance(route, dict)
    }
    routed_services.discard("")
    for service_name, (role, scalable) in service_roles.items():
        if scalable and role in {"frontend", "backend", "app", "web", "api"}:
            routed_services.add(service_name)
    default_service = str(traffic_plan.get("default_service") or traffic_plan.get("entry_service") or "").strip()
    if default_service:
        routed_services.add(default_service)
    reserved_ports = {int(primary_host_port)} if primary_host_port else set()
    # A common Java + Vue layout can be compiled in short-lived toolchain
    # containers with host-mounted package caches.  The release images then
    # receive only dist/JAR artifacts, so deleting an application image does
    # not discard Maven or pnpm downloads and the Docker context stays small.
    mounted_wms_build = (
        (root / "WMSCloud_ui/package.json").is_file()
        and (root / "WMSCloud/pom.xml").is_file()
        and (root / "WMSCloud_ui/containers/nginx.conf").is_file()
    )
    domain_config = db.get(ProjectDomainConfig, project.id) if db is not None else None
    gateway_has_https = bool(domain_config and domain_config.https_enabled)
    django_ssl_redirect_default = False
    if not gateway_has_https:
        for settings_file in root.rglob("*.py"):
            if any(part in {".git", ".venv", "venv", "node_modules"} for part in settings_file.relative_to(root).parts):
                continue
            settings_text = settings_file.read_text(encoding="utf-8", errors="ignore")[:300_000]
            if re.search(
                r"SECURE_SSL_REDIRECT\s*=\s*os\.environ\.get\([^)]*[\"'](?:true|1|yes)[\"']",
                settings_text,
                re.I,
            ):
                django_ssl_redirect_default = True
                break
    if mounted_wms_build:
        java_log_dirs = detect_java_log_directories(root / "WMSCloud")
        java_log_setup = ""
        if java_log_dirs:
            quoted_dirs = " ".join(shlex.quote(value) for value in java_log_dirs)
            java_log_setup = f"RUN mkdir -p {quoted_dirs} && chmod 0777 {quoted_dirs}\n"
        (root / "WMSCloud_ui/.yunzhou.runtime.Dockerfile").write_text(
            enforce_nginx_pid_compatibility(
                f"FROM {PLATFORM_NGINX_IMAGE}\n"
                "COPY containers/nginx.conf /etc/nginx/nginx.conf\n"
                "COPY dist/ /etc/nginx/html/\n"
                "EXPOSE 80\n"
            ),
            encoding="utf-8",
        )
        (root / "WMSCloud_ui/.dockerignore").write_text(
            "*\n!dist\n!dist/**\n!containers\n!containers/nginx.conf\n!.yunzhou.runtime.Dockerfile\n",
            encoding="utf-8",
        )
        (root / "WMSCloud/ruoyi-admin/.yunzhou.runtime.Dockerfile").write_text(
            "FROM eclipse-temurin:8-jre\n"
            + java_log_setup
            + "WORKDIR /app\n"
            "COPY target/ruoyi-admin.jar /app/app.jar\n"
            "EXPOSE 8080\n"
            "ENTRYPOINT [\"java\", \"-jar\", \"/app/app.jar\"]\n",
            encoding="utf-8",
        )
        (root / "WMSCloud/ruoyi-admin/.dockerignore").write_text(
            "*\n!target\n!target/ruoyi-admin.jar\n!.yunzhou.runtime.Dockerfile\n",
            encoding="utf-8",
        )

    def publish_routed_port(service_name: str, port_probe: dict) -> None:
        if service_name not in routed_services or (port_probe.get("ports") or []):
            return
        container_target = _compose_service_container_port(root, port_probe)
        if not container_target:
            raise RuntimeError(f"无法确认入口服务 {service_name} 的容器端口；请在 Compose 中声明 expose 或在镜像 Dockerfile 中声明 EXPOSE")
        if db is None:
            raise RuntimeError(f"入口服务 {service_name} 缺少宿主端口，平台无法在无数据库上下文时安全分配")
        published = choose_node_port(
            db, node, None, reserved=reserved_ports,
            exclude_deployment_id=deployment_id,
        )
        reserved_ports.add(published)
        services[service_name]["ports"] = [f"{published}:{container_target}"]
        if not deployment_id:
            return
        reservation = db.scalar(select(DeploymentPortReservation).where(
            DeploymentPortReservation.node_id == node.id,
            DeploymentPortReservation.host_port == published,
        ))
        if reservation:
            reservation.deployment_id = deployment_id
            reservation.service_name = str(service_name)
            reservation.status = "reserved"
            reservation.created_at = datetime.now(timezone.utc)
        else:
            db.add(DeploymentPortReservation(
                deployment_id=deployment_id,
                node_id=node.id,
                service_name=str(service_name),
                host_port=published,
                status="reserved",
            ))
        db.commit()

    user_runtime_values = environment_values(decrypt(project.env_text_encrypted) or "")
    for service_name, service in (document.get("services") or {}).items():
        if not isinstance(service, dict):
            continue
        # The PID path is owned by the final nginx.conf layer above.  Remove
        # stale AI-generated command-line directives so nginx never sees two
        # competing ``pid`` directives.
        service_command = service.get("command")
        if isinstance(service_command, str):
            service["command"] = re.sub(
                r"(?i)pid\s+[^;]+;\s*", "", service_command
            )
        elif isinstance(service_command, list):
            service["command"] = [
                re.sub(r"(?i)pid\s+[^;]+;\s*", "", str(value))
                for value in service_command
            ]
        # Runtime time is a platform invariant. Apply it to application and
        # dependency containers alike, while Compose's map merge keeps an
        # explicit project-level TZ value authoritative. Mounting the host's
        # zone file also fixes minimal images (for example nginx/alpine) that
        # do not ship the IANA tzdata database.
        managed_environment = {"TZ": "Asia/Shanghai"}
        managed_environment.update(application_environment(
            user_runtime_values,
            service_name=str(service_name),
            service=service,
            routed_services=routed_services,
        ))
        if django_ssl_redirect_default and (service_name in routed_services or service.get("build")):
            # The application must not redirect an HTTP-only platform route to
            # an unconfigured port 443. Once HTTPS is enabled for the project,
            # the gateway supplies X-Forwarded-Proto and this override is not
            # needed.
            managed_environment["SECURE_SSL_REDIRECT"] = "False"
        services[service_name] = {
            "environment": managed_environment,
            "volumes": ["/etc/localtime:/etc/localtime:ro"],
            # Include the release in the physical name so a candidate version
            # can run beside the online version until gateway verification.
            "container_name": _service_container_name(project.slug, service_name, 1, release, runtime_namespace),
        }
        if not service.get("build"):
            publish_routed_port(service_name, service)
            continue
        original_build = service.get("build")
        # Compose files generated for monorepos often point several runtime
        # services at the exact same build and image. Building each service
        # separately makes BuildKit export the same large dependency layer N
        # times. Keep one build owner and let the remaining services reuse its
        # immutable release image.
        group_key = json.dumps(
            {"build": original_build, "image": service.get("image")},
            ensure_ascii=False,
            sort_keys=True,
            default=str,
        )
        if group_key in build_groups:
            services[service_name].update({"image": build_groups[group_key], "build": None})
            publish_routed_port(service_name, service)
            continue
        safe_service = re.sub(r"[^a-z0-9_.-]+", "-", str(service_name).lower()).strip("-.") or "app"
        image = f"yunzhou/{project.slug}-{safe_service}:{release}"
        build_groups[group_key] = image
        build_override = dict(original_build) if isinstance(original_build, dict) else {"context": str(original_build or ".")}
        # Classic Docker build cache is daemon-wide and already shared by all
        # projects. Do not create project-local Buildx cache directories.
        build_override.pop("cache_from", None)
        build_override.pop("cache_to", None)
        if mounted_wms_build:
            target = str(build_override.get("target") or "").lower()
            if "web" in target or any(token in str(service_name).lower() for token in ("web", "front", "ui")):
                build_override = {
                    "context": "./WMSCloud_ui", "dockerfile": ".yunzhou.runtime.Dockerfile",
                    "dockerfile_inline": None, "target": None,
                }
            elif any(token in target for token in ("backend", "api")) or "api" in str(service_name).lower():
                build_override = {
                    "context": "./WMSCloud/ruoyi-admin", "dockerfile": ".yunzhou.runtime.Dockerfile",
                    "dockerfile_inline": None, "target": None,
                }
                # Keep the application contract stable inside the Compose
                # network. The host/gateway port remains dynamically assigned;
                # Spring always listens on 8080 inside its own container.
                services[service_name]["environment"]["SERVER_PORT"] = "8080"
            # Compose merges nested build objects. An override cannot reliably
            # remove an old ``target``/``dockerfile_inline`` inherited from the
            # source Compose file, so write the clean runtime build definition
            # into the staged copy as well. This copy is release-local and does
            # not modify the user's repository.
            if build_override.get("context") in {"./WMSCloud_ui", "./WMSCloud/ruoyi-admin"}:
                clean_build = {
                    "context": build_override["context"],
                    "dockerfile": build_override["dockerfile"],
                }
                service["build"] = clean_build
                build_override = clean_build
                compose_changed = True
        services[service_name].update({"image": image, "build": build_override})
        port_probe = copy.deepcopy(service)
        port_probe["build"] = build_override
        publish_routed_port(service_name, port_probe)
        images.append(image)
    if not services:
        return None, []
    if compose_changed:
        path.write_text(yaml.safe_dump(document, allow_unicode=True, sort_keys=False), encoding="utf-8")
    # A release-specific Compose project must not create new empty database,
    # Redis or upload volumes. Repository-declared named volumes therefore get
    # stable project-level Docker names. Explicit external volumes retain the
    # source-provided name because the platform does not own them.
    for volume_name, volume_config in (document.get("volumes") or {}).items():
        config = volume_config if isinstance(volume_config, dict) else {}
        if config.get("external"):
            if config.get("name"):
                volumes[volume_name] = {"external": True, "name": config["name"]}
            continue
        safe_volume = re.sub(r"[^a-z0-9_.-]", "-", str(volume_name).lower()).strip("-.") or "data"
        safe_namespace = re.sub(r"[^a-z0-9-]", "-", str(runtime_namespace).lower()).strip("-") or "yunzhou"
        volumes[volume_name] = {
            "external": True,
            "name": f"{safe_namespace}-{project.slug}-{safe_volume.replace('_', '-')}",
        }
    override_name = ".yunzhou.images.yml"
    override_document = {"services": services}
    if volumes:
        override_document["volumes"] = volumes
    (Path(work) / override_name).write_text(
        yaml.safe_dump(override_document, allow_unicode=True, sort_keys=False), encoding="utf-8"
    )
    return override_name, images

