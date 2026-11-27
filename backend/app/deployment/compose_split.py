"""Split application and persistent data Compose runtimes safely."""

import copy
import re
from pathlib import Path

import yaml

from ..models import Project


def split_compose_runtime(
    work: str, compose_file: str, project: Project, runtime_namespace: str,
    compose_override: str | None = None,
) -> dict | None:
    """Split stateful dependencies from release-scoped application services.

    Users keep one source Compose file.  The platform materializes a stable
    project data stack and a release-specific application stack at runtime so
    MySQL/Redis are not recreated for every application version.
    """
    source = Path(work) / compose_file
    document = yaml.safe_load(source.read_text(encoding="utf-8", errors="ignore")) or {}
    services = document.get("services") if isinstance(document, dict) else None
    if not isinstance(services, dict) or not services:
        return None

    image_prefixes = ("mysql", "mariadb", "postgres", "postgresql", "redis", "mongo", "mongodb", "minio")
    stateful_names = {"mysql", "mariadb", "postgres", "postgresql", "redis", "mongo", "mongodb", "minio", "db", "database", "cache"}
    data_targets = (
        "/var/lib/mysql", "/var/lib/postgresql", "/var/lib/mongodb",
        "/data", "/bitnami", "/var/lib/redis",
    )

    def is_stateful(name: str, service: dict) -> bool:
        image = str(service.get("image") or "").lower().split("/")[-1]
        if any(image == prefix or image.startswith(prefix + ":") for prefix in image_prefixes):
            return True
        if str(name).lower() in stateful_names and not service.get("build"):
            return True
        for mount in service.get("volumes") or []:
            target = mount.get("target") if isinstance(mount, dict) else (str(mount).split(":")[1] if ":" in str(mount) else "")
            if any(str(target).rstrip("/") == value for value in data_targets):
                return True
        return False

    data_names = {name for name, service in services.items() if isinstance(service, dict) and is_stateful(name, service)}
    app_names = set(services) - data_names
    if not data_names or not app_names:
        return None

    safe_namespace = re.sub(r"[^a-z0-9-]", "-", str(runtime_namespace).lower()).strip("-") or "yunzhou"
    data_project = f"{safe_namespace}-{project.slug}-data"
    data_network_name = data_project
    network_key = "yunzhou_project_data"
    app_egress_key = "yunzhou_project_app"
    source_volumes = document.get("volumes") if isinstance(document.get("volumes"), dict) else {}
    used_data_volumes: set[str] = set()
    data_services: dict = {}
    requested_data_aliases: dict[str, set[str]] = {"redis": set(), "mysql": set(), "postgres": set()}
    for app_name in app_names:
        app_service = services.get(app_name) if isinstance(services.get(app_name), dict) else {}
        environment = app_service.get("environment") or {}
        if isinstance(environment, list):
            environment = dict(str(item).split("=", 1) for item in environment if "=" in str(item))
        if not isinstance(environment, dict):
            continue
        for env_key, env_value in environment.items():
            upper_key = str(env_key).upper()
            family = "redis" if "REDIS" in upper_key else ("postgres" if "POSTGRES" in upper_key else ("mysql" if "MYSQL" in upper_key else ""))
            if not family or not any(token in upper_key for token in ("HOST", "ADDR", "ADDRESS")):
                continue
            host = str(env_value or "").strip()
            fallback = re.fullmatch(r"\$\{[^}:]+:-([^}]+)\}", host)
            if fallback:
                host = fallback.group(1).strip()
            if re.fullmatch(r"[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?", host) and host.lower() not in {"localhost", "127.0.0.1"}:
                requested_data_aliases[family].add(host)
    for name in data_names:
        service = copy.deepcopy(services[name])
        service.pop("ports", None)
        image_name = str(service.get("image") or "").lower().split("/")[-1]
        family = "redis" if image_name.startswith("redis:") or str(name).lower() in {"redis", "cache"} else ("postgres" if image_name.startswith(("postgres:", "postgresql:")) or str(name).lower() in {"postgres", "postgresql"} else ("mysql" if image_name.startswith(("mysql:", "mariadb:")) or str(name).lower() in {"mysql", "mariadb", "db", "database"} else ""))
        aliases = [name] + sorted(requested_data_aliases.get(family) or set())
        service["networks"] = {network_key: {"aliases": list(dict.fromkeys(aliases))}}
        for mount in service.get("volumes") or []:
            volume_name = mount.get("source") if isinstance(mount, dict) else str(mount).split(":", 1)[0]
            if volume_name and not str(volume_name).startswith(('.', '/')):
                used_data_volumes.add(str(volume_name))
        depends = service.get("depends_on")
        if isinstance(depends, dict):
            service["depends_on"] = {key: value for key, value in depends.items() if key in data_names}
        elif isinstance(depends, list):
            service["depends_on"] = [key for key in depends if key in data_names]
        data_services[name] = service

    data_volumes = {}
    for volume_name in used_data_volumes:
        config = copy.deepcopy(source_volumes.get(volume_name) or {})
        if not config.get("external"):
            safe_volume = re.sub(r"[^a-z0-9_.-]", "-", volume_name.lower()).strip("-.") or "data"
            config["name"] = f"{safe_namespace}-{project.slug}-{safe_volume.replace('_', '-')}"
        data_volumes[volume_name] = config

    app_services: dict = {}
    for name in app_names:
        service = copy.deepcopy(services[name])
        depends = service.get("depends_on")
        if isinstance(depends, dict):
            service["depends_on"] = {key: value for key, value in depends.items() if key not in data_names}
        elif isinstance(depends, list):
            service["depends_on"] = [key for key in depends if key not in data_names]
        networks = service.get("networks") or {}
        if isinstance(networks, list):
            networks = {key: None for key in networks}
        elif not isinstance(networks, dict):
            networks = {}
        networks[network_key] = None
        # Keep stateful services isolated while giving application containers a
        # normal release-scoped route for explicitly configured external APIs
        # and databases.
        networks[app_egress_key] = None
        service["networks"] = networks
        app_services[name] = service

    # A source Nginx configuration may reference a compact/legacy upstream
    # hostname (for example ``wmsapi``) while the Compose service is named
    # ``wms-api`` or ``backend``.  apply_safe_build_repairs adds the unique
    # network alias before this split.  Preserve startup ordering here as well:
    # without it Nginx can start before Docker has attached the target service
    # to the network, fail DNS resolution and enter a needless restart loop.
    alias_targets: dict[str, set[str]] = {}
    for target_name, target_service in app_services.items():
        target_networks = target_service.get("networks") or {}
        if not isinstance(target_networks, dict):
            continue
        for network_config in target_networks.values():
            if not isinstance(network_config, dict):
                continue
            for alias in network_config.get("aliases") or []:
                normalized_alias = re.sub(r"[^a-z0-9]", "", str(alias).lower())
                if normalized_alias:
                    alias_targets.setdefault(normalized_alias, set()).add(target_name)

    nginx_upstream_pattern = re.compile(
        r"(?im)\b(?:proxy_pass\s+https?://|server\s+)"
        r"([a-z][a-z0-9_-]*)(?::(\d+))?"
    )

    def service_target_ports(service: dict) -> set[int]:
        """Return container-side ports declared by one Compose service."""
        result: set[int] = set()
        for exposed in service.get("expose") or []:
            match = re.match(r"(\d+)", str(exposed))
            if match:
                result.add(int(match.group(1)))
        for mapping in service.get("ports") or []:
            if isinstance(mapping, dict):
                target = mapping.get("target")
                if str(target or "").isdigit():
                    result.add(int(target))
                continue
            value = str(mapping).split("/", 1)[0]
            target = value.rsplit(":", 1)[-1]
            if target.isdigit():
                result.add(int(target))
        return result
    source_root = Path(work)
    nginx_files: list[Path] = []
    for pattern in ("**/nginx.conf", "**/*.nginx.conf", "**/conf.d/*.conf"):
        nginx_files.extend(source_root.glob(pattern))
    for config_file in dict.fromkeys(nginx_files):
        try:
            config_text = config_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        upstream_refs = {(host, int(port) if port else None) for host, port in nginx_upstream_pattern.findall(config_text)}
        if not upstream_refs:
            continue

        # Prefer the service whose build context contains the Nginx file.  If
        # source layout is unusual, use a unique Nginx/frontend/web service.
        gateway_candidates: list[str] = []
        for candidate_name, candidate_service in app_services.items():
            build = candidate_service.get("build")
            context = build.get("context") if isinstance(build, dict) else build
            context_path = (source_root / str(context or ".")).resolve()
            try:
                if config_file.resolve().is_relative_to(context_path):
                    gateway_candidates.append(candidate_name)
            except (OSError, ValueError):
                continue
        if len(gateway_candidates) != 1:
            named_candidates = [
                name for name, service in app_services.items()
                if any(token in f"{name} {service.get('image', '')}".lower()
                       for token in ("nginx", "frontend", "front-end", "web", "ui"))
            ]
            gateway_candidates = named_candidates if len(named_candidates) == 1 else []
        if len(gateway_candidates) != 1:
            continue

        gateway_name = gateway_candidates[0]
        gateway = app_services[gateway_name]
        dependencies: set[str] = set()
        for host, upstream_port in upstream_refs:
            normalized_host = re.sub(r"[^a-z0-9]", "", host.lower())
            matches = set(alias_targets.get(normalized_host) or set())
            matches.update(
                name for name in app_services
                if re.sub(r"[^a-z0-9]", "", str(name).lower()) == normalized_host
            )
            matches.discard(gateway_name)
            # Names frequently change during platform normalization. Resolve
            # an otherwise unknown upstream from objective runtime evidence:
            # its container port and the set of non-gateway services. This is
            # safe only when the result is unique; multi-backend ambiguity is
            # deliberately left unresolved for preflight to report.
            if not matches and upstream_port:
                matches = {
                    name for name, service in app_services.items()
                    if name != gateway_name and upstream_port in service_target_ports(service)
                }
            if not matches:
                non_gateway = set(app_services) - {gateway_name}
                if len(non_gateway) == 1:
                    matches = non_gateway
            if len(matches) == 1:
                target_name = next(iter(matches))
                dependencies.add(target_name)
                target = app_services[target_name]
                target_networks = target.get("networks") or {}
                if isinstance(target_networks, list):
                    target_networks = {name: {} for name in target_networks}
                if not isinstance(target_networks, dict):
                    target_networks = {}
                shared = target_networks.get(network_key)
                if not isinstance(shared, dict):
                    shared = {}
                aliases = list(shared.get("aliases") or [])
                if host not in aliases:
                    aliases.append(host)
                shared["aliases"] = aliases
                target_networks[network_key] = shared
                target["networks"] = target_networks
                alias_targets.setdefault(normalized_host, set()).add(target_name)
        if not dependencies:
            continue
        depends = gateway.get("depends_on")
        if isinstance(depends, dict):
            for dependency in dependencies:
                depends.setdefault(dependency, {"condition": "service_started"})
        else:
            depends_list = list(depends or []) if isinstance(depends, list) else []
            depends_list.extend(sorted(dependencies - set(depends_list)))
            gateway["depends_on"] = depends_list

    common = {key: copy.deepcopy(document[key]) for key in ("configs", "secrets") if key in document}
    data_document = {
        **common,
        "services": data_services,
        "volumes": data_volumes,
        # Do not mark the shared data network as ``internal``. Application
        # containers also join this network and Docker may select it as their
        # default route. An internal network then silently removes the default
        # gateway, so a host-side database probe succeeds while the actual
        # application container cannot reach an external MySQL/PostgreSQL.
        # Data services remain private because no host ports are published.
        "networks": {network_key: {"name": data_network_name}},
    }
    app_networks = copy.deepcopy(document.get("networks") or {})
    app_networks[network_key] = {"external": True, "name": data_network_name}
    app_networks[app_egress_key] = {}
    app_document = {
        **common,
        "services": app_services,
        "networks": app_networks,
    }
    # Source Compose files occasionally contain an application dependency in
    # one direction while the platform adds the reverse edge for an Nginx
    # upstream alias. Docker Compose rejects that otherwise valid topology as
    # a dependency cycle. Dependencies are startup hints (service discovery is
    # provided by the network), so remove only edges that close a cycle and
    # keep all remaining source ordering intact.
    def break_dependency_cycles(services: dict) -> None:
        def dependency_names(service: dict) -> list[str]:
            depends = service.get("depends_on")
            if isinstance(depends, dict):
                return [str(name) for name in depends if name in services]
            if isinstance(depends, list):
                return [str(name) for name in depends if name in services]
            return []

        while True:
            visiting: list[str] = []
            visited: set[str] = set()
            cycle_edge: tuple[str, str] | None = None

            def visit(name: str) -> bool:
                nonlocal cycle_edge
                if name in visiting:
                    return True
                if name in visited:
                    return False
                visiting.append(name)
                for dependency in dependency_names(services[name]):
                    if dependency in visiting:
                        cycle_edge = (name, dependency)
                        return True
                    if visit(dependency):
                        return True
                visiting.pop()
                visited.add(name)
                return False

            if not any(visit(name) for name in services if name not in visited):
                return
            if not cycle_edge:
                return
            source, target = cycle_edge
            depends = services[source].get("depends_on")
            if isinstance(depends, dict):
                depends.pop(target, None)
                if not depends:
                    services[source].pop("depends_on", None)
            elif isinstance(depends, list):
                remaining = [name for name in depends if str(name) != target]
                if remaining:
                    services[source]["depends_on"] = remaining
                else:
                    services[source].pop("depends_on", None)

    break_dependency_cycles(app_services)
    # Keep application-owned volumes (uploads, generated files, etc.) while
    # excluding database volumes, which belong solely to the data stack.
    app_volume_names = set()
    for service in app_services.values():
        for mount in service.get("volumes") or []:
            volume_name = mount.get("source") if isinstance(mount, dict) else str(mount).split(":", 1)[0]
            if volume_name in source_volumes and volume_name not in used_data_volumes:
                app_volume_names.add(volume_name)
    if app_volume_names:
        app_document["volumes"] = {name: copy.deepcopy(source_volumes[name]) for name in app_volume_names}

    # The general runtime override contains an entry for every original
    # service (timezone, container name, image, ports). Merging it with the
    # app-only file would recreate empty MySQL/Redis service stubs. Materialize
    # an app-only override so the two stacks stay genuinely isolated.
    app_override_file = None
    if compose_override:
        override_path = Path(work) / compose_override
        override_document = yaml.safe_load(override_path.read_text(encoding="utf-8", errors="ignore")) or {}
        override_services = override_document.get("services") if isinstance(override_document, dict) else {}
        filtered_services = {
            name: copy.deepcopy(config)
            for name, config in (override_services or {}).items()
            if name in app_names
        }
        # Runtime Compose is image-only. The build server already produced
        # immutable release images; never upload a `build:` instruction to a
        # target node where it could accidentally compile source again.
        for name, config in filtered_services.items():
            if isinstance(config, dict):
                image = str(config.get("image") or "").strip()
                config.pop("build", None)
                if image and name in app_services:
                    app_services[name]["image"] = image
                    app_services[name].pop("build", None)
        filtered_override = {"services": filtered_services}
        override_volumes = override_document.get("volumes") if isinstance(override_document, dict) else {}
        filtered_volumes = {
            name: copy.deepcopy(config)
            for name, config in (override_volumes or {}).items()
            if name in app_volume_names
        }
        if filtered_volumes:
            filtered_override["volumes"] = filtered_volumes
        remaining_builds = [name for name, config in app_services.items() if isinstance(config, dict) and config.get("build")]
        if remaining_builds:
            raise RuntimeError(
                "平台未能为以下服务生成固定运行镜像：" + "、".join(remaining_builds)
            )
        app_override_file = ".yunzhou.app-images.yml"
        (Path(work) / app_override_file).write_text(
            yaml.safe_dump(filtered_override, allow_unicode=True, sort_keys=False),
            encoding="utf-8",
        )

    data_file = ".yunzhou.data.yml"
    app_file = ".yunzhou.app.yml"
    (Path(work) / data_file).write_text(yaml.safe_dump(data_document, allow_unicode=True, sort_keys=False), encoding="utf-8")
    (Path(work) / app_file).write_text(yaml.safe_dump(app_document, allow_unicode=True, sort_keys=False), encoding="utf-8")
    return {
        "data_file": data_file,
        "app_file": app_file,
        "app_override_file": app_override_file,
        "data_project": data_project,
        "data_network": data_network_name,
        "data_services": sorted(data_names),
        "app_services": sorted(app_names),
        "data_volumes": sorted(data_volumes),
        "volume_names": sorted(str(config.get("name")) for config in data_volumes.values() if config.get("name")),
    }

