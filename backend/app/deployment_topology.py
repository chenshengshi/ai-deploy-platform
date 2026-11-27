import re
from pathlib import Path


def repair_generated_node_dependency_copy(context: Path, dockerfile: Path) -> bool:
    """Replace an impossible generated node_modules COPY with an image install."""
    if not dockerfile.is_file() or not dockerfile.name.startswith(".yunzhou"):
        return False
    text = dockerfile.read_text(encoding="utf-8", errors="replace")
    copy_pattern = re.compile(
        r"(?im)^\s*COPY(?:\s+--\S+)*\s+[\"']?\.?/?node_modules/?[\"']?\s+"
        r"[\"']?\.?/?node_modules/?[\"']?\s*$"
    )
    if not copy_pattern.search(text):
        return False
    if (context / "pnpm-lock.yaml").is_file():
        install = "RUN corepack enable && pnpm install --prod --frozen-lockfile"
    elif (context / "yarn.lock").is_file() and not (context / "package-lock.json").is_file():
        install = "RUN yarn install --production --frozen-lockfile --network-timeout 600000"
    else:
        install = "RUN npm install --omit=dev --no-audit --no-fund"
    dockerfile.write_text(copy_pattern.sub(install, text), encoding="utf-8")
    return True


def add_unambiguous_nginx_aliases(services: dict, upstream_hosts: set[str]) -> list[tuple[str, str]]:
    """Attach legacy Nginx hostnames to an objectively unique app service."""
    normalized: dict[str, list[str]] = {}
    for service_name in services:
        normalized.setdefault(re.sub(r"[^a-z0-9]", "", service_name.lower()), []).append(service_name)
    gateway_names = {
        name for name, service in services.items()
        if isinstance(service, dict)
        and any(token in f"{name} {service.get('image', '')}".lower()
                for token in ("nginx", "frontend", "front-end", "web", "ui"))
    }
    application_names = {
        name for name, service in services.items()
        if isinstance(service, dict) and name not in gateway_names
        and not any(token in f"{name} {service.get('image', '')}".lower()
                    for token in ("mysql", "mariadb", "postgres", "redis", "mongo", "rabbitmq"))
    }
    changed: list[tuple[str, str]] = []
    for host in sorted(upstream_hosts):
        matches = normalized.get(re.sub(r"[^a-z0-9]", "", host.lower()), [])
        if not matches and len(application_names) == 1:
            matches = list(application_names)
        if len(matches) != 1 or matches[0] == host:
            continue
        target_name = matches[0]
        target = services.get(target_name)
        networks = target.get("networks") if isinstance(target, dict) else None
        if networks is None:
            networks = {"default": {}}
        elif isinstance(networks, list):
            networks = {name: {} for name in networks}
        elif not isinstance(networks, dict):
            networks = {"default": {}}
        default_network = networks.get("default")
        if not isinstance(default_network, dict):
            default_network = {}
        aliases = list(default_network.get("aliases") or [])
        if host not in aliases:
            aliases.append(host)
            changed.append((host, target_name))
        default_network["aliases"] = aliases
        networks["default"] = default_network
        target["networks"] = networks
    return changed
