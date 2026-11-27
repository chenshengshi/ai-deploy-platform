"""Platform gateway allocation, routing, snapshots and rollback."""

import base64
import copy
import ipaddress
import json
import re
import shlex
from datetime import datetime, timezone
from urllib.parse import urlsplit

import httpx
from sqlalchemy import select, text

from ..config import decrypt
from ..models import DeployStatus, Deployment, DeploymentPortReservation, DeploymentSettings, Node, Project, ProjectDomainConfig
from ..ssh import SSHNode
from ..source_inspection import _public_path_from_value

def platform_gateway_node(db) -> Node | None:
    for candidate in db.scalars(select(Node).where(Node.enabled.is_(True))).all():
        address = (candidate.public_address or "").strip()
        try:
            if address and not ipaddress.ip_address(address).is_private:
                return candidate
        except ValueError:
            if address:
                return candidate
    return None


def reconcile_runtime_frontend_routes(route_groups: list[dict] | None) -> tuple[list[dict] | None, str | None]:
    """Reconcile planned routes with the frontend that was actually built.

    Source trees often contain several environment files while the final image
    contains only one effective ``baseURL``/runtime config.  The built artifact
    is therefore the strongest evidence.  This also catches projects whose
    production prefix is `/frapi` although an older Nginx sample still mentions
    `/prod-api`.
    """
    if not route_groups:
        return route_groups, None
    frontend = next((group for group in route_groups if any(
        str(path.get("path") if isinstance(path, dict) else path) == "/"
        for path in (group.get("paths") or [])
    )), None)
    backend = next((group for group in route_groups if group is not frontend and group.get("targets")), None)
    if not frontend or not backend or not frontend.get("targets"):
        return route_groups, None

    host, port = frontend["targets"][0]
    origin = f"http://{host}:{port}"
    candidates: dict[str, tuple[int, str]] = {}
    artifact_texts: list[str] = []

    def add(raw: str, score: int, source: str) -> None:
        path = _public_path_from_value(raw)
        if not path:
            return
        current = candidates.get(path)
        if current is None or score > current[0]:
            candidates[path] = (score, source)

    try:
        with httpx.Client(timeout=6, follow_redirects=True, trust_env=False) as client:
            response = client.get(origin + "/")
            if response.status_code >= 400:
                return route_groups, None
            html = response.text[:1_000_000]
            asset_matches = re.finditer(
                r"<(?:script|link)[^>]+(?:src|href)\s*=\s*(?:[\"']([^\"']+)[\"']|([^\s>]+))",
                html,
                re.I,
            )
            assets = [(match.group(1) or match.group(2) or "").strip() for match in asset_matches]
            # Runtime config is intentionally checked before hashed bundles.
            assets.sort(key=lambda value: (0 if re.search(r"posturl|runtime|config|env", value, re.I) else 1, value))
            for asset in assets[:24]:
                parsed = urlsplit(asset)
                if parsed.scheme and parsed.netloc and parsed.netloc != f"{host}:{port}":
                    continue
                asset_path = parsed.path
                if not asset_path.endswith((".js", ".mjs")):
                    continue
                try:
                    content = client.get(origin + (asset_path if asset_path.startswith("/") else "/" + asset_path)).text[:2_500_000]
                except httpx.HTTPError:
                    continue
                artifact_texts.append(content)
                runtime_score = 150 if re.search(r"posturl|runtime|config|env", asset_path, re.I) else 125
                for match in re.finditer(r"\b(?:const|let|var)\s+(?:IP|API_BASE_URL|BASE_API)\s*=\s*[\"']([^\"']+)[\"']", content):
                    add(match.group(1), runtime_score, asset_path)
                for match in re.finditer(r"\bbaseURL\s*:\s*[\"']([^\"']+)[\"']", content):
                    add(match.group(1), runtime_score - 5, asset_path)
    except httpx.HTTPError:
        return route_groups, None
    if not candidates:
        return route_groups, None

    path, (_, evidence) = max(candidates.items(), key=lambda item: (item[1][0], -len(item[0])))
    public_path = path.rstrip("/") + "/"
    previous_strip = next((
        bool(row.get("strip_prefix", False))
        for row in (backend.get("paths") or [])
        if isinstance(row, dict) and str(row.get("path") or "").rstrip("/") == path.rstrip("/")
    ), None)
    strip_prefix = previous_strip

    # When a cheap, read-only endpoint is visible in the bundle, compare the
    # backend's root route with the public-prefix route. A JSON code=200 response
    # is considerably stronger than status alone (many apps return HTTP 200 for
    # their JSON 401 payloads).
    probe = "/captchaImage" if any("/captchaImage" in text for text in artifact_texts) else None
    if probe:
        backend_host, backend_port = backend["targets"][0]
        backend_origin = f"http://{backend_host}:{backend_port}"

        def probe_score(url: str) -> int:
            try:
                with httpx.Client(timeout=5, follow_redirects=True, trust_env=False) as client:
                    response = client.get(url)
                score = 2 if response.status_code < 400 else 0
                if "json" in response.headers.get("content-type", "").lower():
                    score += 3
                    payload = response.json()
                    if isinstance(payload, dict) and int(payload.get("code", 200) or 200) == 200:
                        score += 5
                    if isinstance(payload, dict) and (payload.get("img") or payload.get("data")):
                        score += 2
                return score
            except (httpx.HTTPError, ValueError, TypeError):
                return 0

        root_score = probe_score(backend_origin + probe)
        prefixed_score = probe_score(backend_origin + path.rstrip("/") + probe)
        if root_score != prefixed_score:
            strip_prefix = root_score > prefixed_score
    if strip_prefix is None:
        # Production aliases conventionally live only at the gateway. Preserve
        # neutral `/api` unless runtime probing or source Nginx proved otherwise.
        strip_prefix = bool(re.fullmatch(r"/(?:prod|stage|staging|dev|fr)-api", path, re.I))

    reconciled = copy.deepcopy(route_groups)
    for group in reconciled:
        if str(group.get("name") or "") == str(backend.get("name") or ""):
            group["paths"] = [{"path": public_path, "strip_prefix": bool(strip_prefix)}]
    return reconciled, f"{public_path} → {backend.get('name')}（{'去掉' if strip_prefix else '保留'}前缀，证据 {evidence}）"


def configure_platform_gateway(
    db, deployment: Deployment, target_node: Node, target_port: int, domain: str | None = None,
    http_port: int = 80, https_enabled: bool = False, https_port: int = 443,
    redirect_https: bool = True, certificate: str | None = None, private_key: str | None = None,
    upstreams: list[tuple[str, int]] | None = None, strategy: str = "round_robin",
    route_groups: list[dict] | None = None,
) -> str:
    # Keep the caller's list object as the published routing contract. Runtime
    # asset inspection may discover a more accurate API prefix (for example
    # /frapi/) than source analysis did; final access verification must probe
    # that reconciled route rather than the stale pre-gateway list.
    caller_route_groups = route_groups
    # Domain settings can be changed while a deployment is finishing. Serialize
    # all gateway writes for the same project across API and worker processes,
    # then refresh the authoritative settings so an older deployment cannot
    # overwrite a newer HTTPS/domain choice.
    db.execute(text("SELECT pg_advisory_xact_lock(hashtext(:key))"), {"key": f"gateway:{deployment.project_id}"})
    db.flush()
    db.expire_all()
    current_project = db.get(Project, deployment.project_id)
    current_domain = db.get(ProjectDomainConfig, deployment.project_id)
    if current_project:
        domain = current_project.domain
    if current_domain:
        http_port = current_domain.http_port
        https_enabled = current_domain.https_enabled
        https_port = current_domain.https_port
        redirect_https = current_domain.redirect_https
        certificate = decrypt(current_domain.certificate_encrypted)
        private_key = decrypt(current_domain.private_key_encrypted)
        if current_domain.gateway_mode == "custom":
            try:
                saved_routes = json.loads(current_domain.custom_routes_json or "[]")
            except Exception:
                saved_routes = []
            automatic = {str(group.get("name") or ""): group for group in (route_groups or [])}
            custom_groups: dict[str, dict] = {}
            routes_migrated = False
            for route in saved_routes:
                service = str(route.get("service") or "")
                source_group = automatic.get(service)
                if not source_group:
                    semantic = service.strip().lower()
                    aliases = {
                        "backend": ("backend", "server", "api", "app"),
                        "api": ("backend", "server", "api", "app"),
                        "server": ("backend", "server", "api", "app"),
                        "frontend": ("frontend", "web", "ui"),
                        "web": ("frontend", "web", "ui"),
                    }
                    tokens = aliases.get(semantic, ())
                    route_path = str(route.get("path") or "/")
                    # Generated service names commonly carry a project prefix
                    # (wms-api, warehouse-backend, admin-web). Infer the saved
                    # route's role from both its old name and public path, then
                    # bind it to the unique current runtime service. This keeps
                    # custom routes stable after delete/recreate and reanalysis.
                    if not tokens:
                        if route_path.rstrip("/"):
                            tokens = ("backend", "server", "api", "app")
                        else:
                            tokens = ("frontend", "web", "ui")
                    candidates = [
                        (name, group) for name, group in automatic.items()
                        if tokens and any(token in name.lower() for token in tokens)
                    ]
                    if len(candidates) != 1:
                        role_candidates = []
                        for name, group in automatic.items():
                            group_paths = group.get("paths") or []
                            owns_root = any(
                                str(path.get("path") if isinstance(path, dict) else path) == "/"
                                for path in group_paths
                            )
                            if (route_path.rstrip("/") and not owns_root) or (not route_path.rstrip("/") and owns_root):
                                role_candidates.append((name, group))
                        if len(role_candidates) == 1:
                            candidates = role_candidates
                    if len(candidates) == 1:
                        service, source_group = candidates[0]
                        route["service"] = service
                        routes_migrated = True
                    else:
                        raise RuntimeError(f"自定义网关路由引用了不存在的运行服务：{service}")
                group = custom_groups.setdefault(service, {
                    "name": service, "targets": source_group.get("targets") or [],
                    "strategy": source_group.get("strategy") or strategy, "paths": [],
                })
                group["paths"].append({"path": route.get("path") or "/", "strip_prefix": bool(route.get("strip_prefix", False))})
            if routes_migrated:
                current_domain.custom_routes_json = json.dumps(saved_routes, ensure_ascii=False)
                # Do not touch Deployment.log_text inside this long-lived
                # gateway transaction.  Progress logging uses an independent
                # session, so changing the same deployment row here would make
                # that logger wait on our own uncommitted row lock.
            if custom_groups:
                route_groups = list(custom_groups.values())
        else:
            route_groups, runtime_evidence = reconcile_runtime_frontend_routes(route_groups)
            if runtime_evidence:
                marker = f"[网关识别] 最终前端产物：{runtime_evidence}\n"
                if marker not in (deployment.log_text or ""):
                    deployment.log_text = ((deployment.log_text or "") + marker)[-200_000:]
    else:
        route_groups, runtime_evidence = reconcile_runtime_frontend_routes(route_groups)
        if runtime_evidence:
            marker = f"[网关识别] 最终前端产物：{runtime_evidence}\n"
            if marker not in (deployment.log_text or ""):
                deployment.log_text = ((deployment.log_text or "") + marker)[-200_000:]
    if caller_route_groups is not None and route_groups is not caller_route_groups:
        caller_route_groups[:] = copy.deepcopy(route_groups or [])
    gateway = platform_gateway_node(db)
    if not gateway:
        return f"http://{target_node.public_address or target_node.host}:{target_port}"
    service_key = f"project-{deployment.project_id}"
    policy = db.get(DeploymentSettings, "default")
    port_start = policy.external_port_start if policy else 20000
    port_end = policy.external_port_end if policy else 21000
    previous_service = db.scalar(
        select(Deployment).where(
            Deployment.project_id == deployment.project_id,
            Deployment.id != deployment.id,
            Deployment.access_url.is_not(None),
        ).order_by(Deployment.created_at.desc())
    )
    previous_match = re.search(r":(\d+)(?:/|$)", previous_service.access_url or "") if previous_service else None
    service_port = int(previous_match.group(1)) if previous_match else None
    used = set()
    for value in db.scalars(select(Deployment.access_url).where(
        Deployment.access_url.is_not(None),
        Deployment.id != deployment.id,
        Deployment.project_id != deployment.project_id,
    )).all():
        match = re.search(r":(\d+)(?:/|$)", value or "")
        if match:
            used.add(int(match.group(1)))
    # Keep a database allocation ledger for the gateway listener as well as
    # inspecting Nginx.  This covers domain-based URLs, where the internal
    # 30000-range listener is intentionally not present in access_url.
    gateway_reservations = db.scalars(select(DeploymentPortReservation).where(
        DeploymentPortReservation.node_id == gateway.id,
        DeploymentPortReservation.service_name == "__gateway__",
        DeploymentPortReservation.status.in_(["reserved", "active"]),
    )).all()
    for reservation in gateway_reservations:
        owner = db.get(Deployment, reservation.deployment_id)
        if owner and owner.project_id == deployment.project_id:
            service_port = service_port or reservation.host_port
        else:
            used.add(reservation.host_port)
    # Ports already used by applications hosted on the gateway cannot also be
    # bound by Nginx. Remote-node internal ports do not conflict here.
    used.update(x for x in db.scalars(select(Deployment.host_port).where(Deployment.node_id == gateway.id, Deployment.status.in_([DeployStatus.queued, DeployStatus.running, DeployStatus.success]))).all() if x)
    current_match = re.search(r":(\d+)(?:/|$)", deployment.access_url or "")
    current_port = int(current_match.group(1)) if current_match else None
    # Domain-based public URLs do not contain the private listener used by the
    # platform gateway.  Treat the generated Nginx files as the authoritative
    # allocation ledger as well, otherwise every domain project appears to be
    # free to reuse the same first port and Nginx silently ignores one server.
    gateway_listener_owners: dict[int, set[str]] = {}
    own_gateway_port: int | None = None
    try:
        with SSHNode(gateway) as allocation_ssh:
            _, listener_text = allocation_ssh.run(
                "grep -H -E '^[[:space:]]*listen[[:space:]]+[0-9]+;' "
                "/data/yunzhou-control/data/gateway/conf.d/project-*.conf 2>/dev/null || true",
                timeout=15,
            )
        for row in listener_text.splitlines():
            match = re.match(r"^([^:]+):\s*listen\s+(\d+);", row.strip())
            if not match:
                continue
            filename, listener = match.group(1), int(match.group(2))
            if port_start <= listener <= port_end:
                gateway_listener_owners.setdefault(listener, set()).add(filename)
                if filename.endswith(f"/{service_key}.conf"):
                    own_gateway_port = listener
        used.update(gateway_listener_owners)
    except Exception:
        # Database reservations still provide a safe fallback when the gateway
        # is temporarily unavailable; the final nginx -t remains authoritative.
        pass
    own_is_unique = bool(
        own_gateway_port
        and len(gateway_listener_owners.get(own_gateway_port, set())) == 1
    )
    fallback_reusable = current_port or service_port
    if fallback_reusable in gateway_listener_owners and not own_is_unique:
        fallback_reusable = None
    reusable_port = own_gateway_port if own_is_unique else fallback_reusable
    gateway_port = reusable_port if reusable_port and port_start <= reusable_port <= port_end and reusable_port != target_port else next((port for port in range(port_start, port_end + 1) if port not in used and port != target_port), None)
    if not gateway_port:
        raise RuntimeError("平台网关没有可用映射端口")
    domain = (domain or "").strip().lower()
    if domain and not re.fullmatch(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", domain):
        raise RuntimeError("域名格式不正确")
    targets = upstreams or [(target_node.host, target_port)]
    targets = list(dict.fromkeys((str(host), int(port)) for host, port in targets if host and port))

    def strategy_directive(value: str) -> str:
        return "    least_conn;\n" if value == "least_conn" else ("    ip_hash;\n" if value == "ip_hash" else "")

    read_timeout = int(current_domain.proxy_read_timeout if current_domain else 300)
    body_size_mb = int(current_domain.client_max_body_mb if current_domain else 50)

    def location_proxy(path: str, proxy_target: str, target_count: int, strip_prefix: bool = False) -> str:
        normalized = "/" + str(path or "/").lstrip("/")
        if normalized != "/" and not normalized.endswith("/"):
            normalized += "/"
        # A trailing slash on proxy_pass strips the matched location prefix.
        suffix = "/" if strip_prefix and normalized != "/" else ""
        return f"""    location {normalized} {{
        proxy_pass {proxy_target}{suffix};
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_connect_timeout 2s;
        proxy_next_upstream error timeout invalid_header http_500 http_502 http_503 http_504;
        proxy_next_upstream_tries {max(2, target_count)};
        proxy_read_timeout {read_timeout}s;
        proxy_send_timeout {read_timeout}s;
    }}"""

    upstream_blocks: list[str] = []
    locations: list[tuple[str, str]] = []
    normalized_groups = route_groups or [{
        "name": "entry", "path": "/", "targets": targets,
        "strategy": strategy, "strip_prefix": False,
    }]
    for index, group in enumerate(normalized_groups):
        group_targets = list(dict.fromkeys(
            (str(host), int(port)) for host, port in (group.get("targets") or []) if host and port
        ))
        if not group_targets:
            continue
        group_key = re.sub(r"[^a-zA-Z0-9_]", "_", str(group.get("name") or f"route_{index}"))
        upstream_name = "yunzhou_" + re.sub(r"[^a-zA-Z0-9_]", "_", deployment.project_id) + "_" + group_key
        proxy_target = f"http://{group_targets[0][0]}:{group_targets[0][1]}"
        if len(group_targets) > 1:
            servers = "\n".join(
                f"    server {host}:{port} max_fails=1 fail_timeout=3s;" for host, port in group_targets
            )
            upstream_blocks.append(
                f"upstream {upstream_name} {{\n{strategy_directive(str(group.get('strategy') or strategy))}{servers}\n}}"
            )
            proxy_target = f"http://{upstream_name}"
        paths = group.get("paths") or [group.get("path") or "/"]
        for route_path in paths:
            if isinstance(route_path, dict):
                path = str(route_path.get("path") or "/")
                strip = bool(route_path.get("strip_prefix", group.get("strip_prefix", False)))
            else:
                path = str(route_path or "/")
                strip = bool(group.get("strip_prefix", False))
            locations.append((path, location_proxy(path, proxy_target, len(group_targets), strip)))
    if not locations:
        raise RuntimeError("平台网关没有可用的路由目标")
    # Nginx uses the longest prefix automatically, but sorting also makes the
    # generated configuration easy to audit and keeps the catch-all last.
    unique_locations: dict[str, str] = {}
    for path, block in locations:
        unique_locations.setdefault(path, block)
    locations = list(unique_locations.items())
    locations.sort(key=lambda item: (item[0] == "/", -len(item[0])))
    upstream_block = ("\n".join(upstream_blocks) + "\n") if upstream_blocks else ""
    proxy_block = "\n".join(block for _, block in locations)
    security_block = """    server_tokens off;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
"""
    security_block += f"    client_max_body_size {body_size_mb}m;\n"
    gateway_config = f"""{upstream_block}server {{
    listen {gateway_port};
    server_name _;
{security_block}
{proxy_block}
}}
"""
    config = ""
    if domain:
        if https_enabled:
            if not certificate or not private_key:
                raise RuntimeError("启用 SSL 时必须上传证书和私钥")
            # Domain HTTPS can be toggled by the user. A permanent 301 is cached by
            # browsers and keeps forcing HTTPS even after the setting is disabled.
            # Use a method-preserving temporary redirect and explicitly forbid cache.
            http_action = (
                f"    add_header Cache-Control \"no-store, no-cache, must-revalidate\" always;\n"
                f"    return 307 https://$host{(':' + str(https_port)) if https_port != 443 else ''}$request_uri;"
                if redirect_https else proxy_block
            )
            config += f"""server {{
    listen {http_port};
    server_name {domain};
{security_block}
{http_action}
}}
server {{
    listen {https_port} ssl;
    server_name {domain};
    ssl_certificate /etc/nginx/certs/{service_key}.crt;
    ssl_certificate_key /etc/nginx/certs/{service_key}.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_timeout 1d;
    ssl_session_cache shared:YunzhouTLS:10m;
    ssl_session_tickets off;
{security_block}
{proxy_block}
}}
"""
        else:
            config += f"""server {{
    listen {http_port};
    server_name {domain};
{security_block}
{proxy_block}
}}
"""
    config += gateway_config
    encoded = base64.b64encode(config.encode()).decode()
    filename = f"/data/yunzhou-control/data/gateway/conf.d/{service_key}.conf"
    legacy_ids = db.scalars(select(Deployment.id).where(
        Deployment.project_id == deployment.project_id,
        Deployment.id != deployment.id,
    )).all()
    legacy_files = [f"/data/yunzhou-control/data/gateway/conf.d/{item_id}.conf" for item_id in legacy_ids]
    with SSHNode(gateway) as ssh:
        cert_commands = ""
        cert_restore = ""
        cert_cleanup = ""
        if https_enabled:
            cert64 = base64.b64encode(certificate.encode()).decode()
            key64 = base64.b64encode(private_key.encode()).decode()
            cert_path = f"/data/yunzhou-control/data/gateway/certs/{service_key}.crt"
            key_path = f"/data/yunzhou-control/data/gateway/certs/{service_key}.key"
            cert_commands = (
                f"cp {cert_path} {cert_path}.bak 2>/dev/null || true; cp {key_path} {key_path}.bak 2>/dev/null || true; "
                f"printf %s {shlex.quote(cert64)} | base64 -d > {cert_path}.tmp; "
                f"printf %s {shlex.quote(key64)} | base64 -d > {key_path}.tmp; chmod 600 {key_path}.tmp; "
                f"openssl x509 -in {cert_path}.tmp -noout >/dev/null && openssl pkey -in {key_path}.tmp -noout >/dev/null && "
                f"test \"$(openssl x509 -in {cert_path}.tmp -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum | cut -d' ' -f1)\" = \"$(openssl pkey -in {key_path}.tmp -pubout -outform DER | sha256sum | cut -d' ' -f1)\" || exit 42; "
                f"mv {cert_path}.tmp {cert_path}; mv {key_path}.tmp {key_path}; "
            )
            cert_restore = (
                f"if test -f {cert_path}.bak; then mv {cert_path}.bak {cert_path}; else rm -f {cert_path}; fi; "
                f"if test -f {key_path}.bak; then mv {key_path}.bak {key_path}; else rm -f {key_path}; fi; "
            )
            cert_cleanup = f"rm -f {cert_path}.bak {key_path}.bak; "
        hide_legacy = " ".join(
            f"[ ! -f {shlex.quote(path)} ] || mv {shlex.quote(path)} {shlex.quote(path + '.service-bak')};"
            for path in legacy_files
        )
        restore_legacy = " ".join(
            f"[ ! -f {shlex.quote(path + '.service-bak')} ] || mv {shlex.quote(path + '.service-bak')} {shlex.quote(path)};"
            for path in legacy_files
        )
        remove_legacy_backups = " ".join(f"rm -f {shlex.quote(path + '.service-bak')};" for path in legacy_files)
        command = (
            "mkdir -p /data/yunzhou-control/data/gateway/conf.d /data/yunzhou-control/data/gateway/certs; " + cert_commands +
            hide_legacy +
            f"cp {shlex.quote(filename)} {shlex.quote(filename)}.bak 2>/dev/null || true; "
            f"printf %s {shlex.quote(encoded)} | base64 -d > {shlex.quote(filename)}; "
            "if docker ps -a --format '{{.Names}}' | grep -qx yunzhou-platform-gateway && "
            "docker inspect yunzhou-platform-gateway --format '{{range .Mounts}}{{println .Source}}{{end}}' | grep -qx /data/yunzhou-control/data/gateway/certs && "
            "docker inspect yunzhou-platform-gateway --format '{{.Config.Image}}' | grep -qx nginx:1.30.6-alpine; then "
            "docker start yunzhou-platform-gateway >/dev/null 2>&1 || true; "
            "else docker rm -f yunzhou-platform-gateway >/dev/null 2>&1 || true; docker run -d --name yunzhou-platform-gateway --restart unless-stopped --network host "
            "-v /data/yunzhou-control/data/gateway/conf.d:/etc/nginx/conf.d:ro -v /data/yunzhou-control/data/gateway/certs:/etc/nginx/certs:ro nginx:1.30.6-alpine >/dev/null; fi; "
            "if ! docker exec yunzhou-platform-gateway nginx -t; then "
            f"test -f {shlex.quote(filename)}.bak && mv {shlex.quote(filename)}.bak {shlex.quote(filename)} || rm -f {shlex.quote(filename)}; "
            + cert_restore + restore_legacy + " exit 43; fi; "
            + remove_legacy_backups +
            "docker exec yunzhou-platform-gateway nginx -s reload"
        )
        code, output = ssh.run(command, timeout=60)
        if code:
            if code == 42:
                raise RuntimeError("SSL 证书与私钥不匹配")
            raise RuntimeError("平台网关配置失败：" + output)
        code, output = ssh.run(f"curl -sS -o /dev/null --max-time 8 http://127.0.0.1:{gateway_port}/")
        if code:
            ssh.run(
                f"test -f {shlex.quote(filename)}.bak && mv {shlex.quote(filename)}.bak {shlex.quote(filename)} || rm -f {shlex.quote(filename)}; "
                + cert_restore +
                "docker exec yunzhou-platform-gateway nginx -t && docker exec yunzhou-platform-gateway nginx -s reload",
                timeout=30,
            )
            raise RuntimeError("平台网关映射后无法访问源站：" + output)
        ssh.run(f"rm -f {shlex.quote(filename)}.bak; " + cert_cleanup, timeout=15)
    gateway_reservation = db.scalar(select(DeploymentPortReservation).where(
        DeploymentPortReservation.node_id == gateway.id,
        DeploymentPortReservation.host_port == gateway_port,
    ))
    if gateway_reservation:
        gateway_reservation.deployment_id = deployment.id
        gateway_reservation.service_name = "__gateway__"
        gateway_reservation.status = "active"
        gateway_reservation.created_at = datetime.now(timezone.utc)
    else:
        db.add(DeploymentPortReservation(
            deployment_id=deployment.id,
            node_id=gateway.id,
            service_name="__gateway__",
            host_port=gateway_port,
            status="active",
        ))
    # A project owns only one live gateway listener. Mark any stale listener
    # reservation released after the replacement route has passed nginx -t
    # and its reachability check.
    for reservation in gateway_reservations:
        owner = db.get(Deployment, reservation.deployment_id)
        if owner and owner.project_id == deployment.project_id and reservation.host_port != gateway_port:
            reservation.status = "released"
    db.flush()
    if domain:
        scheme, port = ("https", https_port) if https_enabled else ("http", http_port)
        default_port = 443 if scheme == "https" else 80
        return f"{scheme}://{domain}{':' + str(port) if port != default_port else ''}"
    return f"http://{gateway.public_address or gateway.host}:{gateway_port}"


def snapshot_platform_gateway(db, project_id: str) -> tuple[bool, str]:
    """Capture the current project gateway file before a candidate switch."""
    gateway = platform_gateway_node(db)
    if not gateway:
        return False, ""
    filename = f"/data/yunzhou-control/data/gateway/conf.d/project-{project_id}.conf"
    with SSHNode(gateway) as ssh:
        code, encoded = ssh.run(
            f"test -f {shlex.quote(filename)} && base64 -w0 {shlex.quote(filename)}",
            timeout=20,
        )
    return code == 0 and bool(encoded.strip()), encoded.strip()


def restore_platform_gateway(db, project_id: str, snapshot: tuple[bool, str]) -> None:
    """Restore the previous gateway route after candidate verification fails."""
    gateway = platform_gateway_node(db)
    if not gateway:
        return
    existed, encoded = snapshot
    filename = f"/data/yunzhou-control/data/gateway/conf.d/project-{project_id}.conf"
    with SSHNode(gateway) as ssh:
        if existed:
            command = f"printf %s {shlex.quote(encoded)} | base64 -d > {shlex.quote(filename)}"
        else:
            command = f"rm -f {shlex.quote(filename)}"
        code, output = ssh.run(
            command + "; docker exec yunzhou-platform-gateway nginx -t && docker exec yunzhou-platform-gateway nginx -s reload",
            timeout=30,
        )
    if code:
        raise RuntimeError("恢复旧网关配置失败：" + output[-800:])



