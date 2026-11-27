"""Validate generated deployment plans without modifying a project release."""

from __future__ import annotations

import hashlib
import shlex
import shutil
import tempfile
import time
from pathlib import Path

from ..config import settings
from ..models import Project
from ..ssh import SSHNode
from .ai_plan import materialize_ai_deployment_plan
from .architecture import analyze_repository_topology
from .build_handlers import detect_container_port
from .gateway import platform_gateway_node
from .integration_reconcile import adapt_plan_to_current_integrations, reconcile_managed_integrations
from .integrations import effective_project_environment, environment_values
from .managed_configuration import ensure_managed_secrets, required_compose_variables
from .source_repair import apply_safe_build_repairs

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

