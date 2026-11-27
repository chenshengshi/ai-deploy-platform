"""Infer, probe and diagnose a deployed application's public access path."""

from __future__ import annotations

import json
import re
import shlex
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from ..ai import deployment_followup, reconcile_followup_live_state
from ..chat.diagnostics import diagnose_blank_frontend
from ..database import SessionLocal
from ..models import Deployment, Node, Project
from ..ssh import SSHNode
from .execution_control import ensure_active
from .execution_log import log
from .gateway import platform_gateway_node
from .logs import read_deployment_log
from .naming import deployment_compose_project_name
from .verification import (
    frontend_code_warning,
    has_fatal_startup_error,
    http_status_accepted,
    required_route_accepted,
)

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

