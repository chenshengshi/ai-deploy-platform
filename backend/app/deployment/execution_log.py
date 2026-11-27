"""Ordered deployment logging and cancellable remote command execution."""

import re
import shlex
import threading
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from sqlalchemy import text

from ..database import SessionLocal
from ..models import Deployment
from ..ssh import SSHNode
from .logs import append_deployment_log

ANSI_RE = re.compile(r"\\x1b(?:[@-_][0-?]*[ -/]*[@-~]|\\][^\\x07]*(?:\\x07|\\x1b\\\\))")
_DEPLOYMENT_LOG_LOCKS: dict[str, threading.Lock] = {}
_DEPLOYMENT_LOG_LOCKS_GUARD = threading.Lock()


def tracked_run(
    ssh: SSHNode, deployment_id: str, command: str, stream=None,
    timeout: int = 1800, pid_prefix: str = "yunzhou-deploy",
    stream_channel: str | None = None, stream_label: str | None = None,
):
    """Run a remote deployment command in its own process group so stop is real."""
    pid_file = f"/tmp/{pid_prefix}-{deployment_id}.pid"
    inner = f"exec setsid sh -c {shlex.quote(command)}"
    supervisor = (
        inner + " & pid=$!; echo $pid > " + pid_file + "; "
        + "wait $pid; rc=$?; rm -f " + pid_file + "; exit $rc"
    )
    wrapped = f"sh -c {shlex.quote(supervisor)}"
    channel_stream = stream
    if stream and stream_channel:
        label = stream_label or stream_channel
        docker_progress_buckets: dict[tuple[str, str], int] = {}
        log(deployment_id, f"[构建通道] {stream_channel}|{label}|开始|{datetime.now(timezone.utc).isoformat()}\n")

        def channel_stream(chunk: str) -> None:
            cleaned = ANSI_RE.sub("", str(chunk or "")).replace("\r", "\n")
            readable: list[str] = []
            for raw_line in cleaned.splitlines():
                line = raw_line.strip()
                if not line:
                    continue
                progress = re.match(
                    r"^([0-9a-f]{12})\s+(Downloading|Extracting)\s+\[.*?\]\s+"
                    r"([0-9.]+)([kMGT]?B)/([0-9.]+)([kMGT]?B)",
                    line,
                    re.IGNORECASE,
                )
                if progress:
                    layer, state, current, current_unit, total, total_unit = progress.groups()
                    unit_scale = {"B": 1, "KB": 1024, "MB": 1024**2, "GB": 1024**3, "TB": 1024**4}
                    current_bytes = float(current) * unit_scale.get(current_unit.upper(), 1)
                    total_bytes = float(total) * unit_scale.get(total_unit.upper(), 1)
                    bucket = min(10, int((current_bytes / total_bytes) * 10)) if total_bytes else 0
                    key = (layer, state.lower())
                    if docker_progress_buckets.get(key) == bucket:
                        continue
                    docker_progress_buckets[key] = bucket
                readable.append(line)
            stamped = "".join(
                f"[{datetime.now(timezone.utc).isoformat()}][构建:{stream_channel}] {line}\n"
                for line in readable
            )
            if stamped:
                stream(stamped)
    code, output = ssh.run(wrapped, timeout=timeout, stream=channel_stream)
    if stream and stream_channel:
        state = "完成" if code == 0 else "失败"
        log(deployment_id, f"[构建通道] {stream_channel}|{stream_label or stream_channel}|{state}|{datetime.now(timezone.utc).isoformat()}\n")
    return code, output


def log(deployment_id: str, text: str) -> None:
    if not text:
        return
    text = ANSI_RE.sub("", text).replace("\r", "")
    with _DEPLOYMENT_LOG_LOCKS_GUARD:
        deployment_lock = _DEPLOYMENT_LOG_LOCKS.setdefault(deployment_id, threading.Lock())
    with deployment_lock:
        _write_deployment_log(deployment_id, text)


def _write_deployment_log(deployment_id: str, fragment: str) -> None:
    """Write one ordered log fragment; callers serialize per deployment."""
    # The database keeps a compact, fast UI window. The append-only file keeps
    # every raw line for troubleshooting and download without rendering it.
    append_deployment_log(deployment_id, fragment)
    try:
        with SessionLocal() as db:
            # UI progress is best-effort. It must never wait behind the main
            # deployment transaction and deadlock the worker against itself.
            db.execute(text("SET LOCAL lock_timeout = '2s'"))
            dep = db.get(Deployment, deployment_id)
            if dep:
                combined = (dep.log_text or "") + fragment
                if len(combined) > 200_000:
                # Keep stage markers even when verbose Docker output is truncated.
                    markers = []
                    for line in combined.splitlines():
                        if re.match(r"^\[(计划|方案|准备|源码|依赖分析|AI规划|架构分析|识别|上传|镜像|构建|平台构建|AI构建|启动|检查|完成|失败|停止|停止确认|AI跟进|AI修复|AI自动修复|阶段开始|阶段完成|阶段失败|阶段停止|阶段时间)\]", line) and line not in markers:
                            markers.append(line)
                    combined = "\n".join(markers[-40:]) + "\n[日志] 较早的详细输出已折叠\n" + combined[-185_000:]
                dep.log_text = combined
                db.commit()
    except Exception:
        # The append-only file above remains authoritative if the compact UI
        # row is temporarily locked.
        pass


def log_stage(deployment_id: str, action: str, stage: str, detail: str = "") -> None:
    """Persist a readable boundary and a machine-readable UTC timestamp."""
    suffix = f" | {detail}" if detail else ""
    timestamp = datetime.now(ZoneInfo("Asia/Shanghai")).isoformat()
    log(
        deployment_id,
        f"[阶段{action}] {stage}{suffix}\n"
        f"[阶段时间] {stage} {action} {timestamp}\n",
    )

