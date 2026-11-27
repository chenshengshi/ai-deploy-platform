import re
from datetime import datetime, timezone


def compact_docker_pull_log(section: str) -> str:
    """Collapse terminal-style Docker layer refreshes into one latest row per layer."""
    lines = re.sub(r"\x1b\[[0-9;?]*[ -/]*[@-~]", "", section).replace("\r", "\n").splitlines()
    visible: list[str] = []
    latest: dict[tuple[str, str], str] = {}
    order: list[tuple[str, str]] = []
    progress_pattern = re.compile(
        r"^(?:\[[^\n]+?\]\s*)*([0-9a-f]{12})\s+(Downloading|Extracting)\s+\[.*",
        re.IGNORECASE,
    )
    for line in lines:
        match = progress_pattern.match(line.strip())
        if not match:
            visible.append(line)
            continue
        key = (match.group(1), match.group(2).lower())
        if key not in latest:
            order.append(key)
        latest[key] = line
    if latest:
        visible.append("[镜像下载进度（每层仅保留最新状态）]")
        visible.extend(latest[key] for key in order)
    return "\n".join(visible).strip()


def compact_stage_log(section: str) -> str:
    """Keep live Docker progress readable without altering downloadable logs."""
    lines = compact_docker_pull_log(section).splitlines()
    visible: list[str] = []
    latest_progress: tuple[str, str] | None = None
    compose_progress: dict[str, str] = {}
    progress_was_tail = False
    for line in lines:
        stripped = line.strip()
        service_progress = re.search(
            r"Service\s+(\S+)\s+Building(?:\s+.*?\s)?(\d+(?:\.\d+)?)s\s*$",
            stripped,
        )
        generic_progress = re.search(r"(?:^|\]\s)(?:\[\+\]\s*)?Building\s+\d+/\d+\s*$", stripped)
        orphan_duration = re.search(r"(?:^|\]\s)\d+(?:\.\d+)?s$", stripped)
        compose_header = re.match(r"^\[\+\]\s+(?:Running|Pulling|Building|Stopping|Restarting)\s+\d+/\d+", stripped)
        compose_item = re.match(
            r"^[^A-Za-z0-9\[]*(Network|Container|Volume|Image)\s+(\S+)\s+"
            r"(Created|Creating|Started|Starting|Waiting|Running|Healthy|Error|Pulling|Pulled|Removed|Removing)"
            r"(?:\s+(\d+(?:\.\d+)?s))?\s*$",
            stripped,
        )
        if compose_header:
            progress_was_tail = True
            continue
        if compose_item:
            kind, name, state, duration = compose_item.groups()
            compose_progress[f"{kind}:{name}"] = f"{kind} {name} · {state}" + (f" · {duration}" if duration else "")
            progress_was_tail = True
            continue
        if service_progress:
            latest_progress = (service_progress.group(1), service_progress.group(2))
            progress_was_tail = True
            continue
        if generic_progress or orphan_duration:
            progress_was_tail = True
            continue
        if stripped:
            progress_was_tail = False
        visible.append(line)
    if latest_progress and progress_was_tail:
        service, seconds = latest_progress
        visible.append(f"[构建进度] {service} · {seconds}秒")
    if compose_progress:
        visible.append("[Compose 最新状态]")
        visible.extend(compose_progress.values())
    return "\n".join(visible).strip()


def build_log_streams(section: str) -> list[dict]:
    """Split timestamped concurrent build output into service-specific views."""
    channels: dict[str, dict] = {}
    for match in re.finditer(
        r"(?m)^\[构建通道\]\s+([^|\s]+)\|([^|]+)\|(开始|完成|失败)\|(\S+)\s*$",
        section,
    ):
        key, label, state, raw_time = match.groups()
        channel = channels.setdefault(key, {"key": key, "label": label, "lines": [], "started_at": None, "finished_at": None, "status": "running"})
        channel["label"] = label
        try:
            moment = datetime.fromisoformat(raw_time.replace("Z", "+00:00"))
        except ValueError:
            moment = None
        if state == "开始":
            channel["started_at"] = moment
        else:
            channel["finished_at"] = moment
            channel["status"] = "success" if state == "完成" else "failed"
    line_pattern = re.compile(r"^\[(\S+)\]\[构建:([^\]]+)\]\s?(.*)$")
    for raw_line in section.splitlines():
        match = line_pattern.match(raw_line.strip())
        if not match:
            continue
        raw_time, key, _message = match.groups()
        channel = channels.setdefault(key, {"key": key, "label": key, "lines": [], "started_at": None, "finished_at": None, "status": "running"})
        channel["lines"].append(raw_line)
        if channel["started_at"] is None:
            try:
                channel["started_at"] = datetime.fromisoformat(raw_time.replace("Z", "+00:00"))
            except ValueError:
                pass
    terminal = re.search(r"(?m)^\[阶段时间\]\s+build\s+(完成|失败|停止)\s+(\S+)\s*$", section)
    terminal_state = terminal.group(1) if terminal else None
    result = []
    latest_stream_end: datetime | None = None
    for channel in channels.values():
        started, finished = channel.pop("started_at"), channel.pop("finished_at")
        if finished and (latest_stream_end is None or finished > latest_stream_end):
            latest_stream_end = finished
        effective_end = finished or datetime.now(timezone.utc)
        duration = max(0, (effective_end - started).total_seconds()) if started else None
        if not finished and terminal_state:
            channel["status"] = {"完成": "success", "失败": "failed", "停止": "stopped"}[terminal_state]
        channel["duration_seconds"] = round(duration, 1) if duration is not None else None
        channel["log"] = compact_stage_log("\n".join(channel.pop("lines")))[-30_000:]
        result.append(channel)
    package_markers = (
        "[并发构建] 前端 Web 与后端 API 依赖构建已汇合，开始封装运行镜像。",
        "[镜像封装]", "镜像封装完成", "[即时封装]",
    )
    package_positions = [section.find(marker) for marker in package_markers if section.find(marker) >= 0]
    package_pos = min(package_positions) if package_positions else -1
    if package_pos >= 0 and not any(item.get("key") == "package" for item in result):
        stage_end_match = re.search(r"(?m)^\[阶段时间\]\s+build\s+(?:完成|失败|停止)\s+(\S+)\s*$", section)
        stage_end = None
        if stage_end_match:
            try:
                stage_end = datetime.fromisoformat(stage_end_match.group(1).replace("Z", "+00:00"))
            except ValueError:
                pass
        effective_end = stage_end or datetime.now(timezone.utc)
        package_log = re.sub(r"(?m)^\[阶段(?:时间|开始|完成|失败|停止)\].*$", "", section[package_pos:])
        package_log = re.sub(r"(?m)^\[构建通道\].*$", "", package_log)
        result.append({
            "key": "package",
            "label": "镜像封装",
            "status": "success" if stage_end_match and "完成" in stage_end_match.group(0) else ("failed" if stage_end_match else "running"),
            "duration_seconds": round(max(0, (effective_end - (latest_stream_end or effective_end)).total_seconds()), 1),
            "log": compact_stage_log(package_log)[-30_000:],
        })
    order = {"web": 0, "api": 1, "package": 2, "distribute": 3}
    return sorted(result, key=lambda item: (order.get(item["key"], 99), item["label"]))
"""Deployment package component."""

