import re


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
