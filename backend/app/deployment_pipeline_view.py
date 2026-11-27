"""User-facing deployment pipeline parsing and log rendering."""

import re

from .models import DeployStatus
from .deployment_pipeline import PIPELINE_DEFINITIONS, parse_stage_times, stage_timing
from .deployment_log_rendering import build_log_streams, compact_stage_log

def render_pipeline_steps(log_text: str, status: DeployStatus, selected_key: str | None = None, is_compose: bool = False) -> list[dict]:
    # Keep the user-facing pipeline compact. Detailed AI/preflight activity is
    # retained in the log for the active major stage.
    definitions = PIPELINE_DEFINITIONS
    skipped_stages = set()
    if re.search(r"(?m)^\[平台构建\].*(?:没有\s+build|固定镜像).*已跳过", log_text):
        skipped_stages.add("build")
    stage_times = parse_stage_times(log_text)

    def timing_for(key: str) -> dict:
        return stage_timing(stage_times, key, status == DeployStatus.running)
    # New deployments emit explicit stage boundaries. Prefer them over
    # guessing from ordinary human-readable log messages.
    if "[阶段开始]" in log_text:
        starts = {}
        for match in re.finditer(r"(?m)^\[阶段开始\]\s+(analyze|prepare|build|start|verify)\s*$", log_text):
            starts[match.group(1)] = match.start()
        completed = {match.group(1) for match in re.finditer(
            r"(?m)^\[阶段完成\]\s+(analyze|prepare|build|start|verify)\s*$", log_text
        )}
        failed = {match.group(1) for match in re.finditer(
            r"(?m)^\[阶段失败\]\s+(analyze|prepare|build|start|verify)(?:\s+\|.*)?$", log_text
        )}
        stopped = {match.group(1) for match in re.finditer(
            r"(?m)^\[阶段停止\]\s+(analyze|prepare|build|start|verify)\s*$", log_text
        )}
        active_key = max(starts, key=starts.get) if starts else "analyze"
        stage_order = {key: index for index, (key, _title, _tags) in enumerate(definitions)}
        active_index = stage_order.get(active_key, 0)
        failure_key = next((key for key, _title, _tags in definitions if key in failed), None)
        default_key = failure_key or active_key
        valid_keys = {item[0] for item in definitions}
        # Keep the stage the user clicked even when an older/retried worker
        # emitted explicit boundaries for only the tail of the deployment.
        # The per-stage legacy markers below can still provide that log.  The
        # previous `selected_key in starts` guard silently switched the API to
        # the latest stage while the UI continued to display the clicked card,
        # producing an empty panel with "等待该步骤开始...".
        log_key = selected_key if selected_key in valid_keys else default_key
        ordered_starts = sorted((position, key) for key, position in starts.items())
        # Some releases were completed by a worker that only emitted explicit
        # boundaries for part of the pipeline.  The detailed, human-readable
        # markers are still present (for example [启动] and [检查]).  Use those
        # markers as a per-stage fallback so a successful card never opens an
        # empty log panel merely because one boundary marker is missing.
        legacy_positions = {}
        for legacy_key, _legacy_title, legacy_tags in definitions:
            legacy_positions[legacy_key] = max(
                (log_text.rfind(f"[{tag}]") for tag in legacy_tags),
                default=-1,
            )
        result = []
        for key, title, _tags in definitions:
            stream_rows = []
            start = starts.get(key)
            if start is None:
                # A successful deployment is authoritative even when an
                # older worker did not emit the final explicit stage marker.
                # Leaving the last card at "waiting" after progress reached
                # 100% makes a healthy release look unfinished.
                # Retried/resumed workers may only emit explicit boundaries
                # for the tail of a deployment.  Once a later stage has
                # started, every earlier stage is necessarily complete even
                # if its boundary was written by an older worker version.
                stage_status = (
                    "success"
                    if status == DeployStatus.success or stage_order[key] < active_index
                    else "waiting"
                )
                legacy_start = legacy_positions.get(key, -1)
                later_legacy = [
                    position for candidate, position in legacy_positions.items()
                    if candidate != key and position > legacy_start
                ] if legacy_start >= 0 else []
                legacy_end = min(later_legacy) if later_legacy else len(log_text)
                section = log_text[legacy_start:legacy_end].strip() if key == log_key and legacy_start >= 0 else ""
                if key == log_key and not section and status == DeployStatus.success:
                    section = log_text.strip()
            else:
                end = next((position for position, _next_key in ordered_starts if position > start), len(log_text))
                section = log_text[start:end].strip() if key == log_key else ""
                if key in failed:
                    stage_status = "failed"
                elif key in stopped:
                    stage_status = "stopped"
                elif key in completed or status == DeployStatus.success:
                    stage_status = "success"
                elif key == active_key and status == DeployStatus.running:
                    stage_status = "running"
                elif key == active_key and status == DeployStatus.failed:
                    stage_status = "failed"
                elif key == active_key and status == DeployStatus.stopped:
                    stage_status = "stopped"
                else:
                    stage_status = "waiting"
            if section:
                if key == "build":
                    stream_rows = build_log_streams(section)
                section = re.sub(r"(?m)^\[AI跟进\].*$", "", section).rstrip()
                section = compact_stage_log(section)[-30_000:]
            result.append({"key": key, "title": title, "status": stage_status, "skipped": key in skipped_stages, "log": section, "build_streams": stream_rows, **timing_for(key)})
        return result
    positions = []
    for key, title, tags in definitions:
        # A worker restart can retry the same task. Use the latest attempt's marker.
        pos = max((log_text.rfind(f"[{tag}]") for tag in tags), default=-1)
        positions.append(pos)
    available = [index for index, pos in enumerate(positions) if pos >= 0]
    # The active stage is the marker written latest in the log, not merely the
    # first/last definition containing any historical marker.
    active_index = max(available, key=lambda index: positions[index]) if available else None
    inferred_index = None
    if not available and status in (DeployStatus.running, DeployStatus.stopped):
        lower = log_text.lower()
        if any(word in lower for word in ("load build definition", "building", "docker:default", "transferring context")):
            inferred_index = 2
        elif any(word in lower for word in ("pulling", "pull complete", "downloading")):
            inferred_index = 1
    default_key = definitions[active_index][0] if active_index is not None else definitions[0][0]
    if inferred_index is not None:
        default_key = definitions[inferred_index][0]
    # A failure may happen before the first normal stage marker (for example
    # while preparing an isolated checkout). Keep the failure visible instead
    # of rendering every step as waiting with an empty log panel.
    if status == DeployStatus.failed and active_index is None:
        active_index = inferred_index if inferred_index is not None else 0
        default_key = definitions[active_index][0]
    selected_index = next((i for i, item in enumerate(definitions) if item[0] == selected_key), None)
    if status == DeployStatus.failed and (selected_index is None or positions[selected_index] < 0):
        log_key = default_key
    else:
        log_key = selected_key if selected_key in {x[0] for x in definitions} else default_key
    result = []
    for index, (key, title, _tags) in enumerate(definitions):
        stream_rows = []
        start = positions[index]
        later = [x for x in positions[index + 1:] if x >= 0]
        end = min(later) if later else len(log_text)
        section = log_text[start:end].strip() if start >= 0 and key == log_key else ""
        if status == DeployStatus.failed and index == active_index and key == log_key and not section:
            section = log_text.strip()
        # AI follow-up records are metadata, not build output. Keep raw stage
        # logs clean even for records created by older platform versions.
        if key == "build" and section:
            stream_rows = build_log_streams(section)
        section = re.sub(r"(?m)^\[AI跟进\].*$", "", section).rstrip()
        section = compact_stage_log(section)[-30_000:]
        # Long dependency output can push the useful cache result outside the
        # active 30k window, especially while a build waits for the serialized
        # image-store lock. Keep a compact, evidence-based summary visible so
        # the UI never looks as if earlier logs or cache results disappeared.
        if key == "build" and key == log_key:
            cache_lines = re.findall(r"(?m)^\[缓存命中\].*$", log_text)
            if cache_lines:
                cache_summary = "[本次缓存摘要]\n" + "\n".join(cache_lines[-6:])
                if not all(line in section for line in cache_lines[-6:]):
                    section = cache_summary + "\n\n" + section
        if status == DeployStatus.success:
            stage_status = "success"
            if key == log_key and start < 0:
                section = compact_stage_log(log_text)[-30_000:]
        elif inferred_index is not None and not available:
            stage_status = "success" if index < inferred_index else (("stopped" if status == DeployStatus.stopped else "running") if index == inferred_index else "waiting")
            if index == inferred_index and key == log_key:
                section = compact_stage_log(log_text)[-30_000:]
        elif status == DeployStatus.failed and index == active_index:
            # Legacy workers and failures during task initialization may not
            # have emitted a normal stage marker.  The deployment status is
            # still authoritative: show the first/last inferred stage as
            # failed instead of rendering all five stages as "waiting".
            stage_status = "failed"
            if key == log_key and not section:
                section = compact_stage_log(log_text)[-30_000:]
        elif start < 0:
            stage_status = "waiting"
        elif active_index is not None and index < active_index:
            stage_status = "success"
        elif active_index is not None and index > active_index:
            stage_status = "waiting"
        elif status == DeployStatus.failed:
            stage_status = "failed"
        elif status == DeployStatus.stopped:
            stage_status = "stopped"
        elif status == DeployStatus.success:
            stage_status = "success"
        else:
            stage_status = "running"
        result.append({"key": key, "title": title, "status": stage_status, "skipped": key in skipped_stages, "log": section, "build_streams": stream_rows, **timing_for(key)})
    return result




