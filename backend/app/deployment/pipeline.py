import re
from datetime import datetime, timezone


PIPELINE_DEFINITIONS = (
    ("analyze", "读取方案", ("方案",)),
    ("prepare", "准备环境", ("准备", "源码", "依赖分析", "架构分析", "识别", "上传", "镜像")),
    ("build", "构建应用", ("构建", "平台构建", "AI构建")),
    ("start", "启动服务", ("启动",)),
    ("verify", "验证访问", ("检查", "完成")),
)


def parse_stage_times(log_text: str) -> dict[str, dict[str, datetime]]:
    stage_times: dict[str, dict[str, datetime]] = {}
    for match in re.finditer(
        r"(?m)^\[阶段时间\]\s+(analyze|prepare|build|start|verify)\s+"
        r"(开始|完成|失败|停止)\s+(\S+)\s*$",
        log_text,
    ):
        try:
            moment = datetime.fromisoformat(match.group(3).replace("Z", "+00:00"))
            if moment.tzinfo is None:
                moment = moment.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        bucket = stage_times.setdefault(match.group(1), {})
        bucket["start" if match.group(2) == "开始" else "end"] = moment
    return stage_times


def stage_timing(stage_times: dict[str, dict[str, datetime]], key: str, running: bool) -> dict:
    timing = stage_times.get(key) or {}
    started = timing.get("start")
    finished = timing.get("end")
    if not started:
        return {"started_at": None, "finished_at": None, "duration_seconds": None}
    effective_end = finished or (datetime.now(timezone.utc) if running else None)
    duration = max(0, (effective_end - started).total_seconds()) if effective_end else None
    return {
        "started_at": started.isoformat(),
        "finished_at": finished.isoformat() if finished else None,
        "duration_seconds": round(duration, 1) if duration is not None else None,
    }
"""Deployment package component."""

