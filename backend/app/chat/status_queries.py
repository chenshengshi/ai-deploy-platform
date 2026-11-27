"""Deterministic recognition for platform-wide read-only status questions."""

import re


def asks_active_deployment_summary(message: str) -> bool:
    """Return true only for an explicit query about active deployment jobs."""
    normalized = re.sub(r"\s+", "", str(message or "")).lower()
    if not any(word in normalized for word in ("发布", "部署", "任务")):
        return False
    active_words = ("正在执行", "执行中", "进行中", "正在发布", "正在部署", "排队中", "当前有没有", "当前有无")
    query_words = ("多少", "几个", "有没有", "有无", "哪些", "状态", "查询", "只查询")
    return any(word in normalized for word in active_words) and any(word in normalized for word in query_words)
