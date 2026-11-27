"""Deterministic intent helpers used when interpreting AI chat requests."""

from __future__ import annotations

import re
from collections.abc import Iterable
from difflib import SequenceMatcher
from typing import TypeVar


ProjectLike = TypeVar("ProjectLike")

_INTENT_EXAMPLES = {
    "stop": ("停止部署", "暂停部署", "中止部署", "取消部署", "停掉部署"),
    "rollback": ("回滚上个版本", "回滚上一版本", "恢复历史版本"),
    "restart": ("重启服务", "重启容器", "重启项目"),
    "migrate": ("执行表结构", "更新表结构", "应用迁移文件", "同步数据库结构"),
    "deploy": ("开始部署", "重新部署", "发布项目", "上线项目"),
}

_CONFIRMATIONS = {
    "是", "是的", "确认", "确认部署", "确认停止", "确认取消", "确认回滚", "确认重启",
    "确认修复", "修复", "修复并重新发布", "确认修复并重新发布", "确认执行表结构",
    "确认执行高风险表结构", "确认执行数据变更", "确认执行高风险数据变更", "开始",
    "开始部署", "可以", "执行", "上线", "停止", "取消", "回滚", "重启",
}


def normalize_message(message: str) -> str:
    return re.sub(r"[\s，。！!？?]", "", str(message or ""))


def fallback_action_from_message(message: str) -> str:
    """Return a confirmation-gated action when the configured AI is down."""
    compact = re.sub(r"[\s，。！!？?、]", "", str(message or "").lower())
    ranked = [
        (SequenceMatcher(None, compact, example).ratio(), action)
        for action, examples in _INTENT_EXAMPLES.items()
        for example in examples
    ]
    score, action = max(ranked, default=(0.0, "none"))
    if score < 0.56 or (action == "stop" and "部署" not in compact):
        return "none"
    return action


def explicit_project_match(projects: Iterable[ProjectLike], message: str) -> ProjectLike | None:
    return next((item for item in projects if item.name in message or item.slug in message), None)


def fuzzy_project_match(projects: Iterable[ProjectLike], message: str) -> ProjectLike | None:
    """Tolerate a small typo without ever authorizing the resulting action."""
    normalized = normalize_message(message)
    project_words = re.sub(
        r"(帮我|一下|现在|当前|这个|那个|项目|系统|平台|服务|应用|重启|重新启动|重新|部署|发布|停止|回滚)",
        "",
        normalized,
    )
    ranked = []
    for candidate in projects:
        candidate_name = re.sub(r"(项目|系统|平台|服务|应用|中心)$", "", candidate.name)
        score = max(
            SequenceMatcher(None, project_words, candidate.name).ratio(),
            SequenceMatcher(None, project_words, candidate_name).ratio(),
        ) if project_words else 0
        ranked.append((score, candidate))
    ranked.sort(key=lambda row: row[0], reverse=True)
    if not ranked:
        return None
    best_score, best_project = ranked[0]
    runner_up = ranked[1][0] if len(ranked) > 1 else 0
    return best_project if best_score >= 0.48 and best_score - runner_up >= 0.12 else None


def is_confirmation(message: str) -> bool:
    return normalize_message(message) in _CONFIRMATIONS
