"""Stable identity for the operational part of an AI deployment plan."""

from __future__ import annotations

import hashlib
import json


_NON_OPERATIONAL_PLAN_KEYS = {
    "provider", "requested_model", "model", "summary", "mode_decision",
    "reasoning", "analysis", "analysis_notes", "confidence",
}


def actionable_plan_fingerprint(plan: dict | None) -> str:
    """Ignore explanation-only AI fields when deciding whether a rebuild is needed."""
    if not isinstance(plan, dict):
        return ""

    def normalize(value):
        if isinstance(value, dict):
            return {
                key: normalize(item)
                for key, item in sorted(value.items())
                if key not in _NON_OPERATIONAL_PLAN_KEYS
            }
        if isinstance(value, list):
            return [normalize(item) for item in value]
        return value

    payload = json.dumps(normalize(plan), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
