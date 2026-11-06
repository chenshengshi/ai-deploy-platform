"""Portable, quality-controlled deployment learning utilities."""

from __future__ import annotations

import json
import math
import re
from datetime import datetime, timezone
from typing import Iterable


CORRUPTION_MARKERS = ("\ufffd", "锟斤拷", "烫烫烫")
SECRET_PATTERN = re.compile(
    r"(?i)(password|passwd|token|secret|api[_-]?key|access[_-]?key)\s*[=:]\s*([^\s,;]+)"
)
TECH_TOKENS = {
    "docker", "compose", "nginx", "gateway", "node", "npm", "pnpm", "yarn",
    "vite", "vue", "react", "java", "maven", "gradle", "python", "pip", "go",
    "mysql", "postgres", "postgresql", "redis", "minio", "rabbitmq", "elasticsearch",
    "healthcheck", "network", "timeout", "lockfile", "dockerfile", "sql", "migration",
    "frontend", "backend", "worker", "registry", "volume", "mount", "port",
}


def contains_corruption(value: str | None) -> bool:
    text = value or ""
    return any(marker in text for marker in CORRUPTION_MARKERS) or any(
        ord(char) < 32 and char not in "\n\r\t" for char in text
    )


def sanitize_learning_text(value: str | None, limit: int = 4000) -> str:
    """Remove environment identity and secrets before cross-project reuse."""
    text = value or ""
    text = re.sub(r"\x1b\[[0-9;?]*[a-zA-Z]", " ", text)
    text = re.sub(r"https?://\S+", "<url>", text)
    text = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "<ip>", text)
    text = re.sub(r"(?<![\w/])/(?:data|home|root|opt|srv|var)/[^\s,;]+", "<path>", text)
    text = SECRET_PATTERN.sub(lambda match: f"{match.group(1)}=<redacted>", text)
    text = re.sub(r"\b[0-9a-f]{24,}\b", "<id>", text, flags=re.I)
    text = re.sub(r"[ \t]+", " ", text).strip()
    return text[-limit:]


def infer_experience_stage(category: str, text: str = "") -> str:
    value = f"{category} {text}".lower()
    if any(item in value for item in ("analysis", "source", "lockfile", "dockerfile")):
        return "analysis"
    if any(item in value for item in ("gateway", "nginx", "route", "access")):
        return "gateway"
    if any(item in value for item in ("health", "startup", "network", "timeout")):
        return "verification"
    if any(item in value for item in ("sql", "database", "mysql", "postgres", "redis")):
        return "data"
    return "deployment"


def infer_experience_tags(category: str, error_sample: str, repair_summary: str) -> list[str]:
    value = f"{category} {error_sample} {repair_summary}".lower()
    tags = sorted(token for token in TECH_TOKENS if token in value)
    return tags[:12]


def experience_confidence(verified: bool, successes: int, failures: int, occurrences: int) -> int:
    successes = max(0, int(successes or 0))
    failures = max(0, int(failures or 0))
    occurrences = max(1, int(occurrences or 1))
    base = 55 if verified else 20
    score = base + min(25, successes * 8) - min(35, failures * 7) + min(10, int(math.log2(occurrences + 1) * 3))
    return max(0, min(100, score))


def normalized_state(row) -> str:
    state = str(getattr(row, "state", "") or "").strip().lower()
    if state in {"candidate", "verified", "deprecated", "quarantined"}:
        return state
    return "verified" if bool(getattr(row, "verified", False)) else "candidate"


def rank_learning_experiences(rows: Iterable, context: str, limit: int = 30) -> list:
    """Choose reliable and context-relevant lessons, preserving counterexamples."""
    context_lower = (context or "").lower()
    context_tokens = {token for token in TECH_TOKENS if token in context_lower}
    ranked = []
    for row in rows:
        if not bool(getattr(row, "enabled", True)) or normalized_state(row) in {"deprecated", "quarantined"}:
            continue
        sample = str(getattr(row, "error_sample", "") or "")
        lesson = str(getattr(row, "repair_summary", "") or "")
        if contains_corruption(sample) or contains_corruption(lesson) or not sample.strip():
            continue
        tags = set(infer_experience_tags(str(getattr(row, "category", "")), sample, lesson))
        relevance = len(tags & context_tokens) * 12
        confidence = experience_confidence(
            bool(getattr(row, "verified", False)),
            int(getattr(row, "successful_repairs", 0) or 0),
            int(getattr(row, "failed_repairs", 0) or 0),
            int(getattr(row, "occurrences", 1) or 1),
        )
        ranked.append((relevance + confidence, bool(getattr(row, "verified", False)), row))
    ranked.sort(key=lambda item: (
        item[0], item[1],
        getattr(getattr(item[2], "updated_at", None), "timestamp", lambda: 0.0)(),
    ), reverse=True)
    verified = [item[2] for item in ranked if item[1]][: max(10, limit // 2)]
    counterexamples = [item[2] for item in ranked if not item[1]][: max(8, limit - len(verified))]
    selected = verified + counterexamples
    selected.sort(
        key=lambda row: next(item[0] for item in ranked if item[2] is row), reverse=True
    )
    return selected[:limit]


def portable_experience(row) -> dict:
    sample = sanitize_learning_text(getattr(row, "error_sample", ""), 1200)
    lesson = sanitize_learning_text(getattr(row, "repair_summary", ""), 3000)
    return {
        "signature": row.signature,
        "category": row.category,
        "stage": getattr(row, "stage", "") or infer_experience_stage(row.category, sample),
        "scope_tags": infer_experience_tags(row.category, sample, lesson),
        "state": normalized_state(row),
        "enabled": bool(getattr(row, "enabled", True)),
        "confidence": experience_confidence(row.verified, row.successful_repairs, row.failed_repairs, row.occurrences),
        "error_sample": sample,
        "repair_summary": lesson,
        "occurrences": row.occurrences,
        "successful_repairs": row.successful_repairs,
        "failed_repairs": row.failed_repairs,
        "verified": row.verified,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
        "last_verified_at": row.last_verified_at.isoformat() if row.last_verified_at else None,
    }


def prepare_new_experience(row) -> None:
    """Populate derived metadata and quarantine invalid knowledge."""
    row.error_sample = sanitize_learning_text(row.error_sample, 1200)
    row.repair_summary = sanitize_learning_text(row.repair_summary, 3000)
    corrupted = contains_corruption(row.error_sample) or contains_corruption(row.repair_summary)
    current_state = normalized_state(row)
    successes = max(0, int(getattr(row, "successful_repairs", 0) or 0))
    failures = max(0, int(getattr(row, "failed_repairs", 0) or 0))
    category = str(getattr(row, "category", "") or "").strip().lower()
    sample_lower = (row.error_sample or "").lower()
    platform_program_error = category in {"", "unknown"} and bool(re.search(
        r"name ['\"][a-z_][a-z0-9_]*['\"] is not defined|"
        r"(?:attribute|type|syntax|indentation)error|"
        r"traceback \(most recent call last\)",
        sample_lower,
    ))
    # A once-successful repair can later prove unreliable on more projects.
    # Do not keep presenting an equal-or-worse outcome as verified knowledge;
    # retain it as a counterexample until fresh successful evidence wins again.
    contradicted = failures > 0 and failures >= successes
    if contradicted:
        row.verified = False
        if current_state == "verified":
            current_state = "candidate"
    # Lifecycle is automatic: two clean real successes promote a lesson;
    # repeated failures or platform programming exceptions isolate it so the
    # AI cannot keep recycling a bad/internal fix.
    if successes >= 2 and successes >= failures + 2 and current_state not in {"deprecated", "quarantined"}:
        row.verified = True
        current_state = "verified"
    repeatedly_failed = failures >= 3 and failures > successes
    if corrupted or platform_program_error or repeatedly_failed:
        row.verified = False
        row.state = "quarantined"
        row.enabled = False
    elif current_state not in {"deprecated", "quarantined"}:
        row.state = "verified" if row.verified else "candidate"
    row.stage = infer_experience_stage(row.category, row.error_sample)
    row.scope_tags = json.dumps(infer_experience_tags(row.category, row.error_sample, row.repair_summary), ensure_ascii=False)
    row.confidence = experience_confidence(row.verified, row.successful_repairs, row.failed_repairs, row.occurrences)
    if row.verified and not row.last_verified_at:
        row.last_verified_at = datetime.now(timezone.utc)
