"""Pure SQL extraction, classification and confirmation helpers."""

from __future__ import annotations

import hashlib
import re


_DANGER = re.compile(
    r"(?i)\b(drop\s+(?:table|database|schema)|truncate\s+table|delete\s+from|alter\s+table\s+.+\s+drop\s+)\b"
)


def extract_direct_sql(message: str) -> str | None:
    fenced = re.search(r"```(?:sql)?\s*([\s\S]+?)```", message, re.I)
    if fenced:
        return fenced.group(1).strip()
    match = re.search(
        r"(?is)(?<![A-Za-z0-9_])(select|show|describe|desc|explain|with|alter|create|drop|truncate|comment|rename|insert|update|delete)\b[\s\S]*",
        message,
    )
    return match.group(0).strip() if match else None


def sql_kind(sql: str) -> str:
    cleaned = re.sub(r"(?s)/\*.*?\*/|--[^\n]*", " ", sql).strip()
    first = re.match(r"(?i)([a-z]+)", cleaned)
    keyword = first.group(1).lower() if first else ""
    if keyword in {"select", "show", "describe", "desc", "explain", "with"}:
        tail = cleaned.rstrip().rstrip(";")
        if ";" in tail or re.search(r"(?i)\b(insert|update|delete|alter|create|drop|truncate|rename)\b", tail):
            return "unsupported"
        return "query"
    if keyword in {"alter", "create", "drop", "truncate", "comment", "rename"}:
        if re.search(r"(?i)\b(insert|update|delete|grant|revoke|load\s+data|copy\s+.+\s+from)\b", cleaned):
            return "unsupported"
        return "schema"
    if keyword in {"insert", "update", "delete"}:
        return "data_change"
    return "unsupported"


def high_risk_matches(sql: str) -> list[str]:
    return sorted(set(match.group(0).upper() for match in _DANGER.finditer(sql)))


def is_high_risk_sql(sql: str) -> bool:
    return bool(_DANGER.search(sql))


def data_change_confirmation_token(project_id: str, sql: str, secret: str) -> str:
    return hashlib.sha256(f"{project_id}\n{sql}\n{secret}".encode()).hexdigest()
