"""Parse explicit external-service settings from AI chat requests."""

from __future__ import annotations

import re


def extract_external_mysql_config(message: str) -> dict[str, str]:
    """Extract a complete, explicitly supplied external MySQL connection."""
    text = str(message or "")
    if "mysql" not in text.lower() or not any(word in text for word in ("外置", "外接", "外部")):
        return {}

    host = re.search(r"\b((?:\d{1,3}\.){3}\d{1,3})\b", text)
    port = re.search(r"(?:端口\s*[:：]?\s*|\b\d{1,3}(?:\.\d{1,3}){3}\s*[:：])(\d{2,5})\b", text, re.I)
    database = re.search(r"(?:数据库|库名)\s*[:：]?\s*([A-Za-z0-9_$.-]+)", text, re.I)
    username = re.search(r"(?:用户名|账号|用户)\s*[:：]?\s*([^\s，。；;]+)", text, re.I)
    password = re.search(r"(?:密码)\s*[:：]?\s*([^\s，。；;]+)", text, re.I)
    if not all((host, port, database, username, password)):
        return {}
    return {
        "YUNZHOU_MYSQL_MODE": "external",
        "YUNZHOU_MYSQL_HOST": host.group(1),
        "YUNZHOU_MYSQL_PORT": port.group(1),
        "YUNZHOU_MYSQL_DATABASE": database.group(1),
        "YUNZHOU_MYSQL_USERNAME": username.group(1),
        "YUNZHOU_MYSQL_PASSWORD": password.group(1),
    }
