import ipaddress
from urllib.parse import quote, urlsplit, urlunsplit

from sqlalchemy.orm import Session

from .models import SystemProxy
from .config import decrypt


def normalize_proxy(value: str | None) -> str:
    value = (value or "").strip()
    if value and "://" not in value:
        value = "http://" + value
    return value


def proxy_with_auth(value: str | None, username: str = "", password: str = "") -> str:
    value = normalize_proxy(value)
    if not value or not username:
        return value
    parts = urlsplit(value)
    host = parts.hostname or ""
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    netloc = f"{quote(username, safe='')}:{quote(password or '', safe='')}@{host}"
    if parts.port:
        netloc += f":{parts.port}"
    return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))


def redact_proxy(value: str | None) -> str:
    value = normalize_proxy(value)
    if not value:
        return ""
    parts = urlsplit(value)
    host = parts.hostname or ""
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    netloc = host + (f":{parts.port}" if parts.port else "")
    return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))


def get_proxy_config(db: Session) -> SystemProxy | None:
    return db.query(SystemProxy).first()


def _bypassed(host: str, no_proxy: str) -> bool:
    host = (host or "").lower().strip("[]")
    for raw in (no_proxy or "").split(","):
        rule = raw.strip().lower()
        if not rule:
            continue
        if rule == "*" or host == rule.lstrip(".") or host.endswith(rule if rule.startswith(".") else "." + rule):
            return True
        try:
            if ipaddress.ip_address(host) in ipaddress.ip_network(rule, strict=False):
                return True
        except ValueError:
            pass
    return False


def proxy_for(db: Session, url: str) -> str | None:
    config = get_proxy_config(db)
    if not config or not config.enabled:
        return None
    parts = urlsplit(url)
    if _bypassed(parts.hostname or "", config.no_proxy):
        return None
    selected = (config.https_proxy if parts.scheme == "https" else config.http_proxy) or config.http_proxy or config.https_proxy
    return proxy_with_auth(selected, config.proxy_username or "", decrypt(config.proxy_password_encrypted) or "") or None
