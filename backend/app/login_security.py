import ipaddress
import threading
import time

from fastapi import HTTPException, Request


LOGIN_WINDOW_SECONDS = 15 * 60
LOGIN_MAX_FAILURES_PER_IP = 10
_failures_by_ip: dict[str, list[float]] = {}
_guard = threading.Lock()


def login_source_ip(request: Request) -> str:
    """Return the proxy-normalized client address used for login throttling."""
    forwarded = request.headers.get("x-real-ip", "").strip()
    if forwarded:
        try:
            return str(ipaddress.ip_address(forwarded))
        except ValueError:
            pass
    return request.client.host if request.client else "unknown"


def _active_failures(source_ip: str, now: float) -> list[float]:
    cutoff = now - LOGIN_WINDOW_SECONDS
    return [stamp for stamp in _failures_by_ip.get(source_ip, []) if stamp > cutoff]


def enforce_login_source_limit(source_ip: str) -> None:
    now = time.monotonic()
    with _guard:
        failures = _active_failures(source_ip, now)
        if failures:
            _failures_by_ip[source_ip] = failures
        else:
            _failures_by_ip.pop(source_ip, None)
        if len(failures) >= LOGIN_MAX_FAILURES_PER_IP:
            retry_after = max(1, int(LOGIN_WINDOW_SECONDS - (now - failures[0])))
            raise HTTPException(
                status_code=429,
                detail="登录尝试过于频繁，请稍后重试",
                headers={"Retry-After": str(retry_after)},
            )


def record_login_failure(source_ip: str) -> None:
    now = time.monotonic()
    with _guard:
        failures = _active_failures(source_ip, now)
        failures.append(now)
        _failures_by_ip[source_ip] = failures


def clear_login_failures(source_ip: str) -> None:
    with _guard:
        _failures_by_ip.pop(source_ip, None)
