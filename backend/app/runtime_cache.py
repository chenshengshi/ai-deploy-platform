import copy
import threading
import time

from .models import Deployment


RUNTIME_CACHE_TTL = 4.0
_cache: dict[tuple, tuple[float, dict]] = {}
_locks: dict[tuple, threading.Lock] = {}
_guard = threading.Lock()


def runtime_cache_key(item: Deployment) -> tuple:
    status = item.status.value if hasattr(item.status, "value") else str(item.status)
    return (item.id, status, item.release or "", item.container_name or "", item.host_port or 0)


def read_runtime_cache(key: tuple) -> dict | None:
    now = time.monotonic()
    with _guard:
        cached = _cache.get(key)
        if not cached or now - cached[0] > RUNTIME_CACHE_TTL:
            if cached:
                _cache.pop(key, None)
            return None
        return copy.deepcopy(cached[1])


def write_runtime_cache(key: tuple, value: dict) -> None:
    now = time.monotonic()
    with _guard:
        _cache[key] = (now, copy.deepcopy(value))
        if len(_cache) > 256:
            expired = [cache_key for cache_key, (saved, _) in _cache.items() if now - saved > RUNTIME_CACHE_TTL]
            for cache_key in expired:
                _cache.pop(cache_key, None)
                lock = _locks.get(cache_key)
                if lock is not None and not lock.locked():
                    _locks.pop(cache_key, None)


def runtime_cache_lock(key: tuple) -> threading.Lock:
    with _guard:
        return _locks.setdefault(key, threading.Lock())


def invalidate_runtime_cache(deployment_id: str | None = None) -> None:
    with _guard:
        for key in list(_cache):
            if deployment_id is None or key[0] == deployment_id:
                _cache.pop(key, None)
