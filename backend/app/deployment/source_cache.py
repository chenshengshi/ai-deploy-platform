"""Cross-thread and cross-process locking for the shared Git source cache."""

from __future__ import annotations

import threading
from contextlib import contextmanager
from pathlib import Path


_LOCKS: dict[str, threading.Lock] = {}
_LOCKS_GUARD = threading.Lock()


def source_cache_lock(project_id: str) -> threading.Lock:
    with _LOCKS_GUARD:
        return _LOCKS.setdefault(project_id, threading.Lock())


@contextmanager
def source_cache_guard(project_id: str, workspace_root: Path):
    """Serialize mutation of one immutable Git cache across API/worker processes."""
    thread_lock = source_cache_lock(project_id)
    with thread_lock:
        lock_handle = None
        try:
            lock_path = workspace_root / ".source-cache.lock"
            lock_handle = lock_path.open("a+")
            try:
                import fcntl
                fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
            except ImportError:
                pass
            yield
        finally:
            if lock_handle is not None:
                try:
                    import fcntl
                    fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)
                except ImportError:
                    pass
                lock_handle.close()
