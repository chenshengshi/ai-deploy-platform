"""Pure storage-retention decisions used by the background worker."""
from pathlib import Path


def select_lru_evictions(
    leaves: list[tuple[float, int, Path]], *, cache_limit_bytes: int,
    disk_free_bytes: int, reserve_bytes: int,
) -> list[Path]:
    """Return oldest cache leaves until both hard limit and free-space floor hold."""
    total = sum(max(0, size) for _mtime, size, _path in leaves)
    allowed_by_free_space = max(0, disk_free_bytes + total - reserve_bytes)
    target = min(max(0, cache_limit_bytes), allowed_by_free_space)
    evictions: list[Path] = []
    for _mtime, size, path in sorted(leaves, key=lambda item: item[0]):
        if total <= target:
            break
        evictions.append(path)
        total -= max(0, size)
    return evictions
