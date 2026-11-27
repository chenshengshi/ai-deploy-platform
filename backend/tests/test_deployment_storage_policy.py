import unittest
from pathlib import Path

from app.deployment_storage_policy import select_lru_evictions


class DeploymentStoragePolicyTests(unittest.TestCase):
    def test_oldest_cache_is_evicted_to_hard_limit(self):
        gb = 1024 ** 3
        leaves = [(1, 10 * gb, Path("old")), (2, 10 * gb, Path("middle")), (3, 10 * gb, Path("new"))]
        self.assertEqual(
            select_lru_evictions(leaves, cache_limit_bytes=20 * gb, disk_free_bytes=100 * gb, reserve_bytes=20 * gb),
            [Path("old")],
        )

    def test_free_space_floor_can_override_cache_limit(self):
        gb = 1024 ** 3
        leaves = [(1, 8 * gb, Path("old")), (2, 8 * gb, Path("new"))]
        self.assertEqual(
            select_lru_evictions(leaves, cache_limit_bytes=30 * gb, disk_free_bytes=10 * gb, reserve_bytes=20 * gb),
            [Path("old"), Path("new")],
        )

    def test_empty_cache_never_evicts_runtime_data(self):
        self.assertEqual(
            select_lru_evictions([], cache_limit_bytes=1, disk_free_bytes=0, reserve_bytes=100), [],
        )


if __name__ == "__main__":
    unittest.main()
