import tempfile
import unittest
from pathlib import Path

from app.deployment.source_cache import source_cache_guard, source_cache_lock


class SourceCacheTests(unittest.TestCase):
    def test_same_project_reuses_thread_lock(self):
        self.assertIs(source_cache_lock("project-a"), source_cache_lock("project-a"))

    def test_guard_creates_process_lock_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with source_cache_guard("project-b", root):
                self.assertTrue((root / ".source-cache.lock").exists())


if __name__ == "__main__":
    unittest.main()
