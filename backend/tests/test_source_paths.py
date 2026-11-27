import tempfile
import unittest
from pathlib import Path

from app.deployment.source_paths import discover_source_root, git_source_location


class SourcePathTests(unittest.TestCase):
    def test_tfs_browser_url_becomes_clone_url(self):
        clone_url, branch, path = git_source_location(
            "http://tfs.local/repo?path=/frontend&version=GBdevelop&_a=contents",
            "main",
        )
        self.assertEqual("http://tfs.local/repo", clone_url)
        self.assertEqual("develop", branch)
        self.assertEqual("frontend", path)

    def test_single_nested_project_is_selected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            nested = root / "application"
            nested.mkdir()
            (nested / "package.json").write_text("{}", encoding="utf-8")
            selected, relative = discover_source_root(root)
            self.assertEqual(nested, selected)
            self.assertEqual("application", relative)

    def test_parent_traversal_is_rejected(self):
        with self.assertRaises(RuntimeError):
            git_source_location("http://tfs.local/repo?path=../../secret", "main")


if __name__ == "__main__":
    unittest.main()
