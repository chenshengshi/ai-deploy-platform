import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from app.deployment.workspace import persist_verified_changes
from app.models import SourceType


class WorkspaceRepairTests(unittest.TestCase):
    def test_verified_upload_repair_is_written_to_persistent_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            persistent = root / "persistent"
            work = root / "work"
            persistent.mkdir()
            (work / "frontend").mkdir(parents=True)
            (work / "frontend" / "vite.config.js").write_text("export default { base: '/' }", encoding="utf-8")
            project = SimpleNamespace(
                source_type=SourceType.upload,
                source_path=str(persistent),
            )

            result = persist_verified_changes(
                project,
                str(work),
                "",
                ["frontend/vite.config.js"],
                "deployment-1",
            )

            self.assertIn("写回", result)
            self.assertEqual(
                "export default { base: '/' }",
                (persistent / "frontend" / "vite.config.js").read_text(encoding="utf-8"),
            )


if __name__ == "__main__":
    unittest.main()
