import json
import tempfile
import unittest
from pathlib import Path

from app.deployment_source_repairs import (
    build_source_patch,
    persist_repair_bundle,
    repair_bundle_summary,
    snapshot_text_sources,
)


class DeploymentSourceRepairTests(unittest.TestCase):
    def test_patch_records_source_change_but_ignores_generated_and_dependencies(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text("value = 1\n", encoding="utf-8")
            (root / "node_modules").mkdir()
            (root / "node_modules/x.js").write_text("old", encoding="utf-8")
            before = snapshot_text_sources(root)
            (root / "app.py").write_text("value = 2\n", encoding="utf-8")
            (root / ".yunzhou.Dockerfile").write_text("FROM python:3.12\n", encoding="utf-8")
            patch = build_source_patch(before, root)
            self.assertIn("-value = 1", patch)
            self.assertIn("+value = 2", patch)
            self.assertNotIn("node_modules", patch)
            self.assertNotIn(".yunzhou", patch)

    def test_each_slot_is_bounded_to_one_bundle(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for deployment_id in ("first-deployment", "second-deployment"):
                persist_repair_bundle(
                    root, project_slug="pod", deployment_id=deployment_id,
                    patch=f"patch-{deployment_id}\n", verified=True,
                    report={"summary": deployment_id}, verification_lines=["verified"],
                )
            summaries = repair_bundle_summary(root, "pod")
            self.assertEqual(len(summaries), 1)
            self.assertEqual(summaries[0]["deployment_id"], "second-deployment")
            self.assertEqual((root / "pod/verified/changes.patch").read_text(), "patch-second-deployment\n")

    def test_failed_and_verified_slots_are_independent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            persist_repair_bundle(root, project_slug="crm", deployment_id="ok", patch="ok\n", verified=True, report={}, verification_lines=[])
            persist_repair_bundle(root, project_slug="crm", deployment_id="bad", patch="bad\n", verified=False, report={}, verification_lines=[])
            self.assertEqual({item["status"] for item in repair_bundle_summary(root, "crm")}, {"verified", "failed"})


if __name__ == "__main__":
    unittest.main()
