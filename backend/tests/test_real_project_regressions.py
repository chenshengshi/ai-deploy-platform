"""Sanitized regressions distilled from verified production project layouts."""
import tempfile
import unittest
from pathlib import Path

from app.deployment.architecture import analyze_repository_topology
from app.deployment.repair_policy import assess_failure
from app.deployment.runtime_policy import release_directories
from app.deployment.topology import add_unambiguous_nginx_aliases, repair_generated_node_dependency_copy


class RealProjectRegressionTests(unittest.TestCase):
    def test_pod_integrated_release_and_same_slug_rollback_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "frontend").mkdir()
            (root / "backend").mkdir()
            (root / "frontend/package.json").write_text('{"scripts":{"build":"vite build"}}', encoding="utf-8")
            (root / "backend/requirements.txt").write_text("fastapi\n", encoding="utf-8")
            (root / "Dockerfile").write_text(
                "FROM node:22 AS web\nCOPY frontend/ /app\nRUN npm run build\n"
                "FROM python:3.12\nCOPY backend/ /app\nCOPY --from=web /app/dist /app/static\n"
                'CMD ["python", "-m", "server"]\n', encoding="utf-8",
            )
            plan = analyze_repository_topology(directory, "dockerfile", "Dockerfile")
            self.assertEqual(plan["errors"], [])
            self.assertTrue(plan["single_container_evidence"])
        self.assertEqual(
            release_directories("/data/projects", "pod", "pod", "202611270949"),
            ["/data/projects/pod/202611270949", "/data/projects/pod/202611270949"],
        )

    def test_warehouse_legacy_upstream_gets_safe_backend_alias(self):
        services = {
            "frontend": {"image": "nginx:alpine"},
            "backend": {"build": "./server"},
            "mysql": {"image": "mysql:8.4"},
        }
        repairs = add_unambiguous_nginx_aliases(services, {"wmsapi"})
        self.assertEqual(repairs, [("wmsapi", "backend")])
        self.assertIn("wmsapi", services["backend"]["networks"]["default"]["aliases"])

    def test_ambiguous_upstream_is_reported_instead_of_guessed(self):
        services = {
            "frontend": {"image": "nginx:alpine"},
            "orders": {"build": "./orders"},
            "users": {"build": "./users"},
        }
        self.assertEqual(add_unambiguous_nginx_aliases(services, {"api"}), [])

    def test_generated_node_runtime_never_copies_host_dependencies(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dockerfile = root / ".yunzhou.api.Dockerfile"
            dockerfile.write_text(
                "FROM node:22-alpine\nCOPY package.json ./package.json\n"
                "COPY node_modules/ ./node_modules\nCOPY server.js ./server.js\n",
                encoding="utf-8",
            )
            self.assertTrue(repair_generated_node_dependency_copy(root, dockerfile))
            text = dockerfile.read_text(encoding="utf-8")
            self.assertIn("npm install", text)
            self.assertNotIn("COPY node_modules", text)

    def test_real_engine_and_source_failures_have_different_owners(self):
        engine = assess_failure("failed to prepare extraction snapshot: lease does not exist")
        source = assess_failure("COPY failed\nCompilation error: cannot find symbol InventoryService")
        self.assertEqual((engine.scope, engine.owner, engine.retry_safe), ("platform", "platform", True))
        self.assertEqual((source.scope, source.owner, source.retry_safe), ("source", "project", False))


if __name__ == "__main__":
    unittest.main()
