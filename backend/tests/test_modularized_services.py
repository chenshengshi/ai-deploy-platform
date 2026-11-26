import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.backup import load_backup_config, save_backup_config
from app.build_planning import (
    normalize_inline_dockerfile,
    strip_generated_code_fence,
    valid_generated_dockerfile,
)
from app.config import settings
from app.deployer import _compose_service_mapping, _public_path_from_value as deployer_public_path_from_value
from app.main import app
from app.source_inspection import (
    detect_frontend_api_routes,
    detect_frontend_public_base,
    detect_java_version,
)


class BackupModuleTests(unittest.TestCase):
    def test_backup_routes_are_registered_once(self):
        routes = [
            (route.path, method)
            for route in app.routes
            for method in (getattr(route, "methods", None) or set())
        ]
        for route in (
            ("/api/settings/backups", "GET"),
            ("/api/settings/backups", "POST"),
            ("/api/settings/backups/schedule", "PUT"),
            ("/api/settings/backups/{name}/download", "GET"),
            ("/api/settings/backups/{name}", "DELETE"),
        ):
            self.assertEqual(routes.count(route), 1, route)

    def test_backup_config_round_trip_keeps_defaults(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(settings, "backup_root", directory):
                self.assertEqual(load_backup_config()["time"], "02:00")
                save_backup_config({"enabled": True, "time": "03:15", "retention": 7})
                saved = load_backup_config()
                self.assertTrue(saved["enabled"])
                self.assertEqual(saved["time"], "03:15")
                self.assertEqual(saved["retention"], 7)
                self.assertIsNone(saved["last_run_date"])


class SourceInspectionModuleTests(unittest.TestCase):
    def test_deployer_can_use_shared_public_path_normalizer(self):
        self.assertEqual(deployer_public_path_from_value("https://example.com/prod-api/"), "/prod-api")

    def test_detects_declared_java_version(self):
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "pom.xml").write_text(
                "<project><properties><java.version>11</java.version></properties></project>",
                encoding="utf-8",
            )
            self.assertEqual(detect_java_version(directory), 11)

    def test_detects_frontend_api_and_public_base(self):
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, ".env.production").write_text(
                "VITE_API_BASE_URL=/prod-api\nVITE_APP_BASE=/portal/\n",
                encoding="utf-8",
            )
            self.assertEqual(detect_frontend_api_routes(directory)["primary_path"], "/prod-api")
            self.assertEqual(detect_frontend_public_base(directory)["primary_path"], "/portal/")


class BuildPlanningModuleTests(unittest.TestCase):
    def test_compose_service_mapping_accepts_compose_document(self):
        services = {"web": {"image": "nginx"}}
        self.assertEqual(_compose_service_mapping({"services": services}), services)

    def test_compose_service_mapping_ignores_dockerfile_scalar(self):
        self.assertEqual(_compose_service_mapping("FROM node:22\nRUN npm ci"), {})

    def test_compose_service_mapping_ignores_invalid_services_type(self):
        self.assertEqual(_compose_service_mapping({"services": "web"}), {})

    def test_generated_dockerfile_validation_rejects_compose_yaml(self):
        self.assertTrue(valid_generated_dockerfile("FROM node:22\nRUN npm ci\n"))
        self.assertFalse(valid_generated_dockerfile("services:\n  web:\n    image: nginx\n"))

    def test_generated_dockerfile_normalization_is_stable(self):
        raw = "# syntax=docker/dockerfile:1\nFROM node:22\nRUN --mount=type=cache,target=/root/.npm corepack prepare pnpm@9 --activate\n"
        normalized = normalize_inline_dockerfile(raw)
        self.assertNotIn("--mount=type=cache", normalized)
        self.assertIn("pnpm@9.15.9", normalized)

    def test_code_fence_is_removed(self):
        self.assertEqual(strip_generated_code_fence("```dockerfile\nFROM alpine\n```"), "FROM alpine")


if __name__ == "__main__":
    unittest.main()
