import tempfile
import unittest
from types import SimpleNamespace
from pathlib import Path
from unittest.mock import patch

import yaml

from app.backup import load_backup_config, save_backup_config
from app.build_planning import (
    normalize_inline_dockerfile,
    strip_generated_code_fence,
    valid_generated_dockerfile,
)
from app.config import encrypt, settings
from app.deployer import (
    apply_safe_build_repairs,
    _compose_service_container_port,
    _compose_service_mapping,
    _dockerfile_exposed_port,
    _public_path_from_value as deployer_public_path_from_value,
    analyze_repository_topology,
    reconcile_managed_integrations,
)
from app.deployment_architecture import (
    analyze_repository_topology as architecture_analyze_repository_topology,
    analyze_runtime_dependencies,
    find_compose,
)
from app.main import app
from app.source_inspection import (
    _FRONTEND_API_ENV_KEYS,
    _executable_jar_score,
    detect_frontend_api_routes,
    detect_frontend_public_base,
    detect_java_version,
)


class DeploymentSourceContractTests(unittest.TestCase):
    def test_frontend_base_repair_changes_only_isolated_vite_config(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "vite.config.ts"
            config.write_text("export default { base: '/merp/' }\n", encoding="utf-8")
            changed = apply_safe_build_repairs(directory, "frontend_public_base_mismatch")
            self.assertEqual(changed, ["vite.config.ts"])
            self.assertIn("base: '/'", config.read_text(encoding="utf-8"))

    def test_compose_port_uses_requested_multistage_target(self):
        dockerfile = (
            "FROM node:22 AS backend-runtime\nEXPOSE 8080\n"
            "FROM nginx:alpine AS frontend-runtime\nEXPOSE 80\n"
        )
        self.assertEqual(_dockerfile_exposed_port(dockerfile, "backend-runtime"), 8080)
        self.assertEqual(_dockerfile_exposed_port(dockerfile, "frontend-runtime"), 80)

    def test_compose_port_reads_final_runtime_build_definition(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".yunzhou.backend.runtime.Dockerfile").write_text(
                "FROM eclipse-temurin:17-jre\nEXPOSE 8080\n",
                encoding="utf-8",
            )
            service = {
                "build": {
                    "context": ".",
                    "dockerfile": ".yunzhou.backend.runtime.Dockerfile",
                }
            }
            self.assertEqual(_compose_service_container_port(root, service), 8080)

    def test_frontend_api_environment_keys_remain_available_to_deployer(self):
        from app import deployer

        self.assertEqual(deployer._FRONTEND_API_ENV_KEYS, _FRONTEND_API_ENV_KEYS)
        self.assertIs(deployer._executable_jar_score, _executable_jar_score)

    def test_external_database_is_injected_when_backend_has_no_environment(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "pom.xml").write_text("<project/>", encoding="utf-8")
            compose = root / ".yunzhou.compose.yml"
            compose.write_text(
                "services:\n  backend:\n    image: app:latest\n  frontend:\n    image: nginx:alpine\n",
                encoding="utf-8",
            )
            project = SimpleNamespace(
                env_text_encrypted=encrypt(
                    "YUNZHOU_MYSQL_MODE=external\n"
                    "YUNZHOU_MYSQL_HOST=db.internal\n"
                    "YUNZHOU_MYSQL_PORT=3306\n"
                    "YUNZHOU_MYSQL_DATABASE=app\n"
                    "YUNZHOU_MYSQL_USERNAME=user\n"
                    "YUNZHOU_MYSQL_PASSWORD=secret\n"
                ),
                source_analysis={"summary": "Java Spring Boot application requires Redis"},
                managed_env_text="",
                id="project-id",
                slug="project",
            )

            reconcile_managed_integrations(project, directory, compose.name)

            rendered = yaml.safe_load(compose.read_text(encoding="utf-8"))
            backend_env = rendered["services"]["backend"]["environment"]
            self.assertEqual(backend_env["DB_HOST"], "${YUNZHOU_MYSQL_HOST}")
            self.assertEqual(
                backend_env["SPRING_DATASOURCE_DRUID_MASTER_URL"],
                "jdbc:mysql://${YUNZHOU_MYSQL_HOST}:${YUNZHOU_MYSQL_PORT}/${YUNZHOU_MYSQL_DATABASE}",
            )
            self.assertEqual(backend_env["SPRING_REDIS_HOST"], "${YUNZHOU_REDIS_HOST}")
            self.assertIn("redis", rendered["services"])
            self.assertNotIn("environment", rendered["services"]["frontend"])


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
    def test_deployer_uses_shared_architecture_analyzer(self):
        self.assertIs(analyze_repository_topology, architecture_analyze_repository_topology)

    def test_runtime_dependencies_distinguish_active_config_from_library(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "requirements.txt").write_text("redis\npymysql\n", encoding="utf-8")
            (root / ".env.production").write_text("REDIS_HOST=redis\n", encoding="utf-8")
            result = analyze_runtime_dependencies(directory)
            self.assertIn("Redis", result["required"])
            self.assertIn("MySQL", result["candidates"])

    def test_compose_discovery_prefers_repository_root(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "deploy").mkdir()
            nested = root / "deploy" / "compose.yml"
            nested.write_text("services: {}\n", encoding="utf-8")
            direct = root / "compose.yaml"
            direct.write_text("services: {}\n", encoding="utf-8")
            self.assertEqual(find_compose(root), direct)

    def test_multistage_fullstack_dockerfile_is_valid_single_container(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "frontend").mkdir()
            (root / "backend").mkdir()
            (root / "frontend" / "package.json").write_text(
                '{"scripts":{"build":"vite build"},"devDependencies":{"vite":"5"}}',
                encoding="utf-8",
            )
            (root / "backend" / "requirements.txt").write_text("fastapi", encoding="utf-8")
            (root / "Dockerfile").write_text(
                "FROM node:22 AS web\nCOPY frontend/package.json ./\nRUN npm run build\n"
                "FROM python:3.12\nCOPY backend/ ./\nCOPY --from=web /app/dist /app/frontend/dist\n"
                'CMD ["python", "-m", "server"]\n',
                encoding="utf-8",
            )
            topology = analyze_repository_topology(directory, "dockerfile", "Dockerfile")
            self.assertEqual(topology["errors"], [])
            self.assertIn("多阶段构建", topology["single_container_evidence"])

    def test_plain_container_does_not_hide_unhandled_fullstack_layout(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "frontend").mkdir()
            (root / "backend").mkdir()
            (root / "frontend" / "package.json").write_text(
                '{"scripts":{"build":"vite build"},"devDependencies":{"vite":"5"}}',
                encoding="utf-8",
            )
            (root / "backend" / "requirements.txt").write_text("fastapi", encoding="utf-8")
            (root / "Dockerfile").write_text(
                'FROM python:3.12\nCOPY . .\nCMD ["python", "app.py"]\n',
                encoding="utf-8",
            )
            topology = analyze_repository_topology(directory, "dockerfile", "Dockerfile")
            self.assertTrue(topology["errors"])

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
