import tempfile
import unittest
from pathlib import Path

from app.deployment_architecture import (
    analyze_repository_topology,
    analyze_runtime_dependencies,
    find_compose,
)


class DeploymentArchitectureTests(unittest.TestCase):
    def test_integrated_fullstack_dockerfile_is_one_runtime(self):
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
                "FROM python:3.12\nCOPY backend/ ./\n"
                "COPY --from=web /app/dist /app/frontend/dist\n"
                'CMD ["python", "-m", "server"]\n',
                encoding="utf-8",
            )
            topology = analyze_repository_topology(directory, "dockerfile", "Dockerfile")
            self.assertEqual(topology["errors"], [])
            self.assertIn("多阶段构建", topology["single_container_evidence"])

    def test_plain_container_rejects_unhandled_fullstack_layout(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "frontend").mkdir()
            (root / "backend").mkdir()
            (root / "frontend" / "package.json").write_text(
                '{"dependencies":{"react":"19"}}', encoding="utf-8"
            )
            (root / "backend" / "requirements.txt").write_text("fastapi", encoding="utf-8")
            (root / "Dockerfile").write_text(
                'FROM python:3.12\nCOPY . .\nCMD ["python", "app.py"]\n',
                encoding="utf-8",
            )
            topology = analyze_repository_topology(directory, "dockerfile", "Dockerfile")
            self.assertTrue(topology["errors"])

    def test_compose_reports_services_and_persistent_mounts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "web").mkdir()
            (root / "web" / "Dockerfile").write_text("FROM nginx:alpine\n", encoding="utf-8")
            (root / "compose.yaml").write_text(
                "services:\n"
                "  web:\n"
                "    build:\n"
                "      context: ./web\n"
                "      dockerfile: Dockerfile\n"
                "    volumes:\n"
                "      - content:/data\n"
                "volumes:\n"
                "  content: {}\n",
                encoding="utf-8",
            )
            topology = analyze_repository_topology(directory, "compose", "compose.yaml")
            self.assertEqual(topology["errors"], [])
            self.assertEqual(topology["services"][0]["name"], "web")
            self.assertEqual(topology["persistent_mounts"], ["content:/data"])

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


if __name__ == "__main__":
    unittest.main()
