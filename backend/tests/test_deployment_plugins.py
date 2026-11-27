import tempfile
import unittest
from pathlib import Path

from app.deployment_build_generators import generate_profile_build, generate_static_build
from app.deployment_build_profiles import detect_build_profiles
from app.deployment_runtime_policy import data_compose_project, release_directories, validate_release
from app.deployment_runtime_ports import compose_port_number, compose_published_port, replace_compose_published_port


class DeploymentPluginTests(unittest.TestCase):
    def test_node_generator_does_not_capture_python_project(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "requirements.txt").write_text("fastapi\nuvicorn\n", encoding="utf-8")
            (root / "server.py").write_text("from fastapi import FastAPI\napp = FastAPI()\n", encoding="utf-8")
            profiles = {item.key: item for item in detect_build_profiles(root)}
            generated = generate_profile_build(root, profiles, nginx_image="nginx:alpine", java_version=lambda _: 17)
            self.assertIsNotNone(generated)
            self.assertIn("python:3.12-slim", generated.dockerfile)
            self.assertNotIn("node:22", generated.dockerfile)
            self.assertEqual(generated.port, 8000)

    def test_gradle_generator_isolated_from_maven(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "build.gradle").write_text("plugins { id 'java' }", encoding="utf-8")
            profiles = {item.key: item for item in detect_build_profiles(root)}
            generated = generate_profile_build(root, profiles, nginx_image="nginx:alpine", java_version=lambda _: 17)
            self.assertIn("gradle:8-jdk17", generated.dockerfile)
            self.assertNotIn("maven:", generated.dockerfile)

    def test_static_generator_ignores_build_artifacts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "dist").mkdir()
            (root / "dist" / "index.html").write_text("ignored", encoding="utf-8")
            self.assertIsNone(generate_static_build(root, nginx_image="nginx:alpine"))
            (root / "public").mkdir()
            (root / "public" / "index.html").write_text("ok", encoding="utf-8")
            generated = generate_static_build(root, nginx_image="nginx:alpine")
            self.assertIn("COPY public/", generated.dockerfile)

    def test_release_policy_rejects_path_traversal(self):
        self.assertEqual(validate_release("20261127.1"), "20261127.1")
        with self.assertRaisesRegex(RuntimeError, "不安全"):
            validate_release("../../etc")
        self.assertEqual(
            release_directories("/data/projects", "project-one", "legacy", "v1"),
            ["/data/projects/project-one/v1", "/data/projects/legacy/v1"],
        )
        self.assertEqual(
            release_directories("/data/projects", "pod", "pod", "v1"),
            ["/data/projects/pod/v1", "/data/projects/pod/v1"],
        )
        self.assertEqual(data_compose_project("Yunzhou Main", "crm"), "yunzhou-main-crm-data")

    def test_compose_port_forms_round_trip(self):
        self.assertEqual(compose_port_number("127.0.0.1:10002:8080/tcp"), 8080)
        self.assertEqual(compose_published_port("${APP_PORT:-10002}:8080", {"APP_PORT": "10003"}), 10003)
        self.assertEqual(replace_compose_published_port("127.0.0.1:10002:8080/tcp", 10004), "127.0.0.1:10004:8080/tcp")
        self.assertEqual(replace_compose_published_port({"target": 8080, "published": 10002}, 10004)["published"], 10004)


if __name__ == "__main__":
    unittest.main()
