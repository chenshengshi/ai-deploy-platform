import unittest
from types import SimpleNamespace

from app.deployment.naming import compose_project_name, deployment_compose_project_name, service_container_name


class DeploymentNamingTests(unittest.TestCase):
    def test_release_names_are_isolated(self):
        self.assertEqual("yunzhou-pod-202611271527", compose_project_name("pod", "202611271527"))

    def test_recorded_namespace_is_preserved(self):
        deployment = SimpleNamespace(release="202611271527", container_name="custom-pod-202611271527-app-1")
        project = SimpleNamespace(slug="pod")
        self.assertEqual("custom-pod-202611271527", deployment_compose_project_name(deployment, project))

    def test_service_name_is_sanitized(self):
        self.assertEqual("yunzhou-pod-v1-web-api-2", service_container_name("pod", "Web API", 2, "v1"))


if __name__ == "__main__":
    unittest.main()
