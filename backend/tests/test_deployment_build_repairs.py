import unittest

from app.deployment.build_repairs import apply_dockerfile_text_repairs


class DeploymentBuildRepairTests(unittest.TestCase):
    def apply(self, text: str, error: str = "") -> tuple[str, list[str]]:
        return apply_dockerfile_text_repairs(
            text,
            error,
            nginx_image="nginx:1.30.6-alpine",
        )

    def test_pins_moving_nginx_runtime(self):
        repaired, rules = self.apply("FROM nginx:alpine\n")
        self.assertEqual(repaired, "FROM nginx:1.30.6-alpine\n")
        self.assertIn("pin_nginx_runtime", rules)

    def test_strips_only_buildkit_cache_prefix(self):
        repaired, rules = self.apply(
            "FROM node:22\nRUN --mount=type=cache,target=/root/.npm npm ci\n"
        )
        self.assertIn("RUN npm ci", repaired)
        self.assertIn("strip_buildkit_cache_mount", rules)

    def test_missing_optional_public_copy_is_removed_with_exact_evidence(self):
        dockerfile = (
            "FROM node:22 AS build\n"
            "FROM node:22\n"
            "COPY --from=build /app/public ./public\n"
            "COPY --from=build /app/dist ./dist\n"
        )
        repaired, rules = self.apply(
            dockerfile,
            "COPY failed: stat /app/public: file does not exist",
        )
        self.assertNotIn("/app/public", repaired)
        self.assertIn("/app/dist", repaired)
        self.assertIn("remove_missing_optional_stage_copy", rules)

    def test_missing_required_dist_copy_is_never_removed(self):
        dockerfile = "COPY --from=build /app/dist ./dist\n"
        repaired, rules = self.apply(
            dockerfile,
            "COPY failed: stat /app/dist: file does not exist",
        )
        self.assertEqual(repaired, dockerfile)
        self.assertNotIn("remove_missing_optional_stage_copy", rules)

    def test_maven_multimodule_lookup_requires_matching_failure(self):
        dockerfile = (
            "RUN find target -name '*.jar' ! -name 'original-*' -type f | "
            "head -n 1\n"
        )
        unchanged, _ = self.apply(dockerfile)
        repaired, rules = self.apply(
            dockerfile,
            "find: 'target': No such file or directory",
        )
        self.assertEqual(unchanged, dockerfile)
        self.assertIn("*/target/*.jar", repaired)
        self.assertIn("repair_maven_module_artifact_lookup", rules)


if __name__ == "__main__":
    unittest.main()
