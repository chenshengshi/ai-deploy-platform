import unittest

from app.deployment_repair_policy import MAX_AI_RETRIES, assess_failure


class DeploymentRepairPolicyTests(unittest.TestCase):
    def test_known_runtime_failure_is_retryable(self):
        result = assess_failure("container is unhealthy")
        self.assertTrue(result.retry_safe)
        self.assertEqual(result.scope, "runtime")
        self.assertEqual(result.matched_rule, "unhealthy")

    def test_source_compilation_failure_is_not_auto_modified(self):
        result = assess_failure("Compilation failure: cannot find symbol CustomerService")
        self.assertFalse(result.retry_safe)
        self.assertEqual(result.scope, "source")

    def test_configuration_failure_is_not_guessed(self):
        result = assess_failure("authentication failed: invalid password")
        self.assertFalse(result.retry_safe)
        self.assertEqual(result.scope, "credentials")
        self.assertEqual(result.owner, "user")

    def test_ai_can_allow_bounded_retry_only_for_safe_scope(self):
        safe = assess_failure("unclassified failure", {
            "retry_safe": True,
            "scope": "platform",
            "confidence": "high",
            "summary": "平台镜像缓存暂时不可用",
        })
        unsafe = assess_failure("unclassified failure", {
            "retry_safe": True,
            "scope": "source",
            "confidence": "high",
        })
        self.assertTrue(safe.retry_safe)
        self.assertFalse(unsafe.retry_safe)

    def test_retry_budget_stays_bounded(self):
        self.assertEqual(MAX_AI_RETRIES, 2)

    def test_specific_source_error_beats_generic_timeout(self):
        result = assess_failure("request timeout\nCompilation failure: cannot find symbol OrderService")
        self.assertFalse(result.retry_safe)
        self.assertEqual(result.scope, "source")
        self.assertTrue(result.evidence)

    def test_server_capacity_is_not_blindly_retried(self):
        result = assess_failure("failed to register layer: no space left on device")
        self.assertFalse(result.retry_safe)
        self.assertEqual(result.scope, "server")
        self.assertEqual(result.owner, "operator")

    def test_inner_missing_setting_beats_outer_compose_dependency_error(self):
        result = assess_failure(
            "dependency failed to start: container api exited (1)\n"
            "后端启动失败： Error: 后端数据库配置缺失：AUTH_TOKEN_SECRET"
        )

        self.assertFalse(result.retry_safe)
        self.assertEqual(result.scope, "configuration")
        self.assertEqual(result.owner, "project")
        self.assertIn("AUTH_TOKEN_SECRET", result.reason)
        self.assertIn("AUTH_TOKEN_SECRET", result.suggested_action)
        self.assertEqual(result.matched_rule, "missing_setting")


if __name__ == "__main__":
    unittest.main()
