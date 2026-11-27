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
        self.assertEqual(result.scope, "configuration")

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


if __name__ == "__main__":
    unittest.main()
