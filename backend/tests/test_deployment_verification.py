import unittest

from app.deployment.verification import frontend_code_warning, has_fatal_startup_error, http_status_accepted


class DeploymentVerificationTests(unittest.TestCase):
    def test_authentication_statuses_are_reachable(self):
        self.assertTrue(http_status_accepted("200"))
        self.assertTrue(http_status_accepted("401"))
        self.assertTrue(http_status_accepted("403"))
        self.assertFalse(http_status_accepted("404"))
        self.assertFalse(http_status_accepted("000"))

    def test_frontend_base_problem_is_a_code_warning(self):
        detail = frontend_code_warning({"evidence": [{
            "reference": "/merp/assets/app.js",
            "content_type": "text/html",
            "working_path": "/assets/app.js",
        }]})
        self.assertIn("frontend_public_base_mismatch", detail)
        self.assertIn("/assets/app.js", detail)

    def test_deterministic_startup_error_stops_retries(self):
        self.assertTrue(has_fatal_startup_error("APPLICATION RUN FAILED"))
        self.assertFalse(has_fatal_startup_error("server is warming up"))


if __name__ == "__main__":
    unittest.main()
