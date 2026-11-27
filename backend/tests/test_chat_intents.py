import unittest
from types import SimpleNamespace

from app.chat.intents import fallback_action_from_message, fuzzy_project_match, is_confirmation


class ChatIntentTests(unittest.TestCase):
    def test_fallback_action_is_confirmation_gated(self):
        self.assertEqual("deploy", fallback_action_from_message("重新部署项目"))
        self.assertEqual("none", fallback_action_from_message("停止一下"))

    def test_fuzzy_project_match_tolerates_one_character_typo(self):
        projects = [
            SimpleNamespace(name="仓储", slug="warehouse"),
            SimpleNamespace(name="客户管理", slug="crm"),
        ]
        self.assertEqual("仓储", fuzzy_project_match(projects, "重新发布仓除项目").name)

    def test_confirmation_normalizes_punctuation(self):
        self.assertTrue(is_confirmation(" 确认部署！"))
        self.assertFalse(is_confirmation("先看看"))


if __name__ == "__main__":
    unittest.main()
