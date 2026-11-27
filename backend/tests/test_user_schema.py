import unittest

from pydantic import ValidationError

from app.models import Role
from app.schemas import UserCreate, UserUpdate


class UserSchemaTests(unittest.TestCase):
    def test_new_user_defaults_to_deployer_and_accepts_chinese_name(self):
        user = UserCreate(username="zhangsan", display_name="张三", password="password123")

        self.assertEqual(user.role, Role.deployer)
        self.assertEqual(user.display_name, "张三")

    def test_new_user_rejects_non_chinese_display_name(self):
        with self.assertRaises(ValidationError):
            UserCreate(username="zhangsan", display_name="Zhang San", password="password123")

    def test_new_user_rejects_chinese_or_spaced_login_account(self):
        for username in ("张三", "zhang san", "123zhang"):
            with self.subTest(username=username), self.assertRaises(ValidationError):
                UserCreate(username=username, display_name="张三", password="password123")

    def test_existing_user_can_be_updated_without_changing_name(self):
        update = UserUpdate(active=True)

        self.assertIsNone(update.display_name)


if __name__ == "__main__":
    unittest.main()
