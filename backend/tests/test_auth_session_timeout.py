import unittest
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException
from jose import jwt

from app.auth import current_user
from app.config import settings
from app.models import Role, SecurityConfig, User


class FakeSession:
    def __init__(self, user: User, timeout_minutes: int):
        self.user = user
        self.policy = SecurityConfig(id="default", session_timeout_minutes=timeout_minutes)

    def get(self, model, key):
        if model is User and key == self.user.id:
            return self.user
        if model is SecurityConfig and key == "default":
            return self.policy
        return None


def make_token(user: User, issued_at: datetime, expires_at: datetime) -> str:
    return jwt.encode(
        {"sub": user.id, "role": user.role.value, "iat": issued_at, "exp": expires_at},
        settings.app_secret,
        algorithm="HS256",
    )


class CurrentSessionPolicyTests(unittest.TestCase):
    def setUp(self):
        self.user = User(
            id="user-1",
            username="tester",
            display_name="Tester",
            password_hash="unused",
            role=Role.deployer,
            active=True,
        )

    def test_current_policy_rejects_an_old_long_lived_token(self):
        now = datetime.now(timezone.utc)
        token = make_token(self.user, now - timedelta(minutes=61), now + timedelta(hours=23))

        with self.assertRaises(HTTPException) as raised:
            current_user(token=token, db=FakeSession(self.user, timeout_minutes=60))

        self.assertEqual(raised.exception.status_code, 401)
        self.assertEqual(raised.exception.detail, "登录已超时，请重新登录")

    def test_current_policy_accepts_a_token_within_the_timeout(self):
        now = datetime.now(timezone.utc)
        token = make_token(self.user, now - timedelta(minutes=59), now + timedelta(minutes=1))

        result = current_user(token=token, db=FakeSession(self.user, timeout_minutes=60))

        self.assertIs(result, self.user)


if __name__ == "__main__":
    unittest.main()
