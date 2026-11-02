from functools import lru_cache
from pathlib import Path

from cryptography.fernet import Fernet
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "自助发布平台"
    app_secret: str = "change-me"
    encryption_key: str = ""
    database_url: str = "postgresql+psycopg://aideploy:aideploy@db:5432/aideploy"
    upload_root: str = "/data/uploads"
    backup_root: str = "/data/backups"
    build_data_root: str = "/data/yunzhou"
    # 0 means unlimited. Reusable caches are only evicted when the builder
    # would otherwise cross the minimum-free-space safety floor.
    build_cache_max_gb: int = 0
    docker_build_cache_keep_gb: int = 10
    builder_min_free_gb: int = 20
    builder_workspace_ttl_hours: int = 6
    builder_artifact_ttl_hours: int = 24
    admin_username: str = "admin"
    admin_password: str = "Qwer1234"
    admin_name: str = "系统管理员"
    token_expire_minutes: int = 1440
    # Browser UI is same-origin by default.  Cross-origin callers must be
    # explicitly listed as a comma-separated allowlist in CORS_ORIGINS.
    cors_origins: str = ""
    worker_poll_seconds: int = 2
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    @property
    def fernet_key(self) -> bytes:
        if self.encryption_key:
            return self.encryption_key.encode()
        import base64
        import hashlib

        return base64.urlsafe_b64encode(hashlib.sha256(self.app_secret.encode()).digest())

    def ensure_dirs(self) -> None:
        Path(self.upload_root).mkdir(parents=True, exist_ok=True)
        Path(self.backup_root).mkdir(parents=True, exist_ok=True)
        root = Path(self.build_data_root)
        for relative in (
            "projects", "builder/projects",
        ):
            (root / relative).mkdir(parents=True, exist_ok=True)


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
cipher = Fernet(settings.fernet_key)


def encrypt(value: str | None) -> str | None:
    if not value:
        return None
    return cipher.encrypt(value.encode()).decode()


def decrypt(value: str | None) -> str | None:
    if not value:
        return None
    return cipher.decrypt(value.encode()).decode()

