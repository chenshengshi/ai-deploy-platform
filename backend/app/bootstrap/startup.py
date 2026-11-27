"""Database bootstrap, schema compatibility migrations, and initial data seeding."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import select, text

from ..auth import hash_password
from ..backup import start_backup_scheduler
from ..config import decrypt, encrypt, settings
from ..database import Base, SessionLocal, engine
from ..experience import contains_corruption, prepare_new_experience
from ..models import AiConfig, DeploymentExperience, Project, Role, User

def startup():
    settings.ensure_dirs()
    Base.metadata.create_all(engine)
    with engine.connect() as connection:
        schema_ready = bool(connection.scalar(text(
            "SELECT 1 FROM information_schema.columns WHERE table_schema='public' "
            "AND table_name='projects' AND column_name='integration_analysis_json'"
        )))
    if not schema_ready:
        with engine.begin() as connection:
            connection.execute(text("ALTER TABLE deployment_settings ADD COLUMN IF NOT EXISTS external_port_start INTEGER NOT NULL DEFAULT 20000"))
            connection.execute(text("ALTER TABLE deployment_settings ADD COLUMN IF NOT EXISTS external_port_end INTEGER NOT NULL DEFAULT 21000"))
            connection.execute(text("ALTER TABLE deployment_settings ADD COLUMN IF NOT EXISTS internal_port_start INTEGER NOT NULL DEFAULT 30000"))
            connection.execute(text("ALTER TABLE deployment_settings ADD COLUMN IF NOT EXISTS internal_port_end INTEGER NOT NULL DEFAULT 39999"))
            connection.execute(text("ALTER TABLE deployment_settings ADD COLUMN IF NOT EXISTS default_domain_http_port INTEGER NOT NULL DEFAULT 80"))
            connection.execute(text("ALTER TABLE deployment_settings ADD COLUMN IF NOT EXISTS default_domain_https_port INTEGER NOT NULL DEFAULT 443"))
            connection.execute(text("ALTER TABLE deployment_settings ADD COLUMN IF NOT EXISTS registry_mirrors_text TEXT NOT NULL DEFAULT ''"))
            connection.execute(text("ALTER TABLE deployment_settings ADD COLUMN IF NOT EXISTS system_name VARCHAR(100) NOT NULL DEFAULT '自助发布平台'"))
            connection.execute(text("ALTER TABLE deployment_settings ADD COLUMN IF NOT EXISTS short_name VARCHAR(40) NOT NULL DEFAULT '自助发布'"))
            connection.execute(text("ALTER TABLE deployment_settings ADD COLUMN IF NOT EXISTS system_subtitle VARCHAR(120) NOT NULL DEFAULT '应用交付平台'"))
            connection.execute(text("UPDATE deployment_settings SET system_name='自助发布平台', short_name='自助发布', system_subtitle='应用交付平台' WHERE system_name='云舟 AI 发布平台' OR short_name='云舟'"))
            connection.execute(text("ALTER TABLE deployment_settings ADD COLUMN IF NOT EXISTS login_slogan VARCHAR(200) NOT NULL DEFAULT '一句话，把项目安全发布到服务器'"))
            connection.execute(text("ALTER TABLE deployment_settings ADD COLUMN IF NOT EXISTS logo_data_url TEXT NOT NULL DEFAULT ''"))
            connection.execute(text("ALTER TABLE deployment_settings ADD COLUMN IF NOT EXISTS favicon_data_url TEXT NOT NULL DEFAULT ''"))
            connection.execute(text("ALTER TABLE system_proxy ADD COLUMN IF NOT EXISTS proxy_username VARCHAR(255) NOT NULL DEFAULT ''"))
            connection.execute(text("ALTER TABLE system_proxy ADD COLUMN IF NOT EXISTS proxy_password_encrypted TEXT"))
            connection.execute(text("ALTER TABLE deployments ADD COLUMN IF NOT EXISTS login_info_json TEXT"))
            connection.execute(text("ALTER TABLE projects ADD COLUMN IF NOT EXISTS load_balance_enabled BOOLEAN NOT NULL DEFAULT FALSE"))
            connection.execute(text("ALTER TABLE projects ADD COLUMN IF NOT EXISTS replica_count INTEGER NOT NULL DEFAULT 2"))
            connection.execute(text("ALTER TABLE projects ADD COLUMN IF NOT EXISTS load_balance_strategy VARCHAR(32) NOT NULL DEFAULT 'round_robin'"))
            connection.execute(text("ALTER TABLE projects ADD COLUMN IF NOT EXISTS deployment_mode VARCHAR(32) NOT NULL DEFAULT 'managed_fresh'"))
            connection.execute(text("ALTER TABLE projects ADD COLUMN IF NOT EXISTS release_strategy VARCHAR(32) NOT NULL DEFAULT 'auto'"))
            connection.execute(text("ALTER TABLE projects ADD COLUMN IF NOT EXISTS managed_env_text TEXT"))
            connection.execute(text("ALTER TABLE projects ADD COLUMN IF NOT EXISTS integration_analysis_json TEXT"))
            connection.execute(text("ALTER TABLE nodes ADD COLUMN IF NOT EXISTS docker_proxy_enabled BOOLEAN NOT NULL DEFAULT FALSE"))
            connection.execute(text("ALTER TABLE nodes ADD COLUMN IF NOT EXISTS docker_proxy_status VARCHAR(32) NOT NULL DEFAULT 'disabled'"))
            connection.execute(text("ALTER TABLE nodes ADD COLUMN IF NOT EXISTS docker_proxy_error TEXT"))
    # New optional columns must be migrated even after the original schema
    # marker already exists on long-running installations.
    with engine.begin() as connection:
        connection.execute(text("ALTER TABLE projects ADD COLUMN IF NOT EXISTS release_strategy VARCHAR(32) NOT NULL DEFAULT 'auto'"))
        connection.execute(text("COMMENT ON COLUMN projects.release_strategy IS '发布方式：auto 自动优先源码 Compose，source_compose 使用源码 Compose，platform_generated 使用平台生成方案'"))
        # Service-level scaling was introduced after the original project
        # schema marker.  Keep these migrations outside ``schema_ready`` so
        # an existing installation cannot start with an older replicas table.
        connection.execute(text("ALTER TABLE project_replicas ADD COLUMN IF NOT EXISTS service_name VARCHAR(120) NOT NULL DEFAULT ''"))
        connection.execute(text("ALTER TABLE project_replicas ADD COLUMN IF NOT EXISTS pool_role VARCHAR(32) NOT NULL DEFAULT 'entry'"))
        connection.execute(text("ALTER TABLE project_replicas ADD COLUMN IF NOT EXISTS container_port INTEGER"))
        connection.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS failed_login_attempts INTEGER NOT NULL DEFAULT 0"))
        connection.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS locked_until TIMESTAMPTZ"))
        connection.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS password_changed_at TIMESTAMPTZ"))
        connection.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMPTZ"))
        connection.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login_ip VARCHAR(64) NOT NULL DEFAULT ''"))
        connection.execute(text("ALTER TABLE git_credentials ADD COLUMN IF NOT EXISTS owner_id VARCHAR(36)"))
        connection.execute(text("CREATE INDEX IF NOT EXISTS ix_git_credentials_owner_id ON git_credentials (owner_id)"))
        connection.execute(text("ALTER TABLE git_credentials DROP CONSTRAINT IF EXISTS git_credentials_name_key"))
        connection.execute(text("""
            UPDATE git_credentials
            SET owner_id = (
                SELECT id FROM users WHERE role = 'admin' ORDER BY created_at ASC LIMIT 1
            )
            WHERE owner_id IS NULL
        """))
        connection.execute(text("""
            DO $$ BEGIN
                IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'uq_git_credentials_owner_name') THEN
                    ALTER TABLE git_credentials ADD CONSTRAINT uq_git_credentials_owner_name UNIQUE (owner_id, name);
                END IF;
            END $$
        """))
        connection.execute(text("ALTER TABLE chat_messages ADD COLUMN IF NOT EXISTS elapsed_ms INTEGER"))
        connection.execute(text("COMMENT ON COLUMN chat_messages.elapsed_ms IS 'AI 回答从接收请求到生成完成的耗时，单位毫秒'"))
        connection.execute(text("COMMENT ON COLUMN users.last_login_at IS '用户最近一次成功登录时间'"))
        connection.execute(text("COMMENT ON COLUMN users.last_login_ip IS '用户最近一次成功登录来源 IP'"))
        connection.execute(text("ALTER TABLE security_config ADD COLUMN IF NOT EXISTS audit_retention_days INTEGER NOT NULL DEFAULT 180"))
        connection.execute(text("UPDATE users SET password_changed_at=COALESCE(password_changed_at, created_at, NOW())"))
        connection.execute(text("ALTER TABLE project_domain_configs ADD COLUMN IF NOT EXISTS certificate_id VARCHAR(36)"))
        connection.execute(text("ALTER TABLE project_domain_configs ADD COLUMN IF NOT EXISTS gateway_mode VARCHAR(24) NOT NULL DEFAULT 'auto'"))
        connection.execute(text("ALTER TABLE project_domain_configs ADD COLUMN IF NOT EXISTS custom_routes_json TEXT NOT NULL DEFAULT '[]'"))
        connection.execute(text("ALTER TABLE project_domain_configs ADD COLUMN IF NOT EXISTS proxy_read_timeout INTEGER NOT NULL DEFAULT 300"))
        connection.execute(text("ALTER TABLE project_domain_configs ADD COLUMN IF NOT EXISTS client_max_body_mb INTEGER NOT NULL DEFAULT 50"))
        connection.execute(text("ALTER TABLE projects ADD COLUMN IF NOT EXISTS image_retention_count INTEGER NOT NULL DEFAULT 5"))
        connection.execute(text("ALTER TABLE projects ADD COLUMN IF NOT EXISTS visit_path VARCHAR(500) NOT NULL DEFAULT ''"))
        connection.execute(text("COMMENT ON COLUMN projects.visit_path IS '点击项目访问按钮时追加的站内路径；不参与 Nginx 路由转发'"))
        connection.execute(text("ALTER TABLE projects ADD COLUMN IF NOT EXISTS data_exposure_json TEXT NOT NULL DEFAULT '{}'"))
        connection.execute(text("ALTER TABLE projects ADD COLUMN IF NOT EXISTS runtime_image_overrides_json TEXT NOT NULL DEFAULT '{}'"))
        connection.execute(text("ALTER TABLE projects ADD COLUMN IF NOT EXISTS git_repositories_json TEXT NOT NULL DEFAULT '[]'"))
        connection.execute(text("ALTER TABLE deployment_settings ADD COLUMN IF NOT EXISTS registry_retention_count INTEGER NOT NULL DEFAULT 5"))
        connection.execute(text("ALTER TABLE deployment_settings ADD COLUMN IF NOT EXISTS registry_auto_cleanup BOOLEAN NOT NULL DEFAULT TRUE"))
        connection.execute(text("ALTER TABLE deployment_settings ADD COLUMN IF NOT EXISTS registry_endpoint VARCHAR(255) NOT NULL DEFAULT 'yunzhou.hub:5000'"))
        connection.execute(text("ALTER TABLE deployment_settings ADD COLUMN IF NOT EXISTS registry_namespace VARCHAR(100) NOT NULL DEFAULT 'yunzhou'"))
        connection.execute(text("ALTER TABLE deployment_settings ADD COLUMN IF NOT EXISTS analysis_concurrency INTEGER NOT NULL DEFAULT 2"))
        connection.execute(text("ALTER TABLE deployment_settings ADD COLUMN IF NOT EXISTS build_cache_root VARCHAR(500) NOT NULL DEFAULT '/data/yunzhou/builder/cache'"))
        connection.execute(text("ALTER TABLE deployment_settings ADD COLUMN IF NOT EXISTS build_cache_max_gb INTEGER NOT NULL DEFAULT 30"))
        connection.execute(text("ALTER TABLE deployment_settings ADD COLUMN IF NOT EXISTS builder_min_free_gb INTEGER NOT NULL DEFAULT 20"))
        connection.execute(text("ALTER TABLE deployment_settings ADD COLUMN IF NOT EXISTS builder_workspace_ttl_hours INTEGER NOT NULL DEFAULT 6"))
        connection.execute(text("ALTER TABLE deployment_settings ADD COLUMN IF NOT EXISTS docker_build_cache_keep_gb INTEGER NOT NULL DEFAULT 10"))
        connection.execute(text("ALTER TABLE deployment_settings ADD COLUMN IF NOT EXISTS maven_cache_dir VARCHAR(255) NOT NULL DEFAULT '/root/.m2'"))
        connection.execute(text("ALTER TABLE deployment_settings ADD COLUMN IF NOT EXISTS gradle_cache_dir VARCHAR(255) NOT NULL DEFAULT '/home/gradle/.gradle'"))
        connection.execute(text("ALTER TABLE deployment_settings ADD COLUMN IF NOT EXISTS npm_cache_dir VARCHAR(255) NOT NULL DEFAULT '/root/.npm'"))
        connection.execute(text("ALTER TABLE deployment_settings ADD COLUMN IF NOT EXISTS pnpm_cache_dir VARCHAR(255) NOT NULL DEFAULT '/root/.local/share/pnpm/store'"))
        connection.execute(text("ALTER TABLE deployment_settings ADD COLUMN IF NOT EXISTS yarn_cache_dir VARCHAR(255) NOT NULL DEFAULT '/root/.cache/yarn'"))
        connection.execute(text("ALTER TABLE deployment_settings ADD COLUMN IF NOT EXISTS pip_cache_dir VARCHAR(255) NOT NULL DEFAULT '/root/.cache/pip'"))
        connection.execute(text("ALTER TABLE deployment_settings ADD COLUMN IF NOT EXISTS default_nginx_image VARCHAR(255) NOT NULL DEFAULT 'nginx:1.30.3-alpine'"))
        connection.execute(text("UPDATE deployment_settings SET default_nginx_image = 'nginx:1.30.3-alpine' WHERE default_nginx_image IN ('nginx:1.30.6-alpine', 'nginx:1.30.6')"))
        connection.execute(text("ALTER TABLE deployment_settings ADD COLUMN IF NOT EXISTS default_redis_image VARCHAR(255) NOT NULL DEFAULT 'redis:7.4-alpine'"))
        connection.execute(text("ALTER TABLE deployment_settings ADD COLUMN IF NOT EXISTS default_mysql_image VARCHAR(255) NOT NULL DEFAULT 'mysql:8.4'"))
        connection.execute(text("ALTER TABLE deployment_settings ADD COLUMN IF NOT EXISTS default_postgres_image VARCHAR(255) NOT NULL DEFAULT 'postgres:16'"))
        connection.execute(text("ALTER TABLE ai_configs ADD COLUMN IF NOT EXISTS is_default BOOLEAN NOT NULL DEFAULT FALSE"))
        connection.execute(text("ALTER TABLE chat_sessions ADD COLUMN IF NOT EXISTS ai_config_id VARCHAR(36)"))
        connection.execute(text("ALTER TABLE deployment_experiences ADD COLUMN IF NOT EXISTS state VARCHAR(24) NOT NULL DEFAULT 'candidate'"))
        connection.execute(text("ALTER TABLE deployment_experiences ADD COLUMN IF NOT EXISTS enabled BOOLEAN NOT NULL DEFAULT TRUE"))
        connection.execute(text("ALTER TABLE deployment_experiences ADD COLUMN IF NOT EXISTS stage VARCHAR(32) NOT NULL DEFAULT 'deployment'"))
        connection.execute(text("ALTER TABLE deployment_experiences ADD COLUMN IF NOT EXISTS scope_tags TEXT NOT NULL DEFAULT '[]'"))
        connection.execute(text("ALTER TABLE deployment_experiences ADD COLUMN IF NOT EXISTS confidence INTEGER NOT NULL DEFAULT 0"))
        connection.execute(text("ALTER TABLE deployment_experiences ADD COLUMN IF NOT EXISTS use_count INTEGER NOT NULL DEFAULT 0"))
        connection.execute(text("ALTER TABLE deployment_experiences ADD COLUMN IF NOT EXISTS last_used_at TIMESTAMPTZ"))
        connection.execute(text("UPDATE deployment_experiences SET state=CASE WHEN verified THEN 'verified' ELSE 'candidate' END WHERE state='' OR state IS NULL OR (verified AND state='candidate')"))
        connection.execute(text("UPDATE deployment_experiences SET state='quarantined', enabled=FALSE WHERE position(chr(65533) in COALESCE(error_sample, '')) > 0 OR position(chr(65533) in COALESCE(repair_summary, '')) > 0"))
        connection.execute(text(
            "WITH ranked AS (SELECT id, ROW_NUMBER() OVER (ORDER BY provider_name, id) AS rn "
            "FROM ai_configs WHERE is_default = TRUE) "
            "UPDATE ai_configs SET is_default = FALSE WHERE id IN (SELECT id FROM ranked WHERE rn > 1)"
        ))
        connection.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS uq_ai_configs_single_default ON ai_configs (is_default) WHERE is_default = TRUE"))
    with SessionLocal() as db:
        # Ship only sanitized cross-project deployment knowledge.  Fresh
        # installations can reuse verified fixes and failure counterexamples
        # without importing users, projects, chats, credentials or secrets.
        seed_path = Path(__file__).with_name("deployment_experiences.json")
        if seed_path.exists():
            try:
                seed_rows = json.loads(seed_path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                seed_rows = []
            existing_rows = {item.signature: item for item in db.scalars(select(DeploymentExperience)).all()}
            existing_signatures = set(existing_rows)
            for row in seed_rows if isinstance(seed_rows, list) else []:
                signature = str(row.get("signature") or "").strip()
                if not signature:
                    continue
                def seed_time(key: str):
                    value = row.get(key)
                    if not value:
                        return None
                    try:
                        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
                    except ValueError:
                        return None
                experience = existing_rows.get(signature)
                if experience and not (contains_corruption(experience.error_sample) or contains_corruption(experience.repair_summary)):
                    continue
                if not experience:
                    experience = DeploymentExperience(signature=signature)
                experience.category = str(row.get("category") or "unknown")[:64]
                experience.error_sample = str(row.get("error_sample") or "")
                experience.repair_summary = str(row.get("repair_summary") or "")
                experience.occurrences = max(1, int(row.get("occurrences") or 1))
                experience.successful_repairs = max(0, int(row.get("successful_repairs") or 0))
                experience.failed_repairs = max(0, int(row.get("failed_repairs") or 0))
                experience.verified = bool(row.get("verified"))
                experience.state = "verified" if experience.verified else "candidate"
                experience.enabled = True
                experience.created_at = seed_time("created_at") or experience.created_at or datetime.now(timezone.utc)
                experience.updated_at = seed_time("updated_at") or datetime.now(timezone.utc)
                experience.last_verified_at = seed_time("last_verified_at")
                prepare_new_experience(experience)
                if signature not in existing_signatures:
                    db.add(experience)
                    existing_signatures.add(signature)
            for experience in db.scalars(select(DeploymentExperience)).all():
                prepare_new_experience(experience)
            db.commit()
        default_ai = db.scalar(select(AiConfig).where(AiConfig.enabled.is_(True), AiConfig.is_default.is_(True)))
        if not default_ai:
            first_enabled_ai = db.scalar(select(AiConfig).where(AiConfig.enabled.is_(True)).order_by(AiConfig.provider_name, AiConfig.id))
            if first_enabled_ai:
                first_enabled_ai.is_default = True
                db.commit()
        if not db.scalar(select(User).where(User.username == settings.admin_username)):
            db.add(
                User(
                    username=settings.admin_username,
                    display_name=settings.admin_name,
                    password_hash=hash_password(settings.admin_password),
                    role=Role.admin,
                )
            )
            db.commit()
        # Migrate only credentials that exactly match the platform's deterministic
        # generator. User-entered values remain in encrypted storage.
        for project in db.scalars(select(Project)).all():
            user_lines = (decrypt(project.env_text_encrypted) or "").splitlines()
            kept, managed, changed = [], (project.managed_env_text or "").splitlines(), False
            managed_keys = {line.split("=", 1)[0].strip() for line in managed if "=" in line}
            for line in user_lines:
                if "=" not in line or line.lstrip().startswith("#"):
                    kept.append(line)
                    continue
                key, value = line.split("=", 1)
                key, value = key.strip(), value.strip()
                digest = hashlib.sha256(f"{settings.app_secret}:{project.id}:{key}".encode()).hexdigest()
                expected = ("yz" + digest[:18]) if key.upper().endswith("ACCESS_KEY") else digest[:48]
                if value == expected:
                    if key not in managed_keys:
                        managed.append(f"{key}={value}")
                        managed_keys.add(key)
                    changed = True
                else:
                    kept.append(line)
            if changed:
                project.managed_env_text = "\n".join(managed).strip() + "\n"
                project.env_text_encrypted = encrypt("\n".join(kept).strip() + "\n" if any(x.strip() for x in kept) else "")
        db.commit()
    start_backup_scheduler()

