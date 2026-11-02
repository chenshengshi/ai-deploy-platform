import base64
import asyncio
import copy
import hashlib
import ipaddress
import json
import re
import socket
import shlex
import shutil
import subprocess
import struct
import tarfile
import tempfile
import threading
import time
import uuid
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from zoneinfo import ZoneInfo
from urllib.parse import quote, urlsplit, urlunsplit

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID
from fastapi import BackgroundTasks, Depends, FastAPI, File, Form, HTTPException, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response
from sqlalchemy import desc, func, select, text
from sqlalchemy.orm import Session
from jose import JWTError, jwt

from .ai import analyze_backup_scope, analyze_delete_scope, analyze_project_deployment, deployment_followup, understand
from .auth import current_user, hash_password, require, token_for, verify_password
from .config import decrypt, encrypt, settings
from .database import Base, SessionLocal, engine, get_db
from .deployer import cleanup_registry_versions, choose_port, configure_platform_gateway, delete_deployment_resources, detect_frontend_api_routes, git_source_location, platform_gateway_node, preflight_ai_deployment_plan, project_directory, stage_source, start_deployment, stop_deployment, verify_access
from .models import AiConfig, AuditLog, CertificateStore, ChatMessage, ChatSession, DeployStatus, Deployment, DeploymentExperience, DeploymentSettings, GitCredential, Node, PasswordHistory, Project, ProjectDomainConfig, ProjectReplica, Role, SecurityConfig, SourceType, SystemProxy, User
from .proxy import get_proxy_config, proxy_for, proxy_with_auth, redact_proxy
from .schemas import (
    AiConfigIn,
    AiConfigOut,
    BrandingSettingsIn,
    BrandingSettingsOut,
    ChatIn,
    ChatOut,
    CredentialIn,
    CredentialOut,
    GitConnectionTest,
    DeployIn,
    DeploymentOut,
    DeploymentSettingsIn,
    DeploymentSettingsOut,
    LoginIn,
    PasswordChange,
    NodeIn,
    NodeOut,
    NodeTest,
    NodeUpdate,
    ProjectCreate,
    ProjectUpdate,
    ScaleProjectIn,
    SecuritySettingsIn,
    SecuritySettingsOut,
    SqlConsoleIn,
    ProjectOut,
    ProxyConfigIn,
    ProxyConfigOut,
    TokenOut,
    UserCreate,
    UserOut,
    UserUpdate,
)
from .ssh import SSHNode, ensure_node_runtime, test_node


app = FastAPI(title=settings.app_name, docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[value.strip().rstrip("/") for value in settings.cors_origins.split(",") if value.strip()],
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)


# Runtime discovery opens an SSH session and asks Docker for Compose state and
# a one-shot resource sample. The project and deployment screens often request
# the same deployment at the same time, so without a shared single-flight cache
# both requests repeat the identical remote work. Keep the cache deliberately
# short: it removes duplicate modal loads while normal polling still observes
# changes within a few seconds. Explicit refreshes bypass it.
_RUNTIME_CACHE_TTL = 4.0
_runtime_cache: dict[tuple, tuple[float, dict]] = {}
_runtime_cache_locks: dict[tuple, threading.Lock] = {}
_runtime_cache_guard = threading.Lock()


def _runtime_cache_key(item: Deployment) -> tuple:
    status = item.status.value if hasattr(item.status, "value") else str(item.status)
    return (item.id, status, item.release or "", item.container_name or "", item.host_port or 0)


def _runtime_cache_read(key: tuple) -> dict | None:
    now = time.monotonic()
    with _runtime_cache_guard:
        cached = _runtime_cache.get(key)
        if not cached or now - cached[0] > _RUNTIME_CACHE_TTL:
            if cached:
                _runtime_cache.pop(key, None)
            return None
        return copy.deepcopy(cached[1])


def _runtime_cache_write(key: tuple, value: dict) -> None:
    now = time.monotonic()
    with _runtime_cache_guard:
        _runtime_cache[key] = (now, copy.deepcopy(value))
        # A worker process lives for a long time and sees many releases. Bound
        # stale entries instead of allowing an unbounded per-deployment map.
        if len(_runtime_cache) > 256:
            expired = [cache_key for cache_key, (saved, _) in _runtime_cache.items() if now - saved > _RUNTIME_CACHE_TTL]
            for cache_key in expired:
                _runtime_cache.pop(cache_key, None)
                lock = _runtime_cache_locks.get(cache_key)
                if lock is not None and not lock.locked():
                    _runtime_cache_locks.pop(cache_key, None)


def invalidate_runtime_cache(deployment_id: str | None = None) -> None:
    with _runtime_cache_guard:
        for key in list(_runtime_cache):
            if deployment_id is None or key[0] == deployment_id:
                _runtime_cache.pop(key, None)


def audit(db: Session, user: User | None, action: str, target_type: str = "", target_id: str | None = None, detail: str = ""):
    db.add(AuditLog(user_id=user.id if user else None, action=action, target_type=target_type, target_id=target_id, detail=detail))


def get_deployment_settings(db: Session) -> DeploymentSettings:
    row = db.get(DeploymentSettings, "default")
    if not row:
        row = DeploymentSettings(id="default")
        db.add(row)
        db.commit()
        db.refresh(row)
    return row


def get_security_config(db: Session) -> SecurityConfig:
    row = db.get(SecurityConfig, "default")
    if not row:
        row = SecurityConfig(id="default")
        db.add(row)
        db.commit()
        db.refresh(row)
    elif row.china_ip_source_url in {
        "https://www.ipdeny.com/ipblocks/data/countries/cn.zone",
        "http://www.ipdeny.com/ipblocks/data/countries/cn.zone",
    }:
        row.china_ip_source_url = "https://ispip.clang.cn/all_cn_cidr.html"
        db.commit()
        db.refresh(row)
    return row


def security_config_view(row: SecurityConfig) -> SecuritySettingsOut:
    data = {key: getattr(row, key) for key in SecuritySettingsIn.model_fields}
    return SecuritySettingsOut(
        **data,
        china_ip_count=len([line for line in (row.china_ip_cidrs or "").splitlines() if line.strip()]),
        source_updated_at=row.source_updated_at,
        updated_at=row.updated_at,
    )


def fetch_china_ip_cidrs(source_url: str) -> list[str]:
    try:
        with httpx.Client(timeout=30, follow_redirects=True) as client:
            response = client.get(source_url)
            response.raise_for_status()
    except Exception as exc:
        raise HTTPException(502, f"中国 IP 网段下载失败：{exc}")
    # The canonical source is an HTML page. Extract candidates rather than
    # assuming one CIDR per line, while still supporting plain-text sources.
    candidates = re.findall(r"(?<![0-9.])(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?(?![0-9.])", response.text)
    networks: list[str] = []
    for value in candidates:
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            continue
        if network.version == 4:
            networks.append(str(network))
    networks = list(dict.fromkeys(networks))
    if not networks:
        raise HTTPException(502, "中国 IP 数据源没有返回有效的 IPv4 网段")
    return networks


def apply_china_ip_allowlist(db: Session, row: SecurityConfig) -> None:
    node = platform_gateway_node(db)
    if not node:
        raise HTTPException(409, "未找到平台网关所在服务器")
    path = "/data/yunzhou-control/data/gateway/conf.d/00-platform-allowlist.conf"
    if row.china_ip_allowlist_enabled:
        cidrs = [line.strip() for line in (row.china_ip_cidrs or "").splitlines() if line.strip()]
        if not cidrs:
            raise HTTPException(409, "请先更新中国 IP 白名单，再启用访问限制")
        trusted = ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
        content = "# Managed by Yunzhou\n" + "".join(f"allow {item};\n" for item in trusted + cidrs) + "deny all;\n"
    else:
        content = "# China IP allowlist disabled; managed by Yunzhou\n"
    # China allowlists are large (often >100 KiB). Embedding the whole file in
    # an SSH exec command can exceed the server/channel command-size limit and
    # close the connection with EOF. Upload it over SFTP, then keep the remote
    # activation command small and atomic.
    temporary_path = f"/tmp/yunzhou-allowlist-{uuid.uuid4().hex}.conf"
    command = (
        "mkdir -p /data/yunzhou-control/data/gateway/conf.d; "
        f"cp {shlex.quote(path)} {shlex.quote(path)}.bak 2>/dev/null || true; "
        f"mv {shlex.quote(temporary_path)} {shlex.quote(path)}; "
        "if docker ps --format '{{.Names}}' | grep -qx yunzhou-platform-gateway; then "
        "if ! docker exec yunzhou-platform-gateway nginx -t; then "
        f"test -f {shlex.quote(path)}.bak && mv {shlex.quote(path)}.bak {shlex.quote(path)} || rm -f {shlex.quote(path)}; exit 43; fi; "
        "docker exec yunzhou-platform-gateway nginx -s reload; fi; "
        f"rm -f {shlex.quote(path)}.bak"
    )
    try:
        with SSHNode(node) as ssh:
            sftp = ssh.client.open_sftp()
            try:
                with sftp.open(temporary_path, "w") as handle:
                    handle.write(content)
            finally:
                sftp.close()
            code, output = ssh.run(command, timeout=60)
    except Exception as exc:
        raise HTTPException(502, f"无法连接平台网关服务器：{exc}")
    if code:
        raise HTTPException(502, "中国 IP 白名单应用失败，已恢复原配置：" + output[-500:])


def validate_password(value: str, policy: SecurityConfig, db: Session, user: User | None = None):
    errors = []
    if len(value) < policy.min_password_length:
        errors.append(f"至少 {policy.min_password_length} 位")
    if policy.require_lowercase and not re.search(r"[a-z]", value): errors.append("小写字母")
    if policy.require_uppercase and not re.search(r"[A-Z]", value): errors.append("大写字母")
    if policy.require_digit and not re.search(r"\d", value): errors.append("数字")
    if policy.require_special and not re.search(r"[^A-Za-z0-9]", value): errors.append("特殊字符")
    if policy.max_repeated_chars and re.search(r"(.)\1{" + str(policy.max_repeated_chars) + r",}", value):
        errors.append(f"同一字符不能连续超过 {policy.max_repeated_chars} 次")
    if user and policy.password_min_age_days and user.password_changed_at:
        changed = user.password_changed_at if user.password_changed_at.tzinfo else user.password_changed_at.replace(tzinfo=timezone.utc)
        if datetime.now(timezone.utc) < changed + timedelta(days=policy.password_min_age_days):
            errors.append(f"密码至少使用 {policy.password_min_age_days} 天后才能更换")
    if user and policy.password_history_count:
        history = db.scalars(select(PasswordHistory).where(PasswordHistory.user_id == user.id).order_by(desc(PasswordHistory.created_at)).limit(policy.password_history_count)).all()
        if verify_password(value, user.password_hash) or any(verify_password(value, item.password_hash) for item in history):
            errors.append(f"不能使用最近 {policy.password_history_count} 次密码")
    if errors:
        raise HTTPException(400, "密码不符合安全策略：" + "、".join(errors))


def require_reachable_node(node: Node, db: Session) -> None:
    timeout = get_deployment_settings(db).connection_timeout_seconds
    try:
        with SSHNode(node, connect_timeout=timeout) as ssh:
            code, output = ssh.run("printf yunzhou-ready", timeout=timeout)
            if code or "yunzhou-ready" not in output:
                raise RuntimeError(output or "SSH 检测未返回结果")
    except Exception as exc:
        raise HTTPException(502, f"目标服务器无法连接，未创建部署任务：{str(exc)[:300]}") from exc


@app.on_event("startup")
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
            connection.execute(text("ALTER TABLE projects ADD COLUMN IF NOT EXISTS managed_env_text TEXT"))
            connection.execute(text("ALTER TABLE projects ADD COLUMN IF NOT EXISTS integration_analysis_json TEXT"))
            connection.execute(text("ALTER TABLE nodes ADD COLUMN IF NOT EXISTS docker_proxy_enabled BOOLEAN NOT NULL DEFAULT FALSE"))
            connection.execute(text("ALTER TABLE nodes ADD COLUMN IF NOT EXISTS docker_proxy_status VARCHAR(32) NOT NULL DEFAULT 'disabled'"))
            connection.execute(text("ALTER TABLE nodes ADD COLUMN IF NOT EXISTS docker_proxy_error TEXT"))
    # New optional columns must be migrated even after the original schema
    # marker already exists on long-running installations.
    with engine.begin() as connection:
        # Service-level scaling was introduced after the original project
        # schema marker.  Keep these migrations outside ``schema_ready`` so
        # an existing installation cannot start with an older replicas table.
        connection.execute(text("ALTER TABLE project_replicas ADD COLUMN IF NOT EXISTS service_name VARCHAR(120) NOT NULL DEFAULT ''"))
        connection.execute(text("ALTER TABLE project_replicas ADD COLUMN IF NOT EXISTS pool_role VARCHAR(32) NOT NULL DEFAULT 'entry'"))
        connection.execute(text("ALTER TABLE project_replicas ADD COLUMN IF NOT EXISTS container_port INTEGER"))
        connection.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS failed_login_attempts INTEGER NOT NULL DEFAULT 0"))
        connection.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS locked_until TIMESTAMPTZ"))
        connection.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS password_changed_at TIMESTAMPTZ"))
        connection.execute(text("ALTER TABLE security_config ADD COLUMN IF NOT EXISTS audit_retention_days INTEGER NOT NULL DEFAULT 180"))
        connection.execute(text("UPDATE users SET password_changed_at=COALESCE(password_changed_at, created_at, NOW())"))
        connection.execute(text("ALTER TABLE project_domain_configs ADD COLUMN IF NOT EXISTS certificate_id VARCHAR(36)"))
        connection.execute(text("ALTER TABLE project_domain_configs ADD COLUMN IF NOT EXISTS gateway_mode VARCHAR(24) NOT NULL DEFAULT 'auto'"))
        connection.execute(text("ALTER TABLE project_domain_configs ADD COLUMN IF NOT EXISTS custom_routes_json TEXT NOT NULL DEFAULT '[]'"))
        connection.execute(text("ALTER TABLE project_domain_configs ADD COLUMN IF NOT EXISTS proxy_read_timeout INTEGER NOT NULL DEFAULT 300"))
        connection.execute(text("ALTER TABLE project_domain_configs ADD COLUMN IF NOT EXISTS client_max_body_mb INTEGER NOT NULL DEFAULT 50"))
        connection.execute(text("ALTER TABLE projects ADD COLUMN IF NOT EXISTS image_retention_count INTEGER NOT NULL DEFAULT 5"))
        connection.execute(text("ALTER TABLE projects ADD COLUMN IF NOT EXISTS data_exposure_json TEXT NOT NULL DEFAULT '{}'"))
        connection.execute(text("ALTER TABLE deployment_settings ADD COLUMN IF NOT EXISTS registry_retention_count INTEGER NOT NULL DEFAULT 5"))
        connection.execute(text("ALTER TABLE deployment_settings ADD COLUMN IF NOT EXISTS registry_auto_cleanup BOOLEAN NOT NULL DEFAULT TRUE"))
        connection.execute(text("ALTER TABLE deployment_settings ADD COLUMN IF NOT EXISTS registry_endpoint VARCHAR(255) NOT NULL DEFAULT 'yunzhou.hub:5000'"))
        connection.execute(text("ALTER TABLE deployment_settings ADD COLUMN IF NOT EXISTS registry_namespace VARCHAR(100) NOT NULL DEFAULT 'yunzhou'"))
        connection.execute(text("ALTER TABLE deployment_settings ADD COLUMN IF NOT EXISTS build_cache_root VARCHAR(500) NOT NULL DEFAULT '/data/yunzhou/builder/cache'"))
        connection.execute(text("ALTER TABLE deployment_settings ADD COLUMN IF NOT EXISTS maven_cache_dir VARCHAR(255) NOT NULL DEFAULT '/root/.m2'"))
        connection.execute(text("ALTER TABLE deployment_settings ADD COLUMN IF NOT EXISTS gradle_cache_dir VARCHAR(255) NOT NULL DEFAULT '/home/gradle/.gradle'"))
        connection.execute(text("ALTER TABLE deployment_settings ADD COLUMN IF NOT EXISTS npm_cache_dir VARCHAR(255) NOT NULL DEFAULT '/root/.npm'"))
        connection.execute(text("ALTER TABLE deployment_settings ADD COLUMN IF NOT EXISTS pnpm_cache_dir VARCHAR(255) NOT NULL DEFAULT '/root/.local/share/pnpm/store'"))
        connection.execute(text("ALTER TABLE deployment_settings ADD COLUMN IF NOT EXISTS yarn_cache_dir VARCHAR(255) NOT NULL DEFAULT '/root/.cache/yarn'"))
        connection.execute(text("ALTER TABLE deployment_settings ADD COLUMN IF NOT EXISTS pip_cache_dir VARCHAR(255) NOT NULL DEFAULT '/root/.cache/pip'"))
        connection.execute(text("ALTER TABLE ai_configs ADD COLUMN IF NOT EXISTS is_default BOOLEAN NOT NULL DEFAULT FALSE"))
        connection.execute(text("ALTER TABLE chat_sessions ADD COLUMN IF NOT EXISTS ai_config_id VARCHAR(36)"))
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
        seed_path = Path(__file__).with_name("bootstrap") / "deployment_experiences.json"
        if seed_path.exists():
            try:
                seed_rows = json.loads(seed_path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                seed_rows = []
            existing_signatures = set(db.scalars(select(DeploymentExperience.signature)).all())
            for row in seed_rows if isinstance(seed_rows, list) else []:
                signature = str(row.get("signature") or "").strip()
                if not signature or signature in existing_signatures:
                    continue
                def seed_time(key: str):
                    value = row.get(key)
                    if not value:
                        return None
                    try:
                        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
                    except ValueError:
                        return None
                db.add(DeploymentExperience(
                    signature=signature,
                    category=str(row.get("category") or "unknown")[:64],
                    error_sample=str(row.get("error_sample") or ""),
                    repair_summary=str(row.get("repair_summary") or ""),
                    occurrences=max(1, int(row.get("occurrences") or 1)),
                    successful_repairs=max(0, int(row.get("successful_repairs") or 0)),
                    failed_repairs=max(0, int(row.get("failed_repairs") or 0)),
                    verified=bool(row.get("verified")),
                    created_at=seed_time("created_at") or datetime.now(timezone.utc),
                    updated_at=seed_time("updated_at") or datetime.now(timezone.utc),
                    last_verified_at=seed_time("last_verified_at"),
                ))
                existing_signatures.add(signature)
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


@app.get("/api/health")
def health():
    return {"status": "ok", "name": settings.app_name}


def branding_out(item: DeploymentSettings) -> BrandingSettingsOut:
    return BrandingSettingsOut(
        system_name=item.system_name or "自助发布平台",
        short_name=item.short_name or "自助发布",
        system_subtitle=item.system_subtitle or "应用交付平台",
        login_slogan=item.login_slogan or "一句话，把项目安全发布到服务器",
        logo_data_url=item.logo_data_url or "",
        favicon_data_url=item.favicon_data_url or "",
    )


@app.get("/api/branding", response_model=BrandingSettingsOut)
def read_branding(db: Session = Depends(get_db)):
    return branding_out(get_deployment_settings(db))


@app.put("/api/settings/branding", response_model=BrandingSettingsOut)
def update_branding(body: BrandingSettingsIn, db: Session = Depends(get_db), user: User = Depends(require(Role.admin))):
    allowed_image = re.compile(r"^data:image/(?:png|jpeg|webp|x-icon|vnd\.microsoft\.icon);base64,", re.I)
    for label, value in (("Logo", body.logo_data_url), ("页签图标", body.favicon_data_url)):
        if value and not allowed_image.match(value):
            raise HTTPException(400, f"{label}仅支持 PNG、JPG、WebP 或 ICO 图片")
        if value and len(value) > 2_800_000:
            raise HTTPException(413, f"{label}不能超过 2 MB")
    item = get_deployment_settings(db)
    item.system_name = body.system_name.strip()
    item.short_name = body.short_name.strip()
    item.system_subtitle = body.system_subtitle.strip()
    item.login_slogan = body.login_slogan.strip()
    item.logo_data_url = body.logo_data_url
    item.favicon_data_url = body.favicon_data_url
    audit(db, user, "update_branding", "system", detail=item.system_name)
    db.commit()
    db.refresh(item)
    return branding_out(item)


def backup_items() -> list[dict]:
    root = Path(settings.backup_root)
    root.mkdir(parents=True, exist_ok=True)
    items = []
    for path in sorted(root.glob("yunzhou-backup-*.tar.gz"), key=lambda x: x.stat().st_mtime, reverse=True):
        stat = path.stat()
        items.append({"name": path.name, "size": stat.st_size, "created_at": datetime.fromtimestamp(stat.st_mtime, timezone.utc)})
    return items


BACKUP_TIMEZONE = ZoneInfo("Asia/Shanghai")
BACKUP_EXCLUDED_DIRS = {"node_modules", ".git", ".venv", "venv", "__pycache__", ".pytest_cache", ".mypy_cache", ".next", ".nuxt", "dist", "build", "target"}
_backup_scheduler_started = False
_backup_lock = threading.Lock()
_last_audit_cleanup_date: str | None = None


def backup_config_path() -> Path:
    return Path(settings.backup_root) / "backup-settings.json"


def load_backup_config() -> dict:
    defaults = {"enabled": False, "time": "02:00", "retention": 10, "last_run_date": None}
    path = backup_config_path()
    try:
        saved = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    except (OSError, json.JSONDecodeError):
        saved = {}
    return {**defaults, **saved}


def save_backup_config(config: dict) -> None:
    path = backup_config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(config, ensure_ascii=False, indent=2), encoding="utf-8")


def backup_tar_filter(info: tarfile.TarInfo):
    parts = PurePosixPath(info.name).parts
    if any(part in BACKUP_EXCLUDED_DIRS for part in parts):
        return None
    if info.name.endswith((".pyc", ".pyo", ".log")):
        return None
    return info


def backup_source_inventory() -> dict:
    root = Path(settings.upload_root)
    extensions: dict[str, int] = {}
    excluded_found: set[str] = set()
    files = 0
    if root.exists():
        for path in root.rglob("*"):
            if any(part in BACKUP_EXCLUDED_DIRS for part in path.parts):
                excluded_found.update(part for part in path.parts if part in BACKUP_EXCLUDED_DIRS)
                continue
            if path.is_file():
                files += 1
                suffix = path.suffix.lower() or "无扩展名"
                extensions[suffix] = extensions.get(suffix, 0) + 1
    type_map = {".js": "JavaScript", ".jsx": "React", ".ts": "TypeScript", ".tsx": "React/TypeScript", ".py": "Python", ".java": "Java", ".go": "Go", ".php": "PHP", ".vue": "Vue", ".cs": ".NET", ".sql": "SQL/迁移脚本"}
    source_types = sorted({label for ext, label in type_map.items() if extensions.get(ext)})
    return {"file_count": files, "extensions": dict(sorted(extensions.items(), key=lambda item: item[1], reverse=True)[:20]), "source_types": source_types, "excluded": sorted(BACKUP_EXCLUDED_DIRS), "excluded_found": sorted(excluded_found)}


def perform_backup(db: Session, user: User | None = None) -> dict:
    if not _backup_lock.acquire(blocking=False):
        raise HTTPException(409, "已有备份任务正在执行")
    now_local = datetime.now(BACKUP_TIMEZONE)
    stamp = now_local.strftime("%Y%m%d-%H%M%S")
    root = Path(settings.backup_root)
    root.mkdir(parents=True, exist_ok=True)
    target = root / f"yunzhou-backup-{stamp}.tar.gz"
    temp_dir = Path(tempfile.mkdtemp(prefix="yunzhou-backup-", dir=root))
    try:
        dump_file = temp_dir / "database.json"
        database_export = {}
        for table in Base.metadata.sorted_tables:
            rows = db.execute(select(table)).mappings().all()
            database_export[table.name] = [dict(row) for row in rows]
        dump_file.write_text(json.dumps(database_export, ensure_ascii=False, indent=2, default=lambda value: value.isoformat() if hasattr(value, "isoformat") else str(value)), encoding="utf-8")
        inventory = backup_source_inventory()
        analysis = analyze_backup_scope(db, inventory)
        manifest = {
            "app": settings.app_name,
            "created_at": now_local.isoformat(),
            "database": "database.json",
            "uploads": Path(settings.upload_root).exists(),
            "excluded_directories": sorted(BACKUP_EXCLUDED_DIRS),
            "ai_analysis": analysis,
            "note": "敏感字段保持数据库中的加密状态；恢复时必须使用原 ENCRYPTION_KEY。",
        }
        (temp_dir / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
        with tarfile.open(target, "w:gz") as archive:
            archive.add(dump_file, arcname="database.json")
            archive.add(temp_dir / "manifest.json", arcname="manifest.json")
            upload_root = Path(settings.upload_root)
            if upload_root.exists():
                archive.add(upload_root, arcname="uploads", recursive=True, filter=backup_tar_filter)
        retention = load_backup_config()["retention"]
        for old in backup_items()[retention:]:
            (root / old["name"]).unlink(missing_ok=True)
        audit(db, user, "create_backup", "system", detail=target.name)
        db.commit()
        config = load_backup_config()
        config["last_analysis"] = analysis
        save_backup_config(config)
        return {"ok": True, "item": next(x for x in backup_items() if x["name"] == target.name)}
    except HTTPException:
        raise
    except Exception as exc:
        target.unlink(missing_ok=True)
        raise HTTPException(502, f"备份创建失败：{exc}")
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
        _backup_lock.release()


def backup_scheduler_loop():
    global _last_audit_cleanup_date
    while True:
        try:
            config = load_backup_config()
            now_local = datetime.now(BACKUP_TIMEZONE)
            cleanup_date = now_local.strftime("%Y-%m-%d")
            if _last_audit_cleanup_date != cleanup_date:
                with SessionLocal() as db:
                    _cleanup_audit_logs(db)
                _last_audit_cleanup_date = cleanup_date
            if config["enabled"] and now_local.strftime("%H:%M") == config["time"] and config.get("last_run_date") != now_local.strftime("%Y-%m-%d"):
                with SessionLocal() as db:
                    perform_backup(db)
                config = load_backup_config()
                config["last_run_date"] = now_local.strftime("%Y-%m-%d")
                save_backup_config(config)
        except Exception:
            pass
        time.sleep(30)


def start_backup_scheduler():
    global _backup_scheduler_started
    if not _backup_scheduler_started:
        _backup_scheduler_started = True
        threading.Thread(target=backup_scheduler_loop, daemon=True, name="backup-scheduler").start()


@app.get("/api/settings/backups")
def list_backups(_: User = Depends(require(Role.admin))):
    usage = shutil.disk_usage(settings.backup_root)
    config = load_backup_config()
    return {"items": backup_items(), "retention": config["retention"], "schedule": config, "disk_free": usage.free}


@app.put("/api/settings/backups/schedule")
def update_backup_schedule(body: dict, db: Session = Depends(get_db), user: User = Depends(require(Role.admin))):
    enabled = bool(body.get("enabled", False))
    backup_time = str(body.get("time", "02:00"))
    retention = int(body.get("retention", 10))
    if not re.fullmatch(r"(?:[01]\d|2[0-3]):[0-5]\d", backup_time):
        raise HTTPException(400, "每日备份时间格式不正确")
    if retention < 1 or retention > 100:
        raise HTTPException(400, "保留份数必须在 1 到 100 之间")
    config = load_backup_config()
    config.update({"enabled": enabled, "time": backup_time, "retention": retention})
    save_backup_config(config)
    root = Path(settings.backup_root)
    for old in backup_items()[retention:]:
        (root / old["name"]).unlink(missing_ok=True)
    audit(db, user, "update_backup_schedule", "system", detail=json.dumps({"enabled": enabled, "time": backup_time, "retention": retention}, ensure_ascii=False))
    db.commit()
    return {"ok": True, "schedule": config}


@app.post("/api/settings/backups")
def create_backup(db: Session = Depends(get_db), user: User = Depends(require(Role.admin))):
    return perform_backup(db, user)


@app.get("/api/settings/backups/{name}/download")
def download_backup(name: str, _: User = Depends(require(Role.admin))):
    if not re.fullmatch(r"yunzhou-backup-\d{8}-\d{6}\.tar\.gz", name):
        raise HTTPException(400, "备份文件名不正确")
    path = Path(settings.backup_root) / name
    if not path.exists():
        raise HTTPException(404, "备份不存在")
    return FileResponse(path, filename=name, media_type="application/gzip")


@app.delete("/api/settings/backups/{name}")
def delete_backup(name: str, db: Session = Depends(get_db), user: User = Depends(require(Role.admin))):
    if not re.fullmatch(r"yunzhou-backup-\d{8}-\d{6}\.tar\.gz", name):
        raise HTTPException(400, "备份文件名不正确")
    path = Path(settings.backup_root) / name
    if not path.exists():
        raise HTTPException(404, "备份不存在")
    path.unlink()
    audit(db, user, "delete_backup", "system", detail=name)
    db.commit()
    return {"ok": True}


@app.post("/api/auth/login", response_model=TokenOut)
def login(body: LoginIn, db: Session = Depends(get_db)):
    user = db.scalar(select(User).where(User.username == body.username))
    policy = get_security_config(db)
    now = datetime.now(timezone.utc)
    if user and user.locked_until:
        locked_until = user.locked_until if user.locked_until.tzinfo else user.locked_until.replace(tzinfo=timezone.utc)
        if locked_until > now:
            remaining = max(1, int((locked_until - now).total_seconds() / 60) + 1)
            raise HTTPException(status_code=423, detail=f"账号已锁定，请在 {remaining} 分钟后重试")
        user.locked_until = None
        user.failed_login_attempts = 0
    if not user or not user.active or not verify_password(body.password, user.password_hash):
        if user and user.active:
            user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
            if user.failed_login_attempts >= policy.login_max_attempts:
                user.locked_until = now + timedelta(minutes=policy.login_lock_minutes)
                user.failed_login_attempts = 0
            db.commit()
        raise HTTPException(status_code=401, detail="用户名或密码错误")
    user.failed_login_attempts = 0
    user.locked_until = None
    audit(db, user, "login")
    db.commit()
    return TokenOut(access_token=token_for(user, policy.session_timeout_minutes))


@app.get("/api/auth/me", response_model=UserOut)
def me(user: User = Depends(current_user)):
    return user


@app.post("/api/auth/change-password")
def change_own_password(body: PasswordChange, db: Session = Depends(get_db), user: User = Depends(current_user)):
    if not verify_password(body.current_password, user.password_hash):
        raise HTTPException(400, "当前密码不正确")
    if body.current_password == body.new_password:
        raise HTTPException(400, "新密码不能与当前密码相同")
    policy = get_security_config(db)
    validate_password(body.new_password, policy, db, user)
    db.add(PasswordHistory(user_id=user.id, password_hash=user.password_hash))
    user.password_hash = hash_password(body.new_password)
    user.password_changed_at = datetime.now(timezone.utc)
    audit(db, user, "change_own_password", "user", user.id)
    db.commit()
    return {"ok": True, "message": "密码修改成功"}


@app.get("/api/dashboard")
def dashboard(db: Session = Depends(get_db), user: User = Depends(current_user)):
    recent = db.scalars(select(Deployment).order_by(desc(Deployment.created_at)).limit(8)).all()
    return {
        "projects": db.query(Project).count(),
        "nodes": db.query(Node).count(),
        "running": db.query(Deployment).filter(Deployment.status.in_([DeployStatus.queued, DeployStatus.running])).count(),
        "success": db.query(Deployment).filter(Deployment.status == DeployStatus.success).count(),
        # Use the same derived stage/progress data as deployment details. Raw
        # DeploymentOut has no progress field, which made the workbench show 0%.
        "recent": [deployment_view(x, db, include_log=False) for x in recent],
    }


@app.get("/api/users", response_model=list[UserOut])
def list_users(db: Session = Depends(get_db), _: User = Depends(require(Role.admin))):
    return db.scalars(select(User).order_by(User.created_at)).all()


@app.post("/api/users", response_model=UserOut)
def create_user(body: UserCreate, db: Session = Depends(get_db), user: User = Depends(require(Role.admin))):
    if db.scalar(select(User).where(User.username == body.username)):
        raise HTTPException(409, "用户名已存在")
    validate_password(body.password, get_security_config(db), db)
    item = User(username=body.username, display_name=body.display_name, password_hash=hash_password(body.password), role=body.role, password_changed_at=datetime.now(timezone.utc))
    db.add(item)
    db.flush()
    audit(db, user, "create_user", "user", item.id, item.username)
    db.commit()
    db.refresh(item)
    return item


@app.patch("/api/users/{item_id}", response_model=UserOut)
def update_user(item_id: str, body: UserUpdate, db: Session = Depends(get_db), user: User = Depends(require(Role.admin))):
    item = db.get(User, item_id)
    if not item:
        raise HTTPException(404, "用户不存在")
    changes = body.model_dump(exclude_unset=True)
    if changes.get("username") and changes["username"] != item.username and db.scalar(select(User).where(User.username == changes["username"])):
        raise HTTPException(409, "用户名已存在")
    for key, value in changes.items():
        if key == "password":
            validate_password(value, get_security_config(db), db, item)
            db.add(PasswordHistory(user_id=item.id, password_hash=item.password_hash))
            item.password_hash = hash_password(value)
            item.password_changed_at = datetime.now(timezone.utc)
        else:
            setattr(item, key, value)
    audit(db, user, "update_user", "user", item.id)
    db.commit()
    db.refresh(item)
    return item


@app.get("/api/nodes", response_model=list[NodeOut])
def list_nodes(db: Session = Depends(get_db), _: User = Depends(current_user)):
    return db.scalars(select(Node).order_by(Node.created_at)).all()


@app.get("/api/nodes/resources")
def node_resources(db: Session = Depends(get_db), _: User = Depends(current_user)):
    """Small real-time host snapshot for the node cards."""
    nodes = db.scalars(select(Node).order_by(Node.created_at)).all()
    def collect(node):
        try:
            with SSHNode(node) as ssh:
                command = (
                    "printf '__MEM__\\n'; cat /proc/meminfo; "
                    "printf '__CPU__\\n'; LC_ALL=C top -bn1 2>/dev/null; "
                    "printf '__DISK__\\n'; df -Pk / | tail -1; "
                    "printf '__COUNT__\\n'; docker ps -q 2>/dev/null | wc -l; docker ps -aq 2>/dev/null | wc -l; "
                    "printf '__LOAD__\\n'; cat /proc/loadavg; grep -c '^processor' /proc/cpuinfo; "
                    "printf '__IPS__\\n'; hostname -I 2>/dev/null || hostname -i"
                )
                code, output = ssh.run(command, timeout=12)
            if code:
                raise RuntimeError(output.strip() or "读取资源失败")
            parts = re.split(r"__(MEM|CPU|DISK|COUNT|LOAD|IPS)__\r?\n", output)
            values = {parts[index]: parts[index + 1] for index in range(1, len(parts) - 1, 2)}
            mem_output, cpu_output = values.get("MEM", ""), values.get("CPU", "")
            disk_output, count_output = values.get("DISK", ""), values.get("COUNT", "")
            load_output, host_ips_output = values.get("LOAD", ""), values.get("IPS", "")
            mem_values = {line.split(":", 1)[0]: int(line.split()[1]) * 1024 for line in mem_output.splitlines() if ":" in line and len(line.split()) > 1 and line.split()[1].isdigit()}
            mem_total = mem_values.get("MemTotal", 0)
            mem_used = max(0, mem_total - mem_values.get("MemAvailable", mem_values.get("MemFree", 0)))
            disk_parts = disk_output.split()
            disk_total, disk_used = (int(float(disk_parts[1]) * 1024), int(float(disk_parts[2]) * 1024)) if len(disk_parts) >= 3 else (0, 0)
            counts = [int(x.strip()) for x in count_output.splitlines() if x.strip().isdigit()]
            loads = [x.strip() for x in load_output.splitlines() if x.strip()]
            idle_match = re.search(r"([0-9.]+)\s*id", cpu_output)
            cpu_percent = round(100 - float(idle_match.group(1))) if idle_match else 0
            return node.id, {
                "online": True, "cpu_percent": cpu_percent, "cores": int(loads[1]) if len(loads) > 1 else 0,
                "load": loads[0].split()[0] if loads else "0", "memory_used": mem_used, "memory_total": mem_total,
                "memory_percent": round(mem_used * 100 / mem_total) if mem_total else 0,
                "disk_used": disk_used, "disk_total": disk_total,
                "disk_percent": round(disk_used * 100 / disk_total) if disk_total else 0,
                "containers": counts[0] if counts else 0, "containers_total": counts[1] if len(counts) > 1 else 0,
                "host_ips": [value for value in host_ips_output.split() if re.fullmatch(r"\d+(?:\.\d+){3}", value)],
            }
        except Exception as exc:
            return node.id, {"online": False, "error": str(exc)}
    result = {}
    with ThreadPoolExecutor(max_workers=max(1, min(8, len(nodes)))) as executor:
        futures = [executor.submit(collect, node) for node in nodes]
        for future in as_completed(futures):
            node_id, snapshot = future.result()
            result[node_id] = snapshot
    return result


@app.post("/api/nodes", response_model=NodeOut)
def create_node(body: NodeIn, db: Session = Depends(get_db), user: User = Depends(require(Role.admin))):
    item = Node(**body.model_dump(exclude={"secret", "public_address"}), secret_encrypted=encrypt(body.secret), public_address=body.public_address or body.host)
    db.add(item)
    db.flush()
    try:
        gateway = platform_gateway_node(db)
        result = ensure_node_runtime(item, gateway.host if gateway else None)
        result = test_node(item)
        if item.docker_proxy_enabled:
            apply_node_docker_proxy(item, db, True)
        item.last_status = "online"
        item.last_error = None
    except Exception as exc:
        item.last_status = "error"
        item.last_error = str(exc)
    audit(db, user, "create_node", "node", item.id, item.name)
    db.commit()
    db.refresh(item)
    return item


@app.post("/api/nodes/{item_id}/test")
def check_node(item_id: str, db: Session = Depends(get_db), user: User = Depends(require(Role.admin, Role.deployer))):
    item = db.get(Node, item_id)
    if not item:
        raise HTTPException(404, "节点不存在")
    try:
        result = test_node(item)
        item.last_status, item.last_error = "online", None
    except Exception as exc:
        item.last_status, item.last_error = "error", str(exc)
        result = {"detail": str(exc)}
    audit(db, user, "test_node", "node", item.id, item.last_status)
    db.commit()
    return {"status": item.last_status, **result}


@app.get("/api/nodes/{item_id}/docker-proxy-status")
def node_docker_proxy_status(item_id: str, db: Session = Depends(get_db), _: User = Depends(require(Role.admin))):
    item = db.get(Node, item_id)
    if not item:
        raise HTTPException(404, "节点不存在")
    try:
        with SSHNode(item) as ssh:
            code, output = ssh.run(
                "printf '__FILE__'; test -f /etc/systemd/system/docker.service.d/yunzhou-proxy.conf && echo 1 || echo 0; "
                # Older systemd releases do not support `systemctl show
                # --value`.  Keep the property name and strip it while parsing.
                "printf '__ENV__'; systemctl show docker --property=Environment --no-pager",
                timeout=15,
            )
            if code:
                raise RuntimeError(output or "无法读取 Docker 服务环境")
        configured = "__FILE__1" in output
        environment = output.split("__ENV__", 1)[-1].strip()
        if environment.startswith("Environment="):
            environment = environment.split("=", 1)[1]
        http_match = re.search(r"(?:^|\s)HTTP_PROXY=([^\s]+)", environment)
        https_match = re.search(r"(?:^|\s)HTTPS_PROXY=([^\s]+)", environment)
        no_proxy_match = re.search(r'(?:^|\s)NO_PROXY=(?:"([^"]+)"|([^\s]+))', environment)
        active_no_proxy = (no_proxy_match.group(1) or no_proxy_match.group(2) or "") if no_proxy_match else ""
        required_no_proxy = ["registry", "yunzhou.hub", "yunzhou.hub:5000"]
        missing_no_proxy = [value for value in required_no_proxy if value not in active_no_proxy.split(",")]
        active = bool(http_match or https_match)
        item.docker_proxy_enabled = active
        item.docker_proxy_status = "active" if active else "disabled"
        item.docker_proxy_error = None
        db.commit()
        return {
            "active": active,
            "configured": configured,
            "pending_restart": configured != active or bool(active and missing_no_proxy),
            "http_proxy": redact_proxy(http_match.group(1) if http_match else ""),
            "https_proxy": redact_proxy(https_match.group(1) if https_match else ""),
            "source": "/etc/systemd/system/docker.service.d/yunzhou-proxy.conf",
            "missing_no_proxy": missing_no_proxy,
        }
    except Exception as exc:
        item.docker_proxy_status = "error"
        item.docker_proxy_error = str(exc)
        db.commit()
        raise HTTPException(502, f"读取 Docker 代理状态失败：{exc}") from exc


@app.post("/api/nodes/test-connection")
def test_node_config(body: NodeTest, db: Session = Depends(get_db), _: User = Depends(require(Role.admin))):
    existing = db.get(Node, body.node_id) if body.node_id else None
    secret_encrypted = encrypt(body.secret) if body.secret else (existing.secret_encrypted if existing else None)
    if not secret_encrypted:
        raise HTTPException(400, "请填写 SSH 密码或私钥")
    candidate = Node(
        name=body.name,
        host=body.host,
        port=body.port,
        username=body.username,
        auth_type=body.auth_type,
        secret_encrypted=secret_encrypted,
        public_address=body.public_address or body.host,
        work_dir=body.work_dir,
    )
    try:
        result = test_node(candidate)
        return {"ok": True, "message": "服务器连接成功", **result}
    except Exception as exc:
        raise HTTPException(502, f"服务器连接失败：{exc}") from exc


def apply_node_docker_proxy(node: Node, db: Session, enabled: bool, restart: bool = True) -> None:
    """Apply the shared application proxy to one node's Docker daemon."""
    config = get_proxy_config(db)
    if enabled and (not config or not config.enabled):
        raise RuntimeError("请先在系统设置中启用应用网络代理")
    password = decrypt(config.proxy_password_encrypted) if config and config.proxy_password_encrypted else ""
    http_proxy = proxy_with_auth(config.http_proxy if config else "", config.proxy_username if config else "", password or "")
    https_proxy = proxy_with_auth((config.https_proxy or config.http_proxy) if config else "", config.proxy_username if config else "", password or "")
    if enabled and not (http_proxy or https_proxy):
        raise RuntimeError("系统代理地址为空")
    base_no_proxy = ["localhost", "127.0.0.1", "::1", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
    configured = [value.strip() for value in ((config.no_proxy if config else "") or "").split(",") if value.strip()]
    no_proxy = ",".join(dict.fromkeys(base_no_proxy + configured + [node.host, node.public_address or ""]))

    def systemd_value(value: str) -> str:
        return value.replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%")

    gateway = platform_gateway_node(db)
    restart_is_self_managed = bool(gateway and gateway.id == node.id)
    with SSHNode(node) as ssh:
        if enabled:
            content = (
                "[Service]\n"
                f'Environment="HTTP_PROXY={systemd_value(http_proxy or https_proxy)}"\n'
                f'Environment="HTTPS_PROXY={systemd_value(https_proxy or http_proxy)}"\n'
                f'Environment="NO_PROXY={systemd_value(no_proxy)}"\n'
            )
            prepare = (
                "install -d -m 0755 /etc/systemd/system/docker.service.d && "
                f"printf %s {shlex.quote(content)} > /etc/systemd/system/docker.service.d/yunzhou-proxy.conf && "
                "systemctl daemon-reload"
            )
        else:
            prepare = (
                "rm -f /etc/systemd/system/docker.service.d/yunzhou-proxy.conf && "
                "systemctl daemon-reload"
            )
        if not restart:
            code, output = ssh.run(prepare, timeout=20)
            if code:
                raise RuntimeError((output or "Docker 代理配置文件更新失败")[-600:])
            node.docker_proxy_status = "pending"
            node.docker_proxy_error = None
            return
        if restart_is_self_managed:
            # Restarting Docker on the host that runs this API interrupts the
            # current HTTP request. Persist and acknowledge first, then restart
            # from a fully detached process a few seconds later.
            command = (
                prepare + " && "
                "nohup setsid sh -c 'sleep 6; systemctl restart docker' "
                ">/tmp/yunzhou-docker-restart.log 2>&1 </dev/null &"
            )
            code, output = ssh.run(command, timeout=15)
        else:
            command = prepare + " && timeout 90 systemctl restart docker && systemctl is-active docker"
            code, output = ssh.run(command, timeout=110)
        if code or (not restart_is_self_managed and output.strip().splitlines()[-1:] != ["active"]):
            raise RuntimeError((output or "Docker 服务重启失败")[-600:])
    node.docker_proxy_status = "active" if enabled else "disabled"
    node.docker_proxy_error = None


@app.put("/api/nodes/{item_id}/docker-proxy-config")
def stage_node_docker_proxy_config(item_id: str, body: dict, db: Session = Depends(get_db), user: User = Depends(require(Role.admin))):
    item = db.get(Node, item_id)
    if not item:
        raise HTTPException(404, "节点不存在")
    enabled = bool(body.get("enabled"))
    try:
        apply_node_docker_proxy(item, db, enabled, restart=False)
    except Exception as exc:
        raise HTTPException(502, f"更新 Docker 代理配置文件失败：{exc}") from exc
    audit(db, user, "stage_node_docker_proxy", "node", item.id, "enable" if enabled else "disable")
    db.commit()
    return {"ok": True, "configured": enabled, "pending_restart": enabled != item.docker_proxy_enabled}


@app.patch("/api/nodes/{item_id}", response_model=NodeOut)
def update_node(item_id: str, body: NodeUpdate, db: Session = Depends(get_db), user: User = Depends(require(Role.admin))):
    item = db.get(Node, item_id)
    if not item:
        raise HTTPException(404, "节点不存在")
    proxy_changed = body.docker_proxy_enabled != item.docker_proxy_enabled
    for key, value in body.model_dump(exclude={"secret"}).items():
        setattr(item, key, value)
    if body.secret:
        item.secret_encrypted = encrypt(body.secret)
    try:
        gateway = platform_gateway_node(db)
        ensure_node_runtime(item, gateway.host if gateway else None)
        test_node(item)
        item.last_status, item.last_error = "online", None
        if proxy_changed:
            try:
                apply_node_docker_proxy(item, db, body.docker_proxy_enabled)
            except Exception as exc:
                item.docker_proxy_status = "error"
                item.docker_proxy_error = str(exc)
    except Exception as exc:
        item.last_status, item.last_error = "error", str(exc)
    audit(db, user, "update_node", "node", item.id, item.name)
    db.commit()
    db.refresh(item)
    return item


@app.delete("/api/nodes/{item_id}")
def delete_node(item_id: str, db: Session = Depends(get_db), user: User = Depends(require(Role.admin))):
    item = db.get(Node, item_id)
    if not item:
        raise HTTPException(404, "节点不存在")
    db.delete(item)
    audit(db, user, "delete_node", "node", item_id)
    db.commit()
    return {"ok": True}


@app.get("/api/credentials", response_model=list[CredentialOut])
def list_credentials(db: Session = Depends(get_db), _: User = Depends(require(Role.admin, Role.deployer))):
    return db.scalars(select(GitCredential).order_by(GitCredential.created_at)).all()


@app.post("/api/credentials", response_model=CredentialOut)
def create_credential(body: CredentialIn, db: Session = Depends(get_db), user: User = Depends(require(Role.admin, Role.deployer))):
    item = GitCredential(name=body.name, auth_type=body.auth_type, username=body.username, secret_encrypted=encrypt(body.secret))
    db.add(item)
    db.flush()
    audit(db, user, "create_credential", "credential", item.id, item.name)
    db.commit()
    db.refresh(item)
    return item


@app.post("/api/credentials/test-git")
def test_git_connection(body: GitConnectionTest, db: Session = Depends(get_db), _: User = Depends(require(Role.admin, Role.deployer))):
    raw_url = body.git_url.strip()
    url, url_branch, source_path = git_source_location(raw_url, body.git_branch)
    if not url:
        raise HTTPException(400, "请填写 Git 仓库地址")
    credential = db.get(GitCredential, body.credential_id) if body.credential_id else None
    if body.credential_id and not credential:
        raise HTTPException(404, "选择的 Git 凭据不存在")
    env = dict(__import__("os").environ)
    key_path = None
    secret = ""
    if credential:
        secret = decrypt(credential.secret_encrypted) or ""
        if credential.auth_type in ("token", "password") and url.startswith(("http://", "https://")):
            parts = urlsplit(url)
            username = quote(credential.username or "oauth2", safe="")
            url = urlunsplit((parts.scheme, f"{username}:{quote(secret, safe='')}@{parts.netloc}", parts.path, parts.query, parts.fragment))
        elif credential.auth_type == "ssh_key":
            handle = tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=False, prefix="yunzhou-git-key-")
            handle.write(secret)
            handle.close()
            Path(handle.name).chmod(0o600)
            key_path = handle.name
            env["GIT_SSH_COMMAND"] = f"ssh -i {shlex.quote(key_path)} -o StrictHostKeyChecking=no"
    proxy = get_proxy_config(db)
    route = "服务器直连"
    if proxy and proxy.enabled:
        if proxy.http_proxy or proxy.https_proxy:
            env["HTTP_PROXY"] = proxy.http_proxy or proxy.https_proxy
            env["HTTPS_PROXY"] = proxy.https_proxy or proxy.http_proxy
            env["NO_PROXY"] = proxy.no_proxy or ""
            route = "系统应用代理"
    try:
        branch = url_branch
        command = ["git", "ls-remote", "--heads", url] + ([branch] if branch else [])
        result = subprocess.run(command, capture_output=True, text=True, timeout=25, env=env)
        if result.returncode:
            raise HTTPException(502, "Git 仓库连接失败，请检查地址、凭据和网络")
        lines = [line for line in result.stdout.splitlines() if line.strip()]
        if branch and not lines:
            raise HTTPException(404, f"仓库可以连接，但没有找到分支 {branch}")
        revision = lines[0].split()[0][:12] if lines else None
        return {"ok": True, "message": "仓库连接和凭据验证通过", "branch": branch or "全部分支", "revision": revision, "network_route": route, "source_path": ("/" + source_path) if source_path else "/（仓库根目录）"}
    except subprocess.TimeoutExpired:
        raise HTTPException(504, "Git 仓库连接超时，请检查网络或代理配置")
    finally:
        if key_path:
            Path(key_path).unlink(missing_ok=True)


@app.get("/api/projects", response_model=list[ProjectOut])
def list_projects(db: Session = Depends(get_db), _: User = Depends(current_user)):
    return db.scalars(select(Project).order_by(desc(Project.created_at))).all()


@app.post("/api/projects", response_model=ProjectOut)
def create_project(body: ProjectCreate, tasks: BackgroundTasks, db: Session = Depends(get_db), user: User = Depends(require(Role.admin, Role.deployer))):
    if db.scalar(select(Project).where(Project.slug == body.slug)):
        raise HTTPException(409, "项目标识已存在")
    data = body.model_dump(exclude={"env_text"})
    item = Project(**data, env_text_encrypted=encrypt(body.env_text), owner_id=user.id)
    db.add(item)
    db.flush()
    if item.source_type == SourceType.git:
        item.integration_analysis_json = json.dumps({
            "status": "queued", "phase": "queued", "progress": 5,
            "summary": "项目已保存，等待后台拉取源码。",
            "queued_at": datetime.now(timezone.utc).isoformat(),
        }, ensure_ascii=False)
    audit(db, user, "create_project", "project", item.id, item.name)
    db.commit()
    db.refresh(item)
    # The durable worker consumes the queued state. Do not bind source work to
    # the API request process: an API restart must not lose a clone/analysis.
    return item


@app.post("/api/projects/{item_id}/upload", response_model=ProjectOut)
async def upload_source(item_id: str, tasks: BackgroundTasks, files: list[UploadFile] = File(...), append: bool = False, finalize: bool = True, db: Session = Depends(get_db), user: User = Depends(require(Role.admin, Role.deployer))):
    project = db.get(Project, item_id)
    if not project:
        raise HTTPException(404, "项目不存在")
    project_root = Path(settings.upload_root) / project.id
    target = project_root / "staging"
    if not append:
        shutil.rmtree(target, ignore_errors=True)
    target.mkdir(parents=True, exist_ok=True)
    max_source_bytes = 2 * 1024 * 1024 * 1024
    total_bytes = sum(path.stat().st_size for path in target.rglob("*") if path.is_file()) if append else 0
    existing_files = sum(1 for path in target.rglob("*") if path.is_file()) if append else 0
    if existing_files + len(files) > 30_000:
        raise HTTPException(413, "源码文件数量超过 30000 个，请排除 node_modules、构建产物后重新上传")
    for upload in files:
        relative = PurePosixPath((upload.filename or "file").replace("\\", "/"))
        if relative.is_absolute() or ".." in relative.parts:
            raise HTTPException(400, "文件路径不安全")
        output = target.joinpath(*relative.parts)
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("wb") as handle:
            while chunk := await upload.read(1024 * 1024):
                total_bytes += len(chunk)
                if total_bytes > max_source_bytes:
                    handle.close()
                    output.unlink(missing_ok=True)
                    raise HTTPException(413, "源码上传内容超过 2 GB，请排除依赖目录和构建产物后重新上传")
                handle.write(chunk)
    if not finalize:
        return project
    if len(files) == 1 and files[0].filename and files[0].filename.lower().endswith(".zip"):
        archive = next(target.glob("*.zip"))
        extract_dir = target / "source"
        extract_dir.mkdir()
        with zipfile.ZipFile(archive) as zf:
            members = zf.infolist()
            if len(members) > 30_000 or sum(member.file_size for member in members) > max_source_bytes:
                raise HTTPException(413, "ZIP 解压后的源码超过 2 GB 或 30000 个文件")
            for member in members:
                destination = (extract_dir / member.filename).resolve()
                if extract_dir.resolve() not in destination.parents and destination != extract_dir.resolve():
                    raise HTTPException(400, "ZIP 包含不安全路径")
                if (member.external_attr >> 16) & 0o170000 == 0o120000:
                    raise HTTPException(400, "ZIP 包含不安全的符号链接")
            zf.extractall(extract_dir)
        archive.unlink()
        target = extract_dir
    children = [x for x in target.iterdir() if not x.name.startswith(".")]
    markers = [target / name for name in ("Dockerfile", "compose.yaml", "compose.yml", "docker-compose.yml", "docker-compose.yaml")]
    if not any(x.exists() for x in markers) and len(children) == 1 and children[0].is_dir():
        target = children[0]
    relative_source = target.relative_to(project_root / "staging")
    current = project_root / "current"
    versions = project_root / "versions"
    versions.mkdir(parents=True, exist_ok=True)
    if current.exists():
        archived = versions / datetime.now().strftime("%Y%m%d%H%M%S")
        current.rename(archived)
    staging = project_root / "staging"
    staging.rename(current)
    project.source_path = str(current / relative_source)
    project.integration_analysis_json = json.dumps({
        "status": "queued", "phase": "queued", "progress": 5,
        "summary": "源码已上传，等待后台 AI 分析。",
        "queued_at": datetime.now(timezone.utc).isoformat(),
    }, ensure_ascii=False)
    old_versions = sorted((x for x in versions.iterdir() if x.is_dir()), key=lambda x: x.name, reverse=True)
    for obsolete in old_versions[3:]:
        shutil.rmtree(obsolete, ignore_errors=True)
    audit(db, user, "upload_source", "project", project.id, f"source updated; {len(files)} files; kept {min(len(old_versions), 3)} previous versions")
    db.commit()
    db.refresh(project)
    # The durable worker consumes the queued state.
    return project


@app.get("/api/projects/{item_id}", response_model=ProjectOut)
def get_project(item_id: str, db: Session = Depends(get_db), _: User = Depends(current_user)):
    item = db.get(Project, item_id)
    if not item:
        raise HTTPException(404, "项目不存在")
    return item


@app.get("/api/projects/{item_id}/environment")
def get_project_environment(item_id: str, db: Session = Depends(get_db), _: User = Depends(require(Role.admin, Role.deployer))):
    item = db.get(Project, item_id)
    if not item:
        raise HTTPException(404, "项目不存在")
    return {
        "env_text": decrypt(item.env_text_encrypted) or "",
        "managed_env_text": item.managed_env_text or "",
        "integration_analysis": json.loads(item.integration_analysis_json) if item.integration_analysis_json else None,
    }


def _env_map(value: str | None) -> dict[str, str]:
    result = {}
    for line in (value or "").splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            key, content = line.split("=", 1)
            result[key.strip()] = content.strip()
    return result


@app.get("/api/projects/{item_id}/managed-credentials")
def get_project_managed_credentials(
    item_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(require(Role.admin, Role.deployer)),
):
    """Return only credentials generated and owned by this platform.

    External database and Redis settings are deliberately excluded, so this
    endpoint can never become a general secret dump for user-supplied systems.
    """
    item = db.get(Project, item_id)
    if not item:
        raise HTTPException(404, "项目不存在")
    user_values = _env_map(decrypt(item.env_text_encrypted) or "")
    managed = _env_map(item.managed_env_text or "")
    rows = []
    if user_values.get("YUNZHOU_REDIS_MODE", "managed").lower() != "external" and managed.get("YUNZHOU_REDIS_PASSWORD"):
        rows.append({
            "service": "redis", "label": "Redis", "scope": "项目内部网络",
            "host": managed.get("YUNZHOU_REDIS_HOST", "redis"),
            "port": managed.get("YUNZHOU_REDIS_PORT", "6379"),
            "database": managed.get("YUNZHOU_REDIS_DATABASE", "0"),
            "username": "", "password": managed["YUNZHOU_REDIS_PASSWORD"],
        })
    # Older AI-generated Compose plans used project-specific names such as
    # CRM_DB_PASSWORD before the platform introduced the canonical
    # YUNZHOU_MYSQL_* keys.  They are still platform-owned credentials and
    # must remain visible/copyable.  External credentials are never included.
    mysql_password = managed.get("YUNZHOU_MYSQL_PASSWORD", "")
    if not mysql_password:
        mysql_password = next((
            value for key, value in managed.items()
            if re.search(r"(?:^|_)DB_PASSWORD$", key, re.I) and "ROOT" not in key.upper()
        ), "")
    mysql_url = next((
        values.get(key, "") for values in (managed, user_values)
        for key in ("SPRING_DATASOURCE_URL", "DATABASE_URL", "JDBC_URL")
        if values.get(key)
    ), "")
    mysql_url_match = re.search(r"(?i)(?:jdbc:)?mysql://([^/:?]+)(?::(\d+))?/([^?\s]+)", mysql_url)
    mysql_database = managed.get("YUNZHOU_MYSQL_DATABASE", "")
    mysql_username = managed.get("YUNZHOU_MYSQL_USERNAME", "")
    if mysql_url_match:
        mysql_database = mysql_database or mysql_url_match.group(3)
    if not mysql_username:
        mysql_username = next((
            values.get(key, "") for values in (managed, user_values)
            for key in ("SPRING_DATASOURCE_USERNAME", "MYSQL_USER", "DB_USERNAME", "DB_USER")
            if values.get(key)
        ), "")
    # Platform-generated MySQL stacks use a dedicated application account
    # whose name matches the generated database when no explicit username was
    # persisted by a legacy plan.
    mysql_username = mysql_username or mysql_database
    if user_values.get("YUNZHOU_MYSQL_MODE", "managed").lower() != "external" and mysql_password:
        rows.append({
            "service": "mysql", "label": "MySQL", "scope": "项目内部网络",
            "host": managed.get("YUNZHOU_MYSQL_HOST") or (mysql_url_match.group(1) if mysql_url_match else "mysql"),
            "port": managed.get("YUNZHOU_MYSQL_PORT") or (mysql_url_match.group(2) if mysql_url_match else None) or "3306",
            "database": mysql_database,
            "username": mysql_username,
            "password": mysql_password,
        })
    audit(db, user, "view_managed_credentials", "project", item_id, f"services={','.join(row['service'] for row in rows)}")
    db.commit()
    return {"items": rows, "managed_only": True}


def _project_data_exposures(item: Project) -> dict[str, dict]:
    try:
        value = json.loads(item.data_exposure_json or "{}")
        return value if isinstance(value, dict) else {}
    except (TypeError, ValueError):
        return {}


def _active_compose_deployment(db: Session, project_id: str) -> Deployment | None:
    return db.scalar(select(Deployment).where(
        Deployment.project_id == project_id,
        Deployment.status == DeployStatus.success,
        Deployment.release.is_not(None),
    ).order_by(desc(Deployment.finished_at), desc(Deployment.created_at)))


def _exposure_result(item: Project, deployment: Deployment | None, db: Session) -> list[dict]:
    configs = _project_data_exposures(item)
    node = db.get(Node, deployment.node_id) if deployment else None
    gateway = platform_gateway_node(db)
    result = []
    for service in ("mysql", "redis"):
        config = configs.get(service) if isinstance(configs.get(service), dict) else {}
        enabled = bool(config.get("enabled"))
        mode = str(config.get("mode") or "direct")
        port = int(config.get("host_port") or 0)
        target_port = int(config.get("target_port") or port or 0)
        endpoint_node = gateway if mode == "gateway" and gateway else node
        public_host = (endpoint_node.public_address or endpoint_node.host) if endpoint_node else ""
        result.append({
            "service": service,
            "enabled": enabled,
            "bind_address": "0.0.0.0",
            "host_port": port or None,
            "public_host": public_host,
            "connection_address": f"{public_host}:{port}" if enabled and public_host and port else "",
            "mode": mode,
            "target_host": node.host if node else "",
            "target_port": target_port or None,
            "container_port": 3306 if service == "mysql" else 6379,
            "allow_cidrs": config.get("allow_cidrs") or ["0.0.0.0/0"],
            "node_name": node.name if node else "",
            "gateway_name": gateway.name if gateway else "",
            "updated_at": config.get("updated_at"),
        })
    return result


@app.get("/api/projects/{item_id}/data-exposures")
def get_project_data_exposures(
    item_id: str,
    db: Session = Depends(get_db),
    _: User = Depends(require(Role.admin, Role.deployer)),
):
    item = db.get(Project, item_id)
    if not item:
        raise HTTPException(404, "项目不存在")
    return {"items": _exposure_result(item, _active_compose_deployment(db, item.id), db)}


def _next_external_data_port(db: Session, node: Node, requested: int | None = None) -> int:
    policy = get_deployment_settings(db)
    start, end = policy.external_port_start, policy.external_port_end
    reserved = {policy.default_domain_http_port, policy.default_domain_https_port, 22, 80, 443, 7080, 5000}
    for project in db.scalars(select(Project)).all():
        for config in _project_data_exposures(project).values():
            if isinstance(config, dict) and config.get("enabled") and config.get("host_port"):
                reserved.add(int(config["host_port"]))
    candidates = [requested] if requested else range(start, end + 1)
    for value in candidates:
        port = int(value or 0)
        if port < 1024 or port > 65535:
            continue
        if not requested and port in reserved:
            continue
        free = True
        with SSHNode(node) as ssh:
            code, _ = ssh.run(
                "(ss -ltnH 2>/dev/null | awk '{print $4}' | "
                f"grep -Eq ':{port}$') || (docker ps --format '{{{{.Ports}}}}' | grep -Eq '(^|[^0-9]){port}->')"
            )
        if code == 0:
            free = False
        if free:
            return port
    if requested:
        raise HTTPException(409, f"端口 {requested} 已被占用，请换一个端口")
    raise HTTPException(409, "外部访问端口池已用完，请在系统设置中扩大端口范围")


def _next_internal_data_port(db: Session, node: Node, requested: int | None = None) -> int:
    policy = get_deployment_settings(db)
    start, end = policy.internal_port_start, policy.internal_port_end
    reserved = set(db.scalars(select(Deployment.host_port).where(
        Deployment.node_id == node.id,
        Deployment.host_port.is_not(None),
        Deployment.status.in_([DeployStatus.queued, DeployStatus.running, DeployStatus.success]),
    )).all())
    for project in db.scalars(select(Project)).all():
        for config in _project_data_exposures(project).values():
            if isinstance(config, dict) and config.get("enabled"):
                value = config.get("target_port")
                if value:
                    reserved.add(int(value))
    candidates = [requested] if requested else range(start, end + 1)
    for value in candidates:
        port = int(value or 0)
        if port < 1024 or port > 65535 or (not requested and port in reserved):
            continue
        with SSHNode(node) as ssh:
            code, _ = ssh.run(
                "(ss -ltnH 2>/dev/null | awk '{print $4}' | "
                f"grep -Eq ':{port}$') || (docker ps --format '{{{{.Ports}}}}' | grep -Eq '(^|[^0-9]){port}->')"
            )
        if code != 0:
            return port
    if requested:
        raise HTTPException(409, f"内网实例端口 {requested} 已被占用")
    raise HTTPException(409, "内网实例端口池已用完，请在系统设置中扩大端口范围")


def _apply_data_exposure(
    item: Project,
    deployment: Deployment,
    node: Node,
    configs: dict[str, dict],
    changed_service: str,
    old_config: dict,
    gateway: Node | None,
) -> None:
    release_dir = f"{node.work_dir.rstrip('/')}/{project_directory(item)}/{deployment.release}"
    legacy_dir = f"{node.work_dir.rstrip('/')}/{item.name}/{deployment.release}"
    compose_names = [".yunzhou.ai.compose.yml", ".yunzhou.compose.yml", "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"]
    enabled = {
        name: cfg for name, cfg in configs.items()
        if name in {"mysql", "redis"} and isinstance(cfg, dict) and cfg.get("enabled") and cfg.get("host_port")
    }
    lines = ["services:"]
    target_ports = {"mysql": 3306, "redis": 6379}
    for name, cfg in enabled.items():
        mapped_port = int(cfg.get("target_port") or cfg["host_port"])
        lines.extend([f"  {name}:", "    ports:", f"      - \"0.0.0.0:{mapped_port}:{target_ports[name]}\""])
    content = "\n".join(lines) + "\n"
    encoded = base64.b64encode(content.encode()).decode()
    chain = "YZD" + hashlib.sha256(f"{item.id}:{changed_service}".encode()).hexdigest()[:10].upper()
    old_port = int(old_config.get("target_port") or old_config.get("host_port") or 0)
    cfg = configs.get(changed_service) or {}
    new_port = int(cfg.get("target_port") or cfg.get("host_port") or 0)
    public_port = int(cfg.get("host_port") or 0)
    cidrs = cfg.get("allow_cidrs") or ["0.0.0.0/0"]
    mode = str(cfg.get("mode") or "direct")
    target_cidrs = cidrs
    if mode == "gateway" and gateway and gateway.id != node.id:
        target_cidrs = [f"{gateway.host}/32"]
    with SSHNode(node) as ssh:
        _, actual = ssh.run(
            f"if [ -d {shlex.quote(release_dir)} ]; then printf %s {shlex.quote(release_dir)}; "
            f"elif [ -d {shlex.quote(legacy_dir)} ]; then printf %s {shlex.quote(legacy_dir)}; fi"
        )
        actual = actual.strip()
        if not actual:
            raise HTTPException(409, "当前线上版本目录不存在，请先重新部署项目")
        main_file = ""
        for name in compose_names:
            if ssh.run(f"test -f {shlex.quote(actual + '/' + name)}")[0] == 0:
                main_file = name
                break
        if not main_file:
            raise HTTPException(409, "当前项目不是 Compose 多服务部署，无法开放数据服务端口")
        override_path = actual + "/.yunzhou.external-access.yml"
        if enabled:
            command = f"printf %s {shlex.quote(encoded)} | base64 -d > {shlex.quote(override_path)}"
        else:
            command = f"rm -f -- {shlex.quote(override_path)}"
        code, output = ssh.run(command)
        if code:
            raise HTTPException(502, "写入外部访问配置失败：" + output[-500:])
        # Rebuild only the selected data-service container. Application
        # containers and persistent volumes remain untouched.
        files = [main_file]
        if ssh.run(f"test -f {shlex.quote(actual + '/.yunzhou.images.yml')}")[0] == 0:
            files.append(".yunzhou.images.yml")
        if enabled:
            files.append(".yunzhou.external-access.yml")
        args = " ".join(f"-f {shlex.quote(name)}" for name in files)
        code, output = ssh.run(
            f"cd {shlex.quote(actual)} && docker compose -p {shlex.quote('yz-' + item.slug)} {args} "
            f"up -d --no-deps --force-recreate {shlex.quote(changed_service)}",
            timeout=180,
        )
        if code:
            raise HTTPException(502, "应用端口映射失败：" + output[-1200:])
        # A dedicated DOCKER-USER chain keeps the allow-list effective even
        # when Docker publishes the port before the host INPUT chain.
        cleanup = (
            f"iptables -D DOCKER-USER -p tcp --dport {old_port or new_port} -j {chain} 2>/dev/null || true; "
            f"iptables -F {chain} 2>/dev/null || true; iptables -X {chain} 2>/dev/null || true"
        )
        ssh.run(cleanup)
        if cfg.get("enabled"):
            rules = "; ".join(f"iptables -A {chain} -s {shlex.quote(cidr)} -j RETURN" for cidr in target_cidrs)
            firewall = (
                f"iptables -N {chain} 2>/dev/null || true; iptables -F {chain}; {rules}; "
                f"iptables -A {chain} -j DROP; iptables -I DOCKER-USER 1 -p tcp --dport {new_port} -j {chain}"
            )
            code, output = ssh.run(firewall)
            if code:
                raise HTTPException(502, "端口已映射，但访问范围设置失败：" + output[-800:])
    # A private deployment node can optionally be reached through the public
    # platform node. DNAT keeps database traffic at TCP level; HTTP Nginx is
    # deliberately not involved.
    if gateway and gateway.id != node.id:
        nat_chain = "YZN" + hashlib.sha256(f"{item.id}:{changed_service}".encode()).hexdigest()[:10].upper()
        filter_chain = "YZF" + hashlib.sha256(f"{item.id}:{changed_service}".encode()).hexdigest()[:10].upper()
        old_gateway_port = int(old_config.get("host_port") or public_port or 0)
        old_target_port = int(old_config.get("target_port") or old_config.get("host_port") or new_port or 0)
        with SSHNode(gateway) as gateway_ssh:
            cleanup_gateway = (
                f"iptables -t nat -D PREROUTING -p tcp --dport {old_gateway_port} -j {nat_chain} 2>/dev/null || true; "
                f"iptables -t nat -D POSTROUTING -p tcp -d {shlex.quote(node.host)} --dport {old_target_port} -j MASQUERADE 2>/dev/null || true; "
                f"iptables -D FORWARD -p tcp -d {shlex.quote(node.host)} --dport {old_target_port} -j {filter_chain} 2>/dev/null || true; "
                f"iptables -t nat -F {nat_chain} 2>/dev/null || true; iptables -t nat -X {nat_chain} 2>/dev/null || true; "
                f"iptables -F {filter_chain} 2>/dev/null || true; iptables -X {filter_chain} 2>/dev/null || true"
            )
            gateway_ssh.run(cleanup_gateway)
            if cfg.get("enabled") and mode == "gateway":
                allow_rules = "; ".join(
                    f"iptables -A {filter_chain} -s {shlex.quote(cidr)} -j ACCEPT" for cidr in cidrs
                )
                relay = (
                    "sysctl -w net.ipv4.ip_forward=1 >/dev/null; "
                    f"iptables -t nat -N {nat_chain} 2>/dev/null || true; iptables -t nat -F {nat_chain}; "
                    f"iptables -t nat -A {nat_chain} -j DNAT --to-destination {shlex.quote(node.host)}:{new_port}; "
                    f"iptables -t nat -I PREROUTING 1 -p tcp --dport {public_port} -j {nat_chain}; "
                    f"iptables -t nat -I POSTROUTING 1 -p tcp -d {shlex.quote(node.host)} --dport {new_port} -j MASQUERADE; "
                    f"iptables -N {filter_chain} 2>/dev/null || true; iptables -F {filter_chain}; {allow_rules}; "
                    f"iptables -A {filter_chain} -j DROP; "
                    f"iptables -I FORWARD 1 -p tcp -d {shlex.quote(node.host)} --dport {new_port} -j {filter_chain}"
                )
                code, output = gateway_ssh.run(relay)
                if code:
                    raise HTTPException(502, "平台 TCP 转发应用失败：" + output[-800:])


@app.put("/api/projects/{item_id}/data-exposures/{service}")
def update_project_data_exposure(
    item_id: str,
    service: str,
    body: dict,
    db: Session = Depends(get_db),
    user: User = Depends(require(Role.admin)),
):
    service = service.lower().strip()
    if service not in {"mysql", "redis"}:
        raise HTTPException(400, "只支持 MySQL 或 Redis")
    item = db.get(Project, item_id)
    if not item:
        raise HTTPException(404, "项目不存在")
    deployment = _active_compose_deployment(db, item.id)
    if not deployment:
        raise HTTPException(409, "项目当前没有可调整的线上 Compose 版本")
    node = db.get(Node, deployment.node_id)
    if not node:
        raise HTTPException(409, "线上服务器不存在")
    # Only platform-created services can be exposed. External databases must
    # be managed at their original server instead of through this platform.
    credentials = get_project_managed_credentials(item.id, db, user)["items"]
    if service not in {row["service"] for row in credentials}:
        raise HTTPException(409, f"{service.upper()} 不是平台为该项目创建的服务，不能在这里开放端口")
    enabled = bool(body.get("enabled"))
    mode = "gateway"
    gateway = platform_gateway_node(db)
    if not gateway:
        raise HTTPException(409, "没有配置可用的公网平台节点，无法开启平台转发")
    raw_cidrs = body.get("allow_cidrs") or ["0.0.0.0/0"]
    if isinstance(raw_cidrs, str):
        raw_cidrs = re.split(r"[,\s]+", raw_cidrs.strip())
    cidrs = []
    for raw in raw_cidrs:
        if not str(raw).strip():
            continue
        try:
            cidrs.append(str(ipaddress.ip_network(str(raw).strip(), strict=False)))
        except ValueError:
            raise HTTPException(400, f"允许访问地址格式错误：{raw}")
    if enabled and not cidrs:
        raise HTTPException(400, "请至少填写一个允许访问的 IP 或网段")
    configs = _project_data_exposures(item)
    old_config = dict(configs.get(service) or {})
    old_mode = str(old_config.get("mode") or "direct")
    host_port = None
    target_port = None
    if enabled:
        # Existing platform routes keep their ports; legacy direct routes are
        # migrated once into the two independent configured port pools.
        if old_config.get("enabled") and old_mode == "gateway" and old_config.get("host_port") and old_config.get("target_port"):
            host_port = int(old_config["host_port"])
            target_port = int(old_config["target_port"])
        else:
            host_port = _next_external_data_port(db, gateway)
            target_port = _next_internal_data_port(db, node)
        configs[service] = {
            "enabled": True, "host_port": host_port, "target_port": target_port,
            "allow_cidrs": cidrs, "mode": mode,
            "updated_at": datetime.now(timezone.utc).isoformat(), "node_id": node.id,
        }
    else:
        configs[service] = {
            "enabled": False, "host_port": old_config.get("host_port"),
            "target_port": old_config.get("target_port"),
            "allow_cidrs": old_config.get("allow_cidrs") or cidrs,
            "mode": mode,
            "updated_at": datetime.now(timezone.utc).isoformat(), "node_id": node.id,
        }
    _apply_data_exposure(item, deployment, node, configs, service, old_config, platform_gateway_node(db))
    item.data_exposure_json = json.dumps(configs, ensure_ascii=False)
    audit(db, user, "update_data_exposure", "project", item.id, f"service={service}; enabled={enabled}; public_port={host_port or ''}; target_port={target_port or ''}; cidrs={','.join(cidrs)}")
    db.commit()
    return {"ok": True, "items": _exposure_result(item, deployment, db)}


@app.put("/api/projects/{item_id}/environment")
def update_project_environment(item_id: str, body: dict, db: Session = Depends(get_db), user: User = Depends(require(Role.admin, Role.deployer))):
    item = db.get(Project, item_id)
    if not item:
        raise HTTPException(404, "项目不存在")
    env_text = str(body.get("env_text") or "")
    invalid = [line for line in env_text.splitlines() if line.strip() and not line.lstrip().startswith("#") and "=" not in line]
    if invalid:
        raise HTTPException(400, "环境变量格式应为 KEY=VALUE，每行一项")
    item.env_text_encrypted = encrypt(env_text.strip() + "\n" if env_text.strip() else "")
    audit(db, user, "update_project_environment", "project", item.id, "environment updated")
    db.commit()
    return {"ok": True}


def _source_workspace_metadata(item: Project) -> tuple[str | None, str | None]:
    """Return the durable source location shown by analysis progress/results.

    Git projects keep a project-level checkout between analysis and deployment
    runs.  Upload projects already have a durable ``current`` source tree, so
    reporting the Git cache path for them would point at a directory that is
    intentionally never created.
    """
    if item.source_type == SourceType.git:
        cache = f"{settings.build_data_root.rstrip('/')}/builder/projects/{item.slug}/source-cache"
        return cache, cache
    source = str(item.source_path or "").strip() or None
    return source, None


@app.post("/api/projects/{item_id}/integration-analysis")
def analyze_project_integrations(item_id: str, db: Session = Depends(get_db), user: User = Depends(require(Role.admin, Role.deployer))):
    item = db.get(Project, item_id)
    if not item:
        raise HTTPException(404, "项目不存在")
    cleanup_root = None
    try:
        previous_state = item.source_analysis or {}
        started_at = previous_state.get("started_at") or datetime.now(timezone.utc).isoformat()
        pulling_summary = "正在拉取 Git 仓库和指定分支。" if item.source_type == SourceType.git else "正在读取已上传的源码。"
        workspace_path, repository_cache_path = _source_workspace_metadata(item)
        item.integration_analysis_json = json.dumps({
            "status": "running", "phase": "pulling", "progress": 25,
            "summary": pulling_summary, "started_at": started_at,
            "workspace_path": workspace_path,
            "repository_cache_path": repository_cache_path,
            "branch": item.git_branch or "默认分支",
        }, ensure_ascii=False)
        db.commit()
        source, revision, cleanup_root, source_subpath = stage_source(item, db)
        item = db.get(Project, item_id)
        workspace_path, repository_cache_path = _source_workspace_metadata(item)
        item.integration_analysis_json = json.dumps({
            "status": "running", "phase": "analyzing", "progress": 65,
            "summary": "源码已准备完成，正在识别技术栈、端口和外部依赖。",
            "started_at": started_at, "source_ready_at": datetime.now(timezone.utc).isoformat(),
            "revision": revision, "source_subpath": source_subpath or "",
            "workspace_path": workspace_path,
            "repository_cache_path": repository_cache_path,
            "branch": item.git_branch or "默认分支",
        }, ensure_ascii=False)
        db.commit()
        # Common infrastructure should be detected locally in seconds. Reserve
        # the slower model call for unusual integrations that static evidence
        # cannot classify.
        root = Path(source)
        config_text = ""
        config_names = {"application.yml", "application.yaml", "application.properties", ".env", ".env.example", "bootstrap.yml", "bootstrap.yaml", "package.json", "pom.xml", "build.gradle", "requirements.txt", "go.mod", "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}
        for path in root.rglob("*"):
            parts = path.relative_to(root).parts
            source_config = path.suffix.lower() in {".ts", ".js", ".mjs", ".cjs", ".py", ".java", ".go"} and any(part.lower() in {"config", "db", "database"} for part in parts[:-1])
            if not path.is_file() or (path.name not in config_names and not source_config) or any(part in {".git", "node_modules", "target", "dist", "build"} for part in parts):
                continue
            try:
                config_text += "\n" + path.read_text(encoding="utf-8", errors="ignore")[:80_000]
            except OSError:
                continue
            if len(config_text) > 600_000:
                break
        lower = config_text.lower()
        services, required, inferred = [], [], []
        if any(token in lower for token in ("jdbc:mysql", "mysql2", "mysql.createpool", "mysql", "druid")):
            services.append("MySQL")
            db_name = ""
            match = re.search(r"jdbc:mysql://[^/\s:'\"]+(?::\d+)?/([A-Za-z0-9_-]+)", config_text, re.I)
            if match:
                db_name = match.group(1)
            required.extend([
                {"key": "YUNZHOU_MYSQL_HOST", "reason": "现有 MySQL 地址", "secret": False},
                {"key": "YUNZHOU_MYSQL_PORT", "reason": "现有 MySQL 端口", "secret": False},
                {"key": "YUNZHOU_MYSQL_DATABASE", "reason": "数据库名称", "secret": False},
                {"key": "YUNZHOU_MYSQL_USERNAME", "reason": "现有 MySQL 用户名", "secret": False},
                {"key": "YUNZHOU_MYSQL_PASSWORD", "reason": "现有 MySQL 密码", "secret": True},
            ])
            inferred.append({"key": "YUNZHOU_MYSQL_PORT", "value": "3306", "source": "MySQL 默认端口", "confidence": "high"})
            if db_name:
                inferred.append({"key": "YUNZHOU_MYSQL_DATABASE", "value": db_name, "source": "源码 JDBC 配置", "confidence": "high"})
        if "redis" in lower:
            services.append("Redis")
            required.extend([
                {"key": "YUNZHOU_REDIS_HOST", "reason": "现有 Redis 地址", "secret": False},
                {"key": "YUNZHOU_REDIS_PORT", "reason": "Redis 端口，通常为 6379", "secret": False},
                {"key": "YUNZHOU_REDIS_PASSWORD", "reason": "Redis 密码；无密码时可留空", "secret": True},
                {"key": "YUNZHOU_REDIS_DATABASE", "reason": "Redis 库编号，通常为 0", "secret": False},
            ])
            inferred.extend([
                {"key": "YUNZHOU_REDIS_PORT", "value": "6379", "source": "Redis 默认端口", "confidence": "high"},
                {"key": "YUNZHOU_REDIS_DATABASE", "value": "0", "source": "Redis 默认库", "confidence": "high"},
            ])
        if any(token in lower for token in ("minio", "s3.endpoint", "aws_s3")):
            services.append("MinIO / S3")
            required.extend([
                {"key": "MINIO_ENDPOINT", "reason": "现有对象存储地址", "secret": False},
                {"key": "MINIO_ACCESS_KEY", "reason": "对象存储 Access Key", "secret": True},
                {"key": "MINIO_SECRET_KEY", "reason": "对象存储 Secret Key", "secret": True},
            ])
        local_services, local_required, local_inferred = services, required, inferred
        plan_error = None
        try:
            plan = analyze_project_deployment(db, item, source)
        except Exception as exc:
            plan = None
            plan_error = str(exc)
        if not plan and not local_services:
            raise HTTPException(503, "AI 源码分析暂不可用：" + (plan_error or "尚未启用可用的 AI 模型"))
        if plan:
            # Source evidence is authoritative for the public API prefix.  The
            # model identifies service roles, while this deterministic pass
            # selects the effective production/runtime prefix instead of
            # publishing every dev/stage alias or assuming a global /api.
            detected_traffic = detect_frontend_api_routes(source)
            detected_path = str(detected_traffic.get("primary_path") or "")
            traffic_plan = plan.get("traffic_plan") if isinstance(plan.get("traffic_plan"), dict) else {}
            service_roles = list(traffic_plan.get("service_roles") or [])
            role_by_service = {
                str(row.get("service") or ""): str(row.get("role") or "").lower()
                for row in service_roles if isinstance(row, dict)
            }
            planned_services = [str(value) for value in plan.get("services") or []]
            frontend_service = next((name for name, role in role_by_service.items() if role == "frontend"), "")
            backend_service = next((name for name, role in role_by_service.items() if role == "backend"), "")
            if not frontend_service:
                frontend_service = next((name for name in planned_services if re.search(r"front|web|ui", name, re.I)), "")
            if not backend_service:
                backend_service = next((name for name in planned_services if re.search(r"back|api|server", name, re.I)), "")
            if frontend_service and backend_service and detected_path:
                detected_route = (detected_traffic.get("routes") or [{}])[0]
                traffic_plan = {
                    **traffic_plan,
                    "default_service": frontend_service,
                    "api_paths": [str(detected_route.get("path") or detected_path + "/")],
                    "api_route_evidence": detected_traffic.get("evidence") or [],
                    "traffic_routes": [
                        {
                            "path": str(detected_route.get("path") or detected_path + "/"),
                            "service": backend_service,
                            "strip_prefix": bool(detected_route.get("strip_prefix", False)),
                        },
                        {"path": "/", "service": frontend_service, "strip_prefix": False},
                    ],
                }
                plan["traffic_plan"] = traffic_plan
            # A real, non-example .env referenced by the production Compose is
            # executable project configuration, not documentation.  Import it
            # into the platform's encrypted project environment on first
            # analysis so fixed-image applications keep their required public
            # URL and private runtime keys.  Never replace values the user has
            # already saved in the platform.
            existing_env = (decrypt(item.env_text_encrypted) or "").strip()
            source_env_path = root / ".env"
            compose_uses_env_file = any(
                path.is_file() and re.search(r"(?m)^\s*env_file\s*:\s*(?:\n\s*-\s*)?\.?/?\.env\s*$", path.read_text(encoding="utf-8", errors="ignore"))
                for path in (
                    root / "docker-compose.yml", root / "docker-compose.yaml",
                    root / "compose.yml", root / "compose.yaml",
                )
            )
            if not existing_env and source_env_path.is_file() and compose_uses_env_file:
                source_env = source_env_path.read_text(encoding="utf-8", errors="ignore").strip()
                populated = [
                    line for line in source_env.splitlines()
                    if line.strip() and not line.lstrip().startswith("#")
                    and "=" in line and line.split("=", 1)[1].strip()
                ]
                if populated:
                    item.env_text_encrypted = encrypt(source_env + "\n")
                    existing_env = source_env
                    audit(db, user, "import_production_env", "project", item.id, f"encrypted_keys={len(populated)}")
            services = []
            seen_services = set()
            for service in local_services + list(plan.get("services") or []):
                normalized = str(service).strip().lower()
                if normalized and normalized not in seen_services:
                    seen_services.add(normalized)
                    services.append(service)
            required_rows = local_required + list(plan.get("required_user_config") or [])
            inferred_rows = local_inferred + list(plan.get("inferred_config") or [])
            required = list({row.get("key"): row for row in required_rows if row.get("key")}.values())
            inferred = list({row.get("key"): row for row in inferred_rows if row.get("key")}.values())
            configured_keys = {
                line.split("=", 1)[0].strip()
                for line in existing_env.splitlines()
                if "=" in line and not line.lstrip().startswith("#") and line.split("=", 1)[1].strip()
            }
            required = [row for row in required if row.get("key") not in configured_keys]
            if item.deployment_mode == "managed_fresh":
                # Managed databases and their credentials are platform-owned.
                # Do not ask users for an external database or leak generated
                # secret placeholders into the source-analysis form.
                managed_keys = {
                    "YUNZHOU_HOST_PORT",
                    "YUNZHOU_MYSQL_HOST", "YUNZHOU_MYSQL_PORT", "YUNZHOU_MYSQL_DATABASE",
                    "YUNZHOU_MYSQL_USERNAME", "YUNZHOU_MYSQL_PASSWORD",
                    "CRM_DB_PASSWORD", "CRM_DB_ROOT_PASSWORD",
                    "YUNZHOU_REDIS_HOST", "YUNZHOU_REDIS_PORT", "YUNZHOU_REDIS_PASSWORD",
                    "YUNZHOU_REDIS_DATABASE", "CRM_REDIS_PASSWORD",
                    "MINIO_ENDPOINT", "MINIO_ACCESS_KEY", "MINIO_SECRET_KEY",
                    "MINIO_ROOT_USER", "MINIO_ROOT_PASSWORD",
                }
                required = [row for row in required if row.get("key") not in managed_keys]
                inferred = [
                    row for row in inferred
                    if not str(row.get("key") or "").startswith(("YUNZHOU_MYSQL_", "YUNZHOU_REDIS_"))
                ]
            else:
                # Preserve mode is decided per dependency, not as one global
                # "everything is external" switch.  A managed Redis/MySQL is
                # still created and injected by the platform, while only a
                # dependency explicitly selected as external is shown to the
                # user as required connection configuration.
                user_values = {}
                for line in (decrypt(item.env_text_encrypted) or "").splitlines():
                    if "=" in line and not line.lstrip().startswith("#"):
                        key, value = line.split("=", 1)
                        user_values[key.strip()] = value.strip()
                managed_prefixes = []
                if user_values.get("YUNZHOU_MYSQL_MODE", "managed").lower() != "external":
                    managed_prefixes.append("YUNZHOU_MYSQL_")
                if user_values.get("YUNZHOU_REDIS_MODE", "managed").lower() != "external":
                    managed_prefixes.append("YUNZHOU_REDIS_")
                if managed_prefixes:
                    required = [
                        row for row in required
                        if not str(row.get("key") or "").startswith(tuple(managed_prefixes))
                        and not (
                            str(row.get("key") or "") == "CRM_REDIS_PASSWORD"
                            and "YUNZHOU_REDIS_" in managed_prefixes
                        )
                    ]
                    inferred = [
                        row for row in inferred
                        if not str(row.get("key") or "").startswith(tuple(managed_prefixes))
                    ]
                # An explicitly external MySQL is expected to be an existing,
                # initialized business database.  Do not simultaneously ask
                # the user for a schema bootstrap script.
                if user_values.get("YUNZHOU_MYSQL_MODE", "managed").lower() == "external":
                    required = [
                        row for row in required
                        if str(row.get("key") or "") not in {"WMS_DB_SCHEMA_SQL", "DB_SCHEMA_SQL", "MYSQL_SCHEMA_SQL"}
                    ]
            summary = str(plan.get("mode_decision") or plan.get("summary") or "AI 已完成源码分析")
            model = plan.get("model") or plan.get("requested_model") or "平台 AI"
            item.integration_analysis_json = json.dumps({
                "status": "running", "phase": "preflight", "progress": 85,
                "summary": "AI 已生成部署方案，正在隔离副本中检查架构、构建文件和配置。",
                "started_at": started_at, "revision": revision,
            }, ensure_ascii=False)
            db.commit()
            previous_error = str(
                previous_state.get("previous_error")
                or previous_state.get("error")
                or (((previous_state.get("preflight") or {}).get("execution") or {}).get("error"))
                or ""
            )
            preflight = preflight_ai_deployment_plan(source, plan, item, db, previous_error)
        else:
            services, required, inferred = local_services, local_required, local_inferred
            summary = "AI 本次暂不可用，平台已保留本地源码识别结果；稍后可一键重新分析。"
            model = "平台本地兜底"
            preflight = None
        audit(db, user, "analyze_integrations", "project", item.id, f"required={len(required)}; inferred={len(inferred)}")
        db.commit()
        workspace_path, repository_cache_path = _source_workspace_metadata(item)
        result = {
            "status": "completed",
            "phase": "completed",
            "progress": 100,
            "summary": summary,
            "services": services,
            "required": required,
            "inferred": inferred,
            "model": model,
            "build_environment": list(plan.get("build_environment") or []) if plan else [],
            "deployment_kind": str(plan.get("deployment_kind") or "") if plan else "",
            "container_port": plan.get("container_port") if plan else None,
            "access_path": str(plan.get("access_path") or "/") if plan else "/",
            "ai_completed": bool(plan),
            "ai_error": plan_error if not plan else None,
            # Keep the executable result of the full source analysis. A publish
            # of the same revision can materialize this plan immediately instead
            # of calling the model for the same repository a second time.
            "deployment_plan": plan if plan else None,
            "preflight": preflight,
            "revision": revision,
            "started_at": started_at,
            "finished_at": datetime.now(timezone.utc).isoformat(),
            "workspace_path": workspace_path,
            "repository_cache_path": repository_cache_path,
            "branch": item.git_branch or "默认分支",
        }
        item.integration_analysis_json = json.dumps(result, ensure_ascii=False)
        db.commit()
        return result
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(502, f"AI 分析现有集成失败：{exc}")
    finally:
        if cleanup_root:
            shutil.rmtree(cleanup_root, ignore_errors=True)


def remember_analysis_outcome(db: Session, error: str, repaired: bool) -> None:
    """Persist sanitized analysis/preflight failures and verified recoveries."""
    normalized = (error or "").lower()
    normalized = re.sub(r"\x1b\[[0-9;?]*[a-zA-Z]", " ", normalized)
    normalized = re.sub(r"https?://\S+", "<url>", normalized)
    normalized = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "<ip>", normalized)
    normalized = re.sub(r"\b[0-9a-f]{12,}\b", "<id>", normalized)
    normalized = re.sub(r"\b\d+\b", "<n>", normalized)
    normalized = re.sub(r"(?i)(password|token|secret|api[_-]?key)\s*[=:]\s*\S+", r"\1=<redacted>", normalized)
    normalized = re.sub(r"\s+", " ", normalized).strip()[-4000:]
    if not normalized:
        return
    if "没有生成 dockerfile" in normalized:
        category, fingerprint = "analysis_incomplete_dockerfile", "AI selected Dockerfile but omitted its content"
    elif "could not resolve" in normalized or "module not found" in normalized:
        category, fingerprint = "source_missing_file", normalized[-700:]
    elif "lockfile" in normalized:
        category, fingerprint = "analysis_lockfile", normalized[-700:]
    elif "timeout" in normalized or "timed out" in normalized:
        category, fingerprint = "analysis_timeout", normalized[-700:]
    else:
        category, fingerprint = "analysis_preflight", normalized[-700:]
    signature = hashlib.sha256((category + "|" + fingerprint).encode()).hexdigest()
    row = db.scalar(select(DeploymentExperience).where(DeploymentExperience.signature == signature))
    if not row:
        row = DeploymentExperience(signature=signature, category=category, error_sample=normalized[-1200:])
        db.add(row)
    else:
        row.occurrences = (row.occurrences or 0) + 1
    if repaired:
        row.successful_repairs = (row.successful_repairs or 0) + 1
        row.verified = True
        row.last_verified_at = datetime.now(timezone.utc)
        row.repair_summary = json.dumps({
            "outcome": "verified_success",
            "stage": "source_analysis_preflight",
            "experience": "同类分析错误已通过受控回退或修复完成真实预演，后续优先复用并重新验证",
        }, ensure_ascii=False)
    else:
        row.failed_repairs = (row.failed_repairs or 0) + 1
    db.flush()


def run_project_integration_analysis(item_id: str, user_id: str) -> None:
    with SessionLocal() as db:
        item = db.get(Project, item_id)
        user = db.get(User, user_id)
        if not item or not user:
            return
        queued_state = item.source_analysis or {}
        previous_error = str(queued_state.get("previous_error") or queued_state.get("error") or "")
        workspace_path, repository_cache_path = _source_workspace_metadata(item)
        item.integration_analysis_json = json.dumps({
            "status": "running", "phase": "pulling", "progress": 15,
            "summary": "正在拉取 Git 仓库。" if item.source_type == SourceType.git else "正在读取上传源码。",
            "started_at": datetime.now(timezone.utc).isoformat(),
            "workspace_path": workspace_path,
            "repository_cache_path": repository_cache_path,
            "branch": item.git_branch or "默认分支",
            # Preserve the evidence across the queued -> running transition.
            # analyze_project_integrations reads this state to apply only the
            # platform's bounded, audited repair classifiers.
            "previous_error": previous_error,
        }, ensure_ascii=False)
        db.commit()
        try:
            analyze_project_integrations(item_id, db, user)
            item = db.get(Project, item_id)
            result = item.source_analysis if item else {}
            preflight = (result or {}).get("preflight") or {}
            if preflight.get("status") == "execution_failed":
                execution = preflight.get("execution") or {}
                remember_analysis_outcome(db, str(execution.get("error") or "真实预演失败"), False)
            elif previous_error:
                remember_analysis_outcome(db, previous_error, True)
        except Exception as exc:
            db.rollback()
            item = db.get(Project, item_id)
            if item:
                detail = exc.detail if isinstance(exc, HTTPException) else str(exc)
                previous = item.source_analysis or {}
                item.integration_analysis_json = json.dumps({
                    **previous, "status": "failed", "phase": "failed", "progress": 100,
                    "summary": "源码处理未完成", "error": str(detail)[:500],
                    "finished_at": datetime.now(timezone.utc).isoformat(),
                }, ensure_ascii=False)
                audit(db, user, "analyze_integrations_failed", "project", item.id, str(detail)[:1000])
                remember_analysis_outcome(db, str(detail), False)
                db.commit()


@app.post("/api/projects/{item_id}/integration-analysis/background")
def analyze_project_integrations_background(item_id: str, tasks: BackgroundTasks, db: Session = Depends(get_db), user: User = Depends(require(Role.admin, Role.deployer))):
    item = db.get(Project, item_id)
    if not item:
        raise HTTPException(404, "项目不存在")
    previous = item.source_analysis or {}
    state = {
        "status": "queued", "phase": "queued", "progress": 5,
        "summary": "项目已保存，等待后台拉取源码。" if item.source_type == SourceType.git else "源码已上传，等待后台分析。",
        "queued_at": datetime.now(timezone.utc).isoformat(),
        "previous_error": previous.get("error") or ((previous.get("preflight") or {}).get("execution") or {}).get("error"),
    }
    item.integration_analysis_json = json.dumps(state, ensure_ascii=False)
    db.commit()
    return state


@app.post("/api/projects/{item_id}/integration-test")
def test_project_integration(item_id: str, body: dict, db: Session = Depends(get_db), user: User = Depends(require(Role.admin, Role.deployer))):
    project = db.get(Project, item_id)
    if not project:
        raise HTTPException(404, "项目不存在")
    service = str(body.get("service") or "").lower()
    node_id = str(body.get("node_id") or "")
    if not node_id:
        latest = db.scalar(select(Deployment).where(
            Deployment.project_id == item_id,
            Deployment.status == DeployStatus.success,
        ).order_by(desc(Deployment.created_at)).limit(1))
        node_id = latest.node_id if latest else ""
    node = db.get(Node, node_id) if node_id else None
    if not node:
        raise HTTPException(400, "请先选择用于测试的目标服务器")
    host = str(body.get("host") or "").strip()
    if not host or not re.fullmatch(r"[A-Za-z0-9_.:-]+", host):
        raise HTTPException(400, "请输入有效的服务地址")
    try:
        port = int(body.get("port") or (3306 if service == "mysql" else 6379))
    except (TypeError, ValueError):
        raise HTTPException(400, "端口格式不正确")
    if not 1 <= port <= 65535:
        raise HTTPException(400, "端口范围不正确")
    try:
        with SSHNode(node, connect_timeout=8) as ssh:
            if service == "mysql":
                username = str(body.get("username") or "").strip()
                password = str(body.get("password") or "")
                database = str(body.get("database") or "").strip()
                if not username or not database:
                    raise HTTPException(400, "请填写数据库名称和 MySQL 用户名")
                cmd = (
                    "image=$(docker images --format '{{.Repository}}:{{.Tag}}' | grep -E '^mysql:' | head -n1); "
                    "[ -n \"$image\" ] || exit 44; docker run --rm --pull=never --network host \"$image\" "
                    f"mysql --connect-timeout=6 -h {shlex.quote(host)} -P {port} "
                    f"-u {shlex.quote(username)} {shlex.quote('-p' + password)} "
                    f"-D {shlex.quote(database)} -Nse {shlex.quote('SELECT 1')}"
                )
                code, output = ssh.run(cmd, timeout=15)
                ok = code == 0 and output.strip().endswith("1")
            elif service == "redis":
                password = str(body.get("password") or "")
                database = str(body.get("database") or "0").strip() or "0"
                auth = f" -a {shlex.quote(password)}" if password else ""
                cmd = (
                    "image=$(docker images --format '{{.Repository}}:{{.Tag}}' | grep -E '^redis:' | head -n1); "
                    "[ -n \"$image\" ] || exit 44; docker run --rm --pull=never --network host \"$image\" "
                    f"redis-cli --no-auth-warning -h {shlex.quote(host)} -p {port}{auth} "
                    f"-n {shlex.quote(database)} PING"
                )
                code, output = ssh.run(cmd, timeout=15)
                ok = code == 0 and "PONG" in output.upper()
            else:
                raise HTTPException(400, "不支持的服务类型")
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(502, f"无法从 {node.name} 发起连接测试：{str(exc)[:240]}")
    if not ok:
        if code == 44:
            raise HTTPException(409, f"目标服务器尚无可用的 {service.upper()} 客户端镜像，请先准备对应镜像后再测试")
        upper_output = (output or "").upper()
        if service == "mysql" and "1045" in upper_output:
            raise HTTPException(502, "MySQL 地址和端口可访问，但用户名或密码认证失败")
        if service == "mysql" and "1049" in upper_output:
            raise HTTPException(502, f"MySQL 连接和认证成功，但数据库“{database}”不存在或当前账号无权访问")
        if service == "mysql" and any(token in upper_output for token in ("2002", "2003", "CAN'T CONNECT")):
            raise HTTPException(502, "无法连接 MySQL，请检查地址、端口以及目标服务器网络")
        if service == "mysql" and "1130" in upper_output:
            raise HTTPException(502, "MySQL 已响应，但未允许该目标服务器远程登录")
        if service == "redis" and any(token in upper_output for token in ("WRONGPASS", "NOAUTH")):
            raise HTTPException(502, "Redis 已响应，但密码认证失败")
        if service == "redis" and any(token in upper_output for token in ("CONNECTION REFUSED", "COULD NOT CONNECT")):
            raise HTTPException(502, "无法连接 Redis，请检查地址、端口以及目标服务器网络")
        clean = re.sub(r"(?i)(password|using a password)[^\n]*", "认证信息已隐藏", output or "")
        raise HTTPException(502, f"{service.upper()} 连接失败：{clean.strip()[:240] or '请检查地址、端口和账号信息'}")
    audit(db, user, "test_integration", "project", project.id, f"{service}@{node.name}:ok")
    db.commit()
    return {"ok": True, "message": f"已从 {node.name} 验证 {service.upper()} 连接和认证均正常"}


def _certificate_metadata(certificate_pem: str) -> tuple[x509.Certificate, list[str], str]:
    cert = x509.load_pem_x509_certificate(certificate_pem.encode())
    try:
        domains = list(cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        domains = [value.value for value in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)]
    return cert, list(dict.fromkeys(value.lower() for value in domains if value)), cert.fingerprint(hashes.SHA256()).hex()


def _domain_matches_pattern(domain: str, pattern: str) -> bool:
    domain, pattern = domain.lower(), pattern.lower()
    return domain == pattern or (pattern.startswith("*.") and domain.endswith(pattern[1:]) and domain.count(".") == pattern.count("."))


def _certificate_view(item: CertificateStore, db: Session | None = None) -> dict:
    domains = json.loads(item.domains_json or "[]")
    references = 0 if db is None else int(db.scalar(select(func.count()).select_from(ProjectDomainConfig).where(ProjectDomainConfig.certificate_id == item.id)) or 0)
    return {"id": item.id, "name": item.name, "domains": domains, "expires_at": item.expires_at.isoformat(), "fingerprint": item.fingerprint, "references": references}


def _save_shared_certificate(db: Session, name: str, certificate_pem: str, private_key_pem: str) -> CertificateStore:
    cert, domains, fingerprint = _certificate_metadata(certificate_pem)
    private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
    cert_public = cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    key_public = private_key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    if cert_public != key_public:
        raise HTTPException(400, "SSL 证书与私钥不匹配")
    item = db.scalar(select(CertificateStore).where(CertificateStore.fingerprint == fingerprint))
    if not item:
        item = CertificateStore(fingerprint=fingerprint, name=name or domains[0])
    item.name = name or item.name
    item.domains_json = json.dumps(domains, ensure_ascii=False)
    item.certificate_encrypted = encrypt(certificate_pem)
    item.private_key_encrypted = encrypt(private_key_pem)
    item.expires_at = cert.not_valid_after_utc
    db.add(item)
    db.flush()
    return item


def _matching_certificates(db: Session, domain: str) -> list[CertificateStore]:
    now_value = datetime.now(timezone.utc)
    matched = []
    for item in db.scalars(select(CertificateStore).where(CertificateStore.expires_at > now_value).order_by(CertificateStore.expires_at.desc())).all():
        patterns = json.loads(item.domains_json or "[]")
        if any(_domain_matches_pattern(domain, pattern) for pattern in patterns):
            exact = any(domain.lower() == pattern.lower() for pattern in patterns)
            matched.append((0 if exact else 1, item))
    return [item for _, item in sorted(matched, key=lambda value: (value[0], -value[1].expires_at.timestamp()))]


@app.get("/api/certificates")
def list_certificates(domain: str = "", db: Session = Depends(get_db), _: User = Depends(current_user)):
    items = _matching_certificates(db, domain.strip().lower()) if domain.strip() else db.scalars(select(CertificateStore).order_by(CertificateStore.expires_at.desc())).all()
    return [_certificate_view(item, db) for item in items]


@app.post("/api/certificates")
async def upload_certificate(certificate: UploadFile = File(...), private_key: UploadFile = File(...), db: Session = Depends(get_db), user: User = Depends(require(Role.admin, Role.deployer))):
    cert_raw, key_raw = await certificate.read(), await private_key.read()
    if len(cert_raw) > 2_000_000 or len(key_raw) > 2_000_000:
        raise HTTPException(400, "证书或私钥不能超过 2 MB")
    try:
        item = _save_shared_certificate(db, certificate.filename or "SSL 证书", cert_raw.decode(), key_raw.decode())
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(400, "证书或私钥无法解析，请上传有效的 PEM 文件")
    audit(db, user, "upload_certificate", "certificate", item.id, f"domains={item.domains_json}")
    db.commit()
    return _certificate_view(item, db)


@app.delete("/api/certificates/{certificate_id}")
def delete_certificate(certificate_id: str, db: Session = Depends(get_db), user: User = Depends(require(Role.admin))):
    item = db.get(CertificateStore, certificate_id)
    if not item:
        raise HTTPException(404, "证书不存在")
    references = int(db.scalar(select(func.count()).select_from(ProjectDomainConfig).where(ProjectDomainConfig.certificate_id == item.id)) or 0)
    if references:
        raise HTTPException(409, f"该证书仍被 {references} 个项目使用，不能删除")
    db.delete(item)
    audit(db, user, "delete_certificate", "certificate", certificate_id, item.name)
    db.commit()
    return {"ok": True}


@app.get("/api/projects/{item_id}/domain-config")
def get_project_domain_config(item_id: str, db: Session = Depends(get_db), _: User = Depends(current_user)):
    item = db.get(Project, item_id)
    if not item:
        raise HTTPException(404, "项目不存在")
    config = db.get(ProjectDomainConfig, item_id)
    deployment_settings = get_deployment_settings(db)
    cert_domains, cert_expires_at = [], None
    shared = db.get(CertificateStore, config.certificate_id) if config and config.certificate_id else None
    if config and not shared and config.certificate_encrypted and config.private_key_encrypted:
        try:
            shared = _save_shared_certificate(db, config.certificate_name or "已迁移证书", decrypt(config.certificate_encrypted), decrypt(config.private_key_encrypted))
            config.certificate_id = shared.id
            db.commit()
        except Exception:
            shared = None
    if config and config.certificate_encrypted:
        try:
            cert = x509.load_pem_x509_certificate(decrypt(config.certificate_encrypted).encode())
            try:
                cert_domains = list(cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName))
            except x509.ExtensionNotFound:
                cert_domains = [value.value for value in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)]
            cert_expires_at = cert.not_valid_after_utc.isoformat()
        except Exception:
            pass
    latest = db.scalar(select(Deployment).where(
        Deployment.project_id == item_id, Deployment.status == DeployStatus.success,
    ).order_by(desc(Deployment.created_at)).limit(1))
    gateway_services = []
    if latest:
        node = db.get(Node, latest.node_id)
        if node:
            try:
                gateway_services = [row["name"] for row in _runtime_service_gateway_routes(db, item, latest, node)]
            except Exception:
                gateway_services = []
    try:
        custom_routes = json.loads(config.custom_routes_json or "[]") if config else []
    except Exception:
        custom_routes = []
    return {
        "domain": item.domain or "",
        "http_port": config.http_port if config else deployment_settings.default_domain_http_port,
        "https_enabled": config.https_enabled if config else False,
        "https_port": config.https_port if config else deployment_settings.default_domain_https_port,
        "redirect_https": config.redirect_https if config else True,
        "gateway_mode": config.gateway_mode if config else "auto",
        "custom_routes": custom_routes,
        "proxy_read_timeout": config.proxy_read_timeout if config else 300,
        "client_max_body_mb": config.client_max_body_mb if config else 50,
        "gateway_services": gateway_services,
        "has_certificate": bool(config and config.certificate_encrypted and config.private_key_encrypted),
        "certificate_name": config.certificate_name if config else None,
        "certificate_id": shared.id if shared else None,
        "certificate_domains": cert_domains,
        "certificate_expires_at": cert_expires_at,
        "available_certificates": [_certificate_view(value, db) for value in _matching_certificates(db, item.domain or "")] if item.domain else [],
    }


@app.get("/api/projects/{item_id}/gateway-preview")
def get_project_gateway_preview(item_id: str, db: Session = Depends(get_db), _: User = Depends(require(Role.admin, Role.deployer))):
    """Return the effective, read-only gateway routes and generated Nginx file."""
    item = db.get(Project, item_id)
    if not item:
        raise HTTPException(404, "项目不存在")
    latest = db.scalar(select(Deployment).where(
        Deployment.project_id == item_id,
        Deployment.status == DeployStatus.success,
    ).order_by(desc(Deployment.created_at)).limit(1))
    if not latest:
        return {"generated": False, "message": "项目尚无成功运行的版本，部署完成后才会生成网关配置", "routes": [], "config": ""}
    node = db.get(Node, latest.node_id)
    if not node:
        raise HTTPException(404, "部署节点不存在")
    groups = _runtime_service_gateway_routes(db, item, latest, node)
    domain_config = db.get(ProjectDomainConfig, item_id)
    mode = domain_config.gateway_mode if domain_config else "auto"
    routes = []
    group_map = {str(group.get("name") or ""): group for group in groups}
    if mode == "custom" and domain_config:
        try:
            saved_routes = json.loads(domain_config.custom_routes_json or "[]")
        except Exception:
            saved_routes = []
        for route in saved_routes:
            service = str(route.get("service") or "")
            group = group_map.get(service) or {}
            routes.append({
                "path": str(route.get("path") or "/"),
                "service": service,
                "strip_prefix": bool(route.get("strip_prefix", False)),
                "targets": [f"{host}:{port}" for host, port in (group.get("targets") or [])],
            })
    else:
        for group in groups:
            for route in group.get("paths") or [{"path": group.get("path") or "/", "strip_prefix": False}]:
                route = route if isinstance(route, dict) else {"path": route}
                routes.append({
                    "path": str(route.get("path") or "/"),
                    "service": str(group.get("name") or ""),
                    "strip_prefix": bool(route.get("strip_prefix", False)),
                    "targets": [f"{host}:{port}" for host, port in (group.get("targets") or [])],
                })
    gateway = platform_gateway_node(db)
    filename = f"/data/yunzhou-control/data/gateway/conf.d/project-{item_id}.conf"
    generated_config = ""
    if gateway:
        try:
            with SSHNode(gateway) as ssh:
                code, output = ssh.run(f"cat {shlex.quote(filename)}", timeout=20)
                if code == 0:
                    generated_config = output[:200_000]
        except Exception as exc:
            return {
                "generated": False, "message": f"网关配置读取失败：{exc}", "mode": mode,
                "routes": routes, "config": "", "config_path": filename,
            }
    return {
        "generated": bool(generated_config),
        "message": "平台当前正在使用的配置" if generated_config else "尚未找到已生效的网关配置文件",
        "mode": mode,
        "access_url": latest.access_url,
        "gateway_node": gateway.name if gateway else None,
        "gateway_address": (gateway.public_address or gateway.host) if gateway else None,
        "domain": item.domain or "",
        "http_port": domain_config.http_port if domain_config else 80,
        "https_enabled": domain_config.https_enabled if domain_config else False,
        "https_port": domain_config.https_port if domain_config else 443,
        "certificate_name": domain_config.certificate_name if domain_config else None,
        "config_path": filename,
        "routes": routes,
        "config": generated_config,
    }


@app.put("/api/projects/{item_id}/gateway-policy")
def update_project_gateway_policy(
    item_id: str,
    body: dict,
    db: Session = Depends(get_db),
    user: User = Depends(require(Role.admin, Role.deployer)),
):
    """Update routing-only gateway settings and apply them immediately.

    Domain, ports and certificates deliberately remain owned by the access
    configuration dialog. This keeps the runtime gateway control focused and
    prevents a routing edit from accidentally replacing certificate material.
    """
    item = db.get(Project, item_id)
    if not item:
        raise HTTPException(404, "项目不存在")
    mode = str(body.get("gateway_mode") or "auto")
    if mode not in {"auto", "custom"}:
        raise HTTPException(400, "网关模式不正确")
    try:
        timeout = int(body.get("proxy_read_timeout") or 300)
        upload_mb = int(body.get("client_max_body_mb") or 50)
    except (TypeError, ValueError):
        raise HTTPException(400, "网关超时或上传大小格式不正确")
    if not 1 <= timeout <= 3600 or not 1 <= upload_mb <= 2048:
        raise HTTPException(400, "网关超时或上传大小超出允许范围")

    latest = db.scalar(select(Deployment).where(
        Deployment.project_id == item_id,
        Deployment.status == DeployStatus.success,
        Deployment.host_port.is_not(None),
    ).order_by(desc(Deployment.created_at)).limit(1))
    node = db.get(Node, latest.node_id) if latest else None
    groups = _runtime_service_gateway_routes(db, item, latest, node) if latest and node else []
    services = {str(group.get("name") or "") for group in groups}
    raw_routes = body.get("custom_routes") or []
    if not isinstance(raw_routes, list) or len(raw_routes) > 20:
        raise HTTPException(400, "自定义路由最多支持 20 条")
    normalized_routes = []
    for route in raw_routes:
        path = str((route or {}).get("path") or "").strip()
        service = str((route or {}).get("service") or "").strip()
        if not re.fullmatch(r"/[A-Za-z0-9._~!$&'()*+,;=:@%/-]*", path):
            raise HTTPException(400, f"路由路径不正确：{path or '空路径'}")
        if service not in services:
            raise HTTPException(400, f"目标服务不存在或未运行：{service or '未选择'}")
        normalized_routes.append({"path": path, "service": service, "strip_prefix": bool((route or {}).get("strip_prefix", False))})
    if mode == "custom" and not normalized_routes:
        raise HTTPException(400, "自定义路由至少需要一条规则")

    config = db.get(ProjectDomainConfig, item_id) or ProjectDomainConfig(project_id=item_id)
    config.gateway_mode = mode
    config.custom_routes_json = json.dumps(normalized_routes, ensure_ascii=False)
    config.proxy_read_timeout = timeout
    config.client_max_body_mb = upload_mb
    db.add(config)
    db.flush()
    if latest and node:
        cert_text = decrypt(config.certificate_encrypted)
        key_text = decrypt(config.private_key_encrypted)
        latest.access_url = configure_platform_gateway(
            db, latest, node, latest.host_port, item.domain,
            http_port=config.http_port, https_enabled=config.https_enabled and bool(item.domain),
            https_port=config.https_port, redirect_https=config.redirect_https,
            certificate=cert_text, private_key=key_text,
            upstreams=_existing_project_gateway_targets(db, item_id) or _project_gateway_targets(db, latest, node),
            route_groups=groups or None, strategy=item.load_balance_strategy,
        )
    audit(db, user, "update_gateway_policy", "project", item_id, f"mode={mode}; routes={len(normalized_routes)}; timeout={timeout}; upload_mb={upload_mb}")
    db.commit()
    return get_project_gateway_preview(item_id, db, user)


def _certificate_covers_domain(certificate_pem: str, domain: str) -> bool:
    cert = x509.load_pem_x509_certificate(certificate_pem.encode())
    try:
        names = list(cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        names = [value.value for value in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)]
    domain = domain.lower()
    return any(domain == name.lower() or (name.startswith("*.") and domain.endswith(name[1:].lower()) and domain.count(".") == name.count(".")) for name in names)


def _project_gateway_targets(db: Session, deployment: Deployment, node: Node) -> list[tuple[str, int]]:
    replicas = db.scalars(select(ProjectReplica).where(
        ProjectReplica.project_id == deployment.project_id,
        ProjectReplica.deployment_id == deployment.id,
        ProjectReplica.status == "running",
    ).order_by(ProjectReplica.created_at)).all()
    return [(node.host, deployment.host_port)] + [(node.host, item.host_port) for item in replicas]


def _existing_project_gateway_targets(db: Session, project_id: str) -> list[tuple[str, int]]:
    """Preserve the effective frontend upstream when only domain settings change."""
    gateway = platform_gateway_node(db)
    if not gateway:
        return []
    filename = f"/data/yunzhou-control/data/gateway/conf.d/project-{project_id}.conf"
    with SSHNode(gateway) as ssh:
        code, config = ssh.run(f"cat {shlex.quote(filename)}", timeout=20)
    if code:
        return []
    targets = re.findall(r"(?m)^\s*server\s+([a-zA-Z0-9_.-]+):(\d+)\s+max_fails=", config)
    if not targets:
        direct = re.search(r"proxy_pass\s+http://([a-zA-Z0-9_.-]+):(\d+)\s*;", config)
        targets = [direct.groups()] if direct else []
    return list(dict.fromkeys((host, int(port)) for host, port in targets))


def _runtime_service_gateway_routes(db: Session, project: Project, deployment: Deployment, node: Node) -> list[dict]:
    """Rebuild gateway routes from the actual running Compose services.

    Domain edits and restarts used to retain only the first public upstream,
    which silently replaced backend API routes with the frontend catch-all.
    Docker is the source of truth for service-specific published ports; the
    versioned traffic plan remains the source of truth for URL paths.
    """
    compose_project = "yz-" + project.slug
    service_targets: dict[str, list[tuple[str, int]]] = {}
    try:
        with SSHNode(node) as ssh:
            code, output = ssh.run(
                "docker ps --filter " + shlex.quote("label=com.docker.compose.project=" + compose_project)
                + " --format '{{.Names}}'",
                timeout=30,
            )
            if code:
                return []
            for name in filter(None, map(str.strip, output.splitlines())):
                inspect_code, inspect_output = ssh.run(
                    "docker inspect -f "
                    + shlex.quote('{{json .Config.Labels}}|{{json .NetworkSettings.Ports}}')
                    + " " + shlex.quote(name),
                    timeout=20,
                )
                if inspect_code or "|" not in inspect_output:
                    continue
                labels_text, ports_text = inspect_output.strip().split("|", 1)
                try:
                    labels = json.loads(labels_text) or {}
                    ports = json.loads(ports_text) or {}
                except json.JSONDecodeError:
                    continue
                service = str(labels.get("com.docker.compose.service") or labels.get("yunzhou.service") or "")
                if not service:
                    continue
                for bindings in ports.values():
                    for binding in bindings or []:
                        host_port = str(binding.get("HostPort") or "")
                        if host_port.isdigit():
                            service_targets.setdefault(service, []).append((node.host, int(host_port)))
                            break
                    if service_targets.get(service):
                        break
    except Exception:
        return []
    for row in db.scalars(select(ProjectReplica).where(
        ProjectReplica.project_id == project.id,
        ProjectReplica.deployment_id == deployment.id,
        ProjectReplica.status == "running",
    )).all():
        if row.service_name and row.host_port:
            service_targets.setdefault(row.service_name, []).append((node.host, row.host_port))
    for service, targets in service_targets.items():
        service_targets[service] = list(dict.fromkeys(targets))
    return _route_groups_for_services(project, service_targets)


def _ensure_domain_ports_available(
    db: Session,
    project_id: str,
    domain: str,
    http_port: int,
    https_enabled: bool,
    https_port: int,
) -> None:
    """Reject an exact domain/listen-port collision with another project."""
    if not domain:
        return
    defaults = get_deployment_settings(db)
    requested = [("HTTP", http_port)]
    if https_enabled:
        requested.append(("HTTPS", https_port))
    projects = db.scalars(select(Project).where(
        Project.id != project_id,
        func.lower(Project.domain) == domain.lower(),
    )).all()
    for other in projects:
        other_config = db.get(ProjectDomainConfig, other.id)
        occupied = [("HTTP", other_config.http_port if other_config else defaults.default_domain_http_port)]
        if other_config and other_config.https_enabled:
            occupied.append(("HTTPS", other_config.https_port))
        for requested_protocol, requested_port in requested:
            for occupied_protocol, occupied_port in occupied:
                if requested_port == occupied_port:
                    raise HTTPException(
                        409,
                        f"域名 {domain} 的 {requested_protocol} 端口 {requested_port} "
                        f"与项目“{other.name}”的 {occupied_protocol} 入口冲突，请更换域名或端口",
                    )


@app.post("/api/projects/{item_id}/domain-config")
async def save_project_domain_config(
    item_id: str,
    domain: str = Form(default=""),
    http_port: int = Form(default=80),
    https_enabled: bool = Form(default=False),
    https_port: int = Form(default=443),
    redirect_https: bool = Form(default=True),
    gateway_mode: str = Form(default="auto"),
    custom_routes_json: str = Form(default="[]"),
    proxy_read_timeout: int = Form(default=300),
    client_max_body_mb: int = Form(default=50),
    certificate_id: str = Form(default=""),
    certificate: UploadFile | None = File(default=None),
    private_key: UploadFile | None = File(default=None),
    db: Session = Depends(get_db),
    user: User = Depends(require(Role.admin, Role.deployer)),
):
    item = db.get(Project, item_id)
    if not item:
        raise HTTPException(404, "项目不存在")
    domain = domain.strip().lower().removeprefix("https://").removeprefix("http://").split("/")[0].split(":")[0]
    if domain and not re.fullmatch(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", domain):
        raise HTTPException(400, "域名格式不正确")
    if not 1 <= http_port <= 65535 or not 1 <= https_port <= 65535:
        raise HTTPException(400, "端口必须在 1 到 65535 之间")
    if https_enabled and http_port == https_port:
        raise HTTPException(400, "HTTP 与 HTTPS 不能使用同一个端口")
    if gateway_mode not in {"auto", "custom"}:
        raise HTTPException(400, "网关模式不正确")
    if not 1 <= proxy_read_timeout <= 3600 or not 1 <= client_max_body_mb <= 2048:
        raise HTTPException(400, "网关超时或上传大小超出允许范围")
    try:
        custom_routes = json.loads(custom_routes_json or "[]")
    except Exception:
        raise HTTPException(400, "自定义路由格式不正确")
    if not isinstance(custom_routes, list) or len(custom_routes) > 20:
        raise HTTPException(400, "自定义路由最多支持 20 条")
    normalized_routes = []
    for route in custom_routes:
        path = str((route or {}).get("path") or "").strip()
        service = str((route or {}).get("service") or "").strip()
        if not re.fullmatch(r"/[A-Za-z0-9._~!$&'()*+,;=:@%/-]*", path) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,120}", service):
            raise HTTPException(400, f"自定义路由不正确：{path or '空路径'}")
        normalized_routes.append({"path": path, "service": service, "strip_prefix": bool((route or {}).get("strip_prefix", False))})
    # Serialize the check and write so two concurrent saves cannot both pass.
    db.execute(text("SELECT pg_advisory_xact_lock(hashtext('domain-config-listeners'))"))
    _ensure_domain_ports_available(db, item_id, domain, http_port, https_enabled, https_port)
    config = db.get(ProjectDomainConfig, item_id) or ProjectDomainConfig(project_id=item_id)
    cert_text = decrypt(config.certificate_encrypted)
    key_text = decrypt(config.private_key_encrypted)
    selected_certificate = db.get(CertificateStore, certificate_id) if certificate_id else (db.get(CertificateStore, config.certificate_id) if config.certificate_id else None)
    if selected_certificate:
        cert_text = decrypt(selected_certificate.certificate_encrypted)
        key_text = decrypt(selected_certificate.private_key_encrypted)
        config.certificate_name = selected_certificate.name
    if certificate and certificate.filename:
        raw = await certificate.read()
        if len(raw) > 2_000_000:
            raise HTTPException(400, "证书文件不能超过 2 MB")
        cert_text = raw.decode("utf-8", errors="strict")
        config.certificate_name = certificate.filename
    if private_key and private_key.filename:
        raw = await private_key.read()
        if len(raw) > 2_000_000:
            raise HTTPException(400, "私钥文件不能超过 2 MB")
        key_text = raw.decode("utf-8", errors="strict")
    if certificate and certificate.filename and private_key and private_key.filename:
        try:
            selected_certificate = _save_shared_certificate(db, certificate.filename, cert_text, key_text)
        except HTTPException:
            raise
        except Exception:
            raise HTTPException(400, "证书或私钥无法解析，请上传有效的 PEM 文件")
    elif https_enabled and not selected_certificate and domain:
        matches = _matching_certificates(db, domain)
        if matches:
            selected_certificate = matches[0]
            cert_text = decrypt(selected_certificate.certificate_encrypted)
            key_text = decrypt(selected_certificate.private_key_encrypted)
            config.certificate_name = selected_certificate.name
    if https_enabled:
        if not domain:
            raise HTTPException(400, "启用 SSL 前请填写域名")
        if not cert_text or "BEGIN CERTIFICATE" not in cert_text:
            raise HTTPException(400, "请上传 PEM 格式的 SSL 证书")
        if not key_text or "PRIVATE KEY" not in key_text:
            raise HTTPException(400, "请上传 PEM 格式的证书私钥")
        try:
            if not _certificate_covers_domain(cert_text, domain):
                raise HTTPException(400, f"当前证书不包含域名 {domain}，请上传匹配该域名的证书")
        except HTTPException:
            raise
        except Exception:
            raise HTTPException(400, "SSL 证书无法解析，请上传有效的 PEM 证书")
    elif not domain:
        # Resetting a project to the platform-managed address must also detach
        # its project-level certificate.  The shared certificate library is
        # intentionally untouched so it can still be reused by other projects.
        cert_text = ""
        key_text = ""
        selected_certificate = None
        config.certificate_name = None
    # Persist the user's choice before acquiring the project gateway lock.
    # configure_platform_gateway refreshes these authoritative values so a
    # deployment finishing concurrently cannot restore an older HTTPS state.
    item.domain = domain or None
    config.http_port = http_port
    config.https_enabled = https_enabled
    config.https_port = https_port
    config.redirect_https = redirect_https
    config.gateway_mode = gateway_mode
    config.custom_routes_json = json.dumps(normalized_routes, ensure_ascii=False)
    config.proxy_read_timeout = proxy_read_timeout
    config.client_max_body_mb = client_max_body_mb
    config.certificate_encrypted = encrypt(cert_text)
    config.private_key_encrypted = encrypt(key_text)
    config.certificate_id = selected_certificate.id if selected_certificate else None
    db.add(config)
    db.flush()
    latest = db.scalar(select(Deployment).where(
        Deployment.project_id == item_id,
        Deployment.status == DeployStatus.success,
        Deployment.host_port.is_not(None),
    ).order_by(desc(Deployment.created_at)).limit(1))
    if latest:
        node = db.get(Node, latest.node_id)
        effective_targets = _existing_project_gateway_targets(db, item_id)
        route_groups = _runtime_service_gateway_routes(db, item, latest, node) if node else []
        latest.access_url = configure_platform_gateway(
            db, latest, node, latest.host_port, domain or None,
            http_port=http_port, https_enabled=https_enabled and bool(domain), https_port=https_port,
            redirect_https=redirect_https, certificate=cert_text, private_key=key_text,
            upstreams=effective_targets or _project_gateway_targets(db, latest, node),
            route_groups=route_groups or None, strategy=item.load_balance_strategy,
        )
    audit(db, user, "configure_domain", "project", item_id, f"domain={domain}; http={http_port}; https={https_enabled}:{https_port}; redirect={redirect_https}")
    db.commit()
    return get_project_domain_config(item_id, db, user)


@app.patch("/api/projects/{item_id}", response_model=ProjectOut)
def update_project(item_id: str, body: ProjectUpdate, db: Session = Depends(get_db), user: User = Depends(require(Role.admin, Role.deployer))):
    item = db.get(Project, item_id)
    if not item:
        raise HTTPException(404, "项目不存在")
    old_name, old_domain, old_container_port, old_host_port = item.name, item.domain, item.container_port, item.host_port
    if body.name is not None:
        item.name = body.name.strip()
        if not item.name:
            raise HTTPException(400, "项目名称不能为空")
    if body.domain is not None:
        domain = body.domain.strip().lower()
        if domain and not re.fullmatch(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", domain):
            raise HTTPException(400, "域名格式不正确")
        if domain:
            config = db.get(ProjectDomainConfig, item_id)
            defaults = get_deployment_settings(db)
            db.execute(text("SELECT pg_advisory_xact_lock(hashtext('domain-config-listeners'))"))
            _ensure_domain_ports_available(
                db,
                item_id,
                domain,
                config.http_port if config else defaults.default_domain_http_port,
                config.https_enabled if config else False,
                config.https_port if config else defaults.default_domain_https_port,
            )
        item.domain = domain or None
    fields_set = body.model_fields_set
    if "container_port" in fields_set:
        item.container_port = body.container_port
    if "host_port" in fields_set:
        item.host_port = body.host_port
    if "load_balance_enabled" in fields_set:
        item.load_balance_enabled = bool(body.load_balance_enabled)
    if "replica_count" in fields_set and body.replica_count is not None:
        item.replica_count = body.replica_count
    if "load_balance_strategy" in fields_set and body.load_balance_strategy is not None:
        item.load_balance_strategy = body.load_balance_strategy
    if "deployment_mode" in fields_set and body.deployment_mode is not None:
        item.deployment_mode = body.deployment_mode
    if "image_retention_count" in fields_set and body.image_retention_count is not None:
        item.image_retention_count = body.image_retention_count
    if "git_url" in fields_set:
        item.git_url = body.git_url.strip() if body.git_url else None
    if "git_branch" in fields_set and body.git_branch:
        item.git_branch = body.git_branch.strip()
    db.flush()
    if body.domain is not None and item.domain != old_domain:
        deployment = db.scalar(select(Deployment).where(Deployment.project_id == item.id, Deployment.status == DeployStatus.success, Deployment.host_port.is_not(None)).order_by(desc(Deployment.created_at)).limit(1))
        if deployment:
            node = db.get(Node, deployment.node_id)
            domain_config = db.get(ProjectDomainConfig, item.id)
            route_groups = _runtime_service_gateway_routes(db, item, deployment, node) if node else []
            deployment.access_url = configure_platform_gateway(
                db, deployment, node, deployment.host_port, item.domain,
                http_port=domain_config.http_port if domain_config else 80,
                https_enabled=domain_config.https_enabled if domain_config else False,
                https_port=domain_config.https_port if domain_config else 443,
                redirect_https=domain_config.redirect_https if domain_config else True,
                certificate=decrypt(domain_config.certificate_encrypted) if domain_config else None,
                private_key=decrypt(domain_config.private_key_encrypted) if domain_config else None,
                upstreams=_project_gateway_targets(db, deployment, node),
                route_groups=route_groups or None, strategy=item.load_balance_strategy,
            )
    audit(db, user, "update_project", "project", item.id, f"name:{old_name}->{item.name}; domain:{old_domain}->{item.domain}; container_port:{old_container_port}->{item.container_port}; host_port:{old_host_port}->{item.host_port}")
    db.commit()
    db.refresh(item)
    return item


REGISTRY_API = "http://registry:5000/v2"
REGISTRY_MANIFEST_ACCEPT = ", ".join((
    "application/vnd.docker.distribution.manifest.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.index.v1+json",
))


def _registry_request(method: str, path: str, **kwargs):
    try:
        # Registry is an internal Compose service.  Never route it through the
        # system HTTP proxy configured for external package downloads.
        with httpx.Client(timeout=20, trust_env=False) as client:
            response = client.request(method, REGISTRY_API + path, **kwargs)
    except httpx.HTTPError as exc:
        raise HTTPException(503, f"镜像仓库暂时不可用：{exc}")
    if response.status_code >= 400:
        raise HTTPException(response.status_code, "镜像仓库请求失败")
    return response


@app.get("/api/images")
def list_image_repository(db: Session = Depends(get_db), _: User = Depends(require(Role.admin, Role.deployer))):
    names = _registry_request("GET", "/_catalog?n=100").json().get("repositories") or []
    repositories = []
    for name in sorted(names):
        tags = _registry_request("GET", f"/{quote(name, safe='/')}/tags/list").json().get("tags") or []
        # Registry catalogs may retain a repository name after its last
        # manifest is deleted. It has no usable image and should not appear as
        # a platform repository or inflate repository totals.
        if not tags:
            continue
        versions = []
        for tag in sorted(tags, reverse=True):
            response = _registry_request("GET", f"/{quote(name, safe='/')}/manifests/{quote(tag, safe='')}", headers={"Accept": REGISTRY_MANIFEST_ACCEPT})
            manifest = response.json()
            size = sum(int(x.get("size") or 0) for x in manifest.get("layers") or []) + int((manifest.get("config") or {}).get("size") or 0)
            created_at = None
            config_digest = (manifest.get("config") or {}).get("digest")
            if config_digest:
                try:
                    image_config = _registry_request("GET", f"/{quote(name, safe='/')}/blobs/{quote(config_digest, safe=':')}").json()
                    created_at = image_config.get("created")
                except HTTPException:
                    pass
            if not created_at and re.fullmatch(r"\d{12}(?:\d{2}|-\d{2})?", tag):
                try:
                    stamp = tag.split("-", 1)[0]
                    pattern = "%Y%m%d%H%M%S" if len(stamp) == 14 else "%Y%m%d%H%M"
                    created_at = datetime.strptime(stamp, pattern).replace(tzinfo=timezone(timedelta(hours=8))).isoformat()
                except ValueError:
                    pass
            versions.append({"tag": tag, "digest": response.headers.get("Docker-Content-Digest", ""), "size_bytes": size, "created_at": created_at})
        repositories.append({"name": name, "tags": versions, "tag_count": len(versions)})
    policy = get_deployment_settings(db)
    return {"repositories": repositories, "repository_count": len(repositories), "tag_count": sum(x["tag_count"] for x in repositories), "endpoint": policy.registry_endpoint}


@app.delete("/api/images")
def delete_image_tag(body: dict, db: Session = Depends(get_db), user: User = Depends(require(Role.admin))):
    repository, tag = str(body.get("repository") or "").strip(), str(body.get("tag") or "").strip()
    if not re.fullmatch(r"[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*", repository) or not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}", tag):
        raise HTTPException(400, "仓库或标签无效")
    protected_releases, running_refs = _protected_registry_releases(db)
    reason = _registry_tag_protection_reason(repository, tag, protected_releases, running_refs)
    if reason:
        raise HTTPException(409, f"该镜像受保护，不能删除：{reason}")
    manifest = _registry_request("HEAD", f"/{quote(repository, safe='/')}/manifests/{quote(tag, safe='')}", headers={"Accept": REGISTRY_MANIFEST_ACCEPT})
    digest = manifest.headers.get("Docker-Content-Digest")
    if not digest:
        raise HTTPException(409, "仓库未返回镜像摘要，无法安全删除")
    _registry_request("DELETE", f"/{quote(repository, safe='/')}/manifests/{quote(digest, safe=':')}")
    audit(db, user, "delete_registry_tag", "registry_image", None, f"{repository}:{tag}")
    db.commit()
    return {"ok": True, "message": f"已从仓库删除 {repository}:{tag}"}


def _protected_registry_releases(db: Session) -> tuple[dict[str, set[str]], set[tuple[str, str]]]:
    """Return releases that must remain pullable for restart/rollback safety."""
    protected: dict[str, set[str]] = {}
    projects = {item.id: item for item in db.scalars(select(Project)).all()}
    # Active work may already reference a release before it becomes the latest
    # successful deployment, so always protect queued/running releases.
    active = db.scalars(select(Deployment).where(
        Deployment.status.in_([DeployStatus.queued, DeployStatus.running]),
        Deployment.release.is_not(None),
    )).all()
    for deployment in active:
        project = projects.get(deployment.project_id)
        if project and deployment.release:
            protected.setdefault(project.slug, set()).add(deployment.release)
    # Protect exactly the newest successful release for every project. Older
    # successful records are history and may be deliberately cleaned.
    for project in projects.values():
        latest = db.scalar(select(Deployment).where(
            Deployment.project_id == project.id,
            Deployment.status == DeployStatus.success,
            Deployment.release.is_not(None),
        ).order_by(desc(Deployment.finished_at), desc(Deployment.created_at)).limit(1))
        if latest and latest.release:
            protected.setdefault(project.slug, set()).add(latest.release)
    running_refs: set[tuple[str, str]] = set()
    policy = get_deployment_settings(db)
    endpoint = (policy.registry_endpoint or "yunzhou.hub:5000").strip().rstrip("/")
    for node in db.scalars(select(Node).where(Node.enabled == True)).all():
        try:
            with SSHNode(node) as ssh:
                code, output = ssh.run("docker ps --format '{{.Image}}'", timeout=15)
            if code:
                continue
            for value in output.splitlines():
                image = value.strip()
                if image.startswith(endpoint + "/"):
                    image = image[len(endpoint) + 1:]
                if "@" in image or ":" not in image:
                    continue
                repository, tag = image.rsplit(":", 1)
                if repository.startswith((policy.registry_namespace or "yunzhou").strip("/") + "/"):
                    running_refs.add((repository, tag))
        except Exception:
            # Database protection remains active if one node is temporarily
            # unreachable; the preview reports conservatively from available
            # nodes instead of making repository listing fail.
            continue
    return protected, running_refs


def _registry_tag_protection_reason(repository: str, tag: str, protected: dict[str, set[str]], running_refs: set[tuple[str, str]]) -> str | None:
    if (repository, tag) in running_refs:
        return "节点上仍有运行容器使用该版本"
    tail = repository.split("/", 1)[-1]
    for slug, releases in protected.items():
        if (tail == slug or tail.startswith(slug + "-")) and tag in releases:
            return "当前项目最新在线或正在发布的版本"
    return None


@app.post("/api/images/bulk-delete")
def bulk_delete_image_repositories(body: dict, db: Session = Depends(get_db), user: User = Depends(require(Role.admin))):
    raw_names = body.get("repositories") or []
    if not isinstance(raw_names, list) or not raw_names or len(raw_names) > 100:
        raise HTTPException(400, "请选择 1 至 100 个镜像仓库")
    repositories = list(dict.fromkeys(str(name or "").strip() for name in raw_names))
    repository_pattern = re.compile(r"[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*")
    if any(not repository_pattern.fullmatch(name) for name in repositories):
        raise HTTPException(400, "包含无效的镜像仓库名称")
    catalog = set(_registry_request("GET", "/_catalog?n=1000").json().get("repositories") or [])
    missing = [name for name in repositories if name not in catalog]
    protected_releases, running_refs = _protected_registry_releases(db)
    deletable, protected_tags = [], []
    for repository in repositories:
        if repository not in catalog:
            continue
        tags = _registry_request("GET", f"/{quote(repository, safe='/')}/tags/list").json().get("tags") or []
        for tag in tags:
            reason = _registry_tag_protection_reason(repository, tag, protected_releases, running_refs)
            row = {"repository": repository, "tag": tag}
            if reason:
                protected_tags.append({**row, "reason": reason})
            else:
                deletable.append(row)
    preview = {
        "repository_count": len(repositories),
        "tag_count": len(deletable) + len(protected_tags),
        "deletable_count": len(deletable),
        "protected_count": len(protected_tags),
        "deletable": deletable,
        "protected": protected_tags,
        "missing": missing,
    }
    if not body.get("confirm"):
        return {"ok": True, "preview": preview}
    removed, failed = [], []
    for row in deletable:
        repository, tag = row["repository"], row["tag"]
        try:
            manifest = _registry_request("HEAD", f"/{quote(repository, safe='/')}/manifests/{quote(tag, safe='')}", headers={"Accept": REGISTRY_MANIFEST_ACCEPT})
            digest = manifest.headers.get("Docker-Content-Digest")
            if not digest:
                raise RuntimeError("仓库未返回镜像摘要")
            _registry_request("DELETE", f"/{quote(repository, safe='/')}/manifests/{quote(digest, safe=':')}")
            removed.append(f"{repository}:{tag}")
        except Exception as exc:
            failed.append({"image": f"{repository}:{tag}", "error": str(exc)[:300]})
    audit(db, user, "bulk_delete_registry_repositories", "registry", None,
          f"repositories={len(repositories)},removed={len(removed)},protected={len(protected_tags)},failed={len(failed)}")
    db.commit()
    return {
        "ok": not failed,
        "message": f"已删除 {len(removed)} 个镜像版本；保护 {len(protected_tags)} 个在线版本" + (f"；{len(failed)} 个删除失败" if failed else ""),
        "removed": removed,
        "protected": protected_tags,
        "failed": failed,
    }


def _project_registry_repositories(db: Session, project: Project) -> list[str]:
    policy = get_deployment_settings(db)
    namespace = (policy.registry_namespace or "yunzhou").strip("/")
    prefix = f"{namespace}/{project.slug}"
    catalog = _registry_request("GET", "/_catalog?n=1000").json().get("repositories") or []
    return sorted(name for name in catalog if name == prefix or name.startswith(prefix + "-"))


def _delete_project_registry_repositories(db: Session, project: Project) -> dict:
    """Delete every central-registry manifest owned by one deleted project."""
    repositories = _project_registry_repositories(db, project)
    removed_tags = []
    for repository in repositories:
        tags = _registry_request("GET", f"/{quote(repository, safe='/')}/tags/list").json().get("tags") or []
        digests = []
        for tag in tags:
            manifest = _registry_request(
                "HEAD",
                f"/{quote(repository, safe='/')}/manifests/{quote(tag, safe='')}",
                headers={"Accept": REGISTRY_MANIFEST_ACCEPT},
            )
            digest = manifest.headers.get("Docker-Content-Digest")
            if digest and digest not in digests:
                digests.append(digest)
            removed_tags.append(f"{repository}:{tag}")
        for digest in digests:
            _registry_request("DELETE", f"/{quote(repository, safe='/')}/manifests/{quote(digest, safe=':')}")
        remaining = _registry_request("GET", f"/{quote(repository, safe='/')}/tags/list").json().get("tags") or []
        if remaining:
            raise RuntimeError(f"镜像仓库 {repository} 清理后仍有 {len(remaining)} 个版本")
    return {"repositories": repositories, "tags": removed_tags}


@app.get("/api/projects/{item_id}/delete-preview")
def project_delete_preview(item_id: str, db: Session = Depends(get_db), _: User = Depends(current_user)):
    item = db.get(Project, item_id)
    if not item:
        raise HTTPException(404, "项目不存在")
    deployments = db.scalars(select(Deployment).where(Deployment.project_id == item_id).order_by(desc(Deployment.created_at))).all()
    nodes = {x.node_id: db.get(Node, x.node_id) for x in deployments}
    # Persistent volumes can outlive deployment records or remain on a node
    # after a project is moved. Scan every enabled deployment node so the
    # deletion preview is complete.
    for node in db.scalars(select(Node).where(Node.enabled == True)).all():
        nodes.setdefault(node.id, node)
    resources = {"deployments": [], "containers": [], "images": [], "registry_images": [], "directories": [], "volumes": [], "gateway_files": [], "source_origin": [], "source": []}
    if item.source_type == SourceType.git:
        parsed_source = urlsplit(item.git_url or "")
        safe_repository = (
            f"{parsed_source.scheme}://{parsed_source.hostname or ''}"
            f"{':' + str(parsed_source.port) if parsed_source.port else ''}{parsed_source.path}"
            if parsed_source.scheme and parsed_source.hostname else "Git 仓库"
        )
        resources["source_origin"].append({"name": f"Git 仓库 · {safe_repository}（仅解除关联，不删除远端仓库）"})
    else:
        resources["source_origin"].append({"name": "平台上传源码（删除项目时一并清理）"})
    gateway_candidates = []
    warnings = []
    try:
        for repository in _project_registry_repositories(db, item):
            tags = _registry_request("GET", f"/{quote(repository, safe='/')}/tags/list").json().get("tags") or []
            resources["registry_images"].extend({"name": f"{repository}:{tag}", "node": "平台镜像仓库"} for tag in tags)
    except Exception as exc:
        warnings.append(f"平台镜像仓库查询失败：{exc}")
    for dep in deployments:
        node = nodes.get(dep.node_id)
        resources["deployments"].append({"id": dep.id, "release": dep.release, "status": dep.status.value, "node": node.name if node else "节点已删除"})
        if dep.container_name:
            resources["containers"].append({"name": dep.container_name, "node": node.name if node else "未知节点"})
        if dep.image_name:
            resources["images"].append({"name": dep.image_name, "node": node.name if node else "未知节点"})
        if node and dep.release:
            resources["directories"].append({"path": f"{node.work_dir.rstrip('/')}/{project_directory(item)}/{dep.release}", "node": node.name})
        gateway_candidates.extend([
            f"/data/yunzhou-control/data/gateway/conf.d/{dep.id}.conf",
            f"/data/yunzhou-control/data/gateway/certs/{dep.id}.crt",
            f"/data/yunzhou-control/data/gateway/certs/{dep.id}.key",
        ])
    for node_id, node in nodes.items():
        if not node:
            continue
        try:
            with SSHNode(node) as ssh:
                _, compose_images = ssh.run("docker images --format '{{.Repository}}:{{.Tag}}' --filter " + shlex.quote(f"label=com.docker.compose.project=yz-{item.slug}"), timeout=20)
                for name in filter(None, map(str.strip, compose_images.splitlines())):
                    entry = {"name": name, "node": node.name}
                    if entry not in resources["images"]:
                        resources["images"].append(entry)
                # Central builds and imported target images keep the stable
                # yunzhou namespace even when deployment records or Compose
                # labels no longer exist. Always scan the real image store.
                _, named_images = ssh.run("docker images --format '{{.Repository}}:{{.Tag}}'", timeout=20)
                image_root = f"yunzhou/{item.slug}"
                for name in filter(None, map(str.strip, named_images.splitlines())):
                    repository = name.rsplit(":", 1)[0]
                    if repository != image_root and not repository.startswith(image_root + "-"):
                        continue
                    entry = {"name": name, "node": node.name}
                    if entry not in resources["images"]:
                        resources["images"].append(entry)
                _, compose_containers = ssh.run("docker ps -a --format '{{.Names}}' --filter " + shlex.quote(f"label=com.docker.compose.project=yz-{item.slug}"), timeout=20)
                for name in filter(None, map(str.strip, compose_containers.splitlines())):
                    entry = {"name": name, "node": node.name}
                    if entry not in resources["containers"]:
                        resources["containers"].append(entry)
                _, named_containers = ssh.run("docker ps -a --format '{{.Names}}'", timeout=20)
                container_prefix = f"yz-{item.slug}-"
                for name in filter(None, map(str.strip, named_containers.splitlines())):
                    if not name.startswith(container_prefix):
                        continue
                    entry = {"name": name, "node": node.name}
                    if entry not in resources["containers"]:
                        resources["containers"].append(entry)
                _, volumes = ssh.run("docker volume ls -q", timeout=20)
                prefix = f"yz-{item.slug}"
                for name in filter(None, map(str.strip, volumes.splitlines())):
                    if not (name == prefix or name.startswith(prefix + "_") or name.startswith(prefix + "-")):
                        _, label = ssh.run("docker volume inspect -f " + shlex.quote('{{index .Labels "com.docker.compose.project"}}') + " " + shlex.quote(name), timeout=10)
                        if label.strip() != prefix:
                            continue
                    resources["volumes"].append({"name": name, "node": node.name})
        except Exception as exc:
            warnings.append(f"{node.name} 查询失败：{exc}")
    gateway = platform_gateway_node(db)
    if gateway and gateway_candidates:
        try:
            with SSHNode(gateway) as ssh:
                checks = "; ".join(f"test -e {shlex.quote(path)} && printf '%s\\n' {shlex.quote(path)} || true" for path in gateway_candidates)
                _, existing = ssh.run(checks, timeout=20)
                resources["gateway_files"] = list(dict.fromkeys(filter(None, map(str.strip, existing.splitlines()))))
        except Exception as exc:
            warnings.append(f"平台网关文件查询失败：{exc}")
    source_root = Path(settings.upload_root) / item.id
    if source_root.exists():
        resources["source"].append(str(source_root))
    return {
        "project": {"id": item.id, "name": item.name, "slug": item.slug},
        "resources": resources,
        "counts": {key: len(value) for key, value in resources.items()},
        "warnings": warnings,
        "ai_summary": (
            f"系统已查询到 {len(deployments)} 条发布记录、{len(resources['containers'])} 个容器、"
            f"{len(resources['images'])} 个节点应用镜像、{len(resources['registry_images'])} 个镜像仓库版本。"
            "删除项目会先停止运行服务，再逐项清理并复查。"
        ),
    }


@app.delete("/api/projects/{item_id}")
def delete_project(item_id: str, remove_data: bool = False, delete_volumes: str | None = None, db: Session = Depends(get_db), user: User = Depends(require(Role.admin, Role.deployer))):
    item = db.get(Project, item_id)
    if not item:
        raise HTTPException(404, "项目不存在")
    deployments = db.scalars(select(Deployment).where(Deployment.project_id == item_id).order_by(Deployment.created_at)).all()
    replicas = db.scalars(select(ProjectReplica).where(ProjectReplica.project_id == item_id)).all()
    cleanup_results = []
    retained_volumes = []
    discovered_volumes = []
    try:
        selected_volume_names = set(json.loads(delete_volumes)) if delete_volumes is not None else None
        if selected_volume_names is not None and not all(isinstance(name, str) for name in selected_volume_names):
            raise ValueError
    except Exception:
        raise HTTPException(400, "数据卷选择无效，请重新打开删除窗口")
    try:
        # Replica containers are platform-created resources and are not part of
        # the original Compose release. Remove both recorded replicas and any
        # matching orphan discovered on every node used by this project.
        replica_names_by_node: dict[str, set[str]] = {}
        for replica in replicas:
            replica_names_by_node.setdefault(replica.node_id, set()).add(replica.container_name)
        for dep in deployments:
            replica_names_by_node.setdefault(dep.node_id, set())
        for node_id, recorded_names in replica_names_by_node.items():
            node = db.get(Node, node_id)
            if not node:
                continue
            with SSHNode(node) as ssh:
                _, discovered = ssh.run(
                    "docker ps -a --format '{{.Names}}' --filter "
                    + shlex.quote(f"name=^/yz-{item.slug}-replica-")
                )
                names = recorded_names | {name.strip() for name in discovered.splitlines() if name.strip()}
                for name in sorted(names):
                    ssh.run(f"docker rm -f {shlex.quote(name)} >/dev/null 2>&1 || true")
                if names:
                    _, remaining = ssh.run(
                        "docker ps -aq " + " ".join(
                            f"--filter {shlex.quote('name=^/' + name + '$')}" for name in sorted(names)
                        )
                    )
                    if remaining.strip():
                        raise RuntimeError("应用副本容器清理后仍然存在：" + ", ".join(sorted(names)))
                    cleanup_results.append(f"{len(names)} 个应用副本容器已清理并复查")
        # Inventory persistent data before stopping releases.  Historical
        # Compose versions did not always leave ownership labels behind, so a
        # safe platform name prefix is also recognised.
        volume_nodes = {dep.node_id: db.get(Node, dep.node_id) for dep in deployments}
        for node in db.scalars(select(Node).where(Node.enabled == True)).all():
            volume_nodes.setdefault(node.id, node)
        for node in volume_nodes.values():
            if not node:
                continue
            with SSHNode(node) as ssh:
                _, output = ssh.run("docker volume ls -q", timeout=20)
                prefix = f"yz-{item.slug}"
                names = []
                for name in filter(None, map(str.strip, output.splitlines())):
                    owned = name == prefix or name.startswith(prefix + "_") or name.startswith(prefix + "-")
                    if not owned:
                        _, label = ssh.run("docker volume inspect -f " + shlex.quote('{{index .Labels "com.docker.compose.project"}}') + " " + shlex.quote(name), timeout=10)
                        owned = label.strip() == prefix
                    if owned:
                        names.append(name)
            discovered_volumes.extend({"name": name, "node_id": node.id, "node": node.name} for name in names)
        if selected_volume_names is None:
            selected_volume_names = {volume["name"] for volume in discovered_volumes} if remove_data else set()
        known_names = {volume["name"] for volume in discovered_volumes}
        if not selected_volume_names.issubset(known_names):
            raise RuntimeError("数据卷清单已经变化，请关闭窗口后重新核实")
        retained_volumes = [volume for volume in discovered_volumes if volume["name"] not in selected_volume_names]
        for dep in deployments:
            node = db.get(Node, dep.node_id)
            if node and dep.status in (DeployStatus.queued, DeployStatus.running, DeployStatus.success):
                cleanup_results.append(stop_deployment(dep, item, node))
                dep.status = DeployStatus.stopped
        db.flush()
        remaining_by_node = {}
        for dep in deployments:
            remaining_by_node[dep.node_id] = remaining_by_node.get(dep.node_id, 0) + 1
        for dep in deployments:
            node = db.get(Node, dep.node_id)
            if node:
                remaining_by_node[dep.node_id] -= 1
                cleanup_results.append(delete_deployment_resources(
                    dep, item, node,
                    remove_compose_images=remaining_by_node[dep.node_id] == 0,
                    remove_persistent_data=False,
                ))
        # A release record can be removed independently or an interrupted
        # operation can fail before it is committed. Reconcile the real Docker
        # state on every node instead of trusting database records alone.
        for cleanup_node in db.scalars(select(Node).where(Node.enabled == True)).all():
            with SSHNode(cleanup_node) as ssh:
                image_root = f"yunzhou/{item.slug}"
                container_prefix = f"yz-{item.slug}-"
                compose_project = f"yz-{item.slug}"
                project_dirs = list(dict.fromkeys([
                    f"{cleanup_node.work_dir.rstrip('/')}/{project_directory(item)}",
                    f"{cleanup_node.work_dir.rstrip('/')}/{item.slug}",
                ]))
                command = (
                    "ids=$(docker ps -aq --filter " + shlex.quote(f"label=com.docker.compose.project={compose_project}") + "); "
                    f"named=$(docker ps -a --format '{{{{.Names}}}}' | awk -v p={shlex.quote(container_prefix)} 'index($0,p)==1 {{print}}'); "
                    "all=$(printf '%s\\n%s\\n' \"$ids\" \"$named\" | sed '/^$/d' | sort -u); "
                    "[ -z \"$all\" ] || docker rm -f $all >/dev/null; "
                    "images=$(docker images --format '{{.Repository}}:{{.Tag}}' | "
                    f"awk -F: -v r={shlex.quote(image_root)} '$1==r || index($1,r\"-\")==1 {{print}}'); "
                    "[ -z \"$images\" ] || printf '%s\\n' \"$images\" | xargs -r docker image rm -f >/dev/null; "
                    + "; ".join(f"rm -rf -- {shlex.quote(path)}" for path in project_dirs) + "; "
                    "docker image prune -f >/dev/null 2>&1 || true; "
                    "left_images=$(docker images --format '{{.Repository}}' | "
                    f"awk -v r={shlex.quote(image_root)} '$1==r || index($1,r\"-\")==1 {{print}}'); "
                    "left_containers=$(docker ps -a --format '{{.Names}}' | "
                    f"awk -v p={shlex.quote(container_prefix)} 'index($0,p)==1 {{print}}'); "
                    "[ -z \"$left_images$left_containers\" ]"
                )
                code, output = ssh.run(command, timeout=180)
                if code:
                    raise RuntimeError(output or f"{cleanup_node.name} 项目镜像或容器清理后仍有残留")
                cleanup_results.append(f"{cleanup_node.name} 的真实容器、项目镜像和发布目录已清理并复查")
        deleted_volumes = [volume for volume in discovered_volumes if volume["name"] in selected_volume_names]
        if deleted_volumes:
            by_node: dict[str, list[str]] = {}
            for volume in deleted_volumes:
                by_node.setdefault(volume["node_id"], []).append(volume["name"])
            for node_id, names in by_node.items():
                node = db.get(Node, node_id)
                if not node:
                    continue
                with SSHNode(node) as ssh:
                    command = "; ".join(f"docker volume rm -f {shlex.quote(name)} >/dev/null 2>&1 || true" for name in names)
                    ssh.run(command or "true", timeout=60)
            cleanup_results.append(f"{len(deleted_volumes)} 个平台数据卷已清理")
        gateway = platform_gateway_node(db)
        if gateway and deployments:
            ids = " ".join(shlex.quote(dep.id) for dep in deployments)
            with SSHNode(gateway) as ssh:
                code, output = ssh.run(
                    "for id in " + ids + "; do rm -f -- /data/yunzhou-control/data/gateway/conf.d/$id.conf /data/yunzhou-control/data/gateway/certs/$id.crt /data/yunzhou-control/data/gateway/certs/$id.key; done; "
                    "docker exec yunzhou-platform-gateway nginx -t >/dev/null 2>&1 && docker exec yunzhou-platform-gateway nginx -s reload >/dev/null 2>&1 || true",
                    timeout=30,
                )
                if code:
                    raise RuntimeError(output or "平台网关文件清理失败")
        # Images are built centrally on the platform host before being copied
        # to a target node. They are not represented by target deployment
        # records, so remove them explicitly when the project is deleted.
        if gateway:
            with SSHNode(gateway) as ssh:
                central_prefix = f"yunzhou/{item.slug}-"
                code, output = ssh.run(
                    "images=$(docker images --format '{{.Repository}}:{{.Tag}}' | "
                    f"awk -v p={shlex.quote(central_prefix)} 'index($0,p)==1 {{print}}'); "
                    "if [ -n \"$images\" ]; then printf '%s\\n' \"$images\" | xargs -r docker image rm -f; fi; "
                    f"rm -rf -- {shlex.quote(settings.build_data_root.rstrip('/') + '/builder/projects/' + item.slug)}; "
                    "docker image prune -f >/dev/null 2>&1 || true; "
                    "docker images --format '{{.Repository}}' | "
                    f"awk -v p={shlex.quote(central_prefix)} 'index($0,p)==1 {{found=1}} END {{exit found ? 1 : 0}}'",
                    timeout=120,
                )
                if code:
                    raise RuntimeError(output or "平台构建镜像清理失败")
                cleanup_results.append("平台构建机上的项目镜像及悬空镜像已清理并复查")
        registry_cleanup = _delete_project_registry_repositories(db, item)
        if registry_cleanup["tags"]:
            cleanup_results.append(
                f"平台镜像仓库中的 {len(registry_cleanup['repositories'])} 个项目仓库、"
                f"{len(registry_cleanup['tags'])} 个镜像版本已清理并复查"
            )
        shutil.rmtree(Path(settings.upload_root) / item.id, ignore_errors=True)
    except Exception as exc:
        db.rollback()
        raise HTTPException(502, f"项目尚未删除，资源清理失败：{exc}")
    audit(db, user, "delete_project", "project", item_id, json.dumps({
        "project": item.name,
        "project_slug": item.slug,
        "deployment_count": len(deployments),
        "managed_volumes": "deleted" if not retained_volumes else ("preserved" if not selected_volume_names else "partially_preserved"),
        "retained_volumes": retained_volumes,
        "data_state": "retained" if retained_volumes else ("deleted" if discovered_volumes else "none"),
        "external_data": "preserved",
        "resources": [result.get("summary", str(result)) if isinstance(result, dict) else str(result) for result in cleanup_results],
    }, ensure_ascii=False))
    db.delete(item)
    db.commit()
    return {"ok": True, "summary": f"项目及 {len(deployments)} 条发布记录已删除，远端资源已清理并复查", "details": cleanup_results}


def make_deployment_plan(project: Project, node: Node, db: Session, reserved_host_port: int | None = None) -> dict:
    root = Path(project.source_path) if project.source_path else None
    compose_names = ("compose.yaml", "compose.yml", "docker-compose.yml", "docker-compose.yaml")
    compose_file = next((name for name in compose_names if root and (root / name).exists()), None)
    is_compose = project.build_type == "compose" or (project.build_type == "auto" and bool(compose_file))
    container_port = project.container_port
    detected_from = "项目配置"
    if not container_port and root:
        dockerfile = root / "Dockerfile"
        if dockerfile.exists():
            match = re.search(r"(?im)^\s*EXPOSE\s+(\d+)", dockerfile.read_text(errors="ignore"))
            if match:
                container_port, detected_from = int(match.group(1)), "Dockerfile EXPOSE"
        if not container_port and (root / "package.json").exists():
            container_port, detected_from = 3000, "Node 项目默认值"
        elif not container_port and ((root / "requirements.txt").exists() or (root / "pyproject.toml").exists()):
            container_port, detected_from = 8000, "Python 项目默认值"
        elif not container_port and (root / "pom.xml").exists():
            container_port, detected_from = 8080, "Java 项目默认值"
        elif not container_port and (root / "index.html").exists():
            container_port, detected_from = 80, "静态站点默认值"
    host_port = None if is_compose else (reserved_host_port or project.host_port or choose_port(db, None))
    address = node.public_address or node.host
    access_url = f"https://{project.domain}" if project.domain else (None if is_compose or not host_port else f"http://{address}:{host_port}")
    build_mode = "Docker Compose" if is_compose else ("Dockerfile" if project.build_type == "dockerfile" else "自动识别并生成 Dockerfile")
    git_url, git_branch, git_path = git_source_location(project.git_url or "", project.git_branch)
    source_step = (
        {"title": "拉取 Git 源码", "detail": f"从 {git_url or '已配置仓库'} 的 {git_branch or '默认'} 分支读取源码，项目目录为 {'/' + git_path if git_path else '仓库根目录（拉取后自动扫描）'}"}
        if project.source_type == SourceType.git else
        {"title": "读取上传源码", "detail": "读取用户已上传并保存到平台的项目文件，不访问 Git 仓库"}
    )
    if is_compose:
        execution_steps = [
            {"title": "识别 Compose", "detail": f"读取 {compose_file or 'Compose 配置'}，识别服务、依赖、端口和构建项"},
            {"title": "上传服务器", "detail": f"上传到 {node.work_dir.rstrip('/')}/{project_directory(project)}/版本号"},
            {"title": "拉取服务镜像", "detail": "只拉取 Compose 中直接引用的镜像，本地构建的服务进入下一步"},
            {"title": "构建应用服务", "detail": "构建 Compose 中带 build 的服务并记录每个服务的日志"},
            {"title": "启动全部服务", "detail": "按 Compose 依赖关系启动服务并应用环境变量、端口和重启策略"},
            {"title": "检查服务关系", "detail": "逐个核对容器状态、服务依赖和 Compose 对外端口"},
        ]
    else:
        execution_steps = [
            {"title": "识别项目", "detail": f"使用 {build_mode}，识别运行命令、容器端口和依赖"},
            {"title": "上传服务器", "detail": f"上传到 {node.work_dir.rstrip('/')}/{project_directory(project)}/版本号"},
            {"title": "拉取基础镜像", "detail": "解析 Dockerfile 的 FROM，并逐个拉取实际需要的基础镜像"},
            {"title": "构建应用镜像", "detail": "执行 Docker 构建，在镜像中安装项目依赖并保留完整日志"},
            {"title": "启动应用容器", "detail": f"使用已预留端口 {host_port} 启动容器并应用环境变量和重启策略"},
            {"title": "检查运行状态", "detail": "确认容器确实处于 running 状态后生成访问地址"},
        ]
    return {
        "project": project.name,
        "node": node.name,
        "node_address": address,
        "source": "Git 仓库" if project.source_type == SourceType.git else "已上传源码",
        "build_mode": build_mode,
        "container_port": container_port,
        "container_port_source": detected_from if container_port else "执行时继续识别",
        "host_port": host_port,
        "port_mode": "由 Compose 配置管理" if is_compose else "已预留，不会分配给其他任务",
        "access_url": access_url,
        "steps": [source_step, *execution_steps],
    }


def plan_log(plan: dict) -> str:
    port = plan["port_mode"] if plan["host_port"] is None else f"{plan['host_port']} → {plan['container_port'] or '待识别'}"
    lines = ["[计划] 发布前分析完成", f"目标服务器：{plan['node']}（{plan['node_address']}）", f"构建方式：{plan['build_mode']}", f"端口规划：{port}"]
    lines.extend(f"{index + 1}. {step['title']}：{step['detail']}" for index, step in enumerate(plan["steps"]))
    return "\n".join(lines) + "\n"


@app.get("/api/projects/{item_id}/deployment-plan")
def project_deployment_plan(item_id: str, node_id: str, db: Session = Depends(get_db), _: User = Depends(current_user)):
    project, node = db.get(Project, item_id), db.get(Node, node_id)
    if not project or not node:
        raise HTTPException(404, "项目或节点不存在")
    return make_deployment_plan(project, node, db)


@app.post("/api/projects/{item_id}/deploy", response_model=DeploymentOut)
def deploy(item_id: str, body: DeployIn, db: Session = Depends(get_db), user: User = Depends(require(Role.admin, Role.deployer))):
    project, node = db.get(Project, item_id), db.get(Node, body.node_id)
    if not project or not node:
        raise HTTPException(404, "项目或节点不存在")
    # Deploying from the project form must use exactly what is currently on
    # screen. Persist configuration in the same transaction that creates the
    # deployment so users never need to click a separate save button first.
    submitted = body.model_dump(exclude_unset=True)
    if "env_text" in submitted:
        env_text = str(body.env_text or "")
        invalid = [line for line in env_text.splitlines() if line.strip() and not line.lstrip().startswith("#") and "=" not in line]
        if invalid:
            raise HTTPException(400, "环境变量格式应为 KEY=VALUE，每行一项")
        project.env_text_encrypted = encrypt(env_text.strip() + "\n" if env_text.strip() else "")
    for field in (
        "name", "domain", "container_port", "host_port", "load_balance_enabled",
        "replica_count", "load_balance_strategy", "deployment_mode",
    ):
        if field in submitted:
            setattr(project, field, getattr(body, field))
    source_state = project.source_analysis or {}
    source_phase = source_state.get("phase") or source_state.get("status") or "ready"
    if source_phase in {"queued", "pulling", "analyzing", "running"}:
        raise HTTPException(409, "源码仍在后台拉取和分析，请等待项目显示“分析完成”后再发布")
    if source_phase == "failed":
        raise HTTPException(409, "源码处理失败，请先在“源码管理”中查看原因并重新分析")
    require_reachable_node(node, db)
    active = db.scalar(
        select(Deployment).where(
            Deployment.project_id == project.id,
            Deployment.node_id == node.id,
            Deployment.status.in_([DeployStatus.queued, DeployStatus.running]),
        ).order_by(Deployment.created_at.desc())
    )
    if active:
        raise HTTPException(409, f"该项目在此服务器已有进行中的部署任务（{active.id[:8]}），请等待完成或先停止该任务")
    plan = make_deployment_plan(project, node, db)
    item = Deployment(project_id=project.id, node_id=node.id, requested_by=user.id, status=DeployStatus.queued, host_port=plan["host_port"], log_text=plan_log(plan))
    db.add(item)
    db.flush()
    audit(db, user, "deploy", "deployment", item.id, f"{project.name} -> {node.name}; current form configuration saved atomically")
    db.commit()
    db.refresh(item)
    return item


def pipeline_steps(log_text: str, status: DeployStatus, selected_key: str | None = None, is_compose: bool = False) -> list[dict]:
    # Keep the user-facing pipeline compact. Detailed AI/preflight activity is
    # retained in the log for the active major stage.
    definitions = [
        ("analyze", "读取方案", ("方案",)),
        ("prepare", "准备环境", ("准备", "源码", "依赖分析", "架构分析", "识别", "上传", "镜像")),
        # Centralized builds are marked as [平台构建]. Keep these aliases in
        # the build stage; otherwise the UI sees the earlier [识别] marker and
        # incorrectly leaves "分析项目" active while BuildKit is running.
        ("build", "构建应用", ("构建", "平台构建", "AI构建")),
        ("start", "启动服务", ("启动",)),
        ("verify", "验证访问", ("检查", "完成")),
    ]
    # New deployments emit explicit stage boundaries. Prefer them over
    # guessing from ordinary human-readable log messages.
    if "[阶段开始]" in log_text:
        starts = {}
        for match in re.finditer(r"(?m)^\[阶段开始\]\s+(analyze|prepare|build|start|verify)\s*$", log_text):
            starts[match.group(1)] = match.start()
        completed = {match.group(1) for match in re.finditer(
            r"(?m)^\[阶段完成\]\s+(analyze|prepare|build|start|verify)\s*$", log_text
        )}
        failed = {match.group(1) for match in re.finditer(
            r"(?m)^\[阶段失败\]\s+(analyze|prepare|build|start|verify)(?:\s+\|.*)?$", log_text
        )}
        stopped = {match.group(1) for match in re.finditer(
            r"(?m)^\[阶段停止\]\s+(analyze|prepare|build|start|verify)\s*$", log_text
        )}
        active_key = max(starts, key=starts.get) if starts else "analyze"
        failure_key = next((key for key, _title, _tags in definitions if key in failed), None)
        default_key = failure_key or active_key
        valid_keys = {item[0] for item in definitions}
        log_key = selected_key if selected_key in valid_keys and selected_key in starts else default_key
        ordered_starts = sorted((position, key) for key, position in starts.items())
        result = []
        for key, title, _tags in definitions:
            start = starts.get(key)
            if start is None:
                # A successful deployment is authoritative even when an
                # older worker did not emit the final explicit stage marker.
                # Leaving the last card at "waiting" after progress reached
                # 100% makes a healthy release look unfinished.
                stage_status = "success" if status == DeployStatus.success else "waiting"
                section = ""
            else:
                end = next((position for position, _next_key in ordered_starts if position > start), len(log_text))
                section = log_text[start:end].strip()[-30_000:] if key == log_key else ""
                if key in failed:
                    stage_status = "failed"
                elif key in stopped:
                    stage_status = "stopped"
                elif key in completed or status == DeployStatus.success:
                    stage_status = "success"
                elif key == active_key and status == DeployStatus.running:
                    stage_status = "running"
                elif key == active_key and status == DeployStatus.failed:
                    stage_status = "failed"
                elif key == active_key and status == DeployStatus.stopped:
                    stage_status = "stopped"
                else:
                    stage_status = "waiting"
            result.append({"key": key, "title": title, "status": stage_status, "log": section})
        return result
    positions = []
    for key, title, tags in definitions:
        # A worker restart can retry the same task. Use the latest attempt's marker.
        pos = max((log_text.rfind(f"[{tag}]") for tag in tags), default=-1)
        positions.append(pos)
    available = [index for index, pos in enumerate(positions) if pos >= 0]
    # The active stage is the marker written latest in the log, not merely the
    # first/last definition containing any historical marker.
    active_index = max(available, key=lambda index: positions[index]) if available else None
    inferred_index = None
    if not available and status in (DeployStatus.running, DeployStatus.stopped):
        lower = log_text.lower()
        if any(word in lower for word in ("load build definition", "building", "docker:default", "transferring context")):
            inferred_index = 2
        elif any(word in lower for word in ("pulling", "pull complete", "downloading")):
            inferred_index = 1
    default_key = definitions[active_index][0] if active_index is not None else definitions[0][0]
    if inferred_index is not None:
        default_key = definitions[inferred_index][0]
    # A failure may happen before the first normal stage marker (for example
    # while preparing an isolated checkout). Keep the failure visible instead
    # of rendering every step as waiting with an empty log panel.
    if status == DeployStatus.failed and active_index is None:
        active_index = inferred_index if inferred_index is not None else 0
        default_key = definitions[active_index][0]
    selected_index = next((i for i, item in enumerate(definitions) if item[0] == selected_key), None)
    if status == DeployStatus.failed and (selected_index is None or positions[selected_index] < 0):
        log_key = default_key
    else:
        log_key = selected_key if selected_key in {x[0] for x in definitions} else default_key
    result = []
    for index, (key, title, _tags) in enumerate(definitions):
        start = positions[index]
        later = [x for x in positions[index + 1:] if x >= 0]
        end = min(later) if later else len(log_text)
        section = log_text[start:end].strip()[-30_000:] if start >= 0 and key == log_key else ""
        if status == DeployStatus.failed and index == active_index and key == log_key and not section:
            section = log_text.strip()[-30_000:]
        # AI follow-up records are metadata, not build output. Keep raw stage
        # logs clean even for records created by older platform versions.
        section = re.sub(r"(?m)^\[AI跟进\].*$", "", section).rstrip()
        # Long dependency output can push the useful cache result outside the
        # active 30k window, especially while a build waits for the serialized
        # image-store lock. Keep a compact, evidence-based summary visible so
        # the UI never looks as if earlier logs or cache results disappeared.
        if key == "build" and key == log_key:
            cache_lines = re.findall(r"(?m)^\[缓存命中\].*$", log_text)
            if cache_lines:
                cache_summary = "[本次缓存摘要]\n" + "\n".join(cache_lines[-6:])
                if not all(line in section for line in cache_lines[-6:]):
                    section = cache_summary + "\n\n" + section
        if status == DeployStatus.success:
            stage_status = "success"
            if key == log_key and start < 0:
                section = log_text[-30_000:]
        elif inferred_index is not None and not available:
            stage_status = "success" if index < inferred_index else (("stopped" if status == DeployStatus.stopped else "running") if index == inferred_index else "waiting")
            if index == inferred_index and key == log_key:
                section = log_text[-30_000:]
        elif start < 0:
            stage_status = "waiting"
        elif active_index is not None and index < active_index:
            stage_status = "success"
        elif active_index is not None and index > active_index:
            stage_status = "waiting"
        elif status == DeployStatus.failed:
            stage_status = "failed"
        elif status == DeployStatus.stopped:
            stage_status = "stopped"
        elif status == DeployStatus.success:
            stage_status = "success"
        else:
            stage_status = "running"
        result.append({"key": key, "title": title, "status": stage_status, "log": section})
    return result


def deployment_view(item: Deployment, db: Session, include_log: bool = True, stage: str | None = None) -> dict:
    data = DeploymentOut.model_validate(item).model_dump()
    project, node = db.get(Project, item.project_id), db.get(Node, item.node_id)
    log_text = item.log_text or ""
    if item.status == DeployStatus.failed and item.error and item.error not in log_text:
        log_text = (log_text + "\n[失败] " + item.error).strip()
    stage_definitions = [
        (("方案",), 10, "正在读取方案"),
        (("准备", "源码", "依赖分析", "架构分析", "识别", "上传", "镜像"), 40, "正在准备运行环境"),
        (("构建", "平台构建", "AI构建"), 65, "正在构建应用"),
        (("启动",), 82, "正在启动服务"),
        (("检查", "完成"), 95, "正在验证访问"),
    ]
    if item.status == DeployStatus.queued:
        ahead = db.scalar(select(func.count()).select_from(Deployment).where(Deployment.status.in_([DeployStatus.queued, DeployStatus.running]), Deployment.created_at < item.created_at)) or 0
        progress, current_step = 5, (f"队列等待，前方 {ahead} 个任务" if ahead else "等待执行器领取任务")
    elif item.status == DeployStatus.success:
        progress, current_step = 100, "部署完成，服务运行中"
    elif item.status == DeployStatus.failed:
        progress, current_step = 100, "部署失败"
    elif item.status == DeployStatus.stopped:
        progress, stopped_stage = 10, "准备部署"
        for tags, stage_progress, label in stage_definitions:
            if any(f"[{tag}]" in log_text for tag in tags):
                progress, stopped_stage = stage_progress, label.replace("正在", "")
        current_step = f"已停止（停在{stopped_stage}）"
    else:
        progress, current_step = 10, "正在启动部署流程"
        latest_stage = None
        for tags, stage_progress, label in stage_definitions:
            position = max((log_text.rfind(f"[{tag}]") for tag in tags), default=-1)
            if position >= 0 and (latest_stage is None or position > latest_stage[0]):
                latest_stage = (position, stage_progress, label)
        if latest_stage:
            _, progress, current_step = latest_stage
        lower = log_text.lower()
        if progress == 10 and any(word in lower for word in ("load build definition", "building", "docker:default", "transferring context")):
            progress, current_step = 70, "正在构建镜像并安装依赖"
        elif progress == 10 and any(word in lower for word in ("pulling", "pull complete", "downloading")):
            progress, current_step = 52, "正在拉取项目所需镜像"
    # Collection views only need the assigned ports. Rebuilding the complete
    # deployment plan for every row caused an N+1 query/CPU spike and returned
    # 100+ KB every few seconds on the project and history pages.
    plan = make_deployment_plan(project, node, db, item.host_port) if include_log and project and node else (
        {"container_port": project.container_port, "host_port": item.host_port} if project else None
    )
    image_states = {}
    if include_log:
        for image_name, image_status in re.findall(r"(?m)^\[镜像项\]\s*(.+?)\|(pulling|ready|local|failed)\s*$", log_text):
            image_states[image_name.strip()] = image_status
    login_info = None
    login_payload = item.login_info_json
    if not login_payload:
        login_matches = re.findall(r"(?m)^\[登录信息\]\s*(\{.*\})\s*$", log_text)
        login_payload = login_matches[-1] if login_matches else None
    if include_log and login_payload:
        try:
            login_info = json.loads(login_payload)
            path = str(login_info.get("login_url_path") or "/")
            if item.access_url:
                login_info["login_url"] = item.access_url.rstrip("/") + "/" + path.lstrip("/")
        except (TypeError, ValueError, json.JSONDecodeError):
            login_info = None
    replica_rows = db.scalars(select(ProjectReplica).where(
        ProjectReplica.deployment_id == item.id,
        ProjectReplica.status == "running",
    ).order_by(ProjectReplica.created_at)).all() if include_log else []
    internal_instances = []
    if node and item.host_port:
        internal_instances.append({
            "name": item.container_name or f"yz-{project.slug if project else item.project_id[:8]}",
            "url": f"http://{node.host}:{item.host_port}", "port": item.host_port, "primary": True,
        })
        internal_instances.extend({
            "name": replica.container_name, "url": f"http://{node.host}:{replica.host_port}",
            "port": replica.host_port, "primary": False,
        } for replica in replica_rows)
    data.update({
        "project_name": project.name if project else "未知项目",
        "project_slug": project.slug if project else "",
        "project_domain": project.domain if project else None,
        "node_name": node.name if node else "未知节点",
        "node_address": node.host if node else "",
        "progress": progress,
        "current_step": current_step,
        "pipeline_steps": pipeline_steps(log_text, DeployStatus.success if "[完成]" in log_text else item.status, stage, bool(plan and plan["build_mode"] == "Docker Compose")) if include_log else [],
        "deployment_plan": plan,
        "image_items": [{"name": name, "status": state} for name, state in image_states.items()],
        "node_access_url": (f"http://{node.host}:{item.host_port}" if node and item.host_port else None),
        "internal_instances": internal_instances,
        "ready_replicas": len(internal_instances) if item.status == DeployStatus.success else 0,
        "platform_access_url": item.access_url,
        "login_info": login_info,
        "rollback_allowed": bool(
            item.status == DeployStatus.stopped
            and item.release
            and item.access_url
            and item.host_port
            and any(marker in log_text for marker in ("[完成] 部署成功", "[启用确认]", "[回滚完成]"))
        ),
    })
    data["log_text"] = ""
    return data


@app.get("/api/deployments")
def list_deployments(project_id: str | None = None, db: Session = Depends(get_db), _: User = Depends(current_user)):
    query = select(Deployment).order_by(desc(Deployment.created_at))
    if project_id:
        query = query.where(Deployment.project_id == project_id)
    return [deployment_view(x, db, include_log=False) for x in db.scalars(query.limit(100)).all()]


@app.get("/api/deployments/{item_id}")
def get_deployment(item_id: str, stage: str | None = None, db: Session = Depends(get_db), _: User = Depends(current_user)):
    item = db.get(Deployment, item_id)
    if not item:
        raise HTTPException(404, "部署不存在")
    return deployment_view(item, db, stage=stage)


@app.get("/api/deployments/{item_id}/logs/download")
def download_deployment_log(item_id: str, db: Session = Depends(get_db), _: User = Depends(current_user)):
    item = db.get(Deployment, item_id)
    if not item:
        raise HTTPException(404, "部署不存在")
    project = db.get(Project, item.project_id)
    filename = f"{project.slug if project else 'deployment'}-{item.release or item.id[:8]}.log"
    path = Path(settings.upload_root) / "deployment-logs" / f"{item.id}.log"
    if path.is_file():
        return FileResponse(path, filename=filename, media_type="text/plain; charset=utf-8")
    # Older records predate append-only files; return their retained database
    # log instead of making the download action fail.
    return Response(
        content=item.log_text or "当前记录没有日志。",
        media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/api/deployments/{item_id}/gateway-config")
def deployment_gateway_config(item_id: str, db: Session = Depends(get_db), _: User = Depends(require(Role.admin, Role.deployer))):
    item = db.get(Deployment, item_id)
    if not item:
        raise HTTPException(404, "部署不存在")
    target = db.get(Node, item.node_id)
    project = db.get(Project, item.project_id)
    domain_config = db.get(ProjectDomainConfig, item.project_id)
    gateway = platform_gateway_node(db)
    if not target or not gateway or not item.host_port:
        raise HTTPException(404, "该部署尚未生成平台网关配置")
    # Gateway configuration is stable per project so every release and every
    # replica continues to share one public entry point.
    service_key = f"project-{item.project_id}"
    filename = f"/data/yunzhou-control/data/gateway/conf.d/{service_key}.conf"
    with SSHNode(gateway) as ssh:
        code, config = ssh.run(f"cat {shlex.quote(filename)}", timeout=20)
        configured = code == 0
        if not configured:
            config = ""
        _, firewall = ssh.run(
            "policy=$(iptables -S INPUT 2>/dev/null | head -1); "
            "if printf %s \"$policy\" | grep -q -- '-P INPUT ACCEPT'; then printf unrestricted; else printf managed; fi",
            timeout=20,
        )
        _, gateway_status = ssh.run("docker inspect -f '{{.State.Status}}' yunzhou-platform-gateway 2>/dev/null || printf missing", timeout=20)
    upstreams = re.findall(r"(?m)^\s*server\s+([^;\s]+)\s+max_fails=", config) if configured else []
    if not upstreams and configured:
        direct = re.search(r"proxy_pass\s+http://([^;\s]+);", config)
        if direct and not direct.group(1).startswith("yunzhou_"):
            upstreams = [direct.group(1)]
    return {
        "gateway_node": gateway.name,
        "gateway_address": gateway.public_address or gateway.host,
        "configured": configured,
        "routing_mode": "nginx" if configured else "direct",
        "config_path": filename if configured else None,
        "container": "yunzhou-platform-gateway",
        "container_status": gateway_status.strip(),
        "firewall_status": firewall.strip(),
        "upstream": "、".join(f"http://{value}" for value in upstreams) or f"http://{target.host}:{item.host_port}",
        "upstreams": upstreams,
        "replica_count": len(upstreams) if upstreams else 1,
        "platform_url": item.access_url,
        "domain": project.domain if project else None,
        "http_port": domain_config.http_port if domain_config else 80,
        "https_enabled": domain_config.https_enabled if domain_config else False,
        "https_port": domain_config.https_port if domain_config else 443,
        "redirect_https": domain_config.redirect_https if domain_config else True,
        "certificate_name": domain_config.certificate_name if domain_config else None,
        "config": config.strip(),
    }


@app.get("/api/deployments/{item_id}/launch-config")
def deployment_launch_config(item_id: str, db: Session = Depends(get_db), _: User = Depends(current_user)):
    item = db.get(Deployment, item_id)
    if not item:
        raise HTTPException(404, "部署不存在")
    project, node = db.get(Project, item.project_id), db.get(Node, item.node_id)
    if not project or not node or not item.release:
        raise HTTPException(404, "该发布尚未生成运行配置")
    release_dir = f"{node.work_dir.rstrip('/')}/{project_directory(project)}/{item.release}"
    legacy_dir = f"{node.work_dir.rstrip('/')}/{project.slug}/{item.release}"
    candidates = (".yunzhou.ai.compose.yml", ".yunzhou.compose.yml", "compose.yml", "compose.yaml", "docker-compose.yml", "docker-compose.yaml", ".yunzhou.ai.Dockerfile", ".yunzhou.Dockerfile", "Dockerfile")
    with SSHNode(node) as ssh:
        _, resolved = ssh.run(f"if [ -d {shlex.quote(release_dir)} ]; then printf %s {shlex.quote(release_dir)}; elif [ -d {shlex.quote(legacy_dir)} ]; then printf %s {shlex.quote(legacy_dir)}; fi")
        actual_dir = resolved.strip()
        if not actual_dir:
            raise HTTPException(404, "原发布目录已不存在")
        checks = " ".join(shlex.quote(name) for name in candidates)
        _, selected = ssh.run(f"cd {shlex.quote(actual_dir)} && for f in {checks}; do [ -f \"$f\" ] && printf %s \"$f\" && break; done")
        config_file = selected.strip()
        if not config_file:
            raise HTTPException(404, "未找到编排文件或 Dockerfile")
        code, content = ssh.run(f"cd {shlex.quote(actual_dir)} && head -c 200000 -- {shlex.quote(config_file)}")
        if code:
            raise HTTPException(502, "读取运行配置失败")
        _, env_output = ssh.run(f"cd {shlex.quote(actual_dir)} && test -f .env && head -c 100000 .env || true")
    secret_words = ("password", "secret", "token", "key", "credential")
    # The generated Compose file is useful for diagnostics, but it may contain
    # literal credentials as either YAML values or KEY=VALUE environment items.
    # Keep the endpoint read-only and redact those values before returning it.
    redacted_content_lines = []
    yaml_secret = re.compile(
        r"^(\s*(?:[-]\s*)?[A-Za-z_][A-Za-z0-9_.-]*(?:password|secret|token|key|credential)[A-Za-z0-9_.-]*\s*[:=]\s*)(.*)$",
        re.I,
    )
    for line in content.splitlines():
        match = yaml_secret.match(line)
        redacted_content_lines.append(f"{match.group(1)}******" if match else line)
    content = "\n".join(redacted_content_lines)
    env_lines = []
    for line in env_output.splitlines():
        if "=" not in line or line.lstrip().startswith("#"):
            continue
        key, value = line.split("=", 1)
        env_lines.append(f"{key}={'******' if any(word in key.lower() for word in secret_words) else value}")
    is_compose = config_file.lower().endswith((".yml", ".yaml"))
    command = (
        f"docker compose -p yz-{project.slug} -f {config_file} up -d --no-build --remove-orphans"
        if is_compose else
        f"docker run -d --name {item.container_name or '应用容器'} -p {item.host_port}:<容器端口> {item.image_name or '应用镜像'}"
    )
    return {"type": "compose" if is_compose else "dockerfile", "file": config_file, "content": content, "command": command, "environment": "\n".join(env_lines), "release_dir": actual_dir}


def _docker_size_bytes(value: str) -> float:
    match = re.match(r"\s*([0-9.]+)\s*([kmgt]?i?b)", value or "", re.I)
    if not match:
        return 0
    units = {"b": 1, "kb": 1000, "kib": 1024, "mb": 1000**2, "mib": 1024**2, "gb": 1000**3, "gib": 1024**3, "tb": 1000**4, "tib": 1024**4}
    return float(match.group(1)) * units.get(match.group(2).lower(), 1)


def _human_bytes(value: float) -> str:
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if value < 1024 or unit == "TiB":
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024
    return "0 B"


def _runtime_snapshot_uncached(item: Deployment, db: Session) -> dict:
    project, node = db.get(Project, item.project_id), db.get(Node, item.node_id)
    if not project or not node:
        raise HTTPException(404, "项目或节点不存在")
    release_dir = f"{node.work_dir.rstrip('/')}/{project_directory(project)}/{item.release}" if item.release else ""
    # A compose project name is intentionally stable across releases.  Looking up
    # containers by that name for an old deployment would therefore attach the
    # *current* release to a historical/failed record.  Only the active deployment
    # may expose live containers and container operations.
    latest_success = db.scalar(select(Deployment).where(
        Deployment.project_id == item.project_id,
        Deployment.status == DeployStatus.success,
    ).order_by(desc(Deployment.created_at)).limit(1))
    owns_live_runtime = (
        item.status == DeployStatus.running
        or (item.status == DeployStatus.success and latest_success is not None and latest_success.id == item.id)
    )
    if not owns_live_runtime:
        return {
            "deployment_id": item.id,
            "project": {"id": project.id, "name": project.name, "slug": project.slug, "build_type": project.build_type},
            "node": {"id": node.id, "name": node.name, "host": node.host, "public_address": node.public_address, "work_dir": node.work_dir},
            "release": item.release,
            "release_dir": release_dir,
            "dependencies": {},
            "containers": [],
            "application_instances": 0,
            "ready_application_instances": 0,
            "resources": {"cpu_percent": 0, "cpu": "0.00%", "memory_bytes": 0, "memory_usage": "0 B"},
            "live_runtime": False,
            "runtime_message": "这是历史发布记录，不关联当前正在运行的容器。",
        }
    containers, dependencies = [], {}
    replica_rows = db.scalars(select(ProjectReplica).where(
        ProjectReplica.deployment_id == item.id,
    ).order_by(ProjectReplica.created_at)).all()
    replica_names = {replica.container_name for replica in replica_rows}
    replica_by_name = {replica.container_name: replica for replica in replica_rows}
    with SSHNode(node) as ssh:
        if release_dir and not item.image_name:
            legacy_dir = f"{node.work_dir.rstrip('/')}/{project.slug}/{item.release}"
            _, resolved = ssh.run(f"if [ -d {shlex.quote(release_dir)} ]; then printf %s {shlex.quote(release_dir)}; elif [ -d {shlex.quote(legacy_dir)} ]; then printf %s {shlex.quote(legacy_dir)}; fi")
            if resolved.strip():
                release_dir = resolved.strip()
        # The database is the source of truth for the active application
        # instance.  After failover a healthy standalone replica may have been
        # promoted to primary even though the old Compose file still names the
        # stopped container.  Resolve the recorded container first, then fall
        # back to Compose discovery for ordinary multi-service releases.
        direct_code, direct_output = (1, "")
        # A recorded container name identifies the primary application, but a
        # Compose release can still own backend, Redis, MySQL and other sibling
        # services. Only standalone image deployments should short-circuit to
        # the single recorded container; Compose releases must enumerate the
        # complete Compose project.
        if item.container_name and item.image_name:
            direct_cmd = f"docker ps -a --filter name=^/{shlex.quote(item.container_name)}$ --format '{{{{json .}}}}'"
            direct_code, direct_output = ssh.run(direct_cmd)
        if item.image_name and direct_code == 0 and direct_output.strip():
            code, output = direct_code, direct_output
        elif item.image_name:
            code, output = direct_code, direct_output
        else:
            cmd = f"cd {shlex.quote(release_dir)} && docker compose -p {shlex.quote('yz-' + project.slug)} ps --all --format json" if release_dir else "false"
            code, output = ssh.run(cmd)
            if code != 0:
                code, output = ssh.run(
                    f"docker ps -a --filter label=com.docker.compose.project={shlex.quote('yz-' + project.slug)} --format '{{{{json .}}}}'"
                )
            config_cmd = f"cd {shlex.quote(release_dir)} && docker compose -p {shlex.quote('yz-' + project.slug)} config --format json" if release_dir else "false"
            cfg_code, cfg_output = ssh.run(config_cmd)
            if cfg_code == 0:
                try:
                    cfg = json.loads(cfg_output)
                    for service, spec in cfg.get("services", {}).items():
                        raw = spec.get("depends_on", {})
                        dependencies[service] = list(raw.keys()) if isinstance(raw, dict) else list(raw or [])
                except Exception:
                    pass
        if code == 0 and output.strip():
            try:
                parsed = json.loads(output)
                rows = parsed if isinstance(parsed, list) else [parsed]
            except Exception:
                rows = []
                for line in output.splitlines():
                    try:
                        rows.append(json.loads(line))
                    except Exception:
                        continue
            for row in rows:
                containers.append({
                    "id": row.get("ID") or row.get("Id") or "",
                    "name": row.get("Name") or row.get("Names") or item.container_name or "",
                    "service": row.get("Service") or project.slug,
                    "image": row.get("Image") or item.image_name or "",
                    "state": row.get("State") or row.get("Status") or "unknown",
                    "status": row.get("Status") or row.get("State") or "unknown",
                    "ports": row.get("Ports") or row.get("Publishers") or "",
                })
        if replica_names:
            replica_cmd = "docker ps -a --format '{{json .}}' " + " ".join(
                f"--filter {shlex.quote('name=^/' + name + '$')}" for name in replica_names
            )
            replica_code, replica_output = ssh.run(replica_cmd)
            if replica_code == 0:
                for line in replica_output.splitlines():
                    try:
                        row = json.loads(line)
                    except Exception:
                        continue
                    name = row.get("Names") or row.get("Name") or ""
                    if name and not any(current["name"] == name for current in containers):
                        replica = replica_by_name.get(name)
                        containers.append({
                            "id": row.get("ID") or row.get("Id") or "",
                            "name": name, "service": (replica.service_name if replica else "") or project.slug,
                            "image": row.get("Image") or "",
                            "state": row.get("State") or row.get("Status") or "unknown",
                            "status": row.get("Status") or row.get("State") or "unknown",
                            "ports": row.get("Ports") or "",
                        })
        for container in containers:
            if container["name"] in replica_names:
                container["instance_role"] = "replica"
                replica = replica_by_name[container["name"]]
                container["service_role"] = replica.pool_role or _service_role(project, container["service"])[0]
                container["scalable"] = True
            elif _service_role(project, str(container.get("service") or ""))[1]:
                container["instance_role"] = "primary"
                container["service_role"] = _service_role(project, str(container.get("service") or ""))[0]
                container["scalable"] = True
            else:
                container["instance_role"] = "dependency"
                container["service_role"] = _service_role(project, str(container.get("service") or ""))[0]
                container["scalable"] = False
        running_names = [x["name"] for x in containers if x["name"] and ("running" in str(x["state"]).lower() or str(x["status"]).lower().startswith("up"))]
        stats_by_name = {}
        if running_names:
            stats_cmd = "docker stats --no-stream --format '{{json .}}' " + " ".join(shlex.quote(name) for name in running_names)
            stats_code, stats_output = ssh.run(stats_cmd, timeout=25)
            if stats_code == 0:
                for line in stats_output.splitlines():
                    try:
                        stat = json.loads(line)
                    except Exception:
                        continue
                    name = stat.get("Name") or stat.get("Container") or ""
                    usage, _, limit = (stat.get("MemUsage") or "").partition("/")
                    cpu_text = (stat.get("CPUPerc") or "0%").strip()
                    stats_by_name[name] = {
                        "cpu_percent": float(cpu_text.rstrip("%") or 0),
                        "cpu": cpu_text,
                        "memory_usage": usage.strip() or "0 B",
                        "memory_limit": limit.strip() or "—",
                        "memory_percent": (stat.get("MemPerc") or "0%").strip(),
                        "memory_bytes": _docker_size_bytes(usage),
                        "network_io": stat.get("NetIO") or "—",
                        "block_io": stat.get("BlockIO") or "—",
                        "pids": stat.get("PIDs") or "0",
                    }
        for container in containers:
            container["resources"] = stats_by_name.get(container["name"], {
                "cpu_percent": 0, "cpu": "0%", "memory_usage": "0 B", "memory_limit": "—",
                "memory_percent": "0%", "memory_bytes": 0, "network_io": "—", "block_io": "—", "pids": "0",
            })
    total_cpu = sum(x["resources"]["cpu_percent"] for x in containers)
    total_memory = sum(x["resources"]["memory_bytes"] for x in containers)
    application_instances = [x for x in containers if x.get("instance_role") in ("primary", "replica")]
    return {
        "deployment_id": item.id,
        "project": {"id": project.id, "name": project.name, "slug": project.slug, "build_type": project.build_type},
        "node": {"id": node.id, "name": node.name, "host": node.host, "public_address": node.public_address, "work_dir": node.work_dir},
        "release": item.release,
        "release_dir": release_dir,
        "dependencies": dependencies,
        "containers": containers,
        "application_instances": len(application_instances),
        "ready_application_instances": sum(1 for x in application_instances if "running" in str(x["state"]).lower() or str(x["status"]).lower().startswith("up")),
        "resources": {"cpu_percent": round(total_cpu, 2), "cpu": f"{total_cpu:.2f}%", "memory_bytes": total_memory, "memory_usage": _human_bytes(total_memory)},
        "live_runtime": True,
        "runtime_message": "当前发布拥有实时运行环境。",
    }


def runtime_snapshot(item: Deployment, db: Session, force: bool = False) -> dict:
    """Return live Docker state with short-lived cross-endpoint deduplication."""
    key = _runtime_cache_key(item)
    if not force:
        cached = _runtime_cache_read(key)
        if cached is not None:
            return cached
    with _runtime_cache_guard:
        key_lock = _runtime_cache_locks.setdefault(key, threading.Lock())
    # Project runtime and deployment runtime can arrive concurrently. Only one
    # request performs SSH/Docker discovery; the other waits for and reuses it.
    with key_lock:
        if not force:
            cached = _runtime_cache_read(key)
            if cached is not None:
                return cached
        result = _runtime_snapshot_uncached(item, db)
        _runtime_cache_write(key, result)
        return copy.deepcopy(result)


@app.get("/api/deployments/{item_id}/runtime")
def deployment_runtime(item_id: str, refresh: bool = False, db: Session = Depends(get_db), _: User = Depends(current_user)):
    item = db.get(Deployment, item_id)
    if not item:
        raise HTTPException(404, "部署不存在")
    return runtime_snapshot(item, db, force=refresh)


@app.post("/api/deployments/{item_id}/restart")
def restart_deployment_runtime(item_id: str, body: dict, db: Session = Depends(get_db), user: User = Depends(require(Role.admin, Role.deployer))):
    return _restart_deployment_runtime(item_id, str(body.get("container_name") or "").strip(), db, user)


def _restart_deployment_runtime(item_id: str, requested: str, db: Session, user: User) -> dict:
    item = db.get(Deployment, item_id)
    if not item:
        raise HTTPException(404, "部署不存在")
    project, node = db.get(Project, item.project_id), db.get(Node, item.node_id)
    if not project or not node:
        raise HTTPException(404, "项目或部署服务器不存在")
    snapshot = runtime_snapshot(item, db)
    available = [str(row.get("name") or "") for row in snapshot.get("containers", []) if row.get("name")]
    if requested and requested not in available:
        raise HTTPException(404, "该容器不属于当前运行环境")
    targets = [requested] if requested else available
    if not targets:
        raise HTTPException(409, "当前没有可重启的容器")
    names = " ".join(shlex.quote(name) for name in targets)
    with SSHNode(node) as ssh:
        code, output = ssh.run(f"docker restart --time 20 {names}", timeout=max(40, 30 * len(targets)))
        if code:
            raise HTTPException(502, "重启失败：" + (output.strip()[:300] or "目标服务器未返回原因"))
        code, state = ssh.run(
            "for c in " + names + "; do docker inspect -f '{{.Name}}={{.State.Running}}' \"$c\"; done",
            timeout=20,
        )
    if code or "=false" in state.lower():
        raise HTTPException(502, "容器已执行重启，但有服务未能恢复运行，请查看部署详情日志")
    invalidate_runtime_cache(item.id)
    label = requested or f"全部 {len(targets)} 个容器"
    audit(db, user, "restart_runtime", "deployment", item.id, label)
    db.commit()
    return {"ok": True, "message": f"{label}已重启并恢复运行"}


@app.get("/api/projects/{item_id}/runtime")
def project_runtime(item_id: str, refresh: bool = False, db: Session = Depends(get_db), _: User = Depends(current_user)):
    project = db.get(Project, item_id)
    if not project:
        raise HTTPException(404, "项目不存在")
    rows = db.scalars(select(Deployment).where(Deployment.project_id == item_id).order_by(desc(Deployment.created_at))).all()
    # "Current runtime" must describe the version that is actually serving.
    # A newer cancelled/failed candidate must never hide an older successful
    # release on the same node (the candidates still remain in publish history).
    runtime_priority = {
        DeployStatus.success: 0,
        DeployStatus.running: 1,
        DeployStatus.queued: 2,
        DeployStatus.stopped: 3,
    }
    latest_by_node = {}
    for deployment in rows:
        selected = latest_by_node.get(deployment.node_id)
        if deployment.status in runtime_priority and (
            selected is None or runtime_priority[deployment.status] < runtime_priority[selected.status]
        ):
            latest_by_node[deployment.node_id] = deployment
    environments = []
    for deployment in latest_by_node.values():
        node = db.get(Node, deployment.node_id)
        entry = {
            "deployment_id": deployment.id,
            "node": {"id": node.id, "name": node.name, "address": node.public_address or node.host} if node else None,
            "release": deployment.release,
            "status": deployment.status.value,
            "host_port": deployment.host_port,
            "access_url": deployment.access_url,
            "created_at": deployment.created_at,
            "containers": [],
            "dependencies": {},
        }
        if deployment.release and deployment.status in (DeployStatus.running, DeployStatus.success, DeployStatus.stopped):
            try:
                snapshot = runtime_snapshot(deployment, db, force=refresh)
                entry.update({"release_dir": snapshot["release_dir"], "containers": snapshot["containers"], "dependencies": snapshot["dependencies"], "resources": snapshot["resources"]})
            except Exception as exc:
                entry["runtime_error"] = str(exc)
        environments.append(entry)
    return {"project_id": project.id, "project_name": project.name, "environments": environments}


def _service_instance_prefix(project_slug: str, service_name: str) -> str:
    safe_service = re.sub(r"[^a-z0-9-]", "-", str(service_name).lower()).strip("-") or "app"
    return f"yz-{project_slug}-{safe_service}"


def _service_instance_sequence(name: str, project_slug: str, service_name: str) -> int | None:
    matched = re.fullmatch(re.escape(_service_instance_prefix(project_slug, service_name)) + r"-([1-9][0-9]*)", name or "")
    return int(matched.group(1)) if matched else None


def _next_service_instance_name(
    project_slug: str,
    service_name: str,
    existing_names: set[str],
    minimum: int = 2,
) -> str:
    """Reserve the smallest free sequence; sequence 1 belongs to the primary."""
    prefix = _service_instance_prefix(project_slug, service_name)
    sequence = max(1, int(minimum))
    while f"{prefix}-{sequence}" in existing_names:
        sequence += 1
    name = f"{prefix}-{sequence}"
    existing_names.add(name)
    return name


def _replicas_for_scale_down(
    replicas: list[ProjectReplica],
    project_slug: str,
    service_name: str,
) -> list[ProjectReplica]:
    """Remove legacy random names first, then the highest numeric sequence."""
    numbered: list[tuple[int, ProjectReplica]] = []
    legacy: list[ProjectReplica] = []
    for replica in replicas:
        sequence = _service_instance_sequence(replica.container_name, project_slug, service_name)
        if sequence is None:
            legacy.append(replica)
        else:
            numbered.append((sequence, replica))
    return list(reversed(legacy)) + [replica for _, replica in sorted(numbered, key=lambda item: item[0], reverse=True)]


@app.post("/api/projects/{item_id}/scale")
def scale_project(item_id: str, body: ScaleProjectIn, db: Session = Depends(get_db), user: User = Depends(require(Role.admin, Role.deployer))):
    project = db.get(Project, item_id)
    if not project:
        raise HTTPException(404, "项目不存在")
    deployment = db.scalar(select(Deployment).where(
        Deployment.project_id == item_id,
        Deployment.status == DeployStatus.success,
        Deployment.host_port.is_not(None),
    ).order_by(desc(Deployment.created_at)))
    if not deployment:
        raise HTTPException(409, "项目尚无可扩容的运行版本")
    node = db.get(Node, deployment.node_id)
    if not node:
        raise HTTPException(404, "部署节点不存在")
    all_replicas = db.scalars(select(ProjectReplica).where(
        ProjectReplica.project_id == item_id,
    ).order_by(ProjectReplica.created_at)).all()
    replicas = [item for item in all_replicas if item.deployment_id == deployment.id]
    stale_replicas = [item for item in all_replicas if item.deployment_id != deployment.id]
    created: list[ProjectReplica] = []
    removed: list[ProjectReplica] = []
    with SSHNode(node) as ssh:
        names_code, names_output = ssh.run("docker ps -a --format '{{.Names}}'", timeout=30)
        if names_code:
            raise HTTPException(502, "读取现有容器名称失败，不能安全分配实例序号")
        existing_names = set(filter(None, map(str.strip, names_output.splitlines())))
        # Reconcile physical replica containers as well as database rows. A
        # deployment record may have been deleted by an older platform version
        # while its replica container kept running and holding a host port.
        configured_base_name = deployment.container_name or f"yz-{project.slug}"
        known_names = {configured_base_name, *(item.container_name for item in all_replicas)}
        _, discovered_output = ssh.run(
            "docker ps -a --format '{{.Names}}' | "
            f"grep -E '^{re.escape('yz-' + project.slug + '-replica-')}[0-9]+$' || true"
        )
        for discovered_name in filter(None, map(str.strip, discovered_output.splitlines())):
            if discovered_name not in known_names:
                ssh.run(f"docker rm -f {shlex.quote(discovered_name)} >/dev/null 2>&1 || true")
        # A new release owns a new primary container. Retire replicas cloned from an
        # older image before creating the new replica set, while leaving databases
        # and other Compose dependencies untouched.
        for stale in stale_replicas:
            ssh.run(f"docker rm -f {shlex.quote(stale.container_name)} >/dev/null 2>&1 || true")
            db.delete(stale)
        if stale_replicas:
            db.flush()
        # If the original primary was stopped outside the platform but a
        # healthy replica is still serving traffic, promote that replica. A
        # scale-down to one must never fail merely because the old primary is
        # gone; the surviving application container becomes the new primary.
        base_running_code, _ = ssh.run(
            f"docker inspect -f '{{{{.State.Running}}}}' {shlex.quote(configured_base_name)} 2>/dev/null | grep -qx true"
        )
        promoted = None
        if base_running_code != 0:
            for candidate in replicas:
                running_code, _ = ssh.run(
                    f"docker inspect -f '{{{{.State.Running}}}}' {shlex.quote(candidate.container_name)} 2>/dev/null | grep -qx true"
                )
                if running_code == 0:
                    promoted = candidate
                    break
            if promoted:
                deployment.container_name = promoted.container_name
                deployment.host_port = promoted.host_port
                replicas.remove(promoted)
                db.delete(promoted)
                db.flush()
                configured_base_name = deployment.container_name
        base_name = configured_base_name
        ps_code, ps_output = ssh.run(
            f"docker ps --filter name=^/{shlex.quote(base_name)}$ --format '{{{{json .}}}}'"
        )
        if (ps_code or not ps_output.strip()) and not deployment.image_name:
            ps_code, ps_output = ssh.run(
                f"docker ps --filter label=com.docker.compose.project={shlex.quote('yz-' + project.slug)} --format '{{{{json .}}}}'"
            )
        if ps_code or not ps_output.strip():
            raise HTTPException(409, "未找到当前运行的应用容器")
        rows = []
        for line in ps_output.splitlines():
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        inspected = []
        for row in rows:
            candidate_name = row.get("Names") or row.get("Name")
            if not candidate_name:
                continue
            code, output = ssh.run(f"docker inspect {shlex.quote(candidate_name)}")
            if code:
                continue
            try:
                candidate = json.loads(output)[0]
            except (json.JSONDecodeError, IndexError):
                continue
            bindings = candidate.get("NetworkSettings", {}).get("Ports") or {}
            published_ports = {
                int(binding.get("HostPort"))
                for values in bindings.values() if values
                for binding in values if str(binding.get("HostPort", "")).isdigit()
            }
            inspected.append((candidate_name, candidate, published_ports))
        selected = next((item for item in inspected if deployment.host_port in item[2]), None)
        if not selected:
            raise HTTPException(409, "未识别到可扩容的对外应用服务；依赖容器不会被复制")
        base_name, spec, _ = selected
        base_service = str((spec.get("Config", {}).get("Labels") or {}).get("com.docker.compose.service") or "app")
        base_role, _ = _service_role(project, base_service)
        image = spec.get("Config", {}).get("Image")
        env = [value for value in (spec.get("Config", {}).get("Env") or []) if not value.startswith("HOSTNAME=")]
        networks = list((spec.get("NetworkSettings", {}).get("Networks") or {}).keys())
        network = networks[0] if networks else "bridge"
        container_port = 0
        for port_key, values in (spec.get("NetworkSettings", {}).get("Ports") or {}).items():
            if any(int(value.get("HostPort", 0)) == deployment.host_port for value in (values or [])):
                container_port = int(str(port_key).split("/")[0])
                break
        container_port = container_port or int(project.container_port or 0)
        if not image or not container_port:
            raise HTTPException(409, "应用镜像或容器端口无法识别，已拒绝盲目扩容")
        current = 1 + len(replicas)
        try:
            if body.replicas > current:
                policy = db.get(DeploymentSettings, "default")
                port_end = policy.internal_port_end if policy else 39999
                for _ in range(body.replicas - current):
                    name = _next_service_instance_name(project.slug, base_service, existing_names, minimum=2)
                    port = choose_port(db, None)
                    while port <= port_end:
                        occupied, _ = ssh.run(
                            "(ss -ltnH 2>/dev/null | awk '{print $4}' | "
                            f"grep -Eq ':{port}$') || "
                            "(docker ps --format '{{.Ports}}' 2>/dev/null | "
                            f"grep -Eq '(^|[^0-9]){port}->')"
                        )
                        if occupied != 0:
                            break
                        port += 1
                    if port > port_end:
                        raise RuntimeError("目标服务器内网实例端口池已被占满")
                    env_args = " ".join("-e " + shlex.quote(value) for value in env)
                    mount_args = []
                    for mount in spec.get("Mounts") or []:
                        destination = mount.get("Destination")
                        source = mount.get("Name") if mount.get("Type") == "volume" else mount.get("Source")
                        if not source or not destination:
                            continue
                        mode = "" if mount.get("RW", True) else ",readonly"
                        mount_args.append("--mount " + shlex.quote(f"type={mount.get('Type')},src={source},dst={destination}{mode}"))
                    command = (
                        f"docker rm -f {shlex.quote(name)} >/dev/null 2>&1 || true; "
                        f"docker run -d --name {shlex.quote(name)} --restart unless-stopped "
                        f"--network {shlex.quote(network)} {env_args} {' '.join(mount_args)} "
                        f"-p {port}:{container_port} {shlex.quote(image)}"
                    )
                    code, output = ssh.run(command, timeout=60)
                    if code:
                        raise RuntimeError(output)
                    ready = False
                    for _ in range(20):
                        check, status = ssh.run(f"curl -sS -o /dev/null -w '%{{http_code}}' --connect-timeout 2 --max-time 5 http://127.0.0.1:{port}/")
                        if check == 0 and status.strip().isdigit() and int(status.strip()) < 500:
                            ready = True
                            break
                        time.sleep(2)
                    if not ready:
                        ssh.run(f"docker rm -f {shlex.quote(name)} >/dev/null 2>&1 || true")
                        raise RuntimeError(f"新副本 {name} 健康检查未通过")
                    replica = ProjectReplica(
                        project_id=item_id, deployment_id=deployment.id, node_id=node.id,
                        container_name=name, host_port=port, service_name=base_service,
                        pool_role=base_role, container_port=container_port, status="running",
                    )
                    db.add(replica)
                    db.flush()
                    created.append(replica)
            elif body.replicas < current:
                remove_count = current - body.replicas
                removed = _replicas_for_scale_down(replicas, project.slug, base_service)[:remove_count]

            active = [x for x in replicas if x not in removed] + created
            targets = [(node.host, deployment.host_port)] + [(node.host, x.host_port) for x in active]
            # The legacy project-level scale endpoint is still called by some
            # clients to reconcile a displayed value (including 1 -> 1).  For
            # a Compose project it must not collapse the gateway to the single
            # selected entry container: doing so removes backend API routes
            # that were generated from the source traffic plan.  Rebuild the
            # complete service map from every inspected Compose container and
            # then add replicas to the service they actually belong to.
            service_targets: dict[str, list[tuple[str, int]]] = {}
            for _, candidate, published_ports in inspected:
                labels = candidate.get("Config", {}).get("Labels") or {}
                service_name = str(labels.get("com.docker.compose.service") or labels.get("yunzhou.service") or "").strip()
                if service_name:
                    for published in sorted(published_ports):
                        service_targets.setdefault(service_name, []).append((node.host, int(published)))
            for replica in active:
                service_name = str(replica.service_name or base_service).strip()
                if service_name:
                    service_targets.setdefault(service_name, []).append((node.host, int(replica.host_port)))
            service_targets = {
                service: list(dict.fromkeys(values))
                for service, values in service_targets.items() if values
            }
            route_groups = _route_groups_for_services(project, service_targets)
            domain_config = db.get(ProjectDomainConfig, project.id)
            defaults = db.get(DeploymentSettings, "default")
            deployment.access_url = configure_platform_gateway(
                db, deployment, node, deployment.host_port, project.domain,
                http_port=domain_config.http_port if domain_config else (defaults.default_domain_http_port if defaults else 80),
                https_enabled=domain_config.https_enabled if domain_config else False,
                https_port=domain_config.https_port if domain_config else (defaults.default_domain_https_port if defaults else 443),
                redirect_https=domain_config.redirect_https if domain_config else True,
                certificate=decrypt(domain_config.certificate_encrypted) if domain_config else None,
                private_key=decrypt(domain_config.private_key_encrypted) if domain_config else None,
                upstreams=targets,
                route_groups=route_groups or None,
                strategy=project.load_balance_strategy,
            )
            for replica in removed:
                ssh.run(f"docker rm -f {shlex.quote(replica.container_name)} >/dev/null 2>&1 || true")
                db.delete(replica)
            project.replica_count = body.replicas
            project.load_balance_enabled = body.replicas > 1
            deployment.container_name = base_name
            if promoted:
                deployment.log_text = ((deployment.log_text or "") +
                    f"\n[实例接管] 原主实例已停止，健康副本 {base_name} 已提升为主实例。\n"
                )[-200_000:]
            audit(db, user, "scale_project", "project", project.id,
                  f"replicas={current}->{body.replicas}; services={service_targets}")
            db.commit()
            invalidate_runtime_cache(deployment.id)
        except Exception as exc:
            db.rollback()
            for replica in created:
                ssh.run(f"docker rm -f {shlex.quote(replica.container_name)} >/dev/null 2>&1 || true")
            raise HTTPException(502, f"扩缩容未完成，原有实例继续运行：{exc}") from exc
    return {"ok": True, "desired": body.replicas, "ready": body.replicas, "access_url": deployment.access_url,
            "instances": [{"name": base_name, "port": deployment.host_port, "status": "running"}] +
                         [{"name": x.container_name, "port": x.host_port, "status": x.status} for x in active]}


_NON_SCALABLE_SERVICES = re.compile(
    r"(?:^|[-_.])(mysql|mariadb|postgres|postgresql|redis|mongo|mongodb|oracle|"
    r"minio|elastic|elasticsearch|kafka|rabbitmq|zookeeper|worker|scheduler|"
    r"cron|job|sync)(?:$|[-_.])", re.I,
)


def _traffic_plan(project: Project) -> dict:
    try:
        analysis = json.loads(project.integration_analysis_json or "{}")
    except (TypeError, ValueError):
        analysis = {}
    plan = analysis.get("traffic_plan") if isinstance(analysis, dict) else None
    if isinstance(plan, dict):
        return plan
    deployment_plan = analysis.get("deployment_plan") if isinstance(analysis, dict) else None
    if isinstance(deployment_plan, dict):
        nested = deployment_plan.get("traffic_plan")
        return nested if isinstance(nested, dict) else deployment_plan
    return analysis if isinstance(analysis, dict) else {}


def _service_role(project: Project, service: str) -> tuple[str, bool]:
    plan = _traffic_plan(project)
    roles = plan.get("service_roles") or []
    for row in roles:
        if isinstance(row, dict) and str(row.get("service") or "") == service:
            role = str(row.get("role") or "app").lower()
            return role, bool(row.get("scalable", role in {"frontend", "backend", "app", "web", "api"}))
    lowered = service.lower()
    if _NON_SCALABLE_SERVICES.search(lowered):
        return ("worker" if re.search(r"worker|scheduler|cron|job|sync", lowered) else "data"), False
    if re.search(r"front|web|ui", lowered):
        return "frontend", True
    if re.search(r"back|api|server", lowered):
        return "backend", True
    return "app", True


def _route_groups_for_services(project: Project, service_targets: dict[str, list[tuple[str, int]]]) -> list[dict]:
    """Translate the versioned AI traffic plan into auditable Nginx routes."""
    plan = _traffic_plan(project)
    routes = plan.get("traffic_routes") or plan.get("routes") or []
    default_service = str(plan.get("default_service") or plan.get("entry_service") or "")
    if not default_service:
        default_service = next((name for name in service_targets if _service_role(project, name)[0] == "frontend"), "")
    if not default_service and service_targets:
        default_service = next(iter(service_targets))
    paths_by_service: dict[str, list[dict]] = {}
    for route in routes:
        if not isinstance(route, dict):
            continue
        service = str(route.get("service") or route.get("target_service") or "")
        path = str(route.get("path") or "/")
        if service in service_targets and path.startswith("/"):
            paths_by_service.setdefault(service, []).append({
                "path": path,
                "strip_prefix": bool(route.get("strip_prefix", False)),
            })
    if default_service in service_targets:
        paths_by_service.setdefault(default_service, []).append({"path": "/", "strip_prefix": False})
    # Compatibility fallback for analyses created before traffic_routes was
    # introduced.  Reuse only paths recorded by source analysis.  A missing
    # path is safer than inventing /api and silently routing a project whose
    # actual production prefix is /prod-api, /gateway, or something custom.
    if not routes:
        backend = next((name for name in service_targets if _service_role(project, name)[0] == "backend"), "")
        frontend = next((name for name in service_targets if _service_role(project, name)[0] == "frontend"), "")
        if frontend:
            paths_by_service.setdefault(frontend, []).append({"path": "/", "strip_prefix": False})
        api_paths = plan.get("api_paths") or []
        for path in api_paths:
            if backend and str(path).startswith("/"):
                canonical_path = str(path)
                if canonical_path != "/" and not canonical_path.endswith("/"):
                    canonical_path += "/"
                paths_by_service.setdefault(backend, []).append({
                    "path": canonical_path,
                    "strip_prefix": bool(plan.get("strip_api_prefix", True)),
                })
    groups = []
    for service, paths in paths_by_service.items():
        unique_paths = list({(row["path"], row["strip_prefix"]): row for row in paths}.values())
        if service_targets.get(service) and unique_paths:
            groups.append({
                "name": service,
                "paths": unique_paths,
                "targets": service_targets[service],
                "strategy": project.load_balance_strategy,
            })
    return groups


@app.post("/api/projects/{item_id}/services/{service_name}/scale")
def scale_project_service(item_id: str, service_name: str, body: ScaleProjectIn, db: Session = Depends(get_db), user: User = Depends(require(Role.admin, Role.deployer))):
    project = db.get(Project, item_id)
    if not project:
        raise HTTPException(404, "项目不存在")
    service_name = service_name.strip()
    role, scalable = _service_role(project, service_name)
    if not service_name or not scalable or role in {"data", "worker"} or _NON_SCALABLE_SERVICES.search(service_name):
        raise HTTPException(409, "该服务属于数据或后台任务服务，不能使用普通实例扩缩容")
    deployment = db.scalar(select(Deployment).where(
        Deployment.project_id == item_id,
        Deployment.status == DeployStatus.success,
    ).order_by(desc(Deployment.created_at)))
    if not deployment:
        raise HTTPException(409, "项目尚无可扩容的运行版本")
    node = db.get(Node, deployment.node_id)
    if not node:
        raise HTTPException(404, "部署节点不存在")
    compose_project = "yz-" + project.slug
    all_rows = db.scalars(select(ProjectReplica).where(
        ProjectReplica.project_id == item_id,
        ProjectReplica.deployment_id == deployment.id,
    ).order_by(ProjectReplica.created_at)).all()
    known_replica_names = {row.container_name for row in all_rows}
    created: list[ProjectReplica] = []
    removed: list[ProjectReplica] = []
    with SSHNode(node) as ssh:
        names_code, names_output = ssh.run("docker ps -a --format '{{.Names}}'", timeout=30)
        if names_code:
            raise HTTPException(502, "读取现有容器名称失败，不能安全分配实例序号")
        existing_names = set(filter(None, map(str.strip, names_output.splitlines())))
        code, output = ssh.run(
            "docker ps --filter " + shlex.quote("label=com.docker.compose.project=" + compose_project) +
            " --format '{{json .}}'"
        )
        if code:
            raise HTTPException(502, "读取运行服务失败")
        service_specs: dict[str, tuple[str, dict, int, int]] = {}
        for line in output.splitlines():
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            name = str(row.get("Names") or row.get("Name") or "")
            if not name:
                continue
            inspect_code, inspect_output = ssh.run(f"docker inspect {shlex.quote(name)}")
            if inspect_code:
                continue
            try:
                spec = json.loads(inspect_output)[0]
            except (json.JSONDecodeError, IndexError):
                continue
            labels = spec.get("Config", {}).get("Labels") or {}
            service = str(labels.get("com.docker.compose.service") or labels.get("yunzhou.service") or "")
            if not service:
                continue
            published_port = 0
            container_port = 0
            for port_key, bindings in (spec.get("NetworkSettings", {}).get("Ports") or {}).items():
                for binding in bindings or []:
                    if str(binding.get("HostPort") or "").isdigit():
                        published_port = int(binding["HostPort"])
                        container_port = int(str(port_key).split("/")[0])
                        break
                if published_port:
                    break
            # A later request must continue using the Compose-owned primary,
            # not one of the numbered instances created by this endpoint.
            current_spec = service_specs.get(service)
            if current_spec is None or (current_spec[0] in known_replica_names and name not in known_replica_names):
                service_specs[service] = (name, spec, published_port, container_port)
        if service_name not in service_specs:
            raise HTTPException(404, "当前运行版本中没有找到该服务")
        base_name, spec, base_port, container_port = service_specs[service_name]
        if not base_port or not container_port:
            raise HTTPException(409, "该服务尚未由平台分配独立入口端口，请重新发布后再扩容")
        replicas = [row for row in all_rows if row.service_name == service_name]
        current = 1 + len(replicas)
        image = spec.get("Config", {}).get("Image")
        env = [value for value in (spec.get("Config", {}).get("Env") or []) if not value.startswith("HOSTNAME=")]
        networks = list((spec.get("NetworkSettings", {}).get("Networks") or {}).keys())
        network = networks[0] if networks else "bridge"
        if not image:
            raise HTTPException(409, "服务镜像无法识别，已拒绝盲目扩容")
        try:
            if body.replicas > current:
                policy = db.get(DeploymentSettings, "default")
                port_end = policy.internal_port_end if policy else 39999
                for _ in range(body.replicas - current):
                    name = _next_service_instance_name(project.slug, service_name, existing_names, minimum=2)
                    port = choose_port(db, None)
                    while port <= port_end:
                        occupied, _ = ssh.run(
                            "(ss -ltnH 2>/dev/null | awk '{print $4}' | "
                            f"grep -Eq ':{port}$') || "
                            "(docker ps --format '{{.Ports}}' 2>/dev/null | "
                            f"grep -Eq '(^|[^0-9]){port}->')"
                        )
                        if occupied != 0:
                            break
                        port += 1
                    if port > port_end:
                        raise RuntimeError("目标服务器内网实例端口池已被占满")
                    env_args = " ".join("-e " + shlex.quote(value) for value in env)
                    mount_args = []
                    for mount in spec.get("Mounts") or []:
                        destination = mount.get("Destination")
                        source = mount.get("Name") if mount.get("Type") == "volume" else mount.get("Source")
                        if not source or not destination:
                            continue
                        mode = "" if mount.get("RW", True) else ",readonly"
                        mount_args.append("--mount " + shlex.quote(f"type={mount.get('Type')},src={source},dst={destination}{mode}"))
                    command = (
                        f"docker run -d --name {shlex.quote(name)} --restart unless-stopped "
                        f"--label {shlex.quote('com.docker.compose.project=' + compose_project)} "
                        f"--label {shlex.quote('com.docker.compose.service=' + service_name)} "
                        f"--label {shlex.quote('yunzhou.service=' + service_name)} "
                        f"--network {shlex.quote(network)} {env_args} {' '.join(mount_args)} "
                        f"-p {port}:{container_port} {shlex.quote(image)}"
                    )
                    run_code, run_output = ssh.run(command, timeout=60)
                    if run_code:
                        raise RuntimeError(run_output)
                    ready = False
                    for _ in range(20):
                        check, status = ssh.run(
                            f"curl -sS -o /dev/null -w '%{{http_code}}' --connect-timeout 2 --max-time 5 http://127.0.0.1:{port}/"
                        )
                        if check == 0 and status.strip().isdigit() and int(status.strip()) < 500:
                            ready = True
                            break
                        time.sleep(2)
                    if not ready:
                        ssh.run(f"docker rm -f {shlex.quote(name)} >/dev/null 2>&1 || true")
                        raise RuntimeError(f"新实例 {name} 健康检查未通过")
                    replica = ProjectReplica(
                        project_id=item_id, deployment_id=deployment.id, node_id=node.id,
                        container_name=name, host_port=port, service_name=service_name,
                        pool_role=role, container_port=container_port, status="running",
                    )
                    db.add(replica)
                    db.flush()
                    replicas.append(replica)
                    created.append(replica)
            elif body.replicas < current:
                remove_count = current - body.replicas
                removed = _replicas_for_scale_down(replicas, project.slug, service_name)[:remove_count]
            active = [row for row in replicas if row not in removed]
            service_targets: dict[str, list[tuple[str, int]]] = {}
            for service, (_, _, published, _) in service_specs.items():
                if published:
                    service_targets.setdefault(service, []).append((node.host, published))
            for row in all_rows + created:
                if row not in removed and row.service_name:
                    service_targets.setdefault(row.service_name, []).append((node.host, row.host_port))
            groups = _route_groups_for_services(project, service_targets)
            domain_config = db.get(ProjectDomainConfig, project.id)
            defaults = db.get(DeploymentSettings, "default")
            deployment.access_url = configure_platform_gateway(
                db, deployment, node, deployment.host_port or base_port, project.domain,
                http_port=domain_config.http_port if domain_config else (defaults.default_domain_http_port if defaults else 80),
                https_enabled=domain_config.https_enabled if domain_config else False,
                https_port=domain_config.https_port if domain_config else (defaults.default_domain_https_port if defaults else 443),
                redirect_https=domain_config.redirect_https if domain_config else True,
                certificate=decrypt(domain_config.certificate_encrypted) if domain_config else None,
                private_key=decrypt(domain_config.private_key_encrypted) if domain_config else None,
                route_groups=groups or None,
                strategy=project.load_balance_strategy,
            )
            for row in removed:
                ssh.run(f"docker rm -f {shlex.quote(row.container_name)} >/dev/null 2>&1 || true")
                db.delete(row)
            audit(db, user, "scale_project_service", "project", project.id,
                  f"service={service_name}; role={role}; replicas={current}->{body.replicas}")
            db.commit()
            invalidate_runtime_cache(deployment.id)
        except HTTPException:
            raise
        except Exception as exc:
            db.rollback()
            for row in created:
                ssh.run(f"docker rm -f {shlex.quote(row.container_name)} >/dev/null 2>&1 || true")
            raise HTTPException(502, f"扩缩容未完成，原有实例继续运行：{exc}") from exc
    return {
        "ok": True, "service": service_name, "role": role,
        "desired": body.replicas, "ready": body.replicas,
        "access_url": deployment.access_url,
        "instances": [{"name": base_name, "port": base_port, "status": "running", "primary": True}] + [
            {"name": row.container_name, "port": row.host_port, "status": row.status, "primary": False}
            for row in active
        ],
    }


@app.get("/api/projects/{item_id}/replicas")
def project_replicas(item_id: str, db: Session = Depends(get_db), _: User = Depends(current_user)):
    project = db.get(Project, item_id)
    if not project:
        raise HTTPException(404, "项目不存在")
    desired = max(1, int(project.replica_count or 1)) if project.load_balance_enabled else 1
    deployment = db.scalar(select(Deployment).where(
        Deployment.project_id == item_id,
        Deployment.status == DeployStatus.success,
        Deployment.host_port.is_not(None),
    ).order_by(desc(Deployment.created_at)))
    if not deployment:
        return {"desired": desired, "ready": 0, "access_url": None, "instances": [], "gateway": None}
    node = db.get(Node, deployment.node_id)
    instances = []
    ready = 0
    # Runtime already contains Docker state and resource data. Reusing it here
    # avoids an additional SSH connection plus one docker-inspect call per
    # instance. project/runtime and this endpoint share the same single-flight
    # cache, so opening both UI views performs one remote discovery in total.
    snapshot = None
    try:
        snapshot = runtime_snapshot(deployment, db)
    except Exception:
        snapshot = None
    gateway_info = {
        "status": "running" if deployment.access_url else "unknown",
        "node": node.name if node else None,
        "address": (node.public_address or node.host) if node else None,
        "configured": bool(deployment.access_url),
        "routing_mode": "nginx" if deployment.access_url else "direct",
        "upstream_count": 0,
        "upstream": None,
        "access_url": deployment.access_url,
        "domain": project.domain,
        "https_enabled": str(deployment.access_url or "").startswith("https://"),
    }
    service_pools = []
    try:
        if snapshot is None:
            raise RuntimeError("runtime unavailable")
        grouped: dict[str, dict] = {}
        for container in snapshot.get("containers", []):
            service = str(container.get("service") or project.slug)
            role, scalable = _service_role(project, service)
            pool = grouped.setdefault(service, {
                "service": service, "role": role, "scalable": scalable,
                "desired": 0, "ready": 0, "instances": [],
            })
            status_text = str(container.get("status") or container.get("state") or "unknown")
            running = status_text.lower().startswith("up") or "running" in status_text.lower()
            port_match = re.search(r"(?:0\.0\.0\.0|\[::\]|:::?):(\d+)->", str(container.get("ports") or ""))
            instance = {
                "name": container.get("name"),
                "port": int(port_match.group(1)) if port_match else None,
                "status": "running" if running else status_text,
                "primary": container.get("instance_role") != "replica",
            }
            pool["instances"].append(instance)
            pool["desired"] += 1
            pool["ready"] += 1 if running else 0
            instances.append(instance)
            ready += 1 if running else 0
        service_pools = sorted(grouped.values(), key=lambda row: (
            {"frontend": 0, "backend": 1, "app": 2, "worker": 3, "data": 4}.get(row["role"], 5), row["service"]
        ))
        gateway_info["upstream_count"] = sum(pool["ready"] for pool in service_pools if pool["scalable"])
    except Exception:
        service_pools = []
    return {
        "desired": desired,
        "ready": ready,
        "access_url": deployment.access_url,
        "instances": instances,
        "gateway": gateway_info,
        "services": service_pools,
    }


@app.get("/api/projects/{item_id}/data-resources")
def project_data_resources(item_id: str, db: Session = Depends(get_db), _: User = Depends(current_user)):
    project = db.get(Project, item_id)
    if not project:
        raise HTTPException(404, "项目不存在")
    latest = db.scalar(select(Deployment).where(Deployment.project_id == item_id, Deployment.release.is_not(None)).order_by(desc(Deployment.created_at)))
    files: list[tuple[str, str]] = []
    source_label = "尚无可分析的发布版本"
    if latest:
        node = db.get(Node, latest.node_id)
        if node:
            release_dir = f"{node.work_dir.rstrip('/')}/{project_directory(project)}/{latest.release}"
            legacy_dir = f"{node.work_dir.rstrip('/')}/{project.slug}/{latest.release}"
            with SSHNode(node) as ssh:
                _, resolved = ssh.run(f"if [ -d {shlex.quote(release_dir)} ]; then printf %s {shlex.quote(release_dir)}; elif [ -d {shlex.quote(legacy_dir)} ]; then printf %s {shlex.quote(legacy_dir)}; fi")
                actual = resolved.strip()
                if actual:
                    source_label = f"版本 {latest.release} · {node.name}"
                    _, listing = ssh.run(f"find {shlex.quote(actual)} -type f \\( -iname '*.sql' -o -iname 'application*.yml' -o -iname 'application*.yaml' -o -iname 'application*.properties' -o -name 'sc.properties' -o -name 'pom.xml' -o -name 'package.json' -o -name '.yunzhou.ai.compose.yml' -o -name '.yunzhou.compose.yml' -o -name 'compose.yml' -o -name 'compose.yaml' -o -name 'docker-compose.yml' -o -name 'docker-compose.yaml' \\) -print")
                    sftp = ssh.client.open_sftp()
                    for path in listing.splitlines()[:500]:
                        try:
                            content = sftp.open(path).read(2_000_000).decode("utf-8", "ignore")
                            files.append((path.removeprefix(actual + "/"), content))
                        except Exception:
                            continue
                    sftp.close()
    combined_config = "\n".join(content.lower() for path, content in files if not path.lower().endswith(".sql"))
    env_text = decrypt(project.env_text_encrypted) or ""
    env_values = {line.split("=", 1)[0].strip(): line.split("=", 1)[1] for line in env_text.splitlines() if "=" in line and not line.lstrip().startswith("#")}
    analysis = json.loads(project.integration_analysis_json) if project.integration_analysis_json else {}
    detected_services = {str(name).lower() for name in analysis.get("services", [])}
    combined_evidence = combined_config + "\n" + "\n".join(env_values.keys()).lower()
    database_type = "未识别"
    for marker, label in (("jdbc:mysql", "MySQL"), ("jdbc:postgresql", "PostgreSQL"), ("jdbc:oracle", "Oracle"), ("sqlserver", "SQL Server"), ("kingbase", "人大金仓"), ("dm.jdbc", "达梦")):
        if marker in combined_evidence:
            database_type = label
            break
    if database_type == "未识别" and ("mysql" in detected_services or any("mysql" in key.lower() or key.upper().startswith("DB_") for key in env_values)):
        database_type = "MySQL"
    password_configured = any(value and "password" in key.lower() and any(token in key.lower() for token in ("db", "mysql", "datasource")) for key, value in env_values.items()) or bool(re.search(r"(?im)^\s*[^#\n]*(?:datasource|jdbc)[^\n]*password\s*[:=]\s*\S+", combined_config))
    last_test = db.scalar(select(AuditLog).where(AuditLog.action == "test_integration", AuditLog.target_id == project.id).order_by(desc(AuditLog.created_at)).limit(1))
    live_checked = bool(last_test and "mysql@" in (last_test.detail or "").lower())
    sql_files = []
    destructive_words = re.compile(r"(?i)\b(drop\s+(?:table|database)|truncate\s+table|delete\s+from|alter\s+table\s+.+\s+drop\s+)\b")
    for path, content in files:
        if not path.lower().endswith(".sql"):
            continue
        destructive = sorted(set(match.group(0).upper() for match in destructive_words.finditer(content)))
        sql_files.append({
            "path": path,
            "kind": "初始化脚本" if any(word in path.lower() for word in ("init", "schema", "basic")) else "增量脚本",
            "statements": max(1, content.count(";")),
            "risk": "high" if destructive else "low",
            "risk_reasons": destructive,
        })
    services = [
        {"name": "Redis", "state": "configured" if "redis" in detected_services or any("redis" in key.lower() for key in env_values) or any(x in combined_config for x in ("spring.redis", "redis.host", "redis://", "image: redis")) else "not_found"},
        {"name": "MinIO", "state": "configured" if any("minio" in name or "s3" in name for name in detected_services) or any("minio" in key.lower() or "s3" in key.lower() for key in env_values) or any(x in combined_config for x in ("minio.", "image: minio", "s3.endpoint")) else "not_found"},
        {"name": "RabbitMQ", "state": "candidate" if "rabbitmq" in combined_config else "not_found"},
        {"name": "Elasticsearch", "state": "candidate" if "elasticsearch" in combined_config else "not_found"},
    ]
    high_risk = sum(1 for item in sql_files if item["risk"] == "high")
    return {
        "project_id": project.id,
        "source": source_label,
        "database": {"type": database_type, "connection_configured": database_type != "未识别", "password_configured": password_configured, "live_checked": live_checked},
        "services": services,
        "migrations": sql_files,
        "summary": f"识别到 {database_type} 配置和 {len(sql_files)} 个 SQL 文件，其中 {high_risk} 个包含高风险操作。" if sql_files else f"识别到 {database_type} 配置，未发现 SQL 迁移文件。",
        "next_step": "连接凭据保持隐藏。绑定并测试数据库连接、完成备份后，平台才会允许执行迁移。",
    }


_migration_locks: dict[str, threading.Lock] = {}
_MIGRATION_DANGER = re.compile(
    r"(?i)\b(drop\s+(?:table|database|schema)|truncate\s+table|delete\s+from|alter\s+table\s+.+\s+drop\s+)\b"
)


def _extract_direct_sql(message: str) -> str | None:
    fenced = re.search(r"```(?:sql)?\s*([\s\S]+?)```", message, re.I)
    if fenced:
        return fenced.group(1).strip()
    # ``\b`` treats Chinese characters as word characters, so text such as
    # “帮我执行SELECT ...” has no boundary before SELECT.  Only forbid an
    # adjacent ASCII identifier character; natural-language prefixes remain
    # valid while words like ``reselect`` do not become SQL accidentally.
    match = re.search(r"(?is)(?<![A-Za-z0-9_])(select|show|describe|desc|explain|with|alter|create|drop|truncate|comment|rename|insert|update|delete)\b[\s\S]*", message)
    return match.group(0).strip() if match else None


def _sql_kind(sql: str) -> str:
    cleaned = re.sub(r"(?s)/\*.*?\*/|--[^\n]*", " ", sql).strip()
    first = re.match(r"(?i)([a-z]+)", cleaned)
    keyword = first.group(1).lower() if first else ""
    if keyword in {"select", "show", "describe", "desc", "explain", "with"}:
        # Read-only requests may not smuggle a second modifying statement.
        tail = cleaned.rstrip().rstrip(";")
        if ";" in tail or re.search(r"(?i)\b(insert|update|delete|alter|create|drop|truncate|rename)\b", tail):
            return "unsupported"
        return "query"
    if keyword in {"alter", "create", "drop", "truncate", "comment", "rename"}:
        if re.search(r"(?i)\b(insert|update|delete|grant|revoke|load\s+data|copy\s+.+\s+from)\b", cleaned):
            return "unsupported"
        return "schema"
    if keyword in {"insert", "update", "delete"}:
        return "data_change"
    return "unsupported"


def _external_mysql_config(project: Project) -> dict | None:
    values = _env_map(decrypt(project.env_text_encrypted) or "")
    if values.get("YUNZHOU_MYSQL_MODE", "").lower() != "external":
        return None
    required = {
        "host": values.get("YUNZHOU_MYSQL_HOST", "").strip(),
        "port": values.get("YUNZHOU_MYSQL_PORT", "3306").strip(),
        "database": values.get("YUNZHOU_MYSQL_DATABASE", "").strip(),
        "username": values.get("YUNZHOU_MYSQL_USERNAME", "").strip(),
        "password": values.get("YUNZHOU_MYSQL_PASSWORD", ""),
    }
    if not all(required.values()) or any("\n" in value or "\r" in value for value in required.values()):
        return None
    if not required["port"].isdigit():
        return None
    return required


def _database_container(ssh: SSHNode, project: Project, *, required: bool = True) -> tuple[str, str] | None:
    code, listing = ssh.run("docker ps --format '{{.Names}}\\t{{.Image}}'")
    if code:
        raise HTTPException(502, "无法读取项目数据库容器")
    tokens = {project.slug.lower(), project_directory(project).lower()}
    candidates = []
    for line in listing.splitlines():
        name, _, image = line.partition("\t")
        combined = f"{name} {image}".lower()
        if any(token and token in name.lower() for token in tokens) and any(
            marker in combined for marker in ("mysql", "mariadb", "postgres")
        ):
            candidates.append((name, image.lower()))
    if not candidates and not required:
        return None
    if len(candidates) != 1:
        message = "未找到项目自建数据库容器" if not candidates else "识别到多个数据库容器，无法确定查询目标"
        raise HTTPException(409, message + "；请先在数据资源中确认目标数据库")
    container, image = candidates[0]
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", container):
        raise HTTPException(409, "数据库容器名称不安全")
    return container, image


def _query_project_database(project: Project, sql: str, db: Session, user: User, session_id: str | None = None) -> dict:
    if _sql_kind(sql) != "query":
        raise HTTPException(400, "该入口只允许 SELECT、SHOW、DESCRIBE 或 EXPLAIN 查询")
    deployment = db.scalar(select(Deployment).where(
        Deployment.project_id == project.id, Deployment.status == DeployStatus.success,
    ).order_by(desc(Deployment.created_at)))
    if not deployment:
        raise HTTPException(409, "项目当前没有运行中的数据库")
    node = db.get(Node, deployment.node_id)
    if not node:
        raise HTTPException(409, "项目服务器不存在")
    query_id = uuid.uuid4().hex
    remote_sql = f"/tmp/yunzhou-query-{query_id}.sql"
    remote_out = f"/tmp/yunzhou-query-{query_id}.out"
    with SSHNode(node) as ssh:
        local_target = _database_container(ssh, project, required=False)
        external = _external_mysql_config(project) if not local_target else None
        if not local_target and not external:
            raise HTTPException(409, "未找到可查询的项目数据库；请先在数据资源中配置连接")
        sftp = ssh.client.open_sftp()
        try:
            with sftp.open(remote_sql, "w") as handle:
                handle.write(sql.rstrip().rstrip(";") + ";\n")
            sftp.chmod(remote_sql, 0o600)
            if external:
                with sftp.open(remote_sql + ".env", "w") as handle:
                    handle.write("MYSQL_PWD=" + external["password"] + "\n")
                sftp.chmod(remote_sql + ".env", 0o600)
        finally:
            sftp.close()
        if external:
            execute = (
                f"docker run --rm --network host --env-file {shlex.quote(remote_sql + '.env')} -i mysql:8.4 "
                f"mysql --batch --raw -h {shlex.quote(external['host'])} -P {shlex.quote(external['port'])} "
                f"-u {shlex.quote(external['username'])} {shlex.quote(external['database'])} < {shlex.quote(remote_sql)}"
            )
            engine_name = "MySQL（外接）"
        elif "postgres" in local_target[1]:
            container, image = local_target
            inner = 'exec psql -X -A -F "\t" -P pager=off -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB"'
            engine_name = "PostgreSQL"
            execute = f"docker exec -i {shlex.quote(container)} sh -lc {shlex.quote(inner)} < {shlex.quote(remote_sql)}"
        else:
            container, image = local_target
            inner = 'client=$(command -v mysql || command -v mariadb); [ -n "$client" ] && MYSQL_PWD="$MYSQL_ROOT_PASSWORD" exec "$client" --batch --raw -uroot "$MYSQL_DATABASE"'
            engine_name = "MySQL/MariaDB"
            execute = f"docker exec -i {shlex.quote(container)} sh -lc {shlex.quote(inner)} < {shlex.quote(remote_sql)}"
        command = (
            f"timeout 20s sh -c {shlex.quote(execute)} > {shlex.quote(remote_out)} 2>&1; rc=$?; "
            f"head -c 100000 {shlex.quote(remote_out)}; rm -f {shlex.quote(remote_sql)} {shlex.quote(remote_sql + '.env')} {shlex.quote(remote_out)}; exit $rc"
        )
        code, output = ssh.run(command, timeout=30)
        if code:
            raise HTTPException(502, "数据库查询失败：" + output[-1200:])
    audit(db, user, "ai_query_database", "project", project.id, json.dumps({
        "engine": engine_name, "sha256": hashlib.sha256(sql.encode()).hexdigest(),
        "bytes": len(output.encode()), "sql": sql, "status": "success",
        "chat_session_id": session_id, "requested_via": "AI 对话",
    }, ensure_ascii=False))
    db.commit()
    lines = output.strip().splitlines()
    truncated = len(output.encode()) >= 100000 or len(lines) > 101
    visible = lines[:101]
    return {
        "engine": engine_name,
        "lines": visible,
        "row_count": max(0, len(visible) - 1),
        "column_count": len(visible[0].split("\t")) if visible else 0,
        "truncated": truncated,
    }


def _data_change_confirmation_token(project_id: str, sql: str) -> str:
    return hashlib.sha256(f"{project_id}\n{sql}\n{settings.app_secret}".encode()).hexdigest()


def _execute_project_data_change(project: Project, sql: str, db: Session, user: User, session_id: str | None = None) -> dict:
    if _sql_kind(sql) != "data_change":
        raise HTTPException(400, "该入口只允许单条 INSERT、UPDATE 或 DELETE 语句")
    deployment = db.scalar(select(Deployment).where(
        Deployment.project_id == project.id, Deployment.status == DeployStatus.success,
    ).order_by(desc(Deployment.created_at)))
    if not deployment:
        raise HTTPException(409, "项目当前没有运行中的数据库")
    node = db.get(Node, deployment.node_id)
    if not node:
        raise HTTPException(409, "项目服务器不存在")
    change_id = uuid.uuid4().hex
    remote_sql = f"/tmp/yunzhou-data-change-{change_id}.sql"
    remote_out = f"/tmp/yunzhou-data-change-{change_id}.out"
    with SSHNode(node) as ssh:
        local_target = _database_container(ssh, project, required=False)
        external = _external_mysql_config(project) if not local_target else None
        if not local_target and not external:
            raise HTTPException(409, "未找到可更新的项目数据库；请先在数据资源中配置连接")
        is_postgres = bool(local_target and "postgres" in local_target[1])
        wrapped = f"BEGIN;\n{sql.rstrip().rstrip(';')};\nCOMMIT;\n" if is_postgres else (
            f"START TRANSACTION;\n{sql.rstrip().rstrip(';')};\n"
            "SELECT ROW_COUNT() AS affected_rows;\nCOMMIT;\n"
        )
        sftp = ssh.client.open_sftp()
        try:
            with sftp.open(remote_sql, "w") as handle:
                handle.write(wrapped)
            sftp.chmod(remote_sql, 0o600)
            if external:
                with sftp.open(remote_sql + ".env", "w") as handle:
                    handle.write("MYSQL_PWD=" + external["password"] + "\n")
                sftp.chmod(remote_sql + ".env", 0o600)
        finally:
            sftp.close()
        if external:
            execute = (
                f"docker run --rm --network host --env-file {shlex.quote(remote_sql + '.env')} -i mysql:8.4 "
                f"mysql --batch --raw -h {shlex.quote(external['host'])} -P {shlex.quote(external['port'])} "
                f"-u {shlex.quote(external['username'])} {shlex.quote(external['database'])} < {shlex.quote(remote_sql)}"
            )
            engine_name = "MySQL（外接）"
        elif is_postgres:
            container = local_target[0]
            inner = 'exec psql -X -A -P pager=off -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB"'
            execute = f"docker exec -i {shlex.quote(container)} sh -lc {shlex.quote(inner)} < {shlex.quote(remote_sql)}"
            engine_name = "PostgreSQL"
        else:
            container = local_target[0]
            inner = 'client=$(command -v mysql || command -v mariadb); [ -n "$client" ] && MYSQL_PWD="$MYSQL_ROOT_PASSWORD" exec "$client" --batch --raw -uroot "$MYSQL_DATABASE"'
            execute = f"docker exec -i {shlex.quote(container)} sh -lc {shlex.quote(inner)} < {shlex.quote(remote_sql)}"
            engine_name = "MySQL/MariaDB"
        command = (
            f"timeout 30s sh -c {shlex.quote(execute)} > {shlex.quote(remote_out)} 2>&1; rc=$?; "
            f"tail -c 12000 {shlex.quote(remote_out)}; rm -f {shlex.quote(remote_sql)} {shlex.quote(remote_sql + '.env')} {shlex.quote(remote_out)}; exit $rc"
        )
        code, output = ssh.run(command, timeout=40)
        if code:
            raise HTTPException(502, "数据库数据变更失败，事务已回滚：" + output[-1200:])
    audit(db, user, "ai_update_database", "project", project.id, json.dumps({
        "engine": engine_name, "sha256": hashlib.sha256(sql.encode()).hexdigest(),
        "sql": sql, "status": "success", "result": output.strip()[-2000:],
        "chat_session_id": session_id, "requested_via": "AI 对话" if session_id else "SQL 控制台",
    }, ensure_ascii=False))
    db.commit()
    return {"engine": engine_name, "result": output.strip() or "执行成功"}


@app.post("/api/projects/{item_id}/sql-console")
def project_sql_console(
    item_id: str,
    body: SqlConsoleIn,
    db: Session = Depends(get_db),
    user: User = Depends(require(Role.admin, Role.deployer)),
):
    project = db.get(Project, item_id)
    if not project:
        raise HTTPException(404, "项目不存在")
    sql = body.sql.strip()
    kind = _sql_kind(sql)
    if kind == "query":
        result = _query_project_database(project, sql, db, user)
        lines = result["lines"]
        columns = lines[0].split("\t") if lines else []
        rows = [line.split("\t") for line in lines[1:]] if len(lines) > 1 else []
        return {"kind": "query", "engine": result["engine"], "columns": columns, "rows": rows,
                "row_count": result["row_count"], "truncated": result["truncated"]}
    if kind != "data_change":
        raise HTTPException(400, "SQL 控制台仅支持单条查询或 INSERT、UPDATE、DELETE；表结构请使用迁移流程")
    operation = sql.lstrip().split(None, 1)[0].upper()
    high_risk = bool(operation in {"UPDATE", "DELETE"} and not re.search(r"(?i)\bwhere\b", sql))
    token = _data_change_confirmation_token(project.id, sql)
    required_phrase = "确认执行高风险数据变更" if high_risk else "确认执行数据变更"
    if body.confirm_token != token or body.confirmation != required_phrase:
        return {"kind": "data_change", "requires_confirmation": True, "high_risk": high_risk,
                "operation": operation, "confirm_token": token, "confirmation_phrase": required_phrase,
                "digest": hashlib.sha256(sql.encode()).hexdigest()[:12]}
    try:
        result = _execute_project_data_change(project, sql, db, user)
    except HTTPException as exc:
        audit(db, user, "ai_update_database", "project", project.id, json.dumps({
            "status": "failed", "sql": sql, "sha256": hashlib.sha256(sql.encode()).hexdigest(),
            "error": str(exc.detail)[:1000], "requested_via": "SQL 控制台",
        }, ensure_ascii=False))
        db.commit()
        raise
    return {"kind": "data_change", "requires_confirmation": False, **result}


def _project_migration_plan(project: Project, db: Session) -> dict:
    """Return immutable SQL files from the latest online release.

    A migration is executable only while its path and SHA-256 still match this
    plan.  This prevents a confirmation for one revision from applying changed
    SQL from another revision.
    """
    deployment = db.scalar(
        select(Deployment).where(
            Deployment.project_id == project.id,
            Deployment.status == DeployStatus.success,
            Deployment.release.is_not(None),
        ).order_by(desc(Deployment.created_at))
    )
    if not deployment:
        raise HTTPException(409, "项目当前没有已上线版本，不能执行表结构迁移")
    node = db.get(Node, deployment.node_id)
    if not node:
        raise HTTPException(409, "上线版本对应的服务器不存在")
    release_dir = f"{node.work_dir.rstrip('/')}/{project_directory(project)}/{deployment.release}"
    legacy_dir = f"{node.work_dir.rstrip('/')}/{project.slug}/{deployment.release}"
    files: list[dict] = []
    with SSHNode(node) as ssh:
        _, resolved = ssh.run(
            f"if [ -d {shlex.quote(release_dir)} ]; then printf %s {shlex.quote(release_dir)}; "
            f"elif [ -d {shlex.quote(legacy_dir)} ]; then printf %s {shlex.quote(legacy_dir)}; fi"
        )
        actual = resolved.strip()
        if not actual:
            raise HTTPException(409, "当前上线版本的发布目录不存在，请先重新发布")
        code, listing = ssh.run(f"find {shlex.quote(actual)} -type f -iname '*.sql' -size -8M -print")
        if code:
            raise HTTPException(502, "读取线上版本的 SQL 文件失败")
        sftp = ssh.client.open_sftp()
        try:
            for remote_path in sorted(set(listing.splitlines()))[:200]:
                try:
                    content = sftp.open(remote_path).read(8_000_000)
                except Exception:
                    continue
                text_content = content.decode("utf-8", "ignore")
                relative = remote_path.removeprefix(actual.rstrip("/") + "/")
                danger = sorted(set(match.group(0).upper() for match in _MIGRATION_DANGER.finditer(text_content)))
                files.append({
                    "path": relative,
                    "remote_path": remote_path,
                    "sql": text_content,
                    "sha256": hashlib.sha256(content).hexdigest(),
                    "statements": max(1, text_content.count(";")),
                    "risk": "high" if danger else "low",
                    "risk_reasons": danger,
                })
        finally:
            sftp.close()
    applied: set[str] = set()
    logs = db.scalars(select(AuditLog).where(
        AuditLog.action == "ai_apply_migration", AuditLog.target_id == project.id,
    )).all()
    for row in logs:
        try:
            detail = json.loads(row.detail or "{}")
            if detail.get("status") == "success" and detail.get("sha256"):
                applied.add(str(detail["sha256"]))
        except (TypeError, ValueError):
            continue
    for item in files:
        item["applied"] = item["sha256"] in applied
    return {
        "project": project, "deployment": deployment, "node": node,
        "release_dir": actual, "files": files,
    }


def _execute_project_migrations(project: Project, expected: list[dict], db: Session, user: User, session_id: str | None = None) -> dict:
    lock = _migration_locks.setdefault(project.id, threading.Lock())
    if not lock.acquire(blocking=False):
        raise HTTPException(409, "该项目已有表结构迁移正在执行")
    try:
        plan = _project_migration_plan(project, db)
        current = {item["sha256"]: item for item in plan["files"] if not item["applied"]}
        selected: list[dict] = []
        for expected_item in expected:
            inline_sql = str(expected_item.get("sql") or "").strip()
            if inline_sql:
                digest = hashlib.sha256(inline_sql.encode()).hexdigest()
                if digest != expected_item.get("sha256") or _sql_kind(inline_sql) != "schema":
                    raise HTTPException(409, "直接 SQL 已变化或包含非表结构语句，请重新发起")
                item = {
                    "path": expected_item.get("path") or "AI 直接 SQL",
                    "remote_path": None, "sha256": digest, "sql": inline_sql,
                    "risk": expected_item.get("risk") or ("high" if _MIGRATION_DANGER.search(inline_sql) else "low"),
                }
            else:
                item = current.get(str(expected_item.get("sha256") or ""))
                if not item or item["path"] != expected_item.get("path"):
                    raise HTTPException(409, "迁移文件已变化或已执行，请让 AI 重新生成执行清单")
            selected.append(item)
        if not selected:
            raise HTTPException(409, "没有待执行的表结构迁移")
        node: Node = plan["node"]
        timestamp = datetime.now(ZoneInfo("Asia/Shanghai")).strftime("%Y%m%d%H%M%S")
        backup_dir = f"{plan['release_dir'].rstrip('/')}/.yunzhou/migration-backups"
        with SSHNode(node) as ssh:
            local_target = _database_container(ssh, project, required=False)
            external = _external_mysql_config(project) if not local_target else None
            if not local_target and not external:
                raise HTTPException(409, "未找到可迁移的项目数据库；请先在数据资源中配置连接")
            ssh.run(f"mkdir -p {shlex.quote(backup_dir)} && chmod 700 {shlex.quote(backup_dir)}")
            inline_dir = f"{plan['release_dir'].rstrip('/')}/.yunzhou/ai-migrations"
            inline_items = [item for item in selected if item.get("sql")]
            if inline_items:
                ssh.run(f"mkdir -p {shlex.quote(inline_dir)} && chmod 700 {shlex.quote(inline_dir)}")
                sftp = ssh.client.open_sftp()
                try:
                    for item in inline_items:
                        item["remote_path"] = f"{inline_dir}/{item['sha256'][:16]}.sql"
                        with sftp.open(item["remote_path"], "w") as handle:
                            handle.write(item["sql"].rstrip() + "\n")
                        sftp.chmod(item["remote_path"], 0o600)
                finally:
                    sftp.close()
            external_env = f"/tmp/yunzhou-migration-{project.id[:8]}.env"
            if external:
                sftp = ssh.client.open_sftp()
                try:
                    with sftp.open(external_env, "w") as handle:
                        handle.write("MYSQL_PWD=" + external["password"] + "\n")
                    sftp.chmod(external_env, 0o600)
                finally:
                    sftp.close()
                backup_file = f"{backup_dir}/{timestamp}-schema.sql"
                backup_cmd = (
                    f"docker run --rm --network host --env-file {shlex.quote(external_env)} mysql:8.4 "
                    f"mysqldump --no-data -h {shlex.quote(external['host'])} -P {shlex.quote(external['port'])} "
                    f"-u {shlex.quote(external['username'])} {shlex.quote(external['database'])} > {shlex.quote(backup_file)}"
                )
                apply_inner = None
                engine_name = "MySQL（外接）"
            elif "postgres" in local_target[1]:
                container, image = local_target
                backup_file = f"{backup_dir}/{timestamp}-schema.sql"
                backup_cmd = (
                    f"docker exec {shlex.quote(container)} sh -lc "
                    + shlex.quote('exec pg_dump --schema-only -U "$POSTGRES_USER" -d "$POSTGRES_DB"')
                    + f" > {shlex.quote(backup_file)}"
                )
                apply_inner = 'exec psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB"'
                engine_name = "PostgreSQL"
            else:
                container, image = local_target
                backup_file = f"{backup_dir}/{timestamp}-schema.sql"
                backup_cmd = (
                    f"docker exec {shlex.quote(container)} sh -lc "
                    + shlex.quote('dump=$(command -v mysqldump || command -v mariadb-dump); [ -n "$dump" ] && MYSQL_PWD="$MYSQL_ROOT_PASSWORD" exec "$dump" --no-data -uroot "$MYSQL_DATABASE"')
                    + f" > {shlex.quote(backup_file)}"
                )
                apply_inner = 'client=$(command -v mysql || command -v mariadb); [ -n "$client" ] && MYSQL_PWD="$MYSQL_ROOT_PASSWORD" exec "$client" -uroot "$MYSQL_DATABASE"'
                engine_name = "MySQL/MariaDB"
            code, output = ssh.run(backup_cmd, timeout=600)
            if code:
                if external:
                    ssh.run(f"rm -f {shlex.quote(external_env)}")
                raise HTTPException(502, "执行迁移前的表结构备份失败：" + output[-500:])
            completed = []
            for item in selected:
                if external:
                    command = (
                        f"docker run --rm --network host --env-file {shlex.quote(external_env)} -i mysql:8.4 "
                        f"mysql -h {shlex.quote(external['host'])} -P {shlex.quote(external['port'])} "
                        f"-u {shlex.quote(external['username'])} {shlex.quote(external['database'])} "
                        f"< {shlex.quote(item['remote_path'])}"
                    )
                else:
                    command = (
                        f"docker exec -i {shlex.quote(container)} sh -lc {shlex.quote(apply_inner)} "
                        f"< {shlex.quote(item['remote_path'])}"
                    )
                code, output = ssh.run(command, timeout=1800)
                detail = {
                    "status": "success" if code == 0 else "failed",
                    "path": item["path"], "sha256": item["sha256"],
                    "release": plan["deployment"].release, "engine": engine_name,
                    "backup": backup_file,
                    "sql": item.get("sql") or "",
                    "risk": item.get("risk") or "low",
                    "chat_session_id": session_id,
                    "requested_via": "AI 对话",
                }
                if code:
                    detail["error"] = output[-2000:]
                audit(db, user, "ai_apply_migration", "project", project.id, json.dumps(detail, ensure_ascii=False))
                db.commit()
                if code:
                    if external:
                        ssh.run(f"rm -f {shlex.quote(external_env)}")
                    raise HTTPException(502, f"迁移 {item['path']} 执行失败：" + output[-800:])
                completed.append(item["path"])
            if external:
                ssh.run(f"rm -f {shlex.quote(external_env)}")
        return {"files": completed, "backup": backup_file, "engine": engine_name}
    finally:
        lock.release()


@app.get("/api/deployments/{item_id}/ai-followup")
def deployment_ai_followup(item_id: str, db: Session = Depends(get_db), _: User = Depends(current_user)):
    item = db.get(Deployment, item_id)
    if not item:
        raise HTTPException(404, "部署不存在")
    view = deployment_view(item, db)
    steps = view.get("pipeline_steps", [])
    active = next((x for x in steps if x["status"] in ("running", "failed", "stopped")), None) or (steps[-1] if steps else {"title": view["current_step"], "log": ""})
    live = None
    if item.status in (DeployStatus.running, DeployStatus.success, DeployStatus.stopped):
        try:
            live = runtime_snapshot(item, db)
        except Exception:
            live = None
    live_states = ",".join(sorted(f"{x.get('name')}={x.get('status')}" for x in (live or {}).get("containers", [])))
    cache_key = f"{item.status.value}|{active['title']}|{item.access_url or '-'}|{live_states}"
    marker = "[AI跟进] "
    for line in reversed((item.log_text or "").splitlines()):
        if line.startswith(marker):
            try:
                cached = json.loads(line[len(marker):])
                if cached.get("cache_key") == cache_key and cached.get("source") == "ai":
                    return cached
            except Exception:
                pass
            break
    try:
        evidence = active.get("log", "") + ("\n[实时运行状态]\n" + json.dumps((live or {}).get("containers", []), ensure_ascii=False) if live is not None else "")
        result = deployment_followup(db, item, db.get(Project, item.project_id), db.get(Node, item.node_id), active["title"], evidence)
    except Exception as exc:
        lower = evidence.lower()
        if "jctree$jcimport" in lower and "qualid" in lower:
            summary = "已定位为 Java 编译环境不兼容：项目中的旧版编译器或注解处理器访问了 JDK 21 已变化的 javac 内部字段，sc-common 因此编译失败。"
            advice = "优先按项目原要求改用兼容的 JDK（常见为 8、11 或 17）；也可以升级 Lombok、Maven Compiler Plugin 等注解处理依赖后再用 JDK 21。平台仍会继续尝试调用 AI 给出项目化建议。"
        elif "non-resolvable" in lower or "could not resolve dependencies" in lower:
            summary = "构建失败在依赖解析阶段，Maven 未能取得项目所需依赖。"
            advice = "检查私有仓库凭据、镜像源和目标服务器网络；平台会继续调用 AI 分析具体依赖。"
        elif "compilation failure" in lower or "fatal error compiling" in lower:
            summary = "构建失败在源码编译阶段，已排除容器启动和端口问题。"
            advice = "需要根据最早的编译错误核对源码、JDK 与构建插件版本；平台会继续调用 AI 提炼具体修复项。"
        else:
            unresolved = re.search(r'Could not resolve\s+["\']([^"\']+)["\']\s+from\s+["\']([^"\']+)', evidence, re.I)
            if unresolved:
                summary = f"构建时无法解析模块 {unresolved.group(1)}，引用位置为 {unresolved.group(2)}。"
                advice = "平台将先核对生成的 Dockerfile 是否完整复制了跨目录依赖；若构建上下文完整，则归类为源码缺文件、路径或大小写问题，不会自动修改业务源码。"
            else:
                summary = f"正在重新分析“{active['title']}”阶段的异常。"
                advice = "AI 请求暂未完成，平台将在 15 秒后自动重试。"
        result = {"source": "system", "summary": summary, "advice": advice, "retryable": True, "retry_reason": str(exc)}
    result.update({"cache_key": cache_key, "stage": active["title"], "status": item.status.value, "generated_at": datetime.now(timezone.utc).isoformat()})
    if result.get("source") == "ai":
        item.log_text = ((item.log_text or "") + "\n" + marker + json.dumps(result, ensure_ascii=False) + "\n")[-200_000:]
        db.commit()
    return result


@app.get("/api/deployments/{item_id}/containers/{container_name}/logs")
def container_logs(item_id: str, container_name: str, since: str | None = None, db: Session = Depends(get_db), _: User = Depends(current_user)):
    _, node = _container_access(item_id, container_name, db)
    since_option = f" --since {shlex.quote(since[:64])}" if since else ""
    code, output = _container_browser_run(node, f"docker logs --tail 300{since_option} {shlex.quote(container_name)} 2>&1", timeout=30)
    if code:
        raise HTTPException(502, output)
    return {"container": container_name, "logs": output}


def _container_access(item_id: str, container_name: str, db: Session) -> tuple[Deployment, Node]:
    item = db.get(Deployment, item_id)
    if not item:
        raise HTTPException(404, "部署不存在")
    project = db.get(Project, item.project_id)
    if not project:
        raise HTTPException(404, "项目不存在")
    latest_success = db.scalar(select(Deployment).where(
        Deployment.project_id == item.project_id,
        Deployment.status == DeployStatus.success,
    ).order_by(desc(Deployment.created_at)).limit(1))
    owns_live_runtime = (
        item.status == DeployStatus.running
        or (item.status == DeployStatus.success and latest_success is not None and latest_success.id == item.id)
    )
    if not owns_live_runtime:
        raise HTTPException(409, "历史发布记录不能操作当前运行容器")
    replica_names = set(db.scalars(select(ProjectReplica.container_name).where(ProjectReplica.deployment_id == item.id)).all())
    compose_prefix = f"yz-{project.slug}-"
    allowed = (
        container_name == (item.container_name or "")
        or container_name in replica_names
        or container_name.startswith(compose_prefix)
    )
    if not allowed:
        raise HTTPException(404, "容器不存在或已停止")
    node = db.get(Node, item.node_id)
    if not node:
        raise HTTPException(404, "服务器节点不存在")
    return item, node


def _container_path(value: str | None) -> str:
    raw = str(value or "/").strip() or "/"
    path = PurePosixPath(raw if raw.startswith("/") else "/" + raw)
    if ".." in path.parts or "\x00" in raw:
        raise HTTPException(400, "容器路径不合法")
    return str(path)


_container_browser_clients: dict[str, SSHNode] = {}
_container_browser_locks: dict[str, threading.Lock] = {}
_container_browser_guard = threading.Lock()


def _container_browser_run(node: Node, command: str, timeout: int = 30) -> tuple[int, str]:
    """Reuse one SSH transport per node for responsive directory browsing."""
    key = str(node.id)
    with _container_browser_guard:
        lock = _container_browser_locks.setdefault(key, threading.Lock())
    with lock:
        ssh = _container_browser_clients.get(key)
        transport = ssh.client.get_transport() if ssh else None
        if not transport or not transport.is_active():
            if ssh:
                ssh.client.close()
            ssh = SSHNode(node)
            ssh.__enter__()
            transport = ssh.client.get_transport()
            if transport:
                transport.set_keepalive(30)
            _container_browser_clients[key] = ssh
        try:
            return ssh.run(command, timeout=timeout)
        except Exception:
            ssh.client.close()
            _container_browser_clients.pop(key, None)
            ssh = SSHNode(node)
            ssh.__enter__()
            transport = ssh.client.get_transport()
            if transport:
                transport.set_keepalive(30)
            _container_browser_clients[key] = ssh
            return ssh.run(command, timeout=timeout)


@app.get("/api/deployments/{item_id}/containers/{container_name}/files")
def container_files(item_id: str, container_name: str, path: str = "/", db: Session = Depends(get_db), _: User = Depends(require(Role.admin, Role.deployer))):
    _, node = _container_access(item_id, container_name, db)
    target = _container_path(path)
    # Keep this compatible with BusyBox/Alpine containers: only POSIX shell,
    # find and stat are used, with one entry per line and a bounded result.
    script = (
        "p=$1; [ -e \"$p\" ] || exit 41; [ -d \"$p\" ] || exit 42; command -v find >/dev/null 2>&1 || exit 43; "
        "find \"$p\" -mindepth 1 -maxdepth 1 -print 2>/dev/null | head -200 | "
        "while IFS= read -r f; do "
        "if [ -d \"$f\" ]; then t=d; s=0; else t=f; s=$(stat -c %s \"$f\" 2>/dev/null || echo 0); fi; "
        "m=$(stat -c %Y \"$f\" 2>/dev/null || echo 0); "
        "o=$(stat -c %U \"$f\" 2>/dev/null || stat -c %u \"$f\" 2>/dev/null || echo -); "
        "printf '%s\\t%s\\t%s\\t%s\\t%s\\n' \"$t\" \"$s\" \"$m\" \"$o\" \"$f\"; done"
    )
    command = (
        f"docker exec {shlex.quote(container_name)} sh -lc "
        f"{shlex.quote(script)} sh {shlex.quote(target)}"
    )
    code, output = _container_browser_run(node, command, timeout=30)
    if code:
        if code == 41:
            raise HTTPException(404, f"目录不存在：{target}")
        if code == 42:
            raise HTTPException(400, f"不是目录，不能进入：{target}")
        if code == 43:
            raise HTTPException(409, "当前容器缺少 find 命令，无法浏览目录")
        raise HTTPException(502, "目录读取失败，当前容器可能没有可用的 shell")
    entries = []
    for line in output.splitlines():
        parts = line.split("\t", 4)
        if len(parts) != 5:
            continue
        kind, size, modified, owner, full_path = parts
        name = PurePosixPath(full_path).name
        entries.append({
            "name": name, "path": full_path, "type": "directory" if kind == "d" else "file",
            "size": int(size) if size.isdigit() else 0,
            "modified": int(modified) if modified.isdigit() else 0,
            "owner": owner or "-",
        })
    entries.sort(key=lambda row: (row["type"] != "directory", row["name"].lower()))
    return {"container": container_name, "path": target, "entries": entries, "truncated": len(entries) >= 200}


@app.get("/api/deployments/{item_id}/containers/{container_name}/files/download")
def download_container_file(item_id: str, container_name: str, background_tasks: BackgroundTasks, path: str, archive: bool = False, db: Session = Depends(get_db), _: User = Depends(require(Role.admin, Role.deployer))):
    _, node = _container_access(item_id, container_name, db)
    target = _container_path(path)
    token = uuid.uuid4().hex
    remote_copy = f"/tmp/yunzhou-download-{token}"
    remote_archive = f"/tmp/yunzhou-download-{token}.tar.gz"
    local_dir = Path(tempfile.mkdtemp(prefix="yunzhou-container-download-"))
    name = PurePosixPath(target).name or "root"
    with SSHNode(node) as ssh:
        code, output = ssh.run(
            f"rm -rf {shlex.quote(remote_copy)} {shlex.quote(remote_archive)}; "
            f"docker cp {shlex.quote(container_name + ':' + target)} {shlex.quote(remote_copy)}",
            timeout=120,
        )
        if code:
            shutil.rmtree(local_dir, ignore_errors=True)
            raise HTTPException(502, "容器文件复制失败：" + output[-500:])
        type_code, _ = ssh.run(f"test -d {shlex.quote(remote_copy)}")
        should_archive = type_code == 0 or archive
        if should_archive:
            code, output = ssh.run(
                f"tar -czf {shlex.quote(remote_archive)} -C {shlex.quote(str(PurePosixPath(remote_copy).parent))} {shlex.quote(PurePosixPath(remote_copy).name)}",
                timeout=120,
            )
        else:
            code, output = ssh.run(f"cp {shlex.quote(remote_copy)} {shlex.quote(remote_archive)}", timeout=120)
        if code:
            ssh.run(f"rm -rf {shlex.quote(remote_copy)} {shlex.quote(remote_archive)}")
            shutil.rmtree(local_dir, ignore_errors=True)
            raise HTTPException(502, "容器文件打包失败：" + output[-500:])
        filename = (name + ".tar.gz") if should_archive else name
        local_file = local_dir / filename
        ssh.download_file(remote_archive, str(local_file))
        ssh.run(f"rm -rf {shlex.quote(remote_copy)} {shlex.quote(remote_archive)}")
    background_tasks.add_task(shutil.rmtree, local_dir, True)
    return FileResponse(local_file, filename=filename, media_type="application/gzip" if filename.endswith(".tar.gz") else "application/octet-stream")


@app.post("/api/deployments/{item_id}/containers/{container_name}/files/upload")
async def upload_container_files(item_id: str, container_name: str, path: str = Form("/"), overwrite: bool = Form(False), files: list[UploadFile] = File(...), db: Session = Depends(get_db), user: User = Depends(require(Role.admin, Role.deployer))):
    item, node = _container_access(item_id, container_name, db)
    target_dir = _container_path(path)
    if not files:
        raise HTTPException(400, "请选择要上传的文件")
    uploaded = []
    local_dir = Path(tempfile.mkdtemp(prefix="yunzhou-container-upload-"))
    try:
        with SSHNode(node) as ssh:
            code, _ = ssh.run(f"docker exec {shlex.quote(container_name)} test -d {shlex.quote(target_dir)}")
            if code:
                raise HTTPException(400, "目标目录不存在")
            for upload in files:
                name = PurePosixPath(str(upload.filename or "")).name
                if not name or name in {".", ".."}:
                    raise HTTPException(400, "文件名无效")
                target = str(PurePosixPath(target_dir) / name)
                exists_code, _ = ssh.run(f"docker exec {shlex.quote(container_name)} test -e {shlex.quote(target)}")
                if exists_code == 0 and not overwrite:
                    raise HTTPException(409, f"{name} 已存在，请确认覆盖")
                local_file = local_dir / name
                with local_file.open("wb") as handle:
                    shutil.copyfileobj(upload.file, handle)
                remote_file = f"/tmp/yunzhou-upload-{uuid.uuid4().hex}-{name}"
                ssh.upload_file(str(local_file), remote_file)
                code, output = ssh.run(
                    f"docker cp {shlex.quote(remote_file)} {shlex.quote(container_name + ':' + target)}; rm -f {shlex.quote(remote_file)}",
                    timeout=120,
                )
                if code:
                    raise HTTPException(502, f"{name} 上传失败：" + output[-300:])
                uploaded.append(name)
    finally:
        shutil.rmtree(local_dir, ignore_errors=True)
    audit(db, user, "container_file_upload", "deployment", item.id, f"container={container_name}; path={target_dir}; files={','.join(uploaded)[:500]}; overwrite={overwrite}")
    db.commit()
    return {"message": f"已上传 {len(uploaded)} 个文件", "files": uploaded, "path": target_dir}


@app.delete("/api/deployments/{item_id}/containers/{container_name}/files")
def delete_container_file(item_id: str, container_name: str, path: str, db: Session = Depends(get_db), user: User = Depends(require(Role.admin, Role.deployer))):
    item, node = _container_access(item_id, container_name, db)
    target = _container_path(path)
    if target == "/":
        raise HTTPException(400, "不能删除容器根目录")
    script = 'p=$1; [ -e "$p" ] || [ -L "$p" ] || exit 44; rm -rf -- "$p"'
    command = (
        f"docker exec {shlex.quote(container_name)} sh -lc "
        f"{shlex.quote(script)} sh {shlex.quote(target)}"
    )
    code, output = _container_browser_run(node, command, timeout=120)
    if code == 44:
        raise HTTPException(404, "文件或文件夹不存在")
    if code:
        raise HTTPException(502, "删除失败：" + output[-500:])
    audit(db, user, "container_file_delete", "deployment", item.id, f"container={container_name}; path={target}")
    db.commit()
    return {"message": f"已删除 {PurePosixPath(target).name}", "path": target}


@app.post("/api/deployments/{item_id}/containers/{container_name}/terminal")
def container_terminal(item_id: str, container_name: str, payload: dict, db: Session = Depends(get_db), user: User = Depends(require(Role.admin, Role.deployer))):
    item, node = _container_access(item_id, container_name, db)
    command = str(payload.get("command") or "").strip()
    cwd = _container_path(payload.get("cwd") or "/")
    if not command or len(command) > 2000 or "\x00" in command:
        raise HTTPException(400, "请输入有效命令（最多 2000 个字符）")
    terminal_script = 'cd "$1" 2>/dev/null || exit 42; eval "$2"'
    shell = (
        f"docker exec {shlex.quote(container_name)} sh -lc "
        f"{shlex.quote(terminal_script)} sh {shlex.quote(cwd)} {shlex.quote(command)}"
    )
    with SSHNode(node) as ssh:
        code, output = ssh.run(shell, timeout=60)
    audit_command = command[:300]
    audit_command = re.sub(r"(?i)(--?(?:password|passwd|token|secret|api[-_]?key)(?:=|\s+))\S+", r"\1<redacted>", audit_command)
    audit_command = re.sub(r"(?i)(\b[A-Z0-9_]*(?:PASSWORD|TOKEN|SECRET|API_KEY)\s*=)\S+", r"\1<redacted>", audit_command)
    audit_command = re.sub(r"(?i)(\b(?:mysql|mariadb)\b[^\n]*?\s-p)\S+", r"\1<redacted>", audit_command)
    audit_command = re.sub(r"(?i)(https?://[^:/\s]+:)[^@/\s]+@", r"\1<redacted>@", audit_command)
    audit(db, user, "container_terminal", "deployment", item.id, f"container={container_name}; cwd={cwd}; command={audit_command}")
    db.commit()
    return {"container": container_name, "cwd": cwd, "command": command, "exit_code": code, "output": output[-100_000:]}


@app.websocket("/api/deployments/{item_id}/containers/{container_name}/terminal/ws")
async def container_terminal_websocket(websocket: WebSocket, item_id: str, container_name: str):
    """Keep one SSH/docker-exec shell alive for responsive terminal input."""
    protocols = [value.strip() for value in (websocket.headers.get("sec-websocket-protocol") or "").split(",")]
    token_value = next((value.removeprefix("bearer.") for value in protocols if value.startswith("bearer.")), "")
    db = SessionLocal()
    user = None
    channel = None
    try:
        try:
            payload = jwt.decode(token_value, settings.app_secret, algorithms=["HS256"])
            user = db.get(User, payload.get("sub"))
            issued_at = payload.get("iat")
            changed_at = user.password_changed_at if user else None
            if user and issued_at and changed_at:
                changed_at = changed_at if changed_at.tzinfo else changed_at.replace(tzinfo=timezone.utc)
                if datetime.fromtimestamp(int(issued_at), timezone.utc) < changed_at.replace(microsecond=0):
                    user = None
        except (JWTError, TypeError):
            user = None
        if not user or not user.active or user.role not in {Role.admin, Role.deployer}:
            await websocket.close(code=4401)
            return
        item, node = _container_access(item_id, container_name, db)
        cwd = _container_path(websocket.query_params.get("cwd") or "/")
        await websocket.accept(subprotocol="yunzhou-terminal")
        with SSHNode(node) as ssh:
            transport = ssh.client.get_transport()
            if not transport:
                raise RuntimeError("SSH 会话不可用")
            channel = transport.open_session(timeout=15)
            channel.get_pty(term="xterm-256color", width=160, height=40)
            shell = (
                f"docker exec -it {shlex.quote(container_name)} sh -lc "
                + shlex.quote(f"cd {shlex.quote(cwd)} 2>/dev/null || cd /; exec sh -i")
            )
            channel.exec_command(shell)
            await websocket.send_text("\r\n[终端已连接]\r\n")
            while not channel.exit_status_ready():
                while channel.recv_ready():
                    await websocket.send_text(channel.recv(8192).decode(errors="replace"))
                try:
                    message = await asyncio.wait_for(websocket.receive_text(), timeout=0.03)
                    if len(message) > 16_384 or "\x00" in message:
                        await websocket.send_text("\r\n[输入被拒绝]\r\n")
                    else:
                        channel.send(message)
                except asyncio.TimeoutError:
                    pass
                await asyncio.sleep(0.01)
        audit(db, user, "container_terminal_session", "deployment", item.id, f"container={container_name}")
        db.commit()
    except WebSocketDisconnect:
        pass
    except Exception as exc:
        try:
            await websocket.send_text(f"\r\n[终端连接失败] {exc}\r\n")
        except Exception:
            pass
    finally:
        if channel is not None:
            channel.close()
        db.close()


@app.post("/api/deployments/{item_id}/stop")
def stop(item_id: str, db: Session = Depends(get_db), user: User = Depends(require(Role.admin, Role.deployer))):
    item = db.get(Deployment, item_id)
    if not item:
        raise HTTPException(404, "部署不存在")
    previous = item.status
    item.log_text = (item.log_text or "") + "\n[停止] 已收到请求，正在终止部署进程和容器...\n"
    # Publish the cancellation before touching the remote host.  Local work
    # such as AI analysis has no remote PID; it observes this state at its next
    # checkpoint and exits without continuing the release.
    item.status = DeployStatus.stopped
    item.finished_at = datetime.now(timezone.utc)
    audit(db, user, "stop", "deployment", item.id)
    db.commit()
    try:
        newer_replacement = db.scalar(
            select(Deployment).where(
                Deployment.project_id == item.project_id,
                Deployment.node_id == item.node_id,
                Deployment.id != item.id,
                Deployment.created_at > item.created_at,
                Deployment.status.in_([DeployStatus.queued, DeployStatus.running, DeployStatus.success]),
            ).order_by(Deployment.created_at.desc())
        )
        # While cancelling an unfinished duplicate release, an older successful
        # release is the current production runtime and must not be mistaken for
        # a container created by the task being cancelled.
        existing_runtime = None
        if previous in (DeployStatus.queued, DeployStatus.running):
            existing_runtime = db.scalar(
                select(Deployment).where(
                    Deployment.project_id == item.project_id,
                    Deployment.node_id == item.node_id,
                    Deployment.id != item.id,
                    Deployment.status == DeployStatus.success,
                ).order_by(Deployment.created_at.desc())
            )
        protected_runtime = newer_replacement or existing_runtime
        builder_node = platform_gateway_node(db)
        if builder_node:
            with SSHNode(builder_node) as builder_ssh:
                builder_ssh.run(
                    "ids=$(docker ps -aq --filter label=yunzhou.deployment="
                    + shlex.quote(item.id)
                    + "); [ -z \"$ids\" ] || docker rm -f $ids >/dev/null",
                    timeout=30,
                )
        removed_replica_names = set()
        if not protected_runtime:
            node = db.get(Node, item.node_id)
            replicas = db.scalars(select(ProjectReplica).where(
                ProjectReplica.project_id == item.project_id,
                ProjectReplica.deployment_id == item.id,
            )).all()
            removed_replica_names = {replica.container_name for replica in replicas}
            if node:
                with SSHNode(node) as ssh:
                    _, discovered = ssh.run(
                        f"docker ps -a --filter {shlex.quote('name=^/yz-' + db.get(Project, item.project_id).slug + '-replica-')} "
                        "--format '{{.Names}}'"
                    )
                    removed_replica_names.update(name.strip() for name in discovered.splitlines() if name.strip())
                    for name in removed_replica_names:
                        ssh.run(f"docker rm -f {shlex.quote(name)} >/dev/null 2>&1 || true")
                    for replica in replicas:
                        db.delete(replica)
            db.flush()
        output = stop_deployment(item, db.get(Project, item.project_id), db.get(Node, item.node_id), preserve_runtime=bool(protected_runtime))
        if not protected_runtime:
            output += f"；已停止并清理 {len(removed_replica_names)} 个应用副本，固定 Service 配置已保留"
    except Exception as exc:
        item = db.get(Deployment, item_id)
        item.log_text = (item.log_text or "") + f"[停止失败] {exc}\n"
        item.error = f"停止失败：{exc}"
        db.commit()
        raise HTTPException(502, item.error)
    item = db.get(Deployment, item_id)
    item.status = DeployStatus.stopped
    item.finished_at = datetime.now(timezone.utc)
    item.error = None
    item.log_text = (item.log_text or "") + f"[停止确认] {output}\n"
    db.commit()
    return {"ok": True, "verified": True, "output": output}


@app.post("/api/deployments/{item_id}/retry", response_model=DeploymentOut)
def retry_deployment(item_id: str, db: Session = Depends(get_db), user: User = Depends(require(Role.admin, Role.deployer))):
    previous = db.get(Deployment, item_id)
    if not previous:
        raise HTTPException(404, "部署不存在")
    if previous.status not in (DeployStatus.stopped, DeployStatus.failed):
        raise HTTPException(409, "只有已停止或失败的部署可以继续")
    project, node = db.get(Project, previous.project_id), db.get(Node, previous.node_id)
    if not project or not node:
        raise HTTPException(404, "项目或节点不存在")
    require_reachable_node(node, db)
    active = db.scalar(
        select(Deployment).where(
            Deployment.project_id == project.id,
            Deployment.node_id == node.id,
            Deployment.status.in_([DeployStatus.queued, DeployStatus.running]),
        ).order_by(Deployment.created_at.desc())
    )
    if active:
        raise HTTPException(409, f"该项目在此服务器已有进行中的部署任务（{active.id[:8]}），请等待完成或先停止该任务")
    plan = make_deployment_plan(project, node, db)
    item = Deployment(project_id=project.id, node_id=node.id, requested_by=user.id, status=DeployStatus.queued, trigger="retry", host_port=plan["host_port"], log_text=plan_log(plan) + f"[继续] 从任务 {previous.id[:8]} 重新安全执行\n")
    db.add(item)
    db.flush()
    audit(db, user, "retry_deployment", "deployment", item.id, f"from={previous.id}")
    db.commit()
    db.refresh(item)
    return item


@app.get("/api/deployments/{item_id}/delete-preview")
def deployment_delete_preview(item_id: str, db: Session = Depends(get_db), _: User = Depends(current_user)):
    item = db.get(Deployment, item_id)
    if not item:
        raise HTTPException(404, "部署记录不存在")
    project, node = db.get(Project, item.project_id), db.get(Node, item.node_id)
    if not project or not node:
        raise HTTPException(409, "项目或部署服务器已不存在，无法核实资源")
    resources = {"containers": [], "images": [], "directories": [], "gateway_files": [], "records": []}
    warnings = []
    release_dirs = list(dict.fromkeys([
        f"{node.work_dir.rstrip('/')}/{project_directory(project)}/{item.release}",
        f"{node.work_dir.rstrip('/')}/{project.slug}/{item.release}",
    ])) if item.release else []
    def scan_images(scan_node: Node):
        with SSHNode(scan_node) as ssh:
            # Compose releases contain several images and older failed records
            # did not persist every image name.  Inspect the actual daemon by
            # release/project identity instead of trusting only the DB column.
            # Both conditions must match.  The previous grep used OR and made
            # every historical record claim all current project images.
            _, value = ssh.run(
                "docker images --no-trunc --format '{{.Repository}}:{{.Tag}}'",
                timeout=30,
            )
            for name in filter(None, map(str.strip, value.splitlines())):
                if ":" not in name:
                    continue
                repository, tag = name.rsplit(":", 1)
                repository_name = repository.rsplit("/", 1)[-1]
                project_match = repository_name == project.slug or repository_name.startswith(project.slug + "-")
                release_match = bool(item.release) and tag == item.release
                if not (project_match and release_match):
                    continue
                entry = {"name": name, "node": scan_node.name}
                if entry not in resources["images"]:
                    resources["images"].append(entry)

    try:
        with SSHNode(node) as ssh:
            if item.container_name:
                _, value = ssh.run(f"docker inspect {shlex.quote(item.container_name)} >/dev/null 2>&1 && printf '%s' {shlex.quote(item.container_name)} || true", timeout=20)
                if value.strip():
                    resources["containers"].append({"name": value.strip(), "node": node.name})
            if item.release:
                _, value = ssh.run(
                    "docker ps -a --filter " + shlex.quote(f"label=com.docker.compose.project=yz-{project.slug}") +
                    " --format '{{.Names}}|{{.Label \"com.docker.compose.project.config_files\"}}' | "
                    f"awk -F'|' -v r={shlex.quote('/' + item.release + '/')} 'index($2,r) {{print $1}}'",
                    timeout=20,
                )
                for name in filter(None, map(str.strip, value.splitlines())):
                    entry = {"name": name, "node": node.name}
                    if entry not in resources["containers"]:
                        resources["containers"].append(entry)
            if item.image_name:
                _, value = ssh.run(f"docker image inspect {shlex.quote(item.image_name)} >/dev/null 2>&1 && printf '%s' {shlex.quote(item.image_name)} || true", timeout=20)
                if value.strip():
                    resources["images"].append({"name": value.strip(), "node": node.name})
            else:
                _, value = ssh.run("docker images --format '{{.Repository}}:{{.Tag}}' --filter " + shlex.quote(f"label=com.docker.compose.project=yz-{project.slug}"), timeout=20)
                resources["images"].extend({"name": name, "node": node.name} for name in filter(None, map(str.strip, value.splitlines())))
            for path in release_dirs:
                _, value = ssh.run(f"test -e {shlex.quote(path)} && printf '%s' {shlex.quote(path)} || true", timeout=20)
                if value.strip():
                    resources["directories"].append({"path": value.strip(), "node": node.name})
        scan_images(node)
    except Exception as exc:
        warnings.append(f"{node.name} 资源查询失败：{exc}")
    gateway = platform_gateway_node(db)
    if gateway:
        candidates = [f"/data/yunzhou-control/data/gateway/conf.d/{item.id}.conf", f"/data/yunzhou-control/data/gateway/certs/{item.id}.crt", f"/data/yunzhou-control/data/gateway/certs/{item.id}.key"]
        try:
            with SSHNode(gateway) as ssh:
                checks = "; ".join(f"test -e {shlex.quote(path)} && printf '%s\\n' {shlex.quote(path)} || true" for path in candidates)
                _, existing = ssh.run(checks, timeout=20)
                resources["gateway_files"] = list(filter(None, map(str.strip, existing.splitlines())))
        except Exception as exc:
            warnings.append(f"平台网关查询失败：{exc}")
        if gateway.id != node.id:
            try:
                scan_images(gateway)
            except Exception as exc:
                warnings.append(f"平台构建镜像查询失败：{exc}")
    resources["records"].append({"name": f"发布记录、流水线日志 · {item.release or item.id[:8]}"})
    inventory = {
        "project": project.name,
        "release": item.release,
        "node": node.name,
        "resources": resources,
        "counts": {key: len(value) for key, value in resources.items()},
        "preserved": ["数据库、Redis 等持久化数据", "项目配置与上传源码", "其他发布版本"],
    }
    analysis = analyze_delete_scope(db, inventory)
    return {**inventory, "warnings": warnings, "ai": analysis, "ai_summary": analysis["summary"]}


@app.delete("/api/deployments/{item_id}")
def delete_deployment(item_id: str, remove_data: bool = False, db: Session = Depends(get_db), user: User = Depends(require(Role.admin, Role.deployer))):
    item = db.get(Deployment, item_id)
    if not item:
        raise HTTPException(404, "部署记录不存在")
    if item.status in (DeployStatus.queued, DeployStatus.running):
        raise HTTPException(409, "部署任务仍在执行，请先停止并确认无残留后再删除")
    if item.status == DeployStatus.success:
        raise HTTPException(409, "服务仍在运行，请先停止服务并确认无残留后再删除")
    project, node = db.get(Project, item.project_id), db.get(Node, item.node_id)
    other_count = db.scalar(
        select(func.count()).select_from(Deployment).where(
            Deployment.project_id == item.project_id,
            Deployment.node_id == item.node_id,
            Deployment.id != item.id,
        )
    ) or 0
    if remove_data and other_count:
        raise HTTPException(409, "同一项目在这台服务器还有其他发布版本，为避免误删共享数据，不能删除持久化卷")
    pending_replacement = db.scalar(
        select(Deployment).where(
            Deployment.project_id == item.project_id,
            Deployment.node_id == item.node_id,
            Deployment.id != item.id,
            Deployment.created_at > item.created_at,
            Deployment.status.in_([DeployStatus.queued, DeployStatus.running]),
        ).order_by(Deployment.created_at.desc())
    )
    if pending_replacement:
        raise HTTPException(409, f"新版本 {pending_replacement.id[:8]} 仍在部署中，旧版本可能还在提供服务；请等待新版本完成后再删除")
    replacement = db.scalar(
        select(Deployment).where(
            Deployment.project_id == item.project_id,
            Deployment.node_id == item.node_id,
            Deployment.id != item.id,
            Deployment.created_at > item.created_at,
            Deployment.status == DeployStatus.success,
        ).order_by(Deployment.created_at.desc())
    )
    try:
        # Remove replica containers before their rows are cascaded with the
        # deployment record.  Otherwise they become invisible to the platform
        # while continuing to occupy ports on the node.
        deployment_replicas = db.scalars(select(ProjectReplica).where(
            ProjectReplica.deployment_id == item.id,
        )).all()
        if node and deployment_replicas:
            with SSHNode(node) as replica_ssh:
                for replica in deployment_replicas:
                    replica_ssh.run(
                        f"docker rm -f {shlex.quote(replica.container_name)} >/dev/null 2>&1 || true"
                    )
                    db.delete(replica)
            db.flush()
        cleanup = delete_deployment_resources(
            item,
            project,
            node,
            remove_compose_images=other_count == 0,
            remove_persistent_data=remove_data,
            preserve_runtime=bool(replacement),
        )
        gateway = platform_gateway_node(db)
        if gateway:
            deployment_id = shlex.quote(item.id)
            project_service = shlex.quote(f"project-{item.project_id}")
            with SSHNode(gateway) as ssh:
                code, output = ssh.run(
                    f"rm -f -- /data/yunzhou-control/data/gateway/conf.d/{deployment_id}.conf "
                    f"/data/yunzhou-control/data/gateway/certs/{deployment_id}.crt "
                    f"/data/yunzhou-control/data/gateway/certs/{deployment_id}.key "
                    f"/data/yunzhou-control/data/gateway/conf.d/{project_service}.conf; "
                    "docker exec yunzhou-platform-gateway nginx -t >/dev/null 2>&1 && "
                    "docker exec yunzhou-platform-gateway nginx -s reload >/dev/null 2>&1 || true",
                    timeout=30,
                )
                if code:
                    raise RuntimeError(output or "平台网关文件清理失败")
            cleanup += "；该发布版本的 Nginx 配置与证书文件已清理"
    except Exception as exc:
        raise HTTPException(502, f"部署记录未删除：{exc}")
    audit(db, user, "delete_deployment", "deployment", item.id, json.dumps({
        "project": project.name if project else item.project_id,
        "release": item.release,
        "node": node.name if node else item.node_id,
        "status_before_delete": item.status.value,
        "persistent_data": "deleted" if remove_data else "preserved",
        "cleanup": cleanup,
    }, ensure_ascii=False))
    db.delete(item)
    db.commit()
    return {"ok": True, "cleanup": cleanup}


@app.post("/api/deployments/{item_id}/start")
def start_stopped_deployment(item_id: str, db: Session = Depends(get_db), user: User = Depends(require(Role.admin, Role.deployer))):
    item = db.get(Deployment, item_id)
    if not item:
        raise HTTPException(404, "部署不存在")
    if item.status != DeployStatus.stopped:
        raise HTTPException(409, "只有已停止的服务可以重新启用")
    item.log_text = (item.log_text or "") + "\n[启用] 正在重新启动原发布版本...\n"
    db.commit()
    try:
        output = start_deployment(item, db.get(Project, item.project_id), db.get(Node, item.node_id), db)
    except Exception as exc:
        item = db.get(Deployment, item_id)
        item.error = f"启用失败：{exc}"
        if "原发布目录不存在" in str(exc):
            # Keep the historical version number, but revoke the stale launch
            # entry so project cards offer a clean redeploy instead.
            item.access_url = None
        item.log_text = (item.log_text or "") + f"[启用失败] {exc}\n"
        db.commit()
        raise HTTPException(502, item.error)
    item = db.get(Deployment, item_id)
    item.status = DeployStatus.success
    item.error = None
    item.finished_at = datetime.now(timezone.utc)
    item.log_text = (item.log_text or "") + f"[启用确认] {output}\n"
    audit(db, user, "start", "deployment", item.id)
    db.commit()
    project = db.get(Project, item.project_id)
    scaled = scale_project(item.project_id, ScaleProjectIn(replicas=1), db, user)
    output += f"；项目 Service 已恢复，应用实例就绪 {scaled['ready']}/{scaled['desired']}"
    return {"ok": True, "verified": True, "output": output}


@app.post("/api/deployments/{item_id}/rollback")
def rollback_deployment(item_id: str, db: Session = Depends(get_db), user: User = Depends(require(Role.admin, Role.deployer))):
    """Switch a project back to a previously verified release without rebuilding it."""
    target = db.get(Deployment, item_id)
    if not target:
        raise HTTPException(404, "发布版本不存在")
    verified_markers = ("[完成] 部署成功", "[启用确认]", "[回滚完成]")
    was_verified = any(marker in (target.log_text or "") for marker in verified_markers)
    if target.status != DeployStatus.stopped or not target.release or not target.access_url or not was_verified:
        raise HTTPException(409, "只有曾经成功上线并通过访问验证的历史版本可以回滚；失败或构建中途停止的版本不能回滚")
    project, node = db.get(Project, target.project_id), db.get(Node, target.node_id)
    if not project or not node:
        raise HTTPException(404, "项目或部署服务器不存在")
    active_task = db.scalar(select(Deployment).where(
        Deployment.project_id == project.id,
        Deployment.node_id == node.id,
        Deployment.status.in_([DeployStatus.queued, DeployStatus.running]),
    ))
    if active_task:
        raise HTTPException(409, "当前有发布任务正在执行，请完成或停止后再回滚")
    current = db.scalar(select(Deployment).where(
        Deployment.project_id == project.id,
        Deployment.node_id == node.id,
        Deployment.id != target.id,
        Deployment.status == DeployStatus.success,
    ).order_by(Deployment.created_at.desc()))
    if not current:
        raise HTTPException(409, "当前没有可保护的线上版本；请使用“重新启用”而不是回滚")

    # `start_deployment` uses the ordinary deployment cancellation guard.
    # Historical releases are normally stored as `stopped`, so mark the
    # selected release as active before launching it; otherwise the guard
    # mistakes a valid rollback for a user-cancelled build.
    target.status = DeployStatus.running
    target.started_at = datetime.now(timezone.utc)
    target.finished_at = None
    target.error = None
    target.log_text = ((target.log_text or "") + f"\n[回滚开始] 正在从版本 {current.release or current.id[:8]} 切换到 {target.release}，不重新构建镜像。\n")[-200_000:]
    db.commit()

    def apply_gateway(item: Deployment) -> str:
        domain_config = db.get(ProjectDomainConfig, project.id)
        defaults = db.get(DeploymentSettings, "default")
        access = configure_platform_gateway(
            db, item, node, int(item.host_port), project.domain,
            http_port=domain_config.http_port if domain_config else (defaults.default_domain_http_port if defaults else 80),
            https_enabled=domain_config.https_enabled if domain_config else False,
            https_port=domain_config.https_port if domain_config else (defaults.default_domain_https_port if defaults else 443),
            redirect_https=domain_config.redirect_https if domain_config else True,
            certificate=decrypt(domain_config.certificate_encrypted) if domain_config else None,
            private_key=decrypt(domain_config.private_key_encrypted) if domain_config else None,
        )
        old_path = urlsplit(item.access_url or "").path
        if old_path and old_path != "/":
            access = access.rstrip("/") + old_path
        return access

    try:
        output = start_deployment(target, project, node, db)
        access = apply_gateway(target)
        verify_access(db, target.id, access)
    except Exception as exc:
        restore_error = ""
        try:
            start_deployment(current, project, node, db)
            restored_access = apply_gateway(current)
            verify_access(db, current.id, restored_access)
        except Exception as restore_exc:
            restore_error = f"；原线上版本恢复也失败：{restore_exc}"
        target = db.get(Deployment, item_id)
        target.status = DeployStatus.stopped
        target.error = f"回滚失败：{exc}{restore_error}"
        target.log_text = ((target.log_text or "") + f"[回滚失败] {exc}\n" + ("[恢复失败] " + restore_error + "\n" if restore_error else "[自动恢复] 已恢复回滚前的线上版本。\n"))[-200_000:]
        db.commit()
        raise HTTPException(502, target.error)

    current = db.get(Deployment, current.id)
    current.status = DeployStatus.stopped
    current.error = None
    current.log_text = ((current.log_text or "") + f"\n[版本切换] 已回滚至版本 {target.release}。\n")[-200_000:]
    target = db.get(Deployment, target.id)
    target.status = DeployStatus.success
    target.error = None
    target.access_url = access
    target.finished_at = datetime.now(timezone.utc)
    target.log_text = ((target.log_text or "") + f"[回滚完成] {output}；访问验证通过：{access}\n")[-200_000:]
    audit(db, user, "rollback_deployment", "deployment", target.id, f"from={current.release};to={target.release}")
    db.commit()
    try:
        scale_project(project.id, ScaleProjectIn(replicas=1), db, user)
    except Exception as scale_exc:
        target = db.get(Deployment, target.id)
        target.log_text = ((target.log_text or "") + f"[副本同步] 主版本回滚成功，附加副本将在下次状态刷新时重试：{scale_exc}\n")[-200_000:]
        db.commit()
    return {"ok": True, "verified": True, "release": target.release, "access_url": access}


@app.get("/api/deployments/{item_id}/recovery-analysis")
def deployment_recovery_analysis(item_id: str, db: Session = Depends(get_db), _: User = Depends(current_user)):
    item = db.get(Deployment, item_id)
    if not item:
        raise HTTPException(404, "部署不存在")
    project, node = db.get(Project, item.project_id), db.get(Node, item.node_id)
    if not project or not node:
        raise HTTPException(409, "项目或部署服务器不存在")
    release_dir = f"{node.work_dir.rstrip('/')}/{project_directory(project)}/{item.release}" if item.release else ""
    legacy_dir = f"{node.work_dir.rstrip('/')}/{project.slug}/{item.release}" if item.release else ""
    with SSHNode(node) as ssh:
        _, resolved = ssh.run(
            f"if [ -d {shlex.quote(release_dir)} ]; then printf %s {shlex.quote(release_dir)}; "
            f"elif [ -d {shlex.quote(legacy_dir)} ]; then printf %s {shlex.quote(legacy_dir)}; fi"
        )
        actual_dir = resolved.strip()
        compose_file = ""
        if actual_dir:
            _, compose_file = ssh.run(
                f"cd {shlex.quote(actual_dir)} && for f in .yunzhou.ai.compose.yml .yunzhou.compose.yml compose.yml compose.yaml docker-compose.yml docker-compose.yaml; "
                "do [ -f \"$f\" ] && printf %s \"$f\" && break; done"
            )
        image_exists = False
        if item.image_name:
            image_exists = ssh.run(f"docker image inspect {shlex.quote(item.image_name)} >/dev/null 2>&1")[0] == 0
        _, volume_output = ssh.run(
            f"docker volume ls -q --filter label=com.docker.compose.project={shlex.quote('yz-' + project.slug)}"
        )
    is_compose = not bool(item.image_name)
    recoverable = bool(actual_dir and ((compose_file.strip() if is_compose else image_exists)))
    missing = []
    if not actual_dir:
        missing.append("原发布目录")
    if is_compose and not compose_file.strip():
        missing.append("Compose 配置")
    if not is_compose and not image_exists:
        missing.append("应用镜像")
    plan = make_deployment_plan(project, node, db)
    evidence = {
        "release_dir": actual_dir or None,
        "compose_file": compose_file.strip() or None,
        "image": item.image_name,
        "image_exists": image_exists,
        "volumes": [value for value in volume_output.splitlines() if value.strip()],
        "missing": missing,
    }
    summary = "原版本文件完整，可以直接启用服务。" if recoverable else f"原版本不可直接恢复：{'、'.join(missing)}缺失。"
    advice = "确认后直接启动原容器。" if recoverable else "需要从项目源重新拉取、分析、构建并部署；固定 Service、域名和副本设置继续沿用。"
    diagnostic_detail = ""
    try:
        ai_result = deployment_followup(db, item, project, node, "恢复前检查", json.dumps(evidence, ensure_ascii=False))
        diagnostic_detail = "\n\n".join(str(value) for value in (ai_result.get("summary"), ai_result.get("advice")) if value)
    except Exception:
        pass
    return {
        "recoverable": recoverable, "summary": summary, "advice": advice,
        "diagnostic_detail": diagnostic_detail,
        "evidence": evidence,
        "rebuild_plan": {
            "source": "Git 仓库" if project.source_type == SourceType.git else "已上传源码",
            "node": node.name,
            "build_mode": plan.get("build_mode"),
            "service_entry": item.access_url,
            "replicas": max(1, int(project.replica_count or 1)) if project.load_balance_enabled else 1,
            "steps": ["重新获取源码", "AI 分析项目与依赖", "重新构建应用", "恢复 Service 后端", "验证访问"],
        },
    }


@app.get("/api/settings/ai", response_model=AiConfigOut | None)
def get_ai(db: Session = Depends(get_db), _: User = Depends(require(Role.admin))):
    item = db.scalar(select(AiConfig).order_by(AiConfig.is_default.desc(), AiConfig.provider_name))
    if not item:
        return None
    return ai_config_out(item)


def ai_config_out(item: AiConfig) -> AiConfigOut:
    return AiConfigOut(id=item.id, provider_name=item.provider_name, base_url=item.base_url, model=item.model, enabled=item.enabled, is_default=item.is_default, has_api_key=bool(item.api_key_encrypted))


@app.get("/api/settings/ai/configs", response_model=list[AiConfigOut])
def list_ai_configs(db: Session = Depends(get_db), _: User = Depends(current_user)):
    return [ai_config_out(x) for x in db.query(AiConfig).order_by(AiConfig.is_default.desc(), AiConfig.provider_name).all()]


@app.post("/api/settings/ai/configs", response_model=AiConfigOut)
def create_ai_config(body: AiConfigIn, db: Session = Depends(get_db), user: User = Depends(require(Role.admin))):
    if not body.api_key:
        raise HTTPException(400, "新配置必须填写 API Key")
    has_default = db.scalar(select(AiConfig.id).where(AiConfig.enabled.is_(True), AiConfig.is_default.is_(True)))
    item = AiConfig(provider_name=body.provider_name, base_url=body.base_url, model=body.model, enabled=body.enabled, is_default=bool(body.enabled and not has_default), api_key_encrypted=encrypt(body.api_key))
    db.add(item)
    db.flush()
    audit(db, user, "create_ai_config", "ai_config", item.id, item.provider_name)
    db.commit()
    db.refresh(item)
    return ai_config_out(item)


@app.patch("/api/settings/ai/configs/{item_id}", response_model=AiConfigOut)
def update_ai_config(item_id: str, body: AiConfigIn, db: Session = Depends(get_db), user: User = Depends(require(Role.admin))):
    item = db.get(AiConfig, item_id)
    if not item:
        raise HTTPException(404, "AI 配置不存在")
    item.provider_name, item.base_url, item.model, item.enabled = body.provider_name, body.base_url, body.model, body.enabled
    if item.is_default and not item.enabled:
        replacement = db.scalar(select(AiConfig).where(AiConfig.id != item.id, AiConfig.enabled.is_(True)).order_by(AiConfig.provider_name))
        if not replacement:
            raise HTTPException(400, "默认模型不能停用；请先启用另一个模型并设为默认")
        item.is_default = False
        replacement.is_default = True
    if body.api_key:
        item.api_key_encrypted = encrypt(body.api_key)
    audit(db, user, "update_ai_config", "ai_config", item.id, item.provider_name)
    db.commit()
    db.refresh(item)
    return ai_config_out(item)


@app.delete("/api/settings/ai/configs/{item_id}")
def delete_ai_config(item_id: str, db: Session = Depends(get_db), user: User = Depends(require(Role.admin))):
    item = db.get(AiConfig, item_id)
    if not item:
        raise HTTPException(404, "AI 配置不存在")
    if item.is_default:
        raise HTTPException(400, "默认模型不能删除，请先将其他模型设为默认")
    db.delete(item)
    audit(db, user, "delete_ai_config", "ai_config", item_id, item.provider_name)
    db.commit()
    return {"ok": True}


@app.post("/api/settings/ai/configs/{item_id}/default", response_model=AiConfigOut)
def set_default_ai_config(item_id: str, db: Session = Depends(get_db), user: User = Depends(require(Role.admin))):
    item = db.get(AiConfig, item_id)
    if not item:
        raise HTTPException(404, "AI 配置不存在")
    if not item.enabled:
        raise HTTPException(400, "请先启用该模型，再设为默认")
    db.query(AiConfig).update({AiConfig.is_default: False}, synchronize_session=False)
    item.is_default = True
    audit(db, user, "set_default_ai_config", "ai_config", item.id, f"{item.provider_name} · {item.model}")
    db.commit()
    db.refresh(item)
    return ai_config_out(item)


@app.put("/api/settings/ai", response_model=AiConfigOut)
def set_ai(body: AiConfigIn, db: Session = Depends(get_db), user: User = Depends(require(Role.admin))):
    item = db.query(AiConfig).first() or AiConfig()
    item.provider_name, item.base_url, item.model, item.enabled = body.provider_name, body.base_url, body.model, body.enabled
    if body.api_key:
        item.api_key_encrypted = encrypt(body.api_key)
    db.add(item)
    audit(db, user, "update_ai", "ai_config", item.id)
    db.commit()
    db.refresh(item)
    return ai_config_out(item)


@app.post("/api/settings/ai/test")
def test_ai(body: AiConfigIn, config_id: str | None = None, db: Session = Depends(get_db), _: User = Depends(require(Role.admin))):
    current = db.get(AiConfig, config_id) if config_id else db.query(AiConfig).first()
    api_key = body.api_key or (decrypt(current.api_key_encrypted) if current else None)
    if not api_key:
        raise HTTPException(400, "请先填写 API Key")
    try:
        url = body.base_url.rstrip("/") + "/chat/completions"
        selected_proxy = proxy_for(db, url)
        safe_proxy = redact_proxy(selected_proxy)
        trace_code = "NET-" + uuid.uuid4().hex[:12].upper()
        target = urlsplit(url)
        target_host, target_port = target.hostname or "", target.port or (443 if target.scheme == "https" else 80)
        dns_ips = sorted({item[4][0] for item in socket.getaddrinfo(target_host, target_port, type=socket.SOCK_STREAM)})
        connect_url = urlsplit(selected_proxy) if selected_proxy else target
        connect_host = connect_url.hostname or target_host
        connect_port = connect_url.port or (443 if connect_url.scheme == "https" else 80)
        route_socket = socket.create_connection((connect_host, connect_port), timeout=8)
        local_ip = route_socket.getsockname()[0]
        peer_ip = route_socket.getpeername()[0]
        route_socket.close()
        gateway = None
        try:
            with open("/proc/net/route", encoding="utf-8") as routes:
                for line in routes.readlines()[1:]:
                    fields = line.split()
                    if len(fields) > 2 and fields[1] == "00000000":
                        gateway = socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))
                        break
        except OSError:
            pass
        started = time.perf_counter()
        with httpx.Client(proxy=selected_proxy, trust_env=False, timeout=60) as client:
            response = None
            for attempt in range(3):
                response = client.post(
                    url,
                    headers={"Authorization": "Bearer " + api_key},
                    json={
                        "model": body.model,
                        "messages": [{"role": "user", "content": "只回复：连接正常"}],
                        "max_tokens": 30,
                    },
                )
                if response.status_code not in (502, 503, 504):
                    break
                if attempt < 2:
                    time.sleep(attempt + 1)
        latency_ms = round((time.perf_counter() - started) * 1000)
        if response.status_code in (502, 503, 504):
            raise HTTPException(502, f"AI 服务上游暂时不可用（HTTP {response.status_code}），平台已自动重试 3 次，请稍后再试")
        if response.status_code in (401, 403):
            raise HTTPException(502, "AI 接口拒绝认证，请检查 API Key 是否有效")
        if response.status_code == 404:
            raise HTTPException(502, "AI 接口地址或模型名称不存在，请检查接口地址和模型名称")
        if response.status_code == 429:
            raise HTTPException(502, "AI 服务当前请求过多或额度不足，请稍后再试或检查账户额度")
        if response.status_code == 400:
            try:
                provider_message = response.json().get("error", {}).get("message", "")
            except (ValueError, AttributeError):
                provider_message = ""
            detail = f"：{provider_message}" if provider_message else ""
            raise HTTPException(502, f"AI 接口不接受当前请求参数{detail}")
        response.raise_for_status()
        data = response.json()
        return {
            "ok": True,
            "model": data.get("model", body.model),
            "reply": data["choices"][0]["message"]["content"],
            "network_route": "proxy" if selected_proxy else "direct",
            "network_detail": safe_proxy or "服务器直连",
            "trace_code": trace_code,
            "target_host": target_host,
            "target_port": target_port,
            "dns_ips": dns_ips,
            "local_ip": local_ip,
            "gateway": gateway,
            "peer_ip": peer_ip,
            "latency_ms": latency_ms,
            "route_steps": [
                f"云舟 API ({local_ip})",
                *(([f"默认网关 ({gateway})"] if gateway else [])),
                *(([f"应用代理 ({safe_proxy})"] if selected_proxy else ["服务器直连"])),
                f"{target_host} ({', '.join(dns_ips)}):{target_port}",
            ],
        }
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(502, f"连接测试失败：{exc}") from exc


@app.get("/api/settings/proxy", response_model=ProxyConfigOut)
def get_system_proxy(db: Session = Depends(get_db), _: User = Depends(require(Role.admin))):
    item = get_proxy_config(db)
    if not item:
        return ProxyConfigOut()
    required = ["registry", "yunzhou.hub", "yunzhou.hub:5000"]
    no_proxy = ",".join(dict.fromkeys([x.strip() for x in (item.no_proxy or "").split(",") if x.strip()] + required))
    return ProxyConfigOut(id=item.id, enabled=item.enabled, http_proxy=item.http_proxy, https_proxy=item.https_proxy, proxy_username=item.proxy_username or "", has_proxy_password=bool(item.proxy_password_encrypted), no_proxy=no_proxy)


@app.put("/api/settings/proxy", response_model=ProxyConfigOut)
def set_system_proxy(body: ProxyConfigIn, db: Session = Depends(get_db), user: User = Depends(require(Role.admin))):
    if body.enabled and not (body.http_proxy or body.https_proxy):
        raise HTTPException(400, "启用代理时必须填写代理地址")
    item = get_proxy_config(db) or SystemProxy()
    required = ["registry", "yunzhou.hub", "yunzhou.hub:5000"]
    no_proxy = ",".join(dict.fromkeys([x.strip() for x in body.no_proxy.split(",") if x.strip()] + required))
    item.enabled, item.http_proxy, item.https_proxy, item.no_proxy = body.enabled, body.http_proxy.strip(), body.https_proxy.strip(), no_proxy
    item.proxy_username = body.proxy_username.strip()
    if body.proxy_password:
        item.proxy_password_encrypted = encrypt(body.proxy_password)
    elif not item.proxy_username:
        item.proxy_password_encrypted = None
    db.add(item)
    db.flush()
    audit(db, user, "update_system_proxy", "system_proxy", item.id, "enabled" if item.enabled else "disabled")
    db.commit()
    db.refresh(item)
    # The database is the source of truth, but Docker reads a generated
    # systemd file on every enabled node. Keep both layers synchronized so a
    # saved NO_PROXY change cannot leave targets silently using stale values.
    enabled_nodes = db.scalars(select(Node).where(Node.docker_proxy_enabled == True)).all()
    gateway = platform_gateway_node(db)
    enabled_nodes.sort(key=lambda node: bool(gateway and node.id == gateway.id))
    sync_errors = []
    for node in enabled_nodes:
        try:
            apply_node_docker_proxy(node, db, item.enabled)
        except Exception as exc:
            node.docker_proxy_status = "error"
            node.docker_proxy_error = str(exc)
            sync_errors.append(f"{node.name}: {str(exc)[:180]}")
    db.commit()
    if sync_errors:
        raise HTTPException(502, "代理设置已保存，但以下服务器同步失败：" + "；".join(sync_errors))
    return ProxyConfigOut(id=item.id, enabled=item.enabled, http_proxy=item.http_proxy, https_proxy=item.https_proxy, proxy_username=item.proxy_username or "", has_proxy_password=bool(item.proxy_password_encrypted), no_proxy=item.no_proxy)


@app.get("/api/settings/security", response_model=SecuritySettingsOut)
def read_security_settings(db: Session = Depends(get_db), _: User = Depends(require(Role.admin))):
    return security_config_view(get_security_config(db))


@app.put("/api/settings/security", response_model=SecuritySettingsOut)
def update_security_settings(body: SecuritySettingsIn, db: Session = Depends(get_db), user: User = Depends(require(Role.admin))):
    if body.password_max_age_days and body.password_min_age_days > body.password_max_age_days:
        raise HTTPException(400, "密码最短使用时间不能大于密码有效期")
    row = get_security_config(db)
    for key, value in body.model_dump().items():
        setattr(row, key, value.strip() if isinstance(value, str) else value)
    if row.china_ip_allowlist_enabled and not (row.china_ip_cidrs or "").strip():
        networks = fetch_china_ip_cidrs(row.china_ip_source_url)
        row.china_ip_cidrs = "\n".join(networks) + "\n"
        row.source_updated_at = datetime.now(timezone.utc)
    try:
        apply_china_ip_allowlist(db, row)
    except Exception:
        db.rollback()
        raise
    db.add(row)
    db.flush()
    audit(db, user, "update_security_settings", "system", "security", "china_allowlist=enabled" if row.china_ip_allowlist_enabled else "china_allowlist=disabled")
    db.commit()
    db.refresh(row)
    return security_config_view(row)


@app.post("/api/settings/security/china-ip/update", response_model=SecuritySettingsOut)
def update_china_ip_allowlist(db: Session = Depends(get_db), user: User = Depends(require(Role.admin))):
    row = get_security_config(db)
    networks = fetch_china_ip_cidrs(row.china_ip_source_url)
    row.china_ip_cidrs = "\n".join(networks) + "\n"
    row.source_updated_at = datetime.now(timezone.utc)
    if row.china_ip_allowlist_enabled:
        try:
            apply_china_ip_allowlist(db, row)
        except Exception:
            db.rollback()
            raise
    db.add(row)
    db.flush()
    audit(db, user, "update_china_ip_allowlist", "system", "security", f"cidrs={len(networks)}")
    db.commit()
    db.refresh(row)
    return security_config_view(row)


@app.get("/api/settings/security/china-ip/download")
def download_china_ip_allowlist(db: Session = Depends(get_db), _: User = Depends(require(Role.admin))):
    row = get_security_config(db)
    cidrs = [line.strip() for line in (row.china_ip_cidrs or "").splitlines() if line.strip()]
    content = "# Generated by Yunzhou from " + row.china_ip_source_url + "\n"
    content += "".join(f"allow {item};\n" for item in cidrs)
    content += "deny all;\n"
    return Response(
        content=content,
        media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="blockips.conf"'},
    )


@app.get("/api/settings/deployment", response_model=DeploymentSettingsOut)
def read_deployment_settings(db: Session = Depends(get_db), _: User = Depends(require(Role.admin))):
    return get_deployment_settings(db)


@app.put("/api/settings/deployment", response_model=DeploymentSettingsOut)
def update_deployment_settings(body: DeploymentSettingsIn, db: Session = Depends(get_db), user: User = Depends(require(Role.admin))):
    if body.per_node_concurrency > body.global_concurrency:
        raise HTTPException(400, "同一服务器并发数不能大于全局并发数")
    if body.external_port_start > body.external_port_end:
        raise HTTPException(400, "对外端口段起始值不能大于结束值")
    if body.external_port_end - body.external_port_start < 20:
        raise HTTPException(400, "对外端口段至少需要保留 21 个端口")
    if body.internal_port_start > body.internal_port_end:
        raise HTTPException(400, "内网实例端口段起始值不能大于结束值")
    if body.internal_port_end - body.internal_port_start < 100:
        raise HTTPException(400, "内网实例端口段至少需要保留 101 个端口")
    if not (body.internal_port_end < body.external_port_start or body.internal_port_start > body.external_port_end):
        raise HTTPException(400, "内网实例端口段不能与公网网关端口段重叠")
    if body.default_domain_http_port == body.default_domain_https_port:
        raise HTTPException(400, "HTTP 和 HTTPS 默认端口不能相同")
    reserved_ports = (body.default_domain_http_port, body.default_domain_https_port)
    if any(body.external_port_start <= port <= body.external_port_end for port in reserved_ports):
        raise HTTPException(400, "公网端口段不能包含配置的 HTTP 或 HTTPS 保留端口")
    mirror_lines = [line.strip().rstrip("/") for line in body.registry_mirrors_text.splitlines() if line.strip()]
    if len(mirror_lines) > 20:
        raise HTTPException(400, "Docker 镜像候选源最多配置 20 个")
    if any(urlsplit(line if "://" in line else "https://" + line).scheme not in {"http", "https"} or
           not urlsplit(line if "://" in line else "https://" + line).netloc for line in mirror_lines):
        raise HTTPException(400, "Docker 镜像候选源格式不正确")
    cache_paths = {
        "构建服务器缓存根目录": body.build_cache_root,
        "Maven 缓存目录": body.maven_cache_dir,
        "Gradle 缓存目录": body.gradle_cache_dir,
        "npm 缓存目录": body.npm_cache_dir,
        "pnpm 缓存目录": body.pnpm_cache_dir,
        "Yarn 缓存目录": body.yarn_cache_dir,
        "pip 缓存目录": body.pip_cache_dir,
    }
    for label, value in cache_paths.items():
        path = value.strip().rstrip("/") or "/"
        if not path.startswith("/") or "\x00" in path or any(part == ".." for part in path.split("/")):
            raise HTTPException(400, f"{label}必须是安全的绝对路径")
    item = get_deployment_settings(db)
    item.global_concurrency = body.global_concurrency
    item.per_node_concurrency = body.per_node_concurrency
    item.connection_timeout_seconds = body.connection_timeout_seconds
    item.external_port_start = body.external_port_start
    item.external_port_end = body.external_port_end
    item.internal_port_start = body.internal_port_start
    item.internal_port_end = body.internal_port_end
    item.default_domain_http_port = body.default_domain_http_port
    item.default_domain_https_port = body.default_domain_https_port
    item.registry_mirrors_text = "\n".join(dict.fromkeys(mirror_lines))
    item.registry_retention_count = body.registry_retention_count
    item.registry_auto_cleanup = body.registry_auto_cleanup
    endpoint = body.registry_endpoint.strip().lower().removeprefix("http://").removeprefix("https://").rstrip("/")
    if not re.fullmatch(r"[a-z0-9.-]+(?::\d{1,5})?", endpoint):
        raise HTTPException(400, "仓库访问地址格式不正确")
    item.registry_endpoint = endpoint
    item.registry_namespace = body.registry_namespace.strip().lower()
    item.build_cache_root = body.build_cache_root.strip().rstrip("/")
    item.maven_cache_dir = body.maven_cache_dir.strip().rstrip("/")
    item.gradle_cache_dir = body.gradle_cache_dir.strip().rstrip("/")
    item.npm_cache_dir = body.npm_cache_dir.strip().rstrip("/")
    item.pnpm_cache_dir = body.pnpm_cache_dir.strip().rstrip("/")
    item.yarn_cache_dir = body.yarn_cache_dir.strip().rstrip("/")
    item.pip_cache_dir = body.pip_cache_dir.strip().rstrip("/")
    audit(db, user, "update_deployment_settings", "system", item.id, f"global={item.global_concurrency},per_node={item.per_node_concurrency},timeout={item.connection_timeout_seconds}")
    db.commit()
    db.refresh(item)
    return item


@app.post("/api/settings/deployment/cleanup-registry")
def cleanup_registry_now(db: Session = Depends(get_db), user: User = Depends(require(Role.admin))):
    """Apply the saved retention policy immediately to platform-owned images."""
    policy = get_deployment_settings(db)
    if not policy.registry_auto_cleanup:
        return {"ok": True, "repository_count": 0, "removed_count": 0, "removed": [], "message": "自动清理已关闭，未删除任何版本"}
    repositories = _registry_request("GET", "/_catalog?n=1000").json().get("repositories") or []
    namespace = (policy.registry_namespace or "yunzhou").strip("/") + "/"
    projects = db.scalars(select(Project)).all()
    removed = []
    touched = 0
    for repository in repositories:
        if not repository.startswith(namespace):
            continue
        tail = repository[len(namespace):]
        project = next((item for item in projects if tail == item.slug or tail.startswith(item.slug + "-")), None)
        touched += 1
        for tag in cleanup_registry_versions(db, project, repository):
            removed.append(f"{repository}:{tag}")
    audit(db, user, "cleanup_registry_now", "registry", None, f"repositories={touched},removed={len(removed)}")
    db.commit()
    return {
        "ok": True,
        "repository_count": touched,
        "removed_count": len(removed),
        "removed": removed,
        "message": f"已检查 {touched} 个仓库，清理 {len(removed)} 个旧版本",
    }


@app.post("/api/settings/proxy/test")
def test_system_proxy(body: ProxyConfigIn, db: Session = Depends(get_db), _: User = Depends(require(Role.admin))):
    import time
    saved = get_proxy_config(db)
    password = body.proxy_password or (decrypt(saved.proxy_password_encrypted) if saved and saved.proxy_username == body.proxy_username else "")
    proxy = proxy_with_auth(body.https_proxy or body.http_proxy, body.proxy_username.strip(), password or "")
    if not proxy:
        raise HTTPException(400, "请先填写 HTTP 或 HTTPS 代理地址")
    started = time.perf_counter()
    try:
        with httpx.Client(proxy=proxy, trust_env=False, timeout=8, verify=False) as client:
            # This endpoint is intentionally unrelated to the configured AI
            # provider. Proxy connectivity and AI API authentication are two
            # separate checks; a proxy test must never require an AI key.
            response = client.get("https://www.gstatic.com/generate_204")
        elapsed = round((time.perf_counter() - started) * 1000)
        if 200 <= response.status_code < 400:
            message = "代理通道可用，HTTPS 网络连通正常"
            severity = "success"
        else:
            message = f"代理已建立连接，但公共连通性地址返回 HTTP {response.status_code}"
            severity = "warning"
        return {
            "ok": True,
            "route": "proxy",
            "detail": (body.https_proxy or body.http_proxy),
            "status_code": response.status_code,
            "latency_ms": elapsed,
            "authenticated": True,
            "target_requires_auth": False,
            "severity": severity,
            "message": message,
        }
    except Exception as exc:
        if "407" in str(exc) or "Proxy Authentication Required" in str(exc):
            raise HTTPException(502, "代理服务器要求身份认证（HTTP 407），请展开“代理认证”填写用户名和密码") from exc
        raise HTTPException(502, f"代理地址不可用：{exc}") from exc


def _chat_session_for_user(db: Session, session_id: str, user: User) -> ChatSession:
    session = db.get(ChatSession, session_id)
    if not session or (user.role != Role.admin and session.owner_id != user.id):
        raise HTTPException(404, "对话不存在或无权访问")
    return session


def _chat_session_dict(db: Session, session: ChatSession) -> dict:
    project = db.get(Project, session.project_id) if session.project_id else None
    message_count = db.scalar(select(func.count(ChatMessage.id)).where(ChatMessage.session_id == session.id)) or 0
    return {
        "id": session.id, "title": session.title, "project_id": session.project_id,
        "project_name": project.name if project else "全局助手", "node_id": session.node_id,
        "ai_config_id": session.ai_config_id,
        "visibility": session.visibility, "archived": session.archived,
        "message_count": message_count, "created_at": session.created_at,
        "updated_at": session.updated_at,
    }


@app.get("/api/chat/sessions")
def chat_sessions(project_id: str | None = None, archived: bool = False, db: Session = Depends(get_db), user: User = Depends(current_user)):
    query = select(ChatSession).where(ChatSession.archived == archived)
    if user.role != Role.admin:
        query = query.where(ChatSession.owner_id == user.id)
    if project_id:
        query = query.where(ChatSession.project_id == project_id)
    return [_chat_session_dict(db, item) for item in db.scalars(query.order_by(ChatSession.updated_at.desc()).limit(200)).all()]


@app.get("/api/chat/sessions/{session_id}/messages")
def chat_session_messages(session_id: str, db: Session = Depends(get_db), user: User = Depends(current_user)):
    session = _chat_session_for_user(db, session_id, user)
    messages = db.scalars(select(ChatMessage).where(ChatMessage.session_id == session.id).order_by(ChatMessage.created_at)).all()
    return {
        "session": _chat_session_dict(db, session),
        "messages": [
            {"id": item.id, "role": item.role, "content": item.content, "action": item.action,
             "deployment_id": item.deployment_id, "created_at": item.created_at}
            for item in messages
        ],
    }


@app.post("/api/chat/sessions/{session_id}/archive")
def archive_chat_session(session_id: str, db: Session = Depends(get_db), user: User = Depends(current_user)):
    session = _chat_session_for_user(db, session_id, user)
    session.archived = True
    audit(db, user, "archive_chat_session", "chat_session", session.id, session.title)
    db.commit()
    return {"ok": True}


@app.post("/api/chat/sessions/{session_id}/restore")
def restore_chat_session(session_id: str, db: Session = Depends(get_db), user: User = Depends(current_user)):
    session = _chat_session_for_user(db, session_id, user)
    session.archived = False
    audit(db, user, "restore_chat_session", "chat_session", session.id, session.title)
    db.commit()
    return {"ok": True}


@app.delete("/api/chat/sessions/{session_id}")
def delete_chat_session(session_id: str, db: Session = Depends(get_db), user: User = Depends(current_user)):
    session = _chat_session_for_user(db, session_id, user)
    title = session.title
    db.delete(session)
    audit(db, user, "delete_chat_session", "chat_session", session_id, title)
    db.commit()
    return {"ok": True}


@app.post("/api/chat/sessions/archive-all")
def archive_all_chat_sessions(body: dict, db: Session = Depends(get_db), user: User = Depends(current_user)):
    query = select(ChatSession).where(ChatSession.archived.is_(False))
    if user.role != Role.admin or body.get("scope") != "platform":
        query = query.where(ChatSession.owner_id == user.id)
    if body.get("project_id"):
        query = query.where(ChatSession.project_id == str(body["project_id"]))
    items = db.scalars(query).all()
    for item in items:
        item.archived = True
    audit(db, user, "archive_chat_sessions", "chat_session", detail=f"count={len(items)},scope={body.get('scope', 'mine')}")
    db.commit()
    return {"ok": True, "count": len(items)}


@app.post("/api/chat/sessions/purge")
def purge_chat_sessions(body: dict, db: Session = Depends(get_db), user: User = Depends(current_user)):
    if body.get("confirm") != "永久清理对话":
        raise HTTPException(400, "请输入“永久清理对话”确认")
    scope = str(body.get("scope") or "mine")
    if scope == "platform" and user.role != Role.admin:
        raise HTTPException(403, "只有管理员可以清理全平台对话")
    query = select(ChatSession)
    if scope != "platform":
        query = query.where(ChatSession.owner_id == user.id)
    if body.get("project_id"):
        query = query.where(ChatSession.project_id == str(body["project_id"]))
    if body.get("archived_only", True):
        query = query.where(ChatSession.archived.is_(True))
    items = db.scalars(query).all()
    ids = [item.id for item in items]
    for item in items:
        db.delete(item)
    audit(db, user, "purge_chat_sessions", "chat_session", detail=f"count={len(ids)},scope={scope}")
    db.commit()
    return {"ok": True, "count": len(ids)}


@app.post("/api/chat", response_model=ChatOut)
def chat(body: ChatIn, db: Session = Depends(get_db), user: User = Depends(require(Role.admin, Role.deployer))):
    session = _chat_session_for_user(db, body.session_id, user) if body.session_id else None
    requested_ai = db.get(AiConfig, body.ai_config_id) if body.ai_config_id else None
    if requested_ai and not requested_ai.enabled:
        requested_ai = None
    if not session:
        title = re.sub(r"\s+", " ", body.message).strip()[:48] or "新对话"
        initial_project = db.get(Project, body.project_id) if body.project_id else None
        initial_node = db.get(Node, body.node_id) if body.node_id else None
        session = ChatSession(
            owner_id=user.id,
            project_id=initial_project.id if initial_project else None,
            node_id=initial_node.id if initial_node else None,
            ai_config_id=requested_ai.id if requested_ai else None,
            title=title,
        )
        db.add(session)
        db.flush()
    elif session.archived:
        # Continuing an archived conversation is an explicit restore action.
        session.archived = False
    if requested_ai:
        session.ai_config_id = requested_ai.id
    stored_history = db.scalars(
        select(ChatMessage)
        .where(ChatMessage.session_id == session.id)
        .order_by(ChatMessage.created_at.desc())
        .limit(12)
    ).all()
    ai_history = [
        {"role": item.role, "content": item.content}
        for item in reversed(stored_history)
        if item.role in ("user", "assistant")
    ]
    if not ai_history and body.history:
        ai_history = body.history[-10:]
    db.add(ChatMessage(session_id=session.id, role="user", content=body.message))
    session.updated_at = datetime.now(timezone.utc)
    db.commit()

    def respond(reply: str, *, deployment_id: str | None = None, action: str | None = None,
                project_id: str | None = None, node_id: str | None = None,
                intent: str | None = None) -> ChatOut:
        session.project_id = project_id if project_id and db.get(Project, project_id) else session.project_id
        session.node_id = node_id if node_id and db.get(Node, node_id) else session.node_id
        session.updated_at = datetime.now(timezone.utc)
        db.add(ChatMessage(
            session_id=session.id,
            role="assistant",
            content=reply,
            action=action,
            deployment_id=deployment_id,
        ))
        db.commit()
        return ChatOut(
            reply=reply, deployment_id=deployment_id, action=action,
            project_id=project_id, node_id=node_id, intent=intent,
            session_id=session.id,
        )

    direct_sql = _extract_direct_sql(body.message)
    try:
        decision = ({
            "action": "answer", "project_id": body.project_id or session.project_id,
            "node_id": body.node_id or session.node_id, "reply": "",
        } if direct_sql else understand(db, body.message, body.project_id or session.project_id, body.node_id or session.node_id, session.ai_config_id, ai_history))
    except Exception as exc:
        # Keep the assistant usable when the configured model is temporarily
        # unavailable.  Fuzzy matching is deliberately limited to known,
        # confirmation-gated platform actions; project/node selection and the
        # current chat context are still resolved below in the normal flow.
        from difflib import SequenceMatcher

        compact_message = re.sub(r"[\s，。！!？?、]", "", body.message.lower())
        intent_examples = {
            "stop": ("停止部署", "暂停部署", "中止部署", "取消部署", "停掉部署"),
            "rollback": ("回滚上个版本", "回滚上一版本", "恢复历史版本"),
            "restart": ("重启服务", "重启容器", "重启项目"),
            "migrate": ("执行表结构", "更新表结构", "应用迁移文件", "同步数据库结构"),
            "deploy": ("开始部署", "重新部署", "发布项目", "上线项目"),
        }
        ranked = [
            (SequenceMatcher(None, compact_message, example).ratio(), action)
            for action, examples in intent_examples.items()
            for example in examples
        ]
        score, fallback_action = max(ranked, default=(0.0, "none"))
        # A deployment word plus a close action phrase is strong enough for a
        # confirmation prompt, but never for immediate destructive execution.
        if score < 0.56 or (fallback_action == "stop" and "部署" not in compact_message):
            fallback_action = "none"
        if fallback_action == "none":
            return respond(
                f"AI 服务调用失败：{exc}\n本次错误已保存到对话历史，请稍后重试。",
                action="ai_error", project_id=body.project_id or session.project_id,
                node_id=body.node_id or session.node_id, intent=body.intent,
            )
        decision = {
            "action": fallback_action,
            "project_id": body.project_id or session.project_id,
            "node_id": body.node_id or session.node_id,
            "reply": "AI 暂时不可用，平台已结合当前对话和任务状态识别你的操作意图。",
        }
    projects = db.scalars(select(Project)).all()
    nodes = db.scalars(select(Node).where(Node.enabled.is_(True))).all()
    project_id = decision.get("project_id") or body.project_id
    node_id = decision.get("node_id") or body.node_id
    if not db.get(Project, project_id) if project_id else False:
        project_id = None
    if not db.get(Node, node_id) if node_id else False:
        node_id = None
    project_match = next((x for x in projects if x.name in body.message or x.slug in body.message), None)
    node_match = next((x for x in nodes if x.name in body.message), None)
    project_id = project_match.id if project_match else project_id
    node_id = node_match.id if node_match else node_id
    normalized = re.sub(r"[\s，。！!？?]", "", body.message)
    confirmed = normalized in {"是", "是的", "确认", "确认部署", "确认停止", "确认取消", "确认回滚", "确认重启", "确认执行表结构", "确认执行高风险表结构", "确认执行数据变更", "确认执行高风险数据变更", "开始", "开始部署", "可以", "执行", "上线", "停止", "取消", "回滚", "重启"}
    if direct_sql:
        target = db.get(Project, project_id) if project_id else None
        if not target:
            return respond("请先关联要查询或修改数据库的项目，再发送 SQL。", action="none", project_id=project_id, node_id=node_id, intent=None)
        kind = _sql_kind(direct_sql)
        if kind == "query":
            try:
                result = _query_project_database(target, direct_sql, db, user, session.id)
            except HTTPException as exc:
                audit(db, user, "ai_query_database", "project", target.id, json.dumps({
                    "status": "failed", "sql": direct_sql,
                    "sha256": hashlib.sha256(direct_sql.encode()).hexdigest(),
                    "error": str(exc.detail)[:1000], "chat_session_id": session.id,
                    "requested_via": "AI 对话",
                }, ensure_ascii=False))
                db.commit()
                raise
            content = "\n".join(result["lines"]) or "（查询成功，没有返回数据）"
            suffix = "\n结果较多，已截取前 100 行。" if result["truncated"] else ""
            return respond(
                f"结论：已在“{target.name}”的 {result['engine']} 数据库执行只读查询。\n"
                f"查询结果：{result['row_count']} 行 · {result['column_count']} 列\n"
                f"```table\n{content}\n```{suffix}",
                action="queried_database", project_id=target.id, node_id=node_id, intent=None,
            )
        if kind == "schema":
            digest = hashlib.sha256(direct_sql.encode()).hexdigest()
            risk = "high" if _MIGRATION_DANGER.search(direct_sql) else "low"
            expected = [{
                "path": f"AI 直接 SQL {digest[:8]}", "sha256": digest,
                "risk": risk, "sql": direct_sql,
            }]
            payload = base64.urlsafe_b64encode(json.dumps({
                "project_id": target.id, "node_id": node_id, "files": expected,
            }, ensure_ascii=False).encode()).decode()
            confirmation = "确认执行高风险表结构" if risk == "high" else "确认执行表结构"
            return respond(
                f"结论：已接收你提供的表结构 SQL，平台不会改写内容。\n"
                f"风险：{'高风险（包含删除或清空操作）' if risk == 'high' else '常规表结构变更'}。\n"
                f"SQL 校验值：{digest[:12]}\n下一步：回复“{confirmation}”，平台将先备份当前表结构，再原样执行。",
                action="confirm_migration", project_id=target.id, node_id=node_id,
                intent="migrate:" + payload,
            )
        if kind == "data_change":
            digest = hashlib.sha256(direct_sql.encode()).hexdigest()
            operation = direct_sql.lstrip().split(None, 1)[0].upper()
            high_risk = bool(operation in {"UPDATE", "DELETE"} and not re.search(r"(?i)\bwhere\b", direct_sql))
            payload = base64.urlsafe_b64encode(json.dumps({
                "project_id": target.id, "node_id": node_id, "sql": direct_sql,
                "sha256": digest, "high_risk": high_risk,
            }, ensure_ascii=False).encode()).decode()
            confirmation = "确认执行高风险数据变更" if high_risk else "确认执行数据变更"
            return respond(
                f"结论：已识别到一条 {operation} 数据变更语句，将在“{target.name}”数据库中执行。\n"
                f"风险：{'高风险，语句没有 WHERE 条件，可能影响整张表。' if high_risk else '执行前需要你明确确认。'}\n"
                f"SQL 校验值：{digest[:12]}\n下一步：回复“{confirmation}”后执行；结果会写入操作记录。",
                action="confirm_data_change", project_id=target.id, node_id=node_id, intent="datachange:" + payload,
            )
        return respond("SQL 包含多语句混合操作或不受支持的命令，平台已拒绝执行。请一次只提交一类 SQL。", action="none", project_id=target.id, node_id=node_id, intent=None)
    migrate_payload = None
    if body.intent and body.intent.startswith("migrate:"):
        try:
            migrate_payload = json.loads(base64.urlsafe_b64decode(body.intent.split(":", 1)[1].encode()).decode())
        except Exception:
            migrate_payload = None
    if migrate_payload and confirmed:
        target = db.get(Project, migrate_payload.get("project_id"))
        expected = migrate_payload.get("files") or []
        if not target or not isinstance(expected, list):
            raise HTTPException(409, "待执行的表结构清单已失效，请重新发起")
        has_high_risk = any(item.get("risk") == "high" for item in expected)
        if has_high_risk and normalized != "确认执行高风险表结构":
            return respond(
                "检测到删除表、清空表或删除字段等高风险 SQL。请明确回复“确认执行高风险表结构”后平台才会继续。",
                action="confirm_high_risk_migration", project_id=target.id,
                node_id=migrate_payload.get("node_id"), intent=body.intent,
            )
        result = _execute_project_migrations(target, expected, db, user, session.id)
        files_text = "、".join(result["files"])
        return respond(
            f"结论：已完成“{target.name}”的表结构更新。\n关键依据：已先备份 {result['engine']} 表结构；成功执行 {len(result['files'])} 个迁移文件：{files_text}。\n执行结果和文件校验值已写入操作记录，后续不会重复执行同一版本。",
            action="migrated", project_id=target.id,
            node_id=migrate_payload.get("node_id"), intent=None,
        )
    data_change_payload = None
    if body.intent and body.intent.startswith("datachange:"):
        try:
            data_change_payload = json.loads(base64.urlsafe_b64decode(body.intent.split(":", 1)[1].encode()).decode())
        except Exception:
            data_change_payload = None
    if data_change_payload and confirmed:
        target = db.get(Project, data_change_payload.get("project_id"))
        sql = str(data_change_payload.get("sql") or "")
        digest = hashlib.sha256(sql.encode()).hexdigest()
        if not target or not sql or digest != data_change_payload.get("sha256"):
            raise HTTPException(409, "待执行的数据变更已失效，请重新发送 SQL")
        if data_change_payload.get("high_risk") and normalized != "确认执行高风险数据变更":
            return respond(
                "该语句没有 WHERE 条件，可能修改或删除整张表。请明确回复“确认执行高风险数据变更”后平台才会继续。",
                action="confirm_high_risk_data_change", project_id=target.id,
                node_id=data_change_payload.get("node_id"), intent=body.intent,
            )
        try:
            result = _execute_project_data_change(target, sql, db, user, session.id)
        except HTTPException as exc:
            audit(db, user, "ai_update_database", "project", target.id, json.dumps({
                "status": "failed", "sql": sql, "sha256": digest,
                "error": str(exc.detail)[:1000], "chat_session_id": session.id,
                "requested_via": "AI 对话",
            }, ensure_ascii=False))
            db.commit()
            raise
        return respond(
            f"结论：已在“{target.name}”的 {result['engine']} 数据库完成数据变更。\n"
            f"执行结果：{result['result']}\n说明：完整 SQL、操作人、时间和执行结果已写入操作记录。",
            action="updated_database", project_id=target.id,
            node_id=data_change_payload.get("node_id"), intent=None,
        )
    configure_payload = None
    if body.intent and body.intent.startswith("configure:"):
        try:
            configure_payload = json.loads(base64.urlsafe_b64decode(body.intent.split(":", 1)[1].encode()).decode())
        except Exception:
            configure_payload = None
    if configure_payload and confirmed:
        target = db.get(Project, configure_payload.get("project_id"))
        changes = configure_payload.get("changes") or {}
        if not target or not isinstance(changes, dict):
            raise HTTPException(400, "待应用的项目配置已失效")
        current_lines = (decrypt(target.env_text_encrypted) or "").splitlines()
        positions = {line.split("=", 1)[0].strip(): index for index, line in enumerate(current_lines) if "=" in line and not line.lstrip().startswith("#")}
        for key, value in changes.items():
            key = str(key).strip()
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,127}", key):
                raise HTTPException(400, f"配置名称不正确：{key}")
            line = f"{key}={value}"
            if key in positions:
                current_lines[positions[key]] = line
            else:
                current_lines.append(line)
        target.env_text_encrypted = encrypt("\n".join(current_lines).strip() + "\n")
        audit(db, user, "ai_update_project_config", "project", target.id, detail=",".join(sorted(changes)))
        db.commit()
        return respond(f"已更新“{target.name}”的 {len(changes)} 项配置。配置将在下一次发布或重新发布时生效；如需立即应用，请告诉我重新部署到哪个服务器。", action="configured", project_id=target.id, node_id=node_id, intent=None)
    if decision.get("action") == "configure":
        changes = decision.get("config_changes") or {}
        target = db.get(Project, project_id) if project_id else None
        if not target:
            return respond("请先选择要修改配置的项目。", action="none", project_id=project_id, node_id=node_id, intent="configure")
        if not isinstance(changes, dict) or not changes:
            return respond(decision.get("reply") or "请告诉我要修改的配置名称和值，例如：为这个项目设置 REDIS_HOST=192.168.1.20。", action="none", project_id=target.id, node_id=node_id, intent="configure")
        safe_changes = {str(key): str(value) for key, value in changes.items()}
        payload = base64.urlsafe_b64encode(json.dumps({"project_id": target.id, "changes": safe_changes}, ensure_ascii=False).encode()).decode()
        secret_words = ("password", "secret", "token", "key")
        preview = "\n".join(f"- {key}={'******' if any(word in key.lower() for word in secret_words) else value}" for key, value in safe_changes.items())
        return respond(f"准备修改“{target.name}”的项目配置：\n{preview}\n\n这些配置只会写入项目的加密配置，不会立即修改正在运行的容器。回复“确认”后保存。", action="confirm_config", project_id=target.id, node_id=node_id, intent="configure:" + payload)
    wants_migrate = decision.get("action") == "migrate" or any(
        phrase in body.message for phrase in ("执行表结构", "更新表结构", "同步表结构", "应用迁移", "执行迁移", "更新数据库结构")
    )
    if wants_migrate:
        target = db.get(Project, project_id) if project_id else None
        if not target:
            return respond("请先选择要执行表结构更新的项目。", action="none", project_id=project_id, node_id=node_id, intent="migrate")
        plan = _project_migration_plan(target, db)
        pending = [item for item in plan["files"] if not item["applied"]]
        if not pending:
            return respond(
                f"结论：“{target.name}”当前没有待执行的 SQL 迁移文件。\n关键依据：线上版本中的迁移文件均已执行，或源码中没有发现 SQL 文件。",
                action="none", project_id=target.id, node_id=plan["node"].id, intent=None,
            )
        payload = base64.urlsafe_b64encode(json.dumps({
            "project_id": target.id, "node_id": plan["node"].id,
            "files": [{"path": item["path"], "sha256": item["sha256"], "risk": item["risk"]} for item in pending],
        }, ensure_ascii=False).encode()).decode()
        lines = []
        for item in pending[:20]:
            level = "高风险" if item["risk"] == "high" else "常规"
            lines.append(f"- {item['path']}（{item['statements']} 条语句，{level}）")
        if len(pending) > 20:
            lines.append(f"- 另有 {len(pending) - 20} 个文件")
        high_count = sum(1 for item in pending if item["risk"] == "high")
        confirmation = "确认执行高风险表结构" if high_count else "确认执行表结构"
        return respond(
            f"结论：已找到“{target.name}”待执行的 {len(pending)} 个表结构迁移文件。\n"
            + "\n".join(lines)
            + f"\n\n平台会先备份当前表结构，再按文件名顺序执行；文件变化时会自动中止。"
            + (f"其中 {high_count} 个包含删除或清空操作。" if high_count else "")
            + f"\n下一步：回复“{confirmation}”后执行。",
            action="confirm_migration", project_id=target.id, node_id=plan["node"].id,
            intent="migrate:" + payload,
        )
    stop_deployment_id = body.intent.split(":", 1)[1] if body.intent and body.intent.startswith("stop:") else None
    wants_stop = decision.get("action") == "stop" or any(word in body.message for word in ("停止部署", "暂停部署", "中止部署", "取消部署", "停掉部署"))
    if stop_deployment_id and confirmed:
        target_deployment = db.get(Deployment, stop_deployment_id)
        if not target_deployment or (project_id and target_deployment.project_id != project_id):
            raise HTTPException(409, "待停止的部署任务已经变化，请重新发起停止")
        if target_deployment.status not in (DeployStatus.queued, DeployStatus.running):
            return respond("结论：该部署任务已经结束，无需再次停止。", action="none", project_id=target_deployment.project_id, node_id=target_deployment.node_id, intent=None)
        result = stop(target_deployment.id, db, user)
        target_project = db.get(Project, target_deployment.project_id)
        return respond(
            f"结论：已停止“{target_project.name if target_project else '当前项目'}”的部署任务。\n关键依据：平台已终止构建/发布进程并完成残留检查。",
            deployment_id=target_deployment.id, action="stopped", project_id=target_deployment.project_id,
            node_id=target_deployment.node_id, intent=None,
        )
    if wants_stop:
        target_project = db.get(Project, project_id) if project_id else None
        if not target_project:
            return respond("结论：请先选择要停止部署的项目。", action="none", project_id=project_id, node_id=node_id, intent="stop")
        query = select(Deployment).where(
            Deployment.project_id == target_project.id,
            Deployment.status.in_([DeployStatus.queued, DeployStatus.running]),
        )
        if node_id:
            query = query.where(Deployment.node_id == node_id)
        target_deployment = db.scalar(query.order_by(Deployment.created_at.desc()))
        if not target_deployment:
            return respond(f"结论：“{target_project.name}”当前没有进行中的部署任务。", action="none", project_id=target_project.id, node_id=node_id, intent=None)
        target_node = db.get(Node, target_deployment.node_id)
        return respond(
            f"结论：可以停止“{target_project.name}”当前的部署任务。\n关键依据：任务位于 {target_node.name if target_node else '当前服务器'}，当前状态为部署中；停止后现有已上线版本会保留。\n下一步：回复“确认停止”后执行。",
            deployment_id=target_deployment.id, action="confirm_stop", project_id=target_project.id,
            node_id=target_deployment.node_id, intent=f"stop:{target_deployment.id}",
        )
    rollback_deployment_id = body.intent.split(":", 1)[1] if body.intent and body.intent.startswith("rollback:") else None
    wants_rollback = decision.get("action") == "rollback" or any(word in body.message for word in ("回滚", "上个版本", "上一版本", "历史版本", "恢复版本"))
    if rollback_deployment_id and confirmed:
        target_deployment = db.get(Deployment, rollback_deployment_id)
        if not target_deployment or (project_id and target_deployment.project_id != project_id):
            raise HTTPException(409, "待回滚的历史版本已经变化，请重新发起回滚")
        result = rollback_deployment(target_deployment.id, db, user)
        target_project = db.get(Project, target_deployment.project_id)
        return respond(
            f"结论：已将“{target_project.name if target_project else '当前项目'}”回滚到版本 {result['release']}。\n关键依据：平台复用了已验证镜像，完成服务切换并通过访问验证。\n访问地址：{result['access_url']}",
            deployment_id=target_deployment.id, action="rolled_back", project_id=target_deployment.project_id,
            node_id=target_deployment.node_id, intent=None,
        )
    if wants_rollback:
        target_project = db.get(Project, project_id) if project_id else None
        if not target_project:
            return respond("结论：请先选择要回滚的项目。", action="none", project_id=project_id, node_id=node_id, intent="rollback")
        current_query = select(Deployment).where(
            Deployment.project_id == target_project.id,
            Deployment.status == DeployStatus.success,
        )
        if node_id:
            current_query = current_query.where(Deployment.node_id == node_id)
        current_deployment = db.scalar(current_query.order_by(Deployment.created_at.desc()))
        if not current_deployment:
            return respond(f"结论：“{target_project.name}”当前没有在线版本，不能执行回滚；可以重新启用已验证版本。", action="none", project_id=target_project.id, node_id=node_id, intent=None)
        verified_markers = ("[完成] 部署成功", "[启用确认]", "[回滚完成]")
        candidates = db.scalars(select(Deployment).where(
            Deployment.project_id == target_project.id,
            Deployment.node_id == current_deployment.node_id,
            Deployment.id != current_deployment.id,
            Deployment.status == DeployStatus.stopped,
        ).order_by(Deployment.created_at.desc())).all()
        candidates = [item for item in candidates if item.release and item.access_url and any(marker in (item.log_text or "") for marker in verified_markers)]
        requested_release = next((item for item in candidates if item.release and item.release in body.message), None)
        target_deployment = requested_release or (candidates[0] if candidates else None)
        if not target_deployment:
            return respond(f"结论：“{target_project.name}”没有可回滚的已验证历史版本。\n关键依据：失败、构建中止或未通过访问验证的版本不会用于回滚。", action="none", project_id=target_project.id, node_id=current_deployment.node_id, intent=None)
        return respond(
            f"结论：可以将“{target_project.name}”从版本 {current_deployment.release or current_deployment.id[:8]} 回滚到 {target_deployment.release}。\n关键依据：目标是曾成功上线并通过访问验证的版本；平台将直接复用镜像，不重新构建，失败会自动恢复当前线上版本。\n下一步：回复“确认回滚”后执行。",
            deployment_id=target_deployment.id, action="confirm_rollback", project_id=target_project.id,
            node_id=current_deployment.node_id, intent=f"rollback:{target_deployment.id}",
        )
    restart_deployment_id = body.intent.split(":", 1)[1] if body.intent and body.intent.startswith("restart:") else None
    wants_restart = decision.get("action") == "restart" or any(word in body.message for word in ("重启服务", "重启容器", "重启项目", "重启 pod", "重启pod"))
    if restart_deployment_id and confirmed:
        target_deployment = db.get(Deployment, restart_deployment_id)
        if not target_deployment or (project_id and target_deployment.project_id != project_id):
            raise HTTPException(409, "待重启的运行版本已经变化，请重新发起重启")
        result = _restart_deployment_runtime(target_deployment.id, "", db, user)
        target_project = db.get(Project, target_deployment.project_id)
        return respond(
            f"结论：{result['message']}。\n关键依据：平台已在目标服务器执行受控重启，并确认容器恢复运行。",
            action="restarted", project_id=target_deployment.project_id,
            node_id=target_deployment.node_id, intent=None,
        )
    if wants_restart:
        target_project = db.get(Project, project_id) if project_id else None
        if not target_project:
            return respond("结论：请先选择要重启的项目。", action="none", project_id=project_id, node_id=node_id, intent="restart")
        query = select(Deployment).where(
            Deployment.project_id == target_project.id,
            Deployment.status.in_([DeployStatus.success, DeployStatus.stopped]),
        )
        if node_id:
            query = query.where(Deployment.node_id == node_id)
        target_deployment = db.scalar(query.order_by(Deployment.created_at.desc()))
        if not target_deployment:
            return respond(f"结论：没有找到“{target_project.name}”可重启的运行版本。", action="none", project_id=target_project.id, node_id=node_id, intent=None)
        target_node = db.get(Node, target_deployment.node_id)
        snapshot = runtime_snapshot(target_deployment, db)
        containers = [str(row.get("name") or "") for row in snapshot.get("containers", []) if row.get("name")]
        if not containers:
            return respond(f"结论：“{target_project.name}”当前没有可重启的运行容器。\n下一步：如需重新创建容器，请说“重新部署 {target_project.name}”。", action="none", project_id=target_project.id, node_id=target_deployment.node_id, intent=None)
        return respond(
            f"结论：可以重启“{target_project.name}”。\n关键依据：目标服务器为 {target_node.name if target_node else '当前服务器'}，将重启 {len(containers)} 个运行容器。\n下一步：回复“确认重启”后执行，服务会短暂中断，但不会重新构建镜像或覆盖配置。",
            action="confirm_restart", project_id=target_project.id,
            node_id=target_deployment.node_id, intent=f"restart:{target_deployment.id}",
        )
    # A status question such as “部署成功了吗/发布用了多久” contains the
    # same nouns as an execution request.  Trust the model's explicit answer
    # intent first; only use keyword fallback when it could not classify the
    # message at all.
    fallback_deploy_request = (
        decision.get("action") in (None, "", "none")
        and any(x in body.message for x in ("帮我部署", "开始部署", "确认部署", "重新部署", "发布这个", "上线这个"))
    )
    wants_deploy = decision.get("action") == "deploy" or body.intent in ("deploy", "confirm") or fallback_deploy_request
    next_intent = body.intent
    if wants_deploy and (not project_id or not node_id):
        next_intent = "deploy"
        decision["action"] = "none"
        missing = "项目和目标服务器" if not project_id and not node_id else ("项目" if not project_id else "目标服务器")
        decision["reply"] = f"我已记住当前选择，还缺少{missing}。请直接选择或告诉我名称。"
    elif wants_deploy and project_id and node_id and not (body.intent == "confirm" and confirmed):
        project, node = db.get(Project, project_id), db.get(Node, node_id)
        plan = make_deployment_plan(project, node, db)
        port_text = plan["port_mode"] if plan["host_port"] is None else f"内网实例端口 {plan['host_port']} → 容器端口 {plan['container_port'] or '执行时识别'}"
        step_text = "\n".join(f"{index + 1}. {step['title']}：{step['detail']}" for index, step in enumerate(plan["steps"]))
        decision.update({"action": "confirm", "reply": f"发布前分析已完成。\n目标：{plan['project']} → {plan['node']}（{plan['node_address']}）\n构建：{plan['build_mode']}\n端口：{port_text}\n\n执行步骤：\n{step_text}\n\n回复“确认部署”后开始执行。"})
        next_intent = "confirm"
    elif body.intent == "confirm" and confirmed and project_id and node_id:
        decision["action"] = "deploy"
        next_intent = None
    deployment_id = None
    if decision.get("action") == "deploy":
        project, node = db.get(Project, project_id), db.get(Node, node_id)
        if project and node:
            require_reachable_node(node, db)
            active = db.scalar(
                select(Deployment).where(
                    Deployment.project_id == project.id,
                    Deployment.node_id == node.id,
                    Deployment.status.in_([DeployStatus.queued, DeployStatus.running]),
                ).order_by(Deployment.created_at.desc())
            )
            if active:
                return respond(
                    f"该项目在此服务器已有进行中的部署任务 {active.id[:8]}，我没有重复创建。请等待完成或先停止原任务。",
                    deployment_id=active.id,
                    action="existing_deployment",
                    project_id=project.id,
                    node_id=node.id,
                    intent=None,
                )
            plan = make_deployment_plan(project, node, db)
            item = Deployment(project_id=project.id, node_id=node.id, requested_by=user.id, status=DeployStatus.queued, trigger="ai", host_port=plan["host_port"], log_text=plan_log(plan))
            db.add(item)
            db.flush()
            deployment_id = item.id
            audit(db, user, "ai_deploy", "deployment", item.id, body.message)
            db.commit()
            port_text = plan["port_mode"] if plan["host_port"] is None else f"内网实例端口 {plan['host_port']} → 容器端口 {plan['container_port'] or '执行时识别'}"
            step_text = "\n".join(f"{index + 1}. {step['title']}：{step['detail']}" for index, step in enumerate(plan["steps"]))
            decision["reply"] = f"发布前分析已完成。\n目标：{plan['project']} → {plan['node']}（{plan['node_address']}）\n构建：{plan['build_mode']}\n端口：{port_text}\n访问地址：{plan['access_url'] or '部署完成后根据 Compose 配置生成'}\n\n执行步骤：\n{step_text}\n\n任务已进入队列，可在部署记录中查看每一步进度和日志。"
    return respond(decision.get("reply", "已处理"), deployment_id=deployment_id, action=decision.get("action"), project_id=project_id, node_id=node_id, intent=next_intent)


@app.get("/api/audit")
def audit_logs(q: str = "", action: str = "", db: Session = Depends(get_db), _: User = Depends(require(Role.admin))):
    items = db.scalars(select(AuditLog).order_by(desc(AuditLog.created_at)).limit(1000)).all()
    users = {user.id: (user.display_name or user.username) for user in db.scalars(select(User)).all()}
    if action:
        items = [item for item in items if item.action == action]
    keyword = q.strip().lower()
    if keyword:
        items = [item for item in items if keyword in " ".join((
            users.get(item.user_id, "系统任务"), item.action or "", item.target_type or "",
            item.target_id or "", item.detail or "",
        )).lower()]
    return [{"id": x.id, "user_id": x.user_id, "user_name": users.get(x.user_id, "系统任务"), "action": x.action, "target_type": x.target_type, "target_id": x.target_id, "detail": x.detail, "created_at": x.created_at} for x in items[:200]]


def _cleanup_audit_logs(db: Session) -> int:
    days = int(get_security_config(db).audit_retention_days or 0)
    if days <= 0:
        return 0
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    rows = db.scalars(select(AuditLog).where(AuditLog.created_at < cutoff)).all()
    removed = 0
    for row in rows:
        # Retained Docker volumes are discovered from the delete-project audit
        # record, so preserve that record until the retained data is removed.
        if row.action == "delete_project":
            try:
                detail = json.loads(row.detail or "{}")
                if detail.get("data_state") == "retained" and detail.get("retained_volumes"):
                    continue
            except (TypeError, ValueError):
                pass
        db.delete(row)
        removed += 1
    if removed:
        db.commit()
    return removed


@app.get("/api/audit/settings")
def audit_settings(db: Session = Depends(get_db), _: User = Depends(require(Role.admin))):
    return {"retention_days": get_security_config(db).audit_retention_days}


@app.put("/api/audit/settings")
def update_audit_settings(body: dict, db: Session = Depends(get_db), user: User = Depends(require(Role.admin))):
    try:
        days = int(body.get("retention_days", 180))
    except (TypeError, ValueError):
        raise HTTPException(400, "操作记录保留天数不正确")
    if days < 0 or days > 3650:
        raise HTTPException(400, "操作记录保留天数必须为 0 到 3650；0 表示永久保留")
    config = get_security_config(db)
    config.audit_retention_days = days
    audit(db, user, "update_audit_retention", "system", detail=json.dumps({"retention_days": days}, ensure_ascii=False))
    db.commit()
    removed = _cleanup_audit_logs(db)
    return {"retention_days": days, "removed": removed}


@app.get("/api/retained-data")
def retained_data(db: Session = Depends(get_db), _: User = Depends(require(Role.admin))):
    items = db.scalars(select(AuditLog).where(AuditLog.action == "delete_project").order_by(desc(AuditLog.created_at))).all()
    result = []
    for entry in items:
        try:
            detail = json.loads(entry.detail or "{}")
        except Exception:
            continue
        volumes = detail.get("retained_volumes") or []
        if detail.get("data_state") != "retained" or not volumes:
            continue
        result.append({"id": entry.id, "project": detail.get("project", "已删除项目"), "project_slug": detail.get("project_slug", ""), "volumes": volumes, "count": len(volumes), "retained_at": entry.created_at})
    recorded = {
        (volume.get("node_id"), volume.get("name"))
        for item in result for volume in item["volumes"]
    }
    active_slugs = {project.slug for project in db.scalars(select(Project)).all()}
    for node in db.scalars(select(Node).where(Node.enabled == True)).all():
        try:
            with SSHNode(node) as ssh:
                _, output = ssh.run("docker volume ls -q", timeout=20)
                groups: dict[str, list[dict]] = {}
                for name in filter(None, map(str.strip, output.splitlines())):
                    if not name.startswith("yz-") or (node.id, name) in recorded:
                        continue
                    _, label = ssh.run(
                        "docker volume inspect -f " + shlex.quote('{{index .Labels "com.docker.compose.project"}}') + " " + shlex.quote(name),
                        timeout=10,
                    )
                    compose_project = label.strip()
                    inferred = (compose_project[3:] if compose_project.startswith("yz-") else name[3:].split("_", 1)[0])
                    if inferred in active_slugs:
                        continue
                    _, used = ssh.run("docker ps -aq --filter " + shlex.quote(f"volume={name}"), timeout=10)
                    groups.setdefault(inferred or "历史项目", []).append({
                        "name": name,
                        "node_id": node.id,
                        "node": node.name,
                        "in_use": bool(used.strip()),
                    })
                for slug, volumes in groups.items():
                    result.append({
                        "id": f"orphan:{node.id}:{slug}",
                        "project": slug,
                        "project_slug": slug,
                        "volumes": volumes,
                        "count": len(volumes),
                        "retained_at": None,
                        "discovered": True,
                        "in_use": any(volume["in_use"] for volume in volumes),
                    })
        except Exception:
            # One offline node must not hide retained records from other nodes.
            continue
    return result


@app.delete("/api/retained-data/{audit_id}")
def purge_retained_data(audit_id: str, db: Session = Depends(get_db), user: User = Depends(require(Role.admin))):
    if audit_id.startswith("orphan:"):
        try:
            _, node_id, slug = audit_id.split(":", 2)
        except ValueError:
            raise HTTPException(404, "遗留数据记录不存在")
        node = db.get(Node, node_id)
        if not node:
            raise HTTPException(404, "原部署服务器不存在")
        if db.scalar(select(Project).where(Project.slug == slug)):
            raise HTTPException(409, "该项目仍然存在，不能在遗留数据中删除其数据卷")
        prefix = f"yz-{slug}"
        removed = []
        try:
            with SSHNode(node) as ssh:
                _, output = ssh.run("docker volume ls -q", timeout=20)
                for name in filter(None, map(str.strip, output.splitlines())):
                    if not (name == prefix or name.startswith(prefix + "_") or name.startswith(prefix + "-")):
                        _, label = ssh.run("docker volume inspect -f " + shlex.quote('{{index .Labels "com.docker.compose.project"}}') + " " + shlex.quote(name), timeout=10)
                        if label.strip() != prefix:
                            continue
                    _, used = ssh.run("docker ps -aq --filter " + shlex.quote(f"volume={name}"), timeout=10)
                    if used.strip():
                        raise RuntimeError(f"数据卷 {name} 仍被容器使用，请先停止或删除对应容器")
                    code, output = ssh.run("docker volume rm " + shlex.quote(name), timeout=30)
                    if code:
                        raise RuntimeError(output or f"数据卷 {name} 删除失败")
                    removed.append({"name": name, "node": node.name})
        except Exception as exc:
            raise HTTPException(502, f"遗留数据未全部清理：{exc}")
        # AuditLog.target_id is limited to 36 characters.  The synthetic
        # orphan key also contains the project slug, so record the real node
        # id here and keep the complete identity in the JSON detail.
        audit(db, user, "purge_retained_data", "retained_data", node.id, json.dumps({"project": slug, "orphan_id": audit_id, "volumes": removed, "discovered": True}, ensure_ascii=False))
        db.commit()
        return {"ok": True, "summary": f"已彻底删除 {len(removed)} 个遗留数据卷，并完成占用复查"}
    entry = db.get(AuditLog, audit_id)
    if not entry or entry.action != "delete_project":
        raise HTTPException(404, "保留数据记录不存在")
    try:
        detail = json.loads(entry.detail or "{}")
    except Exception:
        raise HTTPException(409, "保留数据记录格式无效")
    volumes = detail.get("retained_volumes") or []
    if detail.get("data_state") != "retained" or not volumes:
        raise HTTPException(409, "这些托管数据已经清理或不存在")
    grouped = {}
    for volume in volumes:
        grouped.setdefault(volume.get("node_id"), []).append(volume.get("name"))
    removed = []
    try:
        for node_id, names in grouped.items():
            node = db.get(Node, node_id)
            if not node:
                raise RuntimeError("原部署服务器已删除，无法执行远程清理")
            safe_names = [name for name in names if name]
            with SSHNode(node) as ssh:
                command = "; ".join(f"docker volume rm -f {shlex.quote(name)}" for name in safe_names) or "true"
                code, output = ssh.run("set -e; " + command, timeout=60)
                if code:
                    raise RuntimeError(output or f"{node.name} 数据卷清理失败")
                verify = "; ".join(f"docker volume inspect {shlex.quote(name)} >/dev/null 2>&1 && exit 23 || true" for name in safe_names) or "true"
                verify_code, verify_output = ssh.run(verify, timeout=30)
                if verify_code:
                    raise RuntimeError(verify_output or f"{node.name} 清理后复查失败")
            removed.extend({"name": name, "node": node.name} for name in safe_names)
    except Exception as exc:
        raise HTTPException(502, f"保留数据未全部清理：{exc}")
    detail["data_state"] = "deleted"
    detail["purged_at"] = datetime.now(timezone.utc).isoformat()
    detail["purged_by"] = user.display_name or user.username
    entry.detail = json.dumps(detail, ensure_ascii=False)
    audit(db, user, "purge_retained_data", "retained_data", entry.id, json.dumps({"project": detail.get("project"), "volumes": removed}, ensure_ascii=False))
    db.commit()
    return {"ok": True, "summary": f"已彻底删除 {len(removed)} 个平台托管数据卷，并完成复查"}

