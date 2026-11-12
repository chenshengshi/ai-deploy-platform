import enum
import json
import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


def uid() -> str:
    return str(uuid.uuid4())


def now() -> datetime:
    return datetime.now(timezone.utc)


class Role(str, enum.Enum):
    admin = "admin"
    deployer = "deployer"
    viewer = "viewer"


class SourceType(str, enum.Enum):
    upload = "upload"
    git = "git"


class AuthType(str, enum.Enum):
    password = "password"
    ssh_key = "ssh_key"


class DeployStatus(str, enum.Enum):
    queued = "queued"
    running = "running"
    success = "success"
    failed = "failed"
    stopped = "stopped"


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(128), default="")
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[Role] = mapped_column(Enum(Role), default=Role.viewer)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    failed_login_attempts: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    password_changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class PasswordHistory(Base):
    __tablename__ = "password_history"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class ProjectAccess(Base):
    __tablename__ = "project_access"
    __table_args__ = (UniqueConstraint("project_id", "user_id", name="uq_project_access_project_user"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class SecurityConfig(Base):
    __tablename__ = "security_config"
    id: Mapped[str] = mapped_column(String(20), primary_key=True, default="default")
    min_password_length: Mapped[int] = mapped_column(Integer, default=10)
    password_history_count: Mapped[int] = mapped_column(Integer, default=0)
    require_lowercase: Mapped[bool] = mapped_column(Boolean, default=True)
    require_uppercase: Mapped[bool] = mapped_column(Boolean, default=True)
    require_digit: Mapped[bool] = mapped_column(Boolean, default=True)
    require_special: Mapped[bool] = mapped_column(Boolean, default=True)
    max_repeated_chars: Mapped[int] = mapped_column(Integer, default=3)
    password_max_age_days: Mapped[int] = mapped_column(Integer, default=0)
    password_min_age_days: Mapped[int] = mapped_column(Integer, default=0)
    login_max_attempts: Mapped[int] = mapped_column(Integer, default=5)
    login_lock_minutes: Mapped[int] = mapped_column(Integer, default=15)
    expiry_reminder_days: Mapped[int] = mapped_column(Integer, default=0)
    session_timeout_minutes: Mapped[int] = mapped_column(Integer, default=60)
    audit_retention_days: Mapped[int] = mapped_column(Integer, default=180)
    china_ip_allowlist_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    china_ip_source_url: Mapped[str] = mapped_column(String(500), default="https://ispip.clang.cn/all_cn_cidr.html")
    china_ip_cidrs: Mapped[str] = mapped_column(Text, default="")
    source_updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, onupdate=now)


class Node(Base):
    __tablename__ = "nodes"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    name: Mapped[str] = mapped_column(String(100), unique=True)
    host: Mapped[str] = mapped_column(String(255))
    port: Mapped[int] = mapped_column(Integer, default=22)
    username: Mapped[str] = mapped_column(String(100), default="root")
    auth_type: Mapped[AuthType] = mapped_column(Enum(AuthType), default=AuthType.password)
    secret_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    public_address: Mapped[str | None] = mapped_column(String(255), nullable=True)
    work_dir: Mapped[str] = mapped_column(String(255), default="/data/yunzhou/projects")
    docker_proxy_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    docker_proxy_status: Mapped[str] = mapped_column(String(32), default="disabled")
    docker_proxy_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_status: Mapped[str] = mapped_column(String(32), default="unknown")
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    deployments: Mapped[list["Deployment"]] = relationship(back_populates="node")


class GitCredential(Base):
    __tablename__ = "git_credentials"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    name: Mapped[str] = mapped_column(String(100), unique=True)
    auth_type: Mapped[str] = mapped_column(String(32), default="token")
    username: Mapped[str | None] = mapped_column(String(255), nullable=True)
    secret_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Project(Base):
    __tablename__ = "projects"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    name: Mapped[str] = mapped_column(String(120))
    slug: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    source_type: Mapped[SourceType] = mapped_column(Enum(SourceType), default=SourceType.upload)
    source_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    git_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    git_branch: Mapped[str] = mapped_column(String(100), default="main")
    git_credential_id: Mapped[str | None] = mapped_column(ForeignKey("git_credentials.id"), nullable=True)
    git_repositories_json: Mapped[str] = mapped_column(Text, default="[]")
    build_type: Mapped[str] = mapped_column(String(32), default="auto")
    container_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    host_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    load_balance_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    replica_count: Mapped[int] = mapped_column(Integer, default=2)
    load_balance_strategy: Mapped[str] = mapped_column(String(32), default="round_robin")
    deployment_mode: Mapped[str] = mapped_column(String(32), default="managed_fresh")
    image_retention_count: Mapped[int] = mapped_column(Integer, default=5)
    domain: Mapped[str | None] = mapped_column(String(255), nullable=True)
    managed_env_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    env_text_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    integration_analysis_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    data_exposure_json: Mapped[str] = mapped_column(Text, default="{}")
    runtime_image_overrides_json: Mapped[str] = mapped_column(Text, default="{}")
    owner_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    deployments: Mapped[list["Deployment"]] = relationship(back_populates="project", cascade="all,delete")

    @property
    def source_analysis(self) -> dict | None:
        if not self.integration_analysis_json:
            return None
        try:
            value = json.loads(self.integration_analysis_json)
            return value if isinstance(value, dict) else None
        except (TypeError, ValueError):
            return None

    @property
    def git_repositories(self) -> list[dict]:
        try:
            value = json.loads(self.git_repositories_json or "[]")
            return [row for row in value if isinstance(row, dict)] if isinstance(value, list) else []
        except (TypeError, ValueError):
            return []

    @property
    def runtime_image_overrides(self) -> dict:
        try:
            value = json.loads(self.runtime_image_overrides_json or "{}")
            return value if isinstance(value, dict) else {}
        except (TypeError, ValueError):
            return {}


class ChatSession(Base):
    __tablename__ = "chat_sessions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    owner_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    project_id: Mapped[str | None] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), nullable=True, index=True)
    node_id: Mapped[str | None] = mapped_column(ForeignKey("nodes.id", ondelete="SET NULL"), nullable=True)
    ai_config_id: Mapped[str | None] = mapped_column(ForeignKey("ai_configs.id", ondelete="SET NULL"), nullable=True, index=True)
    title: Mapped[str] = mapped_column(String(160), default="新对话")
    visibility: Mapped[str] = mapped_column(String(24), default="private")
    archived: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, onupdate=now)
    messages: Mapped[list["ChatMessage"]] = relationship(back_populates="session", cascade="all,delete-orphan")


class ChatMessage(Base):
    __tablename__ = "chat_messages"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    session_id: Mapped[str] = mapped_column(ForeignKey("chat_sessions.id", ondelete="CASCADE"), index=True)
    role: Mapped[str] = mapped_column(String(24))
    content: Mapped[str] = mapped_column(Text)
    action: Mapped[str | None] = mapped_column(String(64), nullable=True)
    deployment_id: Mapped[str | None] = mapped_column(ForeignKey("deployments.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    session: Mapped[ChatSession] = relationship(back_populates="messages")


class ProjectDomainConfig(Base):
    __tablename__ = "project_domain_configs"
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), primary_key=True)
    http_port: Mapped[int] = mapped_column(Integer, default=80)
    https_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    https_port: Mapped[int] = mapped_column(Integer, default=443)
    redirect_https: Mapped[bool] = mapped_column(Boolean, default=True)
    gateway_mode: Mapped[str] = mapped_column(String(24), default="auto")
    custom_routes_json: Mapped[str] = mapped_column(Text, default="[]")
    proxy_read_timeout: Mapped[int] = mapped_column(Integer, default=300)
    client_max_body_mb: Mapped[int] = mapped_column(Integer, default=50)
    certificate_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    private_key_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    certificate_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    certificate_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, onupdate=now)


class CertificateStore(Base):
    __tablename__ = "certificate_store"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    name: Mapped[str] = mapped_column(String(255))
    domains_json: Mapped[str] = mapped_column(Text, default="[]")
    fingerprint: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    certificate_encrypted: Mapped[str] = mapped_column(Text)
    private_key_encrypted: Mapped[str] = mapped_column(Text)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, onupdate=now)


class Deployment(Base):
    __tablename__ = "deployments"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), index=True)
    node_id: Mapped[str] = mapped_column(ForeignKey("nodes.id"), index=True)
    requested_by: Mapped[str] = mapped_column(ForeignKey("users.id"))
    status: Mapped[DeployStatus] = mapped_column(Enum(DeployStatus), default=DeployStatus.queued, index=True)
    trigger: Mapped[str] = mapped_column(String(32), default="manual")
    release: Mapped[str | None] = mapped_column(String(64), nullable=True)
    container_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    image_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    host_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    access_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    login_info_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    log_text: Mapped[str] = mapped_column(Text, default="")
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    project: Mapped[Project] = relationship(back_populates="deployments")
    node: Mapped[Node] = relationship(back_populates="deployments")


class DeploymentExperience(Base):
    """Sanitized deployment knowledge with an explicit validation lifecycle."""
    __tablename__ = "deployment_experiences"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    signature: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    category: Mapped[str] = mapped_column(String(64), default="unknown", index=True)
    error_sample: Mapped[str] = mapped_column(Text, default="")
    repair_summary: Mapped[str] = mapped_column(Text, default="")
    occurrences: Mapped[int] = mapped_column(Integer, default=1)
    successful_repairs: Mapped[int] = mapped_column(Integer, default=0)
    failed_repairs: Mapped[int] = mapped_column(Integer, default=0)
    verified: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    state: Mapped[str] = mapped_column(String(24), default="candidate", index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    stage: Mapped[str] = mapped_column(String(32), default="deployment", index=True)
    scope_tags: Mapped[str] = mapped_column(Text, default="[]")
    confidence: Mapped[int] = mapped_column(Integer, default=0)
    use_count: Mapped[int] = mapped_column(Integer, default=0)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, onupdate=now)
    last_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ProjectReplica(Base):
    __tablename__ = "project_replicas"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    deployment_id: Mapped[str] = mapped_column(ForeignKey("deployments.id", ondelete="CASCADE"), index=True)
    node_id: Mapped[str] = mapped_column(ForeignKey("nodes.id"), index=True)
    container_name: Mapped[str] = mapped_column(String(255), unique=True)
    host_port: Mapped[int] = mapped_column(Integer)
    # Replicas are grouped by the Compose service they belong to.  Empty
    # values are kept for rows created by older versions and mean the legacy
    # public-entry pool.
    service_name: Mapped[str] = mapped_column(String(120), default="")
    pool_role: Mapped[str] = mapped_column(String(32), default="entry")
    container_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="running")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class DeploymentPortReservation(Base):
    """Every host port owned by a deployment, including Compose side services.

    Deployment.host_port stores only the public entry service.  Multi-service
    Compose releases can publish additional backend ports, which must also be
    reserved while concurrent releases are being prepared.
    """
    __tablename__ = "deployment_port_reservations"
    __table_args__ = (UniqueConstraint("node_id", "host_port", name="uq_deployment_port_node_host"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    deployment_id: Mapped[str] = mapped_column(ForeignKey("deployments.id", ondelete="CASCADE"), index=True)
    node_id: Mapped[str] = mapped_column(ForeignKey("nodes.id", ondelete="CASCADE"), index=True)
    service_name: Mapped[str] = mapped_column(String(120), default="")
    host_port: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(24), default="reserved", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class AiConfig(Base):
    __tablename__ = "ai_configs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    provider_name: Mapped[str] = mapped_column(String(100), default="OpenAI 兼容接口")
    base_url: Mapped[str] = mapped_column(String(255), default="https://api.openai.com/v1")
    model: Mapped[str] = mapped_column(String(100), default="gpt-4.1-mini")
    api_key_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    is_default: Mapped[bool] = mapped_column(Boolean, default=False, index=True)


class SystemProxy(Base):
    __tablename__ = "system_proxy"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    http_proxy: Mapped[str] = mapped_column(String(500), default="")
    https_proxy: Mapped[str] = mapped_column(String(500), default="")
    proxy_username: Mapped[str] = mapped_column(String(255), default="")
    proxy_password_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    no_proxy: Mapped[str] = mapped_column(Text, default="localhost,127.0.0.1,db,api,worker,web,registry,yunzhou.hub,yunzhou.hub:5000")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, onupdate=now)


class DeploymentSettings(Base):
    __tablename__ = "deployment_settings"
    id: Mapped[str] = mapped_column(String(20), primary_key=True, default="default")
    global_concurrency: Mapped[int] = mapped_column(Integer, default=3)
    per_node_concurrency: Mapped[int] = mapped_column(Integer, default=2)
    analysis_concurrency: Mapped[int] = mapped_column(Integer, default=2)
    connection_timeout_seconds: Mapped[int] = mapped_column(Integer, default=6)
    external_port_start: Mapped[int] = mapped_column(Integer, default=20000)
    external_port_end: Mapped[int] = mapped_column(Integer, default=21000)
    internal_port_start: Mapped[int] = mapped_column(Integer, default=30000)
    internal_port_end: Mapped[int] = mapped_column(Integer, default=39999)
    default_domain_http_port: Mapped[int] = mapped_column(Integer, default=80)
    default_domain_https_port: Mapped[int] = mapped_column(Integer, default=443)
    registry_mirrors_text: Mapped[str] = mapped_column(Text, default="")
    registry_retention_count: Mapped[int] = mapped_column(Integer, default=5)
    registry_auto_cleanup: Mapped[bool] = mapped_column(Boolean, default=True)
    registry_endpoint: Mapped[str] = mapped_column(String(255), default="yunzhou.hub:5000")
    registry_namespace: Mapped[str] = mapped_column(String(100), default="yunzhou")
    build_cache_root: Mapped[str] = mapped_column(String(500), default="/data/yunzhou/builder/cache")
    maven_cache_dir: Mapped[str] = mapped_column(String(255), default="/root/.m2")
    gradle_cache_dir: Mapped[str] = mapped_column(String(255), default="/home/gradle/.gradle")
    npm_cache_dir: Mapped[str] = mapped_column(String(255), default="/root/.npm")
    pnpm_cache_dir: Mapped[str] = mapped_column(String(255), default="/root/.local/share/pnpm/store")
    yarn_cache_dir: Mapped[str] = mapped_column(String(255), default="/root/.cache/yarn")
    pip_cache_dir: Mapped[str] = mapped_column(String(255), default="/root/.cache/pip")
    default_nginx_image: Mapped[str] = mapped_column(String(255), default="nginx:1.30.3-alpine")
    default_redis_image: Mapped[str] = mapped_column(String(255), default="redis:7.4-alpine")
    default_mysql_image: Mapped[str] = mapped_column(String(255), default="mysql:8.4")
    default_postgres_image: Mapped[str] = mapped_column(String(255), default="postgres:16")
    system_name: Mapped[str] = mapped_column(String(100), default="自助发布平台")
    short_name: Mapped[str] = mapped_column(String(40), default="自助发布")
    system_subtitle: Mapped[str] = mapped_column(String(120), default="应用交付平台")
    login_slogan: Mapped[str] = mapped_column(String(200), default="一句话，把项目安全发布到服务器")
    logo_data_url: Mapped[str] = mapped_column(Text, default="")
    favicon_data_url: Mapped[str] = mapped_column(Text, default="")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, onupdate=now)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    user_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    action: Mapped[str] = mapped_column(String(100))
    target_type: Mapped[str] = mapped_column(String(50), default="")
    target_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    detail: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)

