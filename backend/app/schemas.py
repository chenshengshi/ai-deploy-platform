from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from .models import AuthType, DeployStatus, Role, SourceType


class ORM(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class LoginIn(BaseModel):
    username: str
    password: str


class PasswordChange(BaseModel):
    current_password: str
    new_password: str = Field(min_length=8, max_length=128)


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    display_name: str = ""
    password: str = Field(min_length=8)
    role: Role = Role.viewer


class UserUpdate(BaseModel):
    username: str | None = Field(default=None, min_length=3, max_length=64)
    display_name: str | None = None
    password: str | None = Field(default=None, min_length=8)
    role: Role | None = None
    active: bool | None = None


class UserProjectsUpdate(BaseModel):
    project_ids: list[str] = Field(default_factory=list, max_length=500)


class UserProjectSummary(BaseModel):
    id: str
    name: str
    slug: str
    permission: str


class UserOut(ORM):
    id: str
    username: str
    display_name: str
    role: Role
    active: bool
    failed_login_attempts: int = 0
    locked_until: datetime | None = None
    created_at: datetime
    project_count: int = 0
    project_scope: str = "owned"
    projects: list[UserProjectSummary] = Field(default_factory=list)


class NodeIn(BaseModel):
    name: str
    host: str
    port: int = 22
    username: str = "root"
    auth_type: AuthType = AuthType.password
    secret: str | None = None
    public_address: str | None = None
    work_dir: str = "/data/yunzhou/projects"
    docker_proxy_enabled: bool = False


class NodeOut(ORM):
    id: str
    name: str
    host: str
    port: int
    username: str
    auth_type: AuthType
    public_address: str | None
    work_dir: str
    docker_proxy_enabled: bool
    docker_proxy_status: str
    docker_proxy_error: str | None
    enabled: bool
    last_status: str
    last_error: str | None
    created_at: datetime


class NodeUpdate(BaseModel):
    name: str
    host: str
    port: int = 22
    username: str = "root"
    auth_type: AuthType = AuthType.password
    secret: str | None = None
    public_address: str | None = None
    work_dir: str = "/data/yunzhou/projects"
    docker_proxy_enabled: bool = False


class NodeTest(NodeUpdate):
    node_id: str | None = None


class CredentialIn(BaseModel):
    name: str
    auth_type: Literal["token", "password", "ssh_key"] = "token"
    username: str | None = None
    secret: str


class CredentialOut(ORM):
    id: str
    name: str
    auth_type: str
    username: str | None
    created_at: datetime


class GitConnectionTest(BaseModel):
    git_url: str
    git_branch: str = "main"
    credential_id: str | None = None


class ProjectGitRepository(BaseModel):
    git_url: str
    git_branch: str = "main"
    credential_id: str | None = None
    role: Literal["frontend", "backend", "other"] = "other"
    target_dir: str = Field(default="", max_length=120)


class ProjectCreate(BaseModel):
    name: str
    slug: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{1,62}$")
    description: str = ""
    source_type: SourceType = SourceType.upload
    git_url: str | None = None
    git_branch: str = "main"
    git_credential_id: str | None = None
    git_repositories: list[ProjectGitRepository] = Field(default_factory=list, max_length=10)
    build_type: Literal["auto", "compose", "dockerfile"] = "auto"
    container_port: int | None = None
    host_port: int | None = None
    domain: str | None = None
    env_text: str | None = None
    deployment_mode: Literal["managed_fresh", "preserve_integrations"] = "managed_fresh"


class ProjectUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    domain: str | None = Field(default=None, max_length=255)
    container_port: int | None = Field(default=None, ge=1, le=65535)
    host_port: int | None = Field(default=None, ge=1, le=65535)
    load_balance_enabled: bool | None = None
    replica_count: int | None = Field(default=None, ge=1, le=10)
    load_balance_strategy: Literal["round_robin", "least_conn", "ip_hash"] | None = None
    deployment_mode: Literal["managed_fresh", "preserve_integrations"] | None = None
    image_retention_count: int | None = Field(default=None, ge=1, le=100)
    git_url: str | None = None
    git_branch: str | None = Field(default=None, max_length=100)
    git_repositories: list[ProjectGitRepository] | None = None


class ProjectOut(ORM):
    id: str
    name: str
    slug: str
    description: str
    source_type: SourceType
    source_path: str | None
    git_url: str | None
    git_branch: str
    git_credential_id: str | None
    git_repositories: list[dict] = Field(default_factory=list)
    build_type: str
    container_port: int | None
    host_port: int | None
    load_balance_enabled: bool
    replica_count: int
    load_balance_strategy: str
    deployment_mode: str
    image_retention_count: int
    domain: str | None
    owner_id: str
    created_at: datetime
    source_analysis: dict | None = None


class DeployIn(BaseModel):
    node_id: str
    name: str | None = Field(default=None, min_length=1, max_length=120)
    domain: str | None = Field(default=None, max_length=255)
    container_port: int | None = Field(default=None, ge=1, le=65535)
    host_port: int | None = Field(default=None, ge=1, le=65535)
    load_balance_enabled: bool | None = None
    replica_count: int | None = Field(default=None, ge=1, le=10)
    load_balance_strategy: Literal["round_robin", "least_conn", "ip_hash"] | None = None
    deployment_mode: Literal["managed_fresh", "preserve_integrations"] | None = None
    env_text: str | None = None


class ScaleProjectIn(BaseModel):
    replicas: int = Field(ge=1, le=10)


class DeploymentOut(ORM):
    id: str
    project_id: str
    node_id: str
    requested_by: str
    status: DeployStatus
    trigger: str
    release: str | None
    container_name: str | None
    image_name: str | None
    host_port: int | None
    access_url: str | None
    log_text: str
    error: str | None
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None


class DeploymentSettingsIn(BaseModel):
    global_concurrency: int = Field(default=3, ge=1, le=20)
    per_node_concurrency: int = Field(default=2, ge=1, le=10)
    analysis_concurrency: int = Field(default=2, ge=1, le=8)
    connection_timeout_seconds: int = Field(default=6, ge=2, le=30)
    external_port_start: int = Field(default=20000, ge=1024, le=65535)
    external_port_end: int = Field(default=21000, ge=1024, le=65535)
    internal_port_start: int = Field(default=30000, ge=1024, le=65535)
    internal_port_end: int = Field(default=39999, ge=1024, le=65535)
    default_domain_http_port: int = Field(default=80, ge=1, le=65535)
    default_domain_https_port: int = Field(default=443, ge=1, le=65535)
    registry_mirrors_text: str = Field(default="", max_length=8000)
    registry_retention_count: int = Field(default=5, ge=1, le=100)
    registry_auto_cleanup: bool = True
    registry_endpoint: str = Field(default="yunzhou.hub:5000", min_length=3, max_length=255)
    registry_namespace: str = Field(default="yunzhou", min_length=1, max_length=100, pattern=r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$")
    build_cache_root: str = Field(default="/data/yunzhou/builder/cache", min_length=1, max_length=500)
    maven_cache_dir: str = Field(default="/root/.m2", min_length=1, max_length=255)
    gradle_cache_dir: str = Field(default="/home/gradle/.gradle", min_length=1, max_length=255)
    npm_cache_dir: str = Field(default="/root/.npm", min_length=1, max_length=255)
    pnpm_cache_dir: str = Field(default="/root/.local/share/pnpm/store", min_length=1, max_length=255)
    yarn_cache_dir: str = Field(default="/root/.cache/yarn", min_length=1, max_length=255)
    pip_cache_dir: str = Field(default="/root/.cache/pip", min_length=1, max_length=255)
    default_nginx_image: str = Field(default="nginx:1.30.3-alpine", min_length=3, max_length=255)
    default_redis_image: str = Field(default="redis:7.4-alpine", min_length=3, max_length=255)
    default_mysql_image: str = Field(default="mysql:8.4", min_length=3, max_length=255)
    default_postgres_image: str = Field(default="postgres:16", min_length=3, max_length=255)


class DeploymentSettingsOut(ORM):
    global_concurrency: int
    per_node_concurrency: int
    analysis_concurrency: int
    connection_timeout_seconds: int
    external_port_start: int
    external_port_end: int
    internal_port_start: int
    internal_port_end: int
    default_domain_http_port: int
    default_domain_https_port: int
    registry_mirrors_text: str
    registry_retention_count: int
    registry_auto_cleanup: bool
    registry_endpoint: str
    registry_namespace: str
    build_cache_root: str
    maven_cache_dir: str
    gradle_cache_dir: str
    npm_cache_dir: str
    pnpm_cache_dir: str
    yarn_cache_dir: str
    pip_cache_dir: str
    default_nginx_image: str
    default_redis_image: str
    default_mysql_image: str
    default_postgres_image: str
    updated_at: datetime


class BrandingSettingsIn(BaseModel):
    system_name: str = Field(default="自助发布平台", min_length=1, max_length=100)
    short_name: str = Field(default="自助发布", min_length=1, max_length=40)
    system_subtitle: str = Field(default="应用交付平台", max_length=120)
    login_slogan: str = Field(default="一句话，把项目安全发布到服务器", max_length=200)
    logo_data_url: str = Field(default="", max_length=1_500_000)
    favicon_data_url: str = Field(default="", max_length=500_000)


class BrandingSettingsOut(BrandingSettingsIn):
    pass


class SecuritySettingsIn(BaseModel):
    min_password_length: int = Field(default=10, ge=8, le=128)
    password_history_count: int = Field(default=0, ge=0, le=24)
    require_lowercase: bool = True
    require_uppercase: bool = True
    require_digit: bool = True
    require_special: bool = True
    max_repeated_chars: int = Field(default=3, ge=0, le=20)
    password_max_age_days: int = Field(default=0, ge=0, le=3650)
    password_min_age_days: int = Field(default=0, ge=0, le=30)
    login_max_attempts: int = Field(default=5, ge=1, le=50)
    login_lock_minutes: int = Field(default=15, ge=1, le=1440)
    expiry_reminder_days: int = Field(default=0, ge=0, le=365)
    session_timeout_minutes: int = Field(default=60, ge=5, le=10080)
    audit_retention_days: int = Field(default=180, ge=0, le=3650)
    china_ip_allowlist_enabled: bool = False
    china_ip_source_url: str = Field(default="https://ispip.clang.cn/all_cn_cidr.html", min_length=1, max_length=500)


class SecuritySettingsOut(SecuritySettingsIn):
    china_ip_count: int = 0
    source_updated_at: datetime | None = None
    updated_at: datetime | None = None


class AiConfigIn(BaseModel):
    provider_name: str = "OpenAI 兼容接口"
    base_url: str
    model: str
    api_key: str | None = None
    enabled: bool = True


class AiConfigOut(BaseModel):
    id: str
    provider_name: str
    base_url: str
    model: str
    enabled: bool
    is_default: bool = False
    has_api_key: bool


class ProxyConfigIn(BaseModel):
    enabled: bool = False
    http_proxy: str = ""
    https_proxy: str = ""
    proxy_username: str = ""
    proxy_password: str = ""
    no_proxy: str = "localhost,127.0.0.1,db,api,worker,web,registry,yunzhou.hub,yunzhou.hub:5000"


class ProxyConfigOut(BaseModel):
    id: str | None = None
    enabled: bool = False
    http_proxy: str = ""
    https_proxy: str = ""
    proxy_username: str = ""
    has_proxy_password: bool = False
    no_proxy: str = "localhost,127.0.0.1,db,api,worker,web,registry,yunzhou.hub,yunzhou.hub:5000"
    source: str = "系统数据库"


class ChatIn(BaseModel):
    message: str
    project_id: str | None = None
    node_id: str | None = None
    ai_config_id: str | None = None
    intent: str | None = None
    history: list[dict[str, str]] = Field(default_factory=list)
    session_id: str | None = None


class ChatOut(BaseModel):
    reply: str
    deployment_id: str | None = None
    action: str | None = None
    project_id: str | None = None
    node_id: str | None = None
    intent: str | None = None
    session_id: str | None = None


class SqlConsoleIn(BaseModel):
    sql: str = Field(min_length=1, max_length=100_000)
    confirm_token: str | None = None
    confirmation: str | None = None

