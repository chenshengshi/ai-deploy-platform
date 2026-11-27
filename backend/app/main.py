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
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from zoneinfo import ZoneInfo
from urllib.parse import quote, urlsplit, urlunsplit

import httpx
from cryptography import x509
from cryptography.x509.oid import NameOID
from fastapi import BackgroundTasks, Depends, FastAPI, File, Form, HTTPException, Request, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response
from sqlalchemy import desc, func, or_, select, text
from sqlalchemy.orm import Session
from jose import JWTError, jwt

from .ai import analyze_delete_scope, analyze_project_deployment, deployment_followup, reconcile_followup_live_state, understand
from .archive_utils import safe_extract_zip
from .audit import audit, cleanup_audit_logs as _cleanup_audit_logs
from .audit_routes import router as audit_routes_router
from .auth import SESSION_COOKIE_NAME, current_user, hash_password, require, token_for, user_from_token, verify_password
from .backup import router as backup_router, start_backup_scheduler
from .bootstrap.startup import startup
from .certificates import _certificate_view, _domain_matches_pattern, _matching_certificates, _save_shared_certificate, _validated_certificate_material
from .chat.diagnostics import deployment_from_message_url, diagnose_blank_frontend
from .chat.external_services import extract_external_mysql_config
from .chat.intents import explicit_project_match, fallback_action_from_message, fuzzy_project_match, is_confirmation, normalize_message
from .chat.responses import format_failure_diagnosis
from .chat.sessions import chat_session_dict, chat_session_for_user
from .chat.status_queries import asks_active_deployment_summary
from .chat.deployment_followup import deployment_ai_followup_service
from .chat.routes import router as chat_routes_router
from .chat.service import chat_service
from .config import decrypt, encrypt, settings
from .database import Base, SessionLocal, engine, get_db
from .project_data.sql_safety import data_change_confirmation_token, extract_direct_sql, high_risk_matches, is_high_risk_sql, sql_kind
from .deployment.logs import deployment_log_path, read_deployment_log
from .deployment.log_rendering import compact_docker_pull_log
from .deployment.lifecycle import can_switch_to_release, is_verified_release
from .deployment.pipeline_view import render_pipeline_steps
from .deployer import _complete_source_compose, cleanup_registry_versions, choose_port, compose_project_name, configure_platform_gateway, delete_deployment_resources, deployment_compose_project_name, detect_frontend_api_routes, effective_project_environment, environment_values, external_integration_preflight, git_source_location, platform_gateway_node, preflight_ai_deployment_plan, project_directory, reconcile_runtime_frontend_routes, remove_project_managed_data_service, stage_source, start_deployment, stop_deployment, stop_project_data_services, verify_access
from .experience import contains_corruption, portable_experience, prepare_new_experience
from .login_security import clear_login_failures, enforce_login_source_limit, login_source_ip as _login_source_ip, record_login_failure
from .models import AiConfig, AuditLog, CertificateStore, ChatMessage, ChatSession, DeployStatus, Deployment, DeploymentExperience, DeploymentPortReservation, DeploymentSettings, GitCredential, Node, PasswordHistory, Project, ProjectAccess, ProjectDomainConfig, ProjectReplica, Role, SecurityConfig, SourceType, SystemProxy, User
from .proxy import get_proxy_config, proxy_for, proxy_with_auth, redact_proxy
from .runtime_cache import invalidate_runtime_cache, read_runtime_cache as _runtime_cache_read, runtime_cache_key as _runtime_cache_key, runtime_cache_lock, write_runtime_cache as _runtime_cache_write
from .deployment.runtime_snapshot import runtime_snapshot
from .deployment.settings import get_deployment_settings
from .deployment.view_service import deployment_view, make_deployment_plan
from .deployment.scaling import scale_project_service_all, scale_single_service
from .deployment.launch_config import deployment_launch_config_service
from .deployment.container_access import (
    _container_access,
    _container_browser_run,
    router as container_access_router,
)
from .deployment.registry import (
    _delete_project_registry_repositories,
    _project_registry_repositories,
    _registry_request,
    router as registry_router,
)
from .deployment.deletion import router as deployment_deletion_router
from .project_data.integration_analysis import analyze_project_integrations_service, _source_workspace_metadata
from .project_data.database_operations import (
    _execute_project_data_change,
    _execute_project_migrations,
    _project_migration_plan,
    _query_project_database,
)
from .project_data.deletion import router as project_deletion_router
from .system_settings.ai import router as ai_settings_router
from .runtime_scaling import _next_service_instance_name, _replicas_for_scale_down, _service_instance_prefix, _service_instance_sequence
from .runtime_topology import _NON_SCALABLE_SERVICES, _route_groups_for_services, _runtime_entry_is_data, _runtime_entry_is_running, _service_role, _traffic_plan
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
    UserProjectsUpdate,
    UserUpdate,
)
from .ssh import SSHNode, ensure_node_runtime, test_node


@asynccontextmanager
async def lifespan(_: FastAPI):
    startup()
    yield


app = FastAPI(title=settings.app_name, docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[value.strip().rstrip("/") for value in settings.cors_origins.split(",") if value.strip()],
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)
app.include_router(backup_router)
app.include_router(container_access_router)
app.include_router(registry_router)
app.include_router(project_deletion_router)
app.include_router(deployment_deletion_router)
app.include_router(chat_routes_router)
app.include_router(ai_settings_router)
app.include_router(audit_routes_router)


@app.post("/api/chat", response_model=ChatOut)
def chat(body: ChatIn, db: Session = Depends(get_db), user: User = Depends(require(Role.admin, Role.deployer))):
    return chat_service(
        body,
        db,
        user,
        restart_deployment_runtime=_restart_deployment_runtime,
        plan_log=plan_log,
        require_reachable_node=require_reachable_node,
        rollback_deployment=rollback_deployment,
        start_stopped_deployment=start_stopped_deployment,
        stop_deployment_action=stop,
        validate_external_integrations_for_deploy=validate_external_integrations_for_deploy,
    )


def _request_user(request: Request, db: Session) -> User | None:
    authorization = request.headers.get("authorization", "")
    token = (
        authorization.split(" ", 1)[1].strip()
        if authorization.lower().startswith("bearer ")
        else request.cookies.get(SESSION_COOKIE_NAME)
    )
    try:
        return user_from_token(token, db)
    except HTTPException:
        return None


def _user_can_access_project(db: Session, user: User, project_id: str) -> bool:
    if user.role == Role.admin:
        return True
    return bool(db.scalar(select(Project.id).where(
        Project.id == project_id,
        (Project.owner_id == user.id) | Project.id.in_(select(ProjectAccess.project_id).where(ProjectAccess.user_id == user.id)),
    )))


def _user_can_access_deployment(db: Session, user: User, deployment_id: str) -> bool:
    if user.role == Role.admin:
        return True
    project_id = db.scalar(
        select(Project.id)
        .join(Deployment, Deployment.project_id == Project.id)
        .where(
            Deployment.id == deployment_id,
            (Project.owner_id == user.id) | Project.id.in_(select(ProjectAccess.project_id).where(ProjectAccess.user_id == user.id)),
        )
    )
    return bool(project_id)


@app.middleware("http")
async def enforce_project_ownership(request: Request, call_next):
    """Apply object ownership to every project/deployment HTTP endpoint."""
    project_match = re.match(r"^/api/projects/([^/]+)(?:/|$)", request.url.path)
    deployment_match = re.match(r"^/api/deployments/([^/]+)(?:/|$)", request.url.path)
    if project_match or deployment_match:
        with SessionLocal() as db:
            user = _request_user(request, db)
            allowed = True
            if user and project_match:
                allowed = _user_can_access_project(db, user, project_match.group(1))
            elif user and deployment_match:
                allowed = _user_can_access_deployment(db, user, deployment_match.group(1))
            if user and not allowed:
                return JSONResponse(status_code=404, content={"detail": "资源不存在"})
    return await call_next(request)


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


@app.post("/api/auth/login", response_model=TokenOut)
def login(body: LoginIn, request: Request, response: Response, db: Session = Depends(get_db)):
    source_ip = _login_source_ip(request)
    enforce_login_source_limit(source_ip)
    user = db.scalar(select(User).where(User.username == body.username))
    policy = get_security_config(db)
    now = datetime.now(timezone.utc)
    if user and user.locked_until:
        locked_until = user.locked_until if user.locked_until.tzinfo else user.locked_until.replace(tzinfo=timezone.utc)
        if locked_until > now:
            remaining = max(1, int((locked_until - now).total_seconds() / 60) + 1)
            audit(db, user, "login_failed", "auth", detail=json.dumps({"username": body.username, "ip": source_ip, "result": "账号已锁定"}, ensure_ascii=False))
            db.commit()
            raise HTTPException(status_code=423, detail=f"账号已锁定，请在 {remaining} 分钟后重试")
        user.locked_until = None
        user.failed_login_attempts = 0
    if not user or not user.active or not verify_password(body.password, user.password_hash):
        record_login_failure(source_ip)
        detail = "用户名或密码错误"
        if user and user.active:
            user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
            if user.failed_login_attempts >= policy.login_max_attempts:
                user.locked_until = now + timedelta(minutes=policy.login_lock_minutes)
                user.failed_login_attempts = 0
                detail = f"登录失败次数过多，账号已锁定 {policy.login_lock_minutes} 分钟"
            else:
                remaining = policy.login_max_attempts - user.failed_login_attempts
                detail = f"用户名或密码错误，还可尝试 {remaining} 次"
        audit(db, user, "login_failed", "auth", detail=json.dumps({"username": body.username, "ip": source_ip, "result": detail}, ensure_ascii=False))
        db.commit()
        raise HTTPException(status_code=401, detail=detail)
    clear_login_failures(source_ip)
    user.failed_login_attempts = 0
    user.locked_until = None
    user.last_login_at = now
    user.last_login_ip = source_ip
    audit(db, user, "login", "auth", detail=json.dumps({"username": user.username, "ip": source_ip, "result": "登录成功"}, ensure_ascii=False))
    db.commit()
    access_token = token_for(user, policy.session_timeout_minutes)
    forwarded_scheme = request.headers.get("x-forwarded-proto", "").split(",", 1)[0].strip().lower()
    secure_cookie = forwarded_scheme == "https" or request.url.scheme == "https"
    response.set_cookie(
        SESSION_COOKIE_NAME,
        access_token,
        max_age=policy.session_timeout_minutes * 60,
        httponly=True,
        secure=secure_cookie,
        samesite="strict",
        path="/",
    )
    return TokenOut(access_token=access_token)


@app.get("/api/auth/me", response_model=UserOut)
def me(user: User = Depends(current_user)):
    return user


@app.post("/api/auth/logout")
def logout_session(request: Request, response: Response, db: Session = Depends(get_db), user: User = Depends(current_user)):
    source_ip = _login_source_ip(request)
    audit(db, user, "logout", "auth", detail=json.dumps({"username": user.username, "ip": source_ip, "result": "退出登录"}, ensure_ascii=False))
    db.commit()
    response.delete_cookie(SESSION_COOKIE_NAME, path="/", samesite="strict")
    return {"ok": True}


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
    deployment_query = select(Deployment)
    project_query = select(Project)
    if user.role != Role.admin:
        accessible_project_ids = select(Project.id).where(
            (Project.owner_id == user.id) | Project.id.in_(select(ProjectAccess.project_id).where(ProjectAccess.user_id == user.id))
        )
        deployment_query = deployment_query.where(Deployment.project_id.in_(accessible_project_ids))
        project_query = project_query.where(Project.id.in_(accessible_project_ids))
    recent = db.scalars(deployment_query.order_by(desc(Deployment.created_at)).limit(8)).all()
    return {
        "projects": db.scalar(select(func.count()).select_from(project_query.subquery())) or 0,
        "nodes": db.query(Node).count(),
        "running": db.scalar(select(func.count()).select_from(deployment_query.where(Deployment.status.in_([DeployStatus.queued, DeployStatus.running])).subquery())) or 0,
        "success": db.scalar(select(func.count()).select_from(deployment_query.where(Deployment.status == DeployStatus.success).subquery())) or 0,
        # Use the same derived stage/progress data as deployment details. Raw
        # DeploymentOut has no progress field, which made the workbench show 0%.
        "recent": [deployment_view(x, db, include_log=False) for x in recent],
    }


@app.get("/api/users", response_model=list[UserOut])
def list_users(db: Session = Depends(get_db), _: User = Depends(require(Role.admin))):
    users = db.scalars(select(User).order_by(User.created_at)).all()
    projects = db.scalars(select(Project).order_by(Project.name, Project.created_at)).all()
    owned: dict[str, list[Project]] = {}
    for project in projects:
        owned.setdefault(project.owner_id, []).append(project)
    shared: dict[str, list[Project]] = {}
    project_by_id = {project.id: project for project in projects}
    for access in db.scalars(select(ProjectAccess)).all():
        if access.project_id in project_by_id:
            shared.setdefault(access.user_id, []).append(project_by_id[access.project_id])
    result = []
    for item in users:
        visible = projects if item.role == Role.admin else list({project.id: project for project in [*owned.get(item.id, []), *shared.get(item.id, [])]}.values())
        permission = "管理全部" if item.role == Role.admin else ("只读" if item.role == Role.viewer else "管理")
        result.append({
            "id": item.id,
            "username": item.username,
            "display_name": item.display_name,
            "role": item.role,
            "active": item.active,
            "failed_login_attempts": item.failed_login_attempts,
            "locked_until": item.locked_until,
            "last_login_at": item.last_login_at,
            "last_login_ip": item.last_login_ip,
            "created_at": item.created_at,
            "project_count": len(visible),
            "project_scope": "all" if item.role == Role.admin else "owned",
            "projects": [
                {"id": project.id, "name": project.name, "slug": project.slug, "permission": permission}
                for project in visible
            ],
        })
    return result


@app.put("/api/users/{item_id}/projects")
def update_user_projects(item_id: str, body: UserProjectsUpdate, db: Session = Depends(get_db), user: User = Depends(require(Role.admin))):
    item = db.get(User, item_id)
    if not item:
        raise HTTPException(404, "用户不存在")
    if item.role == Role.admin:
        raise HTTPException(400, "管理员默认拥有全部项目，无需单独分配")
    project_ids = list(dict.fromkeys(body.project_ids))
    existing_ids = set(db.scalars(select(Project.id).where(Project.id.in_(project_ids))).all()) if project_ids else set()
    if len(existing_ids) != len(project_ids):
        raise HTTPException(400, "包含不存在的项目")
    owned_ids = set(db.scalars(select(Project.id).where(Project.owner_id == item.id)).all())
    assigned_ids = existing_ids - owned_ids
    for access in db.scalars(select(ProjectAccess).where(ProjectAccess.user_id == item.id)).all():
        db.delete(access)
    db.flush()
    for project_id in assigned_ids:
        db.add(ProjectAccess(project_id=project_id, user_id=item.id))
    audit(db, user, "update_user_projects", "user", item.id, f"分配 {len(existing_ids)} 个项目")
    db.commit()
    return {"ok": True, "project_ids": project_ids}


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
    if item.id == user.id:
        if changes.get("active") is False:
            raise HTTPException(400, "不能停用当前登录账号")
        if changes.get("role") not in (None, Role.admin):
            raise HTTPException(400, "不能修改当前管理员的角色")
        if changes.get("password"):
            raise HTTPException(400, "请从右上角使用“修改密码”，修改后需重新登录")
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


@app.delete("/api/users/{item_id}")
def delete_user(item_id: str, db: Session = Depends(get_db), user: User = Depends(require(Role.admin))):
    item = db.get(User, item_id)
    if not item:
        raise HTTPException(404, "用户不存在")
    if item.id == user.id:
        raise HTTPException(400, "不能删除当前登录账号")
    if item.role == Role.admin:
        raise HTTPException(400, "管理员账号不能直接删除，请先调整角色")
    username = item.username
    transferred = 0
    for project in db.scalars(select(Project).where(Project.owner_id == item.id)).all():
        project.owner_id = user.id
        transferred += 1
    for deployment in db.scalars(select(Deployment).where(Deployment.requested_by == item.id)).all():
        deployment.requested_by = user.id
    credential_count = 0
    for credential in db.scalars(select(GitCredential).where(GitCredential.owner_id == item.id)).all():
        for project in db.scalars(select(Project).where(Project.git_credential_id == credential.id)).all():
            project.git_credential_id = None
        for project in db.scalars(select(Project).where(Project.git_repositories_json.contains(credential.id))).all():
            try:
                repositories = json.loads(project.git_repositories_json or "[]")
                for repository in repositories:
                    if repository.get("credential_id") == credential.id:
                        repository["credential_id"] = None
                project.git_repositories_json = json.dumps(repositories, ensure_ascii=False)
            except (TypeError, ValueError):
                pass
        db.delete(credential)
        credential_count += 1
    audit(db, user, "delete_user", "user", item.id, f"删除账号 {username}，移交 {transferred} 个项目，删除 {credential_count} 个 Git 凭据")
    db.delete(item)
    db.commit()
    return {"ok": True, "transferred_projects": transferred}


@app.post("/api/users/{item_id}/unlock", response_model=UserOut)
def unlock_user(item_id: str, db: Session = Depends(get_db), user: User = Depends(require(Role.admin))):
    item = db.get(User, item_id)
    if not item:
        raise HTTPException(404, "用户不存在")
    item.failed_login_attempts = 0
    item.locked_until = None
    audit(db, user, "unlock_user", "user", item.id, item.username)
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
def list_credentials(db: Session = Depends(get_db), user: User = Depends(require(Role.admin, Role.deployer))):
    query = select(GitCredential)
    if user.role != Role.admin:
        query = query.where(GitCredential.owner_id == user.id)
    items = db.scalars(query.order_by(GitCredential.created_at)).all()
    owner_ids = {item.owner_id for item in items if item.owner_id}
    owners = {item.id: item.username for item in db.scalars(select(User).where(User.id.in_(owner_ids))).all()} if owner_ids else {}
    return [{
        "id": item.id, "name": item.name, "owner_id": item.owner_id,
        "owner_username": owners.get(item.owner_id) if item.owner_id else "历史未归属",
        "auth_type": item.auth_type, "username": item.username, "created_at": item.created_at,
    } for item in items]


@app.post("/api/credentials", response_model=CredentialOut)
def create_credential(body: CredentialIn, db: Session = Depends(get_db), user: User = Depends(require(Role.admin, Role.deployer))):
    if db.scalar(select(GitCredential.id).where(GitCredential.owner_id == user.id, GitCredential.name == body.name)):
        raise HTTPException(409, "你已创建同名 Git 凭据")
    item = GitCredential(name=body.name, owner_id=user.id, auth_type=body.auth_type, username=body.username, secret_encrypted=encrypt(body.secret))
    db.add(item)
    db.flush()
    audit(db, user, "create_credential", "credential", item.id, item.name)
    db.commit()
    db.refresh(item)
    return item


def _credential_for_user(db: Session, user: User, credential_id: str | None) -> GitCredential | None:
    if not credential_id:
        return None
    item = db.get(GitCredential, credential_id)
    if not item or (user.role != Role.admin and item.owner_id != user.id):
        raise HTTPException(404, "Git 凭据不存在或不属于当前用户")
    return item


def _validate_project_credentials(db: Session, user: User, project: Project) -> None:
    if project.source_type != SourceType.git:
        return
    _credential_for_user(db, user, project.git_credential_id)
    for repository in project.git_repositories:
        _credential_for_user(db, user, repository.get("credential_id"))


@app.delete("/api/credentials/{item_id}")
def delete_credential(item_id: str, db: Session = Depends(get_db), user: User = Depends(require(Role.admin, Role.deployer))):
    item = _credential_for_user(db, user, item_id)
    referenced = db.scalar(select(func.count()).select_from(Project).where(Project.git_credential_id == item.id)) or 0
    referenced += sum(
        1 for project in db.scalars(select(Project).where(Project.git_repositories_json.contains(item.id))).all()
        if any(repository.get("credential_id") == item.id for repository in project.git_repositories)
    )
    if referenced:
        raise HTTPException(409, f"该凭据仍被 {referenced} 个项目使用，请先更换项目凭据")
    db.delete(item)
    audit(db, user, "delete_credential", "credential", item.id, item.name)
    db.commit()
    return {"ok": True}


@app.post("/api/credentials/test-git")
def test_git_connection(body: GitConnectionTest, db: Session = Depends(get_db), user: User = Depends(require(Role.admin, Role.deployer))):
    raw_url = body.git_url.strip()
    url, url_branch, source_path = git_source_location(raw_url, body.git_branch)
    if not url:
        raise HTTPException(400, "请填写 Git 仓库地址")
    credential = _credential_for_user(db, user, body.credential_id)
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
def list_projects(db: Session = Depends(get_db), user: User = Depends(current_user)):
    query = select(Project)
    if user.role != Role.admin:
        query = query.where((Project.owner_id == user.id) | Project.id.in_(select(ProjectAccess.project_id).where(ProjectAccess.user_id == user.id)))
    return db.scalars(query.order_by(desc(Project.created_at))).all()


@app.post("/api/projects", response_model=ProjectOut)
def create_project(body: ProjectCreate, tasks: BackgroundTasks, db: Session = Depends(get_db), user: User = Depends(require(Role.admin, Role.deployer))):
    if db.scalar(select(Project).where(Project.slug == body.slug)):
        raise HTTPException(409, "项目标识已存在")
    _credential_for_user(db, user, body.git_credential_id)
    for repository in body.git_repositories:
        _credential_for_user(db, user, repository.credential_id)
    data = body.model_dump(exclude={"env_text", "git_repositories"})
    repositories = [row.model_dump() for row in body.git_repositories]
    item = Project(
        **data,
        git_repositories_json=json.dumps(repositories, ensure_ascii=False),
        env_text_encrypted=encrypt(body.env_text),
        owner_id=user.id,
    )
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


def _normalized_uploaded_source_root(path: Path) -> Path:
    """Unwrap repeated archive/folder wrappers without guessing inside a real project."""
    markers = {
        "Dockerfile", "compose.yaml", "compose.yml", "docker-compose.yml", "docker-compose.yaml",
        "package.json", "pom.xml", "pyproject.toml", "requirements.txt", "go.mod", "Cargo.toml",
    }
    current = path
    for _ in range(8):
        if any((current / name).is_file() for name in markers):
            break
        children = [item for item in current.iterdir() if not item.name.startswith(".")]
        if len(children) != 1 or not children[0].is_dir():
            break
        current = children[0]
    return current


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
            try:
                safe_extract_zip(zf, extract_dir)
            except ValueError as exc:
                raise HTTPException(400, str(exc)) from exc
        archive.unlink()
        target = extract_dir
    target = _normalized_uploaded_source_root(target)
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
    # Keep the analysis summary aligned with the saved integration mode.
    # Switching MySQL/Redis/PostgreSQL to external must immediately remove the
    # misleading platform-image recommendation without requiring re-analysis.
    state = dict(item.source_analysis or {})
    if state.get("status") == "completed":
        state["runtime_services"] = _runtime_service_versions(
            item,
            state.get("deployment_plan") or {},
            db,
            state.get("workspace_path") or state.get("repository_cache_path"),
        )
        item.integration_analysis_json = json.dumps(state, ensure_ascii=False)
    audit(db, user, "update_project_environment", "project", item.id, "environment updated")
    db.commit()
    return {"ok": True}


@app.put("/api/projects/{item_id}/runtime-images", response_model=ProjectOut)
def update_project_runtime_images(item_id: str, body: dict, db: Session = Depends(get_db), user: User = Depends(require(Role.admin, Role.deployer))):
    item = db.get(Project, item_id)
    if not item:
        raise HTTPException(404, "项目不存在")
    state = dict(item.source_analysis or {})
    if state.get("status") != "completed":
        raise HTTPException(409, "请等待源码分析完成后再修改运行版本")
    supported = {"Nginx": "nginx", "Redis": "redis", "MySQL": "mysql", "PostgreSQL": "postgres"}
    requested = body.get("items") or []
    requested_images = {}
    for row in requested:
        service = str(row.get("service") or "")
        image = str(row.get("image") or "").strip().lower()
        family = supported.get(service)
        if not family or not re.fullmatch(r"[a-z0-9][a-z0-9._/-]*:[a-z0-9][a-z0-9._-]*", image):
            raise HTTPException(400, f"{service or '运行服务'}镜像格式不正确")
        if image.rsplit("/", 1)[-1].split(":", 1)[0] != family or image.endswith(":latest"):
            raise HTTPException(400, f"{service}必须使用对应的固定版本镜像，不能使用 latest")
        requested_images[service] = image
    current_rows = list(state.get("runtime_services") or [])
    editable_rows = [row for row in current_rows if row.get("editable", True)]
    if set(requested_images) != {str(row.get("service") or "") for row in editable_rows}:
        raise HTTPException(400, "请完整提交当前项目已识别的运行服务")
    overrides = dict(item.runtime_image_overrides)
    for row in current_rows:
        if not row.get("editable", True):
            continue
        service = str(row.get("service") or "")
        old_image = str(row.get("image") or "")
        new_image = requested_images[service]
        if new_image != old_image:
            row["image"] = new_image
            row["source"] = "用户修改"
            plan = state.get("deployment_plan") or {}
            for field in ("compose_yaml", "dockerfile"):
                text_value = str(plan.get(field) or "")
                if old_image and text_value:
                    plan[field] = re.sub(rf"(?<![a-zA-Z0-9._/-]){re.escape(old_image)}(?![a-zA-Z0-9._-])", new_image, text_value)
            state["deployment_plan"] = plan
            overrides[service] = new_image
    state["runtime_services"] = current_rows
    item.runtime_image_overrides_json = json.dumps(overrides, ensure_ascii=False)
    item.integration_analysis_json = json.dumps(state, ensure_ascii=False)
    audit(db, user, "update_runtime_images", "project", item.id, json.dumps(overrides, ensure_ascii=False))
    db.commit()
    db.refresh(item)
    return item


@app.post("/api/projects/{item_id}/integration-analysis")
def analyze_project_integrations(item_id: str, db: Session = Depends(get_db), user: User = Depends(require(Role.admin, Role.deployer))):
    return analyze_project_integrations_service(item_id, db, user)


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
    prepare_new_experience(row)
    db.flush()


def run_project_integration_analysis(item_id: str, user_id: str) -> None:
    with SessionLocal() as db:
        item = db.get(Project, item_id)
        user = db.get(User, user_id)
        if not item or not user:
            return
        queued_state = item.source_analysis or {}
        previous_error = str(queued_state.get("previous_error") or queued_state.get("error") or "")
        retry_count = int(queued_state.get("retry_count") or 0)
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
            "retry_count": retry_count,
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
                detail_text = str(detail)[:500]
                normalized = detail_text.lower()
                recoverable = any(token in normalized for token in (
                    "timed out", "timeout", "read operation timed out", "connect error",
                    "connection reset", "temporarily unavailable", "remote protocol",
                    "ai 源码分析暂不可用", "502", "503", "504",
                ))
                attempt = int(previous.get("retry_count") or retry_count or 0)
                if recoverable and attempt < 3:
                    next_attempt = attempt + 1
                    delay_seconds = 15 * next_attempt
                    item.integration_analysis_json = json.dumps({
                        **previous,
                        "status": "queued", "phase": "queued", "progress": 10,
                        "summary": f"AI 分析暂时未响应，{delay_seconds} 秒后自动重试（{next_attempt}/3）。",
                        "error": detail_text,
                        "previous_error": detail_text,
                        "retry_count": next_attempt,
                        "next_retry_at": (datetime.now(timezone.utc) + timedelta(seconds=delay_seconds)).isoformat(),
                    }, ensure_ascii=False)
                    audit(db, user, "analyze_integrations_retry", "project", item.id, f"{next_attempt}/3: {detail_text[:800]}")
                else:
                    item.integration_analysis_json = json.dumps({
                        **previous, "status": "failed", "phase": "failed", "progress": 100,
                        "summary": "源码处理未完成", "error": detail_text,
                        "retry_count": attempt,
                        "finished_at": datetime.now(timezone.utc).isoformat(),
                    }, ensure_ascii=False)
                    audit(db, user, "analyze_integrations_failed", "project", item.id, detail_text[:1000])
                    remember_analysis_outcome(db, detail_text, False)
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
    tasks.add_task(run_project_integration_analysis, item.id, user.id)
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


@app.get("/api/certificates")
def list_certificates(domain: str = "", db: Session = Depends(get_db), _: User = Depends(current_user)):
    items = _matching_certificates(db, domain.strip().lower()) if domain.strip() else db.scalars(select(CertificateStore).order_by(CertificateStore.expires_at.desc())).all()
    auto_selected_ids = set()
    for item in items:
        for pattern in json.loads(item.domains_json or "[]"):
            probe = f"certificate-check{pattern[1:]}" if pattern.startswith("*.") else pattern
            matches = _matching_certificates(db, probe)
            if matches:
                auto_selected_ids.add(matches[0].id)
    views = [_certificate_view(item, db, item.id in auto_selected_ids) for item in items]
    return sorted(views, key=lambda value: (not bool(value["references"]), not value["auto_selected"], -datetime.fromisoformat(value["expires_at"]).timestamp()))


@app.post("/api/certificates")
async def upload_certificate(
    certificate: UploadFile = File(...),
    private_key: UploadFile = File(...),
    allow_domain_overlap: bool = False,
    db: Session = Depends(get_db),
    user: User = Depends(require(Role.admin, Role.deployer)),
):
    cert_raw, key_raw = await certificate.read(), await private_key.read()
    if len(cert_raw) > 2_000_000 or len(key_raw) > 2_000_000:
        raise HTTPException(400, "证书或私钥不能超过 2 MB")
    try:
        cert_text, key_text = cert_raw.decode(), key_raw.decode()
        _, domains, fingerprint = _validated_certificate_material(cert_text, key_text)
        identical = db.scalar(select(CertificateStore).where(CertificateStore.fingerprint == fingerprint))
        if not identical and not allow_domain_overlap:
            domain_set = {value.lower() for value in domains}
            matches = []
            for existing in db.scalars(select(CertificateStore).order_by(CertificateStore.expires_at.desc())).all():
                existing_domains = json.loads(existing.domains_json or "[]")
                overlaps = any(
                    _domain_matches_pattern(domain, pattern) or _domain_matches_pattern(pattern, domain)
                    for domain in domains for pattern in existing_domains
                )
                if overlaps:
                    exact_set = domain_set == {value.lower() for value in existing_domains}
                    references = int(db.scalar(select(func.count()).select_from(ProjectDomainConfig).where(ProjectDomainConfig.certificate_id == existing.id)) or 0)
                    matches.append((0 if references else 1, 0 if exact_set else 1, -references, existing))
            if matches:
                candidate = sorted(matches, key=lambda value: (value[0], value[1], value[2], -value[3].expires_at.timestamp()))[0][3]
                raise HTTPException(409, {
                    "code": "certificate_domain_overlap",
                    "message": "证书域名已存在，可更新原证书或另存为新证书",
                    "candidate": _certificate_view(candidate, db),
                    "matches": len(matches),
                })
        item = _save_shared_certificate(db, certificate.filename or "SSL 证书", cert_text, key_text)
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(400, "证书或私钥无法解析，请上传有效的 PEM 文件")
    audit(db, user, "upload_certificate", "certificate", item.id, f"domains={item.domains_json}")
    db.commit()
    return _certificate_view(item, db)


@app.put("/api/certificates/{certificate_id}")
async def update_certificate(
    certificate_id: str,
    certificate: UploadFile = File(...),
    private_key: UploadFile = File(...),
    db: Session = Depends(get_db),
    user: User = Depends(require(Role.admin, Role.deployer)),
):
    item = db.get(CertificateStore, certificate_id)
    if not item:
        raise HTTPException(404, "证书不存在")
    cert_raw, key_raw = await certificate.read(), await private_key.read()
    if len(cert_raw) > 2_000_000 or len(key_raw) > 2_000_000:
        raise HTTPException(400, "证书或私钥不能超过 2 MB")
    try:
        cert_text, key_text = cert_raw.decode(), key_raw.decode()
        cert, domains, fingerprint = _validated_certificate_material(cert_text, key_text)
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(400, "证书或私钥无法解析，请上传有效的 PEM 文件")
    duplicate = db.scalar(select(CertificateStore).where(
        CertificateStore.fingerprint == fingerprint,
        CertificateStore.id != certificate_id,
    ))
    if duplicate:
        raise HTTPException(409, f"该证书已存在于证书库：{duplicate.name}")
    configs = db.scalars(select(ProjectDomainConfig).where(ProjectDomainConfig.certificate_id == certificate_id)).all()
    projects = {project.id: project for project in db.scalars(select(Project).where(Project.id.in_([value.project_id for value in configs]))).all()} if configs else {}
    uncovered = [
        projects[config.project_id].domain for config in configs
        if projects.get(config.project_id) and projects[config.project_id].domain
        and not any(_domain_matches_pattern(projects[config.project_id].domain, pattern) for pattern in domains)
    ]
    if uncovered:
        raise HTTPException(400, "新证书不包含正在使用的域名：" + "、".join(sorted(set(uncovered))))

    old_cert, old_key = decrypt(item.certificate_encrypted), decrypt(item.private_key_encrypted)
    old_item = (item.name, item.domains_json, item.fingerprint, item.certificate_encrypted, item.private_key_encrypted, item.expires_at)
    old_configs = {
        config.project_id: (config.certificate_name, config.certificate_encrypted, config.private_key_encrypted)
        for config in configs
    }
    processed: list[tuple[Project, ProjectDomainConfig, Deployment, Node, list[dict], list[tuple[str, int]]]] = []
    try:
        item.name = certificate.filename or item.name
        item.domains_json = json.dumps(domains, ensure_ascii=False)
        item.fingerprint = fingerprint
        item.certificate_encrypted = encrypt(cert_text)
        item.private_key_encrypted = encrypt(key_text)
        item.expires_at = cert.not_valid_after_utc
        for config in configs:
            project = projects.get(config.project_id)
            if not project:
                continue
            config.certificate_name = item.name
            config.certificate_encrypted = encrypt(cert_text)
            config.private_key_encrypted = encrypt(key_text)
            latest = db.scalar(select(Deployment).where(
                Deployment.project_id == project.id,
                Deployment.status == DeployStatus.success,
                Deployment.host_port.is_not(None),
            ).order_by(desc(Deployment.created_at)).limit(1))
            node = db.get(Node, latest.node_id) if latest else None
            if not latest or not node or not config.https_enabled or not project.domain:
                continue
            groups = _runtime_service_gateway_routes(db, project, latest, node)
            targets = _existing_project_gateway_targets(db, project.id) or _project_gateway_targets(db, latest, node)
            latest.access_url = configure_platform_gateway(
                db, latest, node, latest.host_port, project.domain,
                http_port=config.http_port, https_enabled=True, https_port=config.https_port,
                redirect_https=config.redirect_https, certificate=cert_text, private_key=key_text,
                upstreams=targets, route_groups=groups or None, strategy=project.load_balance_strategy,
            )
            processed.append((project, config, latest, node, groups, targets))
    except Exception as exc:
        item.name, item.domains_json, item.fingerprint, item.certificate_encrypted, item.private_key_encrypted, item.expires_at = old_item
        for config in configs:
            old_config = old_configs[config.project_id]
            config.certificate_name, config.certificate_encrypted, config.private_key_encrypted = old_config
        db.flush()
        for project, config, latest, node, groups, targets in reversed(processed):
            try:
                configure_platform_gateway(
                    db, latest, node, latest.host_port, project.domain,
                    http_port=config.http_port, https_enabled=True, https_port=config.https_port,
                    redirect_https=config.redirect_https, certificate=old_cert, private_key=old_key,
                    upstreams=targets, route_groups=groups or None, strategy=project.load_balance_strategy,
                )
            except Exception:
                pass
        db.rollback()
        raise HTTPException(502, f"新证书未能应用，已保留旧证书：{str(exc)[:240]}")
    audit(db, user, "update_certificate", "certificate", item.id, f"name={old_item[0]}->{item.name}; references={len(configs)}")
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


def _normalize_visit_path(value: object) -> str:
    """Normalize the optional page opened by the UI's visit action.

    This is deliberately separate from gateway routing: it changes only the
    browser destination and never participates in health checks or proxying.
    """
    visit_path = str(value or "").strip()
    if not visit_path or visit_path == "/":
        return ""
    if len(visit_path) > 500 or "://" in visit_path or "\\" in visit_path or "\r" in visit_path or "\n" in visit_path:
        raise HTTPException(400, "访问入口格式不正确")
    if not visit_path.startswith("/"):
        visit_path = f"/{visit_path}"
    parsed = urlsplit(visit_path)
    if parsed.scheme or parsed.netloc:
        raise HTTPException(400, "访问入口只能填写站内路径")
    return visit_path


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
    gateway_service_targets = {}
    auto_routes = []
    if latest:
        node = db.get(Node, latest.node_id)
        if node:
            try:
                route_groups = _runtime_service_gateway_routes(db, item, latest, node)
                gateway_services = [row["name"] for row in route_groups]
                for group in route_groups:
                    gateway_service_targets[str(group.get("name") or "")] = [
                        f"{host}:{port}" for host, port in (group.get("targets") or [])
                    ]
                    for route in group.get("paths") or [{"path": group.get("path") or "/", "strip_prefix": False}]:
                        route = route if isinstance(route, dict) else {"path": route}
                        auto_routes.append({
                            "path": str(route.get("path") or "/"),
                            "service": str(group.get("name") or ""),
                            "strip_prefix": bool(route.get("strip_prefix", False)),
                        })
            except Exception:
                gateway_services = []
                gateway_service_targets = {}
                auto_routes = []
    try:
        custom_routes = json.loads(config.custom_routes_json or "[]") if config else []
    except Exception:
        custom_routes = []
    return {
        "domain": item.domain or "",
        "visit_path": item.visit_path or "",
        "http_port": config.http_port if config else deployment_settings.default_domain_http_port,
        "https_enabled": config.https_enabled if config else False,
        "https_port": config.https_port if config else deployment_settings.default_domain_https_port,
        "redirect_https": config.redirect_https if config else True,
        "gateway_mode": config.gateway_mode if config else "auto",
        "custom_routes": custom_routes,
        "auto_routes": auto_routes,
        "proxy_read_timeout": config.proxy_read_timeout if config else 300,
        "client_max_body_mb": config.client_max_body_mb if config else 50,
        "gateway_services": gateway_services,
        "gateway_service_targets": gateway_service_targets,
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
        return {
            "generated": False,
            "message": "项目尚无成功运行的版本，部署完成后才会生成网关配置",
            "visit_path": item.visit_path or "",
            "routes": [],
            "config": "",
        }
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
                "visit_path": item.visit_path or "",
                "routes": routes, "config": "", "config_path": filename,
            }
    return {
        "generated": bool(generated_config),
        "message": "平台当前正在使用的配置" if generated_config else "尚未找到已生效的网关配置文件",
        "mode": mode,
        "access_url": latest.access_url,
        "visit_path": item.visit_path or "",
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
    visit_path = _normalize_visit_path(body.get("visit_path", item.visit_path or ""))

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
    # Auto and custom are two independently persisted plans. Switching back to
    # automatic routing must not erase a known-good manual fallback: operators
    # can safely compare/test automatic detection and later return to the exact
    # custom plan they saved before.
    if mode == "custom":
        config.custom_routes_json = json.dumps(normalized_routes, ensure_ascii=False)
    config.proxy_read_timeout = timeout
    config.client_max_body_mb = upload_mb
    item.visit_path = visit_path
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
    compose_project = deployment_compose_project_name(deployment, project)
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
    groups = _route_groups_for_services(project, service_targets)
    groups, _ = reconcile_runtime_frontend_routes(groups)
    return groups or []


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
    visit_path: str = Form(default=""),
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
    visit_path = _normalize_visit_path(visit_path)
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
    item.visit_path = visit_path
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
    if "release_strategy" in fields_set and body.release_strategy is not None:
        item.release_strategy = body.release_strategy
    if "image_retention_count" in fields_set and body.image_retention_count is not None:
        item.image_retention_count = body.image_retention_count
    if "git_url" in fields_set:
        item.git_url = body.git_url.strip() if body.git_url else None
    if "git_branch" in fields_set and body.git_branch:
        item.git_branch = body.git_branch.strip()
    if "git_credential_id" in fields_set:
        _credential_for_user(db, user, body.git_credential_id)
        item.git_credential_id = body.git_credential_id
    if "git_repositories" in fields_set and body.git_repositories is not None:
        for repository in body.git_repositories:
            _credential_for_user(db, user, repository.credential_id)
        item.git_repositories_json = json.dumps(
            [row.model_dump() for row in body.git_repositories], ensure_ascii=False,
        )
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

















def validate_external_integrations_for_deploy(project: Project, node: Node) -> None:
    """Reject incomplete or unreachable external services before queue/build."""
    effective_env = effective_project_environment(project)
    errors = external_integration_preflight(project, effective_env)
    if errors:
        raise HTTPException(409, "；".join(errors))
    values = environment_values(effective_env)
    checks = []
    for service, default_port in (("MYSQL", "3306"), ("REDIS", "6379")):
        if values.get(f"YUNZHOU_{service}_MODE", "managed").lower() != "external":
            continue
        host = values.get(f"YUNZHOU_{service}_HOST", "").strip()
        port = values.get(f"YUNZHOU_{service}_PORT", default_port).strip()
        if not re.fullmatch(r"[A-Za-z0-9._:-]+", host) or not port.isdigit() or not (1 <= int(port) <= 65535):
            raise HTTPException(409, f"外接 {service.title()} 地址或端口格式不正确")
        checks.append((service.title(), host, port))
    if not checks:
        return
    with SSHNode(node) as ssh:
        for service, host, port in checks:
            command = f"exec 3<>/dev/tcp/{host}/{port}"
            code, _ = ssh.run("timeout 5 bash -c " + shlex.quote(command), timeout=10)
            if code:
                raise HTTPException(409, f"部署服务器无法连接外接 {service}：{host}:{port}，请检查地址、防火墙和监听范围")


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
    _validate_project_credentials(db, user, project)
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
        "replica_count", "load_balance_strategy", "deployment_mode", "release_strategy",
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
    validate_external_integrations_for_deploy(project, node)
    plan = make_deployment_plan(project, node, db, allocate_port=True)
    item = Deployment(project_id=project.id, node_id=node.id, requested_by=user.id, status=DeployStatus.queued, host_port=plan["host_port"], log_text=plan_log(plan))
    db.add(item)
    db.flush()
    audit(db, user, "deploy", "deployment", item.id, f"{project.name} -> {node.name}; current form configuration saved atomically")
    db.commit()
    db.refresh(item)
    return item


@app.get("/api/deployments")
def list_deployments(project_id: str | None = None, db: Session = Depends(get_db), user: User = Depends(current_user)):
    access_condition = None
    query = select(Deployment).order_by(desc(Deployment.created_at))
    if user.role != Role.admin:
        access_condition = Deployment.project_id.in_(select(Project.id).where(
            (Project.owner_id == user.id) | Project.id.in_(select(ProjectAccess.project_id).where(ProjectAccess.user_id == user.id))
        ))
        query = query.where(access_condition)
    if project_id:
        query = query.where(Deployment.project_id == project_id)
    deployments = db.scalars(query.limit(100)).all()

    # The project cards need both the newest attempt and the currently online
    # successful release. A global LIMIT alone can hide those rows when one
    # project has a long deployment history, making a healthy project appear
    # failed because only an old failure remains in the client cache.
    if not project_id:
        def ranked_ids(status: DeployStatus | None = None):
            ranked_query = select(
                Deployment.id.label("deployment_id"),
                func.row_number().over(
                    partition_by=Deployment.project_id,
                    order_by=Deployment.created_at.desc(),
                ).label("row_number"),
            )
            if access_condition is not None:
                ranked_query = ranked_query.where(access_condition)
            if status is not None:
                ranked_query = ranked_query.where(Deployment.status == status)
            ranked = ranked_query.subquery()
            return select(ranked.c.deployment_id).where(ranked.c.row_number == 1)

        summary_ids = ranked_ids().union(ranked_ids(DeployStatus.success))
        summary_rows = db.scalars(
            select(Deployment)
            .where(Deployment.id.in_(summary_ids))
            .order_by(desc(Deployment.created_at))
        ).all()
        known_ids = {item.id for item in deployments}
        deployments.extend(item for item in summary_rows if item.id not in known_ids)
        deployments.sort(key=lambda item: item.created_at, reverse=True)
    ids = [item.id for item in deployments]
    requester_ids = {item.requested_by for item in deployments}
    requesters = {
        item.id: item
        for item in db.scalars(select(User).where(User.id.in_(requester_ids))).all()
    } if requester_ids else {}
    reservations: dict[str, list[DeploymentPortReservation]] = {}
    if ids:
        for row in db.scalars(select(DeploymentPortReservation).where(
            DeploymentPortReservation.deployment_id.in_(ids),
            DeploymentPortReservation.status.in_(["reserved", "active"]),
        ).order_by(DeploymentPortReservation.created_at)).all():
            reservations.setdefault(row.deployment_id, []).append(row)
    return [deployment_view(
        item, db, include_log=bool(project_id and item.status in (DeployStatus.queued, DeployStatus.running)),
        port_reservations=reservations.get(item.id, []),
        requester_by_id=requesters,
    ) for item in deployments]


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
    path = deployment_log_path(item.id)
    if path.is_file():
        content = compact_docker_pull_log(path.read_text(encoding="utf-8", errors="replace"))
        return Response(
            content=content,
            media_type="text/plain; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
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
    return deployment_launch_config_service(item_id, db)


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


@app.post("/api/projects/{item_id}/scale")
def scale_project(item_id: str, body: ScaleProjectIn, db: Session = Depends(get_db), user: User = Depends(require(Role.admin, Role.deployer))):
    return scale_project_service_all(item_id, body, db, user)


@app.post("/api/projects/{item_id}/services/{service_name}/scale")
def scale_project_service(item_id: str, service_name: str, body: ScaleProjectIn, db: Session = Depends(get_db), user: User = Depends(require(Role.admin, Role.deployer))):
    return scale_single_service(item_id, service_name, body, db, user)


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
    kind = sql_kind(sql)
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
    token = data_change_confirmation_token(project.id, sql, settings.app_secret)
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




@app.get("/api/deployments/{item_id}/ai-followup")
def deployment_ai_followup(item_id: str, db: Session = Depends(get_db), user: User = Depends(current_user)):
    return deployment_ai_followup_service(item_id, db, user)











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
            token_value = token_value or websocket.cookies.get(SESSION_COOKIE_NAME, "")
            user = user_from_token(token_value, db)
        except (HTTPException, JWTError, TypeError):
            user = None
        if not user or not user.active or user.role not in {Role.admin, Role.deployer}:
            await websocket.close(code=4401)
            return
        if not _user_can_access_deployment(db, user, item_id):
            await websocket.close(code=4404)
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
    # Stopping an already published service is a runtime operation, not a new
    # deployment.  Preserve the original build interval so days of uptime are
    # never reported as deployment time.
    original_finished_at = item.finished_at
    item.log_text = (item.log_text or "") + "\n[停止] 已收到请求，正在终止部署进程和容器...\n"
    # Publish the cancellation before touching the remote host.  Local work
    # such as AI analysis has no remote PID; it observes this state at its next
    # checkpoint and exits without continuing the release.
    item.status = DeployStatus.stopped
    item.finished_at = original_finished_at if previous == DeployStatus.success else datetime.now(timezone.utc)
    audit(db, user, "stop", "deployment", item.id)
    db.commit()
    try:
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
        # A newer release is never a reason to preserve this release's own
        # containers: release-scoped Compose names make them independent. The
        # only protected runtime is the already-successful version while an
        # unfinished candidate record is being cancelled.
        protected_runtime = existing_runtime
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
                    runtime_policy = db.get(DeploymentSettings, "default")
                    runtime_namespace = (runtime_policy.registry_namespace if runtime_policy else "yunzhou") or "yunzhou"
                    modern_replica = (
                        "^" + re.escape(_service_instance_prefix(
                            db.get(Project, item.project_id).slug, "SERVICE", item.release, runtime_namespace,
                        ).replace("-service", "-")) + ".+-([2-9]|[1-9][0-9]+)$"
                    )
                    _, discovered = ssh.run(
                        "docker ps -a --format '{{.Names}}' | grep -E " + shlex.quote(
                            "(^yz-" + re.escape(db.get(Project, item.project_id).slug) +
                            "-replica-[0-9]+$)|(" + modern_replica + ")"
                        ) + " || true"
                    )
                    removed_replica_names.update(name.strip() for name in discovered.splitlines() if name.strip())
                    for name in removed_replica_names:
                        ssh.run(f"docker rm -f {shlex.quote(name)} >/dev/null 2>&1 || true")
                    for replica in replicas:
                        db.delete(replica)
            db.flush()
        output = stop_deployment(item, db.get(Project, item.project_id), db.get(Node, item.node_id), preserve_runtime=bool(protected_runtime))
        if protected_runtime:
            # The candidate may have temporarily stopped the previous release
            # to obtain an exclusive application volume. Cancellation must be
            # self-healing: re-apply the immutable successful release and wait
            # until its published endpoint is ready before reporting success.
            protected_project = db.get(Project, protected_runtime.project_id)
            protected_node = db.get(Node, protected_runtime.node_id)
            restored = start_deployment(
                protected_runtime, protected_project, protected_node, db,
            )
            output += "；已核验并恢复原线上版本（" + restored + "）"
        if not protected_runtime:
            output += f"；已停止并清理 {len(removed_replica_names)} 个应用副本，固定 Service 配置已保留"
        # A release-level stop controls only this version's application
        # runtime. Project-shared MySQL/Redis containers remain available so a
        # routine application stop cannot unexpectedly interrupt data services.
    except Exception as exc:
        item = db.get(Deployment, item_id)
        # A failed remote stop is not a stopped deployment. Restore the prior
        # state so the UI cannot claim success while containers are still live.
        item.status = previous
        item.finished_at = original_finished_at
        item.log_text = (item.log_text or "") + f"[停止失败] {exc}\n"
        item.error = f"停止失败：{exc}"
        db.commit()
        raise HTTPException(502, item.error)
    item = db.get(Deployment, item_id)
    item.status = DeployStatus.stopped
    item.finished_at = original_finished_at if previous == DeployStatus.success else datetime.now(timezone.utc)
    item.error = None
    item.log_text = (item.log_text or "") + f"[停止确认] {output}\n"
    db.commit()
    invalidate_runtime_cache(item.id)
    return {"ok": True, "verified": True, "output": output}


@app.post("/api/projects/{item_id}/runtime/stop")
def stop_project_runtime(item_id: str, db: Session = Depends(get_db), user: User = Depends(require(Role.admin, Role.deployer))):
    """Stop every application and shared data service owned by a project."""
    project = db.get(Project, item_id)
    if not project:
        raise HTTPException(404, "项目不存在")
    active = db.scalars(select(Deployment).where(
        Deployment.project_id == item_id,
        Deployment.status == DeployStatus.success,
    ).order_by(Deployment.created_at.desc())).all()
    latest_stopped = None if active else db.scalar(select(Deployment).where(
        Deployment.project_id == item_id,
        Deployment.status == DeployStatus.stopped,
        Deployment.release.is_not(None),
        Deployment.access_url.is_not(None),
    ).order_by(Deployment.created_at.desc()))
    if not active and not latest_stopped:
        raise HTTPException(409, "项目当前没有可停止的运行环境")

    outputs: list[str] = []
    nodes: dict[str, Node] = {}
    for deployment in active or [latest_stopped]:
        node = db.get(Node, deployment.node_id)
        if not node:
            raise HTTPException(404, "部署服务器不存在")
        nodes[node.id] = node
        if deployment.status == DeployStatus.success:
            result = stop(deployment.id, db, user)
            outputs.append(str(result.get("output") or "应用服务已停止"))

    for node in nodes.values():
        outputs.append(stop_project_data_services(project, node, db))

    invalidate_runtime_cache()
    audit(db, user, "stop_project_runtime", "project", project.id, "应用与数据服务已全部停止")
    db.commit()
    return {"ok": True, "verified": True, "output": "；".join(filter(None, outputs))}


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
    if project.source_type == SourceType.upload and project.source_path:
        source_path = Path(project.source_path)
        if source_path.is_dir():
            normalized_source = _normalized_uploaded_source_root(source_path)
            if normalized_source != source_path:
                project.source_path = str(normalized_source)
                audit(db, user, "normalize_uploaded_source_root", "project", project.id, f"{source_path} -> {normalized_source}")
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
    validate_external_integrations_for_deploy(project, node)
    plan = make_deployment_plan(project, node, db, allocate_port=True)
    item = Deployment(project_id=project.id, node_id=node.id, requested_by=user.id, status=DeployStatus.queued, trigger="retry", host_port=plan["host_port"], log_text=plan_log(plan) + f"[继续] 从任务 {previous.id[:8]} 重新安全执行\n")
    db.add(item)
    db.flush()
    audit(db, user, "retry_deployment", "deployment", item.id, f"from={previous.id}")
    db.commit()
    db.refresh(item)
    return item




@app.post("/api/deployments/{item_id}/start")
def start_stopped_deployment(item_id: str, db: Session = Depends(get_db), user: User = Depends(require(Role.admin, Role.deployer))):
    item = db.get(Deployment, item_id)
    if not item:
        raise HTTPException(404, "部署不存在")
    if item.status != DeployStatus.stopped:
        raise HTTPException(409, "只有已停止的服务可以重新启用")
    active_release = db.scalar(select(Deployment).where(
        Deployment.project_id == item.project_id,
        Deployment.node_id == item.node_id,
        Deployment.id != item.id,
        Deployment.status == DeployStatus.success,
    ).order_by(Deployment.created_at.desc()))
    if active_release:
        raise HTTPException(409, "该服务器已有运行版本；如需切换历史版本，请使用“回滚到此版本”")
    # Failure cleanup must restore the state that existed before this action.
    # If shared data services were already running (the common "应用已停" state),
    # keep them running even when the application fails to start.
    data_was_running = True  # conservative fallback: never interrupt unknown data state
    try:
        before = runtime_snapshot(item, db, force=True)
        data_was_running = any(
            _runtime_entry_is_data(container) and _runtime_entry_is_running(container)
            for container in before.get("containers", [])
        )
    except Exception:
        pass
    original_started_at = item.started_at
    original_finished_at = item.finished_at
    item.log_text = (item.log_text or "") + "\n[启用] 正在重新启动原发布版本...\n"
    db.commit()
    try:
        output = start_deployment(item, db.get(Project, item.project_id), db.get(Node, item.node_id), db)
    except Exception as exc:
        item = db.get(Deployment, item_id)
        project = db.get(Project, item.project_id)
        node = db.get(Node, item.node_id)
        cleanup_error = ""
        try:
            # start_deployment can fail after Compose has already created some
            # containers (for example during its health check).  The database
            # still says stopped at this point, so explicitly remove this
            # release instead of leaving an invisible live version behind.
            stop_deployment(item, project, node)
            if not data_was_running:
                stop_project_data_services(project, node, db)
        except Exception as cleanup_exc:
            cleanup_error = f"；自动清理失败：{cleanup_exc}"
        item = db.get(Deployment, item_id)
        item.status = DeployStatus.stopped
        item.error = f"启用失败：{exc}{cleanup_error}"
        if "原发布目录不存在" in str(exc):
            # Keep the historical version number, but revoke the stale launch
            # entry so project cards offer a clean redeploy instead.
            item.access_url = None
        item.log_text = ((item.log_text or "") + f"[启用失败] {exc}\n" +
                         (f"[清理异常] {cleanup_error}\n" if cleanup_error else "[自动清理] 未完成启动的容器已清理。\n"))[-200_000:]
        db.commit()
        raise HTTPException(502, item.error)
    item = db.get(Deployment, item_id)
    item.status = DeployStatus.success
    item.error = None
    # Re-enabling the same release must not rewrite its original deployment
    # duration.  Runtime stop/start time is tracked in the operation audit.
    item.started_at = original_started_at
    item.finished_at = original_finished_at
    db.commit()
    project = db.get(Project, item.project_id)
    node = db.get(Node, item.node_id)
    try:
        scaled = scale_project(item.project_id, ScaleProjectIn(replicas=1), db, user)
        output += f"；项目 Service 已恢复，应用实例就绪 {scaled['ready']}/{scaled['desired']}"
    except Exception as exc:
        cleanup_error = ""
        try:
            stop_deployment(item, project, node)
            if not data_was_running:
                stop_project_data_services(project, node, db)
        except Exception as cleanup_exc:
            cleanup_error = f"；自动清理失败：{cleanup_exc}"
        item = db.get(Deployment, item_id)
        item.status = DeployStatus.stopped
        item.error = f"启用失败：{exc}{cleanup_error}"
        item.started_at = original_started_at
        item.finished_at = original_finished_at
        item.log_text = ((item.log_text or "") +
                         f"[启用失败] {exc}\n" +
                         (f"[清理异常] {cleanup_error}\n" if cleanup_error else "[自动清理] 本次启动的版本已停止，不会残留运行容器。\n"))[-200_000:]
        db.commit()
        raise HTTPException(502, item.error) from exc
    item = db.get(Deployment, item_id)
    item.log_text = ((item.log_text or "") + f"[启用确认] {output}\n")[-200_000:]
    audit(db, user, "start", "deployment", item.id)
    db.commit()
    invalidate_runtime_cache()
    return {"ok": True, "verified": True, "output": output}


@app.post("/api/deployments/{item_id}/rollback")
def rollback_deployment(item_id: str, db: Session = Depends(get_db), user: User = Depends(require(Role.admin, Role.deployer))):
    """Switch a project back to a previously verified release without rebuilding it."""
    target = db.get(Deployment, item_id)
    if not target:
        raise HTTPException(404, "发布版本不存在")
    was_verified = is_verified_release(target)
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

    target_original_started_at = target.started_at
    target_original_finished_at = target.finished_at
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
        route_groups = _runtime_service_gateway_routes(db, project, item, node)
        access = configure_platform_gateway(
            db, item, node, int(item.host_port), project.domain,
            http_port=domain_config.http_port if domain_config else (defaults.default_domain_http_port if defaults else 80),
            https_enabled=domain_config.https_enabled if domain_config else False,
            https_port=domain_config.https_port if domain_config else (defaults.default_domain_https_port if defaults else 443),
            redirect_https=domain_config.redirect_https if domain_config else True,
            certificate=decrypt(domain_config.certificate_encrypted) if domain_config else None,
            private_key=decrypt(domain_config.private_key_encrypted) if domain_config else None,
            upstreams=_project_gateway_targets(db, item, node),
            route_groups=route_groups or None,
            strategy=project.load_balance_strategy,
        )
        old_path = urlsplit(item.access_url or "").path
        if old_path and old_path != "/":
            access = access.rstrip("/") + old_path
        return access

    current_stop_started = False
    try:
        output = start_deployment(target, project, node, db)
        access = apply_gateway(target)
        verify_access(db, target.id, access)
        # `stop_deployment` updates port reservations in a short independent
        # session. Commit the outer rollback transaction first, otherwise its
        # reservation lock can make both sessions wait on each other forever.
        db.commit()
        current_stop_started = True
        stop_output = stop_deployment(current, project, node, release_ports=True)
        output += f"；原线上版本已安全停止：{stop_output}"
    except Exception as exc:
        recovery_errors = []
        try:
            # The candidate is always isolated by release. A failed switch must
            # remove it before restoring traffic, otherwise a stopped record can
            # leave healthy-looking historical containers behind.
            stop_deployment(target, project, node, release_ports=True)
        except Exception as cleanup_exc:
            recovery_errors.append(f"候选版本清理失败：{cleanup_exc}")
        try:
            if current_stop_started:
                start_deployment(current, project, node, db)
            restored_access = apply_gateway(current)
            verify_access(db, current.id, restored_access)
        except Exception as restore_exc:
            recovery_errors.append(f"原线上版本恢复失败：{restore_exc}")
        restore_error = ("；" + "；".join(recovery_errors)) if recovery_errors else ""
        target = db.get(Deployment, item_id)
        target.status = DeployStatus.stopped
        target.error = f"回滚失败：{exc}{restore_error}"
        target.started_at = target_original_started_at
        target.finished_at = target_original_finished_at
        target.log_text = ((target.log_text or "") + f"[回滚失败] {exc}\n" + ("[恢复失败] " + restore_error + "\n" if restore_error else "[自动恢复] 已恢复回滚前的线上版本。\n"))[-200_000:]
        db.commit()
        invalidate_runtime_cache()
        raise HTTPException(502, target.error)

    current = db.get(Deployment, current.id)
    current.status = DeployStatus.stopped
    current.error = None
    current.log_text = ((current.log_text or "") + f"\n[版本切换] 已回滚至版本 {target.release}。\n")[-200_000:]
    target = db.get(Deployment, target.id)
    target.status = DeployStatus.success
    target.error = None
    target.access_url = access
    # Rollback is a runtime switch, not a new build. Preserve the historical
    # deployment interval so the release list keeps reporting build duration
    # instead of the time spent performing this rollback.
    target.started_at = target_original_started_at
    target.finished_at = target_original_finished_at
    target.log_text = ((target.log_text or "") + f"[回滚完成] {output}；访问验证通过：{access}\n")[-200_000:]
    audit(db, user, "rollback_deployment", "deployment", target.id, f"from={current.release};to={target.release}")
    db.commit()
    try:
        scale_project(project.id, ScaleProjectIn(replicas=1), db, user)
    except Exception as scale_exc:
        target = db.get(Deployment, target.id)
        target.log_text = ((target.log_text or "") + f"[副本同步] 主版本回滚成功，附加副本将在下次状态刷新时重试：{scale_exc}\n")[-200_000:]
        db.commit()
    invalidate_runtime_cache()
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
    image_defaults = {
        "Nginx": (body.default_nginx_image, "nginx"),
        "Redis": (body.default_redis_image, "redis"),
        "MySQL": (body.default_mysql_image, "mysql"),
        "PostgreSQL": (body.default_postgres_image, "postgres"),
    }
    for label, (value, repository) in image_defaults.items():
        image = value.strip().lower()
        if not re.fullmatch(r"[a-z0-9][a-z0-9._/-]*:[a-z0-9][a-z0-9._-]*", image):
            raise HTTPException(400, f"{label} 默认镜像必须填写完整名称和固定版本")
        if image.rsplit("/", 1)[-1].split(":", 1)[0] != repository or image.endswith(":latest"):
            raise HTTPException(400, f"{label} 默认镜像名称不正确或使用了 latest")
    item = get_deployment_settings(db)
    item.global_concurrency = body.global_concurrency
    item.per_node_concurrency = body.per_node_concurrency
    item.analysis_concurrency = body.analysis_concurrency
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
    item.build_cache_max_gb = body.build_cache_max_gb
    item.builder_min_free_gb = body.builder_min_free_gb
    item.builder_workspace_ttl_hours = body.builder_workspace_ttl_hours
    item.docker_build_cache_keep_gb = body.docker_build_cache_keep_gb
    item.maven_cache_dir = body.maven_cache_dir.strip().rstrip("/")
    item.gradle_cache_dir = body.gradle_cache_dir.strip().rstrip("/")
    item.npm_cache_dir = body.npm_cache_dir.strip().rstrip("/")
    item.pnpm_cache_dir = body.pnpm_cache_dir.strip().rstrip("/")
    item.yarn_cache_dir = body.yarn_cache_dir.strip().rstrip("/")
    item.pip_cache_dir = body.pip_cache_dir.strip().rstrip("/")
    item.default_nginx_image = body.default_nginx_image.strip().lower()
    item.default_redis_image = body.default_redis_image.strip().lower()
    item.default_mysql_image = body.default_mysql_image.strip().lower()
    item.default_postgres_image = body.default_postgres_image.strip().lower()
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

