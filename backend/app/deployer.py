import re
import json
import base64
from contextlib import contextmanager
import ipaddress
import shlex
import shutil
import subprocess
import tempfile
import hashlib
import os
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

from git import Repo
import httpx
import yaml
from sqlalchemy import select, text

from .config import decrypt, encrypt, settings
from .ai import MANAGED_MINIO_FALLBACK, analyze_project_deployment, deployment_followup
from .database import SessionLocal
from .models import AiConfig, DeployStatus, Deployment, DeploymentSettings, GitCredential, Node, Project, ProjectDomainConfig, ProjectReplica, SourceType
from .proxy import get_proxy_config
from .ssh import SSHNode


COMPOSE_NAMES = (
    "compose.yaml", "compose.yml", "docker-compose.yml", "docker-compose.yaml",
    ".yunzhou.compose.yml", ".yunzhou.ai.compose.yml",
)
ANSI_RE = re.compile(r"\x1b(?:[@-_][0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))")
DOCKER_HUB_MIRROR_HOSTS = {
    "docker.m.daocloud.io", "docker.anyhub.us.kg", "dockerhub.jobcher.com",
    "mirror.ccs.tencentyun.com", "docker.mirrors.ustc.edu.cn",
    "docker.nju.edu.cn", "dockerhub.icu", "docker.ckyl.me",
    "docker.awsl9527.cn", "hub-mirror.c.163.com",
}
_SOURCE_CACHE_LOCKS: dict[str, threading.Lock] = {}
_SOURCE_CACHE_LOCKS_GUARD = threading.Lock()


def cleanup_registry_versions(db, project: Project | None, repository: str) -> list[str]:
    policy = db.get(DeploymentSettings, "default")
    if not policy or not policy.registry_auto_cleanup:
        return []
    keep = max(1, int(policy.registry_retention_count or 5))
    base = "http://registry:5000/v2"
    headers = {"Accept": ", ".join((
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.docker.distribution.manifest.v2+json",
        "application/vnd.oci.image.manifest.v1+json",
    ))}
    # A successful deployment is historical evidence, not proof that its image
    # is still active. Protecting every successful release made retention a
    # no-op forever. The newest successful release is the restart/active
    # candidate; older releases are governed by the configured keep count.
    protected: set[str] = set()
    if project is not None:
        active_release = db.scalar(select(Deployment.release).where(
            Deployment.project_id == project.id,
            Deployment.status == DeployStatus.success,
            Deployment.release.is_not(None),
        ).order_by(Deployment.finished_at.desc(), Deployment.created_at.desc()).limit(1))
        if active_release:
            protected.add(active_release)
    removed = []
    with httpx.Client(timeout=20, trust_env=False) as client:
        response = client.get(f"{base}/{repository}/tags/list")
        if response.status_code != 200:
            return []
        tags = sorted(response.json().get("tags") or [], reverse=True)
        retained = set(tags[:keep]) | protected
        for tag in tags:
            if tag in retained:
                continue
            manifest = client.head(f"{base}/{repository}/manifests/{tag}", headers=headers)
            digest = manifest.headers.get("Docker-Content-Digest")
            if digest and client.delete(f"{base}/{repository}/manifests/{digest}").status_code in {200, 202}:
                removed.append(tag)
    return removed


def verify_registry_tag(repository: str, tag: str, attempts: int = 5) -> bool:
    """Confirm that a pushed tag is visible in the platform's central registry."""
    url = f"http://registry:5000/v2/{quote(repository, safe='/')}/tags/list"
    with httpx.Client(timeout=20, trust_env=False) as client:
        for attempt in range(attempts):
            try:
                response = client.get(url)
                if response.status_code == 200 and tag in (response.json().get("tags") or []):
                    return True
            except (httpx.HTTPError, ValueError):
                pass
            if attempt + 1 < attempts:
                time.sleep(1)
    return False


def source_cache_lock(project_id: str) -> threading.Lock:
    with _SOURCE_CACHE_LOCKS_GUARD:
        return _SOURCE_CACHE_LOCKS.setdefault(project_id, threading.Lock())


@contextmanager
def source_cache_guard(project_id: str, workspace_root: Path):
    """Serialize mutation of the immutable Git cache across API/worker processes."""
    thread_lock = source_cache_lock(project_id)
    with thread_lock:
        lock_handle = None
        try:
            lock_path = workspace_root / ".source-cache.lock"
            lock_handle = lock_path.open("a+")
            try:
                import fcntl
                fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
            except ImportError:
                # Windows development uses the in-process lock; production
                # containers use flock because API and worker are separate.
                pass
            yield
        finally:
            if lock_handle is not None:
                try:
                    import fcntl
                    fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)
                except ImportError:
                    pass
                lock_handle.close()


class DeploymentCancelled(RuntimeError):
    pass


def canonical_docker_image(image: str, managed_minio_image: str = MANAGED_MINIO_FALLBACK) -> str:
    """Keep transparent Docker Hub mirrors in daemon.json, not image names."""
    value = image.strip()
    host, separator, remainder = value.partition("/")
    if separator and host.lower() in DOCKER_HUB_MIRROR_HOSTS:
        value = remainder
        if value.startswith("library/"):
            value = value[len("library/"):]
    repository = value.rsplit("@", 1)[0].rsplit(":", 1)[0].lower()
    if repository in {"minio/minio", "quay.io/minio/minio"}:
        return managed_minio_image
    return value


def normalize_login_info(work: Path | str, ai_plan: dict) -> dict:
    """Correct conservative AI auth results when the repository clearly exposes self-registration."""
    work = Path(work)
    info = {
        "auth_mode": str(ai_plan.get("auth_mode") or "unknown")[:40],
        "login_url_path": str(ai_plan.get("login_url_path") or "/")[:300],
        "username": str(ai_plan.get("login_username") or "")[:300],
        "password": str(ai_plan.get("login_password") or "")[:300],
        "note": str(ai_plan.get("login_note") or "未发现可确认的默认登录账号，请查看项目首次使用说明。")[:1000],
    }
    if info["username"] or info["password"] or info["auth_mode"] in {"default_credentials", "external_auth", "none"}:
        return info
    registration_evidence = False
    inspected = 0
    for path in work.rglob("*"):
        if inspected >= 300 or not path.is_file() or path.suffix.lower() not in {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".py", ".html", ".md"}:
            continue
        try:
            if path.stat().st_size > 1_000_000:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
            inspected += 1
            if "/api/auth/register" in text and ("/register" in text or "注册" in text):
                registration_evidence = True
                break
        except OSError:
            continue
    if registration_evidence:
        info.update({
            "auth_mode": "first_register",
            "login_url_path": "/register",
            "username": "",
            "password": "",
            "note": "项目没有默认账号密码，请打开注册页面创建首个账号；密码规则以注册页面提示为准。",
        })
    return info


def project_directory(project: Project) -> str:
    """Human-readable, safe remote directory; Docker names still use the slug."""
    value = re.sub(r"[^\w.-]+", "-", (project.name or "").strip(), flags=re.UNICODE).strip("-.")
    return (value or project.slug)[:80]


def ensure_active(deployment_id: str) -> None:
    with SessionLocal() as check_db:
        current = check_db.get(Deployment, deployment_id)
        if not current or current.status == DeployStatus.stopped:
            raise DeploymentCancelled("部署已由用户停止")


def tracked_run(ssh: SSHNode, deployment_id: str, command: str, stream=None, timeout: int = 1800, pid_prefix: str = "yunzhou-deploy"):
    """Run a remote deployment command in its own process group so stop is real."""
    pid_file = f"/tmp/{pid_prefix}-{deployment_id}.pid"
    inner = f"exec setsid sh -c {shlex.quote(command)}"
    supervisor = (
        inner + " & pid=$!; echo $pid > " + pid_file + "; "
        + "wait $pid; rc=$?; rm -f " + pid_file + "; exit $rc"
    )
    wrapped = f"sh -c {shlex.quote(supervisor)}"
    return ssh.run(wrapped, timeout=timeout, stream=stream)


def stop_tracked_process_groups(ssh: SSHNode, deployment_id: str) -> str:
    """Stop and verify every tracked subprocess belonging to one deployment."""
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", deployment_id or ""):
        raise RuntimeError("部署任务编号不安全，拒绝终止远端进程")
    pattern = f"/tmp/yunzhou-*-{deployment_id}.pid"
    script = (
        "groups=''; files=0; "
        f"for f in {pattern}; do "
        "[ -f \"$f\" ] || continue; files=$((files+1)); "
        "p=$(cat \"$f\" 2>/dev/null | tr -cd '0-9'); "
        "[ -z \"$p\" ] || { groups=\"$groups $p\"; kill -TERM -- -$p 2>/dev/null || true; }; "
        "done; "
        "[ -z \"$groups\" ] || sleep 2; "
        "for p in $groups; do kill -0 -- -$p 2>/dev/null && kill -KILL -- -$p 2>/dev/null || true; done; "
        "sleep 1; residual=''; "
        "for p in $groups; do kill -0 -- -$p 2>/dev/null && residual=\"$residual $p\" || true; done; "
        f"rm -f -- {pattern}; "
        "printf 'pid_files=%s groups=%s residual=%s' \"$files\" \"$groups\" \"$residual\"; "
        "[ -z \"$residual\" ]"
    )
    code, output = ssh.run(script, timeout=20)
    if code:
        raise RuntimeError("停止后仍有构建进程运行：" + output.strip())
    return output.strip()


def log(deployment_id: str, text: str) -> None:
    if not text:
        return
    text = ANSI_RE.sub("", text).replace("\r", "")
    # The database keeps a compact, fast UI window. The append-only file keeps
    # every raw line for troubleshooting and download without rendering it.
    try:
        log_dir = Path(settings.upload_root) / "deployment-logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        with (log_dir / f"{deployment_id}.log").open("a", encoding="utf-8") as handle:
            handle.write(text)
    except OSError:
        pass
    with SessionLocal() as db:
        dep = db.get(Deployment, deployment_id)
        if dep:
            combined = (dep.log_text or "") + text
            if len(combined) > 200_000:
                # Keep stage markers even when verbose Docker output is truncated.
                markers = []
                for line in combined.splitlines():
                    if re.match(r"^\[(计划|方案|准备|源码|依赖分析|AI规划|架构分析|识别|上传|镜像|构建|平台构建|AI构建|启动|检查|完成|失败|停止|停止确认|AI跟进|AI修复|AI自动修复)\]", line) and line not in markers:
                        markers.append(line)
                combined = "\n".join(markers[-40:]) + "\n[日志] 较早的详细输出已折叠\n" + combined[-185_000:]
            dep.log_text = combined
            db.commit()


def git_source_location(raw_url: str, configured_branch: str | None = None) -> tuple[str, str, str]:
    """Turn a TFS/Azure DevOps browser URL into clone URL, branch and repo subdirectory."""
    parts = urlsplit((raw_url or "").strip())
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    source_path = (query.get("path") or "").replace("\\", "/").strip("/")
    if source_path and (source_path == ".." or source_path.startswith("../") or "/../" in f"/{source_path}/"):
        raise RuntimeError("Git 项目子目录不安全")
    version = (query.get("version") or "").strip()
    url_branch = version[2:] if version.startswith("GB") and len(version) > 2 else ""
    branch = url_branch or (configured_branch or "").strip()
    # path/version/_a are browser navigation parameters and must not be sent to git clone.
    clone_query = [(key, value) for key, value in parse_qsl(parts.query, keep_blank_values=True) if key not in {"path", "version", "_a"}]
    clone_url = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(clone_query), ""))
    return clone_url, branch, source_path


def _has_project_marker(path: Path) -> bool:
    names = {"package.json", "pom.xml", "pyproject.toml", "requirements.txt", "index.html", "Dockerfile", *COMPOSE_NAMES}
    return any((path / name).is_file() for name in names)


def _fullstack_roots(root: Path) -> tuple[list[Path], list[Path]]:
    ignored = {".git", "node_modules", "target", "dist", "build", "vendor"}
    frontends, backends = [], []
    for manifest in root.rglob("package.json"):
        if any(part in ignored for part in manifest.relative_to(root).parts):
            continue
        folder = manifest.parent
        text = manifest.read_text(errors="ignore").lower()
        frontend_markers = (
            '"vite"', '"react"', '"vue"', '"@vue/cli-service"',
            '"@angular/core"', '"svelte"', '"next"', '"nuxt"',
        )
        config_markers = (
            "vite.config.ts", "vite.config.js", "vue.config.js",
            "angular.json", "svelte.config.js", "next.config.js", "nuxt.config.ts",
        )
        if any(marker in text for marker in frontend_markers) or any((folder / name).exists() for name in config_markers):
            frontends.append(folder)
    for manifest in root.rglob("pom.xml"):
        if not any(part in ignored for part in manifest.relative_to(root).parts):
            backends.append(manifest.parent)
    return frontends, backends


def _find_compose(root: Path) -> Path | None:
    """Find a topology file without requiring it to live at repository root."""
    direct = [root / name for name in COMPOSE_NAMES if (root / name).is_file()]
    if direct:
        return direct[0]
    ignored = {".git", "node_modules", "target", "dist", "build", "vendor"}
    candidates = []
    for name in COMPOSE_NAMES:
        for path in root.rglob(name):
            relative = path.relative_to(root)
            if len(relative.parts) <= 4 and not any(part in ignored for part in relative.parts):
                candidates.append(path)
    if not candidates:
        return None
    def rank(path: Path):
        relative = path.relative_to(root).as_posix().lower()
        return (0 if relative.startswith("deploy/") else 1, 1 if "prod" in relative else 0, len(path.parts), relative)
    return sorted(set(candidates), key=rank)[0]


def discover_source_root(repo_root: Path, requested_path: str = "") -> tuple[Path, str]:
    if requested_path:
        selected = (repo_root / requested_path).resolve()
        try:
            selected.relative_to(repo_root.resolve())
        except ValueError as exc:
            raise RuntimeError("Git 项目子目录不安全") from exc
        if not selected.is_dir():
            raise RuntimeError(f"Git 仓库中不存在项目目录 /{requested_path}")
        if not _has_project_marker(selected):
            raise RuntimeError(f"目录 /{requested_path} 中未找到 package.json、pom.xml 或其他项目入口文件")
        # Browser URLs often point at the folder currently open in TFS/Azure
        # DevOps.  Do not mistake that navigation path for the whole product
        # when the repository contains a matching frontend/backend topology.
        frontend_roots, backend_roots = _fullstack_roots(repo_root)
        if frontend_roots and backend_roots and (selected in frontend_roots or selected in backend_roots):
            counterpart = backend_roots[0] if selected in frontend_roots else frontend_roots[0]
            common = Path(os.path.commonpath([str(selected), str(counterpart)])).resolve()
            relative = common.relative_to(repo_root.resolve()).as_posix()
            return common, "" if relative == "." else relative
        return selected, requested_path
    if _has_project_marker(repo_root):
        return repo_root, ""
    ignored = {".git", "node_modules", "target", "dist", "build", "vendor", ".idea", ".vscode"}
    candidates = []
    for path in repo_root.rglob("*"):
        if not path.is_dir() or any(part in ignored for part in path.relative_to(repo_root).parts):
            continue
        relative = path.relative_to(repo_root)
        if len(relative.parts) <= 3 and _has_project_marker(path):
            candidates.append(path)
    # A single nested application can be selected safely. Multiple applications
    # mean a repository topology: keep the full checkout so deployment files
    # can reference sibling frontend/backend directories.
    if len(candidates) == 1:
        relative = candidates[0].relative_to(repo_root).as_posix()
        return candidates[0], relative
    if len(candidates) > 1:
        return repo_root, ""
    return repo_root, ""


def stage_source(project: Project, db, workspace_key: str | None = None) -> tuple[str, str, str | None, str]:
    builder_root = Path(settings.build_data_root) / "builder"
    workspace_root = builder_root / "projects" / project.slug
    workspace_root.mkdir(parents=True, exist_ok=True)
    run_root = workspace_root / "runs"
    run_root.mkdir(parents=True, exist_ok=True)
    safe_key = re.sub(r"[^a-zA-Z0-9_.-]+", "-", workspace_key or "analysis")[:64]
    temp = tempfile.mkdtemp(prefix=f"{safe_key}-", dir=run_root)
    if project.source_type == SourceType.upload:
        if not project.source_path or not Path(project.source_path).exists():
            raise RuntimeError("项目还没有上传源码")
        shutil.copytree(project.source_path, temp, dirs_exist_ok=True)
        return temp, "upload", temp, ""

    if not project.git_url:
        raise RuntimeError("Git 地址为空")
    url, branch, requested_path = git_source_location(project.git_url, project.git_branch)
    safe_url = url
    env = None
    credential = db.get(GitCredential, project.git_credential_id) if project.git_credential_id else None
    if credential:
        secret = decrypt(credential.secret_encrypted) or ""
        if credential.auth_type in ("token", "password") and url.startswith(("http://", "https://")):
            parts = urlsplit(url)
            username = quote(credential.username or "oauth2", safe="")
            auth = f"{username}:{quote(secret, safe='')}@{parts.netloc}"
            url = urlunsplit((parts.scheme, auth, parts.path, parts.query, parts.fragment))
        elif credential.auth_type == "ssh_key":
            key_path = Path(temp).parent / f"key-{project.id}"
            key_path.write_text(secret)
            key_path.chmod(0o600)
            env = {"GIT_SSH_COMMAND": f"ssh -i {key_path} -o StrictHostKeyChecking=no"}
    proxy_config = get_proxy_config(db)
    proxy_env = {}
    if proxy_config and proxy_config.enabled:
        proxy_env = {
            "HTTP_PROXY": proxy_config.http_proxy or proxy_config.https_proxy,
            "HTTPS_PROXY": proxy_config.https_proxy or proxy_config.http_proxy,
            "NO_PROXY": proxy_config.no_proxy,
        }
    old_env = {}
    import os
    for key, value in proxy_env.items():
        old_env[key] = os.environ.get(key)
        if value:
            os.environ[key] = value
    if env:
        old_env["GIT_SSH_COMMAND"] = os.environ.get("GIT_SSH_COMMAND")
        os.environ.update(env)
    key_path = locals().get("key_path")
    try:
        with source_cache_guard(project.id, workspace_root):
            # Keep one shallow, immutable checkout as the Git object cache.
            # Every analysis/deployment receives its own shared local clone,
            # so git clean and package-manager cleanup can never race another
            # task of the same project.
            checkout = workspace_root / "source-cache"
            shallow_marker = checkout / ".git" / "shallow"
            if checkout.exists() and not shallow_marker.exists():
                shutil.rmtree(checkout, ignore_errors=True)
            if not (checkout / ".git").exists():
                shutil.rmtree(checkout, ignore_errors=True)
                repo = Repo.clone_from(
                    url, str(checkout), branch=branch or None, depth=1, single_branch=True,
                )
                repo.remote("origin").set_url(safe_url)
            else:
                repo = Repo(str(checkout))
                origin = repo.remote("origin")
                origin.set_url(url)
                try:
                    fetch_branch = branch or repo.active_branch.name
                    origin.fetch(
                        refspec=f"+refs/heads/{fetch_branch}:refs/remotes/origin/{fetch_branch}",
                        depth=1,
                        prune=True,
                    )
                    repo.git.checkout("-B", fetch_branch, f"origin/{fetch_branch}")
                    repo.git.reset("--hard", f"origin/{fetch_branch}")
                    repo.git.clean("-fdx")
                finally:
                    origin.set_url(safe_url)
            revision = repo.head.commit.hexsha[:12]
            run_repo = Repo.clone_from(str(checkout), temp, shared=True, no_hardlinks=True)
            run_repo.git.checkout("--detach", revision)
    finally:
        for key, value in old_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        if key_path:
            Path(key_path).unlink(missing_ok=True)
    source_root, source_path = discover_source_root(Path(temp), requested_path)
    return str(source_root), revision, temp, source_path


def detect_build(path: str, requested: str) -> tuple[str, str | None]:
    root = Path(path)
    compose_path = _find_compose(root)
    compose = compose_path.relative_to(root).as_posix() if compose_path else None
    dockerfile = (root / "Dockerfile").exists()
    if requested == "compose" and not compose:
        raise RuntimeError("未找到 Compose 文件")
    if requested == "dockerfile" and not dockerfile:
        raise RuntimeError("未找到 Dockerfile")
    if requested == "compose" or (requested == "auto" and compose):
        return "compose", compose
    if requested == "dockerfile" or dockerfile:
        return "dockerfile", "Dockerfile"
    raise RuntimeError("未找到 Dockerfile 或 Docker Compose 文件")


def detect_container_port(path: str, dockerfile_name: str = "Dockerfile") -> int | None:
    dockerfile = Path(path) / dockerfile_name
    if dockerfile.exists():
        match = re.search(r"(?im)^\s*EXPOSE\s+(\d+)", dockerfile.read_text(errors="ignore"))
        if match:
            return int(match.group(1))
    return None


def dockerfile_base_images(path: str, dockerfile_name: str) -> list[str]:
    dockerfile = Path(path) / dockerfile_name
    if not dockerfile.exists():
        return []
    images = []
    for match in re.finditer(r"(?im)^\s*FROM\s+(?:--platform=\S+\s+)?([^\s]+)", dockerfile.read_text(errors="ignore")):
        image = match.group(1).strip()
        if image and "$" not in image and image.lower() != "scratch" and image not in images:
            images.append(image)
    return images


def detect_java_version(path: str) -> int:
    """Choose the project's declared Java level before generating a build image."""
    root = Path(path)
    values = []
    for pom in list(root.rglob("pom.xml"))[:80]:
        text = pom.read_text(errors="ignore")
        for tag in ("java.version", "maven.compiler.source", "maven.compiler.target"):
            values.extend(re.findall(rf"<{re.escape(tag)}>\s*([^<]+)\s*</{re.escape(tag)}>", text, re.I))
    for value in values:
        match = re.search(r"(?:1\.)?(8|11|17|21)", value.strip())
        if match:
            return int(match.group(1))
    # JDK 17 is the broadly compatible modern default. JDK 21 is too new for
    # many legacy Lombok/compiler combinations and should only be explicit.
    return 17


_FRONTEND_API_ENV_KEYS = (
    "VUE_APP_BASE_API", "VITE_API_BASE_URL", "VITE_BASE_API",
    "API_BASE_URL", "API_PREFIX",
)


def _public_path_from_value(value: str) -> str | None:
    """Return a usable public URL prefix without guessing one.

    A bare external origin (for example ``https://api.example.com``) contains
    no path evidence and is deliberately ignored.  The caller must then use
    another source signal such as the production dotenv file or an Nginx
    location instead of silently inventing ``/api``.
    """
    raw = str(value or "").strip().strip("'\"").rstrip(";,)")
    if not raw or any(token in raw for token in ("${", "$VITE_", "$VUE_", "{{")):
        return None
    if raw.startswith(("http://", "https://", "//")):
        parsed = urlsplit("https:" + raw if raw.startswith("//") else raw)
        raw = parsed.path or ""
    if not raw.startswith("/") or raw == "/":
        return None
    raw = re.sub(r"/{2,}", "/", raw.split("?", 1)[0].split("#", 1)[0])
    # These are page/static paths, not API gateway prefixes.
    if raw.lower().startswith(("/assets/", "/static/", "/public/", "/src/")):
        return None
    return raw.rstrip("/") or None


def detect_frontend_api_routes(path: str) -> dict:
    """Detect the one effective frontend API prefix from source evidence.

    The detector ranks runtime configuration, production dotenv files,
    request-client ``baseURL`` values and Nginx proxy locations.  It returns a
    single primary route rather than publishing every development/staging
    alias found in the repository.
    """
    root = Path(path)
    ignored = {".git", "node_modules", "target", "dist", "build", ".venv", "vendor"}
    candidates: dict[str, dict] = {}

    def add(value: str, score: int, source: str, strip_prefix: bool | None = None) -> None:
        public_path = _public_path_from_value(value)
        if not public_path:
            return
        # Production is stronger evidence than development/staging aliases.
        lowered = public_path.lower()
        adjusted = score + (8 if "prod" in lowered else 0) - (8 if any(x in lowered for x in ("stage", "dev", "test")) else 0)
        row = candidates.setdefault(public_path, {
            "path": public_path,
            "score": adjusted,
            "strip_prefix": strip_prefix,
            "evidence": [],
        })
        if adjusted > int(row["score"]):
            row["score"] = adjusted
        if strip_prefix is not None:
            row["strip_prefix"] = strip_prefix
        if source not in row["evidence"]:
            row["evidence"].append(source)

    env_pattern = re.compile(
        rf"(?m)^\s*(?:{'|'.join(map(re.escape, _FRONTEND_API_ENV_KEYS))})\s*=\s*([^\r\n#]+)"
    )
    production_origin_sources: list[str] = []
    staged_relative_routes: list[tuple[str, str]] = []
    for env_file in root.rglob(".env*"):
        if not env_file.is_file() or any(part in ignored for part in env_file.relative_to(root).parts):
            continue
        relative = env_file.relative_to(root).as_posix()
        name = env_file.name.lower()
        score = 96 if "production" in name or name in {".env", ".env.local"} else 68
        text_value = env_file.read_text(encoding="utf-8", errors="replace")
        for match in env_pattern.finditer(text_value):
            raw_value = match.group(1).strip().strip("'\"")
            relative_path = _public_path_from_value(raw_value)
            if "production" in name and raw_value.startswith(("http://", "https://", "//")) and not relative_path:
                # A production frontend that points at a bare legacy API
                # origin still needs a same-origin path when the platform
                # takes over routing.  Keep that fact as evidence; do not
                # silently fall back to a global /api convention.
                production_origin_sources.append(relative)
            if "staging" in name and relative_path:
                staged_relative_routes.append((relative_path, relative))
            add(raw_value, score, relative)

    # Vue CLI projects commonly keep production on a legacy absolute API
    # origin while the staging file describes the intended gateway path (for
    # example /stage-api).  `npm run build` selects .env.production, so expose
    # neither the staging route nor a guessed /api route.  Derive the matching
    # production path from both pieces of source evidence instead.
    if production_origin_sources:
        for staged_path, staged_source in staged_relative_routes:
            production_path = re.sub(r"(?i)(?:stage|staging)", "prod", staged_path)
            if production_path != staged_path:
                evidence = f"{production_origin_sources[0]} + {staged_source}（生产外部域名按同项目环境命名归一）"
                add(production_path, 106, evidence, True)

    for runtime_config in root.rglob("postUrl.js"):
        if not runtime_config.is_file() or any(part in ignored for part in runtime_config.relative_to(root).parts):
            continue
        relative = runtime_config.relative_to(root).as_posix()
        text_value = runtime_config.read_text(encoding="utf-8", errors="replace")
        for match in re.finditer(r"(?m)^\s*(?:const|let|var)\s+IP\s*=\s*['\"]([^'\"]+)['\"]", text_value):
            add(match.group(1), 105, relative)

    source_suffixes = {".js", ".jsx", ".ts", ".tsx", ".vue", ".mjs", ".cjs"}
    for source_file in root.rglob("*"):
        if not source_file.is_file() or source_file.suffix.lower() not in source_suffixes:
            continue
        if any(part in ignored for part in source_file.relative_to(root).parts) or source_file.stat().st_size > 1_000_000:
            continue
        relative = source_file.relative_to(root).as_posix()
        text_value = source_file.read_text(encoding="utf-8", errors="replace")
        for match in re.finditer(r"\bbaseURL\s*:\s*['\"]([^'\"]+)['\"]", text_value):
            add(match.group(1), 88, relative)

    nginx_names = {"nginx.conf", "default.conf"}
    for config_file in root.rglob("*"):
        if not config_file.is_file() or (config_file.name not in nginx_names and config_file.suffix.lower() != ".conf"):
            continue
        if any(part in ignored for part in config_file.relative_to(root).parts) or config_file.stat().st_size > 1_000_000:
            continue
        relative = config_file.relative_to(root).as_posix()
        text_value = config_file.read_text(encoding="utf-8", errors="replace")
        # This bounded block matcher covers ordinary generated/hand-written
        # location blocks without trying to implement a complete Nginx parser.
        for match in re.finditer(r"location\s+(?:\^~\s+|=\s+|~\*?\s+)?(?P<path>/[^\s{]*)\s*\{(?P<body>[^{}]*)\}", text_value, re.I | re.S):
            body = match.group("body")
            proxy = re.search(r"proxy_pass\s+(?P<url>https?://[^;\s]+)\s*;", body, re.I)
            if proxy:
                # Nginx only removes the matched public prefix when the
                # proxy_pass URI is the upstream root.  A target such as
                # ``location /api/ { proxy_pass http://backend/api/; }`` keeps
                # /api/ and must not be represented as strip_prefix=true.
                # A proxy_pass without a URI also preserves the full request.
                location_path = match.group("path")
                upstream_path = urlsplit(proxy.group("url")).path
                strip_prefix = bool(
                    location_path != "/" and upstream_path == "/"
                )
                add(location_path, 82, relative, strip_prefix)

    if not candidates:
        return {"primary_path": None, "routes": [], "evidence": []}
    selected = max(candidates.values(), key=lambda row: (int(row["score"]), len(row["evidence"]), -len(row["path"])))
    public_path = str(selected["path"]).rstrip("/")
    return {
        "primary_path": public_path,
        "routes": [{
            "path": public_path + "/",
            # Preserve an observed public prefix unless a production proxy
            # rule explicitly proves that it is only an external alias. A
            # guessed strip silently turns valid backend routes into frontend
            # HTML responses and is much harder to diagnose than a 404.
            "strip_prefix": False if selected["strip_prefix"] is None else bool(selected["strip_prefix"]),
        }],
        "evidence": list(selected["evidence"]),
        "candidates": sorted(
            ({"path": row["path"], "score": row["score"], "evidence": row["evidence"]} for row in candidates.values()),
            key=lambda row: (-int(row["score"]), row["path"]),
        ),
    }


def optimize_staged_sources(path: str) -> list[str]:
    """Rewrite only the isolated release copy so nested build files use reachable mirrors."""
    root = Path(path)
    source_replacements = {
        "registry.npmjs.org": "registry.npmmirror.com",
        "https://pypi.org/simple": "https://pypi.tuna.tsinghua.edu.cn/simple",
        "https://repo.maven.apache.org/maven2": "https://maven.aliyun.com/repository/public",
        "http://deb.debian.org": "https://mirrors.tuna.tsinghua.edu.cn",
        "http://archive.ubuntu.com": "https://mirrors.tuna.tsinghua.edu.cn",
        "http://security.ubuntu.com": "https://mirrors.tuna.tsinghua.edu.cn",
    }
    changed = []
    for candidate in root.rglob("Dockerfile*"):
        if not candidate.is_file() or any(part in {".git", "node_modules", "target"} for part in candidate.parts):
            continue
        original = candidate.read_text(errors="ignore")
        optimized = original
        for old, new in source_replacements.items():
            optimized = optimized.replace(old, new)
        if "RUN apt-get update" in optimized and "mirrors.tuna.tsinghua.edu.cn|g" not in optimized:
            optimized = optimized.replace(
                "RUN apt-get update",
                "RUN sed -i 's|deb.debian.org|mirrors.tuna.tsinghua.edu.cn|g; "
                "s|security.debian.org|mirrors.tuna.tsinghua.edu.cn|g; "
                "s|archive.ubuntu.com|mirrors.tuna.tsinghua.edu.cn|g; "
                "s|security.ubuntu.com|mirrors.tuna.tsinghua.edu.cn|g' "
                "/etc/apt/sources.list /etc/apt/sources.list.d/debian.sources 2>/dev/null || true; apt-get update",
            )
        if optimized != original:
            candidate.write_text(optimized)
            changed.append(candidate.relative_to(root).as_posix())
    return changed


def apply_safe_build_repairs(path: str, previous_error: str, deployment_mode: str = "managed_fresh") -> list[str]:
    """Apply bounded, reversible fixes to the isolated release copy only.

    AI may classify a known failure, but it never receives permission to run
    arbitrary shell commands or change the source repository. Each supported
    repair is implemented and audited here.
    """
    error = (previous_error or "").lower()
    changed: list[str] = []
    root = Path(path)
    generated_dockerfiles = list(root.rglob("Dockerfile*")) + list(root.rglob(".yunzhou*.Dockerfile"))
    generated_dockerfiles = list(dict.fromkeys(generated_dockerfiles))
    # Gradle's official distribution endpoint is extremely slow on the
    # domestic build nodes. Rewrite only the disposable wrapper metadata to a
    # byte-identical mirror; Gradle still verifies the configured checksum.
    for wrapper in root.rglob("gradle-wrapper.properties"):
        if not wrapper.is_file() or ".git" in wrapper.parts:
            continue
        original = wrapper.read_text(encoding="utf-8", errors="replace")
        repaired = original.replace(
            "https\\://services.gradle.org/distributions/",
            "https\\://mirrors.cloud.tencent.com/gradle/",
        ).replace(
            "https://services.gradle.org/distributions/",
            "https://mirrors.cloud.tencent.com/gradle/",
        )
        if repaired != original:
            wrapper.write_text(repaired, encoding="utf-8")
            changed.append(wrapper.relative_to(root).as_posix())
    for gradle_file in root.rglob("build.gradle"):
        if not gradle_file.is_file() or ".git" in gradle_file.parts:
            continue
        original = gradle_file.read_text(encoding="utf-8", errors="replace")
        if "mavenCentral()" not in original or "maven.aliyun.com/repository/public" in original:
            continue
        repaired = original.replace(
            "mavenCentral()",
            "maven { url 'https://maven.aliyun.com/repository/public' }\n    mavenCentral()",
        )
        gradle_file.write_text(repaired, encoding="utf-8")
        changed.append(gradle_file.relative_to(root).as_posix())
    # The platform intentionally uses the classic builder and shared host
    # package caches. AI-generated BuildKit cache mounts are therefore invalid
    # syntax. Strip only the cache-mount prefix and preserve the command.
    for dockerfile in generated_dockerfiles:
        if not dockerfile.is_file() or ".git" in dockerfile.parts:
            continue
        original = dockerfile.read_text(encoding="utf-8", errors="replace")
        # The legacy 3.10 kernels still present on some target nodes reject
        # the pid-file write used by the moving nginx:alpine tag. Pin the
        # platform-tested release instead of allowing a future base-image
        # update to break an unchanged application at runtime.
        original_pinned = re.sub(
            r"(?im)^(\s*FROM\s+)nginx:alpine(\s*(?:AS\s+\S+)?\s*)$",
            r"\1nginx:1.27-alpine\2",
            original,
        )
        if original_pinned != original:
            dockerfile.write_text(original_pinned, encoding="utf-8")
            original = original_pinned
            changed.append(dockerfile.relative_to(root).as_posix())
        repaired = re.sub(
            r"(?m)^(\s*RUN)\s+--mount=type=cache(?:,[^\s]+)*\s+",
            r"\1 ",
            original,
        )
        if repaired != original:
            dockerfile.write_text(repaired, encoding="utf-8")
            changed.append(dockerfile.relative_to(root).as_posix())
        # Generated Debian/Ubuntu stages are created after the initial source
        # optimization pass. Apply the same reachable mirror before package
        # installation so apt cannot silently consume the whole preflight
        # timeout on an overseas endpoint.
        current = dockerfile.read_text(encoding="utf-8", errors="replace")
        if "apt-get update" in current and "mirrors.tuna.tsinghua.edu.cn|g" not in current:
            mirrored = current.replace(
                "apt-get update",
                "sed -i 's|deb.debian.org|mirrors.tuna.tsinghua.edu.cn|g; "
                "s|security.debian.org|mirrors.tuna.tsinghua.edu.cn|g; "
                "s|archive.ubuntu.com|mirrors.tuna.tsinghua.edu.cn|g; "
                "s|security.ubuntu.com|mirrors.tuna.tsinghua.edu.cn|g' "
                "/etc/apt/sources.list /etc/apt/sources.list.d/debian.sources 2>/dev/null || true; apt-get update",
            )
            dockerfile.write_text(mirrored, encoding="utf-8")
            relative = dockerfile.relative_to(root).as_posix()
            if relative not in changed:
                changed.append(relative)
    # Git on Windows/macOS often hides import-path case mistakes that fail in
    # Linux containers. Repair only an unambiguous same-directory match in the
    # disposable release copy (for example noTasks.module.css ->
    # notasks.module.css); never invent a missing file.
    import_pattern = re.compile(r"(?P<prefix>(?:from\s+|import\s*)['\"])(?P<path>\.{1,2}/[^'\"]+)(?P<suffix>['\"])")
    for source_file in root.rglob("*"):
        if not source_file.is_file() or source_file.suffix.lower() not in {".js", ".jsx", ".ts", ".tsx", ".vue", ".svelte"}:
            continue
        if any(part in {".git", "node_modules", "dist", "build"} for part in source_file.relative_to(root).parts):
            continue
        original = source_file.read_text(encoding="utf-8", errors="replace")

        def repair_import(match: re.Match) -> str:
            value = match.group("path")
            requested = source_file.parent / value
            parent = requested.parent
            if not parent.is_dir():
                return match.group(0)
            exact_name = requested.name
            matches = [entry.name for entry in parent.iterdir() if entry.name.lower() == exact_name.lower()]
            if len(matches) != 1 or matches[0] == exact_name:
                return match.group(0)
            repaired_value = value[: -len(exact_name)] + matches[0]
            return match.group("prefix") + repaired_value + match.group("suffix")

        repaired = import_pattern.sub(repair_import, original)
        if repaired != original:
            source_file.write_text(repaired, encoding="utf-8")
            changed.append(source_file.relative_to(root).as_posix())
    # Some legacy RuoYi frontends label the captcha data URL as GIF while the
    # paired Java controller explicitly serializes it as JPEG. Browsers are
    # allowed to reject that mismatched data URL, leaving a broken image even
    # though `/captchaImage` succeeds. Repair only when both sides are present
    # in the same isolated release, so unrelated base64 images are untouched.
    captcha_controller_writes_jpeg = any(
        re.search(r'ImageIO\.write\s*\([^,]+,\s*["\'](?:jpg|jpeg)["\']', file.read_text(encoding="utf-8", errors="replace"), re.I)
        for file in root.rglob("*CaptchaController.java")
        if file.is_file() and ".git" not in file.parts
    )
    if captcha_controller_writes_jpeg:
        for source_file in root.rglob("*"):
            if not source_file.is_file() or source_file.suffix.lower() not in {".js", ".jsx", ".ts", ".tsx", ".vue"}:
                continue
            if any(part in {".git", "node_modules", "dist", "build"} for part in source_file.relative_to(root).parts):
                continue
            original = source_file.read_text(encoding="utf-8", errors="replace")
            if "captchaImage" not in original and "codeUrl" not in original:
                continue
            repaired = original.replace("data:image/gif;base64,", "data:image/jpeg;base64,")
            if repaired != original:
                source_file.write_text(repaired, encoding="utf-8")
                relative = source_file.relative_to(root).as_posix()
                if relative not in changed:
                    changed.append(relative)
    # A separated frontend/backend application has one public API prefix owned
    # by the platform gateway, but the prefix is project evidence rather than a
    # platform constant.  Detect it before rewriting an external runtime origin
    # and never turn every development/staging alias into a public route.
    compose_service_names: set[str] = set()
    for compose_file in root.glob(".yunzhou*.yml"):
        try:
            document = yaml.safe_load(compose_file.read_text(encoding="utf-8", errors="replace")) or {}
        except yaml.YAMLError:
            continue
        services = document.get("services") if isinstance(document, dict) else None
        if isinstance(services, dict):
            compose_service_names.update(str(name).lower() for name in services)
    has_frontend = any(re.search(r"(?:^|[-_.])(front(?:end)?|web|ui)(?:$|[-_.])", name) for name in compose_service_names)
    has_backend = any(re.search(r"(?:^|[-_.])(back(?:end)?|api|server)(?:$|[-_.])", name) for name in compose_service_names)
    if has_frontend and has_backend:
        detected_route = detect_frontend_api_routes(path)
        api_prefix = str(detected_route.get("primary_path") or "")
        api_setting = re.compile(
            rf"(?m)^(\s*(?:{'|'.join(map(re.escape, _FRONTEND_API_ENV_KEYS))})\s*=\s*)([^\r\n#]+)"
        )
        for env_file in root.rglob(".env*"):
            if not env_file.is_file() or any(part in {".git", "node_modules", "dist", "build"} for part in env_file.relative_to(root).parts):
                continue
            env_name = env_file.name.lower()
            if env_name not in {".env", ".env.local"} and "production" not in env_name:
                continue
            original = env_file.read_text(encoding="utf-8", errors="replace")
            # Keep an already-relative source prefix unchanged.  Only replace
            # an environment-bound absolute origin when another source signal
            # established the effective public path.
            def normalize_api_setting(match: re.Match) -> str:
                value = match.group(2).strip().strip("'\"")
                if api_prefix and value.startswith(("http://", "https://", "//")):
                    quote_char = "\"" if match.group(2).strip().startswith("\"") else ""
                    return match.group(1) + quote_char + api_prefix + quote_char
                return match.group(0)

            repaired = api_setting.sub(normalize_api_setting, original)
            if repaired != original:
                env_file.write_text(repaired, encoding="utf-8")
                changed.append(env_file.relative_to(root).as_posix())
        for runtime_config in root.rglob("postUrl.js"):
            if not runtime_config.is_file() or any(part in {".git", "node_modules", "dist", "build"} for part in runtime_config.relative_to(root).parts):
                continue
            original = runtime_config.read_text(encoding="utf-8", errors="replace")
            if "configUrl" not in original or "reqDomain" not in original:
                continue
            repaired = original
            if api_prefix:
                repaired = re.sub(
                    r"(?m)^(\s*(?:const|let|var)\s+IP\s*=\s*)['\"](?:https?:)?//[^'\"]*['\"](\s*;?)",
                    lambda match: match.group(1) + json.dumps(api_prefix) + match.group(2),
                    original,
                    count=1,
                )
            if repaired != original:
                runtime_config.write_text(repaired, encoding="utf-8")
                changed.append(runtime_config.relative_to(root).as_posix())
    # Some applications use a JSON snapshot only for legacy import even when
    # MySQL is the active persistence driver.  COMMERCE_OPS_DATA is therefore
    # a file, while its parent directory is the mounted volume.  Treating the
    # volume root itself as the file deterministically raises EISDIR.
    reads_commerce_data_as_file = any(
        "readFileSync(dataPath" in file.read_text(encoding="utf-8", errors="replace")
        for file in root.rglob("*.mjs")
        if file.is_file() and "node_modules" not in file.parts
    )
    if reads_commerce_data_as_file:
        for compose_file in root.glob(".yunzhou*.yml"):
            try:
                document = yaml.safe_load(compose_file.read_text(encoding="utf-8", errors="replace"))
            except yaml.YAMLError:
                continue
            services = document.get("services") if isinstance(document, dict) else None
            repaired = False
            for service in (services or {}).values():
                env = service.get("environment") if isinstance(service, dict) else None
                if not isinstance(env, dict):
                    continue
                value = str(env.get("COMMERCE_OPS_DATA") or "").rstrip("/")
                if value and not Path(value).suffix:
                    env["COMMERCE_OPS_DATA"] = value + "/commerce-ops.json"
                    repaired = True
            if repaired:
                compose_file.write_text(yaml.safe_dump(document, allow_unicode=True, sort_keys=False), encoding="utf-8")
                changed.append(compose_file.relative_to(root).as_posix())
    # Legacy nginx files frequently use a compact upstream hostname (for
    # example `wmsapi`) while the generated Compose plan follows readable
    # kebab-case (`wms-api`). Docker DNS treats those as different names. Add
    # a network alias only when the names are an unambiguous punctuation-only
    # match; this preserves both the source nginx configuration and the AI
    # service topology without guessing an unrelated destination.
    upstream_hosts: set[str] = set()
    upstream_pattern = re.compile(r"(?im)\b(?:proxy_pass\s+https?://|server\s+)([a-z][a-z0-9_-]*)(?::\d+)?")
    for config_file in root.rglob("*"):
        if not config_file.is_file() or config_file.suffix.lower() not in {".conf", ".template"}:
            continue
        if any(part in {".git", "node_modules", "dist", "build"} for part in config_file.relative_to(root).parts):
            continue
        upstream_hosts.update(upstream_pattern.findall(config_file.read_text(encoding="utf-8", errors="replace")))
    if upstream_hosts:
        for compose_file in root.glob(".yunzhou*.yml"):
            try:
                document = yaml.safe_load(compose_file.read_text(encoding="utf-8", errors="replace"))
            except yaml.YAMLError:
                continue
            services = document.get("services") if isinstance(document, dict) else None
            if not isinstance(services, dict):
                continue
            normalized_services: dict[str, list[str]] = {}
            for service_name in services:
                normalized_services.setdefault(re.sub(r"[^a-z0-9]", "", service_name.lower()), []).append(service_name)
            repaired = False
            for host in sorted(upstream_hosts):
                matches = normalized_services.get(re.sub(r"[^a-z0-9]", "", host.lower()), [])
                if len(matches) != 1 or matches[0] == host:
                    continue
                target = services.get(matches[0])
                if not isinstance(target, dict):
                    continue
                networks = target.get("networks")
                if networks is None:
                    networks = {"default": {"aliases": [host]}}
                elif isinstance(networks, list):
                    networks = {name: ({"aliases": [host]} if name == "default" else {}) for name in networks}
                    networks.setdefault("default", {"aliases": [host]})
                elif isinstance(networks, dict):
                    default_network = networks.get("default")
                    if not isinstance(default_network, dict):
                        default_network = {}
                    aliases = list(default_network.get("aliases") or [])
                    if host not in aliases:
                        aliases.append(host)
                    default_network["aliases"] = aliases
                    networks["default"] = default_network
                target["networks"] = networks
                repaired = True
            if repaired:
                compose_file.write_text(yaml.safe_dump(document, allow_unicode=True, sort_keys=False), encoding="utf-8")
                relative = compose_file.relative_to(root).as_posix()
                if relative not in changed:
                    changed.append(relative)
    # A verified deployment experience showed that `concurrently` may invoke
    # `ps` while supervising sibling Node processes. Slim runtime images do
    # not include it. Apply the learned prerequisite to generated files during
    # source preflight instead of waiting for another production crash.
    uses_concurrently = any(
        '"concurrently"' in file.read_text(encoding="utf-8", errors="replace")
        for file in root.rglob("package.json")
        if file.is_file() and "node_modules" not in file.parts
    )
    if uses_concurrently:
        for dockerfile in generated_dockerfiles:
            if not dockerfile.is_file() or not dockerfile.name.startswith(".yunzhou"):
                continue
            text = dockerfile.read_text(encoding="utf-8", errors="replace")
            if "procps" in text:
                continue
            final_stage = re.split(r"(?im)(?=^\s*FROM\s+)", text)[-1]
            install = (
                "RUN apk add --no-cache procps\n"
                if re.search(r"(?im)^\s*FROM\s+\S*alpine", final_stage)
                else "RUN apt-get update && apt-get install --no-install-recommends -y procps "
                     "&& rm -rf /var/lib/apt/lists/*\n"
            )
            marker = re.search(r"(?im)^\s*USER\s+", text)
            position = marker.start() if marker else len(text)
            text = text[:position] + install + text[position:]
            dockerfile.write_text(text.rstrip() + "\n", encoding="utf-8")
            changed.append(dockerfile.relative_to(root).as_posix())
    # Public proxy.golang.org is frequently unreachable from domestic build
    # nodes. Keep module verification enabled while using a reachable module
    # proxy, then fall back to the origin when necessary.
    for dockerfile in generated_dockerfiles:
        if not dockerfile.is_file() or not dockerfile.name.startswith(".yunzhou"):
            continue
        text = dockerfile.read_text(encoding="utf-8", errors="replace")
        if re.search(r"(?im)^\s*FROM\s+golang:", text) and "GOPROXY=" not in text:
            repaired = re.sub(
                r"(?im)^(\s*FROM\s+golang:[^\n]+\n)",
                r"\1ENV GOPROXY=https://goproxy.cn,direct\n",
                text,
            )
            if repaired != text:
                dockerfile.write_text(repaired, encoding="utf-8")
                changed.append(dockerfile.relative_to(root).as_posix())
    # Pure-Go web services do not need a native toolchain. A generated plan
    # that forces CGO can spend the whole rehearsal window compiling libc and
    # still produce a less portable binary. After an observed build timeout,
    # retry the isolated plan with a static Go binary; genuine CGO projects
    # will fail explicitly and remain blocked rather than being published.
    if "building" in error and ("899." in error or "timed out" in error or "timeout" in error):
        for candidate in dict.fromkeys(generated_dockerfiles + list(root.glob(".yunzhou*.yml"))):
            if not candidate.is_file() or ".git" in candidate.parts:
                continue
            original = candidate.read_text(encoding="utf-8", errors="replace")
            if "go build" not in original or "CGO_ENABLED=1" not in original:
                continue
            repaired = original.replace("CGO_ENABLED=1", "CGO_ENABLED=0")
            candidate.write_text(repaired, encoding="utf-8")
            relative = candidate.relative_to(root).as_posix()
            if relative not in changed:
                changed.append(relative)
    # Gradle's POSIX wrapper invokes xargs. Minimal JDK images may omit
    # findutils, so an otherwise valid project fails before Gradle starts.
    for dockerfile in generated_dockerfiles:
        if not dockerfile.is_file() or not dockerfile.name.startswith(".yunzhou"):
            continue
        text = dockerfile.read_text(encoding="utf-8", errors="replace")
        if "gradlew" in text and "findutils" not in text:
            stages = re.split(r"(?im)(?=^\s*FROM\s+)", text)
            repaired_stages = []
            for stage in stages:
                if "gradlew" not in stage:
                    repaired_stages.append(stage)
                    continue
                marker = re.search(r"(?im)^\s*(?:WORKDIR|COPY|ADD|RUN)\s+", stage)
                if not marker:
                    repaired_stages.append(stage)
                    continue
                install = (
                    "RUN apk add --no-cache findutils\n"
                    if re.search(r"(?im)^\s*FROM\s+\S*alpine", stage)
                    else (
                        "RUN dnf install -y findutils && dnf clean all\n"
                        if re.search(r"(?im)^\s*FROM\s+amazoncorretto:", stage)
                        else "RUN apt-get update && apt-get install --no-install-recommends -y findutils && rm -rf /var/lib/apt/lists/*\n"
                    )
                )
                stage = stage[:marker.start()] + install + stage[marker.start():]
                repaired_stages.append(stage)
            repaired = "".join(repaired_stages)
            if repaired != text:
                dockerfile.write_text(repaired, encoding="utf-8")
                changed.append(dockerfile.relative_to(root).as_posix())
    # eve 0.69+ performs its own runtime guard and requires Node 24. AI plans
    # may otherwise choose the broadly compatible Node 22 LTS image, causing
    # a deterministic platform-generated Dockerfile failure before user code
    # is compiled. Detect the repository's build tool and lift only generated
    # Dockerfiles; the checked-out source remains untouched.
    uses_eve_build = any(
        '"eve"' in file.read_text(encoding="utf-8", errors="replace")
        and "eve build" in file.read_text(encoding="utf-8", errors="replace")
        for file in list(root.rglob("package.json"))[:100]
        if file.is_file() and "node_modules" not in file.parts
    )
    if uses_eve_build:
        for dockerfile in root.rglob("Dockerfile*"):
            if not dockerfile.is_file() or ".git" in dockerfile.parts:
                continue
            original = dockerfile.read_text(encoding="utf-8", errors="replace")
            repaired = re.sub(r"(?m)^(FROM\s+node:)22(?=[-:@])", r"\g<1>24", original)
            if repaired != original:
                dockerfile.write_text(repaired, encoding="utf-8")
                changed.append(str(dockerfile.relative_to(root)).replace("\\", "/"))
        for compose_file in root.glob(".yunzhou*.yml"):
            original = compose_file.read_text(encoding="utf-8", errors="replace")
            repaired = re.sub(r"(?m)(FROM\s+node:)22(?=[-:@])", r"\g<1>24", original)
            if repaired != original:
                compose_file.write_text(repaired, encoding="utf-8")
                relative = compose_file.relative_to(root).as_posix()
                if relative not in changed:
                    changed.append(relative)
    # Bun runs workspace postinstall hooks during dependency installation.
    # Prisma's config loader may require DATABASE_URL even though no database
    # connection is made by `prisma generate`. Ensure a harmless build-only
    # value exists before the first `bun install`; runtime Compose values still
    # override it and no real credential is embedded in the image.
    prisma_requires_database_url = any(
        "DATABASE_URL" in file.read_text(encoding="utf-8", errors="replace")
        for file in root.rglob("prisma.config.*")
        if file.is_file() and "node_modules" not in file.parts
    )
    if prisma_requires_database_url:
        for dockerfile in dict.fromkeys(generated_dockerfiles):
            if not dockerfile.is_file() or ".git" in dockerfile.parts:
                continue
            original = dockerfile.read_text(encoding="utf-8", errors="replace")
            install_at = original.find("RUN bun install")
            if install_at < 0 or "DATABASE_URL" in original[:install_at]:
                continue
            repaired = original[:install_at] + (
                "ARG DATABASE_URL=postgresql://postgres:build@127.0.0.1:5432/build?schema=public\n"
                "ENV DATABASE_URL=$DATABASE_URL\n"
            ) + original[install_at:]
            dockerfile.write_text(repaired, encoding="utf-8")
            relative = str(dockerfile.relative_to(root)).replace("\\", "/")
            if relative not in changed:
                changed.append(relative)
    # eve's just-bash sandbox is an optional peer dependency and some
    # repositories select that provider without declaring the package. Repair
    # only the isolated generated image after Docker reports that exact missing
    # package; never modify the checked-out manifests or lockfile.
    eve_manifest_detected = any(
        "eve" in manifest.read_text(encoding="utf-8", errors="replace").lower()
        for manifest in root.rglob("package.json")
        if "node_modules" not in manifest.parts and ".git" not in manifest.parts
    )
    if ("cannot find package 'just-bash'" in error and "eve" in error) or eve_manifest_detected:
        for dockerfile in dict.fromkeys(generated_dockerfiles):
            if not dockerfile.is_file() or ".git" in dockerfile.parts:
                continue
            original = dockerfile.read_text(encoding="utf-8", errors="replace")
            if "just-bash" in original:
                continue
            install_line = next(
                (line for line in original.splitlines() if line.lstrip().startswith("RUN ") and "bun install" in line),
                None,
            )
            if not install_line:
                continue
            # Keep installation and cache cleanup in one layer.  A separate
            # cleanup layer would still retain Bun's downloaded package cache
            # in the parent image and can turn a small monorepo into tens of
            # gigabytes when several Compose targets export concurrently.
            install_command = install_line.rstrip().removesuffix("\\")
            repaired = original.replace(
                install_line,
                install_command
                + " && bun add --dev just-bash --registry=https://registry.npmmirror.com"
                + " && rm -rf /root/.bun/install/cache /tmp/bun-*",
                1,
            )
            dockerfile.write_text(repaired, encoding="utf-8")
            relative = str(dockerfile.relative_to(root)).replace("\\", "/")
            if relative not in changed:
                changed.append(relative)
    # Older projects frequently carry a Yarn v1 lockfile that was not updated
    # with package.json. On an AI retry, relax only the immutable check in the
    # isolated generated Dockerfile; dependency resolution still fails on any
    # real package/version error and the repository lockfile is never edited.
    if "lockfile needs to be updated" in error and "frozen-lockfile" in error:
        for dockerfile in root.rglob("Dockerfile*"):
            if not dockerfile.is_file() or ".git" in dockerfile.parts:
                continue
            original = dockerfile.read_text(encoding="utf-8", errors="replace")
            repaired = re.sub(r"\s+--frozen-lockfile\b", "", original)
            if repaired != original:
                dockerfile.write_text(repaired, encoding="utf-8")
                relative = str(dockerfile.relative_to(root)).replace("\\", "/")
                if relative not in changed:
                    changed.append(relative)
    # A syntactically broken pnpm lockfile cannot be repaired by merely
    # relaxing --frozen-lockfile: pnpm parses the damaged YAML first.  When
    # the real preflight reports this exact condition, discard the lockfile
    # only inside the disposable release copy and let pnpm resolve a fresh
    # dependency graph.  The Git checkout and the user's repository remain
    # unchanged, while subsequent build/runtime errors are still surfaced.
    broken_pnpm_lock = False
    for lockfile in root.rglob("pnpm-lock.yaml"):
        if lockfile.is_file() and "node_modules" not in lockfile.parts:
            lock_text = lockfile.read_text(encoding="utf-8", errors="replace")
            for section in re.split(r"(?m)^(?=\S)", lock_text):
                keys = re.findall(r"(?m)^  ([^\s][^:]+(?:@[^:]+)?):\s*$", section)
                if len(keys) != len(set(keys)):
                    broken_pnpm_lock = True
                    break
    if broken_pnpm_lock or "err_pnpm_broken_lockfile" in error or (
        "lockfile" in error and "broken" in error and "duplicated mapping key" in error
    ):
        for dockerfile in generated_dockerfiles:
            if not dockerfile.is_file() or ".git" in dockerfile.parts:
                continue
            original = dockerfile.read_text(encoding="utf-8", errors="replace")
            repaired = re.sub(
                r"(?m)^(\s*RUN\s+)(pnpm\s+install)(?:\s+--frozen-lockfile)?",
                r"\1rm -f pnpm-lock.yaml && \2 --no-frozen-lockfile",
                original,
                count=1,
            )
            if repaired != original:
                dockerfile.write_text(repaired, encoding="utf-8")
                relative = dockerfile.relative_to(root).as_posix()
                if relative not in changed:
                    changed.append(relative)
    # A SvelteKit project using a server adapter does not emit /dist. If an AI
    # plan incorrectly selects an nginx static stage, retain the successful
    # build stage and run the project's own preview server in the disposable
    # image. This is triggered only by the exact missing-dist failure.
    svelte_server_build = any(
        "@sveltejs/adapter-" in manifest.read_text(encoding="utf-8", errors="replace")
        and "adapter-static" not in manifest.read_text(encoding="utf-8", errors="replace")
        for manifest in root.rglob("package.json")
        if manifest.is_file() and "node_modules" not in manifest.parts
    )
    if svelte_server_build:
        for dockerfile in generated_dockerfiles:
            if not dockerfile.is_file() or ".git" in dockerfile.parts:
                continue
            original = dockerfile.read_text(encoding="utf-8", errors="replace")
            if "COPY --from=build /app/dist" not in original:
                continue
            stages = list(re.finditer(r"(?im)^\s*FROM\s+", original))
            if len(stages) < 2:
                continue
            repaired = original[:stages[-1].start()] + (
                "FROM node:22-alpine\nWORKDIR /app\n"
                "COPY --from=build /app /app\n"
                "ENV HOST=0.0.0.0 PORT=4300\nEXPOSE 4300\n"
                'CMD ["npm", "run", "preview", "--", "--host", "0.0.0.0", "--port", "4300"]\n'
            )
            dockerfile.write_text(repaired, encoding="utf-8")
            relative = dockerfile.relative_to(root).as_posix()
            if relative not in changed:
                changed.append(relative)
    if broken_pnpm_lock:
        for compose_file in root.glob(".yunzhou*.yml"):
            original = compose_file.read_text(encoding="utf-8", errors="replace")
            repaired = re.sub(
                r"pnpm\s+install(?:\s+--frozen-lockfile)?",
                "rm -f pnpm-lock.yaml && pnpm install --no-frozen-lockfile",
                original,
                count=1,
            )
            if repaired != original:
                compose_file.write_text(repaired, encoding="utf-8")
                relative = compose_file.relative_to(root).as_posix()
                if relative not in changed:
                    changed.append(relative)
    lock_text = "\n".join(
        file.read_text(encoding="utf-8", errors="replace")
        for file in list(Path(path).rglob("package-lock.json"))[:20]
        if file.is_file() and "node_modules" not in file.parts
    ).lower()
    rolldown_lock_incomplete = "node_modules/rolldown" in lock_text and "@rolldown/binding-linux-x64-gnu" not in lock_text
    rolldown_binding_missing = rolldown_lock_incomplete or (
        "cannot find native binding" in error
        and "rolldown" in error
        and ("binding-linux" in error or "optional dependencies" in error)
    )
    if rolldown_binding_missing:
        for dockerfile in root.rglob("Dockerfile*"):
            if not dockerfile.is_file() or ".git" in dockerfile.parts:
                continue
            original = dockerfile.read_text(encoding="utf-8", errors="replace")
            repaired = re.sub(r"\bnpm\s+ci\b", "npm install --include=optional", original)
            # npm/cli#4828 can omit the platform package even after a regular
            # install when the lock was generated on another OS. Install the
            # exact native binding version used by the workspace explicitly.
            install_line = next(
                (line for line in repaired.splitlines() if line.lstrip().startswith("RUN ") and "npm install --include=optional" in line),
                None,
            )
            binding_fix = (
                "RUN ROLLDOWN_VERSION=$(node -p \"require('./admin-web/node_modules/rolldown/package.json').version\") "
                "&& npm install --prefix admin-web --no-save --include=optional "
                "--registry=\"https://registry.npmmirror.com\" \"@rolldown/binding-linux-x64-gnu@$ROLLDOWN_VERSION\""
            )
            if install_line and binding_fix not in repaired:
                repaired = repaired.replace(install_line, install_line + "\n" + binding_fix, 1)
            if repaired != original:
                dockerfile.write_text(repaired, encoding="utf-8")
                changed.append(str(dockerfile.relative_to(root)).replace("\\", "/"))
    # Some older/locked-down Docker nodes allow ordinary writes to a named
    # volume but their default seccomp/AppArmor profile rejects PostgreSQL's
    # durable pid/WAL writes with EPERM.  This was verified independently with
    # a fresh `postgres` container, so it is a node capability issue rather
    # than an application defect.  On a retry, relax only the affected
    # PostgreSQL service; never grant blanket privilege to the whole project.
    postgres_storage_blocked = (
        "operation not permitted" in error
        and ("postmaster.pid" in error or "pg_wal/" in error)
    )
    if postgres_storage_blocked:
        for compose_file in root.glob(".yunzhou*.yml"):
            try:
                document = yaml.safe_load(compose_file.read_text(encoding="utf-8", errors="replace")) or {}
            except yaml.YAMLError:
                continue
            services = document.get("services") if isinstance(document, dict) else None
            repaired = False
            for service in (services or {}).values():
                if not isinstance(service, dict) or "postgres" not in str(service.get("image") or "").lower():
                    continue
                options = list(service.get("security_opt") or [])
                for option in ("seccomp=unconfined", "apparmor=unconfined"):
                    if option not in options:
                        options.append(option)
                        repaired = True
                service["security_opt"] = options
            if repaired:
                compose_file.write_text(yaml.safe_dump(document, allow_unicode=True, sort_keys=False), encoding="utf-8")
                relative = compose_file.relative_to(root).as_posix()
                if relative not in changed:
                    changed.append(relative)
    # Spring treats @Value("${key}") without a default as startup-required.
    # In managed-fresh mode an old Kubernetes service URL must not be copied
    # into the new environment, but an optional outbound integration also
    # should not prevent the core application from starting.  On a verified
    # missing URL/URI placeholder, inject a deterministic disabled endpoint
    # into application services.  It is intentionally non-routable and keeps
    # the missing integration visible; passwords and arbitrary scalar values
    # are never guessed.
    placeholder_match = re.search(
        r"could not resolve placeholder ['\"]([^'\"]+)['\"]",
        previous_error or "",
        re.I,
    )
    if placeholder_match:
        placeholder = placeholder_match.group(1).strip()
        if re.search(r"(?:url|uri)$", placeholder, re.I):
            env_key = re.sub(r"[^A-Za-z0-9]", "_", placeholder).upper()
            fallback_url = "http://127.0.0.1:9/"
            if deployment_mode == "preserve_integrations":
                parts = placeholder.split(".")
                for config_file in sorted(root.rglob("application*.yml")) + sorted(root.rglob("application*.yaml")):
                    try:
                        value = yaml.safe_load(config_file.read_text(encoding="utf-8", errors="replace")) or {}
                        for part in parts:
                            value = value.get(part) if isinstance(value, dict) else None
                        if isinstance(value, str) and value.startswith(("http://", "https://")):
                            fallback_url = value.strip()
                            break
                    except (OSError, yaml.YAMLError):
                        continue
            spring_value: dict = {}
            spring_cursor = spring_value
            for part in placeholder.split(".")[:-1]:
                spring_cursor[part] = {}
                spring_cursor = spring_cursor[part]
            spring_cursor[placeholder.split(".")[-1]] = fallback_url
            for compose_file in root.glob(".yunzhou*.yml"):
                try:
                    document = yaml.safe_load(compose_file.read_text(encoding="utf-8", errors="replace")) or {}
                except yaml.YAMLError:
                    continue
                services = document.get("services") if isinstance(document, dict) else None
                repaired = False
                for service_name, service in (services or {}).items():
                    if not isinstance(service, dict) or not service.get("build"):
                        continue
                    environment = service.get("environment") or {}
                    environment_keys = (
                        {str(item).split("=", 1)[0] for item in environment}
                        if isinstance(environment, list)
                        else {str(key) for key in environment} if isinstance(environment, dict) else set()
                    )
                    is_spring_service = (
                        any(key.startswith("SPRING_") for key in environment_keys)
                        or any(token in str(service_name).lower() for token in ("api", "backend", "spring"))
                        or "8080" in {str(value) for value in (service.get("expose") or [])}
                    )
                    if not is_spring_service:
                        continue
                    if isinstance(environment, list):
                        if not any(str(item).split("=", 1)[0] == env_key for item in environment):
                            environment.append(f"{env_key}={fallback_url}")
                            repaired = True
                        if not any(str(item).split("=", 1)[0] == "SPRING_APPLICATION_JSON" for item in environment):
                            environment.append("SPRING_APPLICATION_JSON=" + json.dumps(spring_value, ensure_ascii=False))
                            repaired = True
                    elif isinstance(environment, dict) and env_key not in environment:
                        environment[env_key] = fallback_url
                        repaired = True
                    if isinstance(environment, dict) and "SPRING_APPLICATION_JSON" not in environment:
                        # @Value placeholders retain camel-case spelling and
                        # are not always resolved by relaxed OS environment
                        # aliases. JSON preserves the exact dotted key.
                        environment["SPRING_APPLICATION_JSON"] = json.dumps(spring_value, ensure_ascii=False)
                        repaired = True
                    service["environment"] = environment
                if repaired:
                    compose_file.write_text(yaml.safe_dump(document, allow_unicode=True, sort_keys=False), encoding="utf-8")
                    relative = compose_file.relative_to(root).as_posix()
                    if relative not in changed:
                        changed.append(relative)
    return changed


def prepare_build(path: str, requested: str) -> tuple[str, str, int | None]:
    """Generate a source-aware build for auto mode; explicit choices stay exact."""
    root = Path(path)
    optimize_staged_sources(path)
    if requested in ("compose", "dockerfile"):
        build_type, build_file = detect_build(path, requested)
        return build_type, build_file or "Dockerfile", detect_container_port(path)

    # Repository Compose/Dockerfile assets are evidence only.  Auto mode must
    # materialize a platform-owned build from the analyzed source instead of
    # executing a third-party file unchanged.
    compose_path = _find_compose(root)
    compose = compose_path.relative_to(root).as_posix() if compose_path else None

    # A common full-stack repository layout: one Vite/React directory plus a
    # Spring Boot directory. Generate an isolated three-service topology so
    # the frontend path in a browser URL cannot silently hide the backend.
    frontend_roots, backend_roots = _fullstack_roots(root)
    frontend = frontend_roots[0] if frontend_roots else None
    backend = backend_roots[0] if backend_roots else None
    if frontend and backend:
        frontend_rel = frontend.relative_to(root).as_posix()
        backend_rel = backend.relative_to(root).as_posix()
        init_sql = next((p for p in (root / "init.sql", root / "schema.sql") if p.exists()), None)
        managed_init_sql = None
        if init_sql:
            sql_text = init_sql.read_text(errors="ignore")
            # MySQL does not accept MariaDB's ADD COLUMN IF NOT EXISTS form.
            # Generate a deployment-only compatible copy; never edit the repo.
            sql_text = re.sub(r"(?i)\bADD\s+COLUMN\s+IF\s+NOT\s+EXISTS\b", "ADD COLUMN", sql_text)
            managed_init_sql = root / ".yunzhou.init.sql"
            managed_init_sql.write_text(sql_text)
        (root / ".yunzhou.frontend.Dockerfile").write_text(
            f"FROM node:22-alpine AS build\nWORKDIR /src\nCOPY {frontend_rel}/package*.json ./\nRUN npm config set registry https://registry.npmmirror.com && npm ci\n"
            f"COPY {frontend_rel}/ ./\nRUN npm run build\nFROM nginx:1.27-alpine\n"
            "COPY .yunzhou.nginx.conf /etc/nginx/conf.d/default.conf\nCOPY --from=build /src/dist /usr/share/nginx/html/app\nEXPOSE 80\n"
        )
        (root / ".yunzhou.maven-settings.xml").write_text('<settings xmlns="http://maven.apache.org/SETTINGS/1.0.0"><mirrors><mirror><id>aliyun</id><mirrorOf>*</mirrorOf><name>Aliyun Maven</name><url>https://maven.aliyun.com/repository/public</url></mirror></mirrors></settings>')
        (root / ".yunzhou.backend.Dockerfile").write_text(
            f"FROM maven:3.9-eclipse-temurin-{detect_java_version(str(backend))} AS build\nWORKDIR /src\nCOPY .yunzhou.maven-settings.xml /tmp/settings.xml\nCOPY {backend_rel}/ ./\n"
            "RUN mvn -s /tmp/settings.xml -DskipTests package\nRUN jar=\"$(find target -name '*.jar' ! -name 'original-*' -type f | head -n1)\" && test -n \"$jar\" && cp \"$jar\" /tmp/app.jar\n"
            f"FROM eclipse-temurin:{detect_java_version(str(backend))}-jre\nWORKDIR /app\nCOPY --from=build /tmp/app.jar app.jar\nEXPOSE 8080\nCMD [\"java\",\"-jar\",\"app.jar\"]\n"
        )
        (root / ".yunzhou.nginx.conf").write_text(
            "server { listen 80; server_name _; client_max_body_size 50m; "
            "location = / { return 302 /app/; } "
            "location /app/api/ { proxy_pass http://backend:8080/api/; proxy_http_version 1.1; "
            "proxy_set_header Host $host; proxy_set_header X-Real-IP $remote_addr; proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for; } "
            "location /app/ { root /usr/share/nginx/html; try_files $uri $uri/ /app/index.html; } }\n"
        )
        init_mount = f"      - ./{managed_init_sql.name}:/docker-entrypoint-initdb.d/001-init.sql:ro\n" if managed_init_sql else ""
        compose_text = f'''services:
  db:
    image: mysql:8.4
    restart: unless-stopped
    environment:
      MYSQL_DATABASE: crm
      MYSQL_USER: crm
      MYSQL_PASSWORD: ${{CRM_DB_PASSWORD}}
      MYSQL_ROOT_PASSWORD: ${{CRM_DB_ROOT_PASSWORD}}
    volumes:
      - crm-data:/var/lib/mysql
{init_mount}    healthcheck:
      test: ["CMD", "mysqladmin", "ping", "-h", "127.0.0.1", "-uroot", "-p${{CRM_DB_ROOT_PASSWORD}}"]
      interval: 10s
      timeout: 5s
      retries: 30
  backend:
    build:
      context: .
      dockerfile: .yunzhou.backend.Dockerfile
    restart: unless-stopped
    environment:
      DB_URL: jdbc:mysql://db:3306/crm?useUnicode=true&characterEncoding=utf8&serverTimezone=Asia/Shanghai&useSSL=false&allowPublicKeyRetrieval=true
      DB_USERNAME: crm
      DB_PASSWORD: ${{CRM_DB_PASSWORD}}
      CRM_JWT_SECRET: ${{CRM_JWT_SECRET}}
    depends_on:
      db:
        condition: service_healthy
  frontend:
    build:
      context: .
      dockerfile: .yunzhou.frontend.Dockerfile
    restart: unless-stopped
    ports:
      - "${{YUNZHOU_HOST_PORT}}:80"
    depends_on:
      - backend
volumes:
  crm-data:
'''
        generated_compose = root / ".yunzhou.compose.yml"
        generated_compose.write_text(compose_text)
        return "compose", generated_compose.name, None

    # Some complete repositories keep the production Dockerfile in
    # containers/ or deploy/ while its build context must remain the repository
    # root. Recognize that layout before falling back to root-only manifests.
    nested_dockerfiles = [
        item for item in root.rglob("Dockerfile")
        if item.is_file() and not any(part in {".git", "node_modules", "target", "dist", "build"} for part in item.relative_to(root).parts)
    ]
    preferred_dockerfile = next((item for item in nested_dockerfiles if item.parent.name in {"containers", "deploy", "docker"}), None)
    if not preferred_dockerfile and len(nested_dockerfiles) == 1:
        preferred_dockerfile = nested_dockerfiles[0]
    # The deterministic fallback cannot prove arbitrary instructions safe.
    # Keep these files available as evidence but do not select them as the
    # executable build artifact; known source layouts below get a newly
    # generated platform Dockerfile, unknown layouts request a fresh AI plan.
    preferred_dockerfile = None
    if preferred_dockerfile:
        dockerfile_rel = preferred_dockerfile.relative_to(root).as_posix()
        port = detect_container_port(path, dockerfile_rel)
        combined = ""
        for name in (".env.example", "PROJECT_CONTEXT.yml", "README.md"):
            candidate = root / name
            if candidate.exists():
                combined += "\n" + candidate.read_text(errors="ignore")
        uses_mysql = bool(re.search(r"(?i)(DB_HOST|target_database:\s*MySQL|COMMERCE_OPS_PERSISTENCE)", combined))
        if uses_mysql:
            generated_compose = root / ".yunzhou.compose.yml"
            generated_compose.write_text(f'''services:
  db:
    image: mysql:8.4
    restart: unless-stopped
    environment:
      MYSQL_DATABASE: commerce_ops
      MYSQL_USER: commerce_ops_app
      MYSQL_PASSWORD: ${{CRM_DB_PASSWORD}}
      MYSQL_ROOT_PASSWORD: ${{CRM_DB_ROOT_PASSWORD}}
    volumes:
      - commerce-ops-mysql:/var/lib/mysql
    healthcheck:
      test: ["CMD", "mysqladmin", "ping", "-h", "127.0.0.1", "-uroot", "-p${{CRM_DB_ROOT_PASSWORD}}"]
      interval: 10s
      timeout: 5s
      retries: 30
  app:
    build:
      context: .
      dockerfile: {dockerfile_rel}
    restart: unless-stopped
    environment:
      ADMIN_API_HOST: 0.0.0.0
      ADMIN_API_PORT: {port or 4300}
      COMMERCE_OPS_PERSISTENCE: mysql
      DB_HOST: db
      DB_PORT: 3306
      DB_NAME: commerce_ops
      DB_USERNAME: commerce_ops_app
      DB_PASSWORD: ${{CRM_DB_PASSWORD}}
    ports:
      - "${{YUNZHOU_HOST_PORT}}:{port or 4300}"
    volumes:
      - commerce-ops-images:/data/images
      - commerce-ops-publisher:/data/publisher
    depends_on:
      db:
        condition: service_healthy
volumes:
  commerce-ops-mysql:
  commerce-ops-images:
  commerce-ops-publisher:
''')
            return "compose", generated_compose.name, None
        return "dockerfile", dockerfile_rel, port

    generated = root / ".yunzhou.Dockerfile"
    reference_port = detect_container_port(path)
    package = root / "package.json"
    if package.exists():
        try:
            meta = json.loads(package.read_text(errors="ignore"))
        except Exception:
            meta = {}
        deps = {**meta.get("dependencies", {}), **meta.get("devDependencies", {})}
        scripts = meta.get("scripts", {})
        if "vite" in deps or "build" in scripts:
            generated.write_text(
                "FROM node:22-alpine AS build\nWORKDIR /app\nCOPY package*.json ./\n"
                "RUN npm config set registry https://registry.npmmirror.com && npm install\nCOPY . .\nRUN npm run build\n"
                "FROM nginx:1.27-alpine\nCOPY --from=build /app/dist /usr/share/nginx/html\nEXPOSE 80\n"
            )
            return "dockerfile", generated.name, reference_port or 80
        generated.write_text(
            "FROM node:22-alpine\nWORKDIR /app\nCOPY package*.json ./\nRUN npm config set registry https://registry.npmmirror.com && npm install --omit=dev\n"
            "COPY . .\nENV NODE_ENV=production\nEXPOSE 3000\nCMD [\"npm\",\"start\"]\n"
        )
        return "dockerfile", generated.name, reference_port or 3000

    if (root / "pom.xml").exists():
        java_version = detect_java_version(path)
        (root / ".yunzhou.maven-settings.xml").write_text('<settings xmlns="http://maven.apache.org/SETTINGS/1.0.0"><mirrors><mirror><id>aliyun</id><mirrorOf>*</mirrorOf><name>Aliyun Maven</name><url>https://maven.aliyun.com/repository/public</url></mirror></mirrors></settings>')
        generated.write_text(
            f"FROM maven:3.9-eclipse-temurin-{java_version} AS build\nWORKDIR /app\nCOPY .yunzhou.maven-settings.xml /tmp/settings.xml\nCOPY . .\nRUN mvn -s /tmp/settings.xml -DskipTests package\n"
            "RUN jar=\"$(find /app -path '*/target/*.jar' ! -name '*-sources.jar' ! -name '*-javadoc.jar' ! -name 'original-*.jar' -type f -printf '%s %p\\n' | sort -nr | head -n1 | cut -d' ' -f2-)\" && test -n \"$jar\" && cp \"$jar\" /tmp/app.jar\n"
            f"FROM eclipse-temurin:{java_version}-jre\nWORKDIR /app\nCOPY --from=build /tmp/app.jar app.jar\n"
            "EXPOSE 8080\nCMD [\"java\",\"-jar\",\"app.jar\"]\n"
        )
        return "dockerfile", generated.name, reference_port or 8080

    if (root / "requirements.txt").exists() or (root / "pyproject.toml").exists():
        candidates = list(root.rglob("*.py"))
        app_file = next((p for p in candidates if "FastAPI(" in p.read_text(errors="ignore")), None)
        module = app_file.relative_to(root).with_suffix("").as_posix().replace("/", ".") if app_file else "app"
        install = "pip install -i https://pypi.tuna.tsinghua.edu.cn/simple -r requirements.txt" if (root / "requirements.txt").exists() else "pip install -i https://pypi.tuna.tsinghua.edu.cn/simple ."
        cmd = f'uvicorn {module}:app --host 0.0.0.0 --port 8000' if app_file else "python app.py"
        generated.write_text(
            f"FROM python:3.12-slim\nWORKDIR /app\nCOPY . .\nRUN {install}\nEXPOSE 8000\nCMD [\"sh\",\"-c\",\"{cmd}\"]\n"
        )
        return "dockerfile", generated.name, reference_port or 8000

    static_index = next(
        (
            item for item in root.rglob("index.html")
            if item.is_file()
            and not any(part in {".git", "node_modules", "target", "dist", "build"} for part in item.relative_to(root).parts)
        ),
        None,
    )
    if static_index:
        static_dir = static_index.parent.relative_to(root).as_posix()
        copy_source = "." if static_dir == "." else static_dir + "/"
        generated.write_text(
            f"FROM nginx:1.27-alpine\nCOPY {copy_source} /usr/share/nginx/html\nEXPOSE 80\n"
        )
        return "dockerfile", generated.name, 80
    if (root / "Dockerfile").exists():
        raise RuntimeError(
            "平台已将仓库 Dockerfile 作为参考完成扫描，但无法仅凭当前源码安全重新生成等价的经典构建文件；"
            "请重新执行 AI 源码分析，不会直接复用仓库 Dockerfile"
        )
    raise RuntimeError("无法从源码安全生成平台构建文件，请重新执行 AI 源码分析")


def source_declares_environment_optional(path: str, variable: str) -> bool:
    """Confirm from executable source that an environment variable has a fallback or is optional."""
    root = Path(path)
    escaped = re.escape(variable)
    # Example environment files are part of the project's configuration
    # contract. A commented or empty assignment explicitly documents that the
    # application may run without the integration; AI must not promote it to
    # a required Compose secret.
    example_assignment = re.compile(
        rf"(?m)^\s*#?\s*(?:export\s+)?{escaped}\s*=\s*(?:['\"]\s*['\"])?\s*(?:#.*)?$"
    )
    for pattern in (".env.example", ".env.sample", ".env.template", "*.env.example", "*.env.sample"):
        for file in root.rglob(pattern):
            if not file.is_file() or any(part in {".git", "node_modules", "dist", "build"} for part in file.parts):
                continue
            try:
                if example_assignment.search(file.read_text(encoding="utf-8", errors="ignore")):
                    return True
            except OSError:
                continue
    access_with_fallback = re.compile(
        rf"(?:process\.env|values|env|config)\s*(?:\.\s*{escaped}\b|\[\s*['\"]{escaped}['\"]\s*\])[^\n]{{0,120}}?(?:\|\||\?\?)"
    )
    schema_optional = re.compile(rf"\b{escaped}\b\s*:[^\n]{{0,160}}?\.optional\s*\(")
    for file in root.rglob("*"):
        if (not file.is_file() or file.name.startswith(".yunzhou") or
                file.suffix.lower() not in {".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".py", ".java", ".go", ".rs"} or
                any(part in {".git", "node_modules", "dist", "build", "target", "vendor"} for part in file.parts)):
            continue
        try:
            if file.stat().st_size > 2_000_000:
                continue
            source = file.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if access_with_fallback.search(source) or schema_optional.search(source):
            return True
    return False


def strip_generated_code_fence(value: str) -> str:
    text = str(value or "").strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[-1] if "\n" in text else ""
        text = text.rsplit("```", 1)[0].strip()
    return text


def valid_generated_dockerfile(value: str) -> bool:
    """Reject YAML/Compose accidentally returned in the Dockerfile field."""
    instructions = []
    continued = False
    for raw_line in value.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if continued:
            continued = line.endswith("\\")
            continue
        token = line.split(None, 1)[0].upper()
        instructions.append(token)
        continued = line.endswith("\\")
    allowed = {
        "ADD", "ARG", "CMD", "COPY", "ENTRYPOINT", "ENV", "EXPOSE", "FROM",
        "HEALTHCHECK", "LABEL", "MAINTAINER", "ONBUILD", "RUN", "SHELL",
        "STOPSIGNAL", "USER", "VOLUME", "WORKDIR",
    }
    return bool(instructions) and instructions[0] in {"ARG", "FROM"} and "FROM" in instructions and all(item in allowed for item in instructions)


def normalize_inline_dockerfile(value: str) -> str:
    """Keep quoted shell text on one Dockerfile instruction line."""
    lines = value.splitlines()
    normalized = []
    index = 0
    while index < len(lines):
        line = lines[index]
        if line.lstrip().upper().startswith("RUN "):
            # AI occasionally places a literal newline inside a single-quoted
            # printf argument. Docker then treats the following quote as a new
            # instruction. Preserve the intended newline as the two characters
            # backslash+n and keep the RUN instruction valid.
            while line.count("'") % 2 == 1 and index + 1 < len(lines):
                index += 1
                line += r"\n" + lines[index].lstrip()
        normalized.append(line)
        index += 1
    result = "\n".join(normalized).rstrip() + "\n"
    # The platform never permits BuildKit-only Dockerfile features.  Convert
    # AI/user inline files to classic syntax before validation/build.  Cache
    # mounts are replaced by normal RUN commands; dependency reuse is handled
    # by the platform-wide host caches and classic image layers.
    result = re.sub(r"(?im)^\s*#\s*syntax=docker/dockerfile[^\n]*\n?", "", result)
    result = re.sub(
        r"(?m)^(\s*RUN)\s+--mount=type=cache(?:,[^\s]+)*\s+",
        r"\1 ",
        result,
    )
    # Corepack does not reliably resolve a bare package-manager major release
    # (for example `pnpm@8`) on older Node images. Pin known compatible patch
    # releases so generated builds are reproducible and do not fail after all
    # base layers and Maven dependencies have already been downloaded.
    pnpm_versions = {"7": "7.33.7", "8": "8.15.9", "9": "9.15.9", "10": "10.20.0"}
    result = re.sub(
        r"(?i)(corepack\s+prepare\s+pnpm@)(7|8|9|10)(?=\s|--)",
        lambda match: match.group(1) + pnpm_versions[match.group(2)],
        result,
    )
    return result


def optimize_node_dependency_layer(root: Path, dockerfile: str) -> str:
    """Keep package installation cacheable when only application source changes.

    AI plans commonly emit ``COPY frontend/ ./`` followed by one RUN containing
    both install and build.  That invalidates the dependency layer for every
    source edit.  For a regular (non-workspace) package directory we can safely
    split it into manifest -> install -> source -> build layers.  Docker's
    classic builder can then reuse the install layer without a project cache
    directory or BuildKit cache mount.
    """
    copy_run = re.compile(
        r"(?im)^(?P<indent>\s*)COPY\s+(?P<src>[^\s]+?)/?\s+\./?\s*\n"
        r"(?P=indent)RUN\s+(?P<command>(?:[^\n]*\\\n[ \t]*)*[^\n]*)$"
    )

    def replace(match: re.Match) -> str:
        source = match.group("src").strip().strip('"').rstrip("/")
        command = re.sub(r"\\\n[ \t]*", " ", match.group("command")).strip()
        if not re.search(r"\b(?:npm|pnpm|yarn)\s+(?:install|i|ci)\b", command, re.I):
            return match.group(0)
        build_match = re.search(r"\s*&&\s*((?:npm|pnpm|yarn)\s+(?:run\s+)?build\b.*)$", command, re.I)
        if not build_match:
            return match.group(0)
        package_dir = (root / source).resolve()
        if root not in package_dir.parents or not (package_dir / "package.json").is_file():
            return match.group(0)
        # Workspace installs may depend on sibling manifests; retain the AI
        # layout in that case instead of producing an incomplete cache layer.
        try:
            package_data = json.loads((package_dir / "package.json").read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            package_data = {}
        if package_data.get("workspaces"):
            return match.group(0)
        manifests = ["package.json", "pnpm-lock.yaml", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock"]
        existing = [name for name in manifests if (package_dir / name).is_file()]
        if not existing:
            return match.group(0)
        install_command = command[:build_match.start()].rstrip()
        build_command = build_match.group(1).strip()
        indent = match.group("indent")
        manifest_sources = " ".join(f"{source}/{name}" for name in existing)
        return (
            f"{indent}COPY {manifest_sources} ./\n"
            f"{indent}RUN {install_command}\n"
            f"{indent}COPY {source}/ ./\n"
            f"{indent}RUN {build_command}"
        )

    return copy_run.sub(replace, dockerfile)


def optimize_maven_dependency_layer(root: Path, dockerfile: str) -> str:
    """Use the mainland mirror without adding a separate warm-up build."""
    if not re.search(r"(?im)^\s*FROM\s+\S*maven[:@]", dockerfile) or not re.search(r"\bmvn\b", dockerfile):
        return dockerfile
    settings_name = ".yunzhou.maven-settings.xml"
    (root / settings_name).write_text(
        '<settings xmlns="http://maven.apache.org/SETTINGS/1.0.0">'
        '<mirrors><mirror><id>yunzhou-mirror</id><mirrorOf>*</mirrorOf>'
        '<name>Yunzhou Maven Mirror</name><url>https://maven.aliyun.com/repository/public</url>'
        '</mirror></mirrors></settings>',
        encoding="utf-8",
    )
    stages = re.split(r"(?im)(?=^\s*FROM\s+)", dockerfile)
    for index, stage in enumerate(stages):
        if not re.search(r"(?im)^\s*FROM\s+\S*maven[:@]", stage) or not re.search(r"(?im)^\s*RUN\s+.*\bmvn\b", stage):
            continue
        if settings_name not in stage:
            from_line = re.search(r"(?im)^\s*FROM[^\n]*\n", stage)
            if from_line:
                stage = stage[:from_line.end()] + f"COPY {settings_name} /tmp/yunzhou-maven-settings.xml\n" + stage[from_line.end():]
        stage = re.sub(
            r"(?im)^(\s*RUN\s+)mvn\b(?!\s+-s\b)",
            r"\1mvn -s /tmp/yunzhou-maven-settings.xml",
            stage,
        )
        # Analysis must never add or preserve an extra dependency warm-up.
        # The single authoritative package command fills the mounted cache.
        stage = re.sub(
            r"(?im)^\s*RUN\s+[^\n]*\bdependency:go-offline\b[^\n]*\n?",
            "",
            stage,
        )
        stages[index] = stage
    return "".join(stages)


def detect_java_log_directories(root: Path) -> list[str]:
    """Find absolute writable log directories declared by Java configs."""
    directories: set[str] = set()
    allowed_suffixes = {".xml", ".yml", ".yaml", ".properties"}
    for path in root.rglob("*"):
        if (
            not path.is_file()
            or path.suffix.lower() not in allowed_suffixes
            or any(part in {".git", "target", "build", "node_modules"} for part in path.parts)
        ):
            continue
        try:
            if path.stat().st_size > 2_000_000:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        # Logback commonly declares paths as
        # <property name="log.path" value="/var/log/app"/>.  Parse the
        # name/value pair explicitly so the quote after name is not mistaken
        # for the value delimiter.
        for match in re.finditer(
            r"(?i)name\s*=\s*[\"'](?:log\.path|logging\.file\.path)[\"'][^>]*?"
            r"value\s*=\s*[\"'](/[^\"'<>]+)",
            text,
        ):
            value = match.group(1).rstrip("/.,;\"")
            if value.startswith("/") and "${" not in value:
                directories.add(value)
        for match in re.finditer(
            r"(?im)^\s*(?:log\.path|logging\.file\.path)\s*[:=]\s*[\"']?(/[^\s\"'<>]+)",
            text,
        ):
            value = match.group(1).rstrip("/.,;\"")
            if value.startswith("/") and "${" not in value:
                directories.add(value)
        for match in re.finditer(r"(/(?:[A-Za-z0-9._-]+/)+)(?:[^/\s\"'<>]+\.log)\b", text):
            directories.add(match.group(1).rstrip("/"))
    return sorted(value for value in directories if value not in {"/", "/tmp"})[:12]


def ensure_java_runtime_directories(runtime: str, context: Path) -> str:
    if not re.search(r"(?i)(?:java\s+-jar|ENTRYPOINT\s*\[\s*[\"']java)", runtime):
        return runtime
    directories = detect_java_log_directories(context)
    if not directories:
        return runtime
    command = "RUN mkdir -p " + " ".join(shlex.quote(value) for value in directories)
    command += " && chmod 0777 " + " ".join(shlex.quote(value) for value in directories) + "\n"
    from_line = re.search(r"(?im)^\s*FROM[^\n]*\n", runtime)
    if not from_line:
        return runtime
    return runtime[:from_line.end()] + command + runtime[from_line.end():]


def runtime_stage_from_prebuilt_artifact(
    dockerfile_text: str, context: Path, artifact_paths: list[str], output_name: str,
    target: str | None = None,
) -> tuple[str, list[str]] | None:
    """Convert a conventional multi-stage Dockerfile to a runtime-only one.

    The compilation has already happened in a disposable toolchain container
    with host-mounted dependency caches.  Only COPY --from lines whose source
    can be mapped to a real artifact in the checkout are rewritten.  Returning
    None leaves unusual Dockerfiles untouched instead of guessing.
    """
    stages = list(re.finditer(r"(?im)^\s*FROM\s+", dockerfile_text))
    if len(stages) < 2:
        return None
    if target:
        target_match = re.search(
            rf"(?im)^\s*FROM\s+\S+\s+AS\s+{re.escape(target)}\s*$",
            dockerfile_text,
        )
        if not target_match:
            return None
        next_stage = next((item.start() for item in stages if item.start() > target_match.start()), len(dockerfile_text))
        runtime = dockerfile_text[target_match.start():next_stage]
    else:
        runtime = dockerfile_text[stages[-1].start():]
    copied: list[str] = []
    pattern = re.compile(
        r"(?im)^(?P<indent>\s*)COPY\s+(?P<flags>(?:--\S+\s+)*)--from=\S+\s+"
        r"(?P<src>\S+)\s+(?P<dest>\S+)\s*$"
    )

    def replace(match: re.Match) -> str:
        source = match.group("src").strip('"\'').rstrip("/")
        candidates: list[Path] = []
        source_name = Path(source).name
        for value in artifact_paths:
            base = context / value
            if base.exists() and (not source_name or base.name == source_name):
                candidates.append(base)
        if not candidates and source_name:
            candidates.extend(path for path in context.rglob(source_name) if path.exists())
        if not candidates:
            return match.group(0)
        artifact = candidates[0]
        relative = artifact.relative_to(context).as_posix()
        copied.append(relative)
        suffix = "/" if artifact.is_dir() else ""
        return f'{match.group("indent")}COPY {relative}{suffix} {match.group("dest")}'

    runtime = pattern.sub(replace, runtime)
    if not copied or "--from=" in runtime:
        return None
    # AI-generated nginx stages sometimes create the configuration with one
    # ``RUN echo`` instruction per line.  The classic builder then has to
    # create and commit dozens of tiny layers even though the commands are a
    # single logical operation.  Merge only consecutive generated echo
    # instructions; arbitrary RUN commands keep their original boundaries.
    runtime_lines = runtime.splitlines()
    compact_lines: list[str] = []
    echo_commands: list[str] = []

    def flush_echo_commands() -> None:
        if not echo_commands:
            return
        compact_lines.append("RUN " + " && \\\n    ".join(echo_commands))
        echo_commands.clear()

    for line in runtime_lines:
        echo_match = re.match(r"^\s*RUN\s+(echo\s+.+)$", line)
        if echo_match:
            echo_commands.append(echo_match.group(1))
            continue
        flush_echo_commands()
        compact_lines.append(line)
    flush_echo_commands()
    runtime = "\n".join(compact_lines)
    runtime = ensure_java_runtime_directories(runtime, context)
    return runtime.rstrip() + "\n", copied


def reconcile_compose_build_targets(root: Path, compose: dict) -> list[str]:
    """Point Compose targets at the Dockerfile that actually defines them.

    An AI plan can generate a valid multi-stage ``.yunzhou.ai.Dockerfile`` but
    accidentally leave a service pointing at a repository Dockerfile.  Docker
    then reports ``target stage ... could not be found`` even though the stage
    is present in the generated plan.  Resolve only an unambiguous match; never
    invent a stage or silently choose between multiple candidates.
    """
    services = compose.get("services") if isinstance(compose, dict) else None
    if not isinstance(services, dict):
        return []

    def stage_names(path: Path) -> set[str]:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return set()
        return {
            match.group(1)
            for match in re.finditer(r"(?im)^\s*FROM\s+\S+(?:\s+AS\s+([A-Za-z0-9_.-]+))?\s*$", text)
            if match.group(1)
        }

    changes: list[str] = []
    for service_name, service in services.items():
        build = service.get("build") if isinstance(service, dict) else None
        if not isinstance(build, dict) or not build.get("target") or build.get("dockerfile_inline"):
            continue
        target = str(build["target"]).strip()
        context_value = str(build.get("context") or ".")
        context = (root / context_value).resolve()
        if context != root and root not in context.parents:
            continue
        configured = (context / str(build.get("dockerfile") or "Dockerfile")).resolve()
        if target in stage_names(configured):
            continue

        candidates: list[Path] = []
        generated = root / ".yunzhou.ai.Dockerfile"
        search = [generated]
        search.extend(path for path in context.glob("*Dockerfile*") if path.is_file())
        for candidate in search:
            resolved = candidate.resolve()
            if resolved == configured or resolved in candidates:
                continue
            if target in stage_names(resolved):
                candidates.append(resolved)
        if len(candidates) != 1:
            continue
        replacement = candidates[0].relative_to(context).as_posix()
        old = str(build.get("dockerfile") or "Dockerfile")
        build["dockerfile"] = replacement
        changes.append(f"{service_name}: {old} -> {replacement}（target={target}）")
    return changes


def materialize_ai_deployment_plan(path: str, plan: dict) -> tuple[str, str, int | None]:
    """Validate and materialize an AI plan without allowing host-level escape hatches."""
    root = Path(path).resolve()
    detected_api = detect_frontend_api_routes(path)
    managed_api_prefix = str(detected_api.get("primary_path") or "")
    traffic_plan = plan.get("traffic_plan") if isinstance(plan.get("traffic_plan"), dict) else {}
    # The AI plan is advisory; effective production source is authoritative.
    # Reconcile the route again at materialization time so a stale analysis or
    # contradictory model answer cannot generate a broken gateway config.
    detected_routes = {
        str(row.get("path") or ""): bool(row.get("strip_prefix", False))
        for row in (detected_api.get("routes") or [])
        if isinstance(row, dict) and str(row.get("path") or "").startswith("/")
    }
    if traffic_plan and detected_routes:
        reconciled_routes = []
        for route in traffic_plan.get("traffic_routes") or traffic_plan.get("routes") or []:
            if not isinstance(route, dict):
                continue
            normalized = dict(route)
            route_path = str(normalized.get("path") or "")
            if route_path in detected_routes:
                normalized["strip_prefix"] = detected_routes[route_path]
            reconciled_routes.append(normalized)
        if reconciled_routes:
            traffic_plan["traffic_routes"] = reconciled_routes
            plan["traffic_plan"] = traffic_plan
    if not managed_api_prefix:
        for route in traffic_plan.get("traffic_routes") or []:
            candidate = _public_path_from_value(str((route or {}).get("path") or "")) if isinstance(route, dict) else None
            if candidate:
                managed_api_prefix = candidate
                break
    kind = str(plan.get("deployment_kind") or "").strip().lower()
    if not str(plan.get("summary") or "").strip() or kind not in {"compose", "dockerfile"}:
        raise RuntimeError("AI 返回的部署方案缺少架构结论或部署类型")
    dockerfile_text = strip_generated_code_fence(plan.get("dockerfile") or "")
    compose_text = strip_generated_code_fence(plan.get("compose_yaml") or "")
    # Some models put a complete Compose document in the `dockerfile` JSON
    # property. Recover it when possible instead of sending YAML to Docker.
    if dockerfile_text and not valid_generated_dockerfile(dockerfile_text):
        try:
            misplaced_compose = yaml.safe_load(dockerfile_text)
        except yaml.YAMLError:
            misplaced_compose = None
        if isinstance(misplaced_compose, dict) and isinstance(misplaced_compose.get("services"), dict):
            if not compose_text:
                compose_text = dockerfile_text
            dockerfile_text = ""
            kind = "compose"
        elif kind == "dockerfile":
            # Do not let malformed AI output reach `docker build`. The local
            # repository detector is deterministic and provides a safe fallback.
            return prepare_build(path, "auto")
    managed_minio_image = str(plan.get("managed_minio_image") or MANAGED_MINIO_FALLBACK)
    if dockerfile_text:
        if re.search(r"(?im)^\s*(?:ADD|COPY)\s+https?://", dockerfile_text):
            raise RuntimeError("AI Dockerfile 包含未经校验的远程文件下载")
        dockerfile_text = re.sub(
            r"(?im)^(\s*FROM\s+(?:--platform=\S+\s+)?)(\S+)",
            lambda match: match.group(1) + canonical_docker_image(match.group(2), managed_minio_image),
            dockerfile_text,
        )
        dockerfile_text = normalize_inline_dockerfile(dockerfile_text)
        unsupported_classic = []
        if re.search(r"(?im)^\s*RUN\s+--mount=", dockerfile_text):
            unsupported_classic.append("RUN --mount")
        if re.search(r"(?im)^\s*(?:COPY|ADD)\s+--link(?:=\S+)?\s+", dockerfile_text):
            unsupported_classic.append("COPY/ADD --link")
        if re.search(r"(?im)^\s*(?:RUN|COPY|ADD)\s+<<[-~]?\w+", dockerfile_text):
            unsupported_classic.append("Dockerfile heredoc")
        if unsupported_classic:
            raise RuntimeError(
                "AI 方案仍依赖 BuildKit 专属语法（" + "、".join(unsupported_classic)
                + "），平台未找到可验证的经典构建等价方案，已停止而不会自动切换 buildx"
            )
        # AI plans sometimes copy only the obvious frontend directories before
        # running a build. Monorepos may legally import shared types or helpers
        # from sibling directories (for example src -> server/src). Ensure the
        # complete repository is present in every Node build stage instead of
        # letting an incomplete generated COPY list look like a source error.
        stages = re.split(r"(?im)(?=^\s*FROM\s+)", dockerfile_text)
        for index, stage in enumerate(stages):
            build_run = re.search(r"(?im)^\s*RUN\s+.*(?:npm|pnpm|yarn)\s+(?:run\s+)?build\b.*$", stage)
            copies_all = re.search(r"(?im)^\s*COPY\s+(?:--\S+\s+)*\.\s+\.\s*$", stage)
            if build_run and not copies_all:
                stages[index] = stage[:build_run.start()] + "COPY . .\n" + stage[build_run.start():]
        dockerfile_text = "".join(stages)
        dockerfile_text = optimize_node_dependency_layer(root, dockerfile_text)
        dockerfile_text = optimize_maven_dependency_layer(root, dockerfile_text)
        (root / ".yunzhou.ai.Dockerfile").write_text(dockerfile_text + "\n", encoding="utf-8")
    try:
        container_port = int(plan["container_port"]) if plan.get("container_port") not in (None, "") else None
    except (TypeError, ValueError):
        raise RuntimeError("AI 返回的容器端口无效")
    if container_port is not None and not 1 <= container_port <= 65535:
        raise RuntimeError("AI 返回的容器端口超出有效范围")
    if kind == "dockerfile":
        requested_file = str(plan.get("primary_file") or ".yunzhou.ai.Dockerfile").replace("\\", "/").lstrip("/")
        dockerfile = (root / requested_file).resolve()
        if root not in dockerfile.parents:
            raise RuntimeError("AI 返回的 Dockerfile 路径不安全")
        if not dockerfile.exists():
            # A model can correctly select the deployment kind but omit the
            # generated file body. Treat that as incomplete model output, not
            # as a source-code failure: the deterministic detector can build a
            # safe Dockerfile from package manifests and known entry points.
            return prepare_build(path, "auto")
        relative = dockerfile.relative_to(root).as_posix()
        # The materialized Dockerfile is the final executable artifact. If an
        # earlier AI analysis carried a stale port, prefer the explicit EXPOSE
        # from the generated file so runtime mapping cannot point at port 80
        # while the application actually listens on 4300.
        return "dockerfile", relative, detect_container_port(path, relative) or container_port
    if not compose_text:
        return prepare_build(path, "auto")
    # AI may occasionally promote a source-level optional variable to `${VAR:?}`.
    # Source code is authoritative: keep it optional so the application's own
    # fallback executes instead of repeatedly asking the user for fake values.
    required_pattern = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*):\?[^}]*\}")
    for variable in set(required_pattern.findall(compose_text)):
        if source_declares_environment_optional(path, variable):
            compose_text = re.sub(
                rf"\$\{{{re.escape(variable)}:\?[^}}]*\}}",
                "${" + variable + ":-}",
                compose_text,
            )
    # Models occasionally double the inner quotes of a password argument
    # inside a YAML flow-style healthcheck. That makes the whole Compose file
    # unparsable. Quotes are unnecessary for this single environment value;
    # keep Compose's escaped dollar and normalize before parsing.
    compose_text = re.sub(
        r'-p""\$\$([A-Za-z_][A-Za-z0-9_]*)""',
        r'-p$$\1',
        compose_text,
    )
    try:
        compose = yaml.safe_load(compose_text)
    except yaml.YAMLError as exc:
        raise RuntimeError(f"AI 生成的 Compose 语法无效：{exc}") from exc
    services = compose.get("services") if isinstance(compose, dict) else None
    if not isinstance(services, dict) or not services:
        raise RuntimeError("AI 生成的 Compose 没有可运行服务")
    target_repairs = reconcile_compose_build_targets(root, compose)
    if target_repairs:
        plan["safe_repairs"] = list(plan.get("safe_repairs") or []) + target_repairs
    published = False
    for name, service in services.items():
        if not isinstance(service, dict):
            raise RuntimeError(f"AI Compose 服务 {name} 配置无效")
        if service.get("image"):
            service["image"] = canonical_docker_image(str(service["image"]), managed_minio_image)
            # PostgreSQL 18+ changed the official image's declared data
            # volume from /var/lib/postgresql/data to /var/lib/postgresql so
            # pg_upgrade can work across major versions.  AI plans trained on
            # older examples often combine a current image with the legacy
            # mount, which makes the container exit before application start.
            postgres_match = re.match(r"(?i)^postgres:(?P<tag>[^@]+)(?:@.*)?$", str(service["image"]))
            postgres_tag = postgres_match.group("tag").lower() if postgres_match else ""
            postgres_major = re.match(r"^(\d+)", postgres_tag)
            # Unversioned rolling tags such as postgres:alpine and
            # postgres:bookworm currently follow the newest major just like
            # :latest. They therefore need the 18+ mount layout too. A pinned
            # 17-alpine (or older) retains the legacy /data target.
            postgres_uses_v18_layout = bool(postgres_match) and (
                not postgres_major or int(postgres_major.group(1)) >= 18
            )
            if postgres_uses_v18_layout:
                repaired_volumes = []
                for volume in service.get("volumes") or []:
                    if isinstance(volume, str):
                        parts = volume.split(":")
                        if len(parts) >= 2 and parts[1] == "/var/lib/postgresql/data":
                            parts[1] = "/var/lib/postgresql"
                            volume = ":".join(parts)
                    elif isinstance(volume, dict) and volume.get("target") == "/var/lib/postgresql/data":
                        volume = {**volume, "target": "/var/lib/postgresql"}
                    repaired_volumes.append(volume)
                service["volumes"] = repaired_volumes
                plan["safe_repairs"] = list(plan.get("safe_repairs") or []) + [
                    f"{name}: PostgreSQL 18+ 数据卷调整为 /var/lib/postgresql"
                ]
        if service.get("privileged") is True or service.get("network_mode") == "host":
            raise RuntimeError(f"AI Compose 服务 {name} 请求了不安全的宿主机权限")
        if service.get("devices") or service.get("pid") == "host" or service.get("ipc") == "host":
            raise RuntimeError(f"AI Compose 服务 {name} 请求了不安全的宿主机资源")
        for volume in service.get("volumes") or []:
            source = str(volume).split(":", 1)[0] if isinstance(volume, str) else str((volume or {}).get("source", ""))
            if source.startswith(("/", "\\")) or ".." in Path(source).parts or "docker.sock" in source:
                raise RuntimeError(f"AI Compose 服务 {name} 包含不安全的宿主机挂载")
        for mapping in service.get("ports") or []:
            if "${YUNZHOU_HOST_PORT}" in str(mapping):
                published = True
        # Vue CLI loads repository .env files while building and those files can
        # override a generated Dockerfile ARG/ENV.  A production-local file has
        # the highest dotenv priority.  Use the prefix detected from this
        # repository/traffic plan; never inject a platform-wide fixed path.
        build = service.get("build")
        if isinstance(build, dict) and isinstance(build.get("dockerfile_inline"), str):
            inline = normalize_inline_dockerfile(build["dockerfile_inline"])
            inline = optimize_node_dependency_layer(root, inline)
            inline = optimize_maven_dependency_layer(root, inline)
            # --openssl-legacy-provider is a Node 17/OpenSSL 3 workaround. Some
            # AI plans add it to Node 16 images where Node rejects the option
            # before the project's build script even starts.
            if re.search(r"(?im)^\s*FROM\s+node:(?:[0-9]|1[0-6])(?:[-:@]|$)", inline):
                inline = re.sub(r"(?i)\bNODE_OPTIONS=--openssl-legacy-provider\s+", "", inline)
            if managed_api_prefix and "VUE_APP_BASE_API" in inline and re.search(r"(?im)^\s*RUN\s+.*(?:npm|pnpm|yarn)\s+(?:run\s+)?build\b", inline):
                marker = "RUN printf " + shlex.quote("VUE_APP_BASE_API=" + managed_api_prefix + "\\n") + " > .env.production.local\n"
                if marker not in inline:
                    inline = re.sub(
                        r"(?im)^(\s*RUN\s+.*(?:npm|pnpm|yarn)\s+(?:run\s+)?build\b.*)$",
                        marker + r"\1",
                        inline,
                        count=1,
                    )
            inline = normalize_inline_dockerfile(inline)
            if not valid_generated_dockerfile(inline):
                raise RuntimeError(f"AI Compose 服务 {name} 生成的 Dockerfile 语法无效，平台已在构建前拦截")
            build["dockerfile_inline"] = inline
    if not published:
        # Do not fail a complete plan only because the model used a fixed host
        # port. Select the most likely web gateway and normalize its public
        # mapping to the port allocated by Yunzhou.
        def entry_score(item):
            service_name, service = item
            text = yaml.safe_dump(service, allow_unicode=True).lower()
            score = 0
            if any(word in service_name.lower() for word in ("web", "front", "ui", "gateway", "nginx")):
                score += 20
            if "nginx" in text:
                score += 15
            if service.get("ports"):
                score += 10
            if any(word in service_name.lower() for word in ("mysql", "redis", "cache", "db")):
                score -= 30
            return score

        entry_name, entry_service = max(services.items(), key=entry_score)
        mappings = list(entry_service.get("ports") or [])
        target_port = container_port
        if mappings:
            first = mappings[0]
            if isinstance(first, dict):
                target_port = first.get("target") or target_port
                first["published"] = "${YUNZHOU_HOST_PORT}"
                mappings[0] = first
            else:
                raw = str(first)
                protocol = "/" + raw.rsplit("/", 1)[1] if "/" in raw else ""
                without_protocol = raw.rsplit("/", 1)[0]
                target = without_protocol.rsplit(":", 1)[-1]
                if target.isdigit():
                    target_port = int(target)
                mappings[0] = f"${{YUNZHOU_HOST_PORT}}:{target_port or 80}{protocol}"
        else:
            if not target_port:
                text = yaml.safe_dump(entry_service, allow_unicode=True).lower()
                target_port = 80 if "nginx" in text else 8080
            mappings = [f"${{YUNZHOU_HOST_PORT}}:{target_port}"]
        entry_service["ports"] = mappings
        published = True
    compose_text = yaml.safe_dump(compose, sort_keys=False, allow_unicode=True)
    compose_file = root / ".yunzhou.ai.compose.yml"
    compose_file.write_text(compose_text + "\n", encoding="utf-8")
    return "compose", compose_file.name, None


def compose_pull_images(path: str, compose_file: str) -> list[str]:
    """Return image-only Compose services; locally-built services are excluded."""
    try:
        document = yaml.safe_load((Path(path) / compose_file).read_text(encoding="utf-8", errors="ignore")) or {}
    except (OSError, yaml.YAMLError):
        return []
    images = []
    for service in (document.get("services") or {}).values():
        if isinstance(service, dict) and service.get("image") and not service.get("build"):
            image = str(service["image"]).strip()
            if image and "${" not in image and image not in images:
                images.append(image)
    return images


def required_compose_variables(path: str, compose_file: str, env_text: str | None = None) -> list[dict]:
    """Find Compose variables that explicitly require a value before Docker runs."""
    source = (Path(path) / compose_file).read_text(encoding="utf-8", errors="ignore")
    supplied = {
        line.split("=", 1)[0].strip()
        for line in (env_text or "").splitlines()
        if "=" in line and not line.lstrip().startswith("#") and line.split("=", 1)[1].strip()
    }
    supplied.update({"COMPOSE_PROJECT_NAME", "YUNZHOU_HOST_PORT", "CRM_DB_PASSWORD", "CRM_DB_ROOT_PASSWORD", "CRM_JWT_SECRET"})
    found = []
    pattern = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::?\?)([^}]*)\}")
    for match in pattern.finditer(source):
        name, hint = match.group(1), match.group(2).strip()
        if name not in supplied and not any(item["name"] == name for item in found):
            found.append({"name": name, "hint": hint or "Compose 声明为必填项"})
    return found


def effective_project_environment(project: Project) -> str:
    """Return effective values while letting managed integrations override stale external fields."""
    managed = (project.managed_env_text or "").strip()
    user = (decrypt(project.env_text_encrypted) or "").strip()
    user_values = environment_values(user)
    managed_values = environment_values(managed)
    lines = [managed, user]
    for service in ("MYSQL", "REDIS"):
        if user_values.get(f"YUNZHOU_{service}_MODE", "managed").lower() != "external":
            for key, value in managed_values.items():
                if key.startswith(f"YUNZHOU_{service}_") and key != f"YUNZHOU_{service}_MODE":
                    lines.append(f"{key}={value}")
    return "\n".join(item for item in lines if item)


def environment_values(text: str | None) -> dict[str, str]:
    values = {}
    for line in (text or "").splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip()
    return values


def adapt_plan_to_current_integrations(plan: dict, project: Project) -> tuple[dict, list[str]]:
    """Apply the form's current integration choices to a saved AI plan.

    Source analysis is reusable, while external credentials and managed versus
    external choices can change immediately before deployment.  The current
    submitted configuration is authoritative and must not be shadowed by an
    older managed-service Compose plan.
    """
    adapted = json.loads(json.dumps(plan))
    values = environment_values(decrypt(project.env_text_encrypted) or "")
    changes: list[str] = []
    if project.deployment_mode != "preserve_integrations":
        return adapted, changes
    if values.get("YUNZHOU_MYSQL_MODE", "managed").lower() != "external":
        return adapted, changes
    compose_text = str(adapted.get("compose_yaml") or "")
    try:
        compose = yaml.safe_load(compose_text)
    except yaml.YAMLError:
        return adapted, changes
    services = compose.get("services") if isinstance(compose, dict) else None
    if not isinstance(services, dict):
        return adapted, changes
    mysql_services = {
        name for name, service in services.items()
        if isinstance(service, dict) and re.match(r"(?i)^(?:[^/]+/)?mysql(?::|$)", str(service.get("image") or ""))
    }
    if not mysql_services:
        return adapted, changes
    for name in mysql_services:
        services.pop(name, None)
    variable_map = {
        "DB_HOST": "YUNZHOU_MYSQL_HOST", "MYSQL_HOST": "YUNZHOU_MYSQL_HOST",
        "DB_PORT": "YUNZHOU_MYSQL_PORT", "MYSQL_PORT": "YUNZHOU_MYSQL_PORT",
        "DB_NAME": "YUNZHOU_MYSQL_DATABASE", "DB_DATABASE": "YUNZHOU_MYSQL_DATABASE",
        "MYSQL_DATABASE": "YUNZHOU_MYSQL_DATABASE",
        "DB_USERNAME": "YUNZHOU_MYSQL_USERNAME", "DB_USER": "YUNZHOU_MYSQL_USERNAME",
        "MYSQL_USER": "YUNZHOU_MYSQL_USERNAME",
        "DB_PASSWORD": "YUNZHOU_MYSQL_PASSWORD", "MYSQL_PASSWORD": "YUNZHOU_MYSQL_PASSWORD",
    }
    for service in services.values():
        if not isinstance(service, dict):
            continue
        depends = service.get("depends_on")
        if isinstance(depends, dict):
            for name in mysql_services:
                depends.pop(name, None)
        elif isinstance(depends, list):
            service["depends_on"] = [name for name in depends if name not in mysql_services]
        env = service.get("environment")
        if isinstance(env, dict):
            for key, source in variable_map.items():
                if key in env:
                    env[key] = "${" + source + "}"
            # Frameworks frequently expose one complete JDBC URL instead of
            # separate DB_HOST/DB_PORT variables (for example Spring/Druid).
            # Rewrite the endpoint generically while preserving driver query
            # parameters, then bind matching credentials to the user's saved
            # external integration values.
            for key, current in list(env.items()):
                rendered = str(current or "")
                if re.search(r"(?i)jdbc:mysql://", rendered):
                    env[key] = re.sub(
                        r"(?i)jdbc:mysql://[^/:?\s]+(?::\d+)?/[^?\s]+",
                        "jdbc:mysql://${YUNZHOU_MYSQL_HOST}:${YUNZHOU_MYSQL_PORT}/${YUNZHOU_MYSQL_DATABASE}",
                        rendered,
                        count=1,
                    )
                    prefix = re.sub(r"(?i)(?:URL|JDBC_URL)$", "", key)
                    username_key = prefix + "USERNAME"
                    password_key = prefix + "PASSWORD"
                    if username_key in env:
                        env[username_key] = "${YUNZHOU_MYSQL_USERNAME}"
                    if password_key in env:
                        env[password_key] = "${YUNZHOU_MYSQL_PASSWORD}"
    adapted["compose_yaml"] = yaml.safe_dump(compose, allow_unicode=True, sort_keys=False)
    adapted["services"] = [name for name in (adapted.get("services") or []) if name not in mysql_services and "mysql" not in str(name).lower()]
    adapted["inferred_config"] = [
        row for row in (adapted.get("inferred_config") or [])
        if str(row.get("key") or "") not in variable_map
    ]
    changes.append("已按当前表单改用外部 MySQL，并移除平台托管 MySQL 服务")
    return adapted, changes


def store_managed_values(project: Project, values: dict[str, str]) -> list[str]:
    """Store platform-owned connection values in readable project configuration."""
    lines = (project.managed_env_text or "").splitlines()
    positions = {
        line.split("=", 1)[0].strip(): index for index, line in enumerate(lines)
        if "=" in line and not line.lstrip().startswith("#")
    }
    added = []
    for key, value in values.items():
        rendered = f"{key}={value}"
        if key in positions:
            if lines[positions[key]] != rendered:
                lines[positions[key]] = rendered
                added.append(key)
        else:
            lines.append(rendered)
            positions[key] = len(lines) - 1
            added.append(key)
    if added:
        project.managed_env_text = "\n".join(lines).strip() + "\n"
    return added


def apply_ai_inferred_config(project: Project, plan: dict) -> list[dict]:
    """Persist only high-confidence, non-secret AI findings without overwriting user values."""
    current_lines = (project.managed_env_text or "").splitlines()
    user_keys = {
        line.split("=", 1)[0].strip() for line in (decrypt(project.env_text_encrypted) or "").splitlines()
        if "=" in line and not line.lstrip().startswith("#")
    }
    positions = {line.split("=", 1)[0].strip(): index for index, line in enumerate(current_lines) if "=" in line and not line.lstrip().startswith("#")}
    applied = []
    secret_words = ("password", "secret", "token", "private", "access_key", "credential")
    allowed_suffixes = ("_URL", "_URI", "_ENDPOINT", "_HOST", "_PORT", "_BUCKET", "_REGION", "_PREFIX", "_ISSUER")
    for item in plan.get("inferred_config") or []:
        if not isinstance(item, dict) or str(item.get("confidence", "")).lower() != "high":
            continue
        key, value = str(item.get("key") or "").strip(), str(item.get("value") or "").strip()
        lower = key.lower()
        if (not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", key) or key in positions or key in user_keys or
                any(word in lower for word in secret_words) or not key.endswith(allowed_suffixes) or
                not value or len(value) > 2048 or any(marker in value.lower() for marker in ("...", "<", ">", "your_", "example.com"))):
            continue
        current_lines.append(f"{key}={value}")
        positions[key] = len(current_lines) - 1
        applied.append({"key": key, "value": value, "source": str(item.get("source") or "AI 源码分析")})
    if applied:
        project.managed_env_text = "\n".join(current_lines).strip() + "\n"
    return applied


def ensure_managed_secrets(project: Project, compose_path: str, compose_file: str) -> list[str]:
    """Generate credentials owned by a fresh managed stack, never third-party credentials."""
    effective_env = "\n".join(filter(None, (project.managed_env_text or "", decrypt(project.env_text_encrypted) or "")))
    missing = required_compose_variables(compose_path, compose_file, effective_env)
    external_prefixes = ("OIDC_", "OAUTH_", "PAYMENT_", "SMS_", "SMTP_", "S3_EXTERNAL_")
    secret_markers = ("PASSWORD", "SECRET", "TOKEN", "ACCESS_KEY")
    current_lines = (project.managed_env_text or "").splitlines()
    generated = []
    for item in missing:
        key = item["name"]
        upper_key = key.upper()
        is_username = upper_key in {"USER", "USERNAME"} or upper_key.endswith(("_USER", "_USERNAME"))
        is_secret = any(marker in upper_key for marker in secret_markers)
        if key.startswith(external_prefixes) or not (is_username or is_secret):
            continue
        digest = hashlib.sha256(f"{settings.app_secret}:{project.id}:{key}".encode()).hexdigest()
        if is_username:
            safe_slug = re.sub(r"[^a-z0-9]+", "_", project.slug.lower()).strip("_")[:20] or "app"
            value = f"yz_{safe_slug}_{digest[:6]}"
        elif upper_key.endswith("ACCESS_KEY"):
            value = "yz" + digest[:18]
        else:
            value = digest[:48]
        current_lines.append(f"{key}={value}")
        generated.append(key)
    if generated:
        project.managed_env_text = "\n".join(current_lines).strip() + "\n"
    return generated


def reconcile_managed_integrations(project: Project, compose_path: str, compose_file: str) -> list[str]:
    """Guarantee that every unchecked integration has a real managed Compose service."""
    target = Path(compose_path) / compose_file
    document = yaml.safe_load(target.read_text(encoding="utf-8", errors="ignore")) or {}
    services = document.setdefault("services", {})
    if not isinstance(services, dict):
        return []
    user_values = environment_values(decrypt(project.env_text_encrypted) or "")
    changes = []

    def consumers(prefix: str) -> list[str]:
        return [name for name, service in services.items()
                if isinstance(service, dict) and prefix in yaml.safe_dump(service, allow_unicode=True)]

    if consumers("YUNZHOU_REDIS_") and user_values.get("YUNZHOU_REDIS_MODE", "managed").lower() != "external":
        password = hashlib.sha256(f"{settings.app_secret}:{project.id}:redis".encode()).hexdigest()[:32]
        redis_name = next((name for name, service in services.items() if isinstance(service, dict) and (
            str(service.get("image") or "").lower().startswith("redis:") or name.lower() in {"redis", "cache"}
        )), None)
        if not redis_name:
            redis_name = "redis"
            services[redis_name] = {
                "image": "redis:7-alpine",
                "command": ["redis-server", "--appendonly", "yes", "--requirepass", "${YUNZHOU_REDIS_PASSWORD}"],
                "volumes": [f"{project.slug}_redis_data:/data"],
                "healthcheck": {"test": ["CMD-SHELL", "redis-cli -a $$YUNZHOU_REDIS_PASSWORD ping | grep PONG"], "interval": "10s", "timeout": "5s", "retries": 10},
                "environment": {"YUNZHOU_REDIS_PASSWORD": "${YUNZHOU_REDIS_PASSWORD}"},
                "restart": "unless-stopped",
            }
            document.setdefault("volumes", {}).setdefault(f"{project.slug}_redis_data", {})
        else:
            # A generated plan may already contain a plain redis:alpine service
            # while the platform has generated YUNZHOU_REDIS_PASSWORD for its
            # consumers.  Configure both sides here so Spring/Node applications
            # never send AUTH to a password-less Redis instance.
            redis_service = services[redis_name]
            redis_service.setdefault("environment", {})
            if isinstance(redis_service["environment"], dict):
                redis_service["environment"]["YUNZHOU_REDIS_PASSWORD"] = "${YUNZHOU_REDIS_PASSWORD}"
            command = redis_service.get("command")
            if isinstance(command, str):
                if "requirepass" not in command.lower():
                    redis_service["command"] = command.rstrip() + " --requirepass ${YUNZHOU_REDIS_PASSWORD}"
            elif isinstance(command, list):
                if not any("requirepass" in str(item).lower() for item in command):
                    redis_service["command"] = [*command, "--requirepass", "${YUNZHOU_REDIS_PASSWORD}"]
            else:
                redis_service["command"] = [
                    "redis-server", "--appendonly", "yes", "--requirepass", "${YUNZHOU_REDIS_PASSWORD}",
                ]
            redis_service["healthcheck"] = {
                "test": ["CMD-SHELL", "redis-cli -a $$YUNZHOU_REDIS_PASSWORD ping | grep PONG"],
                "interval": "10s",
                "timeout": "5s",
                "retries": 10,
            }
        store_managed_values(project, {"YUNZHOU_REDIS_HOST": redis_name, "YUNZHOU_REDIS_PORT": "6379", "YUNZHOU_REDIS_DATABASE": "0", "YUNZHOU_REDIS_PASSWORD": password})
        changes.append("Redis")

    if consumers("YUNZHOU_MYSQL_") and user_values.get("YUNZHOU_MYSQL_MODE", "managed").lower() != "external":
        digest = hashlib.sha256(f"{settings.app_secret}:{project.id}:mysql-managed".encode()).hexdigest()
        database = re.sub(r"[^a-zA-Z0-9_]", "_", project.slug)[:48] or "app"
        services.setdefault("mysql", {
            "image": "mysql:8.4",
            "environment": {"MYSQL_DATABASE": "${YUNZHOU_MYSQL_DATABASE}", "MYSQL_USER": "${YUNZHOU_MYSQL_USERNAME}", "MYSQL_PASSWORD": "${YUNZHOU_MYSQL_PASSWORD}", "MYSQL_ROOT_PASSWORD": "${YUNZHOU_MYSQL_ROOT_PASSWORD}"},
            "volumes": [f"{project.slug}_mysql_data:/var/lib/mysql"],
            "healthcheck": {"test": ["CMD-SHELL", "mysqladmin ping -h 127.0.0.1 -uroot -p$$MYSQL_ROOT_PASSWORD"], "interval": "10s", "timeout": "5s", "retries": 20},
            "restart": "unless-stopped",
        })
        document.setdefault("volumes", {}).setdefault(f"{project.slug}_mysql_data", {})
        store_managed_values(project, {"YUNZHOU_MYSQL_HOST": "mysql", "YUNZHOU_MYSQL_PORT": "3306", "YUNZHOU_MYSQL_DATABASE": database, "YUNZHOU_MYSQL_USERNAME": "yunzhou", "YUNZHOU_MYSQL_PASSWORD": digest[:32], "YUNZHOU_MYSQL_ROOT_PASSWORD": hashlib.sha256((digest + ":root").encode()).hexdigest()[:32]})
        changes.append("MySQL")

    if changes:
        target.write_text(yaml.safe_dump(document, allow_unicode=True, sort_keys=False), encoding="utf-8")
    return changes


def analyze_runtime_dependencies(path: str) -> dict:
    """Classify active configuration separately from libraries merely present in source."""
    root = Path(path)
    config_text = ""
    manifest_text = ""
    config_names = {"application.yml", "application.yaml", "application.properties", "bootstrap.yml", "bootstrap.yaml", "bootstrap.properties", ".env", ".env.production"}
    for file in root.rglob("*"):
        if not file.is_file() or any(part in {".git", "node_modules", "target", "dist", "build"} for part in file.parts):
            continue
        try:
            if file.name.lower() in config_names:
                config_text += "\n" + file.read_text(errors="ignore").lower()
            elif file.name in {"pom.xml", "package.json", "requirements.txt", "pyproject.toml"}:
                manifest_text += "\n" + file.read_text(errors="ignore").lower()
        except OSError:
            continue
    checks = {
        "MySQL": (("jdbc:mysql", "mysql://"), ("mysql-connector", "pymysql", "mysql2")),
        "PostgreSQL": (("jdbc:postgresql", "postgresql://", "postgres://"), ("postgresql", "psycopg", "pg")),
        "Redis": (("spring.redis", "spring:\n  redis", "redis://", "redis_host", "redis.host"), ("starter-data-redis", "sa-token-dao-redis", "ioredis", '"redis"')),
        "RabbitMQ": (("spring.rabbitmq", "amqp://", "rabbitmq_host"), ("starter-amqp", "rabbitmq")),
        "Elasticsearch": (("spring.elasticsearch", "elasticsearch.uris", "elasticsearch_host"), ("elasticsearch",)),
        "MinIO": (("minio.endpoint", "minio:\n", "minio_endpoint"), ("<artifactid>minio", '"minio"')),
        "MongoDB": (("spring.data.mongodb", "mongodb://"), ("starter-data-mongodb", "mongodb")),
        "Kafka": (("spring.kafka", "kafka.bootstrap", "kafka_brokers"), ("spring-kafka", "kafkajs")),
    }
    required, candidates = [], []
    for name, (active_markers, library_markers) in checks.items():
        if any(marker in config_text for marker in active_markers):
            required.append(name)
        elif any(marker in manifest_text for marker in library_markers):
            candidates.append(name)
    compose_services = []
    compose = _find_compose(root)
    if compose:
        text = compose.read_text(errors="ignore").lower()
        compose_services = [name for name in checks if name.lower() in text]
        required = sorted(set(required + compose_services))
        candidates = [name for name in candidates if name not in required]
    return {
        "required": required,
        "candidates": candidates,
        "policy": "仅按生效配置和 Compose 服务认定必需依赖；仅出现在依赖声明中的中间件不自动安装",
    }


def analyze_repository_topology(path: str, build_type: str, build_file: str) -> dict:
    """Build and validate a whole-repository plan before any remote mutation."""
    root = Path(path).resolve()
    ignored = {".git", "node_modules", "target", "dist", "build", "vendor", ".venv"}
    manifests = []
    for file in root.rglob("*"):
        if not file.is_file() or any(part in ignored for part in file.relative_to(root).parts):
            continue
        if file.name in {"package.json", "pom.xml", "requirements.txt", "pyproject.toml", "go.mod", "Cargo.toml"}:
            manifests.append(file.relative_to(root).as_posix())
    frontend_roots, java_roots = _fullstack_roots(root)
    python_roots = sorted({p.parent for name in ("requirements.txt", "pyproject.toml") for p in root.rglob(name) if not any(x in ignored for x in p.relative_to(root).parts)})
    database_scripts = [p.relative_to(root).as_posix() for p in root.rglob("*.sql") if not any(x in ignored for x in p.relative_to(root).parts)][:50]
    config_text = ""
    for file in root.rglob("*"):
        if file.is_file() and file.stat().st_size < 1_000_000 and not any(x in ignored for x in file.relative_to(root).parts):
            if file.suffix.lower() in {".ts", ".tsx", ".js", ".jsx", ".py", ".java", ".yml", ".yaml", ".env"} or file.name.startswith(".env"):
                config_text += "\n" + file.read_text(errors="ignore")
    entry_paths = sorted(set(re.findall(r"(?m)^\s*(?:VITE_APP_BASE|PUBLIC_URL|BASE_PATH)\s*=\s*([^\s#]+)", config_text)))
    detected_api = detect_frontend_api_routes(path)
    api_paths = [str(row["path"]) for row in detected_api.get("routes") or []]
    plan = {
        "scan_scope": "整个仓库",
        "manifests": manifests,
        "frontend_roots": [p.relative_to(root).as_posix() for p in frontend_roots],
        "backend_roots": [p.relative_to(root).as_posix() for p in [*java_roots, *python_roots]],
        "database_scripts": database_scripts,
        "entry_paths": entry_paths,
        "api_paths": api_paths,
        "api_route_evidence": detected_api.get("evidence") or [],
        "build_type": build_type,
        "build_file": build_file,
        "services": [],
        "persistent_mounts": [],
        "errors": [],
    }
    if build_type == "compose":
        compose_path = (root / build_file).resolve()
        try:
            compose_path.relative_to(root)
        except ValueError:
            plan["errors"].append("Compose 文件超出仓库目录")
            return plan
        try:
            document = yaml.safe_load(compose_path.read_text(errors="ignore")) or {}
        except Exception as exc:
            plan["errors"].append(f"Compose 无法解析：{exc}")
            return plan
        services = document.get("services") or {}
        if not services:
            plan["errors"].append("Compose 中没有服务")
        for name, service in services.items():
            service = service or {}
            build = service.get("build")
            image = service.get("image")
            context_value = build if isinstance(build, str) else (build or {}).get("context")
            dockerfile_value = None if isinstance(build, str) else (build or {}).get("dockerfile")
            if context_value:
                context = (compose_path.parent / str(context_value)).resolve()
                if not context.exists():
                    plan["errors"].append(f"服务 {name} 的构建目录不存在：{context_value}")
                elif dockerfile_value and not (context / str(dockerfile_value)).is_file():
                    plan["errors"].append(f"服务 {name} 的 Dockerfile 不存在：{dockerfile_value}")
            volumes = service.get("volumes") or []
            plan["persistent_mounts"].extend(str(value) for value in volumes)
            plan["services"].append({
                "name": name, "build": context_value, "dockerfile": dockerfile_value,
                "image": image, "ports": service.get("ports") or [],
                "depends_on": list((service.get("depends_on") or {}).keys()) if isinstance(service.get("depends_on"), dict) else (service.get("depends_on") or []),
            })
    else:
        plan["services"].append({"name": "app", "build": ".", "dockerfile": build_file, "image": None, "ports": []})
        if frontend_roots and (java_roots or python_roots):
            plan["errors"].append("同时发现前端和后端源码，但当前方案只有一个普通应用容器")
    plan["persistent_mounts"] = sorted(set(plan["persistent_mounts"]))
    return plan


def infer_verified_access_path(source_path: str, ai_plan: dict | None) -> tuple[str, str]:
    """Choose a source-backed HTTP path when the model leaves it at `/`.

    Only explicit routes found in source or project documentation are
    considered. Parameterized/detail routes are excluded because they require
    data. The returned evidence is written to the deployment log so a later
    successful access check can promote it to verified experience.
    """
    configured = str((ai_plan or {}).get("access_path") or "/").strip()
    safe_path = re.compile(r"^/[A-Za-z0-9._~!$&*+,;=:@%/-]*$")
    if configured and configured != "/" and safe_path.fullmatch(configured):
        return (configured if configured.startswith("/") else "/" + configured), "AI 部署方案"
    root = Path(source_path)
    candidates: list[tuple[int, str, str]] = []
    route_pattern = re.compile(r"(?<![A-Za-z0-9_])(/(?:api|actuator)/[A-Za-z0-9_.~!$&*+,;=:@%/-]+)")
    preferred_names = {"README.md", "README", "readme.md"}
    files = [p for p in root.rglob("*") if p.is_file() and (
        p.name in preferred_names or p.suffix.lower() in {".java", ".kt", ".py", ".js", ".ts", ".md"}
    )]
    for file in files[:500]:
        if any(part in {".git", "node_modules", "target", "dist", "build"} for part in file.relative_to(root).parts):
            continue
        text = file.read_text(encoding="utf-8", errors="replace")[:300_000]
        relative_file = file.relative_to(root).as_posix()
        # Spring controllers commonly split a route between the class and the
        # method, for example `/api/device` + `list/{pageNum}/{pageSize}`.  A
        # class-level mapping is only a namespace and often returns 404, so
        # build a concrete GET probe from both annotations before considering
        # generic string matches.  Path variables use harmless deterministic
        # values because this probe only verifies routing/readiness.
        if file.suffix.lower() in {".java", ".kt"}:
            class_match = re.search(
                r"@RequestMapping\s*\(\s*(?:value\s*=\s*)?[\"']([^\"']+)[\"'][^)]*\)\s*(?:public\s+)?class\s+",
                text,
                re.S,
            )
            class_path = class_match.group(1).strip("/") if class_match else ""
            method_pattern = re.compile(
                r"@(GetMapping|RequestMapping)\s*\((.*?)\)\s*"
                r"(?:@[A-Za-z_][A-Za-z0-9_.]*(?:\([^)]*\))?\s*)*"
                r"(?:public|protected|private)\s+",
                re.S,
            )
            for annotation, arguments in method_pattern.findall(text):
                if annotation == "RequestMapping" and "RequestMethod.GET" not in arguments:
                    continue
                value_match = re.search(r"(?:value|path)\s*=\s*[\"']([^\"']+)[\"']|^[\s]*[\"']([^\"']+)[\"']", arguments)
                method_path = next((value for value in (value_match.groups() if value_match else ()) if value), "")
                if not method_path:
                    continue
                joined = "/" + "/".join(part for part in (class_path, method_path.strip("/")) if part)
                joined = re.sub(r"\{[^}/]+\}", "1", joined)
                if safe_path.fullmatch(joined):
                    # Prefer collection/list/health endpoints over mutations or
                    # detail endpoints when several concrete GET routes exist.
                    route_rank = 0 if re.search(r"/(?:list|health|status)(?:/|$)", joined, re.I) else 1
                    candidates.append((route_rank, joined, relative_file))
        for match in route_pattern.finditer(text):
            route = match.group(1).rstrip("/.,;:`'\"")
            if not route or "{" in route or "}" in route:
                continue
            candidates.append((2, route, relative_file))
    if not candidates:
        return "/", "默认根路径"
    # Collection and health endpoints are safer than deep resource paths.
    candidates.sort(key=lambda item: (item[0], item[1].count("/"), len(item[1]), item[1]))
    _, route, evidence = candidates[0]
    return route, f"源码证据 {evidence}"


def preflight_ai_deployment_plan(
    source_path: str, plan: dict, project: Project, db=None, previous_error: str = ""
) -> dict:
    """Materialize and validate an AI plan in a disposable source copy."""
    source = Path(source_path).resolve()
    preflight_root = Path(settings.build_data_root) / "builder" / "preflight"
    preflight_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="yunzhou-analysis-", dir=preflight_root) as temporary:
        rehearsal = Path(temporary) / "source"
        shutil.copytree(
            source,
            rehearsal,
            ignore=shutil.ignore_patterns(".git", "node_modules", "target", "dist", "build", "__pycache__"),
        )
        effective_plan, automatic_repairs = adapt_plan_to_current_integrations(plan, project)
        build_type, build_file, detected_port = materialize_ai_deployment_plan(str(rehearsal), effective_plan)
        # Reuse only bounded repair classifiers implemented by the platform.
        # The previous failure is evidence, never a command or model prompt.
        safe_repairs = apply_safe_build_repairs(str(rehearsal), previous_error, project.deployment_mode)
        managed_integrations: list[str] = []
        generated_secrets: list[str] = []
        if build_type == "compose" and project.deployment_mode == "managed_fresh":
            # Analysis must exercise the same managed-service preparation as a
            # real deployment. Otherwise platform-owned credentials (Redis,
            # MySQL, MinIO, etc.) are incorrectly shown as user configuration
            # and a valid project is blocked before the worker can generate
            # them. All file changes happen in the disposable rehearsal copy;
            # only generated managed values are retained on the project.
            managed_integrations = reconcile_managed_integrations(project, str(rehearsal), build_file)
            generated_secrets = ensure_managed_secrets(project, str(rehearsal), build_file)
        missing = required_compose_variables(
            str(rehearsal), build_file, effective_project_environment(project)
        ) if build_type == "compose" else []
        topology = analyze_repository_topology(str(rehearsal), build_type, build_file)
        if topology.get("errors"):
            raise RuntimeError("；".join(topology["errors"]))
        generated = rehearsal / build_file
        result = {
            "status": "passed" if not missing else "needs_configuration",
            "build_type": build_type,
            "build_file": build_file,
            "container_port": detected_port,
            "service_count": len(topology.get("services") or []),
            "services": topology.get("services") or [],
            "missing_configuration": missing,
            "automatic_repairs": (
                automatic_repairs
                + [f"经验修复：{name}" for name in safe_repairs]
                + [f"托管依赖：{name}" for name in managed_integrations]
                + [f"自动凭据：{name}" for name in generated_secrets]
            ),
            "generated_sha256": hashlib.sha256(generated.read_bytes()).hexdigest() if generated.is_file() else None,
            "source_untouched": True,
        }
        if db is not None and not missing:
            # Source analysis must not compile the same application twice.
            # The generated files, topology, variables, ports, integrations,
            # database initialization assets and known failure classifiers are
            # validated here. The real build remains the single authoritative
            # compilation during deployment, where its image/cache is retained.
            result["execution"] = {
                "status": "static_validated",
                "mode": "analysis_only",
                "reason": "静态架构与配置校验通过；镜像将在发布阶段仅构建一次",
            }
            result["status"] = "passed"
        return result


def _run_temporary_privileged_preflight(db, rehearsal: Path, build_type: str, build_file: str, project: Project) -> dict:
    """Build and start an isolated disposable release on the platform builder."""
    values = environment_values(effective_project_environment(project))
    external = [
        service for service in ("MYSQL", "REDIS")
        if project.deployment_mode == "preserve_integrations"
        and values.get(f"YUNZHOU_{service}_MODE", "").lower() == "external"
    ]
    if external:
        return {
            "status": "skipped_external_integration",
            "mode": "temporary_privileged",
            "reason": "外部集成不会在预演中使用生产凭据：" + "、".join(external),
        }
    node = platform_gateway_node(db)
    if not node:
        return {"status": "skipped_no_builder", "mode": "temporary_privileged", "reason": "没有可用的平台构建节点"}
    compose_project = "yz-preflight-" + hashlib.sha256(f"{project.id}:{time.time_ns()}".encode()).hexdigest()[:12]
    started = time.monotonic()
    environment = {
        **values,
        "YUNZHOU_HOST_PORT": "",
        "CRM_DB_PASSWORD": hashlib.sha256(f"{compose_project}:db".encode()).hexdigest()[:32],
        "CRM_DB_ROOT_PASSWORD": hashlib.sha256(f"{compose_project}:root".encode()).hexdigest()[:40],
        "YUNZHOU_REDIS_PASSWORD": hashlib.sha256(f"{compose_project}:redis".encode()).hexdigest()[:32],
        "CRM_JWT_SECRET": hashlib.sha256(f"{compose_project}:jwt".encode()).hexdigest(),
    }
    env_file = rehearsal / ".yunzhou.preflight.env"
    compose_path = rehearsal / build_file
    container_name = compose_project + "-app"
    image_name = compose_project + ":test"
    base = ""
    logs = ""
    try:
        with SSHNode(node) as ssh:
            code, port_output = ssh.run(
                "for p in $(seq 45000 45999); do "
                "if ! ss -ltn 2>/dev/null | awk '{print $4}' | grep -q \":${p}$\"; "
                "then echo $p; break; fi; done",
                timeout=15,
            )
            port = port_output.strip().splitlines()[-1] if code == 0 and port_output.strip() else ""
            if not port.isdigit():
                raise RuntimeError("没有可用的临时预演端口")
            environment["YUNZHOU_HOST_PORT"] = port
            env_file.write_text("\n".join(f"{key}={value}" for key, value in environment.items() if value is not None) + "\n", encoding="utf-8")
            env_file.chmod(0o600)
            if build_type == "compose":
                base = (
                    f"cd {shlex.quote(str(rehearsal))} && "
                    "export DOCKER_BUILDKIT=0 COMPOSE_DOCKER_CLI_BUILD=0 COMPOSE_BAKE=false && "
                    f"docker compose --env-file {shlex.quote(env_file.name)} -p {shlex.quote(compose_project)} -f {shlex.quote(compose_path.name)}"
                )
                preflight_command = base + " up -d --build"
            else:
                container_port = detect_container_port(str(rehearsal), build_file) or project.container_port or 80
                preflight_command = (
                    f"cd {shlex.quote(str(rehearsal))} && export DOCKER_BUILDKIT=0 && "
                    f"docker build -f {shlex.quote(build_file)} -t {shlex.quote(image_name)} . && "
                    f"docker run -d --name {shlex.quote(container_name)} --env-file {shlex.quote(env_file.name)} "
                    f"-p 127.0.0.1:{port}:{int(container_port)} {shlex.quote(image_name)}"
                )
            # ``cd`` is a shell builtin, so timeout must wrap a shell rather
            # than trying to execute ``cd`` as a binary.
            code, output = ssh.run(
                "timeout 900 sh -lc " + shlex.quote(preflight_command),
                timeout=930,
            )
            logs = output[-20_000:]
            if code:
                raise RuntimeError("预演构建或启动失败：" + (output[-4000:] or "未返回日志"))
            verified = False
            last_status = ""
            for _ in range(36):
                check_code, check_output = ssh.run(
                    f"curl -sS -o /dev/null -w '%{{http_code}}' --connect-timeout 3 --max-time 8 http://127.0.0.1:{port}/",
                    timeout=12,
                )
                last_status = check_output.strip()[-3:]
                if check_code == 0 and last_status.isdigit() and 200 <= int(last_status) < 500:
                    verified = True
                    break
                time.sleep(5)
            if not verified:
                if build_type == "compose":
                    _, service_logs = ssh.run(base + " logs --no-color --tail 160", timeout=30)
                else:
                    _, service_logs = ssh.run(f"docker logs --tail 160 {shlex.quote(container_name)}", timeout=30)
                logs = service_logs[-20_000:]
                raise RuntimeError(f"预演访问验证失败（HTTP {last_status or '无响应'}）：" + logs[-4000:])
            return {
                "status": "passed", "mode": "temporary_privileged",
                "builder": node.name, "http_status": int(last_status),
                "duration_seconds": round(time.monotonic() - started, 1),
                "cleanup": "attempted_after_verification",
            }
    except Exception as exc:
        return {
            "status": "failed", "mode": "temporary_privileged",
            "builder": node.name, "error": str(exc)[:6000], "log_tail": logs[-6000:],
            "duration_seconds": round(time.monotonic() - started, 1),
        }
    finally:
        try:
            with SSHNode(node) as ssh:
                if build_type == "compose":
                    cleanup = (
                        f"cd {shlex.quote(str(rehearsal))} && export DOCKER_BUILDKIT=0 COMPOSE_DOCKER_CLI_BUILD=0 COMPOSE_BAKE=false && "
                        f"docker compose --env-file {shlex.quote(env_file.name)} -p {shlex.quote(compose_project)} "
                        f"-f {shlex.quote(compose_path.name)} down --volumes --rmi local --remove-orphans"
                    )
                else:
                    cleanup = (
                        f"docker rm -f {shlex.quote(container_name)} >/dev/null 2>&1 || true; "
                        f"docker image rm -f {shlex.quote(image_name)} >/dev/null 2>&1 || true"
                    )
                ssh.run(cleanup, timeout=180)
        except Exception:
            pass


def choose_port(db, preferred: int | None) -> int:
    # Port selection and the subsequent Deployment/ProjectReplica write must be
    # serialized across worker and API processes.  Without this transaction
    # lock a release and a simultaneous scale request can both observe the same
    # free port and one of the Docker starts then fails with "port allocated".
    db.execute(text("SELECT pg_advisory_xact_lock(hashtext('node-port-allocation'))"))
    policy = db.get(DeploymentSettings, "default")
    internal_start = policy.internal_port_start if policy else 30000
    internal_end = policy.internal_port_end if policy else 39999
    external_start = policy.external_port_start if policy else 20000
    external_end = policy.external_port_end if policy else 21000
    if preferred:
        if external_start <= preferred <= external_end:
            raise RuntimeError("项目指定的服务器端口占用了公网网关端口段，请改用内网实例端口段")
        return preferred
    used = set(db.scalars(select(Deployment.host_port).where(Deployment.status.in_([DeployStatus.queued, DeployStatus.running, DeployStatus.success]))).all())
    used.update(db.scalars(select(ProjectReplica.host_port).where(ProjectReplica.status == "running")).all())
    for port in range(internal_start, internal_end + 1):
        if port not in used:
            return port
    raise RuntimeError("内网实例端口池已用完，请在系统设置中扩大端口范围")


def choose_node_port(db, node: Node, preferred: int | None, reserved: set[int] | None = None) -> int:
    """Choose a port that is free in both platform state and the real node.

    Old containers can outlive a deleted deployment record.  Looking only at
    the database can therefore select a port which Docker still owns.  Reserve
    the first database candidate, verify it on the target node, and advance
    within the configured internal pool when necessary.
    """
    policy = db.get(DeploymentSettings, "default")
    internal_end = policy.internal_port_end if policy else 39999
    candidate = choose_port(db, preferred)
    used = set(db.scalars(select(Deployment.host_port).where(
        Deployment.status.in_([DeployStatus.queued, DeployStatus.running, DeployStatus.success])
    )).all())
    used.update(db.scalars(select(ProjectReplica.host_port).where(
        ProjectReplica.status == "running"
    )).all())
    locally_reserved = {int(port) for port in (reserved or set()) if port}
    used.update(locally_reserved)
    with SSHNode(node) as ssh:
        while candidate <= internal_end:
            code, _ = ssh.run(
                "(ss -ltnH 2>/dev/null | awk '{print $4}' | "
                f"grep -Eq ':{candidate}$') || "
                "(docker ps --format '{{.Ports}}' 2>/dev/null | "
                f"grep -Eq '(^|[^0-9]){candidate}->')"
            )
            if code != 0 and candidate not in locally_reserved and (candidate == preferred or candidate not in used):
                return candidate
            candidate += 1
    raise RuntimeError("目标服务器内网实例端口池已被占满")


def platform_gateway_node(db) -> Node | None:
    for candidate in db.scalars(select(Node).where(Node.enabled.is_(True))).all():
        address = (candidate.public_address or "").strip()
        try:
            if address and not ipaddress.ip_address(address).is_private:
                return candidate
        except ValueError:
            if address:
                return candidate
    return None


def configure_platform_gateway(
    db, deployment: Deployment, target_node: Node, target_port: int, domain: str | None = None,
    http_port: int = 80, https_enabled: bool = False, https_port: int = 443,
    redirect_https: bool = True, certificate: str | None = None, private_key: str | None = None,
    upstreams: list[tuple[str, int]] | None = None, strategy: str = "round_robin",
    route_groups: list[dict] | None = None,
) -> str:
    # Domain settings can be changed while a deployment is finishing. Serialize
    # all gateway writes for the same project across API and worker processes,
    # then refresh the authoritative settings so an older deployment cannot
    # overwrite a newer HTTPS/domain choice.
    db.execute(text("SELECT pg_advisory_xact_lock(hashtext(:key))"), {"key": f"gateway:{deployment.project_id}"})
    db.flush()
    db.expire_all()
    current_project = db.get(Project, deployment.project_id)
    current_domain = db.get(ProjectDomainConfig, deployment.project_id)
    if current_project:
        domain = current_project.domain
    if current_domain:
        http_port = current_domain.http_port
        https_enabled = current_domain.https_enabled
        https_port = current_domain.https_port
        redirect_https = current_domain.redirect_https
        certificate = decrypt(current_domain.certificate_encrypted)
        private_key = decrypt(current_domain.private_key_encrypted)
        if current_domain.gateway_mode == "custom":
            try:
                saved_routes = json.loads(current_domain.custom_routes_json or "[]")
            except Exception:
                saved_routes = []
            automatic = {str(group.get("name") or ""): group for group in (route_groups or [])}
            custom_groups: dict[str, dict] = {}
            for route in saved_routes:
                service = str(route.get("service") or "")
                source_group = automatic.get(service)
                if not source_group:
                    raise RuntimeError(f"自定义网关路由引用了不存在的运行服务：{service}")
                group = custom_groups.setdefault(service, {
                    "name": service, "targets": source_group.get("targets") or [],
                    "strategy": source_group.get("strategy") or strategy, "paths": [],
                })
                group["paths"].append({"path": route.get("path") or "/", "strip_prefix": bool(route.get("strip_prefix", False))})
            if custom_groups:
                route_groups = list(custom_groups.values())
    gateway = platform_gateway_node(db)
    if not gateway:
        return f"http://{target_node.public_address or target_node.host}:{target_port}"
    service_key = f"project-{deployment.project_id}"
    policy = db.get(DeploymentSettings, "default")
    port_start = policy.external_port_start if policy else 20000
    port_end = policy.external_port_end if policy else 21000
    previous_service = db.scalar(
        select(Deployment).where(
            Deployment.project_id == deployment.project_id,
            Deployment.id != deployment.id,
            Deployment.access_url.is_not(None),
        ).order_by(Deployment.created_at.desc())
    )
    previous_match = re.search(r":(\d+)(?:/|$)", previous_service.access_url or "") if previous_service else None
    service_port = int(previous_match.group(1)) if previous_match else None
    used = set()
    for value in db.scalars(select(Deployment.access_url).where(
        Deployment.access_url.is_not(None),
        Deployment.id != deployment.id,
        Deployment.project_id != deployment.project_id,
    )).all():
        match = re.search(r":(\d+)(?:/|$)", value or "")
        if match:
            used.add(int(match.group(1)))
    # Ports already used by applications hosted on the gateway cannot also be
    # bound by Nginx. Remote-node internal ports do not conflict here.
    used.update(x for x in db.scalars(select(Deployment.host_port).where(Deployment.node_id == gateway.id, Deployment.status.in_([DeployStatus.queued, DeployStatus.running, DeployStatus.success]))).all() if x)
    current_match = re.search(r":(\d+)(?:/|$)", deployment.access_url or "")
    current_port = int(current_match.group(1)) if current_match else None
    # Domain-based public URLs do not contain the private listener used by the
    # platform gateway.  Treat the generated Nginx files as the authoritative
    # allocation ledger as well, otherwise every domain project appears to be
    # free to reuse the same first port and Nginx silently ignores one server.
    gateway_listener_owners: dict[int, set[str]] = {}
    own_gateway_port: int | None = None
    try:
        with SSHNode(gateway) as allocation_ssh:
            _, listener_text = allocation_ssh.run(
                "grep -H -E '^[[:space:]]*listen[[:space:]]+[0-9]+;' "
                "/data/yunzhou-control/data/gateway/conf.d/project-*.conf 2>/dev/null || true",
                timeout=15,
            )
        for row in listener_text.splitlines():
            match = re.match(r"^([^:]+):\s*listen\s+(\d+);", row.strip())
            if not match:
                continue
            filename, listener = match.group(1), int(match.group(2))
            if port_start <= listener <= port_end:
                gateway_listener_owners.setdefault(listener, set()).add(filename)
                if filename.endswith(f"/{service_key}.conf"):
                    own_gateway_port = listener
        used.update(gateway_listener_owners)
    except Exception:
        # Database reservations still provide a safe fallback when the gateway
        # is temporarily unavailable; the final nginx -t remains authoritative.
        pass
    own_is_unique = bool(
        own_gateway_port
        and len(gateway_listener_owners.get(own_gateway_port, set())) == 1
    )
    fallback_reusable = current_port or service_port
    if fallback_reusable in gateway_listener_owners and not own_is_unique:
        fallback_reusable = None
    reusable_port = own_gateway_port if own_is_unique else fallback_reusable
    gateway_port = reusable_port if reusable_port and port_start <= reusable_port <= port_end and reusable_port != target_port else next((port for port in range(port_start, port_end + 1) if port not in used and port != target_port), None)
    if not gateway_port:
        raise RuntimeError("平台网关没有可用映射端口")
    domain = (domain or "").strip().lower()
    if domain and not re.fullmatch(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", domain):
        raise RuntimeError("域名格式不正确")
    targets = upstreams or [(target_node.host, target_port)]
    targets = list(dict.fromkeys((str(host), int(port)) for host, port in targets if host and port))

    def strategy_directive(value: str) -> str:
        return "    least_conn;\n" if value == "least_conn" else ("    ip_hash;\n" if value == "ip_hash" else "")

    read_timeout = int(current_domain.proxy_read_timeout if current_domain else 300)
    body_size_mb = int(current_domain.client_max_body_mb if current_domain else 50)

    def location_proxy(path: str, proxy_target: str, target_count: int, strip_prefix: bool = False) -> str:
        normalized = "/" + str(path or "/").lstrip("/")
        if normalized != "/" and not normalized.endswith("/"):
            normalized += "/"
        # A trailing slash on proxy_pass strips the matched location prefix.
        suffix = "/" if strip_prefix and normalized != "/" else ""
        return f"""    location {normalized} {{
        proxy_pass {proxy_target}{suffix};
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_connect_timeout 2s;
        proxy_next_upstream error timeout invalid_header http_500 http_502 http_503 http_504;
        proxy_next_upstream_tries {max(2, target_count)};
        proxy_read_timeout {read_timeout}s;
        proxy_send_timeout {read_timeout}s;
    }}"""

    upstream_blocks: list[str] = []
    locations: list[tuple[str, str]] = []
    normalized_groups = route_groups or [{
        "name": "entry", "path": "/", "targets": targets,
        "strategy": strategy, "strip_prefix": False,
    }]
    for index, group in enumerate(normalized_groups):
        group_targets = list(dict.fromkeys(
            (str(host), int(port)) for host, port in (group.get("targets") or []) if host and port
        ))
        if not group_targets:
            continue
        group_key = re.sub(r"[^a-zA-Z0-9_]", "_", str(group.get("name") or f"route_{index}"))
        upstream_name = "yunzhou_" + re.sub(r"[^a-zA-Z0-9_]", "_", deployment.project_id) + "_" + group_key
        proxy_target = f"http://{group_targets[0][0]}:{group_targets[0][1]}"
        if len(group_targets) > 1:
            servers = "\n".join(
                f"    server {host}:{port} max_fails=1 fail_timeout=3s;" for host, port in group_targets
            )
            upstream_blocks.append(
                f"upstream {upstream_name} {{\n{strategy_directive(str(group.get('strategy') or strategy))}{servers}\n}}"
            )
            proxy_target = f"http://{upstream_name}"
        paths = group.get("paths") or [group.get("path") or "/"]
        for route_path in paths:
            if isinstance(route_path, dict):
                path = str(route_path.get("path") or "/")
                strip = bool(route_path.get("strip_prefix", group.get("strip_prefix", False)))
            else:
                path = str(route_path or "/")
                strip = bool(group.get("strip_prefix", False))
            locations.append((path, location_proxy(path, proxy_target, len(group_targets), strip)))
    if not locations:
        raise RuntimeError("平台网关没有可用的路由目标")
    # Nginx uses the longest prefix automatically, but sorting also makes the
    # generated configuration easy to audit and keeps the catch-all last.
    unique_locations: dict[str, str] = {}
    for path, block in locations:
        unique_locations.setdefault(path, block)
    locations = list(unique_locations.items())
    locations.sort(key=lambda item: (item[0] == "/", -len(item[0])))
    upstream_block = ("\n".join(upstream_blocks) + "\n") if upstream_blocks else ""
    proxy_block = "\n".join(block for _, block in locations)
    security_block = """    server_tokens off;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
"""
    security_block += f"    client_max_body_size {body_size_mb}m;\n"
    gateway_config = f"""{upstream_block}server {{
    listen {gateway_port};
    server_name _;
{security_block}
{proxy_block}
}}
"""
    config = ""
    if domain:
        if https_enabled:
            if not certificate or not private_key:
                raise RuntimeError("启用 SSL 时必须上传证书和私钥")
            # Domain HTTPS can be toggled by the user. A permanent 301 is cached by
            # browsers and keeps forcing HTTPS even after the setting is disabled.
            # Use a method-preserving temporary redirect and explicitly forbid cache.
            http_action = (
                f"    add_header Cache-Control \"no-store, no-cache, must-revalidate\" always;\n"
                f"    return 307 https://$host{(':' + str(https_port)) if https_port != 443 else ''}$request_uri;"
                if redirect_https else proxy_block
            )
            config += f"""server {{
    listen {http_port};
    server_name {domain};
{security_block}
{http_action}
}}
server {{
    listen {https_port} ssl;
    server_name {domain};
    ssl_certificate /etc/nginx/certs/{service_key}.crt;
    ssl_certificate_key /etc/nginx/certs/{service_key}.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_timeout 1d;
    ssl_session_cache shared:YunzhouTLS:10m;
    ssl_session_tickets off;
{security_block}
{proxy_block}
}}
"""
        else:
            config += f"""server {{
    listen {http_port};
    server_name {domain};
{security_block}
{proxy_block}
}}
"""
    config += gateway_config
    encoded = base64.b64encode(config.encode()).decode()
    filename = f"/data/yunzhou-control/data/gateway/conf.d/{service_key}.conf"
    legacy_ids = db.scalars(select(Deployment.id).where(
        Deployment.project_id == deployment.project_id,
        Deployment.id != deployment.id,
    )).all()
    legacy_files = [f"/data/yunzhou-control/data/gateway/conf.d/{item_id}.conf" for item_id in legacy_ids]
    with SSHNode(gateway) as ssh:
        cert_commands = ""
        if https_enabled:
            cert64 = base64.b64encode(certificate.encode()).decode()
            key64 = base64.b64encode(private_key.encode()).decode()
            cert_path = f"/data/yunzhou-control/data/gateway/certs/{service_key}.crt"
            key_path = f"/data/yunzhou-control/data/gateway/certs/{service_key}.key"
            cert_commands = (
                f"printf %s {shlex.quote(cert64)} | base64 -d > {cert_path}.tmp; "
                f"printf %s {shlex.quote(key64)} | base64 -d > {key_path}.tmp; chmod 600 {key_path}.tmp; "
                f"openssl x509 -in {cert_path}.tmp -noout >/dev/null && openssl pkey -in {key_path}.tmp -noout >/dev/null && "
                f"test \"$(openssl x509 -in {cert_path}.tmp -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum | cut -d' ' -f1)\" = \"$(openssl pkey -in {key_path}.tmp -pubout -outform DER | sha256sum | cut -d' ' -f1)\" || exit 42; "
                f"mv {cert_path}.tmp {cert_path}; mv {key_path}.tmp {key_path}; "
            )
        hide_legacy = " ".join(
            f"[ ! -f {shlex.quote(path)} ] || mv {shlex.quote(path)} {shlex.quote(path + '.service-bak')};"
            for path in legacy_files
        )
        restore_legacy = " ".join(
            f"[ ! -f {shlex.quote(path + '.service-bak')} ] || mv {shlex.quote(path + '.service-bak')} {shlex.quote(path)};"
            for path in legacy_files
        )
        remove_legacy_backups = " ".join(f"rm -f {shlex.quote(path + '.service-bak')};" for path in legacy_files)
        command = (
            "mkdir -p /data/yunzhou-control/data/gateway/conf.d /data/yunzhou-control/data/gateway/certs; " + cert_commands +
            hide_legacy +
            f"cp {shlex.quote(filename)} {shlex.quote(filename)}.bak 2>/dev/null || true; "
            f"printf %s {shlex.quote(encoded)} | base64 -d > {shlex.quote(filename)}; "
            "if docker ps -a --format '{{.Names}}' | grep -qx yunzhou-platform-gateway && "
            "docker inspect yunzhou-platform-gateway --format '{{range .Mounts}}{{println .Source}}{{end}}' | grep -qx /data/yunzhou-control/data/gateway/certs && "
            "docker inspect yunzhou-platform-gateway --format '{{.Config.Image}}' | grep -qx nginx:1.30.6-alpine; then "
            "docker start yunzhou-platform-gateway >/dev/null 2>&1 || true; "
            "else docker rm -f yunzhou-platform-gateway >/dev/null 2>&1 || true; docker run -d --name yunzhou-platform-gateway --restart unless-stopped --network host "
            "-v /data/yunzhou-control/data/gateway/conf.d:/etc/nginx/conf.d:ro -v /data/yunzhou-control/data/gateway/certs:/etc/nginx/certs:ro nginx:1.30.6-alpine >/dev/null; fi; "
            "if ! docker exec yunzhou-platform-gateway nginx -t; then "
            f"test -f {shlex.quote(filename)}.bak && mv {shlex.quote(filename)}.bak {shlex.quote(filename)} || rm -f {shlex.quote(filename)}; "
            + restore_legacy + " exit 43; fi; "
            + remove_legacy_backups +
            f"rm -f {shlex.quote(filename)}.bak; docker exec yunzhou-platform-gateway nginx -s reload"
        )
        code, output = ssh.run(command, timeout=60)
        if code:
            if code == 42:
                raise RuntimeError("SSL 证书与私钥不匹配")
            raise RuntimeError("平台网关配置失败：" + output)
        code, output = ssh.run(f"curl -sS -o /dev/null --max-time 8 http://127.0.0.1:{gateway_port}/")
        if code:
            raise RuntimeError("平台网关映射后无法访问源站：" + output)
    if domain:
        scheme, port = ("https", https_port) if https_enabled else ("http", http_port)
        default_port = 443 if scheme == "https" else 80
        return f"{scheme}://{domain}{':' + str(port) if port != default_port else ''}"
    return f"http://{gateway.public_address or gateway.host}:{gateway_port}"


def ai_checkpoint(deployment_id: str, stage: str, evidence: str) -> None:
    """Run the AI observer beside the deployment so AI latency never blocks it."""
    def follow():
        try:
            with SessionLocal() as db:
                dep = db.get(Deployment, deployment_id)
                if not dep:
                    return
                result = deployment_followup(db, dep, db.get(Project, dep.project_id), db.get(Node, dep.node_id), stage, evidence[-5000:])
                result.update({"stage": stage, "status": dep.status.value, "generated_at": datetime.now(timezone.utc).isoformat()})
                log(deployment_id, "[AI跟进] " + json.dumps(result, ensure_ascii=False) + "\n")
        except Exception as exc:
            log(deployment_id, "[AI跟进] " + json.dumps({"source": "system", "stage": stage, "summary": "AI 分析暂时不可用，部署继续执行。", "advice": str(exc)[:300]}, ensure_ascii=False) + "\n")
    threading.Thread(target=follow, name=f"ai-follow-{deployment_id[:8]}", daemon=True).start()


def verify_access(db, deployment_id: str, access_url: str) -> None:
    """Do not mark a deployment complete until its public entry is reachable."""
    gateway = platform_gateway_node(db)
    if not gateway:
        raise RuntimeError("没有可用于访问验证的平台网关节点")
    last_output = ""
    ai_checkpoint(deployment_id, "验证访问地址", f"开始持续验证 {access_url}")
    parsed = urlsplit(access_url)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    # Public-IP hairpin is commonly disabled by routers. Test the exact gateway
    # listener locally while preserving the public Host header and request path.
    if parsed.scheme == "https":
        curl_target = access_url
        route_args = f"--resolve {shlex.quote(parsed.hostname + ':' + str(port) + ':127.0.0.1')}"
    else:
        curl_target = f"http://127.0.0.1:{port}{path}"
        host_header = parsed.hostname + ((":" + str(port)) if port != 80 else "")
        route_args = f"-H {shlex.quote('Host: ' + host_header)}"

    def collect_diagnostics() -> str:
        try:
            dep = db.get(Deployment, deployment_id)
            project = db.get(Project, dep.project_id) if dep else None
            node = db.get(Node, dep.node_id) if dep else None
            if not dep or not project or not node:
                return ""
            compose_project = shlex.quote("yz-" + project.slug)
            direct_path = shlex.quote(path)
            with SSHNode(node) as node_ssh:
                _, text = node_ssh.run(
                    f"echo '--- 节点直连 ---'; curl -i -sS --max-time 8 http://127.0.0.1:{int(dep.host_port or 0)}{direct_path} | head -40; "
                    "echo '--- 端口监听 ---'; ss -lntp 2>/dev/null | grep -E ':" + str(int(dep.host_port or 0)) + "\\b' || true; "
                    "ids=$( { docker ps -aq --filter label=com.docker.compose.project=" + compose_project + "; "
                    "docker ps -aq --filter name=" + shlex.quote(project.slug) + "; "
                    "docker ps -q --filter publish=" + str(int(dep.host_port or 0)) + "; } | sort -u); "
                    "echo '--- 容器状态 ---'; for id in $ids; do docker inspect -f '{{.Name}} {{.State.Status}} {{.RestartCount}} {{json .NetworkSettings.Ports}}' $id; done; "
                    "echo '--- 容器日志 ---'; for id in $ids; do "
                    "echo \"### $(docker inspect -f '{{.Name}}' $id | sed 's#^/##')\"; docker logs --tail 200 $id 2>&1; done",
                    timeout=90,
                )
            return text
        except Exception as exc:
            log(deployment_id, f"[访问诊断] 诊断采集失败：{exc}\n")
            return ""

    max_attempts = 6
    with SSHNode(gateway) as gateway_ssh:
        attempt = 0
        while attempt < max_attempts:
            attempt += 1
            ensure_active(deployment_id)
            code, output = gateway_ssh.run(
                "curl -L -sS -o /dev/null --connect-timeout 4 --max-time 10 "
                f"{route_args} -w '%{{http_code}}' {shlex.quote(curl_target)}"
            )
            status = output.strip()[-3:] if output.strip() else "000"
            # A missing route is not a successful application verification.
            # Protected endpoints may legitimately answer 401/403; otherwise
            # require a normal success or redirect response.
            accepted = status.isdigit() and (200 <= int(status) < 400 or int(status) in {401, 403})
            if code == 0 and accepted:
                qualifier = "（服务可达，需要鉴权）" if int(status) in {401, 403} else ""
                log(deployment_id, f"[检查] 第 {attempt} 次访问验证通过：HTTP {status}{qualifier} · {access_url}\n")
                ai_checkpoint(deployment_id, "验证访问地址", f"访问验证通过：HTTP {status}{qualifier}，地址 {access_url}")
                return
            last_output = output.strip() or f"curl exit={code}, HTTP {status}"
            log(deployment_id, f"[检查] 第 {attempt}/{max_attempts} 次访问尚未就绪：{last_output[-300:]}\n")
            if attempt in (2, 4, 6):
                diagnostic_text = collect_diagnostics()
                fatal_markers = (
                    "application run failed", "could not resolve placeholder",
                    "failed to start web server", "exception encountered during context initialization",
                    "exec format error",
                )
                if diagnostic_text and any(marker in diagnostic_text.lower() for marker in fatal_markers):
                    log(deployment_id, "[访问诊断] 已发现确定性启动错误，停止无意义的重复 HTTP 检查。\n")
                    ai_checkpoint(deployment_id, "访问失败诊断", diagnostic_text[-5000:])
                    raise RuntimeError(
                        "服务启动日志已出现确定性错误，访问验证提前停止：\n" + diagnostic_text[-10000:]
                    )
                ai_checkpoint(deployment_id, "验证访问地址", f"第 {attempt} 次仍不可访问：{last_output[-1200:]}")
            if attempt < max_attempts:
                time.sleep(15)
    # Preserve the evidence before the failed release is cleaned. Without the
    # application logs, an HTTP 502 only tells the AI that the gateway could
    # not connect and leads to blind retries.
    diagnostic_text = collect_diagnostics()
    if diagnostic_text:
        log(deployment_id, "[访问诊断] 清理前已采集节点直连、端口监听和容器日志：\n" + diagnostic_text[-24000:] + "\n")
        ai_checkpoint(deployment_id, "访问失败诊断", diagnostic_text[-5000:])
    evidence = ("；清理前诊断：\n" + diagnostic_text[-10000:]) if diagnostic_text else ""
    raise RuntimeError(f"服务已启动，但按每 15 秒一次、共 {attempt} 次的规则验证后仍不可访问：{last_output}{evidence}")


def node_platform(node: Node) -> str:
    with SSHNode(node) as ssh:
        code, output = ssh.run("uname -m", timeout=20)
    if code:
        raise RuntimeError("无法识别目标服务器 CPU 架构：" + output)
    machine = output.strip().lower()
    return "linux/arm64" if machine in {"aarch64", "arm64"} else "linux/amd64"


def _service_container_name(project_slug: str, service_name: str, sequence: int = 1) -> str:
    safe_service = re.sub(r"[^a-z0-9-]", "-", str(service_name).lower()).strip("-") or "app"
    return f"yz-{project_slug}-{safe_service}-{max(1, int(sequence))}"


def _project_traffic_plan(project: Project, deployment_plan: dict | None = None) -> dict:
    """Return the versioned traffic plan saved by source analysis."""
    candidates = [deployment_plan, project.source_analysis]
    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue
        nested = candidate.get("traffic_plan")
        if isinstance(nested, dict):
            return nested
        saved = candidate.get("deployment_plan")
        if isinstance(saved, dict) and isinstance(saved.get("traffic_plan"), dict):
            return saved["traffic_plan"]
    return {}


def _traffic_service_roles(traffic_plan: dict) -> dict[str, tuple[str, bool]]:
    roles: dict[str, tuple[str, bool]] = {}
    for row in traffic_plan.get("service_roles") or []:
        if not isinstance(row, dict):
            continue
        service = str(row.get("service") or "").strip()
        role = str(row.get("role") or "app").strip().lower()
        if service:
            roles[service] = (role, bool(row.get("scalable", role in {"frontend", "backend", "app", "web", "api"})))
    return roles


def _compose_port_number(value) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if 1 <= value <= 65535 else None
    raw = str(value or "").strip().split("/", 1)[0]
    # Compose short syntax is [ip:][published:]target. The last component is
    # always the container-side target port.
    target = raw.rsplit(":", 1)[-1]
    match = re.search(r"(\d{1,5})$", target)
    port = int(match.group(1)) if match else None
    return port if port and 1 <= port <= 65535 else None


def _compose_service_container_port(root: Path, service: dict) -> int | None:
    for mapping in service.get("ports") or []:
        port = _compose_port_number(mapping.get("target") if isinstance(mapping, dict) else mapping)
        if port:
            return port
    for exposed in service.get("expose") or []:
        port = _compose_port_number(exposed)
        if port:
            return port
    environment = service.get("environment") or {}
    if isinstance(environment, list):
        environment = dict(
            str(value).split("=", 1) for value in environment
            if isinstance(value, str) and "=" in value
        )
    if isinstance(environment, dict):
        for key in ("SERVER_PORT", "PORT"):
            port = _compose_port_number(environment.get(key))
            if port:
                return port
    build = service.get("build")
    if build:
        build_spec = build if isinstance(build, dict) else {"context": build}
        inline = str(build_spec.get("dockerfile_inline") or "")
        match = re.search(r"(?im)^\s*EXPOSE\s+(\d{1,5})(?:/tcp)?\s*$", inline)
        if match:
            return int(match.group(1))
        context = (root / str(build_spec.get("context") or ".")).resolve()
        dockerfile = (context / str(build_spec.get("dockerfile") or "Dockerfile")).resolve()
        if dockerfile.is_file() and (dockerfile == root or root in dockerfile.parents):
            text_value = dockerfile.read_text(encoding="utf-8", errors="ignore")
            matches = re.findall(r"(?im)^\s*EXPOSE\s+(\d{1,5})(?:/tcp)?\s*$", text_value)
            if matches:
                return int(matches[-1])
    return None


def _compose_route_groups(project: Project, service_targets: dict[str, list[tuple[str, int]]], deployment_plan: dict | None = None) -> list[dict]:
    traffic_plan = _project_traffic_plan(project, deployment_plan)
    roles = _traffic_service_roles(traffic_plan)
    routes = traffic_plan.get("traffic_routes") or traffic_plan.get("routes") or []
    default_service = str(traffic_plan.get("default_service") or traffic_plan.get("entry_service") or "")
    if not default_service:
        default_service = next((name for name, (role, _) in roles.items() if role == "frontend" and name in service_targets), "")
    if not default_service:
        default_service = next(iter(service_targets), "")
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
    groups = []
    for service, paths in paths_by_service.items():
        unique_paths = list({(row["path"], row["strip_prefix"]): row for row in paths}.values())
        groups.append({
            "name": service,
            "paths": unique_paths,
            "targets": service_targets[service],
            "strategy": project.load_balance_strategy,
        })
    return groups


def prepare_compose_image_override(
    work: str, build_file: str, project: Project, release: str, platform: str, node: Node,
    db=None, primary_host_port: int | None = None, deployment_plan: dict | None = None,
) -> tuple[str | None, list[str]]:
    path = Path(work) / build_file
    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8", errors="ignore")) or {}
    except Exception as exc:
        raise RuntimeError(f"Compose 文件无法解析：{exc}")
    services = {}
    images = []
    build_groups: dict[str, str] = {}
    compose_changed = False
    root = Path(work)
    traffic_plan = _project_traffic_plan(project, deployment_plan)
    service_roles = _traffic_service_roles(traffic_plan)
    routed_services = {
        str(route.get("service") or route.get("target_service") or "").strip()
        for route in (traffic_plan.get("traffic_routes") or traffic_plan.get("routes") or [])
        if isinstance(route, dict)
    }
    routed_services.discard("")
    for service_name, (role, scalable) in service_roles.items():
        if scalable and role in {"frontend", "backend", "app", "web", "api"}:
            routed_services.add(service_name)
    default_service = str(traffic_plan.get("default_service") or traffic_plan.get("entry_service") or "").strip()
    if default_service:
        routed_services.add(default_service)
    reserved_ports = {int(primary_host_port)} if primary_host_port else set()
    # A common Java + Vue layout can be compiled in short-lived toolchain
    # containers with host-mounted package caches.  The release images then
    # receive only dist/JAR artifacts, so deleting an application image does
    # not discard Maven or pnpm downloads and the Docker context stays small.
    mounted_wms_build = (
        (root / "WMSCloud_ui/package.json").is_file()
        and (root / "WMSCloud/pom.xml").is_file()
        and (root / "WMSCloud_ui/containers/nginx.conf").is_file()
    )
    if mounted_wms_build:
        java_log_dirs = detect_java_log_directories(root / "WMSCloud")
        java_log_setup = ""
        if java_log_dirs:
            quoted_dirs = " ".join(shlex.quote(value) for value in java_log_dirs)
            java_log_setup = f"RUN mkdir -p {quoted_dirs} && chmod 0777 {quoted_dirs}\n"
        (root / "WMSCloud_ui/.yunzhou.runtime.Dockerfile").write_text(
            "FROM nginx:1.23.3-alpine\n"
            "COPY containers/nginx.conf /etc/nginx/nginx.conf\n"
            "COPY dist/ /etc/nginx/html/\n"
            "EXPOSE 80\n",
            encoding="utf-8",
        )
        (root / "WMSCloud_ui/.dockerignore").write_text(
            "*\n!dist\n!dist/**\n!containers\n!containers/nginx.conf\n!.yunzhou.runtime.Dockerfile\n",
            encoding="utf-8",
        )
        (root / "WMSCloud/ruoyi-admin/.yunzhou.runtime.Dockerfile").write_text(
            "FROM eclipse-temurin:8-jre\n"
            + java_log_setup
            + "WORKDIR /app\n"
            "COPY target/ruoyi-admin.jar /app/app.jar\n"
            "EXPOSE 8080\n"
            "ENTRYPOINT [\"java\", \"-jar\", \"/app/app.jar\"]\n",
            encoding="utf-8",
        )
        (root / "WMSCloud/ruoyi-admin/.dockerignore").write_text(
            "*\n!target\n!target/ruoyi-admin.jar\n!.yunzhou.runtime.Dockerfile\n",
            encoding="utf-8",
        )
    for service_name, service in (document.get("services") or {}).items():
        if not isinstance(service, dict):
            continue
        # Runtime time is a platform invariant. Apply it to application and
        # dependency containers alike, while Compose's map merge keeps an
        # explicit project-level TZ value authoritative. Mounting the host's
        # zone file also fixes minimal images (for example nginx/alpine) that
        # do not ship the IANA tzdata database.
        services[service_name] = {
            "environment": {"TZ": "Asia/Shanghai"},
            "volumes": ["/etc/localtime:/etc/localtime:ro"],
            # Compose owns the primary instance for every service. Keep its
            # name stable across releases; manually scaled instances continue
            # with -2, -3, ... and can therefore be reconciled predictably.
            "container_name": _service_container_name(project.slug, service_name, 1),
        }
        # The platform gateway runs outside the Compose network. Every routed
        # or independently scalable application therefore needs one host-side
        # port even when the repository intentionally declares only `expose`.
        # Keep source Compose untouched and publish it solely in our generated
        # override so users do not have to add infrastructure details to code.
        if service_name in routed_services and not (service.get("ports") or []):
            container_target = _compose_service_container_port(root, service)
            if not container_target:
                raise RuntimeError(f"无法确认入口服务 {service_name} 的容器端口；请在 Compose 中声明 expose 或在镜像 Dockerfile 中声明 EXPOSE")
            if db is None:
                raise RuntimeError(f"入口服务 {service_name} 缺少宿主端口，平台无法在无数据库上下文时安全分配")
            published = choose_node_port(db, node, None, reserved=reserved_ports)
            reserved_ports.add(published)
            services[service_name]["ports"] = [f"{published}:{container_target}"]
        if not service.get("build"):
            continue
        original_build = service.get("build")
        # Compose files generated for monorepos often point several runtime
        # services at the exact same build and image. Building each service
        # separately makes BuildKit export the same large dependency layer N
        # times. Keep one build owner and let the remaining services reuse its
        # immutable release image.
        group_key = json.dumps(
            {"build": original_build, "image": service.get("image")},
            ensure_ascii=False,
            sort_keys=True,
            default=str,
        )
        if group_key in build_groups:
            services[service_name].update({"image": build_groups[group_key], "build": None})
            continue
        safe_service = re.sub(r"[^a-z0-9_.-]+", "-", str(service_name).lower()).strip("-.") or "app"
        image = f"yunzhou/{project.slug}-{safe_service}:{release}"
        build_groups[group_key] = image
        build_override = dict(original_build) if isinstance(original_build, dict) else {"context": str(original_build or ".")}
        # Classic Docker build cache is daemon-wide and already shared by all
        # projects. Do not create project-local Buildx cache directories.
        build_override.pop("cache_from", None)
        build_override.pop("cache_to", None)
        if mounted_wms_build:
            target = str(build_override.get("target") or "").lower()
            if "web" in target or any(token in str(service_name).lower() for token in ("web", "front", "ui")):
                build_override = {
                    "context": "./WMSCloud_ui", "dockerfile": ".yunzhou.runtime.Dockerfile",
                    "dockerfile_inline": None, "target": None,
                }
            elif any(token in target for token in ("backend", "api")) or "api" in str(service_name).lower():
                build_override = {
                    "context": "./WMSCloud/ruoyi-admin", "dockerfile": ".yunzhou.runtime.Dockerfile",
                    "dockerfile_inline": None, "target": None,
                }
                # Keep the application contract stable inside the Compose
                # network. The host/gateway port remains dynamically assigned;
                # Spring always listens on 8080 inside its own container.
                services[service_name]["environment"]["SERVER_PORT"] = "8080"
            # Compose merges nested build objects. An override cannot reliably
            # remove an old ``target``/``dockerfile_inline`` inherited from the
            # source Compose file, so write the clean runtime build definition
            # into the staged copy as well. This copy is release-local and does
            # not modify the user's repository.
            if build_override.get("context") in {"./WMSCloud_ui", "./WMSCloud/ruoyi-admin"}:
                clean_build = {
                    "context": build_override["context"],
                    "dockerfile": build_override["dockerfile"],
                }
                service["build"] = clean_build
                build_override = clean_build
                compose_changed = True
        services[service_name].update({"image": image, "build": build_override})
        images.append(image)
    if not services:
        return None, []
    if compose_changed:
        path.write_text(yaml.safe_dump(document, allow_unicode=True, sort_keys=False), encoding="utf-8")
    override_name = ".yunzhou.images.yml"
    (Path(work) / override_name).write_text(yaml.safe_dump({"services": services}, allow_unicode=True, sort_keys=False), encoding="utf-8")
    return override_name, images


def remote_compose_files(ssh: SSHNode, directory: str) -> list[str]:
    """Return the main Compose file plus Yunzhou's generated image override."""
    # ``.yunzhou.compose.yml`` and ``.yunzhou.ai.compose.yml`` are valid main
    # files generated by the platform. Only ``.yunzhou.images.yml`` is an
    # override and it is intentionally not part of COMPOSE_NAMES.
    main = next((name for name in COMPOSE_NAMES if ssh.run(
        f"test -f {shlex.quote(directory + '/' + name)}"
    )[0] == 0), None)
    if not main:
        return []
    files = [main]
    for override in (".yunzhou.images.yml", ".yunzhou.external-access.yml"):
        if ssh.run(f"test -f {shlex.quote(directory + '/' + override)}")[0] == 0:
            files.append(override)
    return files


def compose_file_args(files: list[str]) -> str:
    return " ".join(f"-f {shlex.quote(name)}" for name in files)


def prepare_runtime_bundle(work: str, build_type: str, build_file: str, compose_override: str | None) -> str:
    bundle = Path(tempfile.mkdtemp(prefix="yunzhou-runtime-"))
    if build_type != "compose":
        return str(bundle)
    root = Path(work).resolve()
    compose_path = (root / build_file).resolve()
    compose_base = compose_path.parent

    def copy_runtime_path(value: str, base: Path = compose_base) -> None:
        raw = str(value or "").strip()
        if not raw or raw.startswith("/"):
            return
        source = (base / raw).resolve()
        try:
            relative = source.relative_to(root)
        except ValueError:
            return
        if not source.exists():
            return
        target = bundle / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if source.is_dir():
            shutil.copytree(source, target, dirs_exist_ok=True)
        else:
            shutil.copy2(source, target)

    copy_runtime_path(build_file, root)
    if compose_override:
        copy_runtime_path(compose_override, root)
    document = yaml.safe_load(compose_path.read_text(encoding="utf-8", errors="ignore")) or {}
    for service in (document.get("services") or {}).values():
        if not isinstance(service, dict):
            continue
        env_files = service.get("env_file") or []
        if isinstance(env_files, (str, dict)):
            env_files = [env_files]
        for entry in env_files:
            copy_runtime_path(entry.get("path") if isinstance(entry, dict) else entry)
        for volume in service.get("volumes") or []:
            source = volume.get("source") if isinstance(volume, dict) else str(volume).split(":", 1)[0]
            if source and (str(source).startswith(".") or "/" in str(source)):
                copy_runtime_path(str(source))
    for section in ("configs", "secrets"):
        for config in (document.get(section) or {}).values():
            if isinstance(config, dict) and config.get("file"):
                copy_runtime_path(str(config["file"]))
    return str(bundle)


def central_build_and_distribute(
    db, deployment: Deployment, project: Project, target: Node, work: str,
    build_type: str, build_file: str, release: str, image_name: str | None,
    compose_override: str | None, built_images: list[str], platform: str, stream,
) -> Node:
    builder = platform_gateway_node(db)
    if not builder:
        raise RuntimeError("未配置平台构建服务器，无法执行统一构建")
    builder_root = f"{settings.build_data_root.rstrip('/')}/builder"
    # The worker and the platform builder share /data/yunzhou. Build directly
    # from the project's single fixed checkout instead of uploading a second
    # full copy for every release.
    builder_dir = work
    archive = f"/tmp/yunzhou-images-{deployment.id}.tar.gz"
    images = built_images if build_type == "compose" else [image_name]
    images = [value for value in images if value]
    if build_type == "compose" and not images:
        log(
            deployment.id,
            "[平台构建] Compose 全部服务均使用固定镜像且没有 build，已跳过 Node/Python/Java 依赖编译与镜像封装。\n",
        )
        return builder
    # Compose validates required ${VAR:?message} substitutions before it even
    # starts an image build. Runtime secrets are irrelevant to that build, so
    # provide safe ephemeral placeholders for every required variable instead
    # of maintaining a fragile hard-coded list (Redis, OIDC, SMTP, etc.).
    required_build_vars: set[str] = set()
    if build_type == "compose":
        for filename in (build_file, compose_override):
            if not filename:
                continue
            candidate = Path(work) / filename
            if not candidate.exists():
                continue
            text = candidate.read_text(encoding="utf-8", errors="ignore")
            required_build_vars.update(re.findall(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::?\?)", text))
    build_env = {
        "YUNZHOU_HOST_PORT": "1",
        "CRM_DB_PASSWORD": "build-placeholder",
        "CRM_DB_ROOT_PASSWORD": "build-placeholder",
        "CRM_JWT_SECRET": "build-placeholder",
        **{key: "build-placeholder" for key in required_build_vars},
    }
    build_env_prefix = " ".join(
        f"{key}={shlex.quote(value)}" for key, value in sorted(build_env.items())
    )
    with SSHNode(builder) as build_ssh:
        build_ssh.run(f"mkdir -p {shlex.quote(builder_dir)}")
        build_policy = db.get(DeploymentSettings, "default")
        cache_root = (build_policy.build_cache_root if build_policy else "") or f"{builder_root}/cache"
        maven_cache_dir = (build_policy.maven_cache_dir if build_policy else "") or "/root/.m2"
        gradle_cache_dir = (build_policy.gradle_cache_dir if build_policy else "") or "/home/gradle/.gradle"
        npm_cache_dir = (build_policy.npm_cache_dir if build_policy else "") or "/root/.npm"
        pnpm_cache_dir = (build_policy.pnpm_cache_dir if build_policy else "") or "/root/.local/share/pnpm/store"
        yarn_cache_dir = (build_policy.yarn_cache_dir if build_policy else "") or "/root/.cache/yarn"
        pip_cache_dir = (build_policy.pip_cache_dir if build_policy else "") or "/root/.cache/pip"
        cache_dirs = " ".join(
            shlex.quote(f"{cache_root}/{name}")
            for name in ("maven", "gradle", "pnpm", "npm", "yarn", "pip")
        )
        code, output = build_ssh.run(f"mkdir -p {cache_dirs}")
        if code:
            raise RuntimeError("公共依赖缓存目录创建失败：" + output[-800:])
        log(
            deployment.id,
            "[构建策略] 使用经典 Docker 构建（BuildKit/Buildx 已关闭）；"
            f"公共依赖缓存位于 {cache_root}/{{maven,gradle,npm,pnpm,yarn,pip}}。\n",
        )

        # Discover dependency manifests recursively instead of assuming that
        # they live at the repository root.  Monorepos commonly keep the real
        # application under ui/, server/, FRCloud/, etc.  Warm every package
        # manager through the same host-mounted cache before the classic
        # Docker build starts.  The warm-up is deliberately best-effort: a
        # source-level dependency error must still be diagnosed by the real
        # build, while successfully downloaded packages remain reusable by
        # later projects and retries.
        source_root = Path(work)
        ignored_parts = {".git", "node_modules", "target", "dist", "build", ".gradle", ".venv"}

        def ensure_context_ignore(context: Path) -> None:
            """Keep dependency/cache trees out of classic Docker contexts."""
            ignore_file = context / ".dockerignore"
            existing = ignore_file.read_text(encoding="utf-8", errors="ignore") if ignore_file.is_file() else ""
            required = (
                ".git", "**/.git", "node_modules", "**/node_modules",
                ".pnpm-store", "**/.pnpm-store",
            )
            lines = existing.splitlines()
            changed = False
            for pattern in required:
                if pattern not in lines:
                    lines.append(pattern)
                    changed = True
            if changed or not ignore_file.is_file():
                ignore_file.write_text("\n".join(lines).strip() + "\n", encoding="utf-8")

        ensure_context_ignore(source_root)
        node_built_contexts: set[str] = set()
        maven_built_contexts: set[str] = set()
        persistent_dependency_root = Path(builder_root) / "projects" / project.slug / "dependencies"

        def source_manifests(name: str) -> list[Path]:
            return sorted(
                path for path in source_root.rglob(name)
                if path.is_file() and not any(part in ignored_parts for part in path.relative_to(source_root).parts)
            )

        node_manifests = source_manifests("package.json")
        for package_file in node_manifests:
            package_dir = package_file.parent
            ensure_context_ignore(package_dir)
            # Old CNPM/Taobao lockfiles pin complete tarball URLs, so changing
            # the package-manager registry alone does not take effect. Repair
            # only the disposable release checkout and record the correction.
            # The user's Git repository and immutable source cache stay intact.
            repaired_lockfiles = []
            legacy_registries = {
                "https://r2.cnpmjs.org/": "https://registry.npmmirror.com/",
                "http://r2.cnpmjs.org/": "https://registry.npmmirror.com/",
                "https://registry.npm.taobao.org/": "https://registry.npmmirror.com/",
                "http://registry.npm.taobao.org/": "https://registry.npmmirror.com/",
                "https://npm.taobao.org/": "https://registry.npmmirror.com/",
                "http://npm.taobao.org/": "https://registry.npmmirror.com/",
            }
            for lock_name in ("yarn.lock", "package-lock.json", "npm-shrinkwrap.json"):
                lock_path = package_dir / lock_name
                if not lock_path.is_file():
                    continue
                original_lock = lock_path.read_text(encoding="utf-8", errors="replace")
                repaired_lock = original_lock
                for old_registry, current_registry in legacy_registries.items():
                    repaired_lock = repaired_lock.replace(old_registry, current_registry)
                if repaired_lock != original_lock:
                    lock_path.write_text(repaired_lock, encoding="utf-8")
                    repaired_lockfiles.append(lock_name)
            if repaired_lockfiles:
                relative_lock_dir = package_dir.relative_to(source_root).as_posix() or "."
                log(
                    deployment.id,
                    "[自动修正] 已在发布副本中更新过期的 npm/yarn 镜像地址："
                    + relative_lock_dir + "/" + "、".join(repaired_lockfiles) + "；源码仓库未改动。\n",
                )
            try:
                package_meta = json.loads(package_file.read_text(encoding="utf-8", errors="replace"))
            except Exception:
                package_meta = {}
            manager_hint = str(package_meta.get("packageManager") or "").lower() if isinstance(package_meta, dict) else ""
            scripts = package_meta.get("scripts") if isinstance(package_meta, dict) else {}
            build_script = isinstance(scripts, dict) and bool(scripts.get("build"))
            # Runtime-only Node services install once in their final Docker
            # build. Do not run a separate dependency warm-up first.
            if not build_script:
                continue
            if (package_dir / "pnpm-lock.yaml").is_file() or manager_hint.startswith("pnpm"):
                manager = "pnpm"
                install = (
                    "corepack enable; corepack prepare pnpm@8.15.9 --activate; "
                    f"pnpm install --store-dir {shlex.quote(pnpm_cache_dir)} --frozen-lockfile" + ("; pnpm run build" if build_script else " --ignore-scripts")
                )
            elif (package_dir / "yarn.lock").is_file() or manager_hint.startswith("yarn"):
                manager = "yarn"
                install = "yarn install --frozen-lockfile" + ("; yarn build" if build_script else " --ignore-scripts")
            else:
                manager = "npm"
                # Keep the checkout's node_modules between releases. npm's
                # tarball cache avoids downloads, but unpacking 2,000+ legacy
                # dependencies still took six minutes on real projects. A
                # lock-aware incremental install reuses the already unpacked
                # tree while the Docker context continues to exclude it.
                install = "npm install --prefer-offline --no-audit --no-fund"
                install += "; npm run build" if build_script else " --ignore-scripts"
            package_text = json.dumps(package_meta, ensure_ascii=False)
            legacy_webpack = bool(
                re.search(r'"(?:webpack|@vue/cli-service)"\s*:\s*"?[~^]?(?:[0-4])(?:\.|"|$)', package_text)
            )
            node_image = "node:16.20.2" if legacy_webpack else "node:20-alpine"
            relative = package_dir.relative_to(source_root).as_posix() or "."
            node_modules_mount = ""
            if manager == "npm":
                # Release checkouts under runs/ are disposable. Keep the
                # unpacked dependency tree in the project's stable workspace
                # and mount it at npm's normal /workspace/node_modules path.
                # A symlink in source-cache makes the retained tree visible to
                # operators without putting it in Git or Docker contexts.
                persistent_modules = persistent_dependency_root / relative / "node_modules"
                persistent_modules.mkdir(parents=True, exist_ok=True)
                visible_modules = Path(builder_root) / "projects" / project.slug / "source-cache" / relative / "node_modules"
                if visible_modules.parent.is_dir() and not visible_modules.exists():
                    try:
                        visible_modules.symlink_to(persistent_modules, target_is_directory=True)
                    except OSError:
                        pass
                node_modules_mount = f"-v {shlex.quote(str(persistent_modules) + ':/workspace/node_modules')} "
            command = (
                f"docker run --rm --label yunzhou.deployment={shlex.quote(deployment.id)} "
                f"-v {shlex.quote(str(package_dir))}:/workspace "
                f"-v {shlex.quote(cache_root + '/pnpm' + ':' + pnpm_cache_dir)} "
                f"-v {shlex.quote(cache_root + '/npm' + ':' + npm_cache_dir)} "
                f"-v {shlex.quote(cache_root + '/yarn' + ':' + yarn_cache_dir)} "
                f"{node_modules_mount}"
                f"-w /workspace {node_image} sh -lc "
                + shlex.quote("set -e; trap 'rm -rf .pnpm-store' EXIT; " + install)
            )
            log(deployment.id, f"[平台构建] {node_image}/{manager}：{relative}，正式构建同时写入公共缓存。\n")
            warm_code, warm_output = tracked_run(
                build_ssh, deployment.id, command, stream=stream, timeout=1200,
                pid_prefix="yunzhou-node-cache",
            )
            if warm_code:
                log(deployment.id, f"[平台构建] {relative} 本次未生成产物，交由项目方案诊断：{warm_output[-500:]}\n")
            else:
                node_built_contexts.add(str(package_dir.resolve()))
                log(deployment.id, f"[平台构建] Node 已使用默认公共缓存生成运行产物：{relative}。\n")
            shutil.rmtree(package_dir / ".pnpm-store", ignore_errors=True)

        generated_dockerfiles = [
            path for path in source_root.rglob(".yunzhou*.Dockerfile") if path.is_file()
        ]
        has_generated_multistage = any(
            len(re.findall(r"(?im)^\s*FROM\s+", path.read_text(encoding="utf-8", errors="ignore"))) > 1
            for path in generated_dockerfiles
        )
        pom_files = source_manifests("pom.xml")
        # A reactor root resolves its child modules itself; avoid repeating the
        # same Maven graph for every nested module.
        reactor_poms = [pom for pom in pom_files if not any(parent / "pom.xml" in pom_files for parent in pom.parents if parent != pom.parent)]
        for pom in reactor_poms:
            if not has_generated_multistage:
                continue
            relative = pom.relative_to(source_root).as_posix()
            command = (
                f"docker run --rm --label yunzhou.deployment={shlex.quote(deployment.id)} "
                f"-v {shlex.quote(str(pom.parent))}:/workspace "
                f"-v {shlex.quote(cache_root + '/maven' + ':' + maven_cache_dir)} "
                "-w /workspace maven:3.9-eclipse-temurin-17 sh -lc "
                + shlex.quote("mvn -B -DskipTests package")
            )
            log(deployment.id, f"[平台构建] Maven：{relative}，正式构建同时写入 {cache_root}/maven。\n")
            maven_code, maven_output = tracked_run(
                build_ssh, deployment.id, command, stream=stream, timeout=1800,
                pid_prefix="yunzhou-maven-build",
            )
            if maven_code:
                log(deployment.id, f"[平台构建] Maven 外置编译未完成，保留原始方案继续诊断：{maven_output[-800:]}\n")
            else:
                maven_built_contexts.add(str(pom.parent.resolve()))
                log(deployment.id, f"[平台构建] Maven 已使用公共缓存 {maven_cache_dir} 生成 JAR：{relative}。\n")

        gradle_roots = sorted({path.parent for name in ("settings.gradle", "settings.gradle.kts", "build.gradle", "build.gradle.kts") for path in source_manifests(name)})
        gradle_roots = [root_path for root_path in gradle_roots if not any(parent in gradle_roots for parent in root_path.parents)]
        for gradle_root in gradle_roots:
            relative = gradle_root.relative_to(source_root).as_posix() or "."
            gradle_entry = "./gradlew" if (gradle_root / "gradlew").is_file() else "gradle"
            gradle_descriptor_text = "\n".join(
                item.read_text(encoding="utf-8", errors="ignore")
                for item in (gradle_root / "build.gradle", gradle_root / "build.gradle.kts")
                if item.is_file()
            )
            generated_gradle_files = [
                item for item in gradle_root.glob(".yunzhou*.Dockerfile")
                if item.is_file() and "gradlew" in item.read_text(encoding="utf-8", errors="ignore")
            ]
            direct_boot_jar = bool(
                generated_gradle_files
                and re.search(r"spring[-.]boot|bootJar", gradle_descriptor_text, re.I)
            )
            # Use the toolchain already selected by source analysis instead of
            # a fixed JDK.  A Java 26 project cannot be safely prewarmed in a
            # JDK 17 helper even though both use Gradle.  Prefer the generated
            # build stage; fall back to the Gradle image only when no evidence
            # exists.
            gradle_image = "gradle:8-jdk17"
            for candidate in list(source_root.rglob(".yunzhou*.Dockerfile")) + list(source_root.rglob("Dockerfile*")):
                if not candidate.is_file():
                    continue
                candidate_text = candidate.read_text(encoding="utf-8", errors="ignore")
                if "gradlew" not in candidate_text and not re.search(r"\bgradle\b", candidate_text, re.I):
                    continue
                image_match = re.search(r"(?im)^FROM\s+(?:--platform=\S+\s+)?([^\s]+)(?:\s+AS\s+\S+)?", candidate_text)
                if image_match:
                    gradle_image = image_match.group(1)
                    break
            if direct_boot_jar:
                log(deployment.id, "[平台构建] Spring Boot/Gradle 仅执行一次 bootJar，构建过程同时填充公共缓存。\n")

            # Spring/Gradle projects must not download the wrapper again from
            # inside a classic Docker build: that build cannot bind-mount the
            # public host cache and would both waste time and hold the global
            # image commit lock.  Compile the boot jar in a disposable helper
            # with the shared GRADLE_USER_HOME, then make the generated
            # Dockerfile package only that artifact.  Repository Dockerfiles
            # remain untouched; only platform-generated .yunzhou files are
            # rewritten in the isolated release copy.
            gradle_descriptors = [gradle_root / "build.gradle", gradle_root / "build.gradle.kts"]
            descriptor_text = gradle_descriptor_text
            if generated_gradle_files and re.search(r"spring[-.]boot|bootJar", descriptor_text, re.I):
                compile_script = (
                    "set -e; "
                    "sed -i 's/\\r$//' ./gradlew; chmod +x ./gradlew; "
                    "./gradlew bootJar -x test --no-daemon"
                )
                # Use a complete build-tool image for the external compile.
                # Minimal JRE images can miss xargs and previously caused an
                # invisible, unbounded yum install before Gradle even started.
                requested_jdks: list[int] = []
                for pattern in (
                    r"JavaLanguageVersion\.of\(\s*(\d+)\s*\)",
                    r"jvmToolchain\(\s*(\d+)\s*\)",
                    r"JavaVersion\.VERSION_(\d+)",
                    r"(?:sourceCompatibility|targetCompatibility)\s*=\s*[\"']?(\d+)",
                ):
                    requested_jdks.extend(int(value) for value in re.findall(pattern, descriptor_text))
                requested_jdk = max(requested_jdks, default=21)
                # The wrapper determines the Gradle version; the helper image
                # only supplies the source-declared JDK and common CLI tools.
                # Never silently downgrade a project toolchain.
                gradle_helper_image = f"gradle:jdk{requested_jdk}"
                compile_command = (
                    f"docker run --rm --label yunzhou.deployment={shlex.quote(deployment.id)} "
                    f"-v {shlex.quote(str(gradle_root))}:/workspace "
                    # Official Gradle images run as the `gradle` user. Mount
                    # the persistent cache at that image's real default home;
                    # /root/.gradle is otherwise ignored and every release
                    # downloads the wrapper and dependencies again.
                    f"-v {shlex.quote(cache_root + '/gradle' + ':' + gradle_cache_dir)} "
                    f"-w /workspace {shlex.quote(gradle_helper_image)} sh -lc "
                    + shlex.quote(compile_script)
                )
                log(deployment.id, f"[平台构建] Gradle 使用 {gradle_helper_image} 与公共缓存外置编译，镜像阶段仅打包 bootJar。\n")
                compile_code, compile_output = tracked_run(
                    build_ssh, deployment.id, compile_command, stream=stream, timeout=1800,
                    pid_prefix="yunzhou-gradle-build",
                )
                if compile_code:
                    raise RuntimeError("Gradle 公共缓存编译失败：" + compile_output[-2000:])
                jars = sorted(
                    item for item in (gradle_root / "build" / "libs").glob("*.jar")
                    if "-plain" not in item.name
                )
                if not jars:
                    raise RuntimeError("Gradle 构建成功但未找到 bootJar 产物")
                jar = jars[-1]
                for dockerfile in generated_gradle_files:
                    original = dockerfile.read_text(encoding="utf-8", errors="ignore")
                    stages = re.split(r"(?im)(?=^\s*FROM\s+)", original)
                    final_stage = stages[-1] if stages else original
                    final_image_match = re.search(r"(?im)^\s*FROM\s+([^\s]+)", final_stage)
                    final_image = final_image_match.group(1) if final_image_match else gradle_image
                    expose_match = re.search(r"(?im)^\s*EXPOSE\s+(\d+)", final_stage)
                    expose = expose_match.group(1) if expose_match else "8080"
                    relative_jar = jar.relative_to(gradle_root).as_posix()
                    gradle_log_dirs = detect_java_log_directories(gradle_root)
                    gradle_log_setup = ""
                    if gradle_log_dirs:
                        quoted_dirs = " ".join(shlex.quote(value) for value in gradle_log_dirs)
                        gradle_log_setup = f"RUN mkdir -p {quoted_dirs} && chmod 0777 {quoted_dirs}\n"
                    dockerfile.write_text(
                        f"FROM {final_image}\n{gradle_log_setup}WORKDIR /app\n"
                        f"COPY {relative_jar} /app/app.jar\n"
                        f"EXPOSE {expose}\n"
                        'ENTRYPOINT ["java", "-jar", "/app/app.jar"]\n',
                        encoding="utf-8",
                    )
                log(deployment.id, f"[缓存命中] Gradle bootJar 已生成：{jar.name}；Docker 不再重复下载依赖。\n")

        # A generated full-stack Dockerfile may place frontend-build before
        # api-runtime (or vice versa). The classic builder executes preceding
        # stages even when a later target does not depend on them. After the
        # ordered external frontend/backend builds above, split every service
        # target into its own runtime-only Dockerfile so API packaging never
        # runs pnpm and frontend packaging never runs Maven/Gradle.
        if build_type == "compose":
            compose_path = Path(work) / build_file
            try:
                split_compose = yaml.safe_load(compose_path.read_text(encoding="utf-8", errors="ignore")) or {}
            except Exception:
                split_compose = {}
            split_override = {}
            if compose_override:
                try:
                    split_override = yaml.safe_load((Path(work) / compose_override).read_text(encoding="utf-8", errors="ignore")) or {}
                except Exception:
                    split_override = {}
            artifacts = sorted({
                path.relative_to(source_root).as_posix()
                for path in source_root.rglob("*")
                if (
                    (path.is_dir() and path.name in {"dist", "build"})
                    or (path.is_file() and path.suffix == ".jar" and "target" in path.parts)
                )
                and not any(part in {"node_modules", ".git", ".pnpm-store"} for part in path.parts)
            })
            split_count = 0
            for service_name, service in (split_compose.get("services") or {}).items():
                build = service.get("build") if isinstance(service, dict) else None
                if not isinstance(build, dict) or not build.get("target"):
                    continue
                context_rel = str(build.get("context") or ".")
                context = (Path(work) / context_rel).resolve()
                dockerfile = context / str(build.get("dockerfile") or "Dockerfile")
                if not dockerfile.is_file():
                    continue
                docker_text = dockerfile.read_text(encoding="utf-8", errors="ignore")
                build_target = str(build.get("target") or "")
                relative_artifacts = []
                for artifact in artifacts:
                    absolute = source_root / artifact
                    try:
                        relative_artifacts.append(absolute.relative_to(context).as_posix())
                    except ValueError:
                        continue
                result = runtime_stage_from_prebuilt_artifact(
                    docker_text, context, relative_artifacts, str(service_name), target=build_target,
                )
                if not result:
                    continue
                runtime_text, copied = result
                safe_service = re.sub(r"[^a-z0-9_.-]+", "-", str(service_name).lower()).strip("-.") or "app"
                runtime_name = f".yunzhou.{safe_service}.runtime.Dockerfile"
                (context / runtime_name).write_text(runtime_text, encoding="utf-8")
                build["dockerfile"] = runtime_name
                build.pop("target", None)
                override_service = (split_override.get("services") or {}).get(service_name)
                if isinstance(override_service, dict) and isinstance(override_service.get("build"), dict):
                    override_service["build"]["dockerfile"] = runtime_name
                    override_service["build"].pop("target", None)
                split_count += 1
                log(deployment.id, f"[平台构建] {service_name} 已拆分为纯运行镜像，仅复制：{', '.join(copied)}。\n")
            if split_count:
                compose_path.write_text(yaml.safe_dump(split_compose, allow_unicode=True, sort_keys=False), encoding="utf-8")
                if compose_override:
                    (Path(work) / compose_override).write_text(
                        yaml.safe_dump(split_override, allow_unicode=True, sort_keys=False), encoding="utf-8"
                    )

        # Python projects often use ``pip --no-cache-dir`` inside Dockerfiles,
        # which makes the visible shared pip directory stay empty. Build a
        # requirements-keyed wheelhouse with a short-lived Python container,
        # then let the classic Docker build install only from those wheels.
        # This keeps Buildx disabled while making pip downloads reusable and
        # inspectable under /data/yunzhou/builder/cache/pip.
        if build_type == "compose":
            try:
                compose_doc = yaml.safe_load((Path(work) / build_file).read_text(encoding="utf-8", errors="ignore")) or {}
            except Exception:
                compose_doc = {}
            warmed_contexts: set[str] = set()
            for service in (compose_doc.get("services") or {}).values():
                if not isinstance(service, dict) or not service.get("build"):
                    continue
                build = service["build"]
                context_rel = str(build.get("context") or ".") if isinstance(build, dict) else str(build)
                dockerfile_rel = str(build.get("dockerfile") or "Dockerfile") if isinstance(build, dict) else "Dockerfile"
                context = (Path(work) / context_rel).resolve()
                dockerfile = context / dockerfile_rel
                requirements = context / "requirements.txt"
                context_key = str(context)
                if context_key in warmed_contexts or not dockerfile.is_file() or not requirements.is_file():
                    continue
                docker_text = dockerfile.read_text(encoding="utf-8", errors="ignore")
                base_match = re.search(r"(?im)^FROM\s+(python:[^\s]+)", docker_text)
                # Locate the complete Dockerfile RUN instruction, including
                # backslash-continued lines. Replacing only its first physical
                # line can leave a following ``&&`` as a top-level Dockerfile
                # instruction ("unknown instruction: &&").
                pip_block: tuple[int, int, str, str] | None = None
                wheel_block: tuple[int, int, str] | None = None
                docker_lines = docker_text.splitlines(keepends=True)
                offset = 0
                line_index = 0
                while line_index < len(docker_lines):
                    line = docker_lines[line_index]
                    block_start = offset
                    block_lines = [line]
                    offset += len(line)
                    if re.match(r"(?i)^\s*RUN\s+", line):
                        while block_lines[-1].rstrip("\r\n").rstrip().endswith("\\") and line_index + 1 < len(docker_lines):
                            line_index += 1
                            next_line = docker_lines[line_index]
                            block_lines.append(next_line)
                            offset += len(next_line)
                        block_text = "".join(block_lines)
                        collapsed = re.sub(r"\\\s*\r?\n\s*", " ", block_text)
                        wheel_match = re.search(
                            r"(?i)\bpip\s+wheel\b.*?--wheel-dir(?:=|\s+)([^\s;&]+).*?\s-r\s+([^\s;&]+requirements\.txt)\b",
                            collapsed,
                        )
                        if wheel_match:
                            wheel_block = (block_start, offset, wheel_match.group(1))
                        requirement_match = re.search(
                            r"(?i)\bpip\s+install\b.*?\s-r\s+([^\s;&]+requirements\.txt)\b",
                            collapsed,
                        )
                        if requirement_match:
                            pip_block = (block_start, offset, block_text, requirement_match.group(1))
                            break
                    line_index += 1
                if not base_match or not pip_block:
                    continue
                warmed_contexts.add(context_key)
                req_hash = hashlib.sha256(requirements.read_bytes()).hexdigest()[:16]
                wheel_dir = f"{cache_root}/pip/{req_hash}"
                marker = f"{wheel_dir}/.complete"
                code, _ = build_ssh.run(f"test -f {shlex.quote(marker)}")
                if code:
                    build_ssh.run(f"rm -rf {shlex.quote(wheel_dir)} && mkdir -p {shlex.quote(wheel_dir)}")
                    python_image = base_match.group(1)
                    pip_command = (
                        f"docker run --rm --label yunzhou.deployment={shlex.quote(deployment.id)} "
                        f"-v {shlex.quote(context_key)}:/workspace:ro "
                        f"-v {shlex.quote(wheel_dir)}:/wheelhouse "
                        f"{shlex.quote(python_image)} sh -lc "
                        + shlex.quote("pip download -r /workspace/requirements.txt -d /wheelhouse")
                    )
                    log(deployment.id, f"[平台构建] Python：{python_image}，首次填充公共 pip wheel 缓存。\n")
                    code, output = tracked_run(
                        build_ssh, deployment.id, pip_command, stream=stream,
                        timeout=1200, pid_prefix="yunzhou-pip-cache",
                    )
                    if code:
                        raise RuntimeError("pip 公共缓存填充失败：" + output[-2000:])
                    build_ssh.run(f"touch {shlex.quote(marker)}")
                    cache_state = "首次填充"
                else:
                    cache_state = "完整命中"
                staged_wheels = context / ".yunzhou-pip-wheels"
                shutil.rmtree(staged_wheels, ignore_errors=True)
                shutil.copytree(Path(wheel_dir), staged_wheels, ignore=shutil.ignore_patterns(".complete"))
                block_start, block_end, _, requirement_path = pip_block
                replacement = (
                    "COPY .yunzhou-pip-wheels /opt/yunzhou-pip-wheels\n"
                    "RUN pip install --no-index --find-links=/opt/yunzhou-pip-wheels "
                    f"-r {requirement_path} \\\n"
                    "    && rm -rf /opt/yunzhou-pip-wheels"
                )
                rewritten_docker = docker_text[:block_start] + replacement + docker_text[block_end:]
                # Generated multi-stage Dockerfiles may have already created a
                # separate ``pip wheel`` stage. Once the public wheelhouse is
                # complete, replace that network download step too; otherwise
                # the later offline install is cached but the builder stage
                # still downloads every dependency again.
                if wheel_block:
                    wheel_start, wheel_end, wheel_target = wheel_block
                    rewritten_docker = (
                        rewritten_docker[:wheel_start]
                        + f"COPY .yunzhou-pip-wheels {wheel_target}\n"
                        + rewritten_docker[wheel_end:]
                    )
                dockerfile.write_text(rewritten_docker, encoding="utf-8")
                wheel_count = len(list(staged_wheels.glob("*")))
                log(deployment.id, f"[缓存命中] pip {cache_state}：requirements={req_hash}，wheel={wheel_count}。\n")

            # Generic conventional Node/Maven multi-stage projects are built
            # in disposable toolchain containers. Dependency state is mounted
            # from the visible platform-wide cache; Docker only packages the
            # resulting dist/JAR into the small runtime stage.
            override_doc: dict = {}
            if compose_override:
                try:
                    override_doc = yaml.safe_load((Path(work) / compose_override).read_text(encoding="utf-8")) or {}
                except Exception:
                    override_doc = {}
            prebuilt_contexts: set[str] = set()
            compose_changed = False
            for service_name, service in (compose_doc.get("services") or {}).items():
                if not isinstance(service, dict) or not service.get("build"):
                    continue
                build = service["build"]
                context_rel = str(build.get("context") or ".") if isinstance(build, dict) else str(build)
                dockerfile_rel = str(build.get("dockerfile") or "Dockerfile") if isinstance(build, dict) else "Dockerfile"
                context = (Path(work) / context_rel).resolve()
                context_key = str(context)
                dockerfile = context / dockerfile_rel
                if context_key in prebuilt_contexts or not dockerfile.is_file():
                    continue
                docker_text = dockerfile.read_text(encoding="utf-8", errors="ignore")
                runtime_text: str | None = None
                artifacts: list[str] = []

                package_json = context / "package.json"
                node_match = re.search(r"(?im)^FROM\s+(node:[^\s]+)", docker_text)
                if package_json.is_file() and node_match and "--from=" in docker_text:
                    try:
                        package_meta = json.loads(package_json.read_text(encoding="utf-8", errors="replace"))
                    except Exception:
                        package_meta = {}
                    scripts = package_meta.get("scripts") if isinstance(package_meta, dict) else {}
                    # A runtime-only Node service (for example Express) has no
                    # build artifact. Do not invent `yarn build`; let its
                    # Dockerfile install dependencies and start normally.
                    if not isinstance(scripts, dict) or not scripts.get("build"):
                        continue
                    package_manager = str(package_meta.get("packageManager") or "").lower()
                    has_package_lock = (context / "package-lock.json").is_file()
                    has_pnpm_lock = (context / "pnpm-lock.yaml").is_file()
                    has_yarn_lock = (context / "yarn.lock").is_file()
                    if package_manager.startswith("pnpm") or (has_pnpm_lock and not has_package_lock and not has_yarn_lock):
                        manager = "pnpm"
                        install = "corepack enable; corepack prepare pnpm@8.15.9 --activate; " \
                                  f"pnpm install --store-dir {shlex.quote(pnpm_cache_dir)} --frozen-lockfile; pnpm run build"
                    elif package_manager.startswith("yarn") or (has_yarn_lock and not has_package_lock):
                        manager = "yarn"
                        install = "yarn install --frozen-lockfile; yarn build"
                    else:
                        manager = "npm"
                        install = "npm install --prefer-offline --no-audit --no-fund; npm run build"
                    package_text = json.dumps(package_meta, ensure_ascii=False)
                    legacy_webpack = bool(
                        re.search(r'"(?:webpack|@vue/cli-service)"\s*:\s*"?[~^]?(?:[0-4])(?:\.|"|$)', package_text)
                    )
                    node_major_match = re.search(r"node:(\d+)", node_match.group(1))
                    if legacy_webpack and node_major_match and int(node_major_match.group(1)) >= 17:
                        install = "export NODE_OPTIONS=--openssl-legacy-provider; " + install
                        log(
                            deployment.id,
                            "[平台兼容] 检测到旧版 Webpack 与 OpenSSL 3，已仅为本次前端构建启用兼容模式。\n",
                        )
                    if context_key not in node_built_contexts:
                        relative_context = context.relative_to(source_root).as_posix() or "."
                        node_modules_mount = ""
                        if manager == "npm":
                            persistent_modules = persistent_dependency_root / relative_context / "node_modules"
                            persistent_modules.mkdir(parents=True, exist_ok=True)
                            visible_modules = Path(builder_root) / "projects" / project.slug / "source-cache" / relative_context / "node_modules"
                            if visible_modules.parent.is_dir() and not visible_modules.exists():
                                try:
                                    visible_modules.symlink_to(persistent_modules, target_is_directory=True)
                                except OSError:
                                    pass
                            node_modules_mount = f"-v {shlex.quote(str(persistent_modules) + ':/workspace/node_modules')} "
                        command = (
                            f"docker run --rm --label yunzhou.deployment={shlex.quote(deployment.id)} "
                            f"-v {shlex.quote(context_key)}:/workspace "
                            f"-v {shlex.quote(cache_root + '/pnpm' + ':' + pnpm_cache_dir)} "
                            f"-v {shlex.quote(cache_root + '/npm' + ':' + npm_cache_dir)} "
                            f"-v {shlex.quote(cache_root + '/yarn' + ':' + yarn_cache_dir)} "
                            f"{node_modules_mount}"
                            f"-w /workspace {shlex.quote(node_match.group(1))} sh -lc "
                            + shlex.quote("set -e; trap 'rm -rf .pnpm-store' EXIT; " + install)
                        )
                        log(deployment.id, f"[平台构建] Node 正式构建：{node_match.group(1)} + {manager}。\n")
                        code, output = tracked_run(build_ssh, deployment.id, command, stream=stream, timeout=1800,
                                                   pid_prefix="yunzhou-node-build")
                        if code:
                            raise RuntimeError("Node 公共缓存构建失败：" + output[-2000:])
                        node_built_contexts.add(context_key)
                        shutil.rmtree(context / ".pnpm-store", ignore_errors=True)
                    else:
                        log(deployment.id, f"[平台构建] Node 产物已生成，跳过重复 {manager} 构建。\n")
                    result = runtime_stage_from_prebuilt_artifact(
                        docker_text, context, ["dist", "build", ".output", "out"], "node"
                    )
                    if result:
                        runtime_text, artifacts = result

                pom = context / "pom.xml"
                maven_match = re.search(r"(?im)^FROM\s+(maven:[^\s]+)", docker_text)
                if runtime_text is None and pom.is_file() and maven_match and "--from=" in docker_text:
                    if context_key not in maven_built_contexts:
                        command = (
                            f"docker run --rm --label yunzhou.deployment={shlex.quote(deployment.id)} "
                            f"-v {shlex.quote(context_key)}:/workspace "
                            f"-v {shlex.quote(cache_root + '/maven' + ':' + maven_cache_dir)} "
                            f"-w /workspace {shlex.quote(maven_match.group(1))} "
                            "mvn -B package -DskipTests"
                        )
                        log(deployment.id, f"[平台构建] Maven 正式构建：{maven_match.group(1)}。\n")
                        code, output = tracked_run(build_ssh, deployment.id, command, stream=stream, timeout=1800,
                                                   pid_prefix="yunzhou-maven-build")
                        if code:
                            raise RuntimeError("Maven 公共缓存构建失败：" + output[-2000:])
                        maven_built_contexts.add(context_key)
                    else:
                        log(deployment.id, "[平台构建] Maven JAR 已生成，跳过重复 package。\n")
                    jar_paths = sorted({str(path.relative_to(context)).replace('\\', '/')
                                       for path in context.rglob("target/*.jar")
                                       if not path.name.startswith(("original-", "sources-", "javadoc-"))})
                    result = runtime_stage_from_prebuilt_artifact(docker_text, context, jar_paths, "maven")
                    if result:
                        runtime_text, artifacts = result

                if runtime_text is None:
                    continue
                prebuilt_contexts.add(context_key)
                runtime_name = ".yunzhou.runtime.Dockerfile"
                (context / runtime_name).write_text(runtime_text, encoding="utf-8")
                ignore_file = context / ".dockerignore"
                ignore_text = ignore_file.read_text(encoding="utf-8", errors="ignore") if ignore_file.is_file() else ""
                for artifact in artifacts:
                    ignore_text += f"\n!{artifact}\n!{artifact}/**\n"
                ignore_text += f"\n!{runtime_name}\n"
                ignore_file.write_text(ignore_text, encoding="utf-8")
                clean_build = {"context": context_rel, "dockerfile": runtime_name}
                service["build"] = clean_build
                override_service = (override_doc.get("services") or {}).get(service_name)
                if isinstance(override_service, dict):
                    override_service["build"] = clean_build
                compose_changed = True
                log(deployment.id, f"[平台构建] {service_name} 已切换为仅打包运行产物，不使用 Docker 依赖缓存。\n")
            if compose_changed:
                (Path(work) / build_file).write_text(yaml.safe_dump(compose_doc, allow_unicode=True, sort_keys=False), encoding="utf-8")
                if compose_override:
                    (Path(work) / compose_override).write_text(yaml.safe_dump(override_doc, allow_unicode=True, sort_keys=False), encoding="utf-8")
        # Compile recognized Java + Vue repositories in disposable toolchain
        # containers. Package-manager state lives in visible host directories,
        # shared by every project and independent from application images.
        mounted_wms_build = (
            (Path(work) / "WMSCloud_ui/.yunzhou.runtime.Dockerfile").is_file()
            and (Path(work) / "WMSCloud/ruoyi-admin/.yunzhou.runtime.Dockerfile").is_file()
        )
        if mounted_wms_build:
            log(deployment.id, f"[平台构建] 公共缓存：{cache_root}/{{maven,pnpm,npm,yarn,gradle,pip}}\n")
            frontend_dist = Path(builder_dir) / "WMSCloud_ui/dist"
            if not frontend_dist.is_dir() or not any(frontend_dist.iterdir()):
                node_command = (
                    f"docker run --rm --label yunzhou.deployment={shlex.quote(deployment.id)} "
                    f"-v {shlex.quote(builder_dir + '/WMSCloud_ui')}:/workspace "
                    f"-v {shlex.quote(cache_root + '/pnpm' + ':' + pnpm_cache_dir)} "
                    f"-v {shlex.quote(cache_root + '/npm' + ':' + npm_cache_dir)} "
                    f"-v {shlex.quote(cache_root + '/yarn' + ':' + yarn_cache_dir)} "
                    "-w /workspace node:16.20.2 sh -lc "
                    + shlex.quote(
                        "set -e; corepack enable; corepack prepare pnpm@8.15.9 --activate; "
                        f"pnpm install --store-dir {shlex.quote(pnpm_cache_dir)} --frozen-lockfile; pnpm run build"
                    )
                )
                log(deployment.id, "[平台构建] 前端：Node 16.20.2 + pnpm 8.15.9，挂载公共 pnpm/npm/yarn 缓存。\n")
                code, output = tracked_run(
                    build_ssh, deployment.id, node_command, stream=stream,
                    timeout=1800, pid_prefix="yunzhou-node-build",
                )
                if code:
                    raise RuntimeError("前端挂载缓存构建失败：" + output[-2000:])
                shutil.rmtree(Path(builder_dir) / "WMSCloud_ui/.pnpm-store", ignore_errors=True)
                reused = max((int(value) for value in re.findall(r"reused\s+(\d+)", output)), default=0)
                downloaded = max((int(value) for value in re.findall(r"downloaded\s+(\d+)", output)), default=0)
                log(deployment.id, f"[缓存命中] pnpm reused={reused}，downloaded={downloaded}。\n")
            else:
                log(deployment.id, "[平台构建] 前端产物已生成，跳过重复 pnpm 构建。\n")

            settings_file = Path(work) / ".yunzhou.maven-settings.xml"
            if not settings_file.is_file():
                settings_file.write_text(
                    '<settings xmlns="http://maven.apache.org/SETTINGS/1.0.0"><mirrors><mirror>'
                    '<id>yunzhou-mirror</id><mirrorOf>*</mirrorOf><url>https://maven.aliyun.com/repository/public</url>'
                    '</mirror></mirrors></settings>', encoding="utf-8",
                )
            maven_command = (
                f"docker run --rm --label yunzhou.deployment={shlex.quote(deployment.id)} "
                f"-v {shlex.quote(builder_dir)}:/workspace "
                f"-v {shlex.quote(cache_root + '/maven' + ':' + maven_cache_dir)} "
                "-w /workspace maven:3.8.8-eclipse-temurin-8 "
                "mvn -s /workspace/.yunzhou.maven-settings.xml -B -f WMSCloud/pom.xml "
                "-pl ruoyi-admin -am package -DskipTests"
            )
            log(deployment.id, f"[平台构建] 后端：Maven 3.8.8 + Java 8，挂载公共 {maven_cache_dir} 缓存。\n")
            code, output = tracked_run(
                build_ssh, deployment.id, maven_command, stream=stream,
                timeout=1800, pid_prefix="yunzhou-maven-build",
            )
            if code:
                raise RuntimeError("Maven 挂载缓存构建失败：" + output[-2000:])
            downloaded = len(re.findall(r"Downloading from ", output))
            log(deployment.id, f"[缓存命中] Maven 本次远程下载请求={downloaded}（二次构建应明显下降）。\n")
        if build_type == "compose":
            files = f"-f {shlex.quote(build_file)}" + (f" -f {shlex.quote(compose_override)}" if compose_override else "")
            build_owners: list[str] = []
            for compose_name in (build_file, compose_override):
                if not compose_name:
                    continue
                try:
                    compose_document = yaml.safe_load((Path(work) / compose_name).read_text(encoding="utf-8")) or {}
                    for name, service in (compose_document.get("services") or {}).items():
                        if isinstance(service, dict) and service.get("build") and str(name) not in build_owners:
                            build_owners.append(str(name))
                except Exception:
                    continue
            compose_prefix = (
                f"cd {shlex.quote(builder_dir)} && "
                # Use Docker's classic builder.  The generated Dockerfiles are
                # multi-stage: Node/Maven stages compile artifacts and the
                # final runtime image only receives the built files.  This
                # keeps runtime images small without accumulating Buildx
                # history and local-cache directories.
                f"DOCKER_BUILDKIT=0 COMPOSE_DOCKER_CLI_BUILD=0 DOCKER_DEFAULT_PLATFORM={shlex.quote(platform)} "
                f"{build_env_prefix} "
                # Compose otherwise builds every service concurrently inside
                # this single job, bypassing the outer deployment lock.  Some
                # Docker/containerd versions then lose ingest leases while
                # exporting layers.  Keep service image commits serial too.
                f"docker compose --parallel 1 -p {shlex.quote('yz-build-' + project.slug)} {files} build"
            )
            build_commands = [
                (service, compose_prefix + " " + shlex.quote(service))
                for service in build_owners
            ] or [("应用镜像", compose_prefix)]
        else:
            command = (
                f"cd {shlex.quote(builder_dir)} && DOCKER_BUILDKIT=0 DOCKER_DEFAULT_PLATFORM={shlex.quote(platform)} "
                f"docker build -f {shlex.quote(build_file)} -t {shlex.quote(image_name)} ."
            )
            build_commands = [("应用镜像", command)]
        # Dependency preparation and classic image packaging may run across
        # deployments concurrently. Cleanup is scheduled separately and only
        # runs when the deployment queue is idle.
        for service_index, (service_name, service_command) in enumerate(build_commands, start=1):
            # Dependency compilation remains fully concurrent. Only the final
            # classic-Docker image write is serialized per builder node;
            # concurrent commits against this node's shared containerd store
            # have repeatedly lost ingest/snapshot files.
            locked_command = (
                "flock -w 1200 /tmp/yunzhou-image-commit.lock sh -lc "
                + shlex.quote(service_command)
            )
            log(
                deployment.id,
                f"[平台构建] 服务 {service_index}/{len(build_commands)}：{service_name} 等待镜像封装；依赖编译与公共缓存不受影响。\n",
            )
            code, output = tracked_run(
                build_ssh, deployment.id, locked_command, stream=stream, timeout=1500,
                pid_prefix=f"yunzhou-build-{service_index}",
            )
            # Docker installations backed by containerd occasionally lose an
            # ingest lease while committing a classic-builder layer. This is
            # an engine storage failure rather than a source failure. Retry
            # only this service, still with the classic builder.
            infrastructure_build_error = any(marker in output.lower() for marker in (
                "lease does not exist",
                "creatediff",
                "failed to commit",
                "failed to export layer",
                "io.containerd.content.v1.content/ingest",
                "failed to export image",
                "failed to unpack image",
                "failed to get reader from content store",
                "content store: content digest",
                "snapshot ",
                "snapshotter",
                "does not exist: not found",
            ))
            if code and infrastructure_build_error:
                log(
                    deployment.id,
                    f"[平台自愈] {service_name} 发生 Docker 存储异常，仅使用经典构建器重试该服务。\n",
                )
                code, output = tracked_run(
                    build_ssh, deployment.id, locked_command, stream=stream, timeout=1500,
                    pid_prefix=f"yunzhou-build-{service_index}-retry",
                )
            if code:
                if code == 1 and not output.strip():
                    raise RuntimeError(f"{service_name} 等待镜像构建队列超时，平台已释放本次任务，请稍后安全重试。")
                raise RuntimeError(f"{service_name} 镜像构建失败：" + output[-2000:])
            log(deployment.id, f"[平台构建] {service_name} 镜像封装完成，已释放提交锁。\n")
        for value in images:
            repository, separator, tag = value.rpartition(":")
            if not separator:
                repository, tag = value, "latest"
            safe_repository = re.sub(r"[^a-z0-9._/-]+", "-", repository.lower()).strip("-/")
            policy = db.get(DeploymentSettings, "default")
            endpoint = (policy.registry_endpoint if policy else "yunzhou.hub:5000").strip().rstrip("/")
            namespace = (policy.registry_namespace if policy else "yunzhou").strip("/")
            repository_tail = safe_repository.split("/", 1)[-1]
            safe_repository = f"{namespace}/{repository_tail}"
            registry_reference = f"{endpoint}/{safe_repository}:{tag}"
            code, registry_output = 1, ""
            for push_attempt in range(1, 4):
                code, registry_output = build_ssh.run(
                    f"docker tag {shlex.quote(value)} {shlex.quote(registry_reference)} && "
                    f"docker push {shlex.quote(registry_reference)}",
                    timeout=1800,
                )
                if code == 0:
                    break
                transient_push_error = any(marker in registry_output.lower() for marker in (
                    " eof", "connection reset", "connection refused", "tls handshake timeout",
                    "i/o timeout", "unexpected status", "service unavailable", "bad gateway",
                ))
                if not transient_push_error or push_attempt >= 3:
                    break
                log(
                    deployment.id,
                    f"[镜像仓库] {safe_repository}:{tag} 第 {push_attempt} 次推送遇到临时网络异常，3 秒后自动重试。\n",
                )
                time.sleep(3)
            if code:
                raise RuntimeError("应用镜像写入平台仓库失败：" + registry_output[-1200:])
            if not verify_registry_tag(safe_repository, tag):
                raise RuntimeError(
                    f"镜像推送命令已结束，但平台中央仓库未发现 {safe_repository}:{tag}；"
                    "已停止发布，避免记录假入库状态。请检查仓库地址解析和存储卷。"
                )
            build_ssh.run(f"docker image rm -f {shlex.quote(registry_reference)} >/dev/null 2>&1 || true", timeout=120)
            log(deployment.id, f"[镜像仓库] 已入库 {safe_repository}:{tag}。\n")
            removed_tags = cleanup_registry_versions(db, project, safe_repository)
            if removed_tags:
                log(deployment.id, f"[镜像仓库] 已按保留策略清理旧版本：{', '.join(removed_tags)}。\n")
        # Dependency reuse is provided by the explicit public cache mounts.
        # Do not retain anonymous Docker build layers after a successful job.
        build_ssh.run("docker image prune -f >/dev/null 2>&1 || true", timeout=120)
        if builder.id != target.id:
            image_args = " ".join(shlex.quote(value) for value in images)
            code, output = build_ssh.run(f"docker save {image_args} | gzip -1 > {shlex.quote(archive)}", timeout=1800)
            if code:
                raise RuntimeError("平台镜像打包失败：" + output[-1200:])
            with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as handle:
                local_archive = handle.name
            try:
                build_ssh.download_file(archive, local_archive)
                with SSHNode(target) as target_ssh:
                    remote_archive = f"/tmp/yunzhou-images-{deployment.id}.tar.gz"
                    target_ssh.upload_file(local_archive, remote_archive)
                    code, output = target_ssh.run(f"gzip -dc {shlex.quote(remote_archive)} | docker load; rm -f {shlex.quote(remote_archive)}", timeout=1800)
                    if code:
                        raise RuntimeError("目标服务器导入平台镜像失败：" + output[-1200:])
            finally:
                Path(local_archive).unlink(missing_ok=True)
                build_ssh.run(f"rm -f -- {shlex.quote(archive)}; rm -rf -- {shlex.quote(builder_dir)}")
        else:
            build_ssh.run(f"rm -rf -- {shlex.quote(builder_dir)}")
    return builder


def cleanup_old_project_images(db, deployment: Deployment, project: Project, target: Node) -> str:
    """Keep one builder copy and two target copies for rollback."""
    history = db.scalars(
        select(Deployment).where(
            Deployment.project_id == project.id,
            Deployment.release.is_not(None),
            Deployment.status.in_([DeployStatus.success, DeployStatus.stopped]),
        ).order_by(Deployment.created_at.desc())
    ).all()
    keep_releases = []
    for item in history:
        release = (item.release or "").strip()
        if release and release not in keep_releases:
            keep_releases.append(release)
        if len(keep_releases) == 2:
            break
    if deployment.release and deployment.release not in keep_releases:
        keep_releases.insert(0, deployment.release)
        keep_releases = keep_releases[:2]

    builder = platform_gateway_node(db)
    nodes = [target] + ([builder] if builder else [])
    unique_nodes = {}
    for node in nodes:
        key = (node.host, node.port, node.username)
        unique_nodes[key] = node

    repository = f"yunzhou/{project.slug}"
    reports = []
    target_key = (target.host, target.port, target.username)
    builder_key = (builder.host, builder.port, builder.username) if builder else None
    for key, node in unique_nodes.items():
        # A dedicated build server only needs the latest successful image. If
        # it is also the runtime target, retain the previous release as well.
        node_keep_releases = keep_releases[:1] if key == builder_key and key != target_key else keep_releases[:2]
        keep_words = " " + " ".join(node_keep_releases) + " "
        script = (
            "removed=0; skipped=0; "
            "docker images --format '{{.Repository}}|{{.Tag}}|{{.ID}}' | "
            "while IFS='|' read -r repo tag iid; do "
            f"case \"$repo\" in {shlex.quote(repository)}|{shlex.quote(repository + '-')}*) ;; *) continue ;; esac; "
            "[ \"$tag\" != '<none>' ] || continue; "
            f"case {shlex.quote(keep_words)} in *\" $tag \"*) skipped=$((skipped+1)); continue ;; esac; "
            "if docker ps -aq --filter ancestor=\"$iid\" | grep -q .; then skipped=$((skipped+1)); continue; fi; "
            "docker image rm \"$repo:$tag\" >/dev/null 2>&1 && removed=$((removed+1)) || true; "
            "done; "
            # Only old dangling images are pruned. Fresh layers may belong to a
            # concurrent build and BuildKit's reusable cache is not touched.
            "dangling=$(docker image prune -f --filter dangling=true --filter until=24h 2>/dev/null | "
            "awk '/Total reclaimed space:/ {print $4 \" \" $5}'); "
            "printf 'retained=%s dangling_reclaimed=%s' " + shlex.quote(",".join(node_keep_releases)) + " \"${dangling:-0B}\""
        )
        with SSHNode(node) as ssh:
            code, output = ssh.run(script, timeout=180)
        if code:
            raise RuntimeError(f"{node.name} 镜像清理失败：{output[-500:]}")
        reports.append(f"{node.name}：{output.strip()}")
    return "；".join(reports)


def cleanup_incomplete_release_images(
    db, deployment: Deployment, project: Project, target: Node, release: str | None,
) -> str:
    """Delete and verify images created by a failed or cancelled release."""
    release = (release or deployment.release or "").strip()
    if not release:
        return "本次任务尚未生成版本镜像"
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", release):
        raise RuntimeError("发布版本号不安全，已拒绝镜像清理")
    builder = platform_gateway_node(db)
    nodes = [target] + ([builder] if builder else [])
    unique_nodes = {(node.host, node.port, node.username): node for node in nodes if node}
    repository = f"yunzhou/{project.slug}"
    reports = []
    for node in unique_nodes.values():
        script = (
            # Compose can leave stopped containers whose images have already
            # lost their repository tag. Match the exact release through the
            # config-files label, remove those containers, then remove only
            # their platform-built images. Never touch another release that
            # shares the same Compose project label.
            f"project_label={shlex.quote('com.docker.compose.project=yz-' + project.slug)}; "
            "owned_images=''; owned_containers=0; "
            "for cid in $(docker ps -aq --filter label=\"$project_label\"); do "
            "cfg=$(docker inspect -f '{{index .Config.Labels \"com.docker.compose.project.config_files\"}}' \"$cid\" 2>/dev/null); "
            f"case \"$cfg\" in */{release}/*) ;; *) continue ;; esac; "
            "iid=$(docker inspect -f '{{.Image}}' \"$cid\" 2>/dev/null); "
            "builder=$(docker image inspect -f '{{index .Config.Labels \"com.docker.compose.image.builder\"}}' \"$iid\" 2>/dev/null); "
            "[ \"$builder\" = classic ] && owned_images=\"$owned_images $iid\"; "
            "docker rm -f \"$cid\" >/dev/null 2>&1 || true; owned_containers=$((owned_containers+1)); done; "
            "for iid in $(printf '%s\n' $owned_images | sort -u); do "
            "docker ps -aq --filter ancestor=\"$iid\" | grep -q . || docker image rm -f \"$iid\" >/dev/null 2>&1 || true; done; "
            "refs=$(docker images --format '{{.Repository}}|{{.Tag}}' | "
            f"awk -F'|' -v r={shlex.quote(repository)} -v t={shlex.quote(release)} "
            "'$2==t && ($1==r || index($1,r\"-\")==1) {print $1\":\"$2}'); "
            "count=$(printf '%s\\n' \"$refs\" | sed '/^$/d' | wc -l); "
            "if [ -n \"$refs\" ]; then printf '%s\\n' \"$refs\" | xargs -r docker image rm -f >/dev/null; fi; "
            "docker image prune -f >/dev/null 2>&1 || true; "
            "left=$(docker images --format '{{.Repository}}|{{.Tag}}' | "
            f"awk -F'|' -v r={shlex.quote(repository)} -v t={shlex.quote(release)} "
            "'$2==t && ($1==r || index($1,r\"-\")==1) {print}'); "
            "[ -z \"$left\" ] || { printf 'remaining=%s' \"$left\"; exit 31; }; "
            "printf 'removed=%s stopped_containers=%s verified=clean' \"$count\" \"$owned_containers\""
        )
        locked_script = (
            "flock -w 1200 /tmp/yunzhou-image-commit.lock sh -lc "
            + shlex.quote(script)
        )
        with SSHNode(node) as ssh:
            code, output = ssh.run(locked_script, timeout=3660)
        if code:
            raise RuntimeError(f"{node.name} 本次版本镜像清理后仍有残留：{output[-800:]}")
        reports.append(f"{node.name}：{output.strip()}")
    return "；".join(reports)


def execute(deployment_id: str) -> None:
    work = None
    cleanup_root = None
    runtime_bundle = None
    with SessionLocal() as db:
        dep = db.get(Deployment, deployment_id)
        if not dep:
            return
        dep.status = DeployStatus.running
        dep.started_at = datetime.now(timezone.utc)
        db.commit()

        project = db.get(Project, dep.project_id)
        node = db.get(Node, dep.node_id)
        current_stage = "analyze"
        try:
            log(dep.id, "[阶段开始] analyze\n")
            log(dep.id, "[准备] 正在获取项目源码...\n")
            ensure_active(dep.id)
            work, revision, cleanup_root, source_subpath = stage_source(project, db, dep.id)
            ensure_active(dep.id)
            previous_error = ""
            # A user-requested retry must receive the same bounded repair
            # context as an automatic retry.  Previously only ai_autofix
            # carried the last error, so clicking "retry" repeated a known
            # deterministic failure without applying the learned repair.
            # The next manual release after a failure is also a retry from the
            # platform's point of view. Carry forward repair evidence when the
            # immediately preceding release on this node failed; do not require
            # a special trigger string and do not resurrect an older failure
            # after an intervening successful/stopped release.
            previous_rows = db.scalars(
                select(Deployment)
                .where(
                    Deployment.project_id == dep.project_id,
                    Deployment.node_id == dep.node_id,
                    Deployment.created_at < dep.created_at,
                )
                .order_by(Deployment.created_at.desc())
                .limit(12)
            ).all()
            failure_evidence = []
            for previous in previous_rows:
                if previous.status == DeployStatus.success:
                    break
                if previous.status == DeployStatus.failed and previous.error:
                    failure_evidence.append(previous.error)
            previous_error = "\n\n".join(failure_evidence)
            if source_subpath:
                log(dep.id, f"[源码] 已定位仓库项目目录 /{source_subpath}\n")
            optimized_files = optimize_staged_sources(work)
            if optimized_files:
                log(dep.id, "[源码] 已将发布副本中的国外依赖源替换为国内镜像：" + "、".join(optimized_files) + "\n")
            dependency_analysis = analyze_runtime_dependencies(work)
            log(dep.id, "[依赖分析] " + json.dumps(dependency_analysis, ensure_ascii=False) + "\n")
            ai_plan = None
            if project.build_type == "auto":
                source_analysis = project.source_analysis or {}
                saved_plan = source_analysis.get("deployment_plan")
                analyzed_revision = str(source_analysis.get("revision") or "").strip()
                current_revision = str(revision or "").strip()
                if (
                    source_analysis.get("status") == "completed"
                    and isinstance(saved_plan, dict)
                    and saved_plan
                    and analyzed_revision
                    and analyzed_revision == current_revision
                ):
                    ai_plan, integration_changes = adapt_plan_to_current_integrations(saved_plan, project)
                    log(dep.id, f"[方案] 已复用源码管理中的全量 AI 分析（版本 {current_revision[:12]}），无需重复分析。\n")
                    if integration_changes:
                        log(dep.id, "[方案] " + "；".join(integration_changes) + "。\n")
                else:
                    reason = "尚未保存完整 AI 方案" if not saved_plan else "源码版本已变化"
                    log(dep.id, f"[方案] {reason}，平台正在根据本次最新源码自动刷新部署方案，无需手动重新分析。\n")
                    refreshed_plan = analyze_project_deployment(db, project, work)
                    if not isinstance(refreshed_plan, dict) or not refreshed_plan:
                        if isinstance(saved_plan, dict) and saved_plan:
                            ai_plan, integration_changes = adapt_plan_to_current_integrations(saved_plan, project)
                            log(dep.id, "[方案] AI 暂未返回新方案，先复用上一版已验证架构处理本次业务代码更新。\n")
                        else:
                            raise RuntimeError("平台未能根据最新源码生成部署方案，请稍后重试")
                    else:
                        ai_plan, integration_changes = adapt_plan_to_current_integrations(refreshed_plan, project)
                        refreshed_state = dict(source_analysis)
                        refreshed_state.update({
                            "status": "completed",
                            "phase": "completed",
                            "progress": 100,
                            "revision": current_revision,
                            "deployment_plan": refreshed_plan,
                            "summary": str(refreshed_plan.get("mode_decision") or refreshed_plan.get("summary") or "已根据最新源码自动刷新部署方案"),
                            "finished_at": datetime.now(timezone.utc).isoformat(),
                            "auto_refreshed_by_deployment": dep.id,
                        })
                        project.integration_analysis_json = json.dumps(refreshed_state, ensure_ascii=False)
                        db.commit()
                        log(dep.id, f"[方案] 已按最新源码版本 {current_revision[:12]} 自动刷新并保存部署方案。\n")
                    if integration_changes:
                        log(dep.id, "[方案] " + "；".join(integration_changes) + "。\n")
            if ai_plan:
                inferred_config = apply_ai_inferred_config(project, ai_plan)
                if inferred_config:
                    db.commit()
                    log(dep.id, "[配置预填] AI 已从源码确认并保存非敏感配置：" + json.dumps(inferred_config, ensure_ascii=False) + "\n")
                required_user_config = ai_plan.get("required_user_config") or []
                if required_user_config:
                    log(dep.id, "[配置清单] 以下配置不能安全自动填写：" + json.dumps(required_user_config, ensure_ascii=False) + "\n")
                build_type, build_file, detected_port = materialize_ai_deployment_plan(work, ai_plan)
                log(dep.id, "[AI规划] " + json.dumps({
                    "provider": ai_plan.get("provider"), "requested_model": ai_plan.get("requested_model"),
                    "actual_model": ai_plan.get("model"), "summary": ai_plan.get("summary"),
                    "deployment_kind": build_type, "services": ai_plan.get("services"),
                    "access_path": ai_plan.get("access_path"), "build_file": build_file,
                }, ensure_ascii=False) + "\n")
                login_info = normalize_login_info(work, ai_plan)
                dep.login_info_json = json.dumps(login_info, ensure_ascii=False)
                db.commit()
                log(dep.id, "[登录信息] " + json.dumps(login_info, ensure_ascii=False) + "\n")
            else:
                log(dep.id, "[AI规划] 当前未配置可用 AI，使用平台本地识别器生成兼容方案。\n")
                build_type, build_file, detected_port = prepare_build(work, project.build_type)
            if build_type == "compose":
                compose_path = Path(work) / build_file
                compose_source = compose_path.read_text(encoding="utf-8", errors="ignore")
                required_pattern = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*):\?[^}]*\}")
                normalized = compose_source
                for variable in set(required_pattern.findall(compose_source)):
                    if source_declares_environment_optional(work, variable):
                        normalized = re.sub(
                            rf"\$\{{{re.escape(variable)}:\?[^}}]*\}}",
                            "${" + variable + ":-}",
                            normalized,
                        )
                if normalized != compose_source:
                    compose_path.write_text(normalized, encoding="utf-8")
                    log(dep.id, "[配置预检] 已按源码环境示例将可选集成调整为允许留空。\n")
            # Run preflight after the final AI-generated build files exist. It
            # catches foreign package sources and cross-platform lock issues
            # before the first remote pull/build instead of waiting to fail.
            preflight_sources = optimize_staged_sources(work)
            repaired_files = apply_safe_build_repairs(work, previous_error, project.deployment_mode)
            preflight_changes = list(dict.fromkeys(preflight_sources + repaired_files))
            # Repairs may replace the final runtime stage (for example a
            # static-server assumption becomes the framework's real preview
            # server). Re-read EXPOSE from the final build artifact instead
            # of carrying forward a port detected from the pre-repair plan.
            if build_type == "dockerfile":
                final_detected_port = detect_container_port(work, build_file)
                if final_detected_port:
                    detected_port = final_detected_port
            if preflight_changes:
                log(dep.id, "[识别] 发布前预检已修复国内软件源及平台原生依赖：" + "、".join(preflight_changes) + "\n")
            else:
                log(dep.id, "[识别] 发布前预检通过：软件源、锁文件和目标平台依赖未发现阻断项\n")
            access_path, access_path_evidence = infer_verified_access_path(work, ai_plan)
            log(dep.id, f"[访问路径] {access_path}（{access_path_evidence}）；将通过真实 HTTP 验证后记为成功经验。\n")
            topology = analyze_repository_topology(work, build_type, build_file)
            log(dep.id, "[架构分析] " + json.dumps(topology, ensure_ascii=False) + "\n")
            ai_checkpoint(dep.id, "识别项目", json.dumps({"dependencies": dependency_analysis, "topology": topology}, ensure_ascii=False))
            if topology["errors"]:
                raise RuntimeError("整仓库分析未通过：" + "；".join(topology["errors"]))
            log(dep.id, "[阶段完成] analyze\n")
            current_stage = "prepare"
            log(dep.id, "[阶段开始] prepare\n")
            if build_type == "compose":
                managed_integrations = reconcile_managed_integrations(project, work, build_file)
                if managed_integrations:
                    db.commit()
                    log(dep.id, "[托管服务] 未勾选外部服务，平台已自动补齐：" + "、".join(managed_integrations) + "\n")
                generated_secrets = ensure_managed_secrets(project, work, build_file)
                if generated_secrets:
                    db.commit()
                    log(dep.id, "[配置生成] 平台已生成托管服务凭据：" + "、".join(generated_secrets) + "（可在项目配置中查看，值不写入发布日志）\n")
                missing_variables = required_compose_variables(work, build_file, effective_project_environment(project))
                if missing_variables:
                    evidence = json.dumps({"missing_variables": missing_variables, "compose_file": build_file}, ensure_ascii=False)
                    log(dep.id, "[配置预检] AI 已在构建前发现 Compose 必填配置缺失：" + evidence + "\n")
                    ai_checkpoint(dep.id, "配置预检", evidence)
                    names = "、".join(item["name"] for item in missing_variables)
                    raise RuntimeError(f"[需要配置] Compose 必填环境变量缺失：{names}。请在项目设置中补充后重新发布")
            log(dep.id, f"[识别] 项目类型 {build_type}，构建文件 {build_file}\n")
            if build_file == ".yunzhou.Dockerfile":
                log(dep.id, "[AI构建] 已根据源码结构、依赖清单和运行版本重新生成平台 Dockerfile；项目原 Dockerfile 仅作为端口与环境参考。\n")
            # Project image tags are minute based so they remain readable in the
            # registry. Concurrent builds of the same project in one minute get
            # a deterministic suffix instead of racing for the same tag.
            # User-facing release tags follow the platform's China-local time.
            # Database timestamps remain UTC and are converted by the UI.
            release_base = datetime.now(timezone(timedelta(hours=8))).strftime("%Y%m%d%H%M")
            releases_in_minute = set(db.scalars(select(Deployment.release).where(
                Deployment.project_id == project.id,
                Deployment.release.like(f"{release_base}%"),
            )).all())
            release = release_base
            sequence = 2
            while release in releases_in_minute:
                release = f"{release_base}-{sequence:02d}"
                sequence += 1
            remote_dir = f"{node.work_dir.rstrip('/')}/{project_directory(project)}/{release}"
            if build_type == "dockerfile":
                container_name = _service_container_name(project.slug, "app", 1)
            else:
                # Compose services receive their own stable service-aware name
                # in the generated override below.  This placeholder is never
                # used as a physical Compose container name.
                container_name = f"yz-{project.slug}"
            image_name = f"yunzhou/{project.slug}:{release}"
            host_port = choose_node_port(db, node, dep.host_port or project.host_port)
            # The final generated/selected Dockerfile is the source of truth.
            # A value saved by an older analysis (commonly the default 80)
            # must not override a newly detected EXPOSE such as Vite's 4300.
            container_port = detected_port or project.container_port
            if container_port and project.container_port != container_port:
                project.container_port = container_port
            dep.release = release
            dep.container_name = container_name
            dep.image_name = image_name if build_type == "dockerfile" else None
            dep.host_port = host_port
            db.commit()
            log(dep.id, f"[源码] 版本 {revision}，发布目录 {remote_dir}\n")

            compose_override = None
            built_images = []
            target_platform = node_platform(node)
            if build_type == "compose":
                compose_override, built_images = prepare_compose_image_override(
                    work, build_file, project, release, target_platform, node,
                    db=db, primary_host_port=host_port, deployment_plan=ai_plan,
                )
            runtime_bundle = prepare_runtime_bundle(work, build_type, build_file, compose_override)
            readme = (
                "自助发布平台部署目录说明\n"
                "====================\n\n"
                f"项目名称：{project.name}\n"
                f"项目标识：{project.slug}\n"
                f"发布版本：{release}\n"
                f"源码版本：{revision}\n"
                f"目标服务器：{node.name}（{node.host}）\n"
                f"构建类型：{'Docker Compose' if build_type == 'compose' else 'Dockerfile'}\n"
                f"主配置文件：{build_file}\n\n"
                "本目录只保存运行所需配置，源码和构建缓存保存在平台构建服务器。\n"
                "以 . 开头的是平台生成的内部文件，普通 ls/ll 不显示。\n"
                "查看全部文件：ls -la\n"
                "请勿直接修改 .env 或 .yunzhou.* 文件；请在自助发布平台修改配置并重新发布。\n"
            )
            (Path(runtime_bundle) / "README-部署说明.txt").write_text(readme, encoding="utf-8")
            # Remote image builds may take many minutes. Release PostgreSQL
            # read locks before waiting so API startup and ordinary project
            # reads are never blocked by a long-running build.
            db.commit()
            def build_stream(text):
                log(dep.id, text)
                ensure_active(dep.id)
            log(dep.id, "[阶段完成] prepare\n")
            current_stage = "build"
            log(dep.id, "[阶段开始] build\n")
            log(dep.id, "[平台构建] 源码只在平台构建服务器编译，目标服务器将接收构建后的镜像与运行配置。\n")
            ai_checkpoint(dep.id, "平台统一构建", f"正在平台构建服务器生成版本 {release} 镜像")
            builder = central_build_and_distribute(
                db, dep, project, node, work, build_type, build_file, release,
                image_name if build_type == "dockerfile" else None,
                compose_override, built_images, target_platform, build_stream,
            )
            log(dep.id, f"[平台构建] 镜像构建完成：{builder.name}；目标节点只负责加载并启动。\n")
            log(dep.id, "[阶段完成] build\n")
            current_stage = "start"
            log(dep.id, "[阶段开始] start\n")

            with SSHNode(node) as ssh:
                log(dep.id, f"[上传] 正在上传 Compose 与运行配置到 {remote_dir}...\n")
                ssh.upload_tree(runtime_bundle, remote_dir)
                log(dep.id, "[上传] 运行配置上传完成\n")
                ai_checkpoint(dep.id, "上传到服务器", f"版本 {revision} 的镜像与运行配置已送达 {remote_dir}")
                def append(text):
                    log(dep.id, text)
                    ensure_active(dep.id)
                ensure_active(dep.id)
                if build_type == "compose":
                    compose_files = f"-f {shlex.quote(build_file)}" + (f" -f {shlex.quote(compose_override)}" if compose_override else "")
                    env_text = effective_project_environment(project)
                    secret_seed = f"{settings.app_secret}:{project.id}".encode()
                    db_password = hashlib.sha256(secret_seed + b":mysql").hexdigest()[:28]
                    root_password = hashlib.sha256(secret_seed + b":mysql-root").hexdigest()[:32]
                    jwt_secret = hashlib.sha256(secret_seed + b":jwt").hexdigest()
                    stored_keys = store_managed_values(project, {
                        "CRM_DB_PASSWORD": db_password,
                        "CRM_DB_ROOT_PASSWORD": root_password,
                        "CRM_JWT_SECRET": jwt_secret,
                    })
                    if stored_keys:
                        db.commit()
                        log(dep.id, "[配置] 已保存平台托管连接信息，可在项目配置中查看\n")
                    env_text = effective_project_environment(project)
                    compose_env = (
                        f"COMPOSE_PROJECT_NAME=yz-{project.slug}\n"
                        f"YUNZHOU_HOST_PORT={host_port}\n"
                        f"CRM_DB_PASSWORD={db_password}\n"
                        f"CRM_DB_ROOT_PASSWORD={root_password}\n"
                        f"CRM_JWT_SECRET={jwt_secret}\n"
                        + ((env_text.rstrip() + "\n") if env_text else "")
                    )
                    code, out = ssh.run(f"printf %s {shlex.quote(compose_env)} > {shlex.quote(remote_dir + '/.env')}")
                    if code:
                        raise RuntimeError(out)
                    compose_images = compose_pull_images(work, build_file)
                    log(dep.id, f"[镜像] Compose 共识别到 {len(compose_images)} 个服务镜像\n")
                    log(dep.id, "[镜像] 统一交由目标服务器 Docker 拉取；镜像源与代理使用该服务器 daemon.json 和 systemd 配置\n")
                    ai_checkpoint(dep.id, "拉取服务镜像", "已识别镜像：" + ", ".join(compose_images))
                    if compose_images:
                        pull_cmd = (
                            f"cd {shlex.quote(remote_dir)} && "
                            f"docker compose -p {shlex.quote('yz-' + project.slug)} "
                            f"{compose_files} pull --ignore-buildable"
                        )
                        pull_code, pull_out = tracked_run(ssh, dep.id, pull_cmd, stream=append, timeout=900)
                        if pull_code:
                            raise RuntimeError("Docker Compose 拉取服务镜像失败：" + pull_out[-1200:])
                    # Older single-container releases used the exact
                    # `yz-<slug>` name. A later Compose deployment uses
                    # `yz-<slug>-<service>-1`; leaving the legacy container
                    # alive can silently keep the selected host port mapped
                    # to an obsolete container port (for example 80 instead
                    # of the newly detected 4300).
                    legacy_container = f"yz-{project.slug}"
                    _, legacy_state = ssh.run(
                        f"docker inspect -f '{{{{.Name}}}} {{{{json .NetworkSettings.Ports}}}}' "
                        f"{shlex.quote(legacy_container)} 2>/dev/null || true"
                    )
                    if legacy_state.strip():
                        log(dep.id, f"[迁移清理] 已识别旧版直启容器：{legacy_state.strip()}\n")
                        ssh.run(f"docker rm -f {shlex.quote(legacy_container)} >/dev/null 2>&1 || true")
                    cmd = (
                        f"cd {shlex.quote(remote_dir)} && "
                        f"docker compose -p {shlex.quote('yz-' + project.slug)} {compose_files} up -d --no-build --remove-orphans"
                    )
                    log(dep.id, "[启动] 使用平台构建镜像启动 Docker Compose...\n")
                    ai_checkpoint(dep.id, "启动应用服务", f"Compose 文件 {build_file}，使用平台构建镜像启动完整服务拓扑")
                    code, out = tracked_run(ssh, dep.id, cmd, stream=append)
                    if code:
                        diagnostic_cmd = (
                            f"cd {shlex.quote(remote_dir)} && "
                            f"docker compose -p {shlex.quote('yz-' + project.slug)} {compose_files} ps -a; "
                            "echo '--- 服务日志 ---'; "
                            f"docker compose -p {shlex.quote('yz-' + project.slug)} {compose_files} logs --no-color --tail 200; "
                            "echo '--- 健康检查 ---'; "
                            f"for id in $(docker compose -p {shlex.quote('yz-' + project.slug)} {compose_files} ps -aq); do "
                            "name=$(docker inspect -f '{{.Name}}' $id 2>/dev/null | sed 's#^/##'); "
                            "health=$(docker inspect -f '{{if .State.Health}}{{json .State.Health.Log}}{{end}}' $id 2>/dev/null); "
                            "[ -n \"$health\" ] && printf '\n[%s]\n%s\n' \"$name\" \"$health\"; done"
                        )
                        _, diagnostic = ssh.run(diagnostic_cmd, timeout=90)
                        append("\n[启动诊断] Compose 启动失败，已在清理前采集容器状态、服务日志和健康检查：\n" + diagnostic[-20000:] + "\n")
                        log(dep.id, "[AI学习] 本次诊断证据将用于修复重试；未通过真实部署验证前不会记为成功经验。\n")
                        raise RuntimeError((out + "\n" + diagnostic)[-24000:])
                    ensure_active(dep.id)
                    code, ps = ssh.run(f"cd {shlex.quote(remote_dir)} && docker compose -p {shlex.quote('yz-' + project.slug)} {compose_files} ps --format json")
                    append("\n[检查] 正在检查 Compose 服务状态...\n" + ps + "\n")
                    ai_checkpoint(dep.id, "启动全部服务", ps)
                    if build_file.startswith(".yunzhou"):
                        readiness_path = access_path if str(access_path).startswith("/") else "/"
                        backend_probe_url = shlex.quote("http://backend:8080" + readiness_path)
                        verify_cmd = (
                            f"cd {shlex.quote(remote_dir)} && expected=$(docker compose -p {shlex.quote('yz-' + project.slug)} {compose_files} config --services | wc -l); "
                            "ok=0; for i in $(seq 1 40); do running=$(docker compose -p " + shlex.quote('yz-' + project.slug) + " " + compose_files + " ps --status running --services | wc -l); "
                            "[ \"$running\" -eq \"$expected\" ] && ok=1 && break; sleep 3; done; "
                            "[ \"$ok\" -eq 1 ] || { docker compose -p " + shlex.quote('yz-' + project.slug) + " " + compose_files + " ps; docker compose -p " + shlex.quote('yz-' + project.slug) + " " + compose_files + " logs --tail 120; exit 44; }; "
                            "services=$(docker compose -p " + shlex.quote('yz-' + project.slug) + " " + compose_files + " config --services); "
                            "if printf '%s\\n' \"$services\" | grep -qx frontend && printf '%s\\n' \"$services\" | grep -qx backend; then "
                            # Do not assume Spring Actuator exists. Probe the
                            # concrete source-derived endpoint and treat any
                            # non-5xx HTTP response as application readiness.
                            "api=0; for i in $(seq 1 40); do reply=$(docker compose -p " + shlex.quote('yz-' + project.slug) + " " + compose_files + " exec -T frontend wget -S -O /dev/null " + backend_probe_url + " 2>&1 || true); "
                            "printf '%s\\n' \"$reply\" | grep -Eq 'HTTP/[0-9.]+ [234][0-9][0-9]' && api=1 && break; sleep 3; done; "
                            "[ \"$api\" -eq 1 ] || { docker compose -p " + shlex.quote('yz-' + project.slug) + " " + compose_files + " logs --tail 120 backend; exit 45; }; fi; "
                            # Service names are arbitrary, so also verify every
                            # container in the generated topology. A container
                            # that keeps restarting can briefly appear running
                            # and must never make the deployment look healthy.
                            # Health checks commonly remain `starting` for tens
                            # of seconds. Wait up to 90 seconds; fail early only
                            # for an exited/restarting/unhealthy container.
                            "stable=0; unstable=0; for attempt in $(seq 1 30); do unstable=0; pending=0; ids=$(docker compose -p " + shlex.quote('yz-' + project.slug) + " " + compose_files + " ps -aq); "
                            "for id in $ids; do state=$(docker inspect -f '{{.State.Status}}' $id 2>/dev/null); restarts=$(docker inspect -f '{{.RestartCount}}' $id 2>/dev/null); health=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{end}}' $id 2>/dev/null); "
                            "[ \"$state\" = running ] || unstable=1; [ \"${restarts:-0}\" -eq 0 ] || unstable=1; [ \"$health\" = unhealthy ] && unstable=1; [ \"$health\" = starting ] && pending=1; done; "
                            "[ \"$unstable\" -eq 0 ] || break; [ \"$pending\" -eq 0 ] && stable=1 && break; sleep 3; done; "
                            "[ \"$stable\" -eq 1 ] || { echo '发现服务退出、反复重启、健康检查异常或等待健康超时'; docker compose -p " + shlex.quote('yz-' + project.slug) + " " + compose_files + " ps -a; docker compose -p " + shlex.quote('yz-' + project.slug) + " " + compose_files + " logs --tail 160; exit 46; }"
                        )
                        verify_code, verify_output = ssh.run(verify_cmd, timeout=150)
                        append("[检查] 前端、后端和数据库联合检查" + ("通过\n" if verify_code == 0 else "失败\n" + verify_output + "\n"))
                        if verify_code:
                            raise RuntimeError("多服务启动后联合检查未通过：" + verify_output)
                        # The previous mistaken single-container release is
                        # removed only after the replacement topology started.
                        ssh.run(f"docker rm -f {shlex.quote(container_name)} >/dev/null 2>&1 || true")
                    container_name = f"yz-{project.slug}"
                    # Compose may declare a fixed published port and ignore the
                    # platform's suggested YUNZHOU_HOST_PORT. Docker is the
                    # final source of truth for every service route, not just
                    # whichever publisher happens to be listed first.
                    published_port = None
                    service_targets: dict[str, list[tuple[str, int]]] = {}
                    if code == 0 and ps.strip():
                        try:
                            parsed = json.loads(ps)
                            rows = parsed if isinstance(parsed, list) else [parsed]
                        except Exception:
                            rows = []
                            for line in ps.splitlines():
                                try:
                                    rows.append(json.loads(line))
                                except Exception:
                                    continue
                        for row in rows:
                            service_name = str(row.get("Service") or row.get("service") or "").strip()
                            for publisher in row.get("Publishers", []) or []:
                                if not isinstance(publisher, dict):
                                    continue
                                candidate = publisher.get("PublishedPort")
                                if service_name and candidate:
                                    service_targets.setdefault(service_name, []).append((node.host, int(candidate)))
                        service_targets = {
                            service: list(dict.fromkeys(targets))
                            for service, targets in service_targets.items() if targets
                        }
                        traffic_plan = _project_traffic_plan(project, ai_plan)
                        entry_service = str(traffic_plan.get("default_service") or traffic_plan.get("entry_service") or "")
                        if not entry_service:
                            entry_service = next((
                                str(route.get("service") or route.get("target_service") or "")
                                for route in (traffic_plan.get("traffic_routes") or traffic_plan.get("routes") or [])
                                if isinstance(route, dict) and str(route.get("path") or "/") == "/"
                            ), "")
                        if not entry_service:
                            roles = _traffic_service_roles(traffic_plan)
                            entry_service = next((
                                service for service, (role, _) in roles.items()
                                if role == "frontend" and service in service_targets
                            ), "")
                        if entry_service in service_targets:
                            published_port = service_targets[entry_service][0][1]
                        if not published_port:
                            published_port = next((
                                port for targets in service_targets.values() for _, port in targets
                                if port == host_port
                            ), None)
                        if not published_port:
                            published_port = next((port for targets in service_targets.values() for _, port in targets), None)
                    if published_port:
                        rendered_targets = "、".join(
                            f"{service}={','.join(str(port) for _, port in targets)}"
                            for service, targets in service_targets.items()
                        )
                        log(dep.id, f"[检查] 识别到 Compose 服务入口：{rendered_targets}\n")
                    domain_config = db.get(ProjectDomainConfig, project.id)
                    domain_defaults = db.get(DeploymentSettings, "default")
                    route_groups = _compose_route_groups(project, service_targets, ai_plan)
                    access = configure_platform_gateway(
                        db, dep, node, published_port, project.domain,
                        http_port=domain_config.http_port if domain_config else (domain_defaults.default_domain_http_port if domain_defaults else 80),
                        https_enabled=domain_config.https_enabled if domain_config else False,
                        https_port=domain_config.https_port if domain_config else (domain_defaults.default_domain_https_port if domain_defaults else 443),
                        redirect_https=domain_config.redirect_https if domain_config else True,
                        certificate=decrypt(domain_config.certificate_encrypted) if domain_config else None,
                        private_key=decrypt(domain_config.private_key_encrypted) if domain_config else None,
                        route_groups=route_groups or None,
                        strategy=project.load_balance_strategy,
                    ) if published_port else None
                    service_names = {service.get("name") for service in topology.get("services", [])}
                    has_root_route = any(
                        str(path.get("path") or "/") == "/"
                        for group in route_groups
                        for path in (group.get("paths") or [])
                        if isinstance(path, dict)
                    )
                    if access and build_file == ".yunzhou.compose.yml" and {"frontend", "backend"}.issubset(service_names):
                        access = access.rstrip("/") + "/app/"
                    elif access and access_path != "/" and not has_root_route:
                        access = access.rstrip("/") + access_path
                    if access:
                        log(dep.id, f"[检查] 平台网关映射完成：{access}\n")
                else:
                    if not container_port:
                        raise RuntimeError("Dockerfile 未声明 EXPOSE，请在项目中填写容器端口")
                    base_images = dockerfile_base_images(work, build_file)
                    ai_checkpoint(dep.id, "拉取基础镜像", "已识别基础镜像：" + (", ".join(base_images) if base_images else "由 Docker 构建自动识别"))
                    log(dep.id, f"[镜像] 基础镜像已由平台构建中心处理：{', '.join(base_images) if base_images else 'Docker 构建自动识别'}\n")
                    log(dep.id, f"[镜像] 平台构建镜像已加载：{image_name}\n")
                    code, out = 0, ""
                    if code and build_file == ".yunzhou.Dockerfile" and "JCTree$JCImport" in out and "qualid" in out:
                        log(dep.id, "\n[AI修复] 识别到旧版 Java 注解处理器与当前 JDK 不兼容，自动切换到 JDK 8 安全重试一次。\n")
                        dockerfile_path = remote_dir + "/" + build_file
                        replace = (
                            f"sed -i -E 's/maven:3\\.9-eclipse-temurin-[0-9]+/maven:3.9-eclipse-temurin-8/g; "
                            f"s/eclipse-temurin:[0-9]+-jre/eclipse-temurin:8-jre/g' {shlex.quote(dockerfile_path)}"
                        )
                        replace_code, replace_out = ssh.run(replace)
                        if replace_code:
                            raise RuntimeError("AI 调整 Java 构建环境失败：" + replace_out)
                        code, out = tracked_run(ssh, dep.id,
                            f"cd {shlex.quote(remote_dir)} && DOCKER_BUILDKIT=0 docker build -f {shlex.quote(build_file)} -t {shlex.quote(image_name)} .",
                            stream=append,
                        )
                    if code:
                        log(dep.id, "\n[构建] 应用镜像编译失败，AI 正在分析并准备安全修复重试。\n")
                        raise RuntimeError(out)
                    ensure_active(dep.id)
                    env_args = ""
                    env_text = effective_project_environment(project)
                    if env_text:
                        env_file = remote_dir + "/.env.runtime"
                        code, out = ssh.run(f"printf %s {shlex.quote(env_text)} > {shlex.quote(env_file)}")
                        if code:
                            raise RuntimeError(out)
                        env_args = f"--env-file {shlex.quote(env_file)}"
                    cmd = (
                        f"docker rm -f {shlex.quote(container_name)} >/dev/null 2>&1 || true; "
                        f"docker run -d --name {shlex.quote(container_name)} --restart unless-stopped "
                        f"-e TZ=Asia/Shanghai -v /etc/localtime:/etc/localtime:ro "
                        f"{env_args} -p {host_port}:{container_port} {shlex.quote(image_name)}"
                    )
                    log(dep.id, f"\n[启动] 宿主机端口 {host_port} → 容器端口 {container_port}\n")
                    code, out = ssh.run(cmd, stream=append)
                    if code:
                        raise RuntimeError(out)
                    ensure_active(dep.id)
                    code, state = ssh.run(f"docker inspect -f '{{{{.State.Status}}}}' {shlex.quote(container_name)}")
                    log(dep.id, f"[检查] 容器状态：{state.strip()}\n")
                    ai_checkpoint(dep.id, "启动应用", f"容器 {container_name} 状态：{state.strip()}")
                    if code or state.strip() != "running":
                        raise RuntimeError("容器启动后状态异常：" + state.strip())
                    domain_config = db.get(ProjectDomainConfig, project.id)
                    domain_defaults = db.get(DeploymentSettings, "default")
                    access = configure_platform_gateway(
                        db, dep, node, host_port, project.domain,
                        http_port=domain_config.http_port if domain_config else (domain_defaults.default_domain_http_port if domain_defaults else 80),
                        https_enabled=domain_config.https_enabled if domain_config else False,
                        https_port=domain_config.https_port if domain_config else (domain_defaults.default_domain_https_port if domain_defaults else 443),
                        redirect_https=domain_config.redirect_https if domain_config else True,
                        certificate=decrypt(domain_config.certificate_encrypted) if domain_config else None,
                        private_key=decrypt(domain_config.private_key_encrypted) if domain_config else None,
                    )
                    if access_path != "/":
                        access = access.rstrip("/") + access_path
                    log(dep.id, f"[检查] 平台网关映射完成：{access}\n")

            log(dep.id, "[阶段完成] start\n")
            current_stage = "verify"
            log(dep.id, "[阶段开始] verify\n")
            ensure_active(dep.id)
            if not access:
                raise RuntimeError("部署未生成可验证的访问地址")
            verify_access(db, dep.id, access)
            log(dep.id, "[阶段完成] verify\n")
            ensure_active(dep.id)
            dep = db.get(Deployment, deployment_id)
            replaced = db.scalars(
                select(Deployment).where(
                    Deployment.project_id == dep.project_id,
                    Deployment.id != dep.id,
                    Deployment.status == DeployStatus.success,
                ).order_by(Deployment.created_at.desc())
            ).all()
            for old in replaced:
                old.status = DeployStatus.stopped
                old.error = None
                old.log_text = ((old.log_text or "") + f"\n[接管] 已由新版本 {release} 接管；历史记录保留，运行入口已切换到新版本。\n")[-200_000:]
            dep.status = DeployStatus.success
            dep.release = release
            dep.container_name = container_name
            dep.image_name = image_name if build_type == "dockerfile" else None
            dep.host_port = host_port if build_type == "dockerfile" else published_port
            dep.access_url = access
            dep.finished_at = datetime.now(timezone.utc)
            db.commit()
            # Every new release must first prove itself as one healthy instance.
            # Retire replicas from the previous release and keep the new release
            # single-instance until the user explicitly scales it from Runtime.
            try:
                from .main import scale_project
                from .schemas import ScaleProjectIn
                from .models import Role, User
                operator = db.scalar(select(User).where(User.role == Role.admin))
                if operator:
                    result = scale_project(project.id, ScaleProjectIn(replicas=1), db, operator)
                    dep = db.get(Deployment, deployment_id)
                    access = result.get("access_url") or access
                    log(dep.id, f"[单实例验证] 已就绪 1/1；如需负载均衡，请在运行服务中手动增加实例。入口 {access}\n")
            except Exception as scale_exc:
                log(dep.id, f"[运行容器] 主版本已发布，但副本同步未完成：{scale_exc}\n")
            try:
                dep = db.get(Deployment, deployment_id)
                cleanup_report = cleanup_old_project_images(db, dep, project, node)
                log(dep.id, "[镜像整理] 已保留当前运行版和上一个成功版；" + cleanup_report + "\n")
            except Exception as cleanup_exc:
                # Image housekeeping must never turn a verified deployment into
                # a failure. The next successful release will retry it.
                log(dep.id, f"[镜像整理] 本次自动整理未完成，将在下次成功发布后重试：{cleanup_exc}\n")
            log(dep.id, f"\n[完成] 部署成功{('，访问地址：' + access) if access else ''}\n")
            ai_checkpoint(dep.id, "检查服务关系", f"部署成功，访问地址：{access or '未生成'}")
        except DeploymentCancelled:
            dep = db.get(Deployment, deployment_id)
            log(dep.id, f"[阶段停止] {current_stage}\n")
            dep.status = DeployStatus.stopped
            dep.finished_at = datetime.now(timezone.utc)
            db.commit()
            log(dep.id, "\n[停止] 部署任务已由用户停止\n")
            if 'remote_dir' in locals():
                try:
                    with SSHNode(node) as cleanup_ssh:
                        cleanup_ssh.run(f"rm -rf -- {shlex.quote(remote_dir)}")
                    log(dep.id, "[清理] 已删除本次未完成的发布目录\n")
                except Exception as cleanup_exc:
                    log(dep.id, f"[清理] 未完成目录清理失败：{cleanup_exc}\n")
            try:
                report = cleanup_incomplete_release_images(db, dep, project, node, locals().get("release"))
                log(dep.id, f"[清理复查] 本次停止版本镜像已删除：{report}\n")
            except Exception as cleanup_exc:
                dep.error = f"停止成功，但镜像清理复查失败：{cleanup_exc}"
                db.commit()
                log(dep.id, f"[清理失败] {cleanup_exc}\n")
        except Exception as exc:
            dep = db.get(Deployment, deployment_id)
            if dep.status != DeployStatus.stopped:
                log(dep.id, f"[阶段失败] {current_stage} | {str(exc)[:500]}\n")
                dep.status = DeployStatus.failed
                dep.error = str(exc)
                dep.finished_at = datetime.now(timezone.utc)
                db.commit()
                log(dep.id, f"\n[失败] {exc}\n")
                ai_checkpoint(dep.id, "部署失败", str(exc))
            if 'remote_dir' in locals():
                # Stop/remove failed runtime containers immediately, but do
                # not touch their image layers while another build may still
                # be committing to the shared Docker store.
                try:
                    release_value = str(locals().get("release") or dep.release or "")
                    with SSHNode(node) as cleanup_ssh:
                        runtime_cleanup = (
                            "ids=$(docker ps -aq --filter "
                            + shlex.quote(f"label=com.docker.compose.project=yz-{project.slug}")
                            + "); for cid in $ids; do cfg=$(docker inspect -f "
                            + shlex.quote('{{index .Config.Labels "com.docker.compose.project.config_files"}}')
                            + " \"$cid\" 2>/dev/null); case \"$cfg\" in */"
                            + release_value
                            + "/*) docker rm -f \"$cid\" >/dev/null 2>&1 || true ;; esac; done; "
                            + (f"docker rm -f {shlex.quote(dep.container_name)} >/dev/null 2>&1 || true" if dep.container_name else "true")
                        )
                        cleanup_ssh.run(runtime_cleanup)
                    log(dep.id, "[清理] 已停止并删除本次失败版本容器；镜像等待构建队列空闲后统一清理\n")
                except Exception as runtime_cleanup_exc:
                    log(dep.id, f"[清理] 失败容器将在后台空闲清理时再次处理：{runtime_cleanup_exc}\n")
                try:
                    with SSHNode(node) as cleanup_ssh:
                        cleanup_ssh.run(f"rm -rf -- {shlex.quote(remote_dir)}")
                    log(dep.id, "[清理] 已删除失败部署的发布目录\n")
                except Exception as cleanup_exc:
                    log(dep.id, f"[清理] 失败目录清理失败：{cleanup_exc}\n")
            # Image deletion/pruning is durable work for the worker's idle
            # cleanup queue. Running it here can race another classic build
            # and corrupt Docker/containerd snapshot metadata.
            dep = db.get(Deployment, deployment_id)
            dep.log_text = ((dep.log_text or "") +
                "[待清理] 已登记本次失败版本镜像；待全部构建任务结束后自动清理并复查\n"
            )[-200_000:]
            db.commit()
        finally:
            # The fixed source checkout is intentionally retained and replaced
            # on the next fetch. Only transfer artifacts are release-specific.
            if 'release' in locals() and project:
                try:
                    builder_node = platform_gateway_node(db)
                    if builder_node:
                        builder_archive = f"/tmp/yunzhou-images-{dep.id}.tar.gz"
                        with SSHNode(builder_node) as builder_cleanup:
                            builder_cleanup.run(
                                f"rm -f -- {shlex.quote(builder_archive)}"
                            )
                except Exception as builder_cleanup_exc:
                    if dep:
                        log(dep.id, f"[清理] 平台构建临时目录将在后台再次整理：{builder_cleanup_exc}\n")
            if runtime_bundle:
                shutil.rmtree(runtime_bundle, ignore_errors=True)
            if cleanup_root:
                shutil.rmtree(cleanup_root, ignore_errors=True)


def stop_deployment(deployment: Deployment, project: Project, node: Node, *, preserve_runtime: bool = False) -> str:
    # A central image build may run on the platform server rather than the
    # target node. Stop that process group as part of the same user action.
    builder_stop = "平台构建节点无跟踪进程"
    with SessionLocal() as lookup_db:
        builder = platform_gateway_node(lookup_db)
    if builder:
        with SSHNode(builder) as builder_ssh:
            builder_stop = stop_tracked_process_groups(builder_ssh, deployment.id)
    with SSHNode(node) as ssh:
        target_stop = stop_tracked_process_groups(ssh, deployment.id)
        if preserve_runtime:
            return f"该记录已被更新版本接管，仅终止本记录的部署进程；当前运行容器已保留（构建节点 {builder_stop}；目标节点 {target_stop}）"
        if deployment.image_name:
            code, out = ssh.run(f"docker rm -f {shlex.quote(deployment.container_name or '')} 2>&1 || true")
        else:
            base = f"{node.work_dir.rstrip('/')}/{project_directory(project)}/{deployment.release}"
            legacy_base = f"{node.work_dir.rstrip('/')}/{project.slug}/{deployment.release}"
            _, resolved = ssh.run(
                f"if [ -d {shlex.quote(base)} ]; then printf %s {shlex.quote(base)}; "
                f"elif [ -d {shlex.quote(legacy_base)} ]; then printf %s {shlex.quote(legacy_base)}; fi"
            )
            actual_dir = resolved.strip()
            files = remote_compose_files(ssh, actual_dir) if actual_dir else []
            args = compose_file_args(files)
            if files:
                code, out = ssh.run(
                f"cd {shlex.quote(actual_dir)} && docker compose -p {shlex.quote('yz-' + project.slug)} {args} down"
                )
            else:
                # A failed cleanup or legacy release may leave labeled Compose
                # containers after its config directory has disappeared. Stop
                # the real runtime by ownership label so restart=unless-stopped
                # cannot keep it alive. Volumes and images remain untouched.
                compose_label = shlex.quote(f"com.docker.compose.project=yz-{project.slug}")
                code, out = ssh.run(
                    f"ids=$(docker ps -q --filter label={compose_label}); "
                    "[ -z \"$ids\" ] || docker stop $ids"
                )
        if code:
            raise RuntimeError(out)
        container = shlex.quote(deployment.container_name or '')
        project_name = shlex.quote('yz-' + project.slug)
        verify = (
            f"running=$(docker ps -q --filter name=^{container}$); "
            f"compose=$(docker ps -q --filter label=com.docker.compose.project={project_name}); "
            "printf 'container=%s compose=%s process=0' \"$running\" \"$compose\""
        )
        verify_code, state = ssh.run(verify)
        if verify_code or "process=1" in state or re.search(r"container=\S+", state) or re.search(r"compose=\S+", state):
            raise RuntimeError("停止后复查发现仍有部署进程或容器运行：" + state.strip())
        return f"已终止部署进程并关闭容器，复查确认无残留（构建节点 {builder_stop}；目标节点 {target_stop}）"


def delete_deployment_resources(
    deployment: Deployment,
    project: Project,
    node: Node,
    *,
    remove_compose_images: bool = False,
    remove_persistent_data: bool = False,
    preserve_runtime: bool = False,
) -> str:
    """Remove only the resources owned by one deployment release.

    Base/pulled images are deliberately retained. Compose build images use a
    project-wide name, so they are removed only when no other deployment for
    the same project/node remains.
    """
    if not project or not node:
        raise RuntimeError("项目或部署服务器已不存在，无法核验远端资源")
    release = (deployment.release or "").strip()
    if release and not re.fullmatch(r"[A-Za-z0-9_.-]+", release):
        raise RuntimeError("发布版本号不安全，已拒绝清理")
    with SSHNode(node) as ssh:
        pid_file = f"/tmp/yunzhou-deploy-{deployment.id}.pid"
        commands = [
            f"if [ -s {shlex.quote(pid_file)} ]; then p=$(cat {shlex.quote(pid_file)}); "
            f"kill -TERM -- -$p 2>/dev/null || true; sleep 1; kill -KILL -- -$p 2>/dev/null || true; fi",
            f"rm -f -- {shlex.quote(pid_file)}",
        ]
        if deployment.container_name and not preserve_runtime:
            commands.append(f"docker rm -f {shlex.quote(deployment.container_name)} >/dev/null 2>&1 || true")
        if release and not preserve_runtime:
            # Failed/stopped Compose records from older platform versions may
            # not contain a primary container name and their release folder
            # may already be gone.  The Compose config-files label still ties
            # every residual container to the exact release, so remove only
            # those containers instead of touching a newer runtime.
            commands.append(
                "docker ps -a --filter " + shlex.quote(f"label=com.docker.compose.project=yz-{project.slug}") +
                " --format '{{.Names}}|{{.Label \"com.docker.compose.project.config_files\"}}' | "
                f"awk -F'|' -v r={shlex.quote('/' + release + '/')} 'index($2,r) {{print $1}}' | "
                "xargs -r docker rm -f >/dev/null 2>&1 || true"
            )
        release_dirs = []
        if release:
            release_dirs = [
                f"{node.work_dir.rstrip('/')}/{project_directory(project)}/{release}",
                f"{node.work_dir.rstrip('/')}/{project.slug}/{release}",
            ]
            if not deployment.image_name and not preserve_runtime:
                for path in dict.fromkeys(release_dirs):
                    volume_flag = " -v" if remove_persistent_data else ""
                    files = remote_compose_files(ssh, path)
                    if files:
                        commands.append(
                            f"cd {shlex.quote(path)} && docker compose -p {shlex.quote('yz-' + project.slug)} "
                            f"{compose_file_args(files)} down{volume_flag} --remove-orphans"
                        )
            # A release folder is unique to this record. Remove both current and
            # legacy naming variants, but never the whole project directory.
            commands.extend(f"rm -rf -- {shlex.quote(path)}" for path in dict.fromkeys(release_dirs))
        if deployment.image_name:
            # Dockerfile deployments are tagged per release and are safe to remove exactly.
            commands.append(f"docker image rm -f {shlex.quote(deployment.image_name)} >/dev/null 2>&1 || true")
        if remove_compose_images:
            # Only locally built Compose images use this prefix. Directly pulled
            # images such as nginx/postgres/python are never selected. Compose
            # may use an explicit image name, so prefer its ownership label.
            prefix = f"yz-{project.slug}-"
            central_prefix = f"yunzhou/{project.slug}-"
            compose_project = f"yz-{project.slug}"
            commands.append(
                "(docker images -q --filter " + shlex.quote(f"label=com.docker.compose.project={compose_project}") + "; "
                "docker images --format '{{.Repository}}:{{.Tag}}' | "
                f"awk -v p={shlex.quote(prefix)} -v c={shlex.quote(central_prefix)} "
                "'index($0,p)==1 || index($0,c)==1 {print}') | "
                "sort -u | xargs -r docker image rm -f >/dev/null 2>&1 || true"
            )
            commands.append("docker image prune -f >/dev/null 2>&1 || true")
            # The last release owns no remaining release directory. Remove the
            # human-readable and legacy project parents only when they are empty.
            parent_dirs = [
                f"{node.work_dir.rstrip('/')}/{project_directory(project)}",
                f"{node.work_dir.rstrip('/')}/{project.slug}",
            ]
            commands.extend(f"rmdir -- {shlex.quote(path)} 2>/dev/null || true" for path in dict.fromkeys(parent_dirs))
        code, output = ssh.run("set -e; " + "; ".join(commands))
        if code:
            raise RuntimeError(output or "服务器资源清理失败")
        checks = []
        if deployment.container_name and not preserve_runtime:
            checks.append(
                f"docker ps -aq --filter {shlex.quote('name=^/' + deployment.container_name + '$')} | grep -q . && exit 21 || true"
            )
        checks.extend(f"test ! -e {shlex.quote(path)} || exit 22" for path in release_dirs)
        if deployment.image_name:
            checks.append(f"docker image inspect {shlex.quote(deployment.image_name)} >/dev/null 2>&1 && exit 23 || true")
        if remove_compose_images:
            checks.append(
                "{ docker images -q --filter " + shlex.quote(f"label=com.docker.compose.project=yz-{project.slug}") + "; "
                "docker images --format '{{.Repository}}' | "
                f"awk -v p={shlex.quote('yz-' + project.slug + '-')} -v c={shlex.quote('yunzhou/' + project.slug + '-')} "
                "'index($0,p)==1 || index($0,c)==1 {print}'; } | grep -q . && exit 23 || true"
            )
        verify_code, verify_output = ssh.run("; ".join(checks) if checks else "true")
        if verify_code:
            label = {21: "容器", 22: "发布目录", 23: "应用镜像"}.get(verify_code, "远端资源")
            raise RuntimeError(f"清理后复查发现{label}仍然存在：{verify_output.strip()}")
    removed = ["部署进程", "发布目录"]
    if not preserve_runtime:
        removed.append("容器")
    if deployment.image_name:
        removed.append("该版本应用镜像")
    elif remove_compose_images:
        removed.append("该项目未被其他版本使用的 Compose 构建镜像")
    if remove_persistent_data:
        removed.append("Compose 持久化卷")
    return "、".join(removed) + "已清理并复查"


def restore_release_images(db, deployment: Deployment, project: Project, node: Node, target_ssh: SSHNode, images: list[str]) -> list[str]:
    """Restore missing immutable release images through the builder, not the target's proxy."""
    release = (deployment.release or "").strip()
    candidates = []
    for image in images:
        image = image.strip()
        repository, separator, tag = image.rpartition(":")
        if separator and tag == release and repository.startswith("yunzhou/"):
            candidates.append(image)
    if not candidates:
        return []
    missing = []
    for image in dict.fromkeys(candidates):
        if target_ssh.run(f"docker image inspect {shlex.quote(image)} >/dev/null 2>&1")[0] != 0:
            missing.append(image)
    if not missing:
        return []
    if db is None:
        raise RuntimeError("历史版本镜像已不在目标服务器，请通过平台回滚以便从中央仓库恢复")
    builder = platform_gateway_node(db)
    if not builder:
        raise RuntimeError("平台构建节点不可用，暂时无法从中央仓库恢复历史镜像")
    policy = db.get(DeploymentSettings, "default")
    endpoint = (policy.registry_endpoint if policy else "yunzhou.hub:5000").strip().rstrip("/")
    namespace = (policy.registry_namespace if policy else "yunzhou").strip("/")
    archive = f"/tmp/yunzhou-rollback-{deployment.id}.tar.gz"

    def pull_and_tag(ssh: SSHNode) -> None:
        for image in missing:
            repository, _, tag = image.rpartition(":")
            repository_tail = repository.split("/", 1)[-1]
            registry_reference = f"{endpoint}/{namespace}/{repository_tail}:{tag}"
            code, output = ssh.run(
                f"docker pull {shlex.quote(registry_reference)} && "
                f"docker tag {shlex.quote(registry_reference)} {shlex.quote(image)}",
                timeout=900,
            )
            if code:
                raise RuntimeError(f"平台仓库中无法恢复历史镜像 {repository_tail}:{tag}，请检查该版本是否仍在保留范围内")

    if builder.id == node.id:
        pull_and_tag(target_ssh)
        return missing
    with SSHNode(builder) as builder_ssh:
        pull_and_tag(builder_ssh)
        image_args = " ".join(shlex.quote(image) for image in missing)
        code, output = builder_ssh.run(
            f"docker save {image_args} | gzip -1 > {shlex.quote(archive)}",
            timeout=1800,
        )
        if code:
            raise RuntimeError("历史镜像恢复包生成失败：" + output[-500:])
        with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as handle:
            local_archive = handle.name
        try:
            builder_ssh.download_file(archive, local_archive)
            remote_archive = f"/tmp/yunzhou-rollback-images-{deployment.id}.tar.gz"
            target_ssh.upload_file(local_archive, remote_archive)
            code, output = target_ssh.run(
                f"gzip -dc {shlex.quote(remote_archive)} | docker load; rm -f {shlex.quote(remote_archive)}",
                timeout=1800,
            )
            if code:
                raise RuntimeError("历史镜像传送到目标服务器失败：" + output[-500:])
        finally:
            Path(local_archive).unlink(missing_ok=True)
            builder_ssh.run(f"rm -f -- {shlex.quote(archive)}", timeout=30)
    return missing


def start_deployment(deployment: Deployment, project: Project, node: Node, db=None) -> str:
    """Start an existing stopped release and verify that Docker really runs it."""
    with SSHNode(node) as ssh:
        release_dir = f"{node.work_dir.rstrip('/')}/{project_directory(project)}/{deployment.release}"
        legacy_dir = f"{node.work_dir.rstrip('/')}/{project.slug}/{deployment.release}"
        _, resolved = ssh.run(
            f"if [ -d {shlex.quote(release_dir)} ]; then printf %s {shlex.quote(release_dir)}; "
            f"elif [ -d {shlex.quote(legacy_dir)} ]; then printf %s {shlex.quote(legacy_dir)}; fi"
        )
        actual_dir = resolved.strip()
        if not actual_dir:
            raise RuntimeError("原发布目录不存在，无法重新启用；请重新部署项目")
        if deployment.image_name:
            restore_release_images(db, deployment, project, node, ssh, [deployment.image_name])
            port = project.container_port
            if not port:
                code, exposed = ssh.run(f"docker image inspect -f '{{{{json .Config.ExposedPorts}}}}' {shlex.quote(deployment.image_name)}")
                match = re.search(r'\"(\d+)/(?:tcp|udp)\"', exposed) if code == 0 else None
                port = int(match.group(1)) if match else None
            if not port or not deployment.host_port:
                raise RuntimeError("缺少容器端口或外部端口，无法重新启用；请重新部署项目")
            env_file = actual_dir + "/.env.runtime"
            env_args = f"--env-file {shlex.quote(env_file)}" if ssh.run(f"test -f {shlex.quote(env_file)}")[0] == 0 else ""
            name = deployment.container_name or f"yz-{project.slug}"
            cmd = (
                f"docker rm -f {shlex.quote(name)} >/dev/null 2>&1 || true; "
                f"docker run -d --name {shlex.quote(name)} --restart unless-stopped {env_args} "
                f"-p {deployment.host_port}:{port} {shlex.quote(deployment.image_name)}"
            )
            code, output = ssh.run(cmd)
            if code:
                raise RuntimeError(output)
            code, state = ssh.run(f"docker inspect -f '{{{{.State.Status}}}}' {shlex.quote(name)}")
            if code or state.strip() != "running":
                raise RuntimeError("容器启动后状态异常：" + state.strip())
        else:
            files = remote_compose_files(ssh, actual_dir)
            if not files:
                raise RuntimeError("原发布目录中未找到 Compose 配置")
            code, configured_images = ssh.run(
                f"cd {shlex.quote(actual_dir)} && docker compose -p {shlex.quote('yz-' + project.slug)} "
                f"{compose_file_args(files)} config --images"
            )
            if code:
                raise RuntimeError("无法读取历史版本镜像清单，请重新发布该项目")
            restored = restore_release_images(
                db, deployment, project, node, ssh,
                [line.strip() for line in configured_images.splitlines() if line.strip()],
            )
            code, output = ssh.run(
                f"cd {shlex.quote(actual_dir)} && docker compose -p {shlex.quote('yz-' + project.slug)} "
                f"{compose_file_args(files)} up -d --no-build --remove-orphans"
            )
            if code:
                clean = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", output)
                raise RuntimeError("历史版本容器启动失败：" + clean[-800:])
            code, running = ssh.run(f"docker ps -q --filter label=com.docker.compose.project={shlex.quote('yz-' + project.slug)}")
            if code or not running.strip():
                raise RuntimeError("Compose 执行完成，但未发现运行中的服务容器")
            # A running container is not yet a ready application (Spring Boot
            # commonly needs 10-30 seconds). Keep the start action pending
            # until the published port actually answers, so the UI cannot
            # report a false successful recovery followed by a 502.
            if deployment.host_port:
                probe = (
                    f"for i in $(seq 1 45); do "
                    f"code=$(curl -sS -o /dev/null -w '%{{http_code}}' --max-time 2 "
                    f"http://127.0.0.1:{int(deployment.host_port)}/ 2>/dev/null || true); "
                    f"case \"$code\" in 2*|3*|4*) exit 0;; esac; sleep 1; done; exit 1"
                )
                code, _ = ssh.run(probe, timeout=55)
                if code:
                    raise RuntimeError("容器已启动，但应用在 45 秒内未就绪；请查看容器日志")
        restored_text = f"；已从平台仓库恢复 {len(restored)} 个旧镜像" if 'restored' in locals() and restored else ""
        return "服务已启动，并确认容器处于运行状态" + restored_text


