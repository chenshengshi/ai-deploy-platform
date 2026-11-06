import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx
import yaml
from sqlalchemy import update
from sqlalchemy.orm import Session

from .config import decrypt
from .experience import experience_confidence, infer_experience_tags, normalized_state, rank_learning_experiences, sanitize_learning_text
from .models import AiConfig, Deployment, DeploymentExperience, DeploymentSettings, Node, Project
from .proxy import proxy_for


SYSTEM = """你是自助发布平台内置的项目运维助手。你能根据平台提供的真实上下文回答项目分析、发布进度、失败原因、运行状态、访问地址、镜像、端口、域名、历史版本与配置问题，也能协助发布、停止部署、回滚历史版本、重启运行服务、执行源码中的数据库表结构迁移和修改项目环境配置。不得假装已经查询到上下文中没有的数据，不得生成或执行 Shell 命令；数据库迁移只能请求平台受控迁移接口。
返回严格 JSON：{"action":"deploy|stop|rollback|restart|migrate|configure|answer|none","project_id":"...或null","node_id":"...或null","config_changes":{},"reply":"中文回复"}。
用户询问状态、原因、耗时、日志、版本、访问方式或部署建议时，action 为 answer。reply 使用适合聊天窗口的紧凑格式：第一行必须是“结论：...”并直接回答；其后最多列 3 条关键依据；只有确实需要用户操作时才增加“下一步：...”。普通回答控制在 8 行以内，不写长篇诊断报告。区分部署耗时与容器运行时长。默认不展示 UUID、slug、内部字段名、环境变量清单或缺失数据清单，除非用户明确要求技术细节。平台上下文已有的信息必须直接使用，不能反过来要求用户提供；只有关键数据确实缺失且无法回答时，才用一句话说明缺少什么，不要编造。
用户明确要求部署、发布、上线或重新部署时 action 才是 deploy。
用户明确要求停止、中止或取消当前部署任务时 action 为 stop。停止必须由平台在用户确认后通过受控接口执行；首次请求只说明将停止哪个项目的当前任务以及影响，不得声称已经执行。
用户明确要求回滚、恢复到上一成功版本或切换到指定历史版本时 action 为 rollback。回滚必须由平台选取曾成功上线且验证通过的历史版本，在用户确认后通过受控接口执行；首次请求不得声称已经执行。
用户明确要求重启当前项目、运行服务或容器时 action 为 restart。重启必须由平台在用户确认后通过受控接口执行；首次请求只说明将重启哪个项目和节点、会短暂中断，不得声称已经执行。
用户明确要求执行、更新、同步、应用数据库表结构或 SQL 迁移文件时 action 为 migrate。首次请求只能让平台扫描当前线上版本中的真实 SQL 文件、判断风险并生成确认清单；用户确认后才可由平台先备份表结构再执行。不得编造 SQL、不得把普通配置文件当作迁移、不得声称未经平台返回的迁移已经执行。
用户明确要求新增、设置或修改项目环境配置，并给出了可确定的 KEY 和值时，action 为 configure，config_changes 只放环境变量键值。绝不猜测密码、地址或端口；缺少明确值时 action 为 none 并逐项询问。
用户要求增加 Redis、MySQL、MinIO、RabbitMQ、Elasticsearch 等中间件但未给出连接信息时，只说明先检查项目实际启用配置，并询问部署方式和连接参数，不能因为依赖声明或关键词就认定需要安装。
删除、清理、扩缩容等其他会改变运行状态的要求，目前只给出建议并说明需要用户确认，不得声称已经执行。"""


MANAGED_MINIO_REPOSITORY = "pgsty/minio"
MANAGED_MINIO_FALLBACK = "pgsty/minio:RELEASE.2026-08-04T00-00-00Z"
_managed_image_cache: dict[str, tuple[float, str]] = {}


def _preferred_ai_config(db: Session, *, require_key: bool = True) -> AiConfig | None:
    query = db.query(AiConfig).filter(AiConfig.enabled.is_(True))
    if require_key:
        query = query.filter(AiConfig.api_key_encrypted.is_not(None))
    return query.order_by(AiConfig.is_default.desc(), AiConfig.provider_name, AiConfig.id).first()


def _compose_environment(root: Path) -> dict[str, str]:
    """Read non-secret Compose interpolation values without exporting them."""
    values: dict[str, str] = {}
    env_file = root / ".env"
    if not env_file.is_file():
        return values
    for raw in env_file.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
            values[key] = value.strip().strip('"').strip("'")
    return values


def _interpolate_compose_value(value: str, environment: dict[str, str]) -> str:
    """Resolve nested ${VAR:-default} expressions using Compose-like precedence."""
    current = str(value)
    inner = re.compile(r"\$\{([^{}]+)\}")
    for _ in range(12):
        changed = False

        def replace(match: re.Match) -> str:
            nonlocal changed
            expression = match.group(1)
            if ":-" in expression:
                key, fallback = expression.split(":-", 1)
                resolved = environment.get(key, "") or fallback
            elif "-" in expression:
                key, fallback = expression.split("-", 1)
                resolved = environment[key] if key in environment else fallback
            else:
                resolved = environment.get(expression, "")
            changed = True
            return resolved

        current = inner.sub(replace, current)
        if not changed:
            break
    return current


def _apply_effective_production_images(root: Path, result: dict) -> None:
    """Keep verified fixed images selected by the repository's real .env precedence.

    AI is allowed to redesign unsafe configuration, but it must not silently
    replace a fixed production image selected by Compose interpolation with the
    fallback written in the Compose file.
    """
    if str(result.get("build_strategy") or "") not in {"reuse", "adapt"}:
        return
    environment = _compose_environment(root)
    selected: dict[str, str] = {}
    source_services: dict[str, dict] = {}
    source_env_services: set[str] = set()
    for filename in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"):
        path = root / filename
        if not path.is_file():
            continue
        try:
            source_doc = yaml.safe_load(path.read_text(encoding="utf-8", errors="ignore")) or {}
        except Exception:
            continue
        for service_name, service in (source_doc.get("services") or {}).items():
            if not isinstance(service, dict) or service.get("build") or not service.get("image"):
                continue
            image = _interpolate_compose_value(str(service["image"]), environment).strip()
            if image and "$" not in image and not image.endswith(":latest"):
                selected[str(service_name)] = image
                source_services[str(service_name)] = service
                env_files = service.get("env_file") or []
                if isinstance(env_files, (str, dict)):
                    env_files = [env_files]
                if any(
                    Path(str(entry.get("path") if isinstance(entry, dict) else entry)).name == ".env"
                    for entry in env_files
                ):
                    source_env_services.add(str(service_name))
        if selected:
            break
    if not selected or not result.get("compose_yaml"):
        return
    try:
        generated = yaml.safe_load(str(result["compose_yaml"])) or {}
    except Exception:
        return
    replacements = []
    restored = []
    changed = False
    for service_name, image in selected.items():
        service = (generated.get("services") or {}).get(service_name)
        if service is None:
            source_service = source_services[service_name]
            serialized = yaml.safe_dump(source_service, allow_unicode=True, sort_keys=False)
            unsafe = (
                source_service.get("privileged") is True
                or str(source_service.get("network_mode") or "").lower() == "host"
                or "/var/run/docker.sock" in serialized
            )
            if not unsafe:
                generated.setdefault("services", {})[service_name] = source_service
                service = generated["services"][service_name]
                restored.append(service_name)
                changed = True
        if isinstance(service, dict) and service.get("image") != image:
            replacements.append(f"{service_name}={image}")
            service["image"] = image
            changed = True
        if isinstance(service, dict) and service_name in source_env_services and service.get("env_file") != ".env":
            service["env_file"] = ".env"
            changed = True

    # When the repository already points at an external MinIO endpoint and its
    # production topology contains no MinIO service, do not let a generated
    # plan silently introduce a second object store.
    minio_endpoint = str(environment.get("MINIO_ENDPOINT") or "").strip()
    generated_services = generated.get("services") or {}
    if minio_endpoint and "minio" not in source_services and "minio" in generated_services:
        generated_services.pop("minio", None)
        changed = True
    if changed:
        result["compose_yaml"] = yaml.safe_dump(generated, allow_unicode=True, sort_keys=False)
    if replacements:
        reason = str(result.get("build_strategy_reason") or "").rstrip()
        result["build_strategy_reason"] = reason + " 有效 Compose 变量优先级已核验并锁定固定镜像：" + "、".join(replacements) + "。"
    if restored:
        reason = str(result.get("build_strategy_reason") or "").rstrip()
        result["build_strategy_reason"] = reason + " 已恢复生产 Compose 中不可遗漏的安全服务：" + "、".join(restored) + "。"


def discover_managed_minio_image(db: Session) -> str:
    """Resolve the newest stable tag from the trusted compatibility project.

    Discovery is restricted to a reviewed repository.  This lets versions
    move without allowing an AI answer to introduce an arbitrary image into a
    deployment.  The normal Compose pull remains the final registry/architecture
    validation on the target node.
    """
    cached = _managed_image_cache.get(MANAGED_MINIO_REPOSITORY)
    if cached and time.monotonic() - cached[0] < 6 * 60 * 60:
        return cached[1]
    url = f"https://hub.docker.com/v2/repositories/{MANAGED_MINIO_REPOSITORY}/tags?page_size=100&ordering=last_updated"
    try:
        with httpx.Client(proxy=proxy_for(db, url), trust_env=False, timeout=20) as client:
            response = client.get(url)
            response.raise_for_status()
        results = response.json().get("results") or []
        tag = next(
            (
                str(item.get("name")) for item in results
                if re.fullmatch(r"RELEASE\.\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}Z", str(item.get("name") or ""))
                and item.get("images")
            ),
            None,
        )
        selected = f"{MANAGED_MINIO_REPOSITORY}:{tag}" if tag else MANAGED_MINIO_FALLBACK
    except Exception:
        selected = cached[1] if cached else MANAGED_MINIO_FALLBACK
    _managed_image_cache[MANAGED_MINIO_REPOSITORY] = (time.monotonic(), selected)
    return selected


def _post_ai(client: httpx.Client, url: str, headers: dict, payload: dict, max_attempts: int = 5) -> httpx.Response:
    """Retry short upstream outages and tolerate gateways without response_format.

    Some OpenAI-compatible gateways incorrectly turn an unsupported
    ``response_format`` into HTTP 500 instead of the expected HTTP 400.  Retry
    once without that optional hint before treating the response as an
    upstream outage.  The prompts still explicitly require JSON output.
    """
    request_payload = dict(payload)
    response = None
    retryable_statuses = (429, 500, 502, 503, 504)
    for attempt in range(max_attempts):
        try:
            response = client.post(url, headers=headers, json=request_payload)
        except (httpx.ConnectError, httpx.ReadTimeout, httpx.RemoteProtocolError):
            if attempt >= max_attempts - 1:
                raise
            time.sleep(min(2 ** attempt, 8))
            continue
        if response.status_code in (400, 500) and "response_format" in request_payload:
            request_payload = dict(request_payload)
            request_payload.pop("response_format", None)
            try:
                response = client.post(url, headers=headers, json=request_payload)
            except (httpx.ConnectError, httpx.ReadTimeout, httpx.RemoteProtocolError):
                if attempt >= max_attempts - 1:
                    raise
                time.sleep(min(2 ** attempt, 8))
                continue
        if response.status_code not in retryable_statuses:
            return response
        if attempt < max_attempts - 1:
            retry_after = response.headers.get("retry-after", "")
            delay = float(retry_after) if retry_after.replace(".", "", 1).isdigit() else min(2 ** attempt, 8)
            time.sleep(max(1, min(delay, 15)))
    return response


def _ai_json_content(response: httpx.Response) -> dict:
    """Return a validated JSON object from an OpenAI-compatible response.

    A few compatible gateways occasionally return an empty body, an empty
    assistant message, or a JSON string wrapped in a Markdown fence while
    still using HTTP 200.  Treat those as retryable provider output instead
    of leaking a low-level ``Expecting value`` error to the UI.
    """
    try:
        data = response.json()
    except ValueError as exc:
        raise ValueError("AI 服务返回了空响应或非 JSON 响应") from exc
    try:
        content = str(data["choices"][0]["message"]["content"] or "").strip()
    except (KeyError, IndexError, TypeError) as exc:
        raise ValueError("AI 服务响应中缺少有效回答") from exc
    if content.startswith("```"):
        content = content.split("\n", 1)[-1].rsplit("```", 1)[0].strip()
    if not content:
        raise ValueError("AI 服务返回了空回答")
    try:
        result = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ValueError("AI 服务未按约定返回结构化回答") from exc
    if not isinstance(result, dict):
        raise ValueError("AI 服务返回的回答结构不正确")
    return result


def _stream_ai_text(client: httpx.Client, url: str, headers: dict, payload: dict) -> tuple[str, str]:
    """Receive long plan generation incrementally so gateways see activity."""
    request_payload = dict(payload)
    request_payload["stream"] = True
    chunks: list[str] = []
    response_model = str(payload.get("model") or "")
    with client.stream("POST", url, headers=headers, json=request_payload) as response:
        response.raise_for_status()
        for line in response.iter_lines():
            line = line.strip()
            if not line or not line.startswith("data:"):
                continue
            data = line[5:].strip()
            if data == "[DONE]":
                break
            try:
                event = json.loads(data)
            except ValueError:
                continue
            response_model = str(event.get("model") or response_model)
            choices = event.get("choices") or []
            if not choices:
                continue
            delta = choices[0].get("delta") or {}
            content = delta.get("content")
            if content:
                chunks.append(str(content))
    if not chunks:
        raise ValueError("AI 流式响应没有返回方案内容")
    return "".join(chunks).strip(), response_model


def analyze_project_deployment(
    db: Session,
    project: Project,
    source_path: str,
    *,
    failure_context: str = "",
    previous_plan: dict | None = None,
    timeout_seconds: float = 360,
) -> dict | None:
    """Let the configured platform AI design the deployment from real source evidence."""
    config = _preferred_ai_config(db)
    if not config:
        return None
    root = Path(source_path)
    ignored = {".git", "node_modules", "dist", "build", "target", ".venv", "vendor"}
    files = [item for item in root.rglob("*") if item.is_file() and not any(part in ignored for part in item.relative_to(root).parts)]
    files.sort(key=lambda item: item.relative_to(root).as_posix())
    # Keep planning requests bounded. Large repositories previously sent a
    # huge directory listing plus source excerpts and could exceed an upstream
    # gateway's long-request window before generation even began.
    tree = [item.relative_to(root).as_posix() for item in files[:600]]
    preferred_names = {
        "README.md", "PROJECT_CONTEXT.yml", ".env", ".env.example", "package.json", "package-lock.json",
        "pnpm-lock.yaml", "yarn.lock", "pom.xml", "build.gradle", "settings.gradle", "requirements.txt",
        "pyproject.toml", "Pipfile", "go.mod", "Cargo.toml", "Dockerfile", "compose.yml", "compose.yaml",
        "docker-compose.yml", "docker-compose.yaml", "nginx.conf", "application.yml", "application.yaml",
        "application.properties", "vite.config.js", "vite.config.ts", "next.config.js", "next.config.mjs",
    }
    evidence = {}
    budget = 28_000
    candidates = sorted(files, key=lambda item: (0 if item.name in preferred_names or item.name.startswith("Dockerfile") else 1, len(item.relative_to(root).parts), item.as_posix()))
    for item in candidates:
        relative = item.relative_to(root).as_posix()
        if item.name not in preferred_names and not item.name.startswith("Dockerfile") and item.suffix.lower() not in {".json", ".yml", ".yaml", ".toml", ".xml", ".properties", ".js", ".mjs", ".cjs", ".ts", ".py", ".go", ".sh"}:
            continue
        try:
            text = item.read_text(errors="ignore")[:6_000]
        except OSError:
            continue
        if not text.strip():
            continue
        take = text[:max(0, budget)]
        evidence[relative] = take
        budget -= len(take)
        if budget <= 0:
            break
    deployment_mode = getattr(project, "deployment_mode", "managed_fresh") or "managed_fresh"
    managed_minio_image = discover_managed_minio_image(db)
    user_env = decrypt(project.env_text_encrypted) or ""
    integration_policy = {
        key: value for key, value in (
            (line.split("=", 1)[0].strip(), line.split("=", 1)[1].strip())
            for line in user_env.splitlines() if "=" in line and line.strip().startswith("YUNZHOU_")
        ) if key.endswith("_MODE") or key.endswith("_PORT") or key.endswith("_DATABASE")
    }
    if deployment_mode == "managed_fresh":
        integration_policy = {}
    runtime_policy = db.get(DeploymentSettings, "default")
    recommended_images = {
        "nginx": getattr(runtime_policy, "default_nginx_image", "nginx:1.30.3-alpine"),
        "redis": getattr(runtime_policy, "default_redis_image", "redis:7.4-alpine"),
        "mysql": getattr(runtime_policy, "default_mysql_image", "mysql:8.4"),
        "postgres": getattr(runtime_policy, "default_postgres_image", "postgres:16"),
    }
    experience_context = "\n".join(tree) + "\n" + "\n".join(
        f"{name}\n{text[:1200]}" for name, text in evidence.items()
    )
    learned_rows = rank_learning_experiences(
        db.query(DeploymentExperience).order_by(DeploymentExperience.updated_at.desc()).limit(500).all(),
        experience_context,
        limit=12,
    )
    now = datetime.now(timezone.utc)
    # Usage telemetry is advisory and may be updated by many simultaneous
    # analyses.  Use one atomic SQL expression instead of dirtying versioned
    # ORM rows; a stale telemetry counter must never abort source analysis or
    # a deployment.
    learned_ids = [row.id for row in learned_rows]
    if learned_ids:
        db.execute(
            update(DeploymentExperience)
            .where(DeploymentExperience.id.in_(learned_ids))
            .values(
                use_count=DeploymentExperience.use_count + 1,
                last_used_at=now,
            )
            .execution_options(synchronize_session=False)
        )
    learned_experience = [{
        "category": row.category,
        "stage": row.stage,
        "state": normalized_state(row),
        "confidence": experience_confidence(row.verified, row.successful_repairs, row.failed_repairs, row.occurrences),
        "scope_tags": infer_experience_tags(row.category, row.error_sample, row.repair_summary),
        "verified_success": bool(row.verified),
        "successful_repairs": row.successful_repairs,
        "failed_repairs": row.failed_repairs,
        "error_pattern": row.error_sample[:300],
        "lesson": row.repair_summary[:600],
    } for row in learned_rows]
    context = {
        "project": project.name,
        "requested_build_type": project.build_type,
        "deployment_mode": deployment_mode,
        "integration_policy": integration_policy,
        "recommended_runtime_images": recommended_images,
        "learned_deployment_experience": learned_experience,
        "file_tree": tree,
        "key_files": evidence,
    }
    if failure_context:
        context["failed_deployment"] = {
            "error": sanitize_learning_text(failure_context, 4000),
            "previous_plan": previous_plan if isinstance(previous_plan, dict) else {},
            "instruction": "必须修改导致失败的生成方案，禁止原样返回上一方案；修复后重新核对构建、启动和健康检查。",
        }
    schema = {
        "summary": "说明识别出的所有可运行模块、入口、模块调用、依赖、端口与选择理由",
        "build_strategy": "reuse、adapt 或 regenerate：分别表示仓库构建方案可直接复用、安全修订后复用、平台重新生成",
        "build_strategy_reason": "说明选择该策略的源码证据、保留内容、修改内容和不能直接复用的原因",
        "deployment_kind": "compose 或 dockerfile",
        "primary_file": "若 compose 固定为 .yunzhou.ai.compose.yml；若 dockerfile 固定为 .yunzhou.ai.Dockerfile",
        "compose_yaml": "完整 Compose YAML；dockerfile 模式为空字符串",
        "dockerfile": "完整且可执行的最终 Dockerfile；可来自安全复用、修订复用或平台重新生成，但必须写入平台发布文件",
        "container_port": 4300,
        "services": ["所有实际需要运行的服务名"],
        "traffic_plan": {
            "service_roles": [{"service": "服务名", "role": "frontend、backend、app、data 或 worker", "scalable": True}],
            "default_service": "接收 location / 的前端或单体服务名",
            "traffic_routes": [
                {"path": "从源码确认的真实接口前缀（如 /prod-api/；不得默认 /api/）", "service": "后端服务名", "strip_prefix": False},
                {"path": "/", "service": "前端或单体服务名", "strip_prefix": False},
            ],
        },
        "build_environment": [{"module": "前端或后端模块", "language": "Node/Java/Python/Go 等", "runtime_version": "源码确认的准确版本", "build_image": "用于构建的基础镜像", "package_manager": "pnpm/npm/Maven/Gradle及准确版本", "build_command": "实际构建命令", "artifact": "dist/JAR/WAR等产物路径", "runtime_image": "最终轻量运行镜像", "evidence": "版本与命令的源码依据"}],
        "access_path": "/",
        "auth_mode": "default_credentials、first_register、external_auth、none 或 unknown",
        "login_url_path": "/login；没有独立登录页则为 /",
        "login_username": "仅填写源码或初始化配置中可确认的默认登录账号，否则为空字符串",
        "login_password": "仅填写源码或初始化配置中可确认的初始密码，否则为空字符串",
        "login_note": "说明账号密码来源、首次注册方式、外部认证方式，或明确说明未发现默认账号",
        "mode_decision": "说明如何按照 deployment_mode 处理旧集成和托管依赖",
        "inferred_config": [{"key": "非敏感环境变量名", "value": "可确认的值", "source": "来源文件与依据", "confidence": "high"}],
        "required_user_config": [{"key": "必须由用户提供的变量", "reason": "不能自动填写的原因", "secret": True}],
    }
    prompt = (
        "你是自助发布平台的自主部署工程师。仓库没有固定目录和固定技术栈，目录名不能作为唯一依据。"
        "必须根据全仓目录树、依赖清单、启动脚本、源码入口、配置引用、监听端口和模块调用关系，识别单体、前后端分离或任意多服务架构，再给出可执行方案。"
        "Nginx、Redis、MySQL 与 PostgreSQL 都由平台按方案生成；版本优先级是用户明确指定、源码明确要求、context.recommended_runtime_images。源码没有版本要求时必须使用平台推荐，不得自行猜测其他版本。外置数据库或外置 Redis 不得创建对应容器。"
        "必须参考 context.learned_deployment_experience：verified_success=true 的经验可作为候选，但仍须由当前源码证据确认；未验证或失败次数较多的经验是反例，必须主动避免重复其错误。经验不能覆盖当前仓库的生产资产。"
        "仓库已有的生产 Dockerfile、Compose、Kubernetes Deployment、CI 发布脚本和 start:container 命令是重要参考证据，但不是可直接执行的发布产物。必须结合源码、依赖清单、锁文件、配置读取、入口、端口、健康检查、数据目录和服务关系重新预研；若证据明确只发布一个容器，应保持单容器拓扑，只有源码和生产证据共同证明需要多服务时才允许改变容器边界。"
        "Dockerfile/Compose 可能位于任意层级，也可能完全不存在。必须先逐项审计现有构建文件与真实源码是否一致，再选择 build_strategy：文件完整、路径存在、拓扑与源码一致、无旧环境绑定、无明文敏感信息、无危险挂载且兼容经典 Docker 时选 reuse；整体正确但需要改端口变量、环境变量引用、健康检查、旧地址或经典构建兼容性时选 adapt；缺文件、入口或拓扑错误、与源码明显不一致时选 regenerate。无论选择哪一种，都把最终方案写入 .yunzhou.ai.Dockerfile 和/或 .yunzhou.ai.compose.yml，保留可审计副本；不得直接覆盖用户源码。构建上下文必须与 COPY 路径匹配。"
        "构建策略必须采用多证据决策，禁止因为发现 Dockerfile 就默认源码重建。先分别建立“成品交付证据”和“源码构建证据”：成品证据包括 Compose 只有 image 无 build、固定且非 latest 的镜像版本、生产脚本执行 pull 后 up/run --no-build、Helm/Kubernetes 引用固定镜像、CI 明确负责构建并推送镜像、README 将源码构建标为开发方式，以及现成 entrypoint、healthcheck、env_file 和持久化语义；源码构建证据包括 Compose 明确 build、生产脚本执行 build/up --build、CI 只产出源码制品、镜像变量为空或仅为本地构建标签、用户明确要求源码构建。每项证据必须由实际文件路径和内容交叉验证，不能只靠文件名或 README 单点结论。"
        "当成品交付证据占优时选择 reuse 或 adapt：先验证镜像引用可拉取、tag/摘要固定、目标 CPU 架构兼容、镜像入口和暴露端口与 Compose/健康检查一致；验证通过后直接拉取并启动，不运行语言编译器、pip/npm/pnpm/yarn/Maven/Gradle，也不把源码目录作为大体积构建上下文发送给 Docker。端口转换为 ${YUNZHOU_HOST_PORT}:原容器端口，PUBLIC_URL、回调地址等环境绑定值由平台注入；保留已验证的服务拓扑、命令、健康检查、固定镜像版本和数据持久化语义。只有镜像不可用或架构不兼容、配置与入口矛盾、生产资产不完整，或源码构建证据明确占优时才选择 regenerate。"
        "当仓库同时存在 image 与 build 时，不得武断选择。必须检查 Compose profiles/override 文件、部署脚本传入的 -f 参数、环境变量、CI 工作流和实际执行命令，判断生产路径究竟是拉取成品镜像、以源码覆盖 image，还是两种都支持；选择与生产默认路径一致的方案，另一条路径只作为回退说明。Kubernetes/Helm、systemd、Makefile、Taskfile、shell/PowerShell 脚本和 CI/CD 均可构成同等级生产证据，不能只识别 docker-compose.yml。build_strategy_reason 必须列出采用证据、冲突证据、验证动作和最终决策，证据冲突且无法安全判定时应停止并准确说明，不能用耗时源码重建来掩盖不确定性。"
        "必须理解配置的真实读取链路，而不是只按文件名处理。检查 .env、.env.*、application.yml/properties、config.toml/json、启动脚本、代码默认值及容器环境覆盖顺序，并将每项配置分类：可移植的非敏感结构值可继承；旧域名/IP/回调地址等环境绑定值应转换或要求确认；密码、Token、Secret、Access Key 只能作为平台密钥注入；示例文件只提供字段证据，不能证明值应继承；可选功能不得升级为必填；核心依赖必须根据实际代码调用路径决定托管、外接或关闭。Compose 中 image、端口和 profile 等含变量表达式时，必须按 shell/项目 .env/Compose 默认值的真实优先级求出有效值；固定镜像版本是可移植的非敏感发布资产，不能用表达式中的默认回退版本替换。build_strategy_reason 必须概括这些分类结论。"
        "对 Node/Vite/TypeScript 等构建，必须检查源码中的跨目录 import；执行 build 前应复制完整构建上下文，不能只复制 src、public 等表面目录而遗漏 server、shared 或工作区包。"
        "前端、网关、后端模块和已生效的数据库必须全部纳入；不能只部署一个表面可访问的前端。"
        "前后端分离项目统一由平台网关负责转发和负载均衡。必须从实际生效的生产环境变量（VUE_APP_BASE_API、VITE_API_BASE_URL、VITE_BASE_API、API_BASE_URL、API_PREFIX）、运行时 postUrl.js/configUrl、请求客户端 baseURL、生产 Nginx location/proxy_pass 和后端上下文路径交叉识别唯一有效的公网接口前缀；禁止无证据写死 /api，也禁止把 development/stage/prod/profile 等所有别名一股脑发布。只生成源码实际需要的一条后端接口 location 和 location / 前端入口，并准确填写 strip_prefix；若运行时配置仍指向旧外部域名，只能改写为已由上述证据确认的相对接口前缀。前端 Nginx 只负责静态文件和 SPA 回退，不得 proxy_pass 后端。若项目本身是单体服务，则只生成 location /。traffic_plan 必须记录最终服务角色、实际前缀及源码证据。"
        "纯静态前端的 Nginx 运行配置由平台在产物构建后统一生成。AI Dockerfile 的 Nginx 最终阶段只需复制 dist/build/out 产物、EXPOSE 80 并以前台方式启动 Nginx；不要用 RUN echo/printf 写入 /etc/nginx/conf.d 或覆盖 /etc/nginx/nginx.conf。平台会生成最小 server/location 配置并执行 nginx -t。"
        "在不改变仓库既有生产拓扑的前提下采用多阶段构建：前端按项目真实运行方式选择静态产物或 Node 网关运行；Java 在 Maven/Gradle 镜像构建并将 JAR/WAR 放入 JRE。不得把编译器、Maven/Gradle 本地仓库或包管理器缓存带入最终镜像。项目生产入口明确用 concurrently/supervisor 组织多个强耦合进程时允许保留，不得机械拆分。数据库、Redis 等是否独立托管仍按 deployment_mode 与 integration_policy 决定。"
        "生成的构建文件必须让经典 Docker 构建缓存可复用。普通 Node 项目应先只 COPY package.json 与实际 lockfile，单独 RUN npm/pnpm/yarn 安装，再 COPY 完整源码并执行 build；不得在依赖安装前 COPY 全部源码，也不得把 install 与 build 合并为同一个 RUN。Maven/Gradle 项目应先复制构建描述文件并单独解析依赖，再复制源码执行打包。工作区或多模块项目必须包含所有父级与子模块描述文件，不能为缓存而破坏模块关系。"
        "平台禁用 BuildKit/buildx。生成文件不得包含 # syntax=docker/dockerfile、RUN --mount、COPY --link、Dockerfile heredoc 或其他仅 BuildKit 支持的语法，也不得要求 --no-cache。若参考文件依赖这些能力，必须先研究等价的经典构建写法；无法安全转换时要在 mode_decision 中准确说明阻断语法和风险，不得偷偷切换构建器。"
        "选择构建镜像前必须先从 package.json 的 engines/packageManager、lockfile 版本、.nvmrc、Maven/Gradle Wrapper、pom.xml 的 java.version/compiler/toolchain、现有 Dockerfile 和 CI 配置交叉确认 Node、包管理器、JDK 与构建工具版本；不得凭经验随意升级。Corepack prepare 必须使用可解析的完整包管理器版本（例如 pnpm@8.15.9），禁止只写 pnpm@8 这类主版本。必须识别真实构建命令、模块路径以及 dist/build/JAR/WAR 等产物位置。"
        "最终运行镜像以小且兼容为目标：纯静态前端优先 Nginx Alpine；Java 优先匹配版本的 JRE；存在 native addon、glibc、字体、浏览器或系统库要求时应选择兼容的 slim/glibc 镜像，不得为了体积盲目使用 Alpine。最终阶段不得包含源码、node_modules、Maven/Gradle 本地仓库、编译器、包管理器缓存或构建工具。"
        "Compose 对外端口必须写 ${YUNZHOU_HOST_PORT}:容器端口。MySQL 密码使用 ${CRM_DB_PASSWORD} 和 ${CRM_DB_ROOT_PASSWORD}，不得编造密钥。"
        "数据库和业务文件使用命名卷。不得使用 privileged、host network、宿主机绝对路径、Docker socket、devices 或任意命令。"
        "Dockerfile 与 Compose 必须使用镜像的标准官方名称（如 node:22、mysql:8.4、minio/minio:latest），不得把镜像代理站域名写进镜像名；目标服务器 Docker daemon.json 会负责镜像加速。依赖包管理器可优先使用中国大陆可访问的软件源。不要假定服务名称必须是 frontend/backend/db。"
        "还必须检查 README、初始化脚本、种子数据、认证源码和环境变量示例，判断应用如何登录。"
        "若应用依赖 MySQL/PostgreSQL 等数据库，必须查找建表 SQL、迁移工具或 ORM 自动建表机制，并将初始化方式纳入 Compose；不能只创建空数据库。若仓库确实没有初始化资产，应在方案摘要和 required_user_config 中明确指出，禁止假装服务可用。"
        "只有源码证据明确时才能返回默认账号和密码，不得猜测；没有默认账号时必须说明首次注册、外部认证或未发现登录要求。"
        "必须遵守 context.deployment_mode：managed_fresh 表示全新托管部署，应为应用正常核心功能自动加入适合自建的标准依赖（如 MySQL、Redis、MinIO），生成随机凭据引用、命名卷和容器内服务地址；旧环境地址不得继承。源码可选的 OIDC、短信、支付等外部业务集成默认关闭，不得把其变量写成 Compose 必填项。"
        "preserve_integrations 表示只保留用户逐项勾选为 external 的现有集成；未勾选、值为 managed 的 MySQL/Redis 仍必须由平台创建托管服务。必须区分源码真正必需和可选配置，可选配置不得升级为 Compose 必填项，真正缺失且已选择 external 的外部地址或密钥才保留为待用户填写项。"
        "只有 deployment_mode=preserve_integrations 时才遵守 context.integration_policy 的逐服务选择；managed_fresh 时 integration_policy 必须视为空，严禁复用任何旧 external 选择。preserve_integrations 下 YUNZHOU_MYSQL_MODE=external 时不得创建 MySQL 容器，应用连接必须由 YUNZHOU_MYSQL_HOST、YUNZHOU_MYSQL_PORT、YUNZHOU_MYSQL_DATABASE、YUNZHOU_MYSQL_USERNAME、YUNZHOU_MYSQL_PASSWORD 组合并映射到源码实际读取的变量；值为 managed 或未选择 external 时可由平台创建托管 MySQL。Redis 同理使用 YUNZHOU_REDIS_MODE 以及 YUNZHOU_REDIS_HOST、PORT、PASSWORD、DATABASE。不得把用户凭据写入生成文件，只能引用变量。"
        f"MinIO 社区官方预构建镜像已停止公开分发。平台刚从受信任兼容项目的实时标签清单选出 {managed_minio_image}。仅当 managed_fresh 且源码确实依赖 S3/MinIO 时使用该镜像，保留 MINIO_ROOT_USER、MINIO_ROOT_PASSWORD、server /data、/minio/health/live 与 S3 API 兼容方式；禁止使用 minio/minio、quay.io/minio/minio、dhi.io/minio 或任何 latest 标签。preserve_integrations 下已有外部 MinIO 地址必须保留，不得改为自建。"
        "生成 Compose 前必须检查变量在源码中的读取方式；若源码使用 ||、??、optional() 或其他默认回退，该变量严禁写成 ${VAR:?错误}，应省略或使用允许为空的默认形式。环境变量示例文件中的旧值本身不能证明变量必填。"
        "将源码或有效配置文件中能够明确确认的非敏感地址、端口、桶名、公开回调地址写入 inferred_config，并注明来源；不得返回示例值、省略号、占位符、localhost猜测值。"
        "密码、Secret、Token、Access Key、Private Key及无法确认的外部地址只能写入 required_user_config，绝不能放入 inferred_config。"
        "build_environment 必须逐个可运行模块填写；版本无法确认时明确写 unknown 并在 evidence 说明缺少依据，不得省略该字段。"
        "只返回严格 JSON，结构为：" + json.dumps(schema, ensure_ascii=False)
    )
    if failure_context:
        prompt += (
            "context.failed_deployment 表示上一轮真实失败。你现在处于自动修复模式，必须根据错误修改生成文件，"
            "不得原样复述或返回 previous_plan。只修平台生成的部署文件，不修改用户业务源码；"
            "对 Nginx、Compose、端口、健康检查、依赖构建等平台可控问题必须给出可执行的新方案。"
        )
    url = config.base_url.rstrip("/") + "/chat/completions"
    payload = {"model": config.model, "response_format": {"type": "json_object"}, "messages": [
        {"role": "system", "content": prompt},
        {"role": "user", "content": json.dumps(context, ensure_ascii=False)},
    ]}
    headers = {"Authorization": "Bearer " + (decrypt(config.api_key_encrypted) or "")}
    # Full repository plans can take several minutes. Stream tokens as they are
    # generated so an upstream gateway does not treat active generation as an
    # idle request and return 504 before the JSON plan is complete.
    with httpx.Client(
        proxy=proxy_for(db, url),
        trust_env=False,
        timeout=max(30, min(float(timeout_seconds), 360)),
    ) as client:
        content, response_model = _stream_ai_text(client, url, headers, payload)
    if content.startswith("```"):
        content = content.split("\n", 1)[-1].rsplit("```", 1)[0].strip()
    result = json.loads(content)
    result["source"] = "ai"
    result["provider"] = config.provider_name
    result["requested_model"] = config.model
    result["model"] = response_model or config.model
    result["managed_minio_image"] = managed_minio_image
    _apply_effective_production_images(root, result)
    return result


def analyze_backup_scope(db: Session, inventory: dict) -> dict:
    config = _preferred_ai_config(db)
    fallback = {"source": "system", "summary": "已按项目结构识别源码，并排除可重新安装的依赖、缓存、日志和构建产物。", "source_types": inventory.get("source_types", []), "excluded": inventory.get("excluded", [])}
    if not config:
        return fallback
    url = config.base_url.rstrip("/") + "/chat/completions"
    payload = {"model": config.model, "response_format": {"type": "json_object"}, "messages": [
        {"role": "system", "content": "你是平台内置备份分析助手。根据目录摘要判断技术栈和备份范围，返回严格 JSON：{\"summary\":\"中文简述\",\"source_types\":[\"识别到的源码类型\"],\"excluded\":[\"可重建依赖或缓存\"]}。不得建议排除用户源码、配置文件、数据库迁移或锁文件。"},
        {"role": "user", "content": json.dumps(inventory, ensure_ascii=False)},
    ]}
    headers = {"Authorization": "Bearer " + (decrypt(config.api_key_encrypted) or "")}
    try:
        with httpx.Client(proxy=proxy_for(db, url), trust_env=False, timeout=45) as client:
            response = _post_ai(client, url, headers, payload)
            response.raise_for_status()
        content = response.json()["choices"][0]["message"]["content"].strip()
        if content.startswith("```"):
            content = content.split("\n", 1)[-1].rsplit("```", 1)[0].strip()
        result = json.loads(content)
        return {"source": "ai", "model": config.model, "summary": str(result.get("summary", fallback["summary"])), "source_types": list(result.get("source_types") or inventory.get("source_types", [])), "excluded": list(result.get("excluded") or inventory.get("excluded", []))}
    except Exception:
        return fallback


def analyze_delete_scope(db: Session, inventory: dict) -> dict:
    """Explain a verified deletion inventory without allowing AI to expand its scope."""
    counts = inventory.get("counts", {})
    fallback = {
        "source": "system",
        "summary": (
            f"已核实本次发布关联 {counts.get('containers', 0)} 个容器、"
            f"{counts.get('images', 0)} 个应用镜像、{counts.get('directories', 0)} 个发布目录和"
            f"{counts.get('gateway_files', 0)} 个网关文件。只清理清单内资源，持久化数据和其他版本保留。"
        ),
    }
    config = _preferred_ai_config(db)
    if not config:
        return fallback
    url = config.base_url.rstrip("/") + "/chat/completions"
    payload = {"model": config.model, "response_format": {"type": "json_object"}, "messages": [
        {"role": "system", "content": "你是平台内置资源清理分析助手。只能根据系统已经核实的清单解释本次删除范围，返回严格 JSON：{\"summary\":\"中文简述\"}。不得增加清单外资源，不得生成命令，必须说明持久化数据、项目源码和其他发布版本会保留。"},
        {"role": "user", "content": json.dumps(inventory, ensure_ascii=False)},
    ]}
    headers = {"Authorization": "Bearer " + (decrypt(config.api_key_encrypted) or "")}
    try:
        with httpx.Client(proxy=proxy_for(db, url), trust_env=False, timeout=20) as client:
            response = _post_ai(client, url, headers, payload)
            response.raise_for_status()
        content = response.json()["choices"][0]["message"]["content"].strip()
        if content.startswith("```"):
            content = content.split("\n", 1)[-1].rsplit("```", 1)[0].strip()
        result = json.loads(content)
        return {"source": "ai", "model": config.model, "summary": str(result.get("summary") or fallback["summary"])}
    except Exception:
        return fallback


def understand(db: Session, message: str, project_id: str | None, node_id: str | None, ai_config_id: str | None = None, history: list[dict[str, str]] | None = None) -> dict:
    config = db.get(AiConfig, ai_config_id) if ai_config_id else None
    if config and not config.enabled:
        config = None
    if not config:
        config = _preferred_ai_config(db, require_key=False)
    projects = db.query(Project).all()
    nodes = db.query(Node).filter(Node.enabled.is_(True)).all()
    context = {
        "selected_project_id": project_id,
        "selected_node_id": node_id,
        "projects": [{"id": x.id, "name": x.name, "slug": x.slug} for x in projects],
        "nodes": [{"id": x.id, "name": x.name, "status": x.last_status} for x in nodes],
        "project_env_keys": {
            x.id: [
                line.split("=", 1)[0].strip()
                for line in "\n".join(filter(None, (x.managed_env_text or "", decrypt(x.env_text_encrypted) or ""))).splitlines()
                if "=" in line and not line.lstrip().startswith("#")
            ]
            for x in projects
        },
    }
    selected_project = db.get(Project, project_id) if project_id else None
    if selected_project:
        recent = (
            db.query(Deployment)
            .filter(Deployment.project_id == selected_project.id)
            .order_by(Deployment.created_at.desc())
            .limit(8)
            .all()
        )
        context["selected_project"] = {
            "id": selected_project.id,
            "name": selected_project.name,
            "slug": selected_project.slug,
            "source_type": selected_project.source_type.value,
            "build_type": selected_project.build_type,
            "container_port": selected_project.container_port,
            "configured_host_port": selected_project.host_port,
            "domain": selected_project.domain,
            "deployment_mode": selected_project.deployment_mode,
            "analysis": selected_project.source_analysis,
            "recent_deployments": [
                {
                    "id": item.id,
                    "status": item.status.value,
                    "release": item.release,
                    "node_id": item.node_id,
                    "host_port": item.host_port,
                    "access_url": item.access_url,
                    "created_at": item.created_at.isoformat() if item.created_at else None,
                    "started_at": item.started_at.isoformat() if item.started_at else None,
                    "finished_at": item.finished_at.isoformat() if item.finished_at else None,
                    "error": item.error,
                    "recent_log": (item.log_text or "")[-2500:],
                }
                for item in recent
            ],
        }
    if config and config.api_key_encrypted:
        url = config.base_url.rstrip("/") + "/chat/completions"
        payload = {
            "model": config.model,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": SYSTEM},
                *[
                    {"role": "assistant" if item.get("role") == "assistant" else "user", "content": str(item.get("content") or "")[:2000]}
                    for item in (history or [])[-10:]
                    if item.get("content")
                ],
                {"role": "user", "content": "平台实时上下文：" + json.dumps(context, ensure_ascii=False, default=str) + "\n本轮用户问题：" + message},
            ],
        }
        headers = {"Authorization": "Bearer " + (decrypt(config.api_key_encrypted) or "")}
        last_parse_error: ValueError | None = None
        with httpx.Client(proxy=proxy_for(db, url), trust_env=False, timeout=60) as client:
            for attempt in range(2):
                response = _post_ai(client, url, headers, payload, max_attempts=2)
                response.raise_for_status()
                try:
                    return _ai_json_content(response)
                except ValueError as exc:
                    last_parse_error = exc
                    if attempt == 0:
                        time.sleep(1)
        raise RuntimeError(f"{last_parse_error or 'AI 服务返回内容格式异常'}，平台自动重试后仍未恢复，请稍后重试")

    wants_deploy = any(word in message for word in ("部署", "发布", "上线", "重新发布"))
    project = next((x for x in projects if x.id == project_id), None)
    node = next((x for x in nodes if x.id == node_id), None)
    if not project:
        project = next((x for x in projects if x.name in message or x.slug in message), None)
    if not node:
        node = next((x for x in nodes if x.name in message), None)
    if wants_deploy and project and node:
        return {"action": "deploy", "project_id": project.id, "node_id": node.id, "reply": f"已创建 {project.name} 到 {node.name} 的部署任务。"}
    if wants_deploy and not projects:
        reply = "还没有项目，请先上传源码或添加 Git 仓库。"
    elif wants_deploy and not nodes:
        reply = "还没有可用节点，请让管理员先添加服务器。"
    elif wants_deploy and not project:
        reply = "请选择要部署的项目。"
    elif wants_deploy and not node:
        reply = "请选择目标服务器节点。"
    else:
        reply = "我可以帮你部署项目。请选择项目和节点，然后输入“部署这个项目”。"
    return {"action": "none", "project_id": None, "node_id": None, "reply": reply}


def deployment_followup(db: Session, deployment: Deployment, project: Project, node: Node, stage: str, stage_log: str) -> dict:
    normalized_log = stage_log.upper()
    if "INVALID ARGUMENT SYNTAX:" in normalized_log:
        evidence = next(
            (line.strip() for line in stage_log.splitlines() if "Invalid argument syntax:" in line),
            "Invalid argument syntax",
        )
        return {
            "source": "system",
            "summary": "后端启动参数包含空的可选项，Spring Boot 在应用初始化前拒绝启动。",
            "advice": "平台将删除形如 --配置项= 的空参数，保留所有非空配置后重新发布。",
            "scope": "configuration",
            "confidence": "high",
            "evidence": [evidence[:300]],
            "retry_safe": True,
        }
    if "WRONGPASS" in normalized_log or "NOAUTH" in normalized_log:
        return {
            "source": "system",
            "summary": "Redis 已正常启动，但健康检查使用的凭据与 Redis 实际启动凭据不一致。",
            "advice": "平台将统一 Redis 启动参数、健康检查和应用连接的托管密码，并仅重建 Redis 容器；持久化数据卷保持不变。",
            "scope": "configuration",
            "confidence": "high",
            "evidence": ["AUTH failed: WRONGPASS invalid username-password pair"],
            "retry_safe": True,
        }
    config = _preferred_ai_config(db)
    context = {"project": project.name, "node": node.name, "status": deployment.status.value, "stage": stage, "release": deployment.release, "access_url": deployment.access_url, "host_port": deployment.host_port, "error": deployment.error, "recent_log": stage_log[-4000:]}
    if not config:
        return {"source": "system", "summary": f"当前处于“{stage}”阶段，状态为 {deployment.status.value}。", "advice": "持续读取流水线日志。", "scope": "unknown", "confidence": "low", "evidence": [], "retry_safe": False}
    url = config.base_url.rstrip("/") + "/chat/completions"
    payload = {"model": config.model, "response_format": {"type": "json_object"}, "messages": [
        {"role": "system", "content": "你是平台内置部署诊断助手。根据真实日志用中文返回严格 JSON：{\"summary\":\"直接说明当前状态或失败根因\",\"advice\":\"可执行修复方向\",\"scope\":\"platform|dependency_network|source|configuration|credentials|runtime|unknown\",\"confidence\":\"high|medium|low\",\"evidence\":[\"原始日志中的关键短句，最多3条\"],\"retry_safe\":true或false}。必须提取最早且最具体的错误，区分平台构建器/容器引擎、依赖网络、编译器兼容、源码编译、配置、凭据和运行故障。只有日志存在明确编译器或测试错误时才能判为 source；证据不足必须返回 unknown，严禁把未命中自动修复规则等同于源码问题。MyBatis 的 Bean already defined、Skipping MapperFactoryBean、No MyBatis mapper was found 如果日志级别为 WARN 且后续 Tomcat/Spring 仍继续初始化，只能记为非阻断警告，绝不能宣称它导致启动失败。snapshot/snapshotter/lease/CreateDiff/content store/daemon EOF 属于 platform。不得只复述 exit code 或 Maven/Docker 通用提示，不得编造已完成步骤，不得生成或执行命令。retry_safe 仅表示在不修改用户源码、不猜测凭据且有确定性修复规则时可以重试。host_port 是目标应用服务器内网端口，access_url 是平台网关对外端口，两者不同是正常映射。若状态成功但 access_url 为空，明确指出尚未识别访问地址；健康状态不是 healthy 时提醒等待或排查。若 minio/minio 或 quay.io/minio/minio 被 denied、unauthorized 或 not found，应判断为旧社区镜像停止公开分发，不得归因于镜像代理。"},
        {"role": "user", "content": json.dumps(context, ensure_ascii=False)},
    ]}
    headers = {"Authorization": "Bearer " + (decrypt(config.api_key_encrypted) or "")}
    with httpx.Client(proxy=proxy_for(db, url), trust_env=False, timeout=90) as client:
        response = _post_ai(client, url, headers, payload)
        response.raise_for_status()
    content = response.json()["choices"][0]["message"]["content"].strip()
    if content.startswith("```"):
        content = content.split("\n", 1)[-1].rsplit("```", 1)[0].strip()
    result = json.loads(content)
    scope = str(result.get("scope") or "unknown")
    if scope not in {"platform", "dependency_network", "source", "configuration", "credentials", "runtime", "unknown"}:
        scope = "unknown"
    confidence = str(result.get("confidence") or "low")
    if confidence not in {"high", "medium", "low"}:
        confidence = "low"
    evidence = [str(item)[:300] for item in (result.get("evidence") or [])[:3]]
    return {
        "source": "ai", "model": config.model,
        "summary": str(result.get("summary", "")), "advice": str(result.get("advice", "")),
        "scope": scope, "confidence": confidence, "evidence": evidence,
        "retry_safe": bool(result.get("retry_safe", False)),
    }

