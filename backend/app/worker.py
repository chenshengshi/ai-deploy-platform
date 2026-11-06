import time
import shutil
import json
import hashlib
import re
import shlex
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import select

from .config import settings
from .database import Base, SessionLocal, engine
from .deployer import (
    cleanup_incomplete_release_images,
    deployment_compose_project_name,
    execute,
    platform_gateway_node,
    stop_deployment,
)
from .experience import prepare_new_experience, sanitize_learning_text
from .models import DeployStatus, Deployment, DeploymentExperience, DeploymentSettings, Node, Project
from .ssh import SSHNode


# Prefer one well-supported repair over repeated speculative rebuilds. A
# second attempt is reserved for a genuinely different follow-up failure.
MAX_AI_RETRIES = 2
DEFERRED_CLEANUP_MARKER = "[待清理] 已登记本次失败版本镜像"
DEFERRED_CLEANUP_DONE_MARKER = "[后台清理完成]"


REPAIR_EVIDENCE_PREFIXES = (
    "[方案]", "[配置预填]", "[配置预检]", "[识别]", "[托管服务]",
    "[配置生成]", "[AI自动修复]", "[平台自愈]", "[数据服务自动修复]",
    "[访问路径修正]", "[版本回退]",
)


def deployment_repair_evidence(log_text: str | None, limit: int = 12) -> list[str]:
    """Extract concrete, secret-free repair actions from a real deployment."""
    evidence = []
    for raw_line in (log_text or "").splitlines():
        line = raw_line.strip()
        if not line.startswith(REPAIR_EVIDENCE_PREFIXES):
            continue
        if any(fragment in line for fragment in (
            "已创建后续修复任务", "正在对隔离发布副本", "正在根据真实错误生成修复方案",
        )):
            continue
        cleaned = sanitize_learning_text(line, 500)
        if cleaned and cleaned not in evidence:
            evidence.append(cleaned)
    return evidence[-max(1, limit):]


def deployment_error_signature(error: str) -> tuple[str, str, str]:
    """Create a stable, secret-free fingerprint for cross-project learning."""
    text = (error or "").lower()
    text = re.sub(r"\x1b\[[0-9;?]*[a-zA-Z]", " ", text)
    text = re.sub(r"https?://\S+", "<url>", text)
    text = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "<ip>", text)
    text = re.sub(r"\b[0-9a-f]{12,}\b", "<id>", text)
    text = re.sub(r"\b\d+\b", "<n>", text)
    text = re.sub(r"(?i)(password|token|secret|api[_-]?key)\s*[=:]\s*\S+", r"\1=<redacted>", text)
    text = re.sub(r"\s+", " ", text).strip()[-4000:]
    if "target stage" in text and "could not be found" in text:
        category = "docker_target_mismatch"
        fingerprint_text = "target stage <stage> could not be found"
    elif "eisdir" in text and ("readfilesync" in text or "illegal operation on a directory" in text):
        category = "file_path_expected_but_directory_supplied"
        fingerprint_text = "application expected a file path but deployment supplied a mounted directory"
    elif "lockfile" in text:
        category = "dependency_lockfile"
        fingerprint_text = "dependency lockfile is incompatible or stale"
    elif (
        "unexpected eof" in text
        or "docker daemon" in text
        or ("snapshot" in text and ("does not exist" in text or "not found" in text))
        or "snapshotter" in text
        or "creatediff" in text
    ):
        category = "docker_engine_interruption"
        fingerprint_text = "docker engine, snapshotter, or build stream became unavailable"
    elif "connection" in text or "timeout" in text:
        category = "network_or_startup"
        fingerprint_text = next((part for part in text.split(". ") if "connection" in part or "timeout" in part), text[-500:])
    elif "unhealthy" in text or "健康" in text:
        category = "healthcheck"
        fingerprint_text = next((part for part in text.split(". ") if "unhealthy" in part or "健康" in part), text[-500:])
    else:
        category = "unknown"
        fragments = re.findall(r"[^.]{0,500}(?:error|failed|exception|失败|错误)[^.]{0,500}", text)
        fingerprint_text = fragments[-1] if fragments else text[-500:]
    signature = hashlib.sha256((category + "|" + fingerprint_text).encode("utf-8")).hexdigest()
    return signature, category, text[-1200:]


def remember_deployment_outcome(db, deployment: Deployment) -> DeploymentExperience | None:
    """Learn only from real outcomes; successful retries become reusable knowledge."""
    previous = None
    if (deployment.trigger or "").startswith(("ai_autofix_", "ai_watchdog")):
        previous = db.scalars(
            select(Deployment).where(
                Deployment.project_id == deployment.project_id,
                Deployment.node_id == deployment.node_id,
                Deployment.status == DeployStatus.failed,
                Deployment.created_at < deployment.created_at,
            ).order_by(Deployment.created_at.desc())
        ).first()
    # A successful retry validates the repair for its predecessor. A failed
    # retry may expose a new root cause and must be learned under its own
    # fingerprint rather than incorrectly counting against the old repair.
    source_error = (
        previous.error
        if previous and deployment.status == DeployStatus.success
        else deployment.error
    ) or ""
    if not source_error:
        return None
    signature, category, sample = deployment_error_signature(source_error)
    item = db.scalar(select(DeploymentExperience).where(DeploymentExperience.signature == signature))
    if not item:
        item = DeploymentExperience(signature=signature, category=category, error_sample=sample)
        db.add(item)
    else:
        item.occurrences = (item.occurrences or 0) + 1
    if previous and deployment.status == DeployStatus.success:
        item.successful_repairs = (item.successful_repairs or 0) + 1
        item.verified = True
        item.last_verified_at = datetime.now(timezone.utc)
        repair_actions = deployment_repair_evidence(deployment.log_text)
        item.repair_summary = json.dumps({
            "category": category,
            "outcome": "verified_success",
            "repair_trigger": deployment.trigger,
            "repair_actions": repair_actions,
            "experience": "优先复用这些真实成功动作，但必须按当前源码重新校验，不能只凭历史结论直接构建",
            "verification": ["构建完成", "服务启动", "健康检查", "访问验证"],
            "learned_at": datetime.now(timezone.utc).isoformat(),
        }, ensure_ascii=False)
        deployment.log_text = ((deployment.log_text or "") +
            f"\n[AI学习] 已总结并验证部署经验：{category}；后续同类项目将优先复用，并重新执行全部验证。\n"
        )[-200_000:]
    elif (deployment.trigger or "").startswith("ai_autofix_") and deployment.status == DeployStatus.failed:
        item.failed_repairs = (item.failed_repairs or 0) + 1
        failed_actions = deployment_repair_evidence(deployment.log_text)
        if failed_actions and not item.verified:
            item.repair_summary = json.dumps({
                "category": category,
                "outcome": "failed_counterexample",
                "attempted_actions": failed_actions,
                "experience": "这些动作未解决当前错误，后续分析不得原样重复，必须结合新的源码或运行证据调整方案",
                "learned_at": datetime.now(timezone.utc).isoformat(),
            }, ensure_ascii=False)
    prepare_new_experience(item)
    db.commit()
    return item


def _tree_size(path):
    total = 0
    for item in path.rglob("*"):
        try:
            if item.is_file():
                total += item.stat().st_size
        except OSError:
            continue
    return total


def maintain_builder_storage() -> None:
    """Bound reusable build storage, but only while no deployment is active."""
    root = settings.build_data_root.rstrip("/") + "/builder"
    with SessionLocal() as db:
        active_count = db.query(Deployment).filter(
            Deployment.status.in_([DeployStatus.queued, DeployStatus.running])
        ).count()
        existing_project_slugs = set(db.scalars(select(Project.slug)).all())
        builder = platform_gateway_node(db)
        db.commit()
    if active_count or not builder:
        return
    now = time.time()
    project_root = Path(root) / "projects"
    for project_dir in project_root.iterdir() if project_root.exists() else []:
        if project_dir.is_dir() and project_dir.name not in existing_project_slugs:
            shutil.rmtree(project_dir, ignore_errors=True)
    # Cache leaves are <project>/<service>/<architecture>. Delete least recently
    # used leaves until the configured platform-wide limit is satisfied.
    leaves = []
    if project_root.exists():
        for project_dir in project_root.iterdir():
            cache_root = project_dir / "cache"
            for service_dir in cache_root.iterdir() if cache_root.exists() else []:
                if not service_dir.is_dir():
                    continue
                for arch_dir in service_dir.iterdir():
                    if arch_dir.is_dir():
                        try:
                            leaves.append((arch_dir.stat().st_mtime, _tree_size(arch_dir), arch_dir))
                        except OSError:
                            continue
    total = sum(size for _mtime, size, _path in leaves)
    disk = shutil.disk_usage(settings.build_data_root)
    reserve = max(1, settings.builder_min_free_gb) * 1024 ** 3
    # A zero cache limit means unlimited: keep useful caches until disk free
    # space reaches the safety floor. A positive value remains available for
    # installations that explicitly want a hard cap.
    free_space_limit = max(0, disk.free + total - reserve)
    configured_limit = settings.build_cache_max_gb * 1024 ** 3
    limit = min(configured_limit, free_space_limit) if configured_limit > 0 else free_space_limit
    for _mtime, size, path in sorted(leaves):
        if total <= limit:
            break
        shutil.rmtree(path, ignore_errors=True)
        total -= size
    with SSHNode(builder) as ssh:
        _code, cleanup_output = ssh.run(
            "removed=0; "
            "for id in $(docker ps -aq --filter status=exited); do "
            "labels=$(docker inspect -f '{{len .Config.Labels}}' $id 2>/dev/null || echo 1); "
            "mounts=$(docker inspect -f '{{len .Mounts}}' $id 2>/dev/null || echo 1); "
            "image=$(docker inspect -f '{{.Image}}' $id 2>/dev/null || true); "
            "tags=$(docker image inspect -f '{{json .RepoTags}}' $image 2>/dev/null || echo tagged); "
            "test \"$labels\" = 0 -a \"$mounts\" = 0 -a \"$tags\" = null || continue; "
            "docker rm $id >/dev/null && removed=$((removed+1)); done; echo CLASSIC_BUILD_CONTAINERS_REMOVED=$removed; "
            f"docker builder prune -af --filter until=168h --keep-storage {max(1, settings.docker_build_cache_keep_gb)}GB >/dev/null 2>&1 || true; "
            "docker image prune -f --filter dangling=true --filter until=24h >/dev/null 2>&1 || true"
        )
        if cleanup_output.strip():
            print(cleanup_output.strip(), flush=True)


def process_deferred_failed_image_cleanup() -> None:
    """Clean failed/cancelled release images only when the build queue is idle."""
    with SessionLocal() as db:
        active_count = db.query(Deployment).filter(
            Deployment.status.in_([DeployStatus.queued, DeployStatus.running])
        ).count()
        if active_count:
            return
        candidates = db.scalars(
            select(Deployment)
            .where(Deployment.status.in_([DeployStatus.failed, DeployStatus.stopped]))
            .order_by(Deployment.finished_at, Deployment.created_at)
        ).all()
        candidates = [
            item for item in candidates
            if DEFERRED_CLEANUP_MARKER in (item.log_text or "")
            and DEFERRED_CLEANUP_DONE_MARKER not in (item.log_text or "")
        ]
        for item in candidates:
            project = db.get(Project, item.project_id)
            node = db.get(Node, item.node_id)
            if not project or not node:
                item.log_text = ((item.log_text or "") +
                    "[后台清理完成] 项目或节点已删除，无可定位的失败镜像\n"
                )[-200_000:]
                db.commit()
                continue
            try:
                report = cleanup_incomplete_release_images(db, item, project, node, item.release)
                item.log_text = ((item.log_text or "") +
                    f"[后台清理完成] 构建队列已空闲，本次失败版本镜像已删除并复查：{report}\n"
                )[-200_000:]
                db.commit()
            except Exception as exc:
                item.log_text = ((item.log_text or "") +
                    f"[后台清理待重试] 空闲清理未完成：{exc}\n"
                )[-200_000:]
                db.commit()


def missing_maven_reactor_module(error: str, project: Project | None) -> bool:
    """Recognize a local Maven module mistaken for a remote dependency.

    A missing private third-party artifact is not safe to retry. A missing
    artifact whose artifactId is declared by a pom.xml in the same checked-out
    repository is different: it is a reactor/cache-ordering problem and the
    platform can safely rebuild it with the multi-module strategy.
    """
    if not project:
        return False
    match = re.search(
        r"could not find artifact\s+[a-z0-9_.-]+:([a-z0-9_.-]+):(?:[a-z0-9_.-]+:)*[a-z0-9_.-]+",
        error.lower(),
    )
    if not match:
        return False
    artifact_id = match.group(1)
    source = Path(settings.build_data_root) / "builder" / "projects" / project.slug / "source-cache"
    if not source.is_dir():
        return False
    marker = f"<artifactId>{artifact_id}</artifactId>".lower()
    for pom in source.rglob("pom.xml"):
        try:
            if marker in pom.read_text(encoding="utf-8", errors="ignore").lower():
                return True
        except OSError:
            continue
    return False


def repair_empty_managed_postgres_volume(db, failed: Deployment, project: Project | None) -> bool:
    """Remove only a tiny, incomplete platform-managed PostgreSQL initialization."""
    error = (failed.error or "").lower()
    if (
        not project
        or project.deployment_mode != "managed_fresh"
        or "pg_control" not in error
        or "could not find the database system" not in error
    ):
        return False
    node = db.get(Node, failed.node_id)
    if not node:
        return False
    compose_project = "yz-" + project.slug
    command = (
        "repaired=0; "
        "for v in $(docker volume ls -q --filter label=com.docker.compose.project=" + compose_project + "); do "
        "role=$(docker volume inspect -f '{{index .Labels \"com.docker.compose.volume\"}}' \"$v\" 2>/dev/null || true); "
        "case \"$role\" in *postgres*) ;; *) continue;; esac; "
        "test -z \"$(docker ps -aq --filter volume=$v)\" || continue; "
        "mp=$(docker volume inspect -f '{{.Mountpoint}}' \"$v\"); "
        "test -n \"$mp\" || continue; "
        "test -z \"$(find \"$mp\" -path '*/global/pg_control' -type f -print -quit 2>/dev/null)\" || continue; "
        "size=$(du -sk \"$mp\" 2>/dev/null | awk '{print $1}'); "
        "test \"${size:-999999}\" -lt 1024 || continue; "
        "docker volume rm \"$v\" >/dev/null && echo \"REPAIRED:$v\" && repaired=1; "
        "done; test $repaired -eq 1"
    )
    try:
        with SSHNode(node) as ssh:
            code, output = ssh.run(command, timeout=60)
    except Exception:
        return False
    if code != 0 or "REPAIRED:" not in output:
        return False
    failed.log_text = ((failed.log_text or "") +
        "\n[AI安全修复] 已确认平台托管 PostgreSQL 卷小于 1 MiB、缺少 pg_control 且未被容器使用；已移除失败初始化残留，下一次发布将重新初始化。\n"
    )[-200_000:]
    return True


def maybe_schedule_ai_retry(deployment_id: str) -> None:
    """Keep the AI deployment loop alive for recoverable startup/access failures."""
    with SessionLocal() as db:
        failed = db.get(Deployment, deployment_id)
        if not failed or failed.status != DeployStatus.failed:
            return
        existing_retry = db.scalar(select(Deployment).where(
            Deployment.project_id == failed.project_id,
            Deployment.node_id == failed.node_id,
            Deployment.created_at > failed.created_at,
            Deployment.trigger.like("ai_autofix_%"),
        ).order_by(Deployment.created_at.desc()))
        if existing_retry:
            return
        experience = remember_deployment_outcome(db, failed)
        match = re.match(r"ai_autofix_(\d+)$", failed.trigger or "")
        attempt = int(match.group(1)) if match else 0
        if attempt >= MAX_AI_RETRIES:
            failed.log_text = ((failed.log_text or "") + f"\n[AI自动修复] 已连续尝试 {MAX_AI_RETRIES} 次，仍未恢复。AI 已保留完整诊断，等待人工处理高风险或源码级问题。\n")[-200_000:]
            db.commit()
            return
        error = (failed.error or "").lower()
        project = db.get(Project, failed.project_id)
        repaired_managed_volume = repair_empty_managed_postgres_volume(db, failed, project)
        ai_retry_safe = False
        ai_result = {}
        for line in reversed((failed.log_text or "").splitlines()):
            if not line.startswith("[AI跟进] "):
                continue
            try:
                ai_result = json.loads(line[len("[AI跟进] "):])
            except (TypeError, ValueError):
                continue
            ai_retry_safe = bool(
                ai_result.get("retry_safe") is True
                and ai_result.get("confidence") in {"high", "medium"}
                and ai_result.get("scope") in {"platform", "dependency_network", "configuration", "runtime"}
            )
            break
        recoverable = any(token in error for token in (
            "unhealthy", "connection refused", "timed out", "timeout", "temporarily",
            "connection reset", "访问验证未通过", "联合检查未通过", "容器启动后状态异常",
            "dependency failed to start", "service unavailable", "429", "500", "502", "503", "504",
            "cannot find native binding", "optional dependencies", "@rolldown/binding-",
            "object has no attribute 'rglob'",
            "lockfile needs to be updated", "requires node.js >=24",
            "target stage", "could not be found",
            "unexpected eof", "unexpected end of file", "expecting \"}\"", "nginx -t", "nginx: [emerg]",
            "docker daemon", "snapshotter", "creatediff",
            "snapshot ", "does not exist: not found",
            "find: ‘target’: no such file or directory",
            "find: 'target': no such file or directory",
            "find target -name '*.jar'",
        )) or missing_maven_reactor_module(error, project) or ai_retry_safe
        learned_repair = bool(
            experience and experience.verified
            and (experience.successful_repairs or 0) > (experience.failed_repairs or 0)
        )
        previous_failed = db.scalars(
            select(Deployment).where(
                Deployment.project_id == failed.project_id,
                Deployment.node_id == failed.node_id,
                Deployment.status == DeployStatus.failed,
                Deployment.created_at < failed.created_at,
            ).order_by(Deployment.created_at.desc())
        ).first()
        same_as_previous = bool(
            previous_failed
            and deployment_error_signature(previous_failed.error or "")[0]
            == deployment_error_signature(failed.error or "")[0]
        )
        if attempt > 0 and same_as_previous and not repaired_managed_volume:
            failed.log_text = ((failed.log_text or "") +
                "\n[AI学习] 同一错误在自动修复后再次出现，说明上一方案没有产生有效变化；"
                "已停止重复构建并保留失败反例，等待方案产生可验证变化后再部署。\n"
            )[-200_000:]
            db.commit()
            return
        if not recoverable and not learned_repair:
            source_markers = (
                "compilation failure", "compilation error", "cannot find symbol",
                "syntaxerror", "syntax error", "type error", "test failed",
            )
            config_markers = (
                "missing required", "environment variable", "authentication failed",
                "access denied", "invalid password", "permission denied",
            )
            if any(token in error for token in source_markers):
                conclusion = "日志包含明确的源码编译或测试失败证据"
            elif any(token in error for token in config_markers):
                conclusion = "日志包含明确的配置、权限或凭据错误证据"
            else:
                conclusion = "当前证据尚不足以确认归属，也未识别出可安全自动执行的修复方案；这不代表一定是源码问题"
            failed.log_text = ((failed.log_text or "") +
                f"\n[AI自动修复] {conclusion}。为避免无变化地重复消耗资源，本轮停止自动重试并保留完整诊断。\n"
            )[-200_000:]
            db.commit()
            return
        next_attempt = attempt + 1
        failed_error_upper = str(failed.error or "").upper()
        if "WRONGPASS" in failed_error_upper or "NOAUTH" in failed_error_upper:
            problem_summary = "Redis 已启动，但启动凭据、健康检查凭据或应用连接凭据不一致"
        elif "INVALID ARGUMENT SYNTAX:" in failed_error_upper:
            problem_summary = "后端包含空的 Spring Boot 命令行参数，应用在初始化前拒绝启动"
        else:
            problem_summary = str(ai_result.get("summary") or "").strip()
        if not problem_summary:
            error_lines = [strip.strip() for strip in re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", failed.error or "").splitlines() if strip.strip()]
            problem_summary = next(
                (line for line in reversed(error_lines) if any(token in line.lower() for token in ("error", "failed", "no such", "not found", "returned a non-zero"))),
                error_lines[-1] if error_lines else "平台识别到可安全修复的部署错误",
            )[:600]
        retry = Deployment(
            project_id=failed.project_id,
            node_id=failed.node_id,
            requested_by=failed.requested_by,
            status=DeployStatus.queued,
            trigger=f"ai_autofix_{next_attempt}",
            host_port=failed.host_port,
            log_text=(f"[AI自动修复] 已分析任务 {failed.id[:8]} 的失败日志，"
                      f"正在对隔离发布副本应用受控修复并重新部署（第 {next_attempt}/{MAX_AI_RETRIES} 次）。\n"
                      f"[修复问题] {problem_summary}\n"),
        )
        db.add(retry)
        db.flush()
        failed.log_text = ((failed.log_text or "") + f"\n[AI自动修复] 已创建后续修复任务 {retry.id[:8]}（第 {next_attempt}/{MAX_AI_RETRIES} 次）。\n")[-200_000:]
        db.commit()


def reconcile_running_services(misses: dict[str, int]) -> None:
    """Continuously verify the newest successful release of every project."""
    with SessionLocal() as db:
        records = db.scalars(select(Deployment).order_by(Deployment.created_at.desc())).all()
        latest = {}
        for item in records:
            latest.setdefault(item.project_id, item)
        active_projects = set(db.scalars(select(Deployment.project_id).where(Deployment.status.in_([DeployStatus.queued, DeployStatus.running]))).all())
        for dep in latest.values():
            if dep.status != DeployStatus.success or dep.project_id in active_projects:
                misses.pop(dep.id, None)
                continue
            project, node = db.get(Project, dep.project_id), db.get(Node, dep.node_id)
            if not project or not node:
                continue
            try:
                with SSHNode(node) as ssh:
                    if dep.image_name:
                        command = f"docker inspect -f '{{{{.State.Status}}}}' {dep.container_name or ''} 2>/dev/null"
                    else:
                        # Compose project names are release-scoped so a verified
                        # candidate can run beside the online version.  The old
                        # fixed ``yz-{slug}`` lookup falsely reported every new
                        # release as missing and the watchdog kept redeploying it.
                        compose_project = deployment_compose_project_name(dep, project)
                        command = (
                            "docker ps -q "
                            f"--filter label=com.docker.compose.project={shlex.quote(compose_project)}"
                        )
                    code, output = ssh.run(command, timeout=15)
                    running = code == 0 and (output.strip() == "running" if dep.image_name else bool(output.strip()))
                    if running and dep.host_port:
                        check_code, status = ssh.run(f"curl -L -sS -o /dev/null -w '%{{http_code}}' --connect-timeout 3 --max-time 8 http://127.0.0.1:{dep.host_port}/", timeout=12)
                        status = status.strip()[-3:]
                        # This is a liveness probe, not a homepage correctness
                        # test. API-only services commonly answer / with 404 or
                        # 405 while remaining fully healthy. Any explicit
                        # non-5xx response proves the process is reachable and
                        # must not trigger an AI watchdog redeployment.
                        running = check_code == 0 and status.isdigit() and 100 <= int(status) < 500
                if running:
                    misses.pop(dep.id, None)
                    continue
            except Exception:
                running = False
            misses[dep.id] = misses.get(dep.id, 0) + 1
            dep.log_text = ((dep.log_text or "") + f"\n[AI巡检] 第 {misses[dep.id]}/3 次发现应用容器或访问入口不可用。\n")[-200_000:]
            if misses[dep.id] < 3:
                db.commit()
                continue
            retry = Deployment(
                project_id=dep.project_id, node_id=dep.node_id, requested_by=dep.requested_by,
                status=DeployStatus.queued, trigger="ai_watchdog", host_port=dep.host_port,
                log_text=f"[AI自动修复] 持续巡检确认发布 {dep.id[:8]} 已不可用，自动重新分析并部署。\n",
            )
            db.add(retry)
            db.flush()
            dep.log_text = ((dep.log_text or "") + f"[AI自动修复] 已创建恢复任务 {retry.id[:8]}。\n")[-200_000:]
            misses.pop(dep.id, None)
            db.commit()


def deployment_settings(db):
    row = db.get(DeploymentSettings, "default")
    if not row:
        row = DeploymentSettings(id="default")
        db.add(row)
        db.commit()
        db.refresh(row)
    return row


def main():
    Base.metadata.create_all(engine)
    with SessionLocal() as db:
        interrupted = db.scalars(select(Deployment).where(Deployment.status == DeployStatus.running)).all()
        builder_node = platform_gateway_node(db)
        for dep in interrupted:
            # Never replay a running deployment after a worker restart. Replaying
            # creates duplicate remote builds and can start the same Compose
            # project several times. Stop and verify the interrupted execution;
            # the user can then explicitly start a fresh deployment.
            try:
                result = stop_deployment(dep, db.get(Project, dep.project_id), db.get(Node, dep.node_id))
                dep.status = DeployStatus.stopped
                dep.error = None
                dep.log_text = ((dep.log_text or "") + f"\n[恢复] 执行器重启，已安全终止中断任务。{result}\n")[-200_000:]
            except Exception as exc:
                dep.status = DeployStatus.failed
                dep.error = f"执行器重启后的远端清理失败：{exc}"
                dep.log_text = ((dep.log_text or "") + f"\n[恢复失败] {dep.error}\n")[-200_000:]
            # Helper build containers run on the central builder, not on the
            # deployment target. They are labelled by deployment id so a
            # worker restart can terminate them deterministically without
            # touching another active build or any shared dependency cache.
            if builder_node:
                try:
                    with SSHNode(builder_node) as builder_ssh:
                        builder_ssh.run(
                            "ids=$(docker ps -aq --filter label=yunzhou.deployment="
                            + shlex.quote(dep.id)
                            + "); [ -z \"$ids\" ] || docker rm -f $ids >/dev/null",
                            timeout=30,
                        )
                except Exception as cleanup_exc:
                    dep.log_text = ((dep.log_text or "") + f"\n[恢复提醒] 构建辅助容器稍后清理：{cleanup_exc}\n")[-200_000:]
        # Source analysis is resumable. Unlike deployments, safely put an
        # interrupted clone/analysis back in the durable queue.
        projects = db.scalars(select(Project)).all()
        for project in projects:
            state = project.source_analysis or {}
            if (state.get("phase") or state.get("status")) in {"pulling", "analyzing", "preflight", "running"}:
                project.integration_analysis_json = json.dumps({
                    **state,
                    "status": "queued",
                    "phase": "queued",
                    "progress": max(5, min(int(state.get("progress") or 5), 20)),
                    "summary": "后台执行器已恢复，正在重新接管源码任务。",
                }, ensure_ascii=False)
        db.commit()
    # Import lazily to avoid coupling API initialization to worker module load.
    from .main import run_project_integration_analysis
    executor = ThreadPoolExecutor(max_workers=20, thread_name_prefix="yunzhou-deploy")
    active = {}
    active_sources = {}
    watchdog_misses = {}
    next_watchdog = 0.0
    next_storage_maintenance = 0.0
    next_deferred_cleanup = 0.0
    next_ai_repair_scan = 0.0
    while True:
        for future in list(active):
            if future.done():
                deployment_id, _node_id = active.pop(future)
                try:
                    future.result()
                finally:
                    with SessionLocal() as db:
                        completed = db.get(Deployment, deployment_id)
                        if completed and completed.status == DeployStatus.success:
                            remember_deployment_outcome(db, completed)
                    maybe_schedule_ai_retry(deployment_id)
        for future in list(active_sources):
            if future.done():
                active_sources.pop(future)
                try:
                    future.result()
                except Exception as exc:
                    print(f"source analysis failed: {exc}", flush=True)
        with SessionLocal() as db:
            limits = deployment_settings(db)
            node_counts = Counter(node_id for _deployment_id, node_id in active.values())
            capacity = max(0, limits.global_concurrency - len(active))
            queued = db.scalars(
                select(Deployment)
                .where(Deployment.status == DeployStatus.queued)
                .order_by(Deployment.created_at)
                .with_for_update(skip_locked=True)
                .limit(max(20, limits.global_concurrency * 5))
            ).all()
            selected = []
            for dep in queued:
                if len(selected) >= capacity:
                    break
                if node_counts[dep.node_id] >= limits.per_node_concurrency:
                    continue
                dep.status = DeployStatus.running
                selected.append((dep.id, dep.node_id))
                node_counts[dep.node_id] += 1
            db.commit()
            source_jobs = []
            analysis_capacity = max(1, min(8, int(getattr(limits, "analysis_concurrency", 2) or 2)))
            if len(active_sources) < analysis_capacity:
                active_project_ids = set(active_sources.values())
                for project in db.scalars(select(Project).order_by(Project.created_at)).all():
                    state = project.source_analysis or {}
                    if (state.get("phase") or state.get("status")) != "queued" or project.id in active_project_ids:
                        continue
                    retry_at = str(state.get("next_retry_at") or "").strip()
                    if retry_at:
                        try:
                            if datetime.fromisoformat(retry_at.replace("Z", "+00:00")) > datetime.now(timezone.utc):
                                continue
                        except ValueError:
                            pass
                    source_jobs.append((project.id, project.owner_id))
                    if len(source_jobs) >= analysis_capacity - len(active_sources):
                        break
        for deployment_id, node_id in selected:
            active[executor.submit(execute, deployment_id)] = (deployment_id, node_id)
        for project_id, owner_id in source_jobs:
            active_sources[executor.submit(run_project_integration_analysis, project_id, owner_id)] = project_id
        if time.monotonic() >= next_watchdog:
            # Project deletion and watchdog reconciliation can legitimately
            # race. A disappearing deployment is not a worker-fatal error;
            # the next cycle will read the authoritative database state.
            try:
                reconcile_running_services(watchdog_misses)
            except Exception as exc:
                print(f"watchdog reconciliation skipped after concurrent change: {exc}", flush=True)
            next_watchdog = time.monotonic() + 30
        if time.monotonic() >= next_ai_repair_scan:
            # Failure diagnosis runs asynchronously. Revisit diagnosed
            # failures after the AI result arrives so a safe recommendation
            # becomes an automatic repair instead of a passive message.
            try:
                with SessionLocal() as db:
                    diagnosed = db.scalars(
                        select(Deployment)
                        .where(Deployment.status == DeployStatus.failed)
                        .order_by(Deployment.created_at.desc())
                        .limit(50)
                    ).all()
                    retry_ids = []
                    for item in diagnosed:
                        latest_ai = next(
                            (line for line in reversed((item.log_text or "").splitlines()) if line.startswith("[AI跟进] ")),
                            "",
                        )
                        if '\"retry_safe\": true' in latest_ai:
                            retry_ids.append(item.id)
                for item_id in retry_ids:
                    maybe_schedule_ai_retry(item_id)
            except Exception as exc:
                print(f"AI repair scan failed: {exc}", flush=True)
            next_ai_repair_scan = time.monotonic() + 15
        if not active and time.monotonic() >= next_deferred_cleanup:
            try:
                process_deferred_failed_image_cleanup()
            except Exception as exc:
                print(f"deferred failed-image cleanup skipped: {exc}", flush=True)
            next_deferred_cleanup = time.monotonic() + 15
        if not active and time.monotonic() >= next_storage_maintenance:
            try:
                maintain_builder_storage()
            except Exception as exc:
                print(f"builder storage maintenance skipped: {exc}", flush=True)
            next_storage_maintenance = time.monotonic() + 3600
        time.sleep(settings.worker_poll_seconds if not selected else 0.2)


if __name__ == "__main__":
    main()

