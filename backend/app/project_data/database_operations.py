"""Safe project database queries, changes, and schema migrations."""

from __future__ import annotations

import hashlib
import json
import re
import shlex
import threading
import uuid
from datetime import datetime
from zoneinfo import ZoneInfo

from fastapi import HTTPException
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from ..audit import audit
from ..config import decrypt
from ..deployment.integrations import environment_values
from ..deployment.naming import project_directory
from ..models import AuditLog, DeployStatus, Deployment, Node, Project, User
from ..ssh import SSHNode
from .sql_safety import high_risk_matches, is_high_risk_sql, sql_kind

_migration_locks: dict[str, threading.Lock] = {}

def _external_mysql_config(project: Project) -> dict | None:
    values = environment_values(decrypt(project.env_text_encrypted) or "")
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
    if sql_kind(sql) != "query":
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


def _execute_project_data_change(project: Project, sql: str, db: Session, user: User, session_id: str | None = None) -> dict:
    if sql_kind(sql) != "data_change":
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
                danger = high_risk_matches(text_content)
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
                if digest != expected_item.get("sha256") or sql_kind(inline_sql) != "schema":
                    raise HTTPException(409, "直接 SQL 已变化或包含非表结构语句，请重新发起")
                item = {
                    "path": expected_item.get("path") or "AI 直接 SQL",
                    "remote_path": None, "sha256": digest, "sql": inline_sql,
                    "risk": expected_item.get("risk") or ("high" if is_high_risk_sql(inline_sql) else "low"),
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

