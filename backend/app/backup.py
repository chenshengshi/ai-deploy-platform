import json
import re
import shutil
import tarfile
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from zoneinfo import ZoneInfo

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from .ai import analyze_backup_scope
from .audit import audit, cleanup_audit_logs
from .auth import require
from .config import settings
from .database import Base, SessionLocal, get_db
from .models import Role, User


router = APIRouter()
BACKUP_TIMEZONE = ZoneInfo("Asia/Shanghai")
BACKUP_EXCLUDED_DIRS = {
    "node_modules", ".git", ".venv", "venv", "__pycache__", ".pytest_cache",
    ".mypy_cache", ".next", ".nuxt", "dist", "build", "target",
}
_backup_scheduler_started = False
_backup_lock = threading.Lock()
_last_audit_cleanup_date: str | None = None


def backup_items() -> list[dict]:
    root = Path(settings.backup_root)
    root.mkdir(parents=True, exist_ok=True)
    items = []
    for path in sorted(root.glob("yunzhou-backup-*.tar.gz"), key=lambda x: x.stat().st_mtime, reverse=True):
        stat = path.stat()
        items.append({
            "name": path.name,
            "size": stat.st_size,
            "created_at": datetime.fromtimestamp(stat.st_mtime, timezone.utc),
        })
    return items


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
    type_map = {
        ".js": "JavaScript", ".jsx": "React", ".ts": "TypeScript",
        ".tsx": "React/TypeScript", ".py": "Python", ".java": "Java",
        ".go": "Go", ".php": "PHP", ".vue": "Vue", ".cs": ".NET",
        ".sql": "SQL/迁移脚本",
    }
    source_types = sorted({label for ext, label in type_map.items() if extensions.get(ext)})
    return {
        "file_count": files,
        "extensions": dict(sorted(extensions.items(), key=lambda item: item[1], reverse=True)[:20]),
        "source_types": source_types,
        "excluded": sorted(BACKUP_EXCLUDED_DIRS),
        "excluded_found": sorted(excluded_found),
    }


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
        dump_file.write_text(
            json.dumps(
                database_export,
                ensure_ascii=False,
                indent=2,
                default=lambda value: value.isoformat() if hasattr(value, "isoformat") else str(value),
            ),
            encoding="utf-8",
        )
        inventory = backup_source_inventory()
        analysis = analyze_backup_scope(db, inventory)
        manifest = {
            "app": settings.app_name,
            "created_at": now_local.isoformat(),
            "database": "database.json",
            "uploads": False,
            "source_recovery": "Git 项目按仓库地址、分支和提交重新拉取；上传项目需由用户重新上传原包。",
            "excluded_directories": sorted(BACKUP_EXCLUDED_DIRS),
            "ai_analysis": analysis,
            "note": "敏感字段保持数据库中的加密状态；恢复时必须使用原 ENCRYPTION_KEY。",
        }
        manifest_path = temp_dir / "manifest.json"
        manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
        with tarfile.open(target, "w:gz") as archive:
            archive.add(dump_file, arcname="database.json")
            archive.add(manifest_path, arcname="manifest.json")
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
        raise HTTPException(502, f"备份创建失败：{exc}") from exc
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
        _backup_lock.release()


def backup_scheduler_loop() -> None:
    global _last_audit_cleanup_date
    while True:
        try:
            config = load_backup_config()
            now_local = datetime.now(BACKUP_TIMEZONE)
            cleanup_date = now_local.strftime("%Y-%m-%d")
            if _last_audit_cleanup_date != cleanup_date:
                with SessionLocal() as db:
                    cleanup_audit_logs(db)
                _last_audit_cleanup_date = cleanup_date
            if (
                config["enabled"]
                and now_local.strftime("%H:%M") == config["time"]
                and config.get("last_run_date") != now_local.strftime("%Y-%m-%d")
            ):
                with SessionLocal() as db:
                    perform_backup(db)
                config = load_backup_config()
                config["last_run_date"] = now_local.strftime("%Y-%m-%d")
                save_backup_config(config)
        except Exception:
            # Keep the scheduler alive. Operational visibility is provided by
            # the backup list and the next successful run date.
            pass
        time.sleep(30)


def start_backup_scheduler() -> None:
    global _backup_scheduler_started
    if not _backup_scheduler_started:
        _backup_scheduler_started = True
        threading.Thread(target=backup_scheduler_loop, daemon=True, name="backup-scheduler").start()


@router.get("/api/settings/backups")
def list_backups(_: User = Depends(require(Role.admin))):
    config = load_backup_config()
    usage = shutil.disk_usage(settings.backup_root)
    return {
        "items": backup_items(),
        "retention": config["retention"],
        "schedule": config,
        "disk_free": usage.free,
    }


@router.put("/api/settings/backups/schedule")
def update_backup_schedule(
    body: dict,
    db: Session = Depends(get_db),
    user: User = Depends(require(Role.admin)),
):
    enabled = bool(body.get("enabled", False))
    backup_time = str(body.get("time", "02:00"))
    retention = int(body.get("retention", 10))
    if not re.fullmatch(r"(?:[01]\d|2[0-3]):[0-5]\d", backup_time):
        raise HTTPException(400, "每日备份时间格式不正确")
    if retention < 1 or retention > 100:
        raise HTTPException(400, "备份保留数量应在 1 到 100 之间")
    config = load_backup_config()
    config.update({"enabled": enabled, "time": backup_time, "retention": retention})
    save_backup_config(config)
    for old in backup_items()[retention:]:
        (Path(settings.backup_root) / old["name"]).unlink(missing_ok=True)
    audit(
        db,
        user,
        "update_backup_schedule",
        "system",
        detail=json.dumps({"enabled": enabled, "time": backup_time, "retention": retention}, ensure_ascii=False),
    )
    db.commit()
    return {"ok": True, "schedule": config}


@router.post("/api/settings/backups")
def create_backup(db: Session = Depends(get_db), user: User = Depends(require(Role.admin))):
    return perform_backup(db, user)


@router.get("/api/settings/backups/{name}/download")
def download_backup(name: str, _: User = Depends(require(Role.admin))):
    if not re.fullmatch(r"yunzhou-backup-\d{8}-\d{6}\.tar\.gz", name):
        raise HTTPException(400, "备份文件名不正确")
    path = Path(settings.backup_root) / name
    if not path.exists():
        raise HTTPException(404, "备份不存在")
    return FileResponse(path, filename=name, media_type="application/gzip")


@router.delete("/api/settings/backups/{name}")
def delete_backup(
    name: str,
    db: Session = Depends(get_db),
    user: User = Depends(require(Role.admin)),
):
    if not re.fullmatch(r"yunzhou-backup-\d{8}-\d{6}\.tar\.gz", name):
        raise HTTPException(400, "备份文件名不正确")
    path = Path(settings.backup_root) / name
    if not path.exists():
        raise HTTPException(404, "备份不存在")
    path.unlink()
    audit(db, user, "delete_backup", "system", detail=name)
    db.commit()
    return {"ok": True}
