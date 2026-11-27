"""Read and redact the effective files used to launch a release."""

from __future__ import annotations

import hashlib
import json
import re
import shlex
from pathlib import Path

from fastapi import HTTPException
from sqlalchemy.orm import Session

from ..config import settings
from ..models import Deployment, Node, Project
from ..ssh import SSHNode
from .naming import project_directory

_SECRET_WORDS = ("password", "secret", "token", "key", "credential", "salt")
_YAML_SECRET = re.compile(
    r"^(\s*(?:[-]\s*)?[A-Za-z_][A-Za-z0-9_.-]*(?:password|secret|token|key|credential|salt)[A-Za-z0-9_.-]*\s*[:=]\s*)(.*)$",
    re.I,
)


def _file_type(relative: str) -> str:
    lowered = relative.lower()
    if Path(relative).name.startswith(".env"):
        return "environment"
    if lowered.endswith((".yml", ".yaml")):
        return "compose"
    if lowered.endswith(".conf"):
        return "nginx"
    return "dockerfile"


def _redact(relative: str, text: str) -> str:
    safe_lines = []
    for line in text.splitlines():
        if Path(relative).name.startswith(".env") and "=" in line and not line.lstrip().startswith("#"):
            key, value = line.split("=", 1)
            safe_lines.append(f"{key}={'******' if any(word in key.lower() for word in _SECRET_WORDS) else value}")
            continue
        match = _YAML_SECRET.match(line)
        env_match = re.match(
            r"^(\s*(?:ENV|ARG)\s+[A-Za-z_][A-Za-z0-9_.-]*(?:PASSWORD|SECRET|TOKEN|KEY|CREDENTIAL|SALT)[A-Za-z0-9_.-]*[=\s]+)(.*)$",
            line,
            re.I,
        )
        safe_lines.append(f"{match.group(1)}******" if match else (f"{env_match.group(1)}******" if env_match else line))
    return "\n".join(safe_lines)


def _snapshot_files(item_id: str) -> tuple[dict, list[dict]]:
    snapshot_root = Path(settings.upload_root) / "deployment-files" / item_id
    manifest_file = snapshot_root / "manifest.json"
    if not manifest_file.is_file():
        return {}, []
    try:
        manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}, []
    files = []
    for record in manifest.get("files") or []:
        relative = str(record.get("path") or "").replace("\\", "/").lstrip("/")
        candidate = (snapshot_root / relative).resolve()
        try:
            candidate.relative_to(snapshot_root.resolve())
        except ValueError:
            continue
        if not candidate.is_file():
            continue
        raw = candidate.read_bytes()[:300_000]
        files.append({
            "path": relative,
            "type": _file_type(relative),
            "content": _redact(relative, raw.decode("utf-8", "replace")),
            "sha256": record.get("sha256") or hashlib.sha256(raw).hexdigest(),
            "used": bool(record.get("used")),
            "source": "build_snapshot",
        })
    return manifest, files

def deployment_launch_config_service(item_id: str, db: Session):
    item = db.get(Deployment, item_id)
    if not item:
        raise HTTPException(404, "部署不存在")
    project, node = db.get(Project, item.project_id), db.get(Node, item.node_id)
    if not project or not node or not item.release:
        raise HTTPException(404, "该发布尚未生成运行配置")
    release_dir = f"{node.work_dir.rstrip('/')}/{project_directory(project)}/{item.release}"
    legacy_dir = f"{node.work_dir.rstrip('/')}/{project.slug}/{item.release}"
    candidates = (".yunzhou.app.yml", ".yunzhou.ai.compose.yml", ".yunzhou.compose.yml", "compose.yml", "compose.yaml", "docker-compose.yml", "docker-compose.yaml", ".yunzhou.ai.Dockerfile", ".yunzhou.Dockerfile", "Dockerfile")
    snapshot_manifest, snapshot_files = _snapshot_files(item.id)
    with SSHNode(node) as ssh:
        _, resolved = ssh.run(f"if [ -d {shlex.quote(release_dir)} ]; then printf %s {shlex.quote(release_dir)}; elif [ -d {shlex.quote(legacy_dir)} ]; then printf %s {shlex.quote(legacy_dir)}; fi")
        actual_dir = resolved.strip()
        if not actual_dir:
            if not snapshot_files:
                raise HTTPException(404, "本次发布尚未生成可查看的发布文件")
            build_file = str(snapshot_manifest.get("build_file") or "")
            selected_file = next((file for file in snapshot_files if file["used"]), snapshot_files[0] if snapshot_files else None)
            is_compose_snapshot = build_file.lower().endswith((".yml", ".yaml"))
            return {
                "type": "compose" if is_compose_snapshot else "dockerfile",
                "file": build_file or (selected_file["path"] if selected_file else "尚未确定"),
                "content": selected_file["content"] if selected_file else "",
                "command": "构建完成后由平台生成最终启动命令",
                "environment": next((file["content"] for file in snapshot_files if file["type"] == "environment"), ""),
                "release_dir": "平台保存的发布文件快照（原失败目录已清理）",
                "files": snapshot_files,
            }
        checks = " ".join(shlex.quote(name) for name in candidates)
        _, selected = ssh.run(f"cd {shlex.quote(actual_dir)} && for f in {checks}; do [ -f \"$f\" ] && printf %s \"$f\" && break; done")
        config_file = selected.strip()
        if not config_file:
            # Central builds intentionally keep only the immutable image and
            # the release's runtime environment.  A missing source Dockerfile
            # is therefore normal for an image-backed release, not a reason
            # to hide its launch configuration from the user.
            if not item.image_name:
                raise HTTPException(404, "未找到编排文件、Dockerfile 或平台镜像运行记录")
            config_file = "平台镜像运行配置"
            content = (
                f"镜像: {item.image_name}\n"
                f"容器: {item.container_name or '应用容器'}\n"
                f"宿主机端口: {item.host_port or '未记录'}\n"
                "启动方式: 平台使用已验证镜像直接启动\n"
            )
        else:
            code, content = ssh.run(f"cd {shlex.quote(actual_dir)} && head -c 200000 -- {shlex.quote(config_file)}")
            if code:
                raise HTTPException(502, "读取运行配置失败")
        _, env_output = ssh.run(
            f"cd {shlex.quote(actual_dir)} && "
            "if [ -f .env.runtime ]; then head -c 100000 .env.runtime; "
            "elif [ -f .env ]; then head -c 100000 .env; fi"
        )
        _, file_listing = ssh.run(
            f"find {shlex.quote(actual_dir)} -maxdepth 6 -type f -size -300k "
            "\\( -name 'Dockerfile*' -o -name '*.Dockerfile' -o -name 'compose.yml' -o -name 'compose.yaml' "
            "-o -name 'docker-compose.yml' -o -name 'docker-compose.yaml' -o -name '.yunzhou*.yml' "
            "-o -name '.env*' -o -name 'nginx.conf' -o -name 'default.conf' \\) -print | head -n 40",
            timeout=30,
        )
    secret_words = _SECRET_WORDS
    # The generated Compose file is useful for diagnostics, but it may contain
    # literal credentials as either YAML values or KEY=VALUE environment items.
    # Keep the endpoint read-only and redact those values before returning it.
    redacted_content_lines = []
    yaml_secret = _YAML_SECRET
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
    listed_relatives = {
        remote_path[len(actual_dir.rstrip("/")) + 1:]
        for remote_path in (line.strip() for line in file_listing.splitlines() if line.strip())
        if remote_path.startswith(actual_dir.rstrip("/") + "/")
    }
    used_files = {config_file, ".env", ".env.runtime"}
    if ".yunzhou.app.yml" in listed_relatives:
        used_files.add(".yunzhou.app.yml")
        used_files.update(name for name in (".yunzhou.app-images.yml", ".yunzhou.external-access.yml") if name in listed_relatives)
    else:
        used_files.update(name for name in (".yunzhou.images.yml", ".yunzhou.external-access.yml") if name in listed_relatives)
    files = []
    sftp = None
    try:
        with SSHNode(node) as file_ssh:
            sftp = file_ssh.client.open_sftp()
            for remote_path in dict.fromkeys(line.strip() for line in file_listing.splitlines() if line.strip()):
                if not remote_path.startswith(actual_dir.rstrip("/") + "/"):
                    continue
                relative = remote_path[len(actual_dir.rstrip("/")) + 1:]
                try:
                    raw = sftp.open(remote_path, "rb").read(300_000)
                except Exception:
                    continue
                text_value = raw.decode("utf-8", "replace")
                if Path(relative).name.startswith(".env"):
                    safe_lines = []
                    for line in text_value.splitlines():
                        if "=" not in line or line.lstrip().startswith("#"):
                            safe_lines.append(line)
                            continue
                        key, value = line.split("=", 1)
                        safe_lines.append(f"{key}={'******' if any(word in key.lower() for word in secret_words) else value}")
                    text_value = "\n".join(safe_lines)
                else:
                    safe_lines = []
                    for line in text_value.splitlines():
                        match = yaml_secret.match(line)
                        env_match = re.match(
                            r"^(\s*(?:ENV|ARG)\s+[A-Za-z_][A-Za-z0-9_.-]*(?:PASSWORD|SECRET|TOKEN|KEY|CREDENTIAL)[A-Za-z0-9_.-]*[=\s]+)(.*)$",
                            line,
                            re.I,
                        )
                        safe_lines.append(f"{match.group(1)}******" if match else (f"{env_match.group(1)}******" if env_match else line))
                    text_value = "\n".join(safe_lines)
                lowered = relative.lower()
                file_type = "environment" if Path(relative).name.startswith(".env") else (
                    "compose" if lowered.endswith((".yml", ".yaml")) else (
                        "nginx" if lowered.endswith(".conf") else "dockerfile"
                    )
                )
                files.append({
                    "path": relative,
                    "type": file_type,
                    "content": text_value,
                    "sha256": hashlib.sha256(raw).hexdigest(),
                    "used": relative in used_files,
                    "source": "runtime",
                })
    finally:
        if sftp:
            sftp.close()
    existing_paths = {file["path"] for file in files}
    files.extend(file for file in snapshot_files if file["path"] not in existing_paths)
    if config_file == "平台镜像运行配置" and config_file not in {file["path"] for file in files}:
        raw = content.encode("utf-8")
        files.insert(0, {
            "path": config_file,
            "type": "dockerfile",
            "content": content,
            "sha256": hashlib.sha256(raw).hexdigest(),
            "used": True,
            "source": "runtime",
        })
    is_compose = config_file.lower().endswith((".yml", ".yaml"))
    compose_runtime_files = [name for name in (".yunzhou.app.yml", ".yunzhou.app-images.yml", ".yunzhou.external-access.yml") if name in used_files]
    if not compose_runtime_files and is_compose:
        compose_runtime_files = [name for name in (config_file, ".yunzhou.images.yml", ".yunzhou.external-access.yml") if name in used_files]
    command = (
        f"docker compose -p yz-{project.slug} " + " ".join(f"-f {name}" for name in compose_runtime_files) + " up -d --no-build --remove-orphans"
        if is_compose else
        f"docker run -d --name {item.container_name or '应用容器'} -p {item.host_port}:<容器端口> {item.image_name or '应用镜像'}"
    )
    return {"type": "compose" if is_compose else "dockerfile", "file": config_file, "content": content, "command": command, "environment": "\n".join(env_lines), "release_dir": actual_dir, "files": files}


