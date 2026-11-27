"""Validate and generate configuration owned by the deployment platform."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import yaml

from ..config import decrypt, settings
from ..models import Project
from .integrations import environment_values


def compose_pull_images(path: str, compose_file: str) -> list[str]:
    try:
        document = yaml.safe_load((Path(path) / compose_file).read_text(encoding="utf-8", errors="ignore")) or {}
    except (OSError, yaml.YAMLError):
        return []
    images: list[str] = []
    for service in (document.get("services") or {}).values():
        if isinstance(service, dict) and service.get("image") and not service.get("build"):
            image = str(service["image"]).strip()
            if image and "${" not in image and image not in images:
                images.append(image)
    return images


def required_compose_variables(path: str, compose_file: str, env_text: str | None = None) -> list[dict]:
    source = (Path(path) / compose_file).read_text(encoding="utf-8", errors="ignore")
    supplied = {
        line.split("=", 1)[0].strip()
        for line in (env_text or "").splitlines()
        if "=" in line and not line.lstrip().startswith("#") and line.split("=", 1)[1].strip()
    }
    supplied.update({"COMPOSE_PROJECT_NAME", "YUNZHOU_HOST_PORT", "CRM_DB_PASSWORD", "CRM_DB_ROOT_PASSWORD", "CRM_JWT_SECRET"})
    found: list[dict] = []
    for match in re.finditer(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::?\?)([^}]*)\}", source):
        name, hint = match.group(1), match.group(2).strip()
        if name not in supplied and not any(item["name"] == name for item in found):
            found.append({"name": name, "hint": hint or "Compose 声明为必填项"})
    return found


def ensure_managed_build_variables(project: Project, source_path: str, compose_file: str) -> list[str]:
    compose_source = (Path(source_path) / compose_file).read_text(encoding="utf-8", errors="ignore")
    referenced = set(re.findall(r"\$\{([A-Za-z_][A-Za-z0-9_]*)[^}]*\}", compose_source))
    current_lines = (project.managed_env_text or "").splitlines()
    current_values = environment_values(project.managed_env_text)
    generated: list[str] = []
    if "YUNZHOU_PNPM_VERSION" in referenced and not current_values.get("YUNZHOU_PNPM_VERSION"):
        version = "8.15.9"
        for package_file in sorted(Path(source_path).rglob("package.json"), key=lambda item: len(item.parts)):
            try:
                package_meta = json.loads(package_file.read_text(encoding="utf-8", errors="ignore"))
            except (OSError, json.JSONDecodeError):
                continue
            match = re.fullmatch(r"pnpm@([0-9]+(?:\.[0-9]+){1,2})(?:\+.*)?", str(package_meta.get("packageManager") or "").strip(), re.I)
            if match:
                version = match.group(1)
                break
        current_lines.append(f"YUNZHOU_PNPM_VERSION={version}")
        generated.append(f"YUNZHOU_PNPM_VERSION={version}")
    if generated:
        project.managed_env_text = "\n".join(current_lines).strip() + "\n"
    return generated


def apply_ai_inferred_config(project: Project, plan: dict) -> list[dict]:
    current_lines = (project.managed_env_text or "").splitlines()
    user_keys = {
        line.split("=", 1)[0].strip() for line in (decrypt(project.env_text_encrypted) or "").splitlines()
        if "=" in line and not line.lstrip().startswith("#")
    }
    positions = {line.split("=", 1)[0].strip(): index for index, line in enumerate(current_lines) if "=" in line and not line.lstrip().startswith("#")}
    applied: list[dict] = []
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
    effective_env = "\n".join(filter(None, (project.managed_env_text or "", decrypt(project.env_text_encrypted) or "")))
    missing = required_compose_variables(compose_path, compose_file, effective_env)
    external_prefixes = ("OIDC_", "OAUTH_", "PAYMENT_", "SMS_", "SMTP_", "S3_EXTERNAL_")
    secret_markers = ("PASSWORD", "SECRET", "TOKEN", "ACCESS_KEY", "SIGNINGKEY", "SIGNING_KEY", "PRIVATE_KEY", "ENCRYPTION_KEY", "ENC_KEY", "HASH_SALT")
    supplied_values = environment_values(effective_env)
    compose_source = (Path(compose_path) / compose_file).read_text(encoding="utf-8", errors="ignore")
    known_missing = {item["name"] for item in missing}
    for name in re.findall(r"\$\{([A-Za-z_][A-Za-z0-9_]*)[^}]*\}", compose_source):
        if name not in known_missing and not supplied_values.get(name) and any(marker in name.upper() for marker in secret_markers):
            missing.append({"name": name, "hint": "Compose 引用了可为空的敏感配置，平台将生成非空安全值"})
            known_missing.add(name)
    current_lines = (project.managed_env_text or "").splitlines()
    generated: list[str] = []
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
