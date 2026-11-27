from __future__ import annotations

from .config import decrypt
from .models import Project


INTEGRATION_FIELDS = {
    "MYSQL": ("HOST", "PORT", "DATABASE", "USERNAME", "PASSWORD"),
    "POSTGRES": ("HOST", "PORT", "DATABASE", "USERNAME", "PASSWORD"),
    "REDIS": ("HOST", "PORT"),
}


def environment_values(text: str | None) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in (text or "").splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip()
    return values


def effective_project_environment(project: Project) -> str:
    managed_values = environment_values((project.managed_env_text or "").strip())
    user_values = environment_values((decrypt(project.env_text_encrypted) or "").strip())
    values = {**managed_values, **user_values}
    for service in ("MYSQL", "REDIS"):
        if user_values.get(f"YUNZHOU_{service}_MODE", "managed").lower() != "external":
            for key, value in managed_values.items():
                if key.startswith(f"YUNZHOU_{service}_") and key != f"YUNZHOU_{service}_MODE":
                    values[key] = value
    priority = [
        f"YUNZHOU_{service}_{suffix}"
        for service in ("MYSQL", "POSTGRES", "REDIS")
        for suffix in ("MODE", "HOST", "PORT", "DATABASE", "USERNAME", "PASSWORD")
    ]
    ordered = [key for key in priority if key in values]
    ordered.extend(key for key in values if key not in ordered)
    return "\n".join(f"{key}={values[key]}" for key in ordered)


def external_integration_preflight(project: Project, env_text: str) -> list[str]:
    user_values = environment_values(decrypt(project.env_text_encrypted) or "")
    effective = environment_values(env_text)
    errors: list[str] = []
    for service, suffixes in INTEGRATION_FIELDS.items():
        if user_values.get(f"YUNZHOU_{service}_MODE", "managed").lower() != "external":
            continue
        missing = [
            f"YUNZHOU_{service}_{suffix}"
            for suffix in suffixes
            if not effective.get(f"YUNZHOU_{service}_{suffix}", "").strip()
        ]
        if missing:
            errors.append(f"外接 {service} 已启用，但保存配置缺少：{'、'.join(missing)}")
    return errors


def store_managed_values(project: Project, values: dict[str, str]) -> list[str]:
    lines = (project.managed_env_text or "").splitlines()
    positions = {
        line.split("=", 1)[0].strip(): index for index, line in enumerate(lines)
        if "=" in line and not line.lstrip().startswith("#")
    }
    changed: list[str] = []
    for key, value in values.items():
        rendered = f"{key}={value}"
        if key in positions:
            if lines[positions[key]] != rendered:
                lines[positions[key]] = rendered
                changed.append(key)
        else:
            lines.append(rendered)
            positions[key] = len(lines) - 1
            changed.append(key)
    if changed:
        project.managed_env_text = "\n".join(lines).strip() + "\n"
    return changed
