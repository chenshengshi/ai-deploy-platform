"""Derive user-facing login instructions from repository evidence."""

from __future__ import annotations

from pathlib import Path


def normalize_login_info(work: Path | str, ai_plan: dict) -> dict:
    info = {
        "auth_mode": str(ai_plan.get("auth_mode") or "unknown")[:40],
        "login_url_path": str(ai_plan.get("login_url_path") or "/")[:300],
        "username": str(ai_plan.get("login_username") or "")[:300],
        "password": str(ai_plan.get("login_password") or "")[:300],
        "note": str(ai_plan.get("login_note") or "未发现可确认的默认登录账号，请查看项目首次使用说明。")[:1000],
    }
    if info["username"] or info["password"] or info["auth_mode"] in {"default_credentials", "external_auth", "none"}:
        return info

    inspected = 0
    for path in Path(work).rglob("*"):
        if inspected >= 300:
            break
        if not path.is_file() or path.suffix.lower() not in {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".py", ".html", ".md"}:
            continue
        try:
            if path.stat().st_size > 1_000_000:
                continue
            source = path.read_text(encoding="utf-8", errors="ignore")
            inspected += 1
        except OSError:
            continue
        if "/api/auth/register" in source and ("/register" in source or "注册" in source):
            info.update({
                "auth_mode": "first_register",
                "login_url_path": "/register",
                "username": "",
                "password": "",
                "note": "项目没有默认账号密码，请打开注册页面创建首个账号；密码规则以注册页面提示为准。",
            })
            break
    return info
