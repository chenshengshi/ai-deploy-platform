"""Evidence-backed diagnostics used by AI chat and deployment verification."""

from __future__ import annotations

import re
from collections.abc import Callable
from urllib.parse import urljoin, urlsplit

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import Deployment


def deployment_from_message_url(
    db: Session,
    message: str,
    can_access_project: Callable[[str], bool],
) -> Deployment | None:
    """Resolve a stored deployment from a public URL pasted into chat."""
    urls = re.findall(r"https?://[^\s，。；;<>]+", str(message or ""), re.I)
    if not urls:
        return None
    deployments = db.scalars(select(Deployment).where(
        Deployment.access_url.is_not(None),
    ).order_by(Deployment.created_at.desc())).all()
    for raw_url in urls:
        requested = urlsplit(raw_url.rstrip("/）)]}"))
        for deployment in deployments:
            stored = urlsplit(deployment.access_url or "")
            requested_port = requested.port or (443 if requested.scheme == "https" else 80)
            stored_port = stored.port or (443 if stored.scheme == "https" else 80)
            if (
                stored.scheme.lower() == requested.scheme.lower()
                and stored.hostname == requested.hostname
                and stored_port == requested_port
                and can_access_project(deployment.project_id)
            ):
                return deployment
    return None


def diagnose_blank_frontend(access_url: str) -> dict | None:
    """Detect an SPA whose JS/CSS URLs return the HTML fallback page."""
    if not access_url:
        return None
    try:
        with httpx.Client(timeout=10, follow_redirects=True, trust_env=False) as client:
            page = client.get(access_url.rstrip("/") + "/")
            if page.status_code >= 400 or "html" not in page.headers.get("content-type", "").lower():
                return None
            references = [
                (match.group(1) or match.group(2) or "").strip()
                for match in re.finditer(
                    r"<(?:script|link)[^>]+(?:src|href)\s*=\s*(?:[\"']([^\"']+)[\"']|([^\s>]+))",
                    page.text[:1_000_000],
                    re.I,
                )
            ]
            failures = []
            for reference in references[:16]:
                path = urlsplit(reference).path
                expected = "javascript" if path.endswith((".js", ".mjs")) else ("css" if path.endswith(".css") else "")
                if not expected:
                    continue
                asset = client.get(urljoin(access_url.rstrip("/") + "/", reference))
                actual_type = asset.headers.get("content-type", "").lower()
                if "text/html" not in actual_type:
                    continue
                working_path = ""
                parts = [part for part in path.split("/") if part]
                if len(parts) >= 3:
                    without_prefix = "/" + "/".join(parts[1:])
                    candidate = client.get(urljoin(access_url.rstrip("/") + "/", without_prefix))
                    if candidate.status_code < 400 and expected in candidate.headers.get("content-type", "").lower():
                        working_path = without_prefix
                failures.append({
                    "reference": path or reference,
                    "status": asset.status_code,
                    "content_type": actual_type or "未声明",
                    "working_path": working_path,
                })
            if not failures:
                return None
            original_parts = [part for part in failures[0]["reference"].split("/") if part]
            return {
                "kind": "frontend_public_base_mismatch",
                "summary": "前端构建基础路径与平台实际发布路径不一致，JS/CSS 请求返回了 HTML 首页，浏览器无法执行前端，因此出现空白页。",
                "scope": "source",
                "prefix": ("/" + original_parts[0]) if failures[0]["working_path"] and original_parts else "",
                "evidence": failures[:3],
            }
    except httpx.HTTPError:
        return None
