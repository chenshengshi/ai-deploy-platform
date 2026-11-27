import re
from urllib.parse import urljoin, urlsplit

import httpx

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import ChatSession, DeployStatus, Deployment, Project


_ACTIVE_ANALYSIS_STATES = {"queued", "running"}
_ACTIVE_DEPLOYMENT_STATES = {DeployStatus.queued, DeployStatus.running}


def extract_external_mysql_config(message: str) -> dict[str, str]:
    """Extract an explicitly supplied external MySQL connection from Chinese text.

    This is deliberately strict: all five connection fields must be present.
    It complements the model so a compound request such as "save this external
    database and remove the old managed one" cannot be mistaken for a status or
    stop request merely because it contains the word ``stop``/``remove``.
    """
    text = str(message or "")
    if "mysql" not in text.lower() or not any(word in text for word in ("外置", "外接", "外部")):
        return {}

    host = re.search(r"\b((?:\d{1,3}\.){3}\d{1,3})\b", text)
    port = re.search(r"(?:端口\s*[:：]?\s*|\b\d{1,3}(?:\.\d{1,3}){3}\s*[:：])(\d{2,5})\b", text, re.I)
    database = re.search(r"(?:数据库|库名)\s*[:：]?\s*([A-Za-z0-9_$.-]+)", text, re.I)
    username = re.search(r"(?:用户名|账号|用户)\s*[:：]?\s*([^\s，。；;]+)", text, re.I)
    password = re.search(r"(?:密码)\s*[:：]?\s*([^\s，。；;]+)", text, re.I)
    if not all((host, port, database, username, password)):
        return {}
    return {
        "YUNZHOU_MYSQL_MODE": "external",
        "YUNZHOU_MYSQL_HOST": host.group(1),
        "YUNZHOU_MYSQL_PORT": port.group(1),
        "YUNZHOU_MYSQL_DATABASE": database.group(1),
        "YUNZHOU_MYSQL_USERNAME": username.group(1),
        "YUNZHOU_MYSQL_PASSWORD": password.group(1),
    }


def session_task_state(db: Session, session: ChatSession, latest_action: str | None) -> tuple[bool, str]:
    """Return the visible task state for one chat without trusting its last message alone."""
    if not session.project_id:
        return False, ""
    project = db.get(Project, session.project_id)
    analysis = project.source_analysis if project else None
    analysis_running = str((analysis or {}).get("status") or "").lower() in _ACTIVE_ANALYSIS_STATES
    deployment_running = bool(db.scalar(select(Deployment.id).where(
        Deployment.project_id == session.project_id,
        Deployment.status.in_(_ACTIVE_DEPLOYMENT_STATES),
    ).limit(1)))
    workflow_running = bool(
        latest_action
        and latest_action.startswith("workflow_")
        and not latest_action.startswith(("workflow_success", "workflow_failed"))
    )
    if not (analysis_running or deployment_running or workflow_running):
        return False, ""
    latest_session_id = db.scalar(select(ChatSession.id).where(
        ChatSession.project_id == session.project_id,
        ChatSession.archived.is_(False),
    ).order_by(ChatSession.updated_at.desc()).limit(1))
    if not workflow_running and latest_session_id != session.id:
        return False, ""
    if analysis_running and not deployment_running:
        return True, "正在分析"
    return True, "正在执行任务"


def format_failure_diagnosis(project_name: str, node_name: str, release: str | None, diagnosis: dict) -> str:
    scope_labels = {
        "platform": "平台问题",
        "dependency_network": "依赖网络问题",
        "source": "项目代码问题",
        "configuration": "环境配置问题",
        "credentials": "凭据问题",
        "runtime": "运行环境问题",
        "server": "服务器资源问题",
        "unknown": "尚未确定",
    }
    evidence = next((str(item).strip() for item in diagnosis.get("evidence", []) if str(item).strip()), "")
    lines = [
        f"结论：“{project_name}”最近一次发布失败。",
        f"问题类型：{scope_labels.get(str(diagnosis.get('scope') or 'unknown'), '尚未确定')}。",
        f"失败原因：{str(diagnosis.get('summary') or '暂未提取到明确根因').strip()}",
    ]
    if evidence:
        lines.append(f"关键依据：{evidence[:500]}")
    lines.extend([
        f"服务器：{node_name}；版本：{release or '构建前失败'}。",
        f"下一步：{str(diagnosis.get('next_step') or diagnosis.get('advice') or '请查看完整日志后处理').strip()}",
    ])
    return "\n".join(lines)


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
