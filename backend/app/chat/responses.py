"""Stable, user-facing response formatting for AI chat."""

from __future__ import annotations


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
