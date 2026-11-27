"""Evidence-first deployment failure classification and bounded retry policy."""
from __future__ import annotations

import re
from dataclasses import dataclass

MAX_AI_RETRIES = 2
AI_RETRY_SCOPES = {"platform", "dependency_network", "configuration", "runtime"}
AI_RETRY_CONFIDENCE = {"high", "medium"}


@dataclass(frozen=True)
class FailureAssessment:
    retry_safe: bool
    scope: str
    reason: str
    matched_rule: str | None = None
    owner: str = "unknown"
    evidence: tuple[str, ...] = ()
    suggested_action: str = "查看完整日志并补充证据后再处理"
    confidence: str = "low"


@dataclass(frozen=True)
class _Rule:
    key: str
    scope: str
    owner: str
    tokens: tuple[str, ...]
    retry_safe: bool
    reason: str
    action: str


# Specific, non-retryable evidence must win over generic timeout text that may
# appear later in compiler/application logs.
RULES = (
    _Rule("source_compile", "source", "project", (
        "compilation failure", "compilation error", "cannot find symbol", "syntaxerror",
        "syntax error", "type error", "test failed", "module not found", "failed to compile",
    ), False, "日志包含明确的源码编译、语法或测试失败证据", "修改项目源码或依赖声明后重新发布"),
    _Rule("credentials", "credentials", "user", (
        "authentication failed", "invalid password", "access denied", "wrongpass",
        "noauth", "unauthorized", "invalid token",
    ), False, "登录凭据或访问令牌未通过目标系统校验", "检查项目凭据、令牌权限及目标服务账号"),
    _Rule("configuration", "configuration", "project", (
        "missing required", "environment variable", "invalid argument syntax",
        "unknown host", "host not found in upstream",
    ), False, "运行配置、环境变量或服务拓扑不完整", "核对环境变量、服务名称、端口和依赖配置"),
    _Rule("capacity", "server", "operator", (
        "no space left on device", "disk quota exceeded", "cannot allocate memory",
        "too many open files", "read-only file system",
    ), False, "服务器资源或文件系统容量不足", "清理或扩容服务器资源后再发布"),
    _Rule("platform_engine", "platform", "platform", (
        "snapshotter", "creatediff", "content store", "docker daemon", "lease does not exist",
        "unexpected eof", "unexpected end of file", "object has no attribute 'rglob'",
        "not enough values to unpack",
    ), True, "容器引擎或平台编排过程出现可隔离重试的故障", "平台清理本次临时产物后重新执行"),
    _Rule("dependency_network", "dependency_network", "external", (
        "connection reset", "temporary failure in name resolution", "tls handshake timeout",
        "i/o timeout", "429 too many requests", "503 service unavailable", "504 gateway timeout",
    ), True, "外部代码源、镜像仓库或依赖服务暂时不可用", "保留缓存并退避后重试下载或连接"),
    _Rule("runtime_transient", "runtime", "platform", (
        "unhealthy", "dependency failed to start", "connection refused",
        "访问验证未通过", "联合检查未通过", "容器启动后状态异常",
        "frontend_public_base_mismatch",
        "cannot find native binding", "optional dependencies", "@rolldown/binding-",
        "lockfile needs to be updated", "requires node.js >=24", "nginx -t", "nginx: [emerg]",
    ), True, "平台识别到可在项目工作区中处理的运行故障", "记录修改并应用确定性兼容规则后进行一次受控重试"),
)


def _evidence_lines(error: str, tokens: tuple[str, ...]) -> tuple[str, ...]:
    result: list[str] = []
    for raw in re.sub(r"\x1b\[[0-9;?]*[ -/]*[@-~]", "", error).splitlines():
        line = raw.strip()
        if line and any(token in line.lower() for token in tokens):
            result.append(line[:300])
        if len(result) == 3:
            break
    return tuple(result)


def assess_failure(error: str | None, ai_result: dict | None = None) -> FailureAssessment:
    """Classify deterministic evidence, using AI only as a bounded fallback."""
    text = str(error or "")
    lowered = text.lower()
    # Compose often reports only ``dependency failed to start`` after the real
    # application error. Prefer the inner, actionable missing-setting line so
    # the UI names the exact key and the worker does not blindly retry it.
    missing_setting = re.search(
        r"(?im)^.*?(?:配置|环境变量)缺失\s*[：:]\s*([A-Z][A-Z0-9_]{2,})[^\r\n]*$",
        text,
    )
    if missing_setting:
        key = missing_setting.group(1)
        evidence = re.sub(r"\x1b\[[0-9;?]*[ -/]*[@-~]", "", missing_setting.group(0)).strip()
        return FailureAssessment(
            False,
            "configuration",
            f"后端容器启动失败：必填环境配置 {key} 未设置",
            "missing_setting",
            "project",
            (evidence[:300],),
            f"在项目环境配置中补充 {key} 后重新发布；平台不会猜测或自动生成业务密钥",
            "high",
        )
    for rule in RULES:
        matched = next((token for token in rule.tokens if token in lowered), None)
        if matched:
            return FailureAssessment(
                rule.retry_safe, rule.scope, rule.reason, matched, rule.owner,
                _evidence_lines(text, rule.tokens), rule.action, "high",
            )
    ai_result = ai_result or {}
    ai_scope = str(ai_result.get("scope") or "").strip()
    ai_confidence = str(ai_result.get("confidence") or "").strip()
    if ai_result.get("retry_safe") is True and ai_scope in AI_RETRY_SCOPES and ai_confidence in AI_RETRY_CONFIDENCE:
        return FailureAssessment(
            True, ai_scope, str(ai_result.get("summary") or "AI 根据真实日志确认可安全重试").strip(),
            "ai_verified", "platform" if ai_scope in {"platform", "runtime"} else "external",
            tuple(str(value)[:300] for value in (ai_result.get("evidence") or [])[:3]),
            str(ai_result.get("advice") or "按 AI 验证方案执行一次受控重试").strip(), ai_confidence,
        )
    return FailureAssessment(
        False, "unknown", "当前证据尚不足以确认归属；平台不会把未知错误直接判成源码问题，也不会盲目重试",
    )
