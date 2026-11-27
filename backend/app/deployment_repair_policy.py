"""Bounded policy for deciding whether a failed release may repair itself.

The policy does not mutate sources and does not execute commands.  It turns
real failure evidence into a conservative retry decision that the worker can
audit, cap and apply to an isolated release copy.
"""

from __future__ import annotations

from dataclasses import dataclass


MAX_AI_RETRIES = 2

SAFE_RETRY_TOKENS = (
    "unhealthy", "connection refused", "timed out", "timeout", "temporarily",
    "connection reset", "访问验证未通过", "联合检查未通过", "容器启动后状态异常",
    "dependency failed to start", "service unavailable", "429", "500", "502",
    "503", "504", "cannot find native binding", "optional dependencies",
    "@rolldown/binding-", "object has no attribute 'rglob'",
    "lockfile needs to be updated", "requires node.js >=24", "target stage",
    "could not be found", "unexpected eof", "unexpected end of file",
    "expecting \"}\"", "nginx -t", "nginx: [emerg]", "docker daemon",
    "snapshotter", "creatediff", "snapshot ", "does not exist: not found",
    "find: ‘target’: no such file or directory",
    "find: 'target': no such file or directory",
    "find target -name '*.jar'",
)

SOURCE_FAILURE_TOKENS = (
    "compilation failure", "compilation error", "cannot find symbol",
    "syntaxerror", "syntax error", "type error", "test failed",
)

CONFIGURATION_FAILURE_TOKENS = (
    "missing required", "environment variable", "authentication failed",
    "access denied", "invalid password", "permission denied",
)

AI_RETRY_SCOPES = {"platform", "dependency_network", "configuration", "runtime"}
AI_RETRY_CONFIDENCE = {"high", "medium"}


@dataclass(frozen=True)
class FailureAssessment:
    retry_safe: bool
    scope: str
    reason: str
    matched_rule: str | None = None


def assess_failure(error: str | None, ai_result: dict | None = None) -> FailureAssessment:
    """Classify a failure using deterministic evidence plus bounded AI input."""
    lowered = str(error or "").lower()
    for token in SAFE_RETRY_TOKENS:
        if token in lowered:
            return FailureAssessment(
                retry_safe=True,
                scope="runtime",
                reason="平台识别到可在隔离发布副本中处理的已知故障",
                matched_rule=token,
            )

    ai_result = ai_result or {}
    ai_scope = str(ai_result.get("scope") or "").strip()
    ai_confidence = str(ai_result.get("confidence") or "").strip()
    if (
        ai_result.get("retry_safe") is True
        and ai_scope in AI_RETRY_SCOPES
        and ai_confidence in AI_RETRY_CONFIDENCE
    ):
        return FailureAssessment(
            retry_safe=True,
            scope=ai_scope,
            reason=str(ai_result.get("summary") or "AI 根据真实日志确认可安全重试").strip(),
            matched_rule="ai_verified",
        )

    if any(token in lowered for token in SOURCE_FAILURE_TOKENS):
        return FailureAssessment(
            retry_safe=False,
            scope="source",
            reason="日志包含明确的源码编译或测试失败证据",
            matched_rule="source_evidence",
        )
    if any(token in lowered for token in CONFIGURATION_FAILURE_TOKENS):
        return FailureAssessment(
            retry_safe=False,
            scope="configuration",
            reason="日志包含明确的配置、权限或凭据错误证据",
            matched_rule="configuration_evidence",
        )
    return FailureAssessment(
        retry_safe=False,
        scope="unknown",
        reason="当前证据尚不足以确认归属，也未识别出可安全自动执行的修复方案；这不代表一定是源码问题",
    )
