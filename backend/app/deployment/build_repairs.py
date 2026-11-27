"""Deterministic text repairs for generated Dockerfiles.

Rules are intentionally narrow and operate only on the disposable release
copy.  Each rule is independently testable and returns its audit name when it
changes the generated file.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from pathlib import Path


TextRepair = Callable[[str, str, str], str]
_OPTIONAL_STAGE_COPY_DIRECTORIES = {"public"}


def pin_nginx_runtime(text: str, _error: str, nginx_image: str) -> str:
    return re.sub(
        r"(?im)^(\s*FROM\s+)nginx:alpine(\s*(?:AS\s+\S+)?\s*)$",
        rf"\1{nginx_image}\2",
        text,
    )


def strip_buildkit_cache_mount(text: str, _error: str, _nginx_image: str) -> str:
    return re.sub(
        r"(?m)^(\s*RUN)\s+--mount=type=cache(?:,[^\s]+)*\s+",
        r"\1 ",
        text,
    )


def remove_missing_optional_stage_copy(text: str, error: str, _nginx_image: str) -> str:
    missing_match = re.search(
        r"COPY failed:\s*stat\s+/?(?P<path>[^:\r\n]+):\s*file does not exist",
        error or "",
        re.I,
    )
    if not missing_match:
        return text
    missing_source = (
        missing_match.group("path").strip().strip("'\"")
        .replace("\\", "/").lstrip("/").rstrip("/")
    )
    if Path(missing_source).name.lower() not in _OPTIONAL_STAGE_COPY_DIRECTORIES:
        return text
    copy_pattern = re.compile(
        r"(?im)^(?P<line>\s*COPY\s+(?=[^\r\n]*--from=)[^\r\n]+)(?:\r?\n|$)"
    )

    def remove_if_exact_source(match: re.Match) -> str:
        line = match.group("line")
        if "[" in line or "]" in line:
            return match.group(0)
        tokens = re.findall(r"(?:[^\s\"']+|\"[^\"]*\"|'[^']*')+", line.strip())
        operands = [token.strip("'\"") for token in tokens[1:] if not token.startswith("--")]
        if len(operands) != 2:
            return match.group(0)
        source = operands[0].replace("\\", "/").lstrip("/").rstrip("/")
        return "" if source == missing_source else match.group(0)

    return copy_pattern.sub(remove_if_exact_source, text)


def repair_maven_module_artifact_lookup(text: str, error: str, _nginx_image: str) -> str:
    lowered = (error or "").lower()
    missing_root_target = (
        "find:" in lowered
        and "target" in lowered
        and "no such file or directory" in lowered
        and (
            "find target" in lowered
            or "find: ‘target’" in lowered
            or "find: 'target'" in lowered
        )
    )
    if not missing_root_target:
        return text
    pattern = re.compile(
        r"find\s+(?:\./)?target\s+-name\s+(['\"])\*\.jar\1"
        r"(?:\s+!\s+-name\s+(['\"])original-\*\2)?\s+-type\s+f\s*\|\s*head\s+-n\s*1"
    )
    return pattern.sub(
        "find . -path '*/target/*.jar' ! -name 'original-*' "
        "! -name '*-sources.jar' ! -name '*-javadoc.jar' -type f "
        "-printf '%s %p\\n' | sort -nr | head -n1 | cut -d' ' -f2-",
        text,
    )


DOCKERFILE_TEXT_REPAIRS: tuple[tuple[str, TextRepair], ...] = (
    ("pin_nginx_runtime", pin_nginx_runtime),
    ("strip_buildkit_cache_mount", strip_buildkit_cache_mount),
    ("remove_missing_optional_stage_copy", remove_missing_optional_stage_copy),
    ("repair_maven_module_artifact_lookup", repair_maven_module_artifact_lookup),
)


def apply_dockerfile_text_repairs(
    text: str,
    error: str,
    *,
    nginx_image: str,
) -> tuple[str, list[str]]:
    current = text
    applied: list[str] = []
    for name, repair in DOCKERFILE_TEXT_REPAIRS:
        updated = repair(current, error, nginx_image)
        if updated != current:
            current = updated
            applied.append(name)
    return current, applied
"""Deployment package component."""

