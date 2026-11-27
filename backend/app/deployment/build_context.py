"""Classic Docker build-context preparation helpers."""

import hashlib
import json
import re
import shlex
import shutil
import tempfile
from pathlib import Path

import yaml

from ..config import settings


def ensure_context_ignore(context: Path) -> None:
    """Keep dependency/cache trees out of classic Docker contexts."""
    ignore_file = context / ".dockerignore"
    existing = ignore_file.read_text(encoding="utf-8", errors="ignore") if ignore_file.is_file() else ""
    required = (
        ".git", "**/.git", "node_modules", "**/node_modules",
        ".pnpm-store", "**/.pnpm-store", ".agents", "**/.agents",
        "dist", "**/dist", "build", "**/build",
    )
    lines = existing.splitlines()
    changed = False
    for pattern in required:
        if pattern not in lines:
            lines.append(pattern)
            changed = True
    if changed or not ignore_file.is_file():
        ignore_file.write_text("\n".join(lines).strip() + "\n", encoding="utf-8")

def ensure_generated_copy_inputs(context: Path, dockerfile: Path) -> list[str]:
    """Make generated COPY inputs authoritative over repo ignores.

    Source repositories legitimately exclude generated assets such as
    ``/web/`` from their own production Docker context.  When source
    analysis creates a new multi-stage Dockerfile that explicitly
    builds that directory, retaining the old ignore rule makes Docker
    report the files as missing.  Append narrow negations only for
    real top-level inputs referenced by the generated file.
    """
    if not dockerfile.is_file():
        return []
    docker_text = dockerfile.read_text(encoding="utf-8", errors="ignore")
    collapsed = re.sub(r"\\\s*\r?\n\s*", " ", docker_text)
    required_roots: set[str] = set()
    explicit_generated_inputs: set[str] = set()
    for match in re.finditer(r"(?im)^\s*(?:COPY|ADD)\s+(.+)$", collapsed):
        instruction = match.group(1).strip()
        try:
            values = json.loads(instruction) if instruction.startswith("[") else shlex.split(instruction)
        except (ValueError, json.JSONDecodeError):
            continue
        if not isinstance(values, list):
            continue
        values = [str(value) for value in values]
        if any(value == "--from" or value.startswith("--from=") for value in values):
            continue
        while values and values[0].startswith("--"):
            values.pop(0)
        for source in values[:-1]:
            normalized = source.strip("/.")
            if not normalized or any(token in normalized for token in ("$", "*", "?", "[")):
                continue
            top = normalized.replace("\\", "/").split("/", 1)[0]
            if top and (context / top).exists():
                required_roots.add(top)
                normalized_path = normalized.replace("\\", "/").rstrip("/")
                if any(part in {"dist", "build", "out"} for part in normalized_path.split("/")):
                    explicit_generated_inputs.add(normalized_path)
    if not required_roots:
        return []
    ignore_file = context / ".dockerignore"
    existing = ignore_file.read_text(encoding="utf-8", errors="ignore") if ignore_file.is_file() else ""
    lines = existing.splitlines()
    added: list[str] = []
    for top in sorted(required_roots):
        for pattern in (f"!{top}", f"!{top}/", f"!{top}/**"):
            if pattern not in lines:
                lines.append(pattern)
                added.append(pattern)
        # A broad source-root negation must not re-include generated
        # dependencies or previous build output.  Those directories
        # can make atomic build scripts fail on OverlayFS (EXDEV) and
        # also bloat or contaminate the Docker context.
        for generated in ("node_modules", ".pnpm-store", "dist", "build"):
            pattern = f"{top}/{generated}"
            # Docker ignore rules are order-sensitive.  Append even
            # when the repository already contains the same pattern:
            # the preceding ``!top/**`` would otherwise re-include it.
            lines.append(pattern)
            added.append(pattern)
    # Runtime-only Dockerfiles explicitly COPY a completed dist/build
    # directory. Re-include that exact artifact after the broad
    # dependency/output exclusions above. Multi-stage Dockerfiles
    # that merely COPY the source root still keep stale artifacts out.
    for artifact in sorted(explicit_generated_inputs):
        for pattern in (f"!{artifact}", f"!{artifact}/", f"!{artifact}/**"):
            lines.append(pattern)
            added.append(pattern)
    if added:
        ignore_file.write_text("\n".join(lines).strip() + "\n", encoding="utf-8")
    return added

def source_manifests(source_root: Path, name: str, ignored_parts: set[str]) -> list[Path]:
    return sorted(
        path for path in source_root.rglob(name)
        if path.is_file() and not any(part in ignored_parts for part in path.relative_to(source_root).parts)
    )



def prepare_runtime_bundle(
    work: str, build_type: str, build_file: str, compose_override: str | None,
    extra_files: list[str] | None = None,
) -> str:
    bundle = Path(tempfile.mkdtemp(prefix="yunzhou-runtime-"))
    if build_type != "compose":
        return str(bundle)
    root = Path(work).resolve()
    compose_path = (root / build_file).resolve()
    compose_base = compose_path.parent

    def copy_runtime_path(value: str, base: Path = compose_base) -> None:
        raw = str(value or "").strip()
        if not raw or raw.startswith("/"):
            return
        source = (base / raw).resolve()
        try:
            relative = source.relative_to(root)
        except ValueError:
            return
        if not source.exists():
            return
        target = bundle / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if source.is_dir():
            shutil.copytree(source, target, dirs_exist_ok=True)
        else:
            shutil.copy2(source, target)

    copy_runtime_path(build_file, root)
    if compose_override:
        copy_runtime_path(compose_override, root)
    for extra_file in extra_files or []:
        copy_runtime_path(extra_file, root)
    document = yaml.safe_load(compose_path.read_text(encoding="utf-8", errors="ignore")) or {}
    for service in (document.get("services") or {}).values():
        if not isinstance(service, dict):
            continue
        env_files = service.get("env_file") or []
        if isinstance(env_files, (str, dict)):
            env_files = [env_files]
        for entry in env_files:
            copy_runtime_path(entry.get("path") if isinstance(entry, dict) else entry)
        for volume in service.get("volumes") or []:
            source = volume.get("source") if isinstance(volume, dict) else str(volume).split(":", 1)[0]
            if source and (str(source).startswith(".") or "/" in str(source)):
                copy_runtime_path(str(source))
    for section in ("configs", "secrets"):
        for config in (document.get(section) or {}).values():
            if isinstance(config, dict) and config.get("file"):
                copy_runtime_path(str(config["file"]))
    return str(bundle)


def validate_runtime_only_dockerfiles(work: str, build_file: str, compose_override: str | None = None) -> None:
    """Ensure image packaging cannot compile source a second time.

    Runtime-labelled Dockerfiles must never compile source. Complete generated
    compatibility builds remain valid for applications whose frontend and
    backend cannot be separated into independent runtime images safely.
    """
    root = Path(work)
    services: dict[str, dict] = {}
    for compose_name in (build_file, compose_override):
        if not compose_name:
            continue
        compose_path = root / compose_name
        if not compose_path.is_file():
            continue
        try:
            document = yaml.safe_load(compose_path.read_text(encoding="utf-8", errors="ignore")) or {}
        except Exception:
            continue
        for name, service in (document.get("services") or {}).items():
            if isinstance(service, dict) and service.get("build"):
                services[str(name)] = service

    compile_pattern = re.compile(
        r"(?im)^\s*RUN\s+.*(?:"
        r"\bmvn\b.*\b(?:package|install)\b|\bgradle\w*\b.*\b(?:build|bootJar)\b|"
        r"\b(?:npm|pnpm|yarn)\b.*\b(?:run\s+)?build\b|\bgo\s+build\b|\bdotnet\s+publish\b"
        r")"
    )
    problems: list[str] = []
    for service_name, service in services.items():
        build = service.get("build")
        build = {"context": build} if isinstance(build, str) else dict(build or {})
        context = (root / str(build.get("context") or ".")).resolve()
        dockerfile = context / str(build.get("dockerfile") or "Dockerfile")
        if not dockerfile.is_file():
            problems.append(f"{service_name}：找不到 {dockerfile.name}")
            continue
        content = dockerfile.read_text(encoding="utf-8", errors="ignore")
        # A generated ``*.runtime.Dockerfile`` is a hard runtime-only
        # contract.  ``.yunzhou.ai.Dockerfile`` can still be a complete
        # compatibility build for a single-container application (for
        # example Python API + compiled React UI).  Rejecting that fallback
        # leaves otherwise valid projects undeployable when their artifacts
        # cannot be split safely; allow it to build once instead of failing
        # before Docker starts.
        runtime_contract = dockerfile.name.endswith(".runtime.Dockerfile")
        if runtime_contract and compile_pattern.search(content):
            problems.append(f"{service_name}：{dockerfile.name} 仍包含源码编译命令")
    if problems:
        raise RuntimeError(
            "平台生成的运行镜像配置校验失败；镜像封装不得重复构建源码：" + "；".join(problems)
        )


def snapshot_deployment_files(deployment_id: str, work: str, build_file: str) -> None:
    """Persist a small, redacted copy of the files that define one release."""
    root = Path(work)
    destination = Path(settings.upload_root) / "deployment-files" / deployment_id
    shutil.rmtree(destination, ignore_errors=True)
    destination.mkdir(parents=True, exist_ok=True)
    candidates = []
    for path in root.rglob("*"):
        if not path.is_file() or ".git" in path.parts or "node_modules" in path.parts:
            continue
        relative = path.relative_to(root)
        name = path.name
        if not (
            name.startswith("Dockerfile") or name.endswith(".Dockerfile")
            or name in {"compose.yml", "compose.yaml", "docker-compose.yml", "docker-compose.yaml", ".env", "nginx.conf", "default.conf"}
            or (name.startswith(".yunzhou") and path.suffix in {".yml", ".yaml"})
        ):
            continue
        try:
            if path.stat().st_size > 300_000:
                continue
        except OSError:
            continue
        candidates.append((relative, path))
        if len(candidates) >= 40:
            break
    secret_pattern = re.compile(r"(password|secret|token|credential|private[_-]?key)", re.I)
    manifest = []
    for relative, source in candidates:
        raw = source.read_bytes()
        text_value = raw.decode("utf-8", "replace")
        safe_lines = []
        for line in text_value.splitlines():
            env_match = re.match(r"^(\s*(?:[-]\s*)?(?:ENV\s+|ARG\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*[:=]\s*)(.*)$", line, re.I)
            if env_match and secret_pattern.search(env_match.group(2)):
                safe_lines.append(env_match.group(1) + "******")
            else:
                safe_lines.append(line)
        output = destination / relative
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text("\n".join(safe_lines), encoding="utf-8")
        manifest.append({
            "path": relative.as_posix(),
            "used": relative.as_posix() == build_file,
            "sha256": hashlib.sha256(raw).hexdigest(),
        })
    (destination / "manifest.json").write_text(json.dumps({"build_file": build_file, "files": manifest}, ensure_ascii=False), encoding="utf-8")

