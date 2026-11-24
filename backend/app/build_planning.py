import json
import re
import shlex
from pathlib import Path

from .source_inspection import (
    _executable_jar_score,
    _select_runnable_jar,
    detect_frontend_public_base,
)


PLATFORM_NGINX_IMAGE = "nginx:1.30.3-alpine"


def source_declares_environment_optional(path: str, variable: str) -> bool:
    """Confirm from executable source that an environment variable has a fallback or is optional."""
    root = Path(path)
    escaped = re.escape(variable)
    # Example environment files are part of the project's configuration
    # contract. A commented or empty assignment explicitly documents that the
    # application may run without the integration; AI must not promote it to
    # a required Compose secret.
    example_assignment = re.compile(
        rf"(?m)^\s*#?\s*(?:export\s+)?{escaped}\s*=\s*(?:['\"]\s*['\"])?\s*(?:#.*)?$"
    )
    for pattern in (".env.example", ".env.sample", ".env.template", "*.env.example", "*.env.sample"):
        for file in root.rglob(pattern):
            if not file.is_file() or any(part in {".git", "node_modules", "dist", "build"} for part in file.parts):
                continue
            try:
                if example_assignment.search(file.read_text(encoding="utf-8", errors="ignore")):
                    return True
            except OSError:
                continue
    access_with_fallback = re.compile(
        rf"(?:process\.env|values|env|config)\s*(?:\.\s*{escaped}\b|\[\s*['\"]{escaped}['\"]\s*\])[^\n]{{0,120}}?(?:\|\||\?\?)"
    )
    schema_optional = re.compile(rf"\b{escaped}\b\s*:[^\n]{{0,160}}?\.optional\s*\(")
    for file in root.rglob("*"):
        if (not file.is_file() or file.name.startswith(".yunzhou") or
                file.suffix.lower() not in {".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".py", ".java", ".go", ".rs"} or
                any(part in {".git", "node_modules", "dist", "build", "target", "vendor"} for part in file.parts)):
            continue
        try:
            if file.stat().st_size > 2_000_000:
                continue
            source = file.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if access_with_fallback.search(source) or schema_optional.search(source):
            return True
    return False


def strip_generated_code_fence(value: str) -> str:
    text = str(value or "").strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[-1] if "\n" in text else ""
        text = text.rsplit("```", 1)[0].strip()
    return text


def valid_generated_dockerfile(value: str) -> bool:
    """Reject YAML/Compose accidentally returned in the Dockerfile field."""
    instructions = []
    continued = False
    for raw_line in value.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if continued:
            continued = line.endswith("\\")
            continue
        token = line.split(None, 1)[0].upper()
        instructions.append(token)
        continued = line.endswith("\\")
    allowed = {
        "ADD", "ARG", "CMD", "COPY", "ENTRYPOINT", "ENV", "EXPOSE", "FROM",
        "HEALTHCHECK", "LABEL", "MAINTAINER", "ONBUILD", "RUN", "SHELL",
        "STOPSIGNAL", "USER", "VOLUME", "WORKDIR",
    }
    return bool(instructions) and instructions[0] in {"ARG", "FROM"} and "FROM" in instructions and all(item in allowed for item in instructions)


def normalize_inline_dockerfile(value: str) -> str:
    """Keep quoted shell text on one Dockerfile instruction line."""
    lines = value.splitlines()
    normalized = []
    index = 0
    while index < len(lines):
        line = lines[index]
        if line.lstrip().upper().startswith("RUN "):
            # AI occasionally places a literal newline inside a single-quoted
            # printf argument. Docker then treats the following quote as a new
            # instruction. Preserve the intended newline as the two characters
            # backslash+n and keep the RUN instruction valid.
            while line.count("'") % 2 == 1 and index + 1 < len(lines):
                index += 1
                line += r"\n" + lines[index].lstrip()
        normalized.append(line)
        index += 1
    result = "\n".join(normalized).rstrip() + "\n"
    # The platform never permits BuildKit-only Dockerfile features.  Convert
    # AI/user inline files to classic syntax before validation/build.  Cache
    # mounts are replaced by normal RUN commands; dependency reuse is handled
    # by the platform-wide host caches and classic image layers.
    result = re.sub(r"(?im)^\s*#\s*syntax=docker/dockerfile[^\n]*\n?", "", result)
    result = re.sub(
        r"(?m)^(\s*RUN)\s+--mount=type=cache(?:,[^\s]+)*\s+",
        r"\1 ",
        result,
    )
    # Corepack does not reliably resolve a bare package-manager major release
    # (for example `pnpm@8`) on older Node images. Pin known compatible patch
    # releases so generated builds are reproducible and do not fail after all
    # base layers and Maven dependencies have already been downloaded.
    pnpm_versions = {"7": "7.33.7", "8": "8.15.9", "9": "9.15.9", "10": "10.20.0"}
    result = re.sub(
        r"(?i)(corepack\s+prepare\s+pnpm@)(7|8|9|10)(?=\s|--)",
        lambda match: match.group(1) + pnpm_versions[match.group(2)],
        result,
    )
    return result


def optimize_node_dependency_layer(root: Path, dockerfile: str) -> str:
    """Keep package installation cacheable when only application source changes.

    AI plans commonly emit ``COPY frontend/ ./`` followed by one RUN containing
    both install and build.  That invalidates the dependency layer for every
    source edit.  For a regular (non-workspace) package directory we can safely
    split it into manifest -> install -> source -> build layers.  Docker's
    classic builder can then reuse the install layer without a project cache
    directory or BuildKit cache mount.
    """
    copy_run = re.compile(
        r"(?im)^(?P<indent>\s*)COPY\s+(?P<src>[^\s]+?)/?\s+\./?\s*\n"
        r"(?P=indent)RUN\s+(?P<command>(?:[^\n]*\\\n[ \t]*)*[^\n]*)$"
    )

    def replace(match: re.Match) -> str:
        source = match.group("src").strip().strip('"').rstrip("/")
        command = re.sub(r"\\\n[ \t]*", " ", match.group("command")).strip()
        if not re.search(r"\b(?:npm|pnpm|yarn)\s+(?:install|i|ci)\b", command, re.I):
            return match.group(0)
        build_match = re.search(r"\s*&&\s*((?:npm|pnpm|yarn)\s+(?:run\s+)?build\b.*)$", command, re.I)
        if not build_match:
            return match.group(0)
        package_dir = (root / source).resolve()
        if root not in package_dir.parents or not (package_dir / "package.json").is_file():
            return match.group(0)
        # Workspace installs may depend on sibling manifests; retain the AI
        # layout in that case instead of producing an incomplete cache layer.
        try:
            package_data = json.loads((package_dir / "package.json").read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            package_data = {}
        if package_data.get("workspaces"):
            return match.group(0)
        manifests = ["package.json", "pnpm-lock.yaml", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock"]
        existing = [name for name in manifests if (package_dir / name).is_file()]
        if not existing:
            return match.group(0)
        install_command = command[:build_match.start()].rstrip()
        build_command = build_match.group(1).strip()
        indent = match.group("indent")
        manifest_sources = " ".join(f"{source}/{name}" for name in existing)
        return (
            f"{indent}COPY {manifest_sources} ./\n"
            f"{indent}RUN {install_command}\n"
            f"{indent}COPY {source}/ ./\n"
            f"{indent}RUN {build_command}"
        )

    return copy_run.sub(replace, dockerfile)


def optimize_maven_dependency_layer(root: Path, dockerfile: str) -> str:
    """Use the mainland mirror without adding a separate warm-up build."""
    if not re.search(r"(?im)^\s*FROM\s+\S*maven[:@]", dockerfile) or not re.search(r"\bmvn\b", dockerfile):
        return dockerfile
    settings_name = ".yunzhou.maven-settings.xml"
    (root / settings_name).write_text(
        '<settings xmlns="http://maven.apache.org/SETTINGS/1.0.0">'
        '<mirrors><mirror><id>yunzhou-mirror</id><mirrorOf>*</mirrorOf>'
        '<name>Yunzhou Maven Mirror</name><url>https://maven.aliyun.com/repository/public</url>'
        '</mirror></mirrors></settings>',
        encoding="utf-8",
    )
    stages = re.split(r"(?im)(?=^\s*FROM\s+)", dockerfile)
    for index, stage in enumerate(stages):
        if not re.search(r"(?im)^\s*FROM\s+\S*maven[:@]", stage) or not re.search(r"(?im)^\s*RUN\s+.*\bmvn\b", stage):
            continue
        if settings_name not in stage:
            from_line = re.search(r"(?im)^\s*FROM[^\n]*\n", stage)
            if from_line:
                stage = stage[:from_line.end()] + f"COPY {settings_name} /tmp/yunzhou-maven-settings.xml\n" + stage[from_line.end():]
        stage = re.sub(
            r"(?im)^(\s*RUN\s+)mvn\b(?!\s+-s\b)",
            r"\1mvn -s /tmp/yunzhou-maven-settings.xml",
            stage,
        )
        # Analysis must never add or preserve an extra dependency warm-up.
        # The single authoritative package command fills the mounted cache.
        stage = re.sub(
            r"(?im)^\s*RUN\s+[^\n]*\bdependency:go-offline\b[^\n]*\n?",
            "",
            stage,
        )
        stages[index] = stage
    return "".join(stages)


def detect_java_log_directories(root: Path) -> list[str]:
    """Find absolute writable log directories declared by Java configs."""
    directories: set[str] = set()
    allowed_suffixes = {".xml", ".yml", ".yaml", ".properties"}
    for path in root.rglob("*"):
        if (
            not path.is_file()
            or path.suffix.lower() not in allowed_suffixes
            or any(part in {".git", "target", "build", "node_modules"} for part in path.parts)
        ):
            continue
        try:
            if path.stat().st_size > 2_000_000:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        # Logback commonly declares paths as
        # <property name="log.path" value="/var/log/app"/>.  Parse the
        # name/value pair explicitly so the quote after name is not mistaken
        # for the value delimiter.
        for match in re.finditer(
            r"(?i)name\s*=\s*[\"'](?:log\.path|logging\.file\.path)[\"'][^>]*?"
            r"value\s*=\s*[\"'](/[^\"'<>]+)",
            text,
        ):
            value = match.group(1).rstrip("/.,;\"")
            if value.startswith("/") and "${" not in value:
                directories.add(value)
        for match in re.finditer(
            r"(?im)^\s*(?:log\.path|logging\.file\.path)\s*[:=]\s*[\"']?(/[^\s\"'<>]+)",
            text,
        ):
            value = match.group(1).rstrip("/.,;\"")
            if value.startswith("/") and "${" not in value:
                directories.add(value)
        for match in re.finditer(r"(/(?:[A-Za-z0-9._-]+/)+)(?:[^/\s\"'<>]+\.log)\b", text):
            directories.add(match.group(1).rstrip("/"))
    return sorted(value for value in directories if value not in {"/", "/tmp"})[:12]


def ensure_java_runtime_directories(runtime: str, context: Path) -> str:
    if not re.search(r"(?i)(?:java\s+-jar|ENTRYPOINT\s*\[\s*[\"']java)", runtime):
        return runtime
    directories = detect_java_log_directories(context)
    if not directories:
        return runtime
    command = "RUN mkdir -p " + " ".join(shlex.quote(value) for value in directories)
    command += " && chmod 0777 " + " ".join(shlex.quote(value) for value in directories) + "\n"
    from_line = re.search(r"(?im)^\s*FROM[^\n]*\n", runtime)
    if not from_line:
        return runtime
    return runtime[:from_line.end()] + command + runtime[from_line.end():]


def platform_spa_runtime_dockerfile(image: str, artifact: str, public_base: str = "/") -> str:
    """Return the platform-owned static SPA runtime.

    Repository/AI Nginx snippets are evidence only.  Every static frontend
    gets the same route fallback, conservative caching and version hiding so
    a direct refresh such as /login never becomes an Nginx 404.
    """
    source = artifact.rstrip("/") + "/"
    normalized_base = "/" + str(public_base or "/").strip("/")
    base_config = ""
    if normalized_base != "/":
        base_config = (
            f"      '    location = {normalized_base} {{ return 301 {normalized_base}/; }}' \\\n"
            f"      '    location {normalized_base}/ {{ rewrite ^{re.escape(normalized_base)}/(.*)$ /$1 break; try_files $uri $uri/ /index.html; }}' \\\n"
        )
    return (
        f"FROM {image}\n"
        "RUN rm -f /etc/nginx/conf.d/default.conf \\\n"
        " && printf '%s\\n' \\\n"
        "      'server {' \\\n"
        "      '    listen 80 default_server;' \\\n"
        "      '    listen [::]:80 default_server;' \\\n"
        "      '    server_name _;' \\\n"
        "      '    server_tokens off;' \\\n"
        "      '    root /usr/share/nginx/html;' \\\n"
        "      '    index index.html;' \\\n"
        "      '    charset utf-8;' \\\n"
        + base_config
        + "      '    location / { try_files $uri $uri/ /index.html; }' \\\n"
        "      '}' \\\n"
        "    > /etc/nginx/conf.d/app.conf \\\n"
        " && nginx -t\n"
        f"COPY {source} /usr/share/nginx/html/\n"
        "EXPOSE 80\n"
        'CMD ["nginx", "-g", "daemon off;"]\n'
    )


def runtime_stage_from_prebuilt_artifact(
    dockerfile_text: str, context: Path, artifact_paths: list[str], output_name: str,
    target: str | None = None,
) -> tuple[str, list[str]] | None:
    """Convert a conventional multi-stage Dockerfile to a runtime-only one.

    The compilation has already happened in a disposable toolchain container
    with host-mounted dependency caches.  Only COPY --from lines whose source
    can be mapped to a real artifact in the checkout are rewritten.  Returning
    None leaves unusual Dockerfiles untouched instead of guessing.
    """
    stages = list(re.finditer(r"(?im)^\s*FROM\s+", dockerfile_text))
    if len(stages) < 2:
        return None
    if target:
        target_match = re.search(
            rf"(?im)^\s*FROM\s+\S+\s+AS\s+{re.escape(target)}\s*$",
            dockerfile_text,
        )
        if not target_match:
            return None
        next_stage = next((item.start() for item in stages if item.start() > target_match.start()), len(dockerfile_text))
        runtime = dockerfile_text[target_match.start():next_stage]
    else:
        runtime = dockerfile_text[stages[-1].start():]
    copied: list[str] = []
    pattern = re.compile(
        r"(?im)^(?P<indent>\s*)COPY\s+(?P<flags_before>(?:--\S+\s+)*)--from=\S+\s+"
        r"(?P<flags_after>(?:--\S+\s+)*)(?P<src>\S+)\s+(?P<dest>\S+)\s*$"
    )

    def replace(match: re.Match) -> str:
        source = match.group("src").strip('"\'').rstrip("/")
        candidates: list[Path] = []
        source_name = Path(source).name
        for value in artifact_paths:
            base = context / value
            if base.exists() and (not source_name or base.name == source_name):
                candidates.append(base)
        if not candidates and source_name:
            candidates.extend(path for path in context.rglob(source_name) if path.exists())
        if not candidates and source.lower().endswith(".jar"):
            # Multi-module Maven plans commonly normalize their builder output
            # to app.jar while the host-built artifact keeps the module name.
            # Reuse the largest compiled JAR instead of running Maven again.
            jar_candidates = [
                context / value for value in artifact_paths
                if str(value).lower().endswith(".jar") and (context / value).is_file()
            ]
            selected = _select_runnable_jar(jar_candidates)
            if selected and _executable_jar_score(selected)[0]:
                candidates.append(selected)
        if source.lower().endswith(".jar"):
            # Never turn a multi-stage Java build into a runtime-only image
            # using a plain reactor/library JAR.  If the host-side Maven pass
            # has not produced a runnable artifact, preserve the original
            # Dockerfile so its explicit Spring Boot repackage/bootJar stage
            # can finish the job.
            candidates = [path for path in candidates if _executable_jar_score(path)[0]]
        if not candidates:
            return match.group(0)
        artifact = candidates[0]
        relative = artifact.relative_to(context).as_posix()
        copied.append(relative)
        suffix = "/" if artifact.is_dir() else ""
        direct_flags = (match.group("flags_before") or "") + (match.group("flags_after") or "")
        return f'{match.group("indent")}COPY {direct_flags}{relative}{suffix} {match.group("dest")}'

    runtime = pattern.sub(replace, runtime)
    if not copied or "--from=" in runtime:
        return None
    # Static frontends are served by a platform-owned Nginx runtime.  AI plans
    # may describe the correct topology while still emitting a subtly broken
    # shell-generated config (for example a missing final ``}`` in server{}).
    # Once the frontend artifact has been built successfully there is no value
    # in carrying that generated shell fragment forward.  Replace the entire
    # runtime stage with one small, deterministic SPA server.  API routing is
    # owned by the platform gateway, so the frontend container never proxies
    # backend traffic itself.
    from_match = re.search(r"(?im)^\s*FROM\s+(?:--platform=\S+\s+)?nginx:[^\s]+.*$", runtime)
    artifact = next(
        (
            value for value in copied
            if (context / value).is_dir()
            and Path(value).name.lower() in {"dist", "build", "out", "public"}
        ),
        None,
    )
    if from_match and artifact:
        image_match = re.search(r"(?im)^\s*FROM\s+(?:--platform=\S+\s+)?(?P<image>nginx:[^\s]+)", from_match.group(0))
        image = image_match.group("image") if image_match else PLATFORM_NGINX_IMAGE
        runtime = platform_spa_runtime_dockerfile(
            image, artifact, detect_frontend_public_base(str(context)).get("primary_path") or "/"
        )
        return runtime, [artifact]
    # AI-generated nginx stages sometimes create the configuration with one
    # ``RUN echo`` instruction per line.  The classic builder then has to
    # create and commit dozens of tiny layers even though the commands are a
    # single logical operation.  Merge only consecutive generated echo
    # instructions; arbitrary RUN commands keep their original boundaries.
    runtime_lines = runtime.splitlines()
    compact_lines: list[str] = []
    echo_commands: list[str] = []

    def flush_echo_commands() -> None:
        if not echo_commands:
            return
        compact_lines.append("RUN " + " && \\\n    ".join(echo_commands))
        echo_commands.clear()

    for line in runtime_lines:
        echo_match = re.match(r"^\s*RUN\s+(echo\s+.+)$", line)
        if echo_match:
            echo_commands.append(echo_match.group(1))
            continue
        flush_echo_commands()
        compact_lines.append(line)
    flush_echo_commands()
    runtime = "\n".join(compact_lines)
    runtime = ensure_java_runtime_directories(runtime, context)
    return runtime.rstrip() + "\n", copied
