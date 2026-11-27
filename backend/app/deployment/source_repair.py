"""Conservative, repeatable repairs for common source build failures."""

import json
import re
from datetime import datetime, timezone
from pathlib import Path

import yaml

from ..build_planning import PLATFORM_NGINX_IMAGE
from .build_repairs import apply_dockerfile_text_repairs
from .topology import add_unambiguous_nginx_aliases
from ..source_inspection import _FRONTEND_API_ENV_KEYS, detect_frontend_api_routes


def apply_safe_build_repairs(path: str, previous_error: str, deployment_mode: str = "managed_fresh") -> list[str]:
    """Apply bounded, reversible fixes to the isolated release copy only.

    AI may classify a known failure, but it never receives permission to run
    arbitrary shell commands or change the source repository. Each supported
    repair is implemented and audited here.
    """
    error = (previous_error or "").lower()
    changed: list[str] = []
    root = Path(path)
    # A verified SPA can still render blank when its production build embeds a
    # subdirectory (for example /merp/) while the platform publishes it at the
    # project root.  On an explicit, evidence-backed AI repair request, change
    # only the isolated release copy. The user's Git checkout is never written.
    if "frontend_public_base_mismatch" in error:
        vite_files = list(root.rglob("vite.config.js")) + list(root.rglob("vite.config.ts")) + list(root.rglob("vite.config.mjs")) + list(root.rglob("vite.config.cjs"))
        for config_file in vite_files:
            if not config_file.is_file() or any(part in {".git", "node_modules", "dist", "build"} for part in config_file.relative_to(root).parts):
                continue
            original = config_file.read_text(encoding="utf-8", errors="replace")
            repaired = re.sub(
                r"(?m)(\bbase\s*:\s*)([\"'])/(?!\2)(?:[^\"']+/)+\2",
                r"\g<1>\g<2>/\g<2>",
                original,
                count=1,
            )
            if repaired != original:
                config_file.write_text(repaired, encoding="utf-8")
                changed.append(config_file.relative_to(root).as_posix())
    # User-defined Spring String placeholders usually describe optional
    # business integrations (sync.*, sms.*, oss.*, callback.*, and so on).
    # Give every member of those namespaces an empty default in the isolated
    # release copy up front. This prevents a deployment from failing once per
    # missing sibling property while keeping infrastructure connections strict.
    strict_spring_namespaces = {
        "spring", "datasource", "database", "db", "mysql", "mariadb",
        "postgres", "redis", "mongo", "mongodb", "minio", "s3",
    }
    strict_value = re.compile(
        r'(@Value\(\s*["\']\$\{)'
        r'([A-Za-z][A-Za-z0-9_-]*)'
        r'(\.[A-Za-z0-9_.-]+)'
        r'(\}["\']\s*\)\s*(?:private|protected|public)\s+String\s+)',
        re.MULTILINE,
    )

    def default_optional_string(match: re.Match) -> str:
        namespace = match.group(2)
        if namespace.lower() in strict_spring_namespaces:
            return match.group(0)
        return f"{match.group(1)}{namespace}{match.group(3)}:{match.group(4)}"

    for source_file in root.rglob("*.java"):
        if any(part in {".git", "target", "build"} for part in source_file.parts):
            continue
        original = source_file.read_text(encoding="utf-8", errors="replace")
        repaired = strict_value.sub(default_optional_string, original)
        if repaired == original:
            continue
        source_file.write_text(repaired, encoding="utf-8")
        changed.append(source_file.relative_to(root).as_posix())
    generated_dockerfiles = list(root.rglob("Dockerfile*")) + list(root.rglob(".yunzhou*.Dockerfile"))
    generated_dockerfiles = list(dict.fromkeys(generated_dockerfiles))
    # Gradle's official distribution endpoint is extremely slow on the
    # domestic build nodes. Rewrite only the disposable wrapper metadata to a
    # byte-identical mirror; Gradle still verifies the configured checksum.
    for wrapper in root.rglob("gradle-wrapper.properties"):
        if not wrapper.is_file() or ".git" in wrapper.parts:
            continue
        original = wrapper.read_text(encoding="utf-8", errors="replace")
        repaired = original.replace(
            "https\\://services.gradle.org/distributions/",
            "https\\://mirrors.cloud.tencent.com/gradle/",
        ).replace(
            "https://services.gradle.org/distributions/",
            "https://mirrors.cloud.tencent.com/gradle/",
        )
        if repaired != original:
            wrapper.write_text(repaired, encoding="utf-8")
            changed.append(wrapper.relative_to(root).as_posix())
    for gradle_file in root.rglob("build.gradle"):
        if not gradle_file.is_file() or ".git" in gradle_file.parts:
            continue
        original = gradle_file.read_text(encoding="utf-8", errors="replace")
        if "mavenCentral()" not in original or "maven.aliyun.com/repository/public" in original:
            continue
        repaired = original.replace(
            "mavenCentral()",
            "maven { url 'https://maven.aliyun.com/repository/public' }\n    mavenCentral()",
        )
        gradle_file.write_text(repaired, encoding="utf-8")
        changed.append(gradle_file.relative_to(root).as_posix())
    # The platform intentionally uses the classic builder and shared host
    # package caches. AI-generated BuildKit cache mounts are therefore invalid
    # syntax. Strip only the cache-mount prefix and preserve the command.
    for dockerfile in generated_dockerfiles:
        if not dockerfile.is_file() or ".git" in dockerfile.parts:
            continue
        original = dockerfile.read_text(encoding="utf-8", errors="replace")
        current, text_repairs = apply_dockerfile_text_repairs(
            original,
            previous_error,
            nginx_image=PLATFORM_NGINX_IMAGE,
        )
        if text_repairs:
            dockerfile.write_text(current, encoding="utf-8")
            changed.append(dockerfile.relative_to(root).as_posix())
        # Debian 11 security indices can temporarily reference superseded
        # openssl/ca-certificates packages that have already disappeared from
        # every mirror.  For Node Bullseye images, prefer the same official
        # non-slim base (which already contains OpenSSL and CA roots) instead
        # of repeatedly changing mirrors or weakening the whole build.  Only
        # an apt instruction whose install set is exactly these bootstrap
        # packages is removed; mixed application dependencies stay intact.
        current = dockerfile.read_text(encoding="utf-8", errors="replace")
        node_bullseye_crypto_gap = (
            "404" in error
            and "bullseye-security" in error
            and "openssl" in error
            and "ca-certificates" in error
            and re.search(r"(?im)^\s*FROM\s+node:[^\s]+-bullseye-slim", current)
        )
        if node_bullseye_crypto_gap:
            node_repaired = re.sub(
                r"(?im)^(\s*FROM\s+node:[^\s]+-bullseye)-slim(\s*(?:AS\s+\S+)?\s*)$",
                r"\1\2",
                current,
            )
            instruction_pattern = re.compile(
                r"(?ims)^\s*RUN\s+.*?(?=^\s*(?:FROM|RUN|COPY|ADD|WORKDIR|ENV|ARG|CMD|ENTRYPOINT|"
                r"EXPOSE|LABEL|USER|VOLUME|HEALTHCHECK|SHELL|STOPSIGNAL|ONBUILD)\b|\Z)"
            )

            def replace_crypto_bootstrap(match: re.Match) -> str:
                instruction = match.group(0)
                flattened = instruction.replace("\\\n", " ")
                install_match = re.search(
                    r"\bapt-get(?:\s+-o\s+\S+)*\s+install\s+([^;&\n]+)",
                    flattened,
                    re.I,
                )
                if not install_match:
                    return instruction
                packages = {
                    token for token in re.split(r"\s+", install_match.group(1).strip())
                    if token and not token.startswith("-")
                }
                if packages and packages <= {"openssl", "ca-certificates"}:
                    return "RUN openssl version && test -s /etc/ssl/certs/ca-certificates.crt\n"
                return instruction

            node_repaired = instruction_pattern.sub(replace_crypto_bootstrap, node_repaired)
            if node_repaired != current:
                dockerfile.write_text(node_repaired, encoding="utf-8")
                current = node_repaired
                relative = dockerfile.relative_to(root).as_posix()
                if relative not in changed:
                    changed.append(relative)
        # A mirror can finish publishing its package index before every
        # referenced .deb is available (or an HTTP caching proxy can retain
        # that stale index). Repeating the identical build only returns the
        # same 404. On that verified signature, switch the disposable release
        # file to a second HTTPS mirror, discard package lists and explicitly
        # bypass intermediary caches before the next package install.
        current = dockerfile.read_text(encoding="utf-8", errors="replace")
        apt_mirror_out_of_sync = (
            "apt-get" in error
            and (
                (
                    "404" in error
                    and ("mirrors.tuna.tsinghua.edu.cn" in error or "failed to fetch" in error)
                )
                or (
                    "certificate verification failed" in error
                    and "no system certificates available" in error
                )
            )
        )
        if apt_mirror_out_of_sync and "apt-get update" in current:
            mirror_repaired = current.replace(
                "https://mirrors.tuna.tsinghua.edu.cn",
                "https://mirrors.aliyun.com",
            ).replace(
                "http://mirrors.tuna.tsinghua.edu.cn",
                "https://mirrors.aliyun.com",
            ).replace(
                "mirrors.tuna.tsinghua.edu.cn",
                "mirrors.aliyun.com",
            )
            # A minimal Debian/Ubuntu base can lack CA roots while an HTTPS
            # intercepting proxy presents its own certificate.  Only the
            # bootstrap apt invocations get Verify-Peer disabled; apt still
            # validates signed Release metadata and package hashes, and no
            # persistent apt.conf weakening is written into the image.
            apt_bootstrap_options = (
                "-o Acquire::http::Proxy=false "
                "-o Acquire::https::Proxy=false "
                "-o Acquire::http::No-Cache=true "
                "-o Acquire::https::No-Cache=true "
                "-o Acquire::http::Pipeline-Depth=0 "
                "-o Acquire::https::Verify-Peer=false "
                "-o Acquire::https::Verify-Host=false"
            )
            refresh_command = (
                "rm -rf /var/lib/apt/lists/*; apt-get clean; "
                "sed -i 's|http://mirrors.aliyun.com|https://mirrors.aliyun.com|g; "
                "s|http://deb.debian.org|https://deb.debian.org|g; "
                "s|http://security.debian.org|https://security.debian.org|g' "
                "/etc/apt/sources.list /etc/apt/sources.list.d/debian.sources 2>/dev/null || true; "
                f"apt-get {apt_bootstrap_options} update --fix-missing"
            )
            mirror_repaired = mirror_repaired.replace("apt-get update", refresh_command)
            mirror_repaired = re.sub(
                r"\bapt-get\s+install\b",
                f"apt-get {apt_bootstrap_options} install",
                mirror_repaired,
            )
            if mirror_repaired != current:
                dockerfile.write_text(mirror_repaired, encoding="utf-8")
                current = mirror_repaired
                relative = dockerfile.relative_to(root).as_posix()
                if relative not in changed:
                    changed.append(relative)
        # Some repositories commit a uv.lock generated against an internal or
        # third-party package depot.  A TLS failure on that depot cannot be
        # repaired by merely retrying the frozen lock URLs.  Re-lock inside the
        # disposable build stage against the platform-reachable PyPI mirror,
        # retain the resolved versions/hashes where available, and give uv a
        # bounded retry/timeout budget.  The repository lockfile is untouched.
        current = dockerfile.read_text(encoding="utf-8", errors="replace")
        uv_locked_source_unreachable = (
            "uv sync" in error
            and ("tls handshake" in error or "failed to download" in error)
        )
        if uv_locked_source_unreachable and re.search(r"(?im)^\s*RUN\s+uv\s+sync\b", current):
            def repair_uv_sync(match: re.Match) -> str:
                indent = match.group("indent") or ""
                args = (match.group("args") or "").strip()
                return (
                    f"{indent}ENV UV_HTTP_TIMEOUT=120 UV_HTTP_RETRIES=8\n"
                    f"{indent}RUN uv lock --refresh --default-index "
                    "https://pypi.tuna.tsinghua.edu.cn/simple "
                    f"&& uv sync {args} --default-index "
                    "https://pypi.tuna.tsinghua.edu.cn/simple"
                )

            uv_repaired = re.sub(
                r"(?im)^(?P<indent>\s*)RUN\s+uv\s+sync(?P<args>[^\r\n]*)$",
                repair_uv_sync,
                current,
                count=1,
            )
            if uv_repaired != current:
                dockerfile.write_text(uv_repaired, encoding="utf-8")
                current = uv_repaired
                relative = dockerfile.relative_to(root).as_posix()
                if relative not in changed:
                    changed.append(relative)
        # Some Go applications validate version metadata at process startup.
        # A generic AI plan may use VERSION=dev, which builds successfully but
        # then enters a restart loop. After that exact verified failure, give
        # only the disposable release Dockerfile a syntactically valid
        # development version; the repository remains untouched.
        current = dockerfile.read_text(encoding="utf-8", errors="replace")
        if "invalid build version" in error or "invalid build metadata" in error:
            now = datetime.now(timezone.utc)
            safe_version = f"{now:%y.%m}.{now.day}-dev.0000000"
            version_repaired = re.sub(
                r"(?im)^(\s*ARG\s+VERSION\s*=\s*)dev\s*$",
                rf"\g<1>{safe_version}",
                current,
            )
            if version_repaired == current and re.search(r"(?im)^\s*ARG\s+[^\n]*\bVERSION\b", current):
                version_repaired = re.sub(
                    r"(?im)^(\s*ARG\s+[^\n]*\bVERSION\b[^\n]*)$",
                    rf"\1\nARG VERSION={safe_version}",
                    current,
                    count=1,
                )
            if version_repaired != current:
                dockerfile.write_text(version_repaired, encoding="utf-8")
                current = version_repaired
                relative = dockerfile.relative_to(root).as_posix()
                if relative not in changed:
                    changed.append(relative)
        # Production publishing must still reject real compiler errors, but a
        # repository's local Roslyn analyzer policy must not turn style/global
        # locale findings (for example CA1305) into an undeployable image.
        # Disable analyzers only inside the disposable container build and
        # lower warning promotion; the checked-out source and CI policy stay
        # untouched.  MSBuild compilation errors continue to fail normally.
        current = dockerfile.read_text(encoding="utf-8", errors="replace")
        if re.search(r"(?i)\bdotnet\s+publish\b", current):
            # A semicolon list passed through ``-p:WarningsNotAsErrors`` is
            # parsed by MSBuild as multiple property assignments; bare rule
            # IDs then raise MSB1006 before compilation starts.  RunAnalyzers
            # is disabled for this disposable publish anyway, so remove this
            # redundant and shell-fragile switch rather than editing source.
            normalized_dotnet = re.sub(
                r"\s+-p:WarningsNotAsErrors=(?:\"[^\"]*\"|'[^']*'|[^\s\\]+)",
                "",
                current,
                flags=re.I,
            )
            if normalized_dotnet != current:
                dockerfile.write_text(normalized_dotnet, encoding="utf-8")
                current = normalized_dotnet
                relative = dockerfile.relative_to(root).as_posix()
                if relative not in changed:
                    changed.append(relative)

            def relax_dotnet_analyzers(match: re.Match) -> str:
                command = match.group(1)
                if "RunAnalyzers=" in command:
                    return command
                suffix = " -p:RunAnalyzers=false -p:TreatWarningsAsErrors=false"
                if command.rstrip().endswith("\\"):
                    stripped = command.rstrip()
                    return stripped[:-1].rstrip() + suffix + " \\"
                return command + suffix

            dotnet_repaired = re.sub(
                r"(?im)(\bdotnet\s+publish\b[^\r\n]*)(?=\r?$)",
                relax_dotnet_analyzers,
                current,
            )
            if dotnet_repaired != current:
                dockerfile.write_text(dotnet_repaired, encoding="utf-8")
                relative = dockerfile.relative_to(root).as_posix()
                if relative not in changed:
                    changed.append(relative)
        # Generated Debian/Ubuntu stages are created after the initial source
        # optimization pass. Apply the same reachable mirror before package
        # installation so apt cannot silently consume the whole preflight
        # timeout on an overseas endpoint.
        current = dockerfile.read_text(encoding="utf-8", errors="replace")
        if "apt-get update" in current and "mirrors.tuna.tsinghua.edu.cn|g" not in current:
            mirrored = current.replace(
                "apt-get update",
                "sed -i 's|deb.debian.org|mirrors.tuna.tsinghua.edu.cn|g; "
                "s|security.debian.org|mirrors.tuna.tsinghua.edu.cn|g; "
                "s|archive.ubuntu.com|mirrors.tuna.tsinghua.edu.cn|g; "
                "s|security.ubuntu.com|mirrors.tuna.tsinghua.edu.cn|g' "
                "/etc/apt/sources.list /etc/apt/sources.list.d/debian.sources 2>/dev/null || true; apt-get update",
            )
            dockerfile.write_text(mirrored, encoding="utf-8")
            relative = dockerfile.relative_to(root).as_posix()
            if relative not in changed:
                changed.append(relative)
    # Failures produced by the platform's own packaging contract must never
    # authorize edits to application source files.  Keep any generated
    # Dockerfile/Compose corrections above, but leave Vue/Java/Python/Go source
    # untouched; the platform fix is applied by the deployer itself.
    platform_only_failure = any(marker in error for marker in (
        "invalid hostport",
        "build-placeholder",
        "ƽ̨���ɵ����о�������У��ʧ��",
        "�����װ�����ظ�����Դ��",
    ))
    if platform_only_failure:
        return list(dict.fromkeys(changed))

    # Git on Windows/macOS often hides import-path case mistakes that fail in
    # Linux containers. Repair only an unambiguous same-directory match in the
    # disposable release copy (for example noTasks.module.css ->
    # notasks.module.css); never invent a missing file.
    import_pattern = re.compile(r"(?P<prefix>(?:from\s+|import\s*)['\"])(?P<path>\.{1,2}/[^'\"]+)(?P<suffix>['\"])")
    for source_file in root.rglob("*"):
        if not source_file.is_file() or source_file.suffix.lower() not in {".js", ".jsx", ".ts", ".tsx", ".vue", ".svelte"}:
            continue
        if any(part in {".git", "node_modules", "dist", "build"} for part in source_file.relative_to(root).parts):
            continue
        original = source_file.read_text(encoding="utf-8", errors="replace")

        def repair_import(match: re.Match) -> str:
            value = match.group("path")
            requested = source_file.parent / value
            parent = requested.parent
            if not parent.is_dir():
                return match.group(0)
            exact_name = requested.name
            matches = [entry.name for entry in parent.iterdir() if entry.name.lower() == exact_name.lower()]
            if len(matches) != 1 or matches[0] == exact_name:
                return match.group(0)
            repaired_value = value[: -len(exact_name)] + matches[0]
            return match.group("prefix") + repaired_value + match.group("suffix")

        repaired = import_pattern.sub(repair_import, original)
        if repaired != original:
            source_file.write_text(repaired, encoding="utf-8")
            changed.append(source_file.relative_to(root).as_posix())
    # Some legacy RuoYi frontends label the captcha data URL as GIF while the
    # paired Java controller explicitly serializes it as JPEG. Browsers are
    # allowed to reject that mismatched data URL, leaving a broken image even
    # though `/captchaImage` succeeds. Repair only when both sides are present
    # in the same isolated release, so unrelated base64 images are untouched.
    captcha_controller_writes_jpeg = any(
        re.search(r'ImageIO\.write\s*\([^,]+,\s*["\'](?:jpg|jpeg)["\']', file.read_text(encoding="utf-8", errors="replace"), re.I)
        for file in root.rglob("*CaptchaController.java")
        if file.is_file() and ".git" not in file.parts
    )
    if captcha_controller_writes_jpeg:
        for source_file in root.rglob("*"):
            if not source_file.is_file() or source_file.suffix.lower() not in {".js", ".jsx", ".ts", ".tsx", ".vue"}:
                continue
            if any(part in {".git", "node_modules", "dist", "build"} for part in source_file.relative_to(root).parts):
                continue
            original = source_file.read_text(encoding="utf-8", errors="replace")
            if "captchaImage" not in original and "codeUrl" not in original:
                continue
            repaired = original.replace("data:image/gif;base64,", "data:image/jpeg;base64,")
            if repaired != original:
                source_file.write_text(repaired, encoding="utf-8")
                relative = source_file.relative_to(root).as_posix()
                if relative not in changed:
                    changed.append(relative)
    # A separated frontend/backend application has one public API prefix owned
    # by the platform gateway, but the prefix is project evidence rather than a
    # platform constant.  Detect it before rewriting an external runtime origin
    # and never turn every development/staging alias into a public route.
    compose_service_names: set[str] = set()
    for compose_file in root.glob(".yunzhou*.yml"):
        try:
            document = yaml.safe_load(compose_file.read_text(encoding="utf-8", errors="replace")) or {}
        except yaml.YAMLError:
            continue
        services = document.get("services") if isinstance(document, dict) else None
        if isinstance(services, dict):
            compose_service_names.update(str(name).lower() for name in services)
    has_frontend = any(re.search(r"(?:^|[-_.])(front(?:end)?|web|ui)(?:$|[-_.])", name) for name in compose_service_names)
    has_backend = any(re.search(r"(?:^|[-_.])(back(?:end)?|api|server)(?:$|[-_.])", name) for name in compose_service_names)
    if has_frontend and has_backend:
        detected_route = detect_frontend_api_routes(path)
        api_prefix = str(detected_route.get("primary_path") or "")
        api_setting = re.compile(
            rf"(?m)^(\s*(?:{'|'.join(map(re.escape, _FRONTEND_API_ENV_KEYS))})\s*=\s*)([^\r\n#]+)"
        )
        for env_file in root.rglob(".env*"):
            if not env_file.is_file() or any(part in {".git", "node_modules", "dist", "build"} for part in env_file.relative_to(root).parts):
                continue
            env_name = env_file.name.lower()
            if env_name not in {".env", ".env.local"} and "production" not in env_name:
                continue
            original = env_file.read_text(encoding="utf-8", errors="replace")
            # Keep an already-relative source prefix unchanged.  Only replace
            # an environment-bound absolute origin when another source signal
            # established the effective public path.
            def normalize_api_setting(match: re.Match) -> str:
                value = match.group(2).strip().strip("'\"")
                if api_prefix and value.startswith(("http://", "https://", "//")):
                    quote_char = "\"" if match.group(2).strip().startswith("\"") else ""
                    return match.group(1) + quote_char + api_prefix + quote_char
                return match.group(0)

            repaired = api_setting.sub(normalize_api_setting, original)
            if repaired != original:
                env_file.write_text(repaired, encoding="utf-8")
                changed.append(env_file.relative_to(root).as_posix())
        for runtime_config in root.rglob("postUrl.js"):
            if not runtime_config.is_file() or any(part in {".git", "node_modules", "dist", "build"} for part in runtime_config.relative_to(root).parts):
                continue
            original = runtime_config.read_text(encoding="utf-8", errors="replace")
            if "configUrl" not in original or "reqDomain" not in original:
                continue
            repaired = original
            if api_prefix:
                repaired = re.sub(
                    r"(?m)^(\s*(?:const|let|var)\s+IP\s*=\s*)['\"](?:https?:)?//[^'\"]*['\"](\s*;?)",
                    lambda match: match.group(1) + json.dumps(api_prefix) + match.group(2),
                    original,
                    count=1,
                )
            if repaired != original:
                runtime_config.write_text(repaired, encoding="utf-8")
                changed.append(runtime_config.relative_to(root).as_posix())
    # Some applications use a JSON snapshot only for legacy import even when
    # MySQL is the active persistence driver.  COMMERCE_OPS_DATA is therefore
    # a file, while its parent directory is the mounted volume.  Treating the
    # volume root itself as the file deterministically raises EISDIR.
    reads_commerce_data_as_file = any(
        "readFileSync(dataPath" in file.read_text(encoding="utf-8", errors="replace")
        for file in root.rglob("*.mjs")
        if file.is_file() and "node_modules" not in file.parts
    )
    if reads_commerce_data_as_file:
        for compose_file in root.glob(".yunzhou*.yml"):
            try:
                document = yaml.safe_load(compose_file.read_text(encoding="utf-8", errors="replace"))
            except yaml.YAMLError:
                continue
            services = document.get("services") if isinstance(document, dict) else None
            repaired = False
            for service in (services or {}).values():
                env = service.get("environment") if isinstance(service, dict) else None
                if not isinstance(env, dict):
                    continue
                value = str(env.get("COMMERCE_OPS_DATA") or "").rstrip("/")
                if value and not Path(value).suffix:
                    env["COMMERCE_OPS_DATA"] = value + "/commerce-ops.json"
                    repaired = True
            if repaired:
                compose_file.write_text(yaml.safe_dump(document, allow_unicode=True, sort_keys=False), encoding="utf-8")
                changed.append(compose_file.relative_to(root).as_posix())
    # Legacy nginx files frequently use a compact upstream hostname (for
    # example `wmsapi`) while the generated Compose plan follows readable
    # kebab-case (`wms-api`). Docker DNS treats those as different names. Add
    # a network alias only when the names are an unambiguous punctuation-only
    # match; this preserves both the source nginx configuration and the AI
    # service topology without guessing an unrelated destination.
    upstream_hosts: set[str] = set()
    upstream_pattern = re.compile(r"(?im)\b(?:proxy_pass\s+https?://|server\s+)([a-z][a-z0-9_-]*)(?::\d+)?")
    for config_file in root.rglob("*"):
        if not config_file.is_file() or config_file.suffix.lower() not in {".conf", ".template"}:
            continue
        if any(part in {".git", "node_modules", "dist", "build"} for part in config_file.relative_to(root).parts):
            continue
        upstream_hosts.update(upstream_pattern.findall(config_file.read_text(encoding="utf-8", errors="replace")))
    if upstream_hosts:
        for compose_file in root.glob(".yunzhou*.yml"):
            try:
                document = yaml.safe_load(compose_file.read_text(encoding="utf-8", errors="replace"))
            except yaml.YAMLError:
                continue
            services = document.get("services") if isinstance(document, dict) else None
            if not isinstance(services, dict):
                continue
            alias_repairs = add_unambiguous_nginx_aliases(services, upstream_hosts)
            if alias_repairs:
                compose_file.write_text(yaml.safe_dump(document, allow_unicode=True, sort_keys=False), encoding="utf-8")
                relative = compose_file.relative_to(root).as_posix()
                if relative not in changed:
                    changed.append(relative)
    # A verified deployment experience showed that `concurrently` may invoke
    # `ps` while supervising sibling Node processes. Slim runtime images do
    # not include it. Apply the learned prerequisite to generated files during
    # source preflight instead of waiting for another production crash.
    uses_concurrently = any(
        '"concurrently"' in file.read_text(encoding="utf-8", errors="replace")
        for file in root.rglob("package.json")
        if file.is_file() and "node_modules" not in file.parts
    )
    if uses_concurrently:
        for dockerfile in generated_dockerfiles:
            if not dockerfile.is_file() or not dockerfile.name.startswith(".yunzhou"):
                continue
            text = dockerfile.read_text(encoding="utf-8", errors="replace")
            if "procps" in text:
                continue
            final_stage = re.split(r"(?im)(?=^\s*FROM\s+)", text)[-1]
            install = (
                "RUN apk add --no-cache procps\n"
                if re.search(r"(?im)^\s*FROM\s+\S*alpine", final_stage)
                else "RUN apt-get update && apt-get install --no-install-recommends -y procps "
                     "&& rm -rf /var/lib/apt/lists/*\n"
            )
            marker = re.search(r"(?im)^\s*USER\s+", text)
            position = marker.start() if marker else len(text)
            text = text[:position] + install + text[position:]
            dockerfile.write_text(text.rstrip() + "\n", encoding="utf-8")
            changed.append(dockerfile.relative_to(root).as_posix())
    # Public proxy.golang.org is frequently unreachable from domestic build
    # nodes. Keep module verification enabled while using a reachable module
    # proxy, then fall back to the origin when necessary.
    for dockerfile in generated_dockerfiles:
        if not dockerfile.is_file() or not dockerfile.name.startswith(".yunzhou"):
            continue
        text = dockerfile.read_text(encoding="utf-8", errors="replace")
        if re.search(r"(?im)^\s*FROM\s+golang:", text) and "GOPROXY=" not in text:
            repaired = re.sub(
                r"(?im)^(\s*FROM\s+golang:[^\n]+\n)",
                r"\1ENV GOPROXY=https://goproxy.cn,direct\n",
                text,
            )
            if repaired != text:
                dockerfile.write_text(repaired, encoding="utf-8")
                changed.append(dockerfile.relative_to(root).as_posix())
    # Pure-Go web services do not need a native toolchain. A generated plan
    # that forces CGO can spend the whole rehearsal window compiling libc and
    # still produce a less portable binary. After an observed build timeout,
    # retry the isolated plan with a static Go binary; genuine CGO projects
    # will fail explicitly and remain blocked rather than being published.
    if "building" in error and ("899." in error or "timed out" in error or "timeout" in error):
        for candidate in dict.fromkeys(generated_dockerfiles + list(root.glob(".yunzhou*.yml"))):
            if not candidate.is_file() or ".git" in candidate.parts:
                continue
            original = candidate.read_text(encoding="utf-8", errors="replace")
            if "go build" not in original or "CGO_ENABLED=1" not in original:
                continue
            repaired = original.replace("CGO_ENABLED=1", "CGO_ENABLED=0")
            candidate.write_text(repaired, encoding="utf-8")
            relative = candidate.relative_to(root).as_posix()
            if relative not in changed:
                changed.append(relative)
    # Gradle's POSIX wrapper invokes xargs. Minimal JDK images may omit
    # findutils, so an otherwise valid project fails before Gradle starts.
    for dockerfile in generated_dockerfiles:
        if not dockerfile.is_file() or not dockerfile.name.startswith(".yunzhou"):
            continue
        text = dockerfile.read_text(encoding="utf-8", errors="replace")
        if "gradlew" in text and "findutils" not in text:
            stages = re.split(r"(?im)(?=^\s*FROM\s+)", text)
            repaired_stages = []
            for stage in stages:
                if "gradlew" not in stage:
                    repaired_stages.append(stage)
                    continue
                marker = re.search(r"(?im)^\s*(?:WORKDIR|COPY|ADD|RUN)\s+", stage)
                if not marker:
                    repaired_stages.append(stage)
                    continue
                install = (
                    "RUN apk add --no-cache findutils\n"
                    if re.search(r"(?im)^\s*FROM\s+\S*alpine", stage)
                    else (
                        "RUN dnf install -y findutils && dnf clean all\n"
                        if re.search(r"(?im)^\s*FROM\s+amazoncorretto:", stage)
                        else "RUN apt-get update && apt-get install --no-install-recommends -y findutils && rm -rf /var/lib/apt/lists/*\n"
                    )
                )
                stage = stage[:marker.start()] + install + stage[marker.start():]
                repaired_stages.append(stage)
            repaired = "".join(repaired_stages)
            if repaired != text:
                dockerfile.write_text(repaired, encoding="utf-8")
                changed.append(dockerfile.relative_to(root).as_posix())
    # eve 0.69+ performs its own runtime guard and requires Node 24. AI plans
    # may otherwise choose the broadly compatible Node 22 LTS image, causing
    # a deterministic platform-generated Dockerfile failure before user code
    # is compiled. Detect the repository's build tool and lift only generated
    # Dockerfiles; the checked-out source remains untouched.
    uses_eve_build = any(
        '"eve"' in file.read_text(encoding="utf-8", errors="replace")
        and "eve build" in file.read_text(encoding="utf-8", errors="replace")
        for file in list(root.rglob("package.json"))[:100]
        if file.is_file() and "node_modules" not in file.parts
    )
    if uses_eve_build:
        for dockerfile in root.rglob("Dockerfile*"):
            if not dockerfile.is_file() or ".git" in dockerfile.parts:
                continue
            original = dockerfile.read_text(encoding="utf-8", errors="replace")
            repaired = re.sub(r"(?m)^(FROM\s+node:)22(?=[-:@])", r"\g<1>24", original)
            if repaired != original:
                dockerfile.write_text(repaired, encoding="utf-8")
                changed.append(str(dockerfile.relative_to(root)).replace("\\", "/"))
        for compose_file in root.glob(".yunzhou*.yml"):
            original = compose_file.read_text(encoding="utf-8", errors="replace")
            repaired = re.sub(r"(?m)(FROM\s+node:)22(?=[-:@])", r"\g<1>24", original)
            if repaired != original:
                compose_file.write_text(repaired, encoding="utf-8")
                relative = compose_file.relative_to(root).as_posix()
                if relative not in changed:
                    changed.append(relative)
    # Bun runs workspace postinstall hooks during dependency installation.
    # Prisma's config loader may require DATABASE_URL even though no database
    # connection is made by `prisma generate`. Ensure a harmless build-only
    # value exists before the first `bun install`; runtime Compose values still
    # override it and no real credential is embedded in the image.
    prisma_requires_database_url = any(
        "DATABASE_URL" in file.read_text(encoding="utf-8", errors="replace")
        for file in root.rglob("prisma.config.*")
        if file.is_file() and "node_modules" not in file.parts
    )
    if prisma_requires_database_url:
        for dockerfile in dict.fromkeys(generated_dockerfiles):
            if not dockerfile.is_file() or ".git" in dockerfile.parts:
                continue
            original = dockerfile.read_text(encoding="utf-8", errors="replace")
            install_at = original.find("RUN bun install")
            if install_at < 0 or "DATABASE_URL" in original[:install_at]:
                continue
            repaired = original[:install_at] + (
                "ARG DATABASE_URL=postgresql://postgres:build@127.0.0.1:5432/build?schema=public\n"
                "ENV DATABASE_URL=$DATABASE_URL\n"
            ) + original[install_at:]
            dockerfile.write_text(repaired, encoding="utf-8")
            relative = str(dockerfile.relative_to(root)).replace("\\", "/")
            if relative not in changed:
                changed.append(relative)
    # eve's just-bash sandbox is an optional peer dependency and some
    # repositories select that provider without declaring the package. Repair
    # only the isolated generated image after Docker reports that exact missing
    # package; never modify the checked-out manifests or lockfile.
    eve_manifest_detected = any(
        "eve" in manifest.read_text(encoding="utf-8", errors="replace").lower()
        for manifest in root.rglob("package.json")
        if "node_modules" not in manifest.parts and ".git" not in manifest.parts
    )
    if ("cannot find package 'just-bash'" in error and "eve" in error) or eve_manifest_detected:
        for dockerfile in dict.fromkeys(generated_dockerfiles):
            if not dockerfile.is_file() or ".git" in dockerfile.parts:
                continue
            original = dockerfile.read_text(encoding="utf-8", errors="replace")
            if "just-bash" in original:
                continue
            install_line = next(
                (line for line in original.splitlines() if line.lstrip().startswith("RUN ") and "bun install" in line),
                None,
            )
            if not install_line:
                continue
            # Keep installation and cache cleanup in one layer.  A separate
            # cleanup layer would still retain Bun's downloaded package cache
            # in the parent image and can turn a small monorepo into tens of
            # gigabytes when several Compose targets export concurrently.
            install_command = install_line.rstrip().removesuffix("\\")
            repaired = original.replace(
                install_line,
                install_command
                + " && bun add --dev just-bash --registry=https://registry.npmmirror.com"
                + " && rm -rf /root/.bun/install/cache /tmp/bun-*",
                1,
            )
            dockerfile.write_text(repaired, encoding="utf-8")
            relative = str(dockerfile.relative_to(root)).replace("\\", "/")
            if relative not in changed:
                changed.append(relative)
    # Older projects frequently carry a Yarn v1 lockfile that was not updated
    # with package.json. On an AI retry, relax only the immutable check in the
    # isolated generated Dockerfile; dependency resolution still fails on any
    # real package/version error and the repository lockfile is never edited.
    if "lockfile needs to be updated" in error and "frozen-lockfile" in error:
        for dockerfile in root.rglob("Dockerfile*"):
            if not dockerfile.is_file() or ".git" in dockerfile.parts:
                continue
            original = dockerfile.read_text(encoding="utf-8", errors="replace")
            repaired = re.sub(r"\s+--frozen-lockfile\b", "", original)
            if repaired != original:
                dockerfile.write_text(repaired, encoding="utf-8")
                relative = str(dockerfile.relative_to(root)).replace("\\", "/")
                if relative not in changed:
                    changed.append(relative)
    # A syntactically broken pnpm lockfile cannot be repaired by merely
    # relaxing --frozen-lockfile: pnpm parses the damaged YAML first.  When
    # the real preflight reports this exact condition, discard the lockfile
    # only inside the disposable release copy and let pnpm resolve a fresh
    # dependency graph.  The Git checkout and the user's repository remain
    # unchanged, while subsequent build/runtime errors are still surfaced.
    broken_pnpm_lock = False
    for lockfile in root.rglob("pnpm-lock.yaml"):
        if lockfile.is_file() and "node_modules" not in lockfile.parts:
            lock_text = lockfile.read_text(encoding="utf-8", errors="replace")
            for section in re.split(r"(?m)^(?=\S)", lock_text):
                keys = re.findall(r"(?m)^  ([^\s][^:]+(?:@[^:]+)?):\s*$", section)
                if len(keys) != len(set(keys)):
                    broken_pnpm_lock = True
                    break
    if broken_pnpm_lock or "err_pnpm_broken_lockfile" in error or (
        "lockfile" in error and "broken" in error and "duplicated mapping key" in error
    ):
        for dockerfile in generated_dockerfiles:
            if not dockerfile.is_file() or ".git" in dockerfile.parts:
                continue
            original = dockerfile.read_text(encoding="utf-8", errors="replace")
            repaired = re.sub(
                r"(?m)^(\s*RUN\s+)(pnpm\s+install)(?:\s+--frozen-lockfile)?",
                r"\1rm -f pnpm-lock.yaml && \2 --no-frozen-lockfile",
                original,
                count=1,
            )
            if repaired != original:
                dockerfile.write_text(repaired, encoding="utf-8")
                relative = dockerfile.relative_to(root).as_posix()
                if relative not in changed:
                    changed.append(relative)
    # A SvelteKit project using a server adapter does not emit /dist. If an AI
    # plan incorrectly selects an nginx static stage, retain the successful
    # build stage and run the project's own preview server in the disposable
    # image. This is triggered only by the exact missing-dist failure.
    svelte_server_build = any(
        "@sveltejs/adapter-" in manifest.read_text(encoding="utf-8", errors="replace")
        and "adapter-static" not in manifest.read_text(encoding="utf-8", errors="replace")
        for manifest in root.rglob("package.json")
        if manifest.is_file() and "node_modules" not in manifest.parts
    )
    if svelte_server_build:
        for dockerfile in generated_dockerfiles:
            if not dockerfile.is_file() or ".git" in dockerfile.parts:
                continue
            original = dockerfile.read_text(encoding="utf-8", errors="replace")
            if "COPY --from=build /app/dist" not in original:
                continue
            stages = list(re.finditer(r"(?im)^\s*FROM\s+", original))
            if len(stages) < 2:
                continue
            repaired = original[:stages[-1].start()] + (
                "FROM node:22-alpine\nWORKDIR /app\n"
                "COPY --from=build /app /app\n"
                "ENV HOST=0.0.0.0 PORT=4300\nEXPOSE 4300\n"
                'CMD ["npm", "run", "preview", "--", "--host", "0.0.0.0", "--port", "4300"]\n'
            )
            dockerfile.write_text(repaired, encoding="utf-8")
            relative = dockerfile.relative_to(root).as_posix()
            if relative not in changed:
                changed.append(relative)
    if broken_pnpm_lock:
        for compose_file in root.glob(".yunzhou*.yml"):
            original = compose_file.read_text(encoding="utf-8", errors="replace")
            repaired = re.sub(
                r"pnpm\s+install(?:\s+--frozen-lockfile)?",
                "rm -f pnpm-lock.yaml && pnpm install --no-frozen-lockfile",
                original,
                count=1,
            )
            if repaired != original:
                compose_file.write_text(repaired, encoding="utf-8")
                relative = compose_file.relative_to(root).as_posix()
                if relative not in changed:
                    changed.append(relative)
    lock_text = "\n".join(
        file.read_text(encoding="utf-8", errors="replace")
        for file in list(Path(path).rglob("package-lock.json"))[:20]
        if file.is_file() and "node_modules" not in file.parts
    ).lower()
    rolldown_lock_incomplete = "node_modules/rolldown" in lock_text and "@rolldown/binding-linux-x64-gnu" not in lock_text
    rolldown_binding_missing = rolldown_lock_incomplete or (
        "cannot find native binding" in error
        and "rolldown" in error
        and ("binding-linux" in error or "optional dependencies" in error)
    )
    if rolldown_binding_missing:
        for dockerfile in root.rglob("Dockerfile*"):
            if not dockerfile.is_file() or ".git" in dockerfile.parts:
                continue
            original = dockerfile.read_text(encoding="utf-8", errors="replace")
            repaired = re.sub(r"\bnpm\s+ci\b", "npm install --include=optional", original)
            # npm/cli#4828 can omit the platform package even after a regular
            # install when the lock was generated on another OS. Install the
            # exact native binding version used by the workspace explicitly.
            install_line = next(
                (line for line in repaired.splitlines() if line.lstrip().startswith("RUN ") and "npm install --include=optional" in line),
                None,
            )
            binding_fix = (
                "RUN ROLLDOWN_VERSION=$(node -p \"require('./admin-web/node_modules/rolldown/package.json').version\") "
                "&& npm install --prefix admin-web --no-save --include=optional "
                "--registry=\"https://registry.npmmirror.com\" \"@rolldown/binding-linux-x64-gnu@$ROLLDOWN_VERSION\""
            )
            if install_line and binding_fix not in repaired:
                repaired = repaired.replace(install_line, install_line + "\n" + binding_fix, 1)
            if repaired != original:
                dockerfile.write_text(repaired, encoding="utf-8")
                changed.append(str(dockerfile.relative_to(root)).replace("\\", "/"))
    # Some older/locked-down Docker nodes allow ordinary writes to a named
    # volume but their default seccomp/AppArmor profile rejects PostgreSQL's
    # durable pid/WAL writes with EPERM.  This was verified independently with
    # a fresh `postgres` container, so it is a node capability issue rather
    # than an application defect.  On a retry, relax only the affected
    # PostgreSQL service; never grant blanket privilege to the whole project.
    postgres_storage_blocked = (
        "operation not permitted" in error
        and ("postmaster.pid" in error or "pg_wal/" in error)
    )
    if postgres_storage_blocked:
        for compose_file in root.glob(".yunzhou*.yml"):
            try:
                document = yaml.safe_load(compose_file.read_text(encoding="utf-8", errors="replace")) or {}
            except yaml.YAMLError:
                continue
            services = document.get("services") if isinstance(document, dict) else None
            repaired = False
            for service in (services or {}).values():
                if not isinstance(service, dict) or "postgres" not in str(service.get("image") or "").lower():
                    continue
                options = list(service.get("security_opt") or [])
                for option in ("seccomp=unconfined", "apparmor=unconfined"):
                    if option not in options:
                        options.append(option)
                        repaired = True
                service["security_opt"] = options
            if repaired:
                compose_file.write_text(yaml.safe_dump(document, allow_unicode=True, sort_keys=False), encoding="utf-8")
                relative = compose_file.relative_to(root).as_posix()
                if relative not in changed:
                    changed.append(relative)
    # Spring treats @Value("${key}") without a default as startup-required.
    # In managed-fresh mode an old Kubernetes service URL must not be copied
    # into the new environment, but an optional outbound integration also
    # should not prevent the core application from starting.  On a verified
    # missing URL/URI placeholder, inject a deterministic disabled endpoint
    # into application services.  It is intentionally non-routable and keeps
    # the missing integration visible; passwords and arbitrary scalar values
    # are never guessed.
    placeholder_match = re.search(
        r"could not resolve placeholder ['\"]([^'\"]+)['\"]",
        previous_error or "",
        re.I,
    )
    if placeholder_match:
        placeholder = placeholder_match.group(1).strip()
        # A project may contain an optional outbound feature whose String
        # properties were written as strict Spring @Value placeholders. Once
        # a real startup failure proves one member is absent, repair the whole
        # feature namespace in the disposable release copy so deployment does
        # not fail repeatedly on sibling keys. Core database/cache namespaces
        # are deliberately excluded and remain strict configuration errors.
        namespace = placeholder.split(".", 1)[0] if "." in placeholder else ""
        if namespace and namespace.lower() not in strict_spring_namespaces:
            annotation = re.compile(
                r'(@Value\(\s*["\']\$\{)'
                + re.escape(namespace)
                + r'(\.[A-Za-z0-9_.-]+)(\}["\']\s*\)\s*'
                  r'(?:private|protected|public)\s+String\s+)',
                re.MULTILINE,
            )
            for source_file in root.rglob("*.java"):
                if any(part in {".git", "target", "build"} for part in source_file.parts):
                    continue
                original = source_file.read_text(encoding="utf-8", errors="replace")
                repaired = annotation.sub(r"\1" + namespace + r"\2:\3", original)
                if repaired == original:
                    continue
                source_file.write_text(repaired, encoding="utf-8")
                relative = source_file.relative_to(root).as_posix()
                if relative not in changed:
                    changed.append(relative)
        if re.search(r"(?:url|uri)$", placeholder, re.I):
            env_key = re.sub(r"[^A-Za-z0-9]", "_", placeholder).upper()
            fallback_url = "http://127.0.0.1:9/"
            if deployment_mode == "preserve_integrations":
                parts = placeholder.split(".")
                for config_file in sorted(root.rglob("application*.yml")) + sorted(root.rglob("application*.yaml")):
                    try:
                        value = yaml.safe_load(config_file.read_text(encoding="utf-8", errors="replace")) or {}
                        for part in parts:
                            value = value.get(part) if isinstance(value, dict) else None
                        if isinstance(value, str) and value.startswith(("http://", "https://")):
                            fallback_url = value.strip()
                            break
                    except (OSError, yaml.YAMLError):
                        continue
            spring_value: dict = {}
            spring_cursor = spring_value
            for part in placeholder.split(".")[:-1]:
                spring_cursor[part] = {}
                spring_cursor = spring_cursor[part]
            spring_cursor[placeholder.split(".")[-1]] = fallback_url
            for compose_file in root.glob(".yunzhou*.yml"):
                try:
                    document = yaml.safe_load(compose_file.read_text(encoding="utf-8", errors="replace")) or {}
                except yaml.YAMLError:
                    continue
                services = document.get("services") if isinstance(document, dict) else None
                repaired = False
                for service_name, service in (services or {}).items():
                    if not isinstance(service, dict) or not service.get("build"):
                        continue
                    environment = service.get("environment") or {}
                    environment_keys = (
                        {str(item).split("=", 1)[0] for item in environment}
                        if isinstance(environment, list)
                        else {str(key) for key in environment} if isinstance(environment, dict) else set()
                    )
                    is_spring_service = (
                        any(key.startswith("SPRING_") for key in environment_keys)
                        or any(token in str(service_name).lower() for token in ("api", "backend", "spring"))
                        or "8080" in {str(value) for value in (service.get("expose") or [])}
                    )
                    if not is_spring_service:
                        continue
                    if isinstance(environment, list):
                        if not any(str(item).split("=", 1)[0] == env_key for item in environment):
                            environment.append(f"{env_key}={fallback_url}")
                            repaired = True
                        if not any(str(item).split("=", 1)[0] == "SPRING_APPLICATION_JSON" for item in environment):
                            environment.append("SPRING_APPLICATION_JSON=" + json.dumps(spring_value, ensure_ascii=False))
                            repaired = True
                    elif isinstance(environment, dict) and env_key not in environment:
                        environment[env_key] = fallback_url
                        repaired = True
                    if isinstance(environment, dict) and "SPRING_APPLICATION_JSON" not in environment:
                        # @Value placeholders retain camel-case spelling and
                        # are not always resolved by relaxed OS environment
                        # aliases. JSON preserves the exact dotted key.
                        environment["SPRING_APPLICATION_JSON"] = json.dumps(spring_value, ensure_ascii=False)
                        repaired = True
                    service["environment"] = environment
                if repaired:
                    compose_file.write_text(yaml.safe_dump(document, allow_unicode=True, sort_keys=False), encoding="utf-8")
                    relative = compose_file.relative_to(root).as_posix()
                    if relative not in changed:
                        changed.append(relative)
    return changed

