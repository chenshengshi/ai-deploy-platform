import re
import zipfile
from pathlib import Path
from urllib.parse import urlsplit


_FRONTEND_API_ENV_KEYS = (
    "VUE_APP_BASE_API", "VITE_API_BASE_URL", "VITE_BASE_API",
    "API_BASE_URL", "API_PREFIX",
)


def _executable_jar_score(path: Path) -> tuple[int, int, int, str]:
    """Rank runnable application JARs ahead of parent/library artifacts.

    Maven reactors may emit several similarly named JARs.  Size and module
    names are only tie breakers: the manifest is the authoritative evidence
    that ``java -jar`` can start the selected artifact.
    """
    manifest = ""
    try:
        with zipfile.ZipFile(path) as archive:
            manifest = archive.read("META-INF/MANIFEST.MF").decode("utf-8", "ignore")
    except (OSError, KeyError, zipfile.BadZipFile):
        pass
    executable = bool(re.search(r"(?im)^(?:Main-Class|Start-Class):\s*\S+", manifest))
    spring_boot = bool(re.search(r"(?im)^Start-Class:\s*\S+", manifest))
    return (
        int(executable),
        int(spring_boot),
        path.stat().st_size if path.is_file() else 0,
        path.as_posix(),
    )


def _select_runnable_jar(paths: list[Path]) -> Path | None:
    candidates = [path for path in paths if path.is_file()]
    return max(candidates, key=_executable_jar_score) if candidates else None


def enforce_nginx_pid_compatibility(dockerfile_text: str) -> str:
    """Let the Debian nginx image own its PID file; remove stale CLI overrides."""
    from_lines = re.findall(
        r"(?im)^\s*FROM\s+(?:--platform=\S+\s+)?(?P<image>\S+)",
        dockerfile_text,
    )
    if not from_lines or not re.match(r"(?i)(?:[^/]+/)*nginx(?:[:@]|$)", from_lines[-1]):
        return dockerfile_text

    lines: list[str] = []
    for line in dockerfile_text.splitlines():
        if re.match(r"(?i)^\s*(?:CMD|ENTRYPOINT)\b", line):
            line = re.sub(r"(?i)pid\s+[^;]+;\s*", "", line)
        lines.append(line)
    return "\n".join(lines).rstrip() + "\n"


def dockerfile_base_images(path: str, dockerfile_name: str) -> list[str]:
    dockerfile = Path(path) / dockerfile_name
    if not dockerfile.exists():
        return []
    images = []
    for match in re.finditer(r"(?im)^\s*FROM\s+(?:--platform=\S+\s+)?([^\s]+)", dockerfile.read_text(errors="ignore")):
        image = match.group(1).strip()
        if image and "$" not in image and image.lower() != "scratch" and image not in images:
            images.append(image)
    return images


def detect_java_version(path: str) -> int:
    """Choose the project's declared Java level before generating a build image."""
    root = Path(path)
    values = []
    for pom in list(root.rglob("pom.xml"))[:80]:
        text = pom.read_text(errors="ignore")
        for tag in ("java.version", "maven.compiler.source", "maven.compiler.target"):
            values.extend(re.findall(rf"<{re.escape(tag)}>\s*([^<]+)\s*</{re.escape(tag)}>", text, re.I))
    for value in values:
        match = re.search(r"(?:1\.)?(8|11|17|21)", value.strip())
        if match:
            return int(match.group(1))
    # JDK 17 is the broadly compatible modern default. JDK 21 is too new for
    # many legacy Lombok/compiler combinations and should only be explicit.
    return 17


def detect_spring_boot_version(path: str) -> str | None:
    """Return an explicit Spring Boot version declared by Maven source."""
    root = Path(path)
    texts = [pom.read_text(encoding="utf-8", errors="ignore") for pom in list(root.rglob("pom.xml"))[:80]]
    patterns = (
        r"<spring-boot\.version>\s*([^<\s]+)\s*</spring-boot\.version>",
        r"<artifactId>spring-boot-starter-parent</artifactId>[\s\S]{0,240}?<version>\s*([^<\s]+)",
        r"<artifactId>spring-boot-dependencies</artifactId>[\s\S]{0,240}?<version>\s*([^<\s]+)",
    )
    for pattern in patterns:
        for text in texts:
            match = re.search(pattern, text, re.I)
            if match and re.match(r"^\d+(?:\.\d+){1,3}(?:[-.][A-Za-z0-9]+)*$", match.group(1)):
                return match.group(1)
    return None


def _public_path_from_value(value: str) -> str | None:
    """Return a usable public URL prefix without guessing one.

    A bare external origin (for example ``https://api.example.com``) contains
    no path evidence and is deliberately ignored.  The caller must then use
    another source signal such as the production dotenv file or an Nginx
    location instead of silently inventing ``/api``.
    """
    raw = str(value or "").strip().strip("'\"").rstrip(";,)")
    if not raw or any(token in raw for token in ("${", "$VITE_", "$VUE_", "{{")):
        return None
    if raw.startswith(("http://", "https://", "//")):
        parsed = urlsplit("https:" + raw if raw.startswith("//") else raw)
        raw = parsed.path or ""
    if not raw.startswith("/") or raw == "/":
        return None
    raw = re.sub(r"/{2,}", "/", raw.split("?", 1)[0].split("#", 1)[0])
    # These are page/static paths, not API gateway prefixes.
    if raw.lower().startswith(("/assets/", "/static/", "/public/", "/src/")):
        return None
    return raw.rstrip("/") or None


def detect_frontend_api_routes(path: str) -> dict:
    """Detect the one effective frontend API prefix from source evidence.

    The detector ranks runtime configuration, production dotenv files,
    request-client ``baseURL`` values and Nginx proxy locations.  It returns a
    single primary route rather than publishing every development/staging
    alias found in the repository.
    """
    root = Path(path)
    ignored = {".git", "node_modules", "target", "dist", "build", ".venv", "vendor"}
    candidates: dict[str, dict] = {}

    def add(value: str, score: int, source: str, strip_prefix: bool | None = None) -> None:
        public_path = _public_path_from_value(value)
        if not public_path:
            return
        # Production is stronger evidence than development/staging aliases.
        lowered = public_path.lower()
        adjusted = score + (8 if "prod" in lowered else 0) - (8 if any(x in lowered for x in ("stage", "dev", "test")) else 0)
        row = candidates.setdefault(public_path, {
            "path": public_path,
            "score": adjusted,
            "strip_prefix": strip_prefix,
            "evidence": [],
        })
        if adjusted > int(row["score"]):
            row["score"] = adjusted
        if strip_prefix is not None:
            row["strip_prefix"] = strip_prefix
        if source not in row["evidence"]:
            row["evidence"].append(source)

    env_pattern = re.compile(
        rf"(?m)^\s*(?:{'|'.join(map(re.escape, _FRONTEND_API_ENV_KEYS))})\s*=\s*([^\r\n#]+)"
    )
    production_origin_sources: list[str] = []
    staged_relative_routes: list[tuple[str, str]] = []
    for env_file in root.rglob(".env*"):
        if not env_file.is_file() or any(part in ignored for part in env_file.relative_to(root).parts):
            continue
        relative = env_file.relative_to(root).as_posix()
        name = env_file.name.lower()
        score = 96 if "production" in name or name in {".env", ".env.local"} else 68
        text_value = env_file.read_text(encoding="utf-8", errors="replace")
        for match in env_pattern.finditer(text_value):
            raw_value = match.group(1).strip().strip("'\"")
            relative_path = _public_path_from_value(raw_value)
            if "production" in name and raw_value.startswith(("http://", "https://", "//")) and not relative_path:
                # A production frontend that points at a bare legacy API
                # origin still needs a same-origin path when the platform
                # takes over routing.  Keep that fact as evidence; do not
                # silently fall back to a global /api convention.
                production_origin_sources.append(relative)
            if "staging" in name and relative_path:
                staged_relative_routes.append((relative_path, relative))
            add(raw_value, score, relative)

    # Vue CLI projects commonly keep production on a legacy absolute API
    # origin while the staging file describes the intended gateway path (for
    # example /stage-api).  `npm run build` selects .env.production, so expose
    # neither the staging route nor a guessed /api route.  Derive the matching
    # production path from both pieces of source evidence instead.
    if production_origin_sources:
        for staged_path, staged_source in staged_relative_routes:
            production_path = re.sub(r"(?i)(?:stage|staging)", "prod", staged_path)
            if production_path != staged_path:
                evidence = f"{production_origin_sources[0]} + {staged_source}（生产外部域名按同项目环境命名归一）"
                add(production_path, 106, evidence, True)

    for runtime_config in root.rglob("postUrl.js"):
        if not runtime_config.is_file() or any(part in ignored for part in runtime_config.relative_to(root).parts):
            continue
        relative = runtime_config.relative_to(root).as_posix()
        text_value = runtime_config.read_text(encoding="utf-8", errors="replace")
        for match in re.finditer(r"(?m)^\s*(?:const|let|var)\s+IP\s*=\s*['\"]([^'\"]+)['\"]", text_value):
            add(match.group(1), 105, relative)

    source_suffixes = {".js", ".jsx", ".ts", ".tsx", ".vue", ".mjs", ".cjs"}
    for source_file in root.rglob("*"):
        if not source_file.is_file() or source_file.suffix.lower() not in source_suffixes:
            continue
        if any(part in ignored for part in source_file.relative_to(root).parts) or source_file.stat().st_size > 1_000_000:
            continue
        relative = source_file.relative_to(root).as_posix()
        text_value = source_file.read_text(encoding="utf-8", errors="replace")
        for match in re.finditer(r"\bbaseURL\s*:\s*['\"]([^'\"]+)['\"]", text_value):
            add(match.group(1), 88, relative)

    nginx_names = {"nginx.conf", "default.conf"}
    for config_file in root.rglob("*"):
        if not config_file.is_file() or (config_file.name not in nginx_names and config_file.suffix.lower() != ".conf"):
            continue
        if any(part in ignored for part in config_file.relative_to(root).parts) or config_file.stat().st_size > 1_000_000:
            continue
        relative = config_file.relative_to(root).as_posix()
        text_value = config_file.read_text(encoding="utf-8", errors="replace")
        # This bounded block matcher covers ordinary generated/hand-written
        # location blocks without trying to implement a complete Nginx parser.
        for match in re.finditer(r"location\s+(?:\^~\s+|=\s+|~\*?\s+)?(?P<path>/[^\s{]*)\s*\{(?P<body>[^{}]*)\}", text_value, re.I | re.S):
            body = match.group("body")
            proxy = re.search(r"proxy_pass\s+(?P<url>https?://[^;\s]+)\s*;", body, re.I)
            if proxy:
                # Nginx only removes the matched public prefix when the
                # proxy_pass URI is the upstream root.  A target such as
                # ``location /api/ { proxy_pass http://backend/api/; }`` keeps
                # /api/ and must not be represented as strip_prefix=true.
                # A proxy_pass without a URI also preserves the full request.
                location_path = match.group("path")
                upstream_path = urlsplit(proxy.group("url")).path
                strip_prefix = bool(
                    location_path != "/" and upstream_path == "/"
                )
                add(location_path, 82, relative, strip_prefix)

    if not candidates:
        return {"primary_path": None, "routes": [], "evidence": []}
    selected = max(candidates.values(), key=lambda row: (int(row["score"]), len(row["evidence"]), -len(row["path"])))
    public_path = str(selected["path"]).rstrip("/")
    return {
        "primary_path": public_path,
        "routes": [{
            "path": public_path + "/",
            # Preserve an observed public prefix unless a production proxy
            # rule explicitly proves that it is only an external alias. A
            # guessed strip silently turns valid backend routes into frontend
            # HTML responses and is much harder to diagnose than a 404.
            "strip_prefix": False if selected["strip_prefix"] is None else bool(selected["strip_prefix"]),
        }],
        "evidence": list(selected["evidence"]),
        "candidates": sorted(
            ({"path": row["path"], "score": row["score"], "evidence": row["evidence"]} for row in candidates.values()),
            key=lambda row: (-int(row["score"]), row["path"]),
        ),
    }


def detect_frontend_public_base(path: str) -> dict:
    """Detect a non-root frontend mount from production source evidence.

    API prefixes and the frontend mount are different contracts.  A project
    can request ``/app/api/v1`` while its static SPA itself must be served from
    ``/app/``.  Only production dotenv/config evidence is accepted here; no
    project-wide default is invented.
    """
    root = Path(path)
    ignored = {".git", "node_modules", "target", "dist", "build", ".venv", "vendor"}
    candidates: dict[str, dict] = {}

    def add(value: str, score: int, source: str) -> None:
        raw = str(value or "").strip().strip("'\"").split("?", 1)[0].split("#", 1)[0]
        if not raw.startswith("/") or raw == "/":
            return
        normalized = "/" + raw.strip("/") + "/"
        row = candidates.setdefault(normalized, {"path": normalized, "score": score, "evidence": []})
        row["score"] = max(int(row["score"]), score)
        if source not in row["evidence"]:
            row["evidence"].append(source)

    env_pattern = re.compile(
        r"(?m)^\s*(?:VITE_APP_BASE|BASE_URL|PUBLIC_URL|VUE_APP_PUBLIC_PATH)\s*=\s*([^\r\n#]+)"
    )
    for env_file in root.rglob(".env*"):
        if not env_file.is_file() or any(part in ignored for part in env_file.relative_to(root).parts):
            continue
        name = env_file.name.lower()
        if "production" not in name and name not in {".env", ".env.local"}:
            continue
        relative = env_file.relative_to(root).as_posix()
        text_value = env_file.read_text(encoding="utf-8", errors="replace")
        for match in env_pattern.finditer(text_value):
            add(match.group(1), 120 if "production" in name else 95, relative)

    # A production Nginx static location corroborates the dotenv value.  It is
    # deliberately not sufficient on its own because many repositories retain
    # obsolete deployment examples beside the current application.
    for config_file in root.rglob("*.conf"):
        if not config_file.is_file() or any(part in ignored for part in config_file.relative_to(root).parts):
            continue
        relative = config_file.relative_to(root).as_posix()
        text_value = config_file.read_text(encoding="utf-8", errors="replace")
        for match in re.finditer(r"location\s+(?:\^~\s+|=\s+)?(?P<path>/[^\s{]+)\s*\{(?P<body>[^{}]*)\}", text_value, re.I | re.S):
            body = match.group("body")
            if "proxy_pass" not in body and re.search(r"\b(?:root|alias|try_files)\b", body):
                add(match.group("path"), 70, relative)

    if not candidates:
        return {"primary_path": "/", "evidence": []}
    selected = max(candidates.values(), key=lambda row: (int(row["score"]), len(row["evidence"])))
    # Require production environment evidence. This prevents an old Nginx
    # sample from moving an otherwise root-hosted application unexpectedly.
    if not any(".env" in source for source in selected["evidence"]):
        return {"primary_path": "/", "evidence": []}
    return {"primary_path": selected["path"], "evidence": list(selected["evidence"])}
