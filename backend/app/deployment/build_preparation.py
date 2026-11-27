"""Source-aware build preparation and generated platform build plans."""

import re
from pathlib import Path

from ..build_planning import PLATFORM_NGINX_IMAGE
from .architecture import find_compose as _find_compose, fullstack_roots as _fullstack_roots
from .build_generators import generate_profile_build, generate_static_build
from .build_handlers import detect_build, detect_container_port
from .build_profiles import detect_build_profiles
from .source_optimization import optimize_staged_sources
from ..source_inspection import detect_java_version


def prepare_build(path: str, requested: str) -> tuple[str, str, int | None]:
    """Generate a source-aware build for auto mode; explicit choices stay exact."""
    root = Path(path)
    build_profiles = {profile.key: profile for profile in detect_build_profiles(root)}
    optimize_staged_sources(path)
    if requested in ("compose", "dockerfile"):
        build_type, build_file = detect_build(path, requested)
        return build_type, build_file or "Dockerfile", detect_container_port(path)

    # Repository Compose/Dockerfile assets are evidence only.  Auto mode must
    # materialize a platform-owned build from the analyzed source instead of
    # executing a third-party file unchanged.
    compose_path = _find_compose(root)
    compose = compose_path.relative_to(root).as_posix() if compose_path else None

    # A common full-stack repository layout: one Vite/React directory plus a
    # Spring Boot directory. Generate an isolated three-service topology so
    # the frontend path in a browser URL cannot silently hide the backend.
    frontend_roots, backend_roots = _fullstack_roots(root)
    frontend = frontend_roots[0] if frontend_roots else None
    backend = backend_roots[0] if backend_roots else None
    if frontend and backend:
        frontend_rel = frontend.relative_to(root).as_posix()
        backend_rel = backend.relative_to(root).as_posix()
        init_sql = next((p for p in (root / "init.sql", root / "schema.sql") if p.exists()), None)
        managed_init_sql = None
        if init_sql:
            sql_text = init_sql.read_text(errors="ignore")
            # MySQL does not accept MariaDB's ADD COLUMN IF NOT EXISTS form.
            # Generate a deployment-only compatible copy; never edit the repo.
            sql_text = re.sub(r"(?i)\bADD\s+COLUMN\s+IF\s+NOT\s+EXISTS\b", "ADD COLUMN", sql_text)
            managed_init_sql = root / ".yunzhou.init.sql"
            managed_init_sql.write_text(sql_text)
        (root / ".yunzhou.frontend.Dockerfile").write_text(
            f"FROM node:22-alpine AS build\nWORKDIR /src\nCOPY {frontend_rel}/package*.json ./\nRUN npm config set registry https://registry.npmmirror.com && npm ci\n"
            f"COPY {frontend_rel}/ ./\nRUN npm run build\nFROM {PLATFORM_NGINX_IMAGE}\n"
            "COPY .yunzhou.nginx.conf /etc/nginx/conf.d/default.conf\nCOPY --from=build /src/dist /usr/share/nginx/html/app\nEXPOSE 80\n"
        )
        (root / ".yunzhou.maven-settings.xml").write_text('<settings xmlns="http://maven.apache.org/SETTINGS/1.0.0"><mirrors><mirror><id>aliyun</id><mirrorOf>*</mirrorOf><name>Aliyun Maven</name><url>https://maven.aliyun.com/repository/public</url></mirror></mirrors></settings>')
        (root / ".yunzhou.backend.Dockerfile").write_text(
            f"FROM maven:3.9-eclipse-temurin-{detect_java_version(str(backend))} AS build\nWORKDIR /src\nCOPY .yunzhou.maven-settings.xml /tmp/settings.xml\nCOPY {backend_rel}/ ./\n"
            "RUN mvn -s /tmp/settings.xml -DskipTests package\nRUN jar=\"$(find target -name '*.jar' ! -name 'original-*' -type f | head -n1)\" && test -n \"$jar\" && cp \"$jar\" /tmp/app.jar\n"
            f"FROM eclipse-temurin:{detect_java_version(str(backend))}-jre\nWORKDIR /app\nCOPY --from=build /tmp/app.jar app.jar\nEXPOSE 8080\nCMD [\"java\",\"-jar\",\"app.jar\"]\n"
        )
        (root / ".yunzhou.nginx.conf").write_text(
            "server { listen 80; server_name _; client_max_body_size 50m; "
            "location = / { return 302 /app/; } "
            "location /app/api/ { proxy_pass http://backend:8080/api/; proxy_http_version 1.1; "
            "proxy_set_header Host $host; proxy_set_header X-Real-IP $remote_addr; proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for; } "
            "location /app/ { root /usr/share/nginx/html; try_files $uri $uri/ /app/index.html; } }\n"
        )
        init_mount = f"      - ./{managed_init_sql.name}:/docker-entrypoint-initdb.d/001-init.sql:ro\n" if managed_init_sql else ""
        compose_text = f'''services:
  db:
    image: mysql:8.4
    restart: unless-stopped
    environment:
      MYSQL_DATABASE: crm
      MYSQL_USER: crm
      MYSQL_PASSWORD: ${{CRM_DB_PASSWORD}}
      MYSQL_ROOT_PASSWORD: ${{CRM_DB_ROOT_PASSWORD}}
    volumes:
      - crm-data:/var/lib/mysql
{init_mount}    healthcheck:
      test: ["CMD", "mysqladmin", "ping", "-h", "127.0.0.1", "-uroot", "-p${{CRM_DB_ROOT_PASSWORD}}"]
      interval: 10s
      timeout: 5s
      retries: 30
  backend:
    build:
      context: .
      dockerfile: .yunzhou.backend.Dockerfile
    restart: unless-stopped
    environment:
      DB_URL: jdbc:mysql://db:3306/crm?useUnicode=true&characterEncoding=utf8&serverTimezone=Asia/Shanghai&useSSL=false&allowPublicKeyRetrieval=true
      DB_USERNAME: crm
      DB_PASSWORD: ${{CRM_DB_PASSWORD}}
      CRM_JWT_SECRET: ${{CRM_JWT_SECRET}}
    depends_on:
      db:
        condition: service_healthy
  frontend:
    build:
      context: .
      dockerfile: .yunzhou.frontend.Dockerfile
    restart: unless-stopped
    ports:
      - "${{YUNZHOU_HOST_PORT}}:80"
    depends_on:
      - backend
volumes:
  crm-data:
'''
        generated_compose = root / ".yunzhou.compose.yml"
        generated_compose.write_text(compose_text)
        return "compose", generated_compose.name, None

    # Some complete repositories keep the production Dockerfile in
    # containers/ or deploy/ while its build context must remain the repository
    # root. Recognize that layout before falling back to root-only manifests.
    nested_dockerfiles = [
        item for item in root.rglob("Dockerfile")
        if item.is_file() and not any(part in {".git", "node_modules", "target", "dist", "build"} for part in item.relative_to(root).parts)
    ]
    preferred_dockerfile = next((item for item in nested_dockerfiles if item.parent.name in {"containers", "deploy", "docker"}), None)
    if not preferred_dockerfile and len(nested_dockerfiles) == 1:
        preferred_dockerfile = nested_dockerfiles[0]
    # The deterministic fallback cannot prove arbitrary instructions safe.
    # Keep these files available as evidence but do not select them as the
    # executable build artifact; known source layouts below get a newly
    # generated platform Dockerfile, unknown layouts request a fresh AI plan.
    preferred_dockerfile = None
    if preferred_dockerfile:
        dockerfile_rel = preferred_dockerfile.relative_to(root).as_posix()
        port = detect_container_port(path, dockerfile_rel)
        combined = ""
        for name in (".env.example", "PROJECT_CONTEXT.yml", "README.md"):
            candidate = root / name
            if candidate.exists():
                combined += "\n" + candidate.read_text(errors="ignore")
        uses_mysql = bool(re.search(r"(?i)(DB_HOST|target_database:\s*MySQL|COMMERCE_OPS_PERSISTENCE)", combined))
        if uses_mysql:
            generated_compose = root / ".yunzhou.compose.yml"
            generated_compose.write_text(f'''services:
  db:
    image: mysql:8.4
    restart: unless-stopped
    environment:
      MYSQL_DATABASE: commerce_ops
      MYSQL_USER: commerce_ops_app
      MYSQL_PASSWORD: ${{CRM_DB_PASSWORD}}
      MYSQL_ROOT_PASSWORD: ${{CRM_DB_ROOT_PASSWORD}}
    volumes:
      - commerce-ops-mysql:/var/lib/mysql
    healthcheck:
      test: ["CMD", "mysqladmin", "ping", "-h", "127.0.0.1", "-uroot", "-p${{CRM_DB_ROOT_PASSWORD}}"]
      interval: 10s
      timeout: 5s
      retries: 30
  app:
    build:
      context: .
      dockerfile: {dockerfile_rel}
    restart: unless-stopped
    environment:
      ADMIN_API_HOST: 0.0.0.0
      ADMIN_API_PORT: {port or 4300}
      COMMERCE_OPS_PERSISTENCE: mysql
      DB_HOST: db
      DB_PORT: 3306
      DB_NAME: commerce_ops
      DB_USERNAME: commerce_ops_app
      DB_PASSWORD: ${{CRM_DB_PASSWORD}}
    ports:
      - "${{YUNZHOU_HOST_PORT}}:{port or 4300}"
    volumes:
      - commerce-ops-images:/data/images
      - commerce-ops-publisher:/data/publisher
    depends_on:
      db:
        condition: service_healthy
volumes:
  commerce-ops-mysql:
  commerce-ops-images:
  commerce-ops-publisher:
''')
            return "compose", generated_compose.name, None
        return "dockerfile", dockerfile_rel, port

    generated = root / ".yunzhou.Dockerfile"
    reference_port = detect_container_port(path)
    generated_build = generate_profile_build(
        root,
        build_profiles,
        nginx_image=PLATFORM_NGINX_IMAGE,
        java_version=detect_java_version,
    ) or generate_static_build(root, nginx_image=PLATFORM_NGINX_IMAGE)
    if generated_build:
        for relative, content in (generated_build.supporting_files or {}).items():
            (root / relative).write_text(content)
        generated.write_text(generated_build.dockerfile)
        return "dockerfile", generated.name, reference_port or generated_build.port
    if (root / "Dockerfile").exists():
        raise RuntimeError(
            "平台已将仓库 Dockerfile 作为参考完成扫描，但无法仅凭当前源码安全重新生成等价的经典构建文件；"
            "请重新执行 AI 源码分析，不会直接复用仓库 Dockerfile"
        )
    raise RuntimeError("无法从源码安全生成平台构建文件，请重新执行 AI 源码分析")

