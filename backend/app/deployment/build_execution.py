"""Central classic-build execution and image distribution."""

import hashlib
import json
import re
import shlex
import shutil
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

import yaml

from ..build_planning import (
    PLATFORM_NGINX_IMAGE,
    detect_java_log_directories,
    platform_spa_runtime_dockerfile,
    runtime_stage_from_prebuilt_artifact,
)
from ..config import decrypt, settings
from ..models import Deployment, DeploymentSettings, Node, Project
from ..proxy import get_proxy_config, proxy_with_auth
from ..source_inspection import (
    _executable_jar_score,
    _select_runnable_jar,
    detect_frontend_public_base,
    detect_java_version,
    detect_spring_boot_version,
    enforce_nginx_pid_compatibility,
)
from ..ssh import SSHNode
from .build_context import (
    ensure_context_ignore,
    ensure_generated_copy_inputs,
    snapshot_deployment_files,
    source_manifests,
    validate_runtime_only_dockerfiles,
)
from .build_profiles import compatible_node_image
from .compose_plan import compose_service_mapping as _compose_service_mapping
from .execution_log import ANSI_RE, log, tracked_run
from .gateway import platform_gateway_node
from .image_cleanup import cleanup_registry_versions, verify_registry_tag
from .runtime_ports import project_traffic_plan as _project_traffic_plan, traffic_service_roles as _traffic_service_roles
from .topology import repair_generated_node_dependency_copy


def central_build_and_distribute(
    db, deployment: Deployment, project: Project, target: Node, work: str,
    build_type: str, build_file: str, release: str, image_name: str | None,
    compose_override: str | None, built_images: list[str], platform: str, stream,
) -> Node:
    builder = platform_gateway_node(db)
    if not builder:
        raise RuntimeError("未配置平台构建服务器，无法执行统一构建")
    builder_root = f"{settings.build_data_root.rstrip('/')}/builder"
    # The worker and the platform builder share /data/yunzhou. Build directly
    # from the project's single fixed checkout instead of uploading a second
    # full copy for every release.
    builder_dir = work
    archive = f"/tmp/yunzhou-images-{deployment.id}.tar.gz"
    images = built_images if build_type == "compose" else [image_name]
    images = [value for value in images if value]
    if build_type == "compose" and not images:
        log(
            deployment.id,
            "[平台构建] Compose 全部服务均使用固定镜像且没有 build，已跳过 Node/Python/Java 依赖编译与镜像封装。\n",
        )
        return builder
    # Compose validates required ${VAR:?message} substitutions before it even
    # starts an image build. Runtime secrets are irrelevant to that build, so
    # provide safe ephemeral placeholders for every required variable instead
    # of maintaining a fragile hard-coded list (Redis, OIDC, SMTP, etc.).
    required_build_vars: set[str] = set()
    referenced_build_vars: set[str] = set()
    if build_type == "compose":
        for filename in (build_file, compose_override):
            if not filename:
                continue
            candidate = Path(work) / filename
            if not candidate.exists():
                continue
            text = candidate.read_text(encoding="utf-8", errors="ignore")
            required_build_vars.update(re.findall(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::?\?)", text))
            referenced_build_vars.update(re.findall(r"\$\{([A-Za-z_][A-Za-z0-9_]*)", text))
    # Populate generic substitutions first, then override typed platform
    # values.  Otherwise a referenced YUNZHOU_HOST_PORT is overwritten with
    # the string ``build-placeholder`` and Compose rejects it as hostPort.
    build_env = {
        **{key: "build-placeholder" for key in referenced_build_vars | required_build_vars},
        "YUNZHOU_HOST_PORT": "1",
        "CRM_DB_PASSWORD": "build-placeholder",
        "CRM_DB_ROOT_PASSWORD": "build-placeholder",
        "CRM_JWT_SECRET": "build-placeholder",
    }
    build_env.update({
        # Build-tool settings are not secrets and must never receive the
        # generic placeholder.  A placeholder used as PIP_INDEX_URL makes pip
        # treat it as a local directory, so every valid dependency appears to
        # be missing and an automatic retry repeats the same failure.
        "PIP_INDEX_URL": "https://pypi.tuna.tsinghua.edu.cn/simple/",
        "NPM_REGISTRY": "https://registry.npmmirror.com/",
        "APT_MIRROR": "https://mirrors.tuna.tsinghua.edu.cn",
        "YUNZHOU_MYSQL_HOST": "127.0.0.1",
        "YUNZHOU_MYSQL_PORT": "3306",
        "YUNZHOU_MYSQL_DATABASE": "build",
        "YUNZHOU_MYSQL_USERNAME": "build",
        "YUNZHOU_MYSQL_PASSWORD": "build-placeholder",
        "YUNZHOU_REDIS_HOST": "127.0.0.1",
        "YUNZHOU_REDIS_PORT": "6379",
        "YUNZHOU_REDIS_DATABASE": "0",
        "YUNZHOU_REDIS_PASSWORD": "build-placeholder",
    })
    # Application proxy settings must also reach the short-lived toolchain
    # containers.  Merely setting the worker process environment does not make
    # `yarn install`, npm, Maven or pip inside `docker run` use that proxy.
    proxy_config = get_proxy_config(db)
    build_proxy_env: dict[str, str] = {}
    if proxy_config and proxy_config.enabled:
        proxy_password = decrypt(proxy_config.proxy_password_encrypted) if proxy_config.proxy_password_encrypted else ""
        http_proxy = proxy_with_auth(
            proxy_config.http_proxy or proxy_config.https_proxy,
            proxy_config.proxy_username or "",
            proxy_password or "",
        )
        https_proxy = proxy_with_auth(
            proxy_config.https_proxy or proxy_config.http_proxy,
            proxy_config.proxy_username or "",
            proxy_password or "",
        )
        no_proxy = (proxy_config.no_proxy or "").strip()
        build_proxy_env = {
            "HTTP_PROXY": http_proxy,
            "HTTPS_PROXY": https_proxy,
            "NO_PROXY": no_proxy,
            "http_proxy": http_proxy,
            "https_proxy": https_proxy,
            "no_proxy": no_proxy,
        }
        build_proxy_env = {key: value for key, value in build_proxy_env.items() if value}
        build_env.update(build_proxy_env)
        log(deployment.id, "[网络] 应用代理已启用，源码与构建依赖下载统一通过代理；内网地址继续直连。\n")
    else:
        log(deployment.id, "[网络] 应用代理未启用，源码与构建依赖下载使用直连。\n")
    proxy_run_args = " ".join(
        f"-e {key}={shlex.quote(value)}" for key, value in sorted(build_proxy_env.items())
    )
    proxy_build_args = " ".join(
        f"--build-arg {key}={shlex.quote(value)}" for key, value in sorted(build_proxy_env.items())
    )
    proxy_compose_override: str | None = None
    if build_type == "compose" and build_proxy_env:
        # Compose has no command-line equivalent of `docker build --build-arg`
        # that applies to every service.  Add a disposable override containing
        # environment references (never credentials) so every service build
        # receives the same global proxy policy.
        build_services: set[str] = set()
        for filename in (build_file, compose_override):
            if not filename:
                continue
            candidate = Path(work) / filename
            if not candidate.is_file():
                continue
            try:
                document = yaml.safe_load(candidate.read_text(encoding="utf-8")) or {}
            except Exception:
                continue
            for service_name, service in (document.get("services") or {}).items():
                if isinstance(service, dict) and service.get("build"):
                    build_services.add(str(service_name))
        if build_services:
            proxy_compose_override = ".yunzhou.proxy-build.yml"
            proxy_refs = {key: f"${{{key}:-}}" for key in sorted(build_proxy_env)}
            proxy_document = {
                "services": {
                    service_name: {"build": {"args": proxy_refs}}
                    for service_name in sorted(build_services)
                }
            }
            (Path(work) / proxy_compose_override).write_text(
                yaml.safe_dump(proxy_document, allow_unicode=True, sort_keys=False),
                encoding="utf-8",
            )
    build_env_prefix = " ".join(
        f"{key}={shlex.quote(value)}" for key, value in sorted(build_env.items())
    )
    # Compose expands the complete document even when only one image service
    # is being packaged. Give it a non-secret build-only env file so optional
    # runtime variables do not become empty strings or flood the UI with false
    # warnings. Real runtime values are injected later on the target node.
    build_env_file = Path(work) / ".yunzhou.build.env"
    build_env_file.write_text(
        "\n".join(f"{key}={str(value).replace(chr(10), '')}" for key, value in sorted(build_env.items())) + "\n",
        encoding="utf-8",
    )
    with SSHNode(builder) as build_ssh:
        build_ssh.run(f"mkdir -p {shlex.quote(builder_dir)}")
        build_policy = db.get(DeploymentSettings, "default")
        cache_root = (build_policy.build_cache_root if build_policy else "") or f"{builder_root}/cache"
        maven_cache_dir = (build_policy.maven_cache_dir if build_policy else "") or "/root/.m2"
        gradle_cache_dir = (build_policy.gradle_cache_dir if build_policy else "") or "/home/gradle/.gradle"
        npm_cache_dir = (build_policy.npm_cache_dir if build_policy else "") or "/root/.npm"
        pnpm_cache_dir = (build_policy.pnpm_cache_dir if build_policy else "") or "/root/.local/share/pnpm/store"
        yarn_cache_dir = (build_policy.yarn_cache_dir if build_policy else "") or "/root/.cache/yarn"
        pip_cache_dir = (build_policy.pip_cache_dir if build_policy else "") or "/root/.cache/pip"
        maven_cache_env = f"-e MAVEN_OPTS={shlex.quote('-Dmaven.repo.local=' + maven_cache_dir)} "
        gradle_cache_env = f"-e GRADLE_USER_HOME={shlex.quote(gradle_cache_dir)} "
        node_cache_env = (
            f"-e npm_config_cache={shlex.quote(npm_cache_dir)} "
            f"-e YARN_CACHE_FOLDER={shlex.quote(yarn_cache_dir)} "
        )
        pip_cache_env = f"-e PIP_CACHE_DIR={shlex.quote(pip_cache_dir)} "
        cache_dirs = " ".join(
            shlex.quote(f"{cache_root}/{name}")
            for name in ("maven", "gradle", "pnpm", "npm", "yarn", "pip", "nuget", "go-mod", "go-build")
        )
        code, output = build_ssh.run(f"mkdir -p {cache_dirs}")
        if code:
            raise RuntimeError("公共依赖缓存目录创建失败：" + output[-800:])
        log(
            deployment.id,
            "[构建策略] 使用经典 Docker 构建（BuildKit/Buildx 已关闭）；"
            f"公共依赖缓存位于 {cache_root}/{{maven,gradle,npm,pnpm,yarn,pip,nuget,go-mod,go-build}}。\n",
        )

        # Discover dependency manifests recursively instead of assuming that
        # they live at the repository root.  Monorepos commonly keep the real
        # application under ui/, server/, FRCloud/, etc.  Warm every package
        # manager through the same host-mounted cache before the classic
        # Docker build starts.  The warm-up is deliberately best-effort: a
        # source-level dependency error must still be diagnosed by the real
        # build, while successfully downloaded packages remain reusable by
        # later projects and retries.
        source_root = Path(work)
        ignored_parts = {".git", "node_modules", "target", "dist", "build", ".gradle", ".venv"}



        ensure_context_ignore(source_root)
        node_built_contexts: set[str] = set()
        maven_built_contexts: set[str] = set()
        persistent_dependency_root = Path(builder_root) / "projects" / project.slug / "dependencies"


        node_manifests = source_manifests(source_root, "package.json", ignored_parts)
        generated_dockerfiles = [
            path for path in source_root.rglob(".yunzhou*.Dockerfile") if path.is_file()
        ]
        # When a repository contains both the real frontend and an auxiliary
        # documentation/demo site, building every package.json lets the first
        # completed dist directory claim the frontend image.  The generated
        # Dockerfile is the authoritative deployment plan, so prefer Node
        # modules that it explicitly copies.  A broad ``COPY . .`` provides
        # no module evidence and deliberately keeps the previous fallback.
        referenced_node_manifests: list[Path] = []
        generated_docker_text = "\n".join(
            path.read_text(encoding="utf-8", errors="ignore")
            for path in generated_dockerfiles
        )
        collapsed_docker_text = re.sub(r"\\\s*\r?\n\s*", " ", generated_docker_text)
        for manifest in node_manifests:
            relative_parent = manifest.parent.relative_to(source_root).as_posix()
            if relative_parent == ".":
                continue
            escaped_parent = re.escape(relative_parent.rstrip("/"))
            if re.search(
                rf"(?im)^\s*(?:COPY|ADD)\s+[^\n]*?(?:^|[\s\"'])\.?/?{escaped_parent}(?:/|[\s\"'])",
                collapsed_docker_text,
            ):
                referenced_node_manifests.append(manifest)
        if referenced_node_manifests and len(referenced_node_manifests) < len(node_manifests):
            skipped_modules = [
                manifest.parent.relative_to(source_root).as_posix()
                for manifest in node_manifests
                if manifest not in referenced_node_manifests
            ]
            node_manifests = referenced_node_manifests
            log(
                deployment.id,
                "[构建范围] 按发布方案仅构建正式前端模块；已排除文档/示例模块："
                + "、".join(skipped_modules) + "。\n",
            )
        for generated_dockerfile in generated_dockerfiles:
            context = generated_dockerfile.parent
            ensure_context_ignore(context)
            if repair_generated_node_dependency_copy(context, generated_dockerfile):
                log(
                    deployment.id,
                    "[平台兼容] 生成的运行镜像不能从源码上下文复制 node_modules；"
                    "已改为在镜像内按锁文件安装运行依赖。\n",
                )
            restored_inputs = ensure_generated_copy_inputs(context, generated_dockerfile)
            if restored_inputs:
                log(
                    deployment.id,
                    "[构建上下文] 生成文件明确引用的源码已从仓库忽略规则中恢复："
                    + "、".join(restored_inputs) + "。\n",
                )
        has_generated_multistage = any(
            len(re.findall(r"(?im)^\s*FROM\s+", path.read_text(encoding="utf-8", errors="ignore"))) > 1
            for path in generated_dockerfiles
        )
        pom_files = source_manifests(source_root, "pom.xml", ignored_parts)
        reactor_poms = [
            pom for pom in pom_files
            if not any(parent / "pom.xml" in pom_files for parent in pom.parents if parent != pom.parent)
        ]

        # WMS-style Java + Vue projects already have platform-owned, runtime-
        # only Dockerfiles at this point.  Package each side as soon as its
        # artifact is ready instead of waiting for the other compiler.  The
        # global image-store lock still protects classic Docker commits, while
        # Maven/Node compilation remains concurrent outside that lock.
        eager_package_specs: dict[str, dict[str, str]] = {}
        eager_packaged_services: set[str] = set()
        eager_package_guard = threading.Lock()
        # The generated image overlay is not guaranteed to keep the same file
        # name between analyzers (and legacy plans may place it beside the
        # primary compose file). Discover every platform-owned compose snapshot
        # for this release so eager packaging never depends on a project or
        # service naming convention.
        eager_compose_files: list[Path] = []
        for eager_candidate in (
            Path(work) / str(build_file or ""),
            Path(work) / str(compose_override or ""),
            *sorted(Path(work).glob(".yunzhou*.yml")),
            *sorted(Path(work).glob(".yunzhou*.yaml")),
        ):
            if eager_candidate.is_file() and eager_candidate not in eager_compose_files:
                eager_compose_files.append(eager_candidate)
        for eager_compose_file in eager_compose_files:
            try:
                eager_override = yaml.safe_load(
                    eager_compose_file.read_text(encoding="utf-8", errors="ignore")
                ) or {}
            except Exception:
                continue
            # ``build_file`` is a Dockerfile for non-Compose releases. YAML can
            # legally parse some Dockerfiles as a scalar string, so parsing
            # success alone does not mean this is a Compose document.
            eager_services = _compose_service_mapping(eager_override)
            for eager_name, eager_service in eager_services.items():
                if not isinstance(eager_service, dict) or not isinstance(eager_service.get("build"), dict):
                    continue
                eager_build = eager_service["build"]
                eager_context = str(eager_build.get("context") or "")
                eager_dockerfile = str(eager_build.get("dockerfile") or "")
                eager_image = str(eager_service.get("image") or "")
                eager_dockerfile_path = Path(work) / eager_context.removeprefix("./") / eager_dockerfile
                eager_dockerfile_text = (
                    eager_dockerfile_path.read_text(encoding="utf-8", errors="ignore")
                    if eager_dockerfile_path.is_file() else ""
                )
                eager_hint = " ".join((
                    str(eager_name).lower(),
                    str(eager_build.get("target") or "").lower(),
                ))
                eager_role = (
                    "web" if any(token in eager_hint for token in ("web", "ui", "front", "nginx"))
                    else "api" if any(token in eager_hint for token in ("api", "back", "server", "java"))
                    else "web" if re.search(r"(?im)^\s*FROM\s+nginx\b", eager_dockerfile_text)
                    else "api" if re.search(r"(?im)^\s*FROM\s+.*(?:temurin|openjdk|corretto|java)", eager_dockerfile_text)
                    else ""
                )
                if eager_image and eager_dockerfile and eager_role:
                    eager_package_specs[str(eager_name)] = {
                        "context": eager_context,
                        "dockerfile": eager_dockerfile,
                        "image": eager_image,
                        "role": eager_role,
                    }
        if eager_package_specs:
            log(
                deployment.id,
                "[即时封装计划] "
                + "、".join(
                    f"{name}={spec['role']}" for name, spec in eager_package_specs.items()
                )
                + "；各服务产物完成后立即封装，不等待其他服务。\n",
            )
        elif node_manifests or reactor_poms:
            log(
                deployment.id,
                "[即时封装计划] 未发现可安全独立封装的运行镜像，保留统一封装流程。\n",
            )

        def eager_package_ready_service(role: str, ready_root: Path | None = None) -> None:
            candidates = [
                (name, spec) for name, spec in eager_package_specs.items()
                if spec.get("role") == role
            ]
            # The authoritative runtime Compose overlay is deliberately
            # generated after compilation, so a first-time project has no
            # service specs to discover here yet.  The release image names,
            # however, are already final.  Derive a minimal per-service spec
            # from those names and the artifact root; this lets the completed
            # side start packaging without waiting for its peer or for the
            # late Compose normalization pass.
            if not candidates and ready_root is not None:
                role_tokens = (
                    ("api", "backend", "server", "app")
                    if role == "api" else
                    ("web", "frontend", "ui")
                )
                image_prefix = f"yunzhou/{project.slug}-"
                for release_image in images:
                    image_repository = str(release_image).split(":", 1)[0]
                    if not image_repository.startswith(image_prefix):
                        continue
                    derived_name = image_repository[len(image_prefix):]
                    lowered_name = derived_name.lower()
                    if not any(token in lowered_name for token in role_tokens):
                        continue
                    try:
                        derived_context = ready_root.resolve().relative_to(Path(work).resolve()).as_posix()
                    except ValueError:
                        continue
                    derived_spec = {
                        "context": derived_context or ".",
                        "dockerfile": f".yunzhou.{derived_name}.bootstrap.Dockerfile",
                        "image": str(release_image),
                        "role": role,
                    }
                    eager_package_specs[derived_name] = derived_spec
                    candidates.append((derived_name, derived_spec))
                if candidates:
                    log(
                        deployment.id,
                        "[即时封装计划] 已根据实际构建产物补全运行镜像："
                        + "、".join(name for name, _ in candidates)
                        + "。\n",
                    )
            for service_name, spec in candidates:
                context_path = (Path(work) / spec["context"].removeprefix("./")).resolve()
                if ready_root is not None:
                    resolved_ready = ready_root.resolve()
                    if context_path != resolved_ready and context_path not in resolved_ready.parents and resolved_ready not in context_path.parents:
                        continue
                with eager_package_guard:
                    if service_name in eager_packaged_services:
                        continue
                # Runtime-only Dockerfiles may normally be produced by a
                # later normalization pass. Materialize the small packaging
                # file here from the artifact that just completed, so a fast
                # backend can be packaged while a slower frontend is still
                # compiling (and vice versa).
                dockerfile_candidate = context_path / spec["dockerfile"]
                if not spec["dockerfile"].lower().endswith(".runtime.dockerfile"):
                    original_text = (
                        dockerfile_candidate.read_text(encoding="utf-8", errors="ignore")
                        if dockerfile_candidate.is_file() else ""
                    )
                    safe_service = re.sub(r"[^a-z0-9_.-]+", "-", service_name.lower()).strip("-.") or role
                    runtime_name = f".yunzhou.{safe_service}.runtime.Dockerfile"
                    runtime_path = context_path / runtime_name
                    runtime_text = ""
                    if role == "api" and ready_root is not None:
                        jars = sorted(
                            path for path in ready_root.rglob("*.jar")
                            if path.is_file() and not path.name.startswith(("original-", "sources-", "javadoc-"))
                        )
                        jars = [path for path in jars if path == ready_root or ready_root in path.parents]
                        jars = [path for path in jars if context_path == path.parent or context_path in path.parents]
                        if jars:
                            jar = _select_runnable_jar(jars)
                            if jar is None or not _executable_jar_score(jar)[0]:
                                continue
                            java_images = re.findall(
                                r"(?im)^\s*FROM\s+(?:--platform=\S+\s+)?([^\s]*(?:temurin|openjdk|corretto|java)[^\s]*)",
                                original_text,
                            )
                            java_image = java_images[-1] if java_images else "eclipse-temurin:8-jre"
                            relative_jar = jar.relative_to(context_path).as_posix()
                            runtime_text = (
                                f"FROM {java_image}\nWORKDIR /app\n"
                                f"COPY {relative_jar} /app/app.jar\n"
                                "EXPOSE 8080\n"
                                'ENTRYPOINT ["java", "-jar", "/app/app.jar"]\n'
                            )
                    elif role == "web" and ready_root is not None:
                        static_dirs = []
                        for directory_name in ("dist", "build", "out"):
                            static_dirs.extend(
                                path for path in ready_root.rglob(directory_name)
                                if path.is_dir() and (path / "index.html").is_file()
                                and (context_path == path.parent or context_path in path.parents)
                            )
                        if static_dirs:
                            static_dir = min(static_dirs, key=lambda path: len(path.parts))
                            nginx_images = re.findall(
                                r"(?im)^\s*FROM\s+(?:--platform=\S+\s+)?(nginx:[^\s]+)",
                                original_text,
                            )
                            runtime_text = platform_spa_runtime_dockerfile(
                                nginx_images[-1] if nginx_images else PLATFORM_NGINX_IMAGE,
                                static_dir.relative_to(context_path).as_posix(),
                                detect_frontend_public_base(str(context_path)).get("primary_path") or "/",
                            )
                    if runtime_text:
                        runtime_path.write_text(
                            enforce_nginx_pid_compatibility(runtime_text), encoding="utf-8"
                        )
                        ensure_generated_copy_inputs(context_path, runtime_path)
                        spec["dockerfile"] = runtime_name
                    else:
                        # No verified artifact means this service is not safe
                        # to package early; leave it to the normal build path.
                        continue
                # A runtime Dockerfile can already exist before compilation.
                # At that earlier point its dist/build input does not exist,
                # so ignore-rule restoration correctly has no evidence to
                # act on. Re-evaluate the final packaging file now that the
                # compiler has produced and verified the artifact.
                final_dockerfile = context_path / spec["dockerfile"]
                restored_artifacts = ensure_generated_copy_inputs(context_path, final_dockerfile)
                if restored_artifacts:
                    log(
                        deployment.id,
                        "[构建上下文] 已按最终运行镜像恢复真实构建产物："
                        + "、".join(restored_artifacts) + "。\n",
                    )
                relative_context = spec["context"].removeprefix("./")
                dockerfile_path = f"{relative_context}/{spec['dockerfile']}"
                package_command = (
                    f"cd {shlex.quote(builder_dir)} && "
                    f"DOCKER_BUILDKIT=0 DOCKER_DEFAULT_PLATFORM={shlex.quote(platform)} "
                    f"docker build {proxy_build_args} -f {shlex.quote(dockerfile_path)} "
                    f"-t {shlex.quote(spec['image'])} {shlex.quote(relative_context)}"
                )
                log(
                    deployment.id,
                    f"[即时封装] {service_name} 构建产物已就绪，不等待其他服务，立即生成运行镜像。\n",
                )
                locked_command = (
                    # The node has one shared classic-Docker/containerd image
                    # store. Different image names can still race while layers
                    # are committed, so use the same node-wide commit lock.
                    "flock -w 1200 /tmp/yunzhou-image-commit.lock sh -lc "
                    + shlex.quote(package_command)
                )
                with SSHNode(builder) as package_ssh:
                    code, output = tracked_run(
                        package_ssh, deployment.id, locked_command, stream=stream, timeout=1500,
                        pid_prefix=f"yunzhou-eager-package-{role}",
                        stream_channel="package", stream_label="镜像封装",
                    )
                    eager_storage_error = any(marker in output.lower() for marker in (
                        "lease does not exist", "failed to prepare snapshot", "failed to commit",
                        "failed to export layer", "content/ingest", "snapshotter",
                        "does not exist: not found",
                    ))
                    if code and eager_storage_error:
                        log(deployment.id, f"[平台自愈] {service_name} 即时封装遇到 Docker 存储抖动，保持写入锁自动重试。\n")
                        code, output = tracked_run(
                            package_ssh, deployment.id, locked_command, stream=stream, timeout=1500,
                            pid_prefix=f"yunzhou-eager-package-{role}-retry",
                            stream_channel="package", stream_label="镜像封装重试",
                        )
                if code:
                    raise RuntimeError(f"{service_name} 即时镜像封装失败：" + output[-2000:])
                with eager_package_guard:
                    eager_packaged_services.add(service_name)
                log(deployment.id, f"[即时封装] {service_name} 运行镜像已完成。\n")

        def build_maven_reactors() -> set[str]:
            completed: set[str] = set()
            if not has_generated_multistage:
                return completed
            with SSHNode(builder) as maven_ssh:
                for pom_index, pom in enumerate(reactor_poms, start=1):
                    relative = pom.relative_to(source_root).as_posix()
                    maven_image = "maven:3.9-eclipse-temurin-17"
                    ranked_dockerfiles = sorted(
                        generated_dockerfiles,
                        key=lambda candidate: (
                            0 if candidate.parent == pom.parent else 1,
                            len(candidate.relative_to(source_root).parts),
                        ),
                    )
                    module_match = None
                    for candidate in ranked_dockerfiles:
                        candidate_text = candidate.read_text(encoding="utf-8", errors="ignore")
                        image_match = re.search(
                            r"(?im)^\s*FROM\s+(?:--platform=\S+\s+)?(maven:[^\s]+)",
                            candidate_text,
                        )
                        if image_match:
                            maven_image = image_match.group(1)
                        module_match = re.search(
                            r"(?im)^\s*RUN\s+[^\n]*?\bmvn\b[^\n]*?\s-f\s+([\"']?)([^\s\"'\\]+pom[^\s\"'\\]*\.xml)\1",
                            candidate_text,
                        )
                        if module_match:
                            break
                    module_pom = module_match.group(2) if module_match else ""
                    if module_pom and not (pom.parent / module_pom).is_file():
                        real_pom = Path(module_pom).parent / "pom.xml"
                        module_pom = real_pom.as_posix() if (pom.parent / real_pom).is_file() else ""
                    module_arg = f"-f {shlex.quote(module_pom)} " if module_pom else ""
                    command = (
                        f"docker run --rm {proxy_run_args} --label yunzhou.deployment={shlex.quote(deployment.id)} "
                        f"-v {shlex.quote(str(pom.parent))}:/workspace "
                        f"-v {shlex.quote(cache_root + '/maven' + ':' + maven_cache_dir)} "
                        f"{maven_cache_env}"
                        f"-w /workspace {shlex.quote(maven_image)} sh -lc "
                        + shlex.quote(f"mvn -B {module_arg}-DskipTests package")
                    )
                    build_scope = module_pom or relative
                    log(deployment.id, f"[平台构建] {maven_image}：{build_scope}，与前端并发构建并写入 {cache_root}/maven。\n")
                    maven_code, maven_output = tracked_run(
                        maven_ssh, deployment.id, command, stream=stream, timeout=1800,
                        pid_prefix=f"yunzhou-maven-build-{pom_index}",
                        stream_channel="api", stream_label="后端 API",
                    )
                    if maven_code:
                        log(deployment.id, f"[平台构建] Maven 外置编译未完成，保留原始方案继续诊断：{maven_output[-800:]}\n")
                    else:
                        artifact_root = (pom.parent / Path(module_pom).parent) if module_pom else pom.parent
                        built_jars = [
                            path for path in artifact_root.rglob("target/*.jar")
                            if path.is_file() and not path.name.startswith(("original-", "sources-", "javadoc-"))
                        ]
                        boot_version = detect_spring_boot_version(str(pom.parent))
                        if (
                            built_jars
                            and not any(_executable_jar_score(path)[0] for path in built_jars)
                            and boot_version
                            and module_pom
                        ):
                            # Some integrated Maven/SPA repositories copy a
                            # sibling frontend's dist directory during the
                            # backend resources phase.  The two toolchains are
                            # compiled concurrently, so wait briefly for that
                            # already-running frontend build before the final
                            # package+repackage lifecycle.  This is not a
                            # second frontend build.
                            sibling_frontends = [
                                package.parent for package in node_manifests
                                if package.parent != artifact_root
                                and package.parent.parent in {pom.parent, artifact_root.parent}
                            ]
                            for frontend_root in sibling_frontends:
                                for _ in range(240):
                                    if any((frontend_root / name).is_dir() for name in ("dist", "build", "out")):
                                        break
                                    time.sleep(0.25)
                            repackage = (
                                f"mvn -B -f {shlex.quote(module_pom)} "
                                "-DskipTests package "
                                f"org.springframework.boot:spring-boot-maven-plugin:{shlex.quote(boot_version)}:repackage "
                            )
                            repackage_command = (
                                f"docker run --rm {proxy_run_args} --label yunzhou.deployment={shlex.quote(deployment.id)} "
                                f"-v {shlex.quote(str(pom.parent))}:/workspace "
                                f"-v {shlex.quote(cache_root + '/maven' + ':' + maven_cache_dir)} "
                                f"{maven_cache_env}"
                                f"-w /workspace {shlex.quote(maven_image)} sh -lc {shlex.quote(repackage)}"
                            )
                            log(deployment.id, f"[平台构建] 普通 JAR 按 Spring Boot {boot_version} 自动重打包并校验。\n")
                            repack_code, repack_output = tracked_run(
                                maven_ssh, deployment.id, repackage_command, stream=stream, timeout=900,
                                pid_prefix=f"yunzhou-maven-repackage-{pom_index}",
                                stream_channel="api", stream_label="后端 API",
                            )
                            if repack_code:
                                log(deployment.id, f"[平台构建] Spring Boot 重打包失败，保留原始方案继续诊断：{repack_output[-800:]}\n")
                        completed.add(str(pom.parent.resolve()))
                        log(deployment.id, f"[平台构建] Maven 已使用公共缓存 {maven_cache_dir} 生成 JAR：{relative}。\n")
                        eager_package_ready_service("api", artifact_root)
            return completed

        maven_executor = None
        maven_future = None
        if reactor_poms and has_generated_multistage:
            log(deployment.id, "[并发构建] 前端 Web 与后端 API 已同时开始。\n")
            maven_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="yunzhou-maven")
            maven_future = maven_executor.submit(build_maven_reactors)
        for package_file in node_manifests:
            package_dir = package_file.parent
            ensure_context_ignore(package_dir)
            # Old CNPM/Taobao lockfiles pin complete tarball URLs, so changing
            # the package-manager registry alone does not take effect. Repair
            # only the disposable release checkout and record the correction.
            # The user's Git repository and immutable source cache stay intact.
            repaired_lockfiles = []
            legacy_registries = {
                "https://r2.cnpmjs.org/": "https://registry.npmmirror.com/",
                "http://r2.cnpmjs.org/": "https://registry.npmmirror.com/",
                "https://registry.npm.taobao.org/": "https://registry.npmmirror.com/",
                "http://registry.npm.taobao.org/": "https://registry.npmmirror.com/",
                "https://npm.taobao.org/": "https://registry.npmmirror.com/",
                "http://npm.taobao.org/": "https://registry.npmmirror.com/",
            }
            for lock_name in ("yarn.lock", "package-lock.json", "npm-shrinkwrap.json"):
                lock_path = package_dir / lock_name
                if not lock_path.is_file():
                    continue
                original_lock = lock_path.read_text(encoding="utf-8", errors="replace")
                repaired_lock = original_lock
                for old_registry, current_registry in legacy_registries.items():
                    repaired_lock = repaired_lock.replace(old_registry, current_registry)
                if repaired_lock != original_lock:
                    lock_path.write_text(repaired_lock, encoding="utf-8")
                    repaired_lockfiles.append(lock_name)
            if repaired_lockfiles:
                relative_lock_dir = package_dir.relative_to(source_root).as_posix() or "."
                log(
                    deployment.id,
                    "[自动修正] 已在发布副本中更新过期的 npm/yarn 镜像地址："
                    + relative_lock_dir + "/" + "、".join(repaired_lockfiles) + "；源码仓库未改动。\n",
                )
            try:
                package_meta = json.loads(package_file.read_text(encoding="utf-8", errors="replace"))
            except Exception:
                package_meta = {}
            manager_hint = str(package_meta.get("packageManager") or "").lower() if isinstance(package_meta, dict) else ""
            scripts = package_meta.get("scripts") if isinstance(package_meta, dict) else {}
            build_script = isinstance(scripts, dict) and bool(scripts.get("build"))
            # Runtime-only Node services install once in their final Docker
            # build. Do not run a separate dependency warm-up first.
            if not build_script:
                continue
            if (package_dir / "pnpm-lock.yaml").is_file() or manager_hint.startswith("pnpm"):
                manager = "pnpm"
                install = (
                    "corepack enable; corepack prepare pnpm@8.15.9 --activate; "
                    f"pnpm install --store-dir {shlex.quote(pnpm_cache_dir)} --frozen-lockfile" + ("; pnpm run build" if build_script else " --ignore-scripts")
                )
            elif (package_dir / "yarn.lock").is_file() or manager_hint.startswith("yarn"):
                manager = "yarn"
                install = f"yarn install --cache-folder {shlex.quote(yarn_cache_dir)} --frozen-lockfile --prefer-offline --network-timeout 600000" + ("; yarn build" if build_script else " --ignore-scripts")
            else:
                manager = "npm"
                # Keep the checkout's node_modules between releases. npm's
                # tarball cache avoids downloads, but unpacking 2,000+ legacy
                # dependencies still took six minutes on real projects. A
                # lock-aware incremental install reuses the already unpacked
                # tree while the Docker context continues to exclude it.
                install = "npm install --prefer-offline --no-audit --no-fund"
                install += "; npm run build" if build_script else " --ignore-scripts"
            package_text = json.dumps(package_meta, ensure_ascii=False)
            legacy_webpack = bool(
                re.search(r'"(?:webpack|@vue/cli-service)"\s*:\s*"?[~^]?(?:[0-4])(?:\.|"|$)', package_text)
            )
            node_image = "node:16.20.2" if legacy_webpack else "node:20-alpine"
            if not legacy_webpack:
                # Keep the external, cache-warming build on the exact Node
                # major already selected by source analysis for the generated
                # Dockerfile.  Using a fixed Node 20 helper made modern pnpm
                # itself fail on ``node:sqlite`` before the real image build,
                # so the expensive compile then had to run while holding the
                # shared Docker image-store lock.
                selected_node_image = None
                for candidate in generated_dockerfiles:
                    dockerfile_text = candidate.read_text(encoding="utf-8", errors="ignore")
                    image_match = re.search(r"(?im)^\s*FROM\s+(node:[^\s]+)", dockerfile_text)
                    if image_match:
                        selected_node_image = image_match.group(1)
                        break
                if selected_node_image:
                    node_image = selected_node_image
                else:
                    engine_hint = str((package_meta.get("engines") or {}).get("node") or "")
                    package_manager_match = re.search(r"\bpnpm@(\d+)", manager_hint)
                    if re.search(r"(?:>=|\^|~)?\s*2[4-9](?:\D|$)", engine_hint):
                        node_image = "node:24-alpine"
                    elif re.search(r"(?:>=|\^|~)?\s*22(?:\D|$)", engine_hint) or (
                        package_manager_match and int(package_manager_match.group(1)) >= 11
                    ):
                        node_image = "node:22-alpine"
            relative = package_dir.relative_to(source_root).as_posix() or "."
            node_modules_mount = ""
            if manager in {"npm", "yarn", "pnpm"}:
                # Release checkouts under runs/ are disposable. Keep the
                # unpacked dependency tree in the project's stable workspace
                # and mount it at npm's normal /workspace/node_modules path.
                # A symlink in source-cache makes the retained tree visible to
                # operators without putting it in Git or Docker contexts.
                persistent_modules = persistent_dependency_root / relative / "node_modules"
                persistent_modules.mkdir(parents=True, exist_ok=True)
                visible_modules = Path(builder_root) / "projects" / project.slug / "source-cache" / relative / "node_modules"
                if visible_modules.parent.is_dir() and not visible_modules.exists():
                    try:
                        visible_modules.symlink_to(persistent_modules, target_is_directory=True)
                    except OSError:
                        pass
                node_modules_mount = f"-v {shlex.quote(str(persistent_modules) + ':/workspace/node_modules')} "
            command = (
                f"docker run --rm {proxy_run_args} --label yunzhou.deployment={shlex.quote(deployment.id)} "
                f"-v {shlex.quote(str(package_dir))}:/workspace "
                f"-v {shlex.quote(cache_root + '/pnpm' + ':' + pnpm_cache_dir)} "
                f"-v {shlex.quote(cache_root + '/npm' + ':' + npm_cache_dir)} "
                f"-v {shlex.quote(cache_root + '/yarn' + ':' + yarn_cache_dir)} "
                f"{node_cache_env}"
                f"{node_modules_mount}"
                f"-w /workspace {node_image} sh -lc "
                + shlex.quote("set -e; trap 'rm -rf .pnpm-store' EXIT; " + install)
            )
            log(deployment.id, f"[平台构建] {node_image}/{manager}：{relative}，正式构建同时写入公共缓存。\n")
            warm_code, warm_output = tracked_run(
                build_ssh, deployment.id, command, stream=stream, timeout=1200,
                pid_prefix="yunzhou-node-cache", stream_channel="web", stream_label="前端 Web",
            )
            if warm_code:
                log(deployment.id, f"[平台构建] {relative} 本次未生成产物，交由项目方案诊断：{warm_output[-500:]}\n")
            else:
                node_built_contexts.add(str(package_dir.resolve()))
                log(deployment.id, f"[平台构建] Node 已使用默认公共缓存生成运行产物：{relative}。\n")
                eager_package_ready_service("web", package_dir)
            shutil.rmtree(package_dir / ".pnpm-store", ignore_errors=True)
        if maven_future is not None:
            try:
                maven_built_contexts.update(maven_future.result())
            finally:
                maven_executor.shutdown(wait=True)
            log(deployment.id, "[并发构建] 前端 Web 与后端 API 已全部完成，继续处理尚未封装的服务。\n")

        gradle_roots = sorted({
            path.parent
            for name in ("settings.gradle", "settings.gradle.kts", "build.gradle", "build.gradle.kts")
            for path in source_manifests(source_root, name, ignored_parts)
        })
        gradle_roots = [root_path for root_path in gradle_roots if not any(parent in gradle_roots for parent in root_path.parents)]
        for gradle_root in gradle_roots:
            relative = gradle_root.relative_to(source_root).as_posix() or "."
            gradle_entry = "./gradlew" if (gradle_root / "gradlew").is_file() else "gradle"
            gradle_descriptor_text = "\n".join(
                item.read_text(encoding="utf-8", errors="ignore")
                for item in (gradle_root / "build.gradle", gradle_root / "build.gradle.kts")
                if item.is_file()
            )
            generated_gradle_files = [
                item for item in gradle_root.glob(".yunzhou*.Dockerfile")
                if item.is_file() and "gradlew" in item.read_text(encoding="utf-8", errors="ignore")
            ]
            direct_boot_jar = bool(
                generated_gradle_files
                and re.search(r"spring[-.]boot|bootJar", gradle_descriptor_text, re.I)
            )
            # Use the toolchain already selected by source analysis instead of
            # a fixed JDK.  A Java 26 project cannot be safely prewarmed in a
            # JDK 17 helper even though both use Gradle.  Prefer the generated
            # build stage; fall back to the Gradle image only when no evidence
            # exists.
            gradle_image = "gradle:8-jdk17"
            for candidate in list(source_root.rglob(".yunzhou*.Dockerfile")) + list(source_root.rglob("Dockerfile*")):
                if not candidate.is_file():
                    continue
                candidate_text = candidate.read_text(encoding="utf-8", errors="ignore")
                if "gradlew" not in candidate_text and not re.search(r"\bgradle\b", candidate_text, re.I):
                    continue
                image_match = re.search(r"(?im)^FROM\s+(?:--platform=\S+\s+)?([^\s]+)(?:\s+AS\s+\S+)?", candidate_text)
                if image_match:
                    gradle_image = image_match.group(1)
                    break
            if direct_boot_jar:
                log(deployment.id, "[平台构建] Spring Boot/Gradle 仅执行一次 bootJar，构建过程同时填充公共缓存。\n")

            # Spring/Gradle projects must not download the wrapper again from
            # inside a classic Docker build: that build cannot bind-mount the
            # public host cache and would both waste time and hold the global
            # image commit lock.  Compile the boot jar in a disposable helper
            # with the shared GRADLE_USER_HOME, then make the generated
            # Dockerfile package only that artifact.  Repository Dockerfiles
            # remain untouched; only platform-generated .yunzhou files are
            # rewritten in the isolated release copy.
            gradle_descriptors = [gradle_root / "build.gradle", gradle_root / "build.gradle.kts"]
            descriptor_text = gradle_descriptor_text
            if generated_gradle_files and re.search(r"spring[-.]boot|bootJar", descriptor_text, re.I):
                compile_script = (
                    "set -e; "
                    "sed -i 's/\\r$//' ./gradlew; chmod +x ./gradlew; "
                    "./gradlew bootJar -x test --no-daemon"
                )
                # Use a complete build-tool image for the external compile.
                # Minimal JRE images can miss xargs and previously caused an
                # invisible, unbounded yum install before Gradle even started.
                requested_jdks: list[int] = []
                for pattern in (
                    r"JavaLanguageVersion\.of\(\s*(\d+)\s*\)",
                    r"jvmToolchain\(\s*(\d+)\s*\)",
                    r"JavaVersion\.VERSION_(\d+)",
                    r"(?:sourceCompatibility|targetCompatibility)\s*=\s*[\"']?(\d+)",
                ):
                    requested_jdks.extend(int(value) for value in re.findall(pattern, descriptor_text))
                requested_jdk = max(requested_jdks, default=21)
                # The wrapper determines the Gradle version; the helper image
                # only supplies the source-declared JDK and common CLI tools.
                # Never silently downgrade a project toolchain.
                gradle_helper_image = f"gradle:jdk{requested_jdk}"
                compile_command = (
                    f"docker run --rm {proxy_run_args} --label yunzhou.deployment={shlex.quote(deployment.id)} "
                    f"-v {shlex.quote(str(gradle_root))}:/workspace "
                    # Official Gradle images run as the `gradle` user. Mount
                    # the persistent cache at that image's real default home;
                    # /root/.gradle is otherwise ignored and every release
                    # downloads the wrapper and dependencies again.
                    f"-v {shlex.quote(cache_root + '/gradle' + ':' + gradle_cache_dir)} "
                    f"{gradle_cache_env}"
                    f"-w /workspace {shlex.quote(gradle_helper_image)} sh -lc "
                    + shlex.quote(compile_script)
                )
                log(deployment.id, f"[平台构建] Gradle 使用 {gradle_helper_image} 与公共缓存外置编译，镜像阶段仅打包 bootJar。\n")
                compile_code, compile_output = tracked_run(
                    build_ssh, deployment.id, compile_command, stream=stream, timeout=1800,
                    pid_prefix="yunzhou-gradle-build", stream_channel="api", stream_label="后端 API",
                )
                if compile_code:
                    raise RuntimeError("Gradle 公共缓存编译失败：" + compile_output[-2000:])
                jars = sorted(
                    item for item in (gradle_root / "build" / "libs").glob("*.jar")
                    if "-plain" not in item.name
                )
                if not jars:
                    raise RuntimeError("Gradle 构建成功但未找到 bootJar 产物")
                jar = jars[-1]
                for dockerfile in generated_gradle_files:
                    original = dockerfile.read_text(encoding="utf-8", errors="ignore")
                    stages = re.split(r"(?im)(?=^\s*FROM\s+)", original)
                    final_stage = stages[-1] if stages else original
                    final_image_match = re.search(r"(?im)^\s*FROM\s+([^\s]+)", final_stage)
                    final_image = final_image_match.group(1) if final_image_match else gradle_image
                    expose_match = re.search(r"(?im)^\s*EXPOSE\s+(\d+)", final_stage)
                    expose = expose_match.group(1) if expose_match else "8080"
                    relative_jar = jar.relative_to(gradle_root).as_posix()
                    gradle_log_dirs = detect_java_log_directories(gradle_root)
                    gradle_log_setup = ""
                    if gradle_log_dirs:
                        quoted_dirs = " ".join(shlex.quote(value) for value in gradle_log_dirs)
                        gradle_log_setup = f"RUN mkdir -p {quoted_dirs} && chmod 0777 {quoted_dirs}\n"
                    dockerfile.write_text(
                        f"FROM {final_image}\n{gradle_log_setup}WORKDIR /app\n"
                        f"COPY {relative_jar} /app/app.jar\n"
                        f"EXPOSE {expose}\n"
                        'ENTRYPOINT ["java", "-jar", "/app/app.jar"]\n',
                        encoding="utf-8",
                    )
                log(deployment.id, f"[缓存命中] Gradle bootJar 已生成：{jar.name}；Docker 不再重复下载依赖。\n")

        # A generated full-stack Dockerfile may place frontend-build before
        # api-runtime (or vice versa). The classic builder executes preceding
        # stages even when a later target does not depend on them. After the
        # ordered external frontend/backend builds above, split every service
        # target into its own runtime-only Dockerfile so API packaging never
        # runs pnpm and frontend packaging never runs Maven/Gradle.
        if build_type == "compose":
            compose_path = Path(work) / build_file
            try:
                split_compose = yaml.safe_load(compose_path.read_text(encoding="utf-8", errors="ignore")) or {}
            except Exception:
                split_compose = {}
            split_override = {}
            if compose_override:
                try:
                    split_override = yaml.safe_load((Path(work) / compose_override).read_text(encoding="utf-8", errors="ignore")) or {}
                except Exception:
                    split_override = {}
            artifacts = sorted({
                path.relative_to(source_root).as_posix()
                for path in source_root.rglob("*")
                if (
                    (path.is_dir() and path.name in {"dist", "build"})
                    or (path.is_file() and path.suffix == ".jar" and "target" in path.parts)
                )
                and not any(part in {"node_modules", ".git", ".pnpm-store"} for part in path.parts)
            })
            split_count = 0
            for service_name, service in (split_compose.get("services") or {}).items():
                build = service.get("build") if isinstance(service, dict) else None
                if not isinstance(build, dict) or not build.get("target"):
                    continue
                context_rel = str(build.get("context") or ".")
                context = (Path(work) / context_rel).resolve()
                dockerfile = context / str(build.get("dockerfile") or "Dockerfile")
                if not dockerfile.is_file():
                    continue
                docker_text = dockerfile.read_text(encoding="utf-8", errors="ignore")
                build_target = str(build.get("target") or "")
                relative_artifacts = []
                for artifact in artifacts:
                    absolute = source_root / artifact
                    try:
                        relative_artifacts.append(absolute.relative_to(context).as_posix())
                    except ValueError:
                        continue
                result = runtime_stage_from_prebuilt_artifact(
                    docker_text, context, relative_artifacts, str(service_name), target=build_target,
                )
                if not result:
                    continue
                runtime_text, copied = result
                nginx_images = re.findall(
                    r"(?im)^\s*FROM\s+(?:--platform=\S+\s+)?(nginx:[^\s]+)",
                    runtime_text,
                )
                static_artifact = next(
                    (
                        value for value in copied
                        if (context / value).is_dir()
                        and (context / value / "index.html").is_file()
                    ),
                    None,
                )
                if nginx_images and static_artifact:
                    runtime_text = platform_spa_runtime_dockerfile(
                        nginx_images[-1], static_artifact,
                        detect_frontend_public_base(str(context)).get("primary_path") or "/",
                    )
                    copied = [static_artifact]
                safe_service = re.sub(r"[^a-z0-9_.-]+", "-", str(service_name).lower()).strip("-.") or "app"
                runtime_name = f".yunzhou.{safe_service}.runtime.Dockerfile"
                runtime_text = enforce_nginx_pid_compatibility(runtime_text)
                (context / runtime_name).write_text(runtime_text, encoding="utf-8")
                build["dockerfile"] = runtime_name
                build.pop("target", None)
                override_service = (split_override.get("services") or {}).get(service_name)
                if isinstance(override_service, dict) and isinstance(override_service.get("build"), dict):
                    override_service["build"]["dockerfile"] = runtime_name
                    override_service["build"].pop("target", None)
                split_count += 1
                log(deployment.id, f"[平台构建] {service_name} 已拆分为纯运行镜像，仅复制：{', '.join(copied)}。\n")
            if split_count:
                compose_path.write_text(yaml.safe_dump(split_compose, allow_unicode=True, sort_keys=False), encoding="utf-8")
                if compose_override:
                    (Path(work) / compose_override).write_text(
                        yaml.safe_dump(split_override, allow_unicode=True, sort_keys=False), encoding="utf-8"
                    )

        # Python projects often use ``pip --no-cache-dir`` inside Dockerfiles,
        # which makes the visible shared pip directory stay empty. Build a
        # requirements-keyed wheelhouse with a short-lived Python container,
        # then let the classic Docker build install only from those wheels.
        # This keeps Buildx disabled while making pip downloads reusable and
        # inspectable under /data/yunzhou/builder/cache/pip.
        if build_type == "compose":
            try:
                compose_doc = yaml.safe_load((Path(work) / build_file).read_text(encoding="utf-8", errors="ignore")) or {}
            except Exception:
                compose_doc = {}
            warmed_contexts: set[str] = set()
            for service in (compose_doc.get("services") or {}).values():
                if not isinstance(service, dict) or not service.get("build"):
                    continue
                build = service["build"]
                context_rel = str(build.get("context") or ".") if isinstance(build, dict) else str(build)
                dockerfile_rel = str(build.get("dockerfile") or "Dockerfile") if isinstance(build, dict) else "Dockerfile"
                context = (Path(work) / context_rel).resolve()
                dockerfile = context / dockerfile_rel
                context_key = str(context)
                if context_key in warmed_contexts or not dockerfile.is_file():
                    continue
                docker_text = dockerfile.read_text(encoding="utf-8", errors="ignore")
                base_match = re.search(r"(?im)^FROM\s+(python:[^\s]+)", docker_text)
                # Locate the complete Dockerfile RUN instruction, including
                # backslash-continued lines. Replacing only its first physical
                # line can leave a following ``&&`` as a top-level Dockerfile
                # instruction ("unknown instruction: &&").
                pip_block: tuple[int, int, str, str] | None = None
                wheel_block: tuple[int, int, str] | None = None
                docker_lines = docker_text.splitlines(keepends=True)
                offset = 0
                line_index = 0
                while line_index < len(docker_lines):
                    line = docker_lines[line_index]
                    block_start = offset
                    block_lines = [line]
                    offset += len(line)
                    if re.match(r"(?i)^\s*RUN\s+", line):
                        while block_lines[-1].rstrip("\r\n").rstrip().endswith("\\") and line_index + 1 < len(docker_lines):
                            line_index += 1
                            next_line = docker_lines[line_index]
                            block_lines.append(next_line)
                            offset += len(next_line)
                        block_text = "".join(block_lines)
                        collapsed = re.sub(r"\\\s*\r?\n\s*", " ", block_text)
                        wheel_match = re.search(
                            r"(?i)\bpip\s+wheel\b.*?--wheel-dir(?:=|\s+)([^\s;&]+).*?\s-r\s+([^\s;&]+\.txt)\b",
                            collapsed,
                        )
                        if wheel_match:
                            wheel_block = (block_start, offset, wheel_match.group(1))
                        requirement_match = re.search(
                            r"(?i)\bpip\s+install\b.*?\s-r\s+([^\s;&]+\.txt)\b",
                            collapsed,
                        )
                        if requirement_match:
                            pip_block = (block_start, offset, block_text, requirement_match.group(1))
                            break
                    line_index += 1
                if not base_match or not pip_block:
                    continue
                requirement_path = pip_block[3].strip("'\"")
                requirement_relative = requirement_path.lstrip("/")
                requirements = context / requirement_relative
                if not requirements.is_file() and "/requirements/" in ("/" + requirement_relative):
                    requirement_relative = "requirements/" + requirement_relative.split("/requirements/", 1)[-1]
                    requirements = context / requirement_relative
                if not requirements.is_file():
                    # The path passed to pip is resolved inside the image, not
                    # necessarily from the Docker build-context root. A common
                    # layout is ``COPY backend/requirements.txt ./`` followed
                    # by ``pip install -r requirements.txt``. Trace COPY/ADD
                    # instructions before the install block back to their
                    # context source so these projects also use the shared
                    # wheel cache.
                    requested_name = Path(requirement_relative).name
                    copy_candidates: list[str] = []
                    for copy_match in re.finditer(
                        r"(?im)^\s*(?:COPY|ADD)\s+(?:--\S+\s+)*([^\s]+)\s+([^\s]+)\s*$",
                        docker_text[:pip_block[0]],
                    ):
                        source_value = copy_match.group(1).strip("'\"")
                        target_value = copy_match.group(2).strip("'\"")
                        if source_value.startswith(("http://", "https://")):
                            continue
                        target_name = Path(target_value.rstrip("/")).name
                        if (
                            Path(source_value).name == requested_name
                            and (target_value in {".", "./"} or target_name == requested_name)
                        ):
                            copy_candidates.append(source_value.lstrip("/"))
                    for copied_requirement in reversed(copy_candidates):
                        copied_path = (context / copied_requirement).resolve()
                        if copied_path.is_file() and (copied_path == context or context in copied_path.parents):
                            requirement_relative = copied_requirement
                            requirements = copied_path
                            break
                if not requirements.is_file():
                    continue
                warmed_contexts.add(context_key)
                requirement_payload = bytearray(requirements.read_bytes())
                requirement_text = requirements.read_text(encoding="utf-8", errors="ignore")
                for include in re.findall(r"(?im)^\s*(?:-r|--requirement)\s+([^\s#]+)", requirement_text):
                    included = (requirements.parent / include.strip("'\"")).resolve()
                    if included.is_file() and (included == context or context in included.parents):
                        requirement_payload.extend(b"\n--included--\n")
                        requirement_payload.extend(included.read_bytes())
                # Bump the cache contract when the platform-owned wheelhouse
                # contents change. Python sdists may create an isolated build
                # environment even when all application requirements were
                # downloaded, so include the standard PEP 517 bootstrap
                # wheels as well.
                requirement_payload.extend(b"\n--yunzhou-wheelhouse-v3-compiled-sdists--\n")
                req_hash = hashlib.sha256(requirement_payload).hexdigest()[:16]
                wheel_dir = f"{cache_root}/pip/{req_hash}"
                marker = f"{wheel_dir}/.complete"
                code, _ = build_ssh.run(f"test -f {shlex.quote(marker)}")
                if code:
                    build_ssh.run(f"rm -rf {shlex.quote(wheel_dir)} && mkdir -p {shlex.quote(wheel_dir)}")
                    python_image = base_match.group(1)
                    pip_command = (
                        f"docker run --rm {proxy_run_args} --label yunzhou.deployment={shlex.quote(deployment.id)} "
                        f"-v {shlex.quote(context_key)}:/workspace:ro "
                        f"-v {shlex.quote(wheel_dir)}:/wheelhouse "
                        f"{shlex.quote(python_image)} sh -lc "
                        + shlex.quote(
                            "set -e; "
                            "if command -v apt-get >/dev/null 2>&1; then "
                            "apt-get update >/dev/null && "
                            "apt-get install -y --no-install-recommends build-essential >/dev/null; "
                            "elif command -v apk >/dev/null 2>&1; then "
                            "apk add --no-cache build-base linux-headers >/dev/null; "
                            "fi; "
                            "pip wheel setuptools wheel packaging -w /wheelhouse && "
                            f"pip wheel -r /workspace/{requirement_relative} -w /wheelhouse"
                        )
                    )
                    log(deployment.id, f"[平台构建] Python：{python_image}，首次填充公共 pip wheel 缓存。\n")
                    code, output = tracked_run(
                        build_ssh, deployment.id, pip_command, stream=stream,
                        timeout=1200, pid_prefix="yunzhou-pip-cache",
                    )
                    if code:
                        raise RuntimeError("pip 公共缓存填充失败：" + output[-2000:])
                    build_ssh.run(f"touch {shlex.quote(marker)}")
                    cache_state = "首次填充"
                else:
                    cache_state = "完整命中"
                staged_wheels = context / ".yunzhou-pip-wheels"
                shutil.rmtree(staged_wheels, ignore_errors=True)
                shutil.copytree(Path(wheel_dir), staged_wheels, ignore=shutil.ignore_patterns(".complete"))
                block_start, block_end, _, requirement_path = pip_block
                virtual_env_match = re.search(
                    r"(?im)\bVIRTUAL_ENV\s*=\s*([^\s\\]+)",
                    docker_text,
                )
                virtual_env = virtual_env_match.group(1).strip("'\"") if virtual_env_match else ""
                if not virtual_env:
                    copied_virtual_env = re.search(
                        r"(?im)^\s*COPY\s+--from=\S+\s+(/[^\s]+/(?:\.venv|venv))\s+\1\s*$",
                        docker_text,
                    )
                    path_virtual_env = re.search(
                        r"(?im)\bPATH\s*=\s*([^\s\\:]+/(?:\.venv|venv))/bin(?::|$)",
                        docker_text,
                    )
                    if copied_virtual_env:
                        virtual_env = copied_virtual_env.group(1)
                    elif path_virtual_env:
                        virtual_env = path_virtual_env.group(1)
                # Only setup performed *before* the RUN block being replaced
                # survives this rewrite. Counting ``python -m venv`` inside
                # the same pip-install block incorrectly removes the command
                # that creates the environment and leaves ``.../bin/pip``
                # missing during the real Docker build.
                docker_before_install = docker_text[:pip_block[0]]
                virtual_env_ready = bool(
                    virtual_env
                    and (
                        re.search(
                            rf"(?im)\bpython(?:3)?\s+-m\s+venv\s+{re.escape(virtual_env)}(?:\s|$)",
                            docker_before_install,
                        )
                        or re.search(
                            rf"(?im)^\s*COPY\s+--from=\S+\s+{re.escape(virtual_env)}\s+{re.escape(virtual_env)}\s*$",
                            docker_before_install,
                        )
                    )
                )
                if virtual_env.startswith("/"):
                    pip_executable = f"{virtual_env}/bin/pip"
                    venv_setup = "" if virtual_env_ready else f"python -m venv {virtual_env} && "
                else:
                    pip_executable = "pip"
                    venv_setup = ""
                replacement = (
                    "COPY .yunzhou-pip-wheels /opt/yunzhou-pip-wheels\n"
                    f"RUN {venv_setup}{pip_executable} install --no-index --find-links=/opt/yunzhou-pip-wheels "
                    f"-r {requirement_path} \\\n"
                    "    && rm -rf /opt/yunzhou-pip-wheels\n"
                )
                rewritten_docker = docker_text[:block_start] + replacement + docker_text[block_end:]
                # Do not replace an upstream ``pip wheel`` RUN instruction as
                # a whole. Such instructions commonly also create /venv or
                # perform other setup in the same continued shell command.
                # Replacing the complete RUN block made an otherwise valid
                # image build successfully but fail at runtime because
                # /venv/bin/python no longer existed. The final offline install
                # still consumes the platform wheelhouse; preserving this
                # builder step is the safe behaviour for arbitrary projects.
                dockerfile.write_text(rewritten_docker, encoding="utf-8")
                wheel_count = len(list(staged_wheels.glob("*")))
                log(deployment.id, f"[缓存命中] pip {cache_state}：requirements={req_hash}，wheel={wheel_count}。\n")

            # Generic conventional Node/Maven multi-stage projects are built
            # in disposable toolchain containers. Dependency state is mounted
            # from the visible platform-wide cache; Docker only packages the
            # resulting dist/JAR into the small runtime stage.
            override_doc: dict = {}
            if compose_override:
                try:
                    override_doc = yaml.safe_load((Path(work) / compose_override).read_text(encoding="utf-8")) or {}
                except Exception:
                    override_doc = {}
            prebuilt_contexts: set[str] = set()
            compose_changed = False
            for service_name, service in (compose_doc.get("services") or {}).items():
                if not isinstance(service, dict) or not service.get("build"):
                    continue
                build = service["build"]
                context_rel = str(build.get("context") or ".") if isinstance(build, dict) else str(build)
                dockerfile_rel = str(build.get("dockerfile") or "Dockerfile") if isinstance(build, dict) else "Dockerfile"
                context = (Path(work) / context_rel).resolve()
                context_key = str(context)
                dockerfile = context / dockerfile_rel
                if context_key in prebuilt_contexts or not dockerfile.is_file():
                    continue
                docker_text = dockerfile.read_text(encoding="utf-8", errors="ignore")
                runtime_text: str | None = None
                artifacts: list[str] = []

                package_json = context / "package.json"
                node_match = re.search(r"(?im)^FROM\s+(node:[^\s]+)", docker_text)
                if package_json.is_file() and node_match and "--from=" in docker_text:
                    try:
                        package_meta = json.loads(package_json.read_text(encoding="utf-8", errors="replace"))
                    except Exception:
                        package_meta = {}
                    scripts = package_meta.get("scripts") if isinstance(package_meta, dict) else {}
                    # A runtime-only Node service (for example Express) has no
                    # build artifact. Do not invent `yarn build`; let its
                    # Dockerfile install dependencies and start normally.
                    if not isinstance(scripts, dict) or not scripts.get("build"):
                        continue
                    node_image = compatible_node_image(context, node_match.group(1))
                    if node_image != node_match.group(1):
                        log(deployment.id, f"[平台兼容] 项目依赖要求较新 Node，构建镜像已从 {node_match.group(1)} 调整为 {node_image}。\n")
                    package_manager = str(package_meta.get("packageManager") or "").lower()
                    has_package_lock = (context / "package-lock.json").is_file()
                    has_pnpm_lock = (context / "pnpm-lock.yaml").is_file()
                    has_yarn_lock = (context / "yarn.lock").is_file()
                    if package_manager.startswith("pnpm") or (has_pnpm_lock and not has_package_lock and not has_yarn_lock):
                        manager = "pnpm"
                        install = "corepack enable; corepack prepare pnpm@8.15.9 --activate; " \
                                  f"pnpm install --store-dir {shlex.quote(pnpm_cache_dir)} --frozen-lockfile; pnpm run build"
                    elif package_manager.startswith("yarn") or (has_yarn_lock and not has_package_lock):
                        manager = "yarn"
                        install = f"yarn install --cache-folder {shlex.quote(yarn_cache_dir)} --frozen-lockfile --prefer-offline --network-timeout 600000; yarn build"
                    else:
                        manager = "npm"
                        install = "npm install --prefer-offline --no-audit --no-fund; npm run build"
                    package_text = json.dumps(package_meta, ensure_ascii=False)
                    legacy_webpack = bool(
                        re.search(r'"(?:webpack|@vue/cli-service)"\s*:\s*"?[~^]?(?:[0-4])(?:\.|"|$)', package_text)
                    )
                    node_major_match = re.search(r"node:(\d+)", node_match.group(1))
                    if legacy_webpack and node_major_match and int(node_major_match.group(1)) >= 17:
                        install = "export NODE_OPTIONS=--openssl-legacy-provider; " + install
                        log(
                            deployment.id,
                            "[平台兼容] 检测到旧版 Webpack 与 OpenSSL 3，已仅为本次前端构建启用兼容模式。\n",
                        )
                    if context_key not in node_built_contexts:
                        relative_context = context.relative_to(source_root).as_posix() or "."
                        node_modules_mount = ""
                        if manager in {"npm", "yarn", "pnpm"}:
                            persistent_modules = persistent_dependency_root / relative_context / "node_modules"
                            persistent_modules.mkdir(parents=True, exist_ok=True)
                            visible_modules = Path(builder_root) / "projects" / project.slug / "source-cache" / relative_context / "node_modules"
                            if visible_modules.parent.is_dir() and not visible_modules.exists():
                                try:
                                    visible_modules.symlink_to(persistent_modules, target_is_directory=True)
                                except OSError:
                                    pass
                            node_modules_mount = f"-v {shlex.quote(str(persistent_modules) + ':/workspace/node_modules')} "
                        command = (
                            f"docker run --rm {proxy_run_args} --label yunzhou.deployment={shlex.quote(deployment.id)} "
                            f"-v {shlex.quote(context_key)}:/workspace "
                            f"-v {shlex.quote(cache_root + '/pnpm' + ':' + pnpm_cache_dir)} "
                            f"-v {shlex.quote(cache_root + '/npm' + ':' + npm_cache_dir)} "
                            f"-v {shlex.quote(cache_root + '/yarn' + ':' + yarn_cache_dir)} "
                            f"{node_cache_env}"
                            f"{node_modules_mount}"
                            f"-w /workspace {shlex.quote(node_image)} sh -lc "
                            + shlex.quote("set -e; trap 'rm -rf .pnpm-store' EXIT; " + install)
                        )
                        log(deployment.id, f"[平台构建] Node 正式构建：{node_image} + {manager}。\n")
                        code, output = tracked_run(build_ssh, deployment.id, command, stream=stream, timeout=1800,
                                                   pid_prefix="yunzhou-node-build", stream_channel="web", stream_label="前端 Web")
                        if code:
                            raise RuntimeError("Node 公共缓存构建失败：" + output[-2000:])
                        node_built_contexts.add(context_key)
                        shutil.rmtree(context / ".pnpm-store", ignore_errors=True)
                    else:
                        log(deployment.id, f"[平台构建] Node 产物已生成，跳过重复 {manager} 构建。\n")
                    result = runtime_stage_from_prebuilt_artifact(
                        docker_text, context, ["dist", "build", ".output", "out"], "node"
                    )
                    if result:
                        runtime_text, artifacts = result

                pom = context / "pom.xml"
                # Some repositories ship a runtime-only Dockerfile that copies
                # target/*.jar and assumes CI has already run Maven.  The
                # platform owns the build, so materialize that prerequisite
                # before Docker packaging instead of failing on a missing JAR.
                runtime_jar_copy = re.search(
                    r"(?im)^\s*COPY(?:\s+--\S+)*\s+[^\n]*?target/[^\s]+\.jar\s+",
                    docker_text,
                )
                existing_context_jars = [
                    path for path in context.rglob("target/*.jar")
                    if path.is_file() and not path.name.startswith(("original-", "sources-", "javadoc-"))
                ]
                maven_file_match = re.search(
                    r"(?im)^\s*RUN\s+[^\n]*?\bmvn\b[^\n]*?\s-f\s+([\"']?)([^\s\"'\\]+pom[^\s\"'\\]*\.xml)\1",
                    docker_text,
                )
                maven_file = maven_file_match.group(2) if maven_file_match else ""
                # A generated Dockerfile may create a temporary corrected POM
                # inside a Docker stage.  It is unavailable to the host-side
                # compiler, so fall back to the real module pom beside it.
                if maven_file and not (context / maven_file).is_file():
                    candidate = Path(maven_file).parent / "pom.xml"
                    maven_file = candidate.as_posix() if (context / candidate).is_file() else ""
                maven_file_arg = f"-f {shlex.quote(maven_file)} " if maven_file else ""
                if pom.is_file() and runtime_jar_copy and not existing_context_jars:
                    java_version = detect_java_version(str(context))
                    maven_image = f"maven:3.9-eclipse-temurin-{java_version}"
                    settings_arg = "-s /workspace/.yunzhou.maven-settings.xml " \
                        if (context / ".yunzhou.maven-settings.xml").is_file() else ""
                    command = (
                        f"docker run --rm {proxy_run_args} --label yunzhou.deployment={shlex.quote(deployment.id)} "
                        f"-v {shlex.quote(context_key)}:/workspace "
                        f"-v {shlex.quote(cache_root + '/maven' + ':' + maven_cache_dir)} "
                        f"{maven_cache_env}"
                        f"-w /workspace {shlex.quote(maven_image)} "
                        f"mvn {settings_arg}-B {maven_file_arg}package -DskipTests"
                    )
                    log(
                        deployment.id,
                        f"[平台构建] 检测到运行 Dockerfile 依赖尚未生成的 JAR；"
                        f"先使用 {maven_image} 生成构建产物，再执行镜像封装。\n",
                    )
                    # Repository-wide style plugins may scan every text file,
                    # including platform-owned runtime env snapshots. Keep
                    # those files outside the source tree during compilation
                    # and restore them before Docker/Compose packaging.
                    hidden_platform_files: list[tuple[Path, Path]] = []
                    for platform_file in context.glob(".yunzhou*.env"):
                        backup = context.parent / (
                            f".{context.name}.{deployment.id[:8]}.{platform_file.name}.runtime"
                        )
                        platform_file.replace(backup)
                        hidden_platform_files.append((platform_file, backup))
                    try:
                        code, output = tracked_run(
                            build_ssh, deployment.id, command, stream=stream, timeout=1800,
                            pid_prefix="yunzhou-maven-build", stream_channel="api", stream_label="后端 API",
                        )
                    finally:
                        for platform_file, backup in hidden_platform_files:
                            if backup.exists():
                                backup.replace(platform_file)
                    if code:
                        raise RuntimeError("Maven 前置产物构建失败：" + output[-2000:])
                    built_jars = [
                        path for path in context.rglob("target/*.jar")
                        if path.is_file() and not path.name.startswith(("original-", "sources-", "javadoc-"))
                    ]
                    if built_jars and not any(_executable_jar_score(path)[0] for path in built_jars):
                        boot_version = detect_spring_boot_version(str(context))
                        if boot_version and maven_file:
                            repackage_command = (
                                f"docker run --rm {proxy_run_args} --label yunzhou.deployment={shlex.quote(deployment.id)} "
                                f"-v {shlex.quote(context_key)}:/workspace "
                                f"-v {shlex.quote(cache_root + '/maven' + ':' + maven_cache_dir)} "
                                f"{maven_cache_env}"
                                f"-w /workspace {shlex.quote(maven_image)} "
                                f"mvn {settings_arg}-B -f {shlex.quote(maven_file)} "
                                f"org.springframework.boot:spring-boot-maven-plugin:{shlex.quote(boot_version)}:repackage "
                                "-DskipTests"
                            )
                            log(deployment.id, f"[平台构建] 普通 JAR 按 Spring Boot {boot_version} 自动重打包。\n")
                            repack_code, repack_output = tracked_run(
                                build_ssh, deployment.id, repackage_command, stream=stream, timeout=900,
                                pid_prefix="yunzhou-maven-repackage", stream_channel="api", stream_label="后端 API",
                            )
                            if repack_code:
                                raise RuntimeError("Spring Boot JAR 重打包失败：" + repack_output[-2000:])
                            built_jars = [
                                path for path in context.rglob("target/*.jar")
                                if path.is_file() and not path.name.startswith(("original-", "sources-", "javadoc-"))
                            ]
                            if not any(_executable_jar_score(path)[0] for path in built_jars):
                                raise RuntimeError("Spring Boot 重打包完成，但仍未生成带 Main-Class 的可执行 JAR")
                    maven_built_contexts.add(context_key)

                maven_match = re.search(r"(?im)^FROM\s+(maven:[^\s]+)", docker_text)
                if runtime_text is None and pom.is_file() and maven_match and "--from=" in docker_text:
                    if context_key not in maven_built_contexts:
                        command = (
                            f"docker run --rm {proxy_run_args} --label yunzhou.deployment={shlex.quote(deployment.id)} "
                            f"-v {shlex.quote(context_key)}:/workspace "
                            f"-v {shlex.quote(cache_root + '/maven' + ':' + maven_cache_dir)} "
                            f"{maven_cache_env}"
                            f"-w /workspace {shlex.quote(maven_match.group(1))} "
                            f"mvn -B {maven_file_arg}package -DskipTests"
                        )
                        build_scope = maven_file or "根工程"
                        log(deployment.id, f"[平台构建] Maven 正式构建：{maven_match.group(1)}，范围 {build_scope}。\n")
                        code, output = tracked_run(build_ssh, deployment.id, command, stream=stream, timeout=1800,
                                                   pid_prefix="yunzhou-maven-build", stream_channel="api", stream_label="后端 API")
                        if code:
                            raise RuntimeError("Maven 公共缓存构建失败：" + output[-2000:])
                        built_jars = [
                            path for path in context.rglob("target/*.jar")
                            if path.is_file() and not path.name.startswith(("original-", "sources-", "javadoc-"))
                        ]
                        if built_jars and not any(_executable_jar_score(path)[0] for path in built_jars):
                            boot_version = detect_spring_boot_version(str(context))
                            if boot_version and maven_file:
                                repackage_command = (
                                    f"docker run --rm {proxy_run_args} --label yunzhou.deployment={shlex.quote(deployment.id)} "
                                    f"-v {shlex.quote(context_key)}:/workspace "
                                    f"-v {shlex.quote(cache_root + '/maven' + ':' + maven_cache_dir)} "
                                    f"{maven_cache_env}"
                                    f"-w /workspace {shlex.quote(maven_match.group(1))} "
                                    f"mvn -B -f {shlex.quote(maven_file)} "
                                    f"org.springframework.boot:spring-boot-maven-plugin:{shlex.quote(boot_version)}:repackage "
                                    "-DskipTests"
                                )
                                log(
                                    deployment.id,
                                    f"[平台构建] 检测到普通 Spring Boot JAR，按源码版本 {boot_version} 自动重打包并校验启动清单。\n",
                                )
                                repack_code, repack_output = tracked_run(
                                    build_ssh, deployment.id, repackage_command, stream=stream, timeout=900,
                                    pid_prefix="yunzhou-maven-repackage", stream_channel="api", stream_label="后端 API",
                                )
                                if repack_code:
                                    raise RuntimeError("Spring Boot JAR 重打包失败：" + repack_output[-2000:])
                                built_jars = [
                                    path for path in context.rglob("target/*.jar")
                                    if path.is_file() and not path.name.startswith(("original-", "sources-", "javadoc-"))
                                ]
                                if not any(_executable_jar_score(path)[0] for path in built_jars):
                                    raise RuntimeError("Spring Boot 重打包完成，但仍未生成带 Main-Class 的可执行 JAR")
                        maven_built_contexts.add(context_key)
                    else:
                        log(deployment.id, "[平台构建] Maven JAR 已生成，跳过重复 package。\n")
                    jar_paths = sorted({str(path.relative_to(context)).replace('\\', '/')
                                       for path in context.rglob("target/*.jar")
                                       if not path.name.startswith(("original-", "sources-", "javadoc-"))})
                    result = runtime_stage_from_prebuilt_artifact(docker_text, context, jar_paths, "maven")
                    if result:
                        runtime_text, artifacts = result

                # Go backends can be substantially more expensive than their
                # frontend (Memos is a representative example). Compile the
                # binary before entering the serialized image-store section,
                # with persistent module and compiler caches mounted from the
                # builder. The final Docker stage then only copies the binary
                # and any referenced runtime scripts.
                go_image_match = re.search(
                    r"(?im)^FROM\s+(?:--platform=\S+\s+)?(golang:[^\s]+)",
                    docker_text,
                )
                go_build_match = re.search(
                    r"(?ims)\bgo\s+build\s+(?P<args>.*?)(?=\n\s*\n|^\s*FROM\s+)",
                    docker_text,
                )
                if (
                    runtime_text is None
                    and go_image_match
                    and go_build_match
                    and (context / "go.mod").is_file()
                    and "--from=" in docker_text
                ):
                    raw_go_command = "go build " + go_build_match.group("args")
                    raw_go_command = re.sub(r"\\\s*\n\s*", " ", raw_go_command).strip()
                    output_match = re.search(r"(?:^|\s)-o\s+(?:[\"']?)([^\s\"']+)", raw_go_command)
                    if output_match:
                        binary_name = Path(output_match.group(1).rstrip("/")).name or "app"
                        artifact_dir = context / ".yunzhou-go-build"
                        artifact_dir.mkdir(parents=True, exist_ok=True)
                        binary_path = artifact_dir / binary_name
                        raw_go_command = re.sub(
                            r"(?:^|\s)-o\s+(?:[\"']?)[^\s\"']+",
                            f" -o /workspace/.yunzhou-go-build/{binary_name}",
                            raw_go_command,
                            count=1,
                        ).strip()
                        now = datetime.now(timezone.utc)
                        safe_go_version = f"{now:%y.%m}.{now.day}-dev.0000000"
                        go_command = (
                            "set -e; export PATH=/usr/local/go/bin:$PATH; "
                            "apk add --no-cache git ca-certificates >/dev/null; "
                            f"export CGO_ENABLED=0 GOOS=linux GOARCH=amd64 VERSION=${{VERSION:-{safe_go_version}}} COMMIT=${{COMMIT:-0000000}}; "
                            + raw_go_command
                        )
                        command = (
                            f"docker run --rm {proxy_run_args} --label yunzhou.deployment={shlex.quote(deployment.id)} "
                            f"-v {shlex.quote(context_key)}:/workspace "
                            f"-v {shlex.quote(cache_root + '/go-mod:/go/pkg/mod')} "
                            f"-v {shlex.quote(cache_root + '/go-build:/root/.cache/go-build')} "
                            f"-w /workspace {shlex.quote(go_image_match.group(1))} sh -c "
                            + shlex.quote(go_command)
                        )
                        log(
                            deployment.id,
                            f"[平台构建] Go 使用 {go_image_match.group(1)} 与公共模块缓存并发编译；镜像阶段仅打包二进制。\n",
                        )
                        code, output = tracked_run(
                            build_ssh, deployment.id, command, stream=stream, timeout=1800,
                            pid_prefix="yunzhou-go-build", stream_channel="api", stream_label="后端 API",
                        )
                        if code:
                            raise RuntimeError("Go 公共缓存构建失败：" + output[-2000:])
                        runtime_artifacts = [str(binary_path.relative_to(context)).replace('\\', '/')]
                        for copy_match in re.finditer(
                            r"(?im)^\s*COPY\s+(?:--\S+\s+)*--from=\S+\s+(?:--\S+\s+)*([^\s]+)\s+([^\s]+)\s*$",
                            docker_text,
                        ):
                            source_name = Path(copy_match.group(1).strip("\"'")).name
                            for candidate in context.rglob(source_name):
                                if candidate.is_file() and not any(part == ".git" for part in candidate.parts):
                                    runtime_artifacts.append(candidate.relative_to(context).as_posix())
                                    break
                        result = runtime_stage_from_prebuilt_artifact(
                            docker_text, context, list(dict.fromkeys(runtime_artifacts)), "go"
                        )
                        if result:
                            runtime_text, artifacts = result

                # .NET compilation is safe to run concurrently with Node,
                # Java and Python when it writes to a host-mounted NuGet
                # cache.  Publish outside Docker first, then let the short
                # image-store critical section package only the runtime
                # files.  This avoids a three-minute dotnet publish holding
                # the global classic-Docker commit lock and blocking unrelated
                # projects on the same builder.
                dotnet_sdk_match = re.search(
                    r"(?im)^FROM\s+(mcr\.microsoft\.com/dotnet/sdk:[^\s]+)",
                    docker_text,
                )
                if runtime_text is None and dotnet_sdk_match and "--from=" in docker_text:
                    publish_match = re.search(
                        r"(?im)\bdotnet\s+publish\s+['\"]?([^\s'\"]+\.csproj)",
                        docker_text,
                    )
                    csproj_candidates = sorted(
                        path for path in context.rglob("*.csproj")
                        if not any(part in {"bin", "obj", ".git"} for part in path.relative_to(context).parts)
                    )
                    csproj = None
                    if publish_match:
                        declared = publish_match.group(1).replace("\\", "/")
                        for prefix in ("/src/", "/workspace/", "./"):
                            if declared.startswith(prefix):
                                declared = declared[len(prefix):]
                                break
                        candidate = context / declared
                        if candidate.is_file():
                            csproj = candidate
                    if csproj is None and len(csproj_candidates) == 1:
                        csproj = csproj_candidates[0]
                    if csproj is not None:
                        publish_dir = context / "publish"
                        shutil.rmtree(publish_dir, ignore_errors=True)
                        project_rel = csproj.relative_to(context).as_posix()
                        publish_command = (
                            f"dotnet restore {shlex.quote(project_rel)} && "
                            f"dotnet publish {shlex.quote(project_rel)} -c Release -o /workspace/publish "
                            "--no-restore /p:UseAppHost=false "
                            "-p:RunAnalyzers=false -p:TreatWarningsAsErrors=false"
                        )
                        command = (
                            f"docker run --rm {proxy_run_args} --label yunzhou.deployment={shlex.quote(deployment.id)} "
                            f"-v {shlex.quote(context_key)}:/workspace "
                            f"-v {shlex.quote(cache_root + '/nuget:/root/.nuget/packages')} "
                            f"-w /workspace {shlex.quote(dotnet_sdk_match.group(1))} sh -lc "
                            + shlex.quote(publish_command)
                        )
                        log(
                            deployment.id,
                            f"[平台构建] .NET 使用 {dotnet_sdk_match.group(1)} 与公共 NuGet 缓存并发发布；镜像阶段仅打包产物。\n",
                        )
                        code, output = tracked_run(
                            build_ssh, deployment.id, command, stream=stream, timeout=1800,
                            pid_prefix="yunzhou-dotnet-build", stream_channel="api", stream_label="后端 API",
                        )
                        if code:
                            raise RuntimeError(".NET 公共缓存发布失败：" + output[-2000:])
                        result = runtime_stage_from_prebuilt_artifact(
                            docker_text, context, ["publish"], "dotnet"
                        )
                        if result:
                            runtime_text, artifacts = result

                if runtime_text is None:
                    continue
                prebuilt_contexts.add(context_key)
                runtime_name = ".yunzhou.runtime.Dockerfile"
                (context / runtime_name).write_text(runtime_text, encoding="utf-8")
                ignore_file = context / ".dockerignore"
                ignore_text = ignore_file.read_text(encoding="utf-8", errors="ignore") if ignore_file.is_file() else ""
                for artifact in artifacts:
                    ignore_text += f"\n!{artifact}\n!{artifact}/**\n"
                ignore_text += f"\n!{runtime_name}\n"
                ignore_file.write_text(ignore_text, encoding="utf-8")
                clean_build = {"context": context_rel, "dockerfile": runtime_name}
                service["build"] = clean_build
                override_service = (override_doc.get("services") or {}).get(service_name)
                if isinstance(override_service, dict):
                    override_service["build"] = clean_build
                compose_changed = True
                log(deployment.id, f"[平台构建] {service_name} 已切换为仅打包运行产物，不使用 Docker 依赖缓存。\n")
            if compose_changed:
                (Path(work) / build_file).write_text(yaml.safe_dump(compose_doc, allow_unicode=True, sort_keys=False), encoding="utf-8")
                if compose_override:
                    (Path(work) / compose_override).write_text(yaml.safe_dump(override_doc, allow_unicode=True, sort_keys=False), encoding="utf-8")
        # Compile recognized Java + Vue repositories in disposable toolchain
        # containers. Package-manager state lives in visible host directories,
        # shared by every project and independent from application images.
        # Detect the repository from source evidence, not from runtime files
        # produced by an older analysis.  Fresh projects and re-analysis runs
        # must enter this path before any runtime-only Dockerfile exists.
        mounted_wms_build = (
            (Path(work) / "WMSCloud/pom.xml").is_file()
            and (Path(work) / "WMSCloud/ruoyi-admin/pom.xml").is_file()
            and (Path(work) / "WMSCloud_ui/package.json").is_file()
        )
        if mounted_wms_build:
            log(deployment.id, f"[平台构建] 公共缓存：{cache_root}/{{maven,pnpm,npm,yarn,gradle,pip}}\n")
            frontend_dist = Path(builder_dir) / "WMSCloud_ui/dist"
            if not frontend_dist.is_dir() or not any(frontend_dist.iterdir()):
                node_command = (
                    f"docker run --rm {proxy_run_args} --label yunzhou.deployment={shlex.quote(deployment.id)} "
                    f"-v {shlex.quote(builder_dir + '/WMSCloud_ui')}:/workspace "
                    f"-v {shlex.quote(cache_root + '/pnpm' + ':' + pnpm_cache_dir)} "
                    f"-v {shlex.quote(cache_root + '/npm' + ':' + npm_cache_dir)} "
                    f"-v {shlex.quote(cache_root + '/yarn' + ':' + yarn_cache_dir)} "
                    f"{node_cache_env}"
                    "-w /workspace node:16.20.2 sh -lc "
                    + shlex.quote(
                        "set -e; corepack enable; corepack prepare pnpm@8.15.9 --activate; "
                        f"pnpm install --store-dir {shlex.quote(pnpm_cache_dir)} --frozen-lockfile; pnpm run build"
                    )
                )
                log(deployment.id, "[平台构建] 前端：Node 16.20.2 + pnpm 8.15.9，挂载公共 pnpm/npm/yarn 缓存。\n")
                code, output = tracked_run(
                    build_ssh, deployment.id, node_command, stream=stream,
                    timeout=1800, pid_prefix="yunzhou-node-build", stream_channel="web", stream_label="前端 Web",
                )
                if code:
                    raise RuntimeError("前端挂载缓存构建失败：" + output[-2000:])
                shutil.rmtree(Path(builder_dir) / "WMSCloud_ui/.pnpm-store", ignore_errors=True)
                reused = max((int(value) for value in re.findall(r"reused\s+(\d+)", output)), default=0)
                downloaded = max((int(value) for value in re.findall(r"downloaded\s+(\d+)", output)), default=0)
                log(deployment.id, f"[缓存命中] pnpm reused={reused}，downloaded={downloaded}。\n")
            else:
                log(deployment.id, "[平台构建] 前端产物已生成，跳过重复 pnpm 构建。\n")

            settings_file = Path(work) / ".yunzhou.maven-settings.xml"
            if not settings_file.is_file():
                settings_file.write_text(
                    '<settings xmlns="http://maven.apache.org/SETTINGS/1.0.0"><mirrors><mirror>'
                    '<id>yunzhou-mirror</id><mirrorOf>*</mirrorOf><url>https://maven.aliyun.com/repository/public</url>'
                    '</mirror></mirrors></settings>', encoding="utf-8",
                )
            existing_wms_jars = sorted(
                path for path in (Path(builder_dir) / "WMSCloud").rglob("target/*.jar")
                if path.is_file() and not path.name.startswith(("original-", "sources-", "javadoc-"))
            )
            if existing_wms_jars:
                log(
                    deployment.id,
                    "[平台构建] 后端产物已由并发 Maven 构建生成，跳过第二次 package："
                    + existing_wms_jars[-1].relative_to(Path(builder_dir)).as_posix() + "。\n",
                )
            else:
                maven_command = (
                    f"docker run --rm {proxy_run_args} --label yunzhou.deployment={shlex.quote(deployment.id)} "
                    f"-v {shlex.quote(builder_dir)}:/workspace "
                    f"-v {shlex.quote(cache_root + '/maven' + ':' + maven_cache_dir)} "
                    f"{maven_cache_env}"
                    "-w /workspace maven:3.8.8-eclipse-temurin-8 "
                    "mvn -s /workspace/.yunzhou.maven-settings.xml -B -f WMSCloud/pom.xml "
                    "-pl ruoyi-admin -am package -DskipTests"
                )
                log(deployment.id, f"[平台构建] 后端：Maven 3.8.8 + Java 8，挂载公共 {maven_cache_dir} 缓存。\n")
                code, output = tracked_run(
                    build_ssh, deployment.id, maven_command, stream=stream,
                    timeout=1800, pid_prefix="yunzhou-maven-build", stream_channel="api", stream_label="后端 API",
                )
                if code:
                    raise RuntimeError("Maven 挂载缓存构建失败：" + output[-2000:])
                downloaded = len(re.findall(r"Downloading from ", output))
                log(deployment.id, f"[缓存命中] Maven 本次远程下载请求={downloaded}。\n")

            # WMS-style repositories keep the frontend and the Maven reactor
            # below one shared Compose build context.  The generic converter
            # above intentionally looks only at manifests in the immediate
            # context, so it cannot safely guess which nested artifact belongs
            # to each service.  At this point both builds have completed and
            # their real outputs are available.  Resolve them by service
            # runtime evidence and replace every generated multi-stage file
            # with a per-service, runtime-only Dockerfile.
            compose_path = Path(work) / build_file
            try:
                wms_compose = yaml.safe_load(compose_path.read_text(encoding="utf-8", errors="ignore")) or {}
            except Exception:
                wms_compose = {}
            wms_override: dict = {}
            if compose_override:
                try:
                    wms_override = yaml.safe_load(
                        (Path(work) / compose_override).read_text(encoding="utf-8", errors="ignore")
                    ) or {}
                except Exception:
                    wms_override = {}
            wms_jars = sorted(
                path for path in (Path(work) / "WMSCloud").rglob("target/*.jar")
                if path.is_file() and not path.name.startswith(("original-", "sources-", "javadoc-"))
            )
            wms_dist = Path(work) / "WMSCloud_ui/dist"
            rewritten_services: list[str] = []
            for service_name, service in (wms_compose.get("services") or {}).items():
                if not isinstance(service, dict) or not service.get("build"):
                    continue
                build = service["build"]
                build = {"context": build} if isinstance(build, str) else dict(build)
                context_rel = str(build.get("context") or ".")
                context = (Path(work) / context_rel).resolve()
                dockerfile = context / str(build.get("dockerfile") or "Dockerfile")
                if not dockerfile.is_file():
                    continue
                docker_text = dockerfile.read_text(encoding="utf-8", errors="ignore")
                lower_name = str(service_name).lower()
                environment = service.get("environment") or {}
                environment_keys = " ".join(
                    str(key).lower()
                    for key in (environment.keys() if isinstance(environment, dict) else [])
                )
                # Runtime role is authoritative. A previous generic pass may
                # already have replaced the Dockerfile with Nginx, so the
                # current base image alone is not trustworthy evidence.
                is_backend = bool(
                    any(token in lower_name for token in ("api", "backend", "server"))
                    or any(token in environment_keys for token in ("spring_", "server_port", "java_"))
                )
                is_frontend = bool(
                    not is_backend
                    and re.search(r"(?im)^\s*FROM\s+(?:--platform=\S+\s+)?(?:node|nginx):", docker_text)
                    and ("web" in lower_name or "front" in lower_name or "ui" in lower_name or "nginx" in docker_text.lower())
                )
                if is_frontend and wms_dist.is_dir() and wms_dist.is_relative_to(context):
                    artifact_values = [wms_dist.relative_to(context).as_posix()]
                    output_kind = "wms-frontend"
                elif is_backend and wms_jars:
                    # A Compose build can only COPY files below its own build
                    # context.  Multi-module repositories also contain many
                    # library JARs in sibling modules; feeding those paths to
                    # relative_to() both crashes packaging and risks selecting
                    # a non-executable dependency as the application image.
                    context_jars = [path for path in wms_jars if path.is_relative_to(context)]
                    if not context_jars:
                        continue
                    artifact_values = [path.relative_to(context).as_posix() for path in context_jars]
                    output_kind = "wms-backend"
                else:
                    continue
                if is_frontend:
                    nginx_images = re.findall(
                        r"(?im)^\s*FROM\s+(?:--platform=\S+\s+)?(nginx:[^\s]+)",
                        docker_text,
                    )
                    runtime_text = platform_spa_runtime_dockerfile(
                        nginx_images[-1] if nginx_images else PLATFORM_NGINX_IMAGE,
                        artifact_values[0],
                        detect_frontend_public_base(str(context)).get("primary_path") or "/",
                    )
                    copied = [artifact_values[0]]
                else:
                    # Select by executable evidence, never by a project/module
                    # name. This remains valid when users rename services or
                    # deploy a completely different multi-module project.
                    jar_candidates = [context / value for value in artifact_values]
                    selected_jar = max(jar_candidates, key=_executable_jar_score)
                    java_match = re.search(
                        r"(?im)^\s*FROM\s+(?:--platform=\S+\s+)?([^\s]*(?:temurin|openjdk)[^\s]*)",
                        docker_text,
                    )
                    java_image = java_match.group(1) if java_match else "eclipse-temurin:8-jre"
                    relative_jar = selected_jar.relative_to(context).as_posix()
                    runtime_text = (
                        f"FROM {java_image}\nWORKDIR /app\n"
                        f"COPY {relative_jar} /app/app.jar\n"
                        "EXPOSE 8080\n"
                        'ENTRYPOINT ["java", "-jar", "/app/app.jar"]\n'
                    )
                    copied = [relative_jar]
                safe_service = re.sub(r"[^a-z0-9_.-]+", "-", lower_name).strip("-.") or "app"
                runtime_name = f".yunzhou.{safe_service}.runtime.Dockerfile"
                runtime_text = enforce_nginx_pid_compatibility(runtime_text)
                (context / runtime_name).write_text(runtime_text, encoding="utf-8")
                clean_build = {"context": context_rel, "dockerfile": runtime_name}
                service["build"] = clean_build
                override_service = (wms_override.get("services") or {}).get(service_name)
                if isinstance(override_service, dict):
                    override_service["build"] = clean_build
                rewritten_services.append(str(service_name))
                log(
                    deployment.id,
                    f"[平台构建] {service_name} 已改为纯运行镜像，仅复制：{', '.join(copied)}。\n",
                )
            if rewritten_services:
                compose_path.write_text(
                    yaml.safe_dump(wms_compose, allow_unicode=True, sort_keys=False), encoding="utf-8"
                )
                if compose_override:
                    (Path(work) / compose_override).write_text(
                        yaml.safe_dump(wms_override, allow_unicode=True, sort_keys=False), encoding="utf-8"
                    )
                log(
                    deployment.id,
                    "[封装准备] 多模块产物已汇合，运行镜像不再执行 npm/pnpm/Maven："
                    + "、".join(rewritten_services) + "。\n",
                )

        # Generic shared-root monorepo fallback.  Node/Maven builds above scan
        # manifests recursively and therefore may have produced artifacts in
        # VUE/dist, frontend/build, API/target, or any other module name.  Do
        # not key packaging to project/service names: map real artifacts to
        # each remaining generated multi-stage Dockerfile by runtime role.
        if build_type == "compose":
            compose_path = Path(work) / build_file
            try:
                generic_compose = yaml.safe_load(
                    compose_path.read_text(encoding="utf-8", errors="ignore")
                ) or {}
            except Exception:
                generic_compose = {}
            generic_override: dict = {}
            if compose_override:
                try:
                    generic_override = yaml.safe_load(
                        (Path(work) / compose_override).read_text(encoding="utf-8", errors="ignore")
                    ) or {}
                except Exception:
                    generic_override = {}
            frontend_artifacts = sorted(
                path for path in Path(work).rglob("*")
                if path.is_dir()
                and path.name.lower() in {"dist", "build", "out", "public"}
                and (path / "index.html").is_file()
                and not any(part in {"node_modules", ".git"} for part in path.relative_to(Path(work)).parts)
            )
            backend_artifacts = sorted(
                path for path in Path(work).rglob("target/*.jar")
                if path.is_file()
                and not path.name.startswith(("original-", "sources-", "javadoc-"))
            )
            planned_roles = _traffic_service_roles(
                _project_traffic_plan(
                    project,
                    (project.source_analysis or {}).get("deployment_plan") or {},
                )
            )
            generic_changes: list[str] = []
            for service_name, service in (generic_compose.get("services") or {}).items():
                if not isinstance(service, dict) or not service.get("build"):
                    continue
                build = service["build"]
                build = {"context": build} if isinstance(build, str) else dict(build)
                context_rel = str(build.get("context") or ".")
                context = (Path(work) / context_rel).resolve()
                dockerfile = context / str(build.get("dockerfile") or "Dockerfile")
                if not dockerfile.is_file():
                    continue
                docker_text = dockerfile.read_text(encoding="utf-8", errors="ignore")
                has_compile_step = bool(re.search(
                    r"(?im)^\s*RUN\s+.*(?:\bmvn\b.*\b(?:package|install)\b|"
                    r"\bgradle\w*\b.*\b(?:build|bootJar)\b|"
                    r"\b(?:npm|pnpm|yarn)\b.*\b(?:run\s+)?build\b)",
                    docker_text,
                ))
                lower_name = str(service_name).lower()
                environment = service.get("environment") or {}
                environment_keys = " ".join(
                    str(key).lower()
                    for key in (environment.keys() if isinstance(environment, dict) else [])
                )
                nginx_images = re.findall(
                    r"(?im)^\s*FROM\s+(?:--platform=\S+\s+)?(nginx:[^\s]+)", docker_text
                )
                context_poms = list(context.rglob("pom.xml")) if context.is_dir() else []
                context_jars = [path for path in backend_artifacts if context == path or context in path.parents]
                planned_role = str((planned_roles.get(str(service_name)) or ("", False))[0]).lower()
                name_is_frontend = any(token in lower_name for token in ("web", "front", "ui"))
                name_is_backend = any(token in lower_name for token in ("api", "backend", "server"))
                backend_role = bool(
                    planned_role in {"backend", "api", "server"}
                    or name_is_backend
                    or (
                        planned_role not in {"frontend", "web", "ui"}
                        and not name_is_frontend
                        and (
                            (lower_name in {"app", "application"} and bool(backend_artifacts))
                            or any(token in environment_keys for token in ("spring_", "server_port", "java_"))
                            or context_poms
                            or context_jars
                            or re.search(r"(?i)\b(?:java|mvn|maven|gradle|jar)\b", docker_text)
                        )
                    )
                )
                frontend_role = bool(
                    planned_role in {"frontend", "web", "ui"}
                    or (
                        not backend_role
                        and (
                        name_is_frontend
                        or (nginx_images and not backend_artifacts)
                        )
                    )
                )
                artifact_values: list[str]
                if frontend_role and frontend_artifacts:
                    # Prefer the shallowest artifact; ties are deterministic.
                    chosen_frontend = min(
                        frontend_artifacts,
                        key=lambda path: (len(path.relative_to(context).parts), path.as_posix()),
                    )
                    artifact_values = [chosen_frontend.relative_to(context).as_posix()]
                    runtime_text = platform_spa_runtime_dockerfile(
                        nginx_images[-1] if nginx_images else PLATFORM_NGINX_IMAGE,
                        artifact_values[0],
                        detect_frontend_public_base(str(context)).get("primary_path") or "/",
                    )
                    copied = artifact_values
                elif backend_role and backend_artifacts:
                    usable_jars = context_jars or [
                        path for path in backend_artifacts if Path(work) in path.parents
                    ]
                    selected_jar = _select_runnable_jar(usable_jars)
                    if selected_jar is None or not _executable_jar_score(selected_jar)[0]:
                        continue
                    if context not in selected_jar.parents:
                        # A faulty AI plan may point the backend service at the
                        # frontend directory.  Re-anchor the generated runtime
                        # image at the release root where the proven JAR lives.
                        context = Path(work).resolve()
                        context_rel = "."
                    relative_jar = selected_jar.relative_to(context).as_posix()
                    java_version = detect_java_version(str(context))
                    runtime_text = (
                        f"FROM eclipse-temurin:{java_version}-jre\nWORKDIR /app\n"
                        f"COPY {relative_jar} /app/app.jar\n"
                        "EXPOSE 8080\n"
                        'ENTRYPOINT ["java", "-jar", "/app/app.jar"]\n'
                    )
                    copied = [relative_jar]
                    log(
                        deployment.id,
                        f"[角色校正] {service_name} 检测到后端源码/可执行 JAR；忽略参考 Dockerfile 中的 Nginx，按后端运行镜像封装。\n",
                    )
                else:
                    continue
                safe_service = re.sub(r"[^a-z0-9_.-]+", "-", lower_name).strip("-.") or "app"
                runtime_name = f".yunzhou.{safe_service}.runtime.Dockerfile"
                (context / runtime_name).write_text(
                    enforce_nginx_pid_compatibility(runtime_text), encoding="utf-8"
                )
                clean_build = {"context": context_rel, "dockerfile": runtime_name}
                service["build"] = clean_build
                override_service = (generic_override.get("services") or {}).get(service_name)
                if isinstance(override_service, dict):
                    override_service["build"] = clean_build
                generic_changes.append(f"{service_name}→{', '.join(copied)}")
            if generic_changes:
                compose_path.write_text(
                    yaml.safe_dump(generic_compose, allow_unicode=True, sort_keys=False), encoding="utf-8"
                )
                if compose_override:
                    (Path(work) / compose_override).write_text(
                        yaml.safe_dump(generic_override, allow_unicode=True, sort_keys=False), encoding="utf-8"
                    )
                log(
                    deployment.id,
                    "[封装准备] 已按实际产物自动生成纯运行镜像：" + "；".join(generic_changes) + "。\n",
                )
        # Materialize the generic platform-artifact contract used by AI
        # runtime Dockerfiles. This is technology based, never project-name
        # based: Docker only packages outputs that the platform has already
        # built and verified.
        if build_type == "compose":
            artifact_compose_path = Path(work) / build_file
            try:
                artifact_compose = yaml.safe_load(
                    artifact_compose_path.read_text(encoding="utf-8", errors="ignore")
                ) or {}
            except Exception:
                artifact_compose = {}
            for artifact_service_name, artifact_service in (artifact_compose.get("services") or {}).items():
                if not isinstance(artifact_service, dict) or not artifact_service.get("build"):
                    continue
                artifact_build = artifact_service["build"]
                artifact_build = {"context": artifact_build} if isinstance(artifact_build, str) else dict(artifact_build)
                artifact_context = (Path(work) / str(artifact_build.get("context") or ".")).resolve()
                artifact_dockerfile = artifact_context / str(artifact_build.get("dockerfile") or "Dockerfile")
                if not artifact_dockerfile.is_file():
                    continue
                artifact_text = artifact_dockerfile.read_text(encoding="utf-8", errors="ignore")
                # AI plans have used both ``.yunzhou/artifacts/...`` and the
                # older dotted ``.yunzhou.artifacts/...`` spelling.  Neither
                # path belongs to the uploaded source package: both are
                # platform-owned build outputs that must be materialized
                # before Docker receives the build context.
                requested = set(re.findall(
                    r"(?im)^\s*COPY\s+(?!--from=)(?:--\S+\s+)*(\.yunzhou(?:/artifacts|\.artifacts)/[^\s]+)",
                    artifact_text,
                ))
                requested = {value.rstrip("/") for value in requested}
                missing = [value for value in requested if not (artifact_context / value).exists()]
                if not missing:
                    continue
                requirements_candidates = sorted(
                    path for path in artifact_context.rglob("requirements.txt")
                    if not any(part in {".git", ".venv", "venv", "node_modules"} for part in path.relative_to(artifact_context).parts)
                )
                backend_requirements = min(
                    requirements_candidates,
                    key=lambda path: (
                        0 if path.parent.name.lower() in {"backend", "server", "api"} else 1,
                        len(path.relative_to(artifact_context).parts),
                        path.as_posix(),
                    ),
                    default=None,
                )
                package_candidates = []
                for package_file in artifact_context.rglob("package.json"):
                    if any(part in {".git", "node_modules", "dist", "build"} for part in package_file.relative_to(artifact_context).parts):
                        continue
                    try:
                        package_data = json.loads(package_file.read_text(encoding="utf-8", errors="replace"))
                    except Exception:
                        continue
                    scripts = package_data.get("scripts") if isinstance(package_data, dict) else {}
                    if isinstance(scripts, dict) and scripts.get("build"):
                        package_candidates.append((package_file, package_data))
                frontend_package, frontend_meta = min(
                    package_candidates,
                    key=lambda item: (
                        0 if item[0].parent.name.lower() in {"frontend", "web", "ui"} else 1,
                        len(item[0].relative_to(artifact_context).parts),
                        item[0].as_posix(),
                    ),
                    default=(None, {}),
                )
                for relative_artifact in missing:
                    destination = artifact_context / relative_artifact
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    artifact_kind = destination.name.lower()
                    artifact_kind = {
                        "backend": "backend-runtime",
                        "python": "python-runtime",
                        "frontend": "frontend-dist",
                    }.get(artifact_kind, artifact_kind)
                    if artifact_kind == "backend-runtime":
                        if backend_requirements is None:
                            raise RuntimeError(f"[平台产物校验] {artifact_service_name} 缺少可识别的 Python 后端源码")
                        shutil.rmtree(destination, ignore_errors=True)
                        shutil.copytree(
                            backend_requirements.parent, destination,
                            ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".venv", "venv"),
                        )
                    elif artifact_kind == "python-runtime":
                        if backend_requirements is None:
                            raise RuntimeError(f"[平台产物校验] {artifact_service_name} 缺少 requirements.txt")
                        shutil.rmtree(destination, ignore_errors=True)
                        destination.mkdir(parents=True, exist_ok=True)
                        python_match = re.search(r"(?im)^\s*FROM\s+(python:[^\s]+)", artifact_text)
                        python_image = python_match.group(1) if python_match else "python:3.12-slim"
                        requirements_rel = backend_requirements.relative_to(artifact_context).as_posix()
                        destination_rel = destination.relative_to(artifact_context).as_posix()
                        command = (
                            f"docker run --rm {proxy_run_args} --label yunzhou.deployment={shlex.quote(deployment.id)} "
                            f"-v {shlex.quote(str(artifact_context))}:/workspace "
                            f"-v {shlex.quote(cache_root + '/pip' + ':' + pip_cache_dir)} "
                            f"{pip_cache_env}"
                            "-w /workspace "
                            f"{shlex.quote(python_image)} sh -lc "
                            + shlex.quote(
                                f"pip install --cache-dir {shlex.quote(pip_cache_dir)} -r {requirements_rel} --target {destination_rel}"
                            )
                        )
                        code, output = tracked_run(
                            build_ssh, deployment.id, command, stream=stream, timeout=1800,
                            pid_prefix="yunzhou-python-artifact", stream_channel="api", stream_label="后端 API",
                        )
                        if code:
                            raise RuntimeError("Python 运行依赖产物生成失败：" + output[-2000:])
                    elif artifact_kind == "frontend-dist":
                        if frontend_package is None:
                            raise RuntimeError(f"[平台产物校验] {artifact_service_name} 缺少带 build 脚本的前端 package.json")
                        frontend_root = frontend_package.parent
                        if (frontend_root / "pnpm-lock.yaml").is_file():
                            frontend_command = "corepack enable; pnpm install --frozen-lockfile; pnpm run build"
                        elif (frontend_root / "yarn.lock").is_file():
                            frontend_command = "corepack enable; yarn install --frozen-lockfile; yarn build"
                        elif (frontend_root / "package-lock.json").is_file():
                            frontend_command = "npm ci --no-audit --no-fund; npm run build"
                        else:
                            frontend_command = "npm install --no-audit --no-fund; npm run build"
                        frontend_rel = frontend_root.relative_to(artifact_context).as_posix()
                        frontend_workdir = "/workspace/" + frontend_rel.strip("/")
                        command = (
                            f"docker run --rm {proxy_run_args} --label yunzhou.deployment={shlex.quote(deployment.id)} "
                            f"-v {shlex.quote(str(artifact_context))}:/workspace -w {shlex.quote(frontend_workdir)} "
                            "node:22-slim sh -lc " + shlex.quote("set -e; " + frontend_command)
                        )
                        code, output = tracked_run(
                            build_ssh, deployment.id, command, stream=stream, timeout=1800,
                            pid_prefix="yunzhou-frontend-artifact", stream_channel="web", stream_label="前端 Web",
                        )
                        if code:
                            raise RuntimeError("前端运行产物生成失败：" + output[-2000:])
                        built_dir = next(
                            (frontend_root / name for name in ("dist", "build", "out") if (frontend_root / name).is_dir()),
                            None,
                        )
                        if built_dir is None:
                            raise RuntimeError("前端构建完成但未找到 dist/build/out 产物")
                        shutil.rmtree(destination, ignore_errors=True)
                        shutil.copytree(built_dir, destination)
                    else:
                        raise RuntimeError(f"[平台产物校验] 不支持的运行产物契约：{relative_artifact}")
                    if not destination.exists() or (destination.is_dir() and not any(destination.iterdir())):
                        raise RuntimeError(f"[平台产物校验] 运行产物为空：{relative_artifact}")
                    dockerignore = artifact_context / ".dockerignore"
                    ignore_text = dockerignore.read_text(encoding="utf-8", errors="ignore") if dockerignore.is_file() else ""
                    artifact_rule = relative_artifact.rstrip("/")
                    if artifact_rule.startswith(".yunzhou.artifacts/"):
                        artifact_parent_rules = ["!.yunzhou.artifacts/"]
                    else:
                        artifact_parent_rules = ["!.yunzhou/", "!.yunzhou/artifacts/"]
                    required_rules = [
                        *artifact_parent_rules,
                        f"!{artifact_rule}",
                        f"!{artifact_rule}/**",
                    ]
                    missing_rules = [rule for rule in required_rules if rule not in ignore_text.splitlines()]
                    if missing_rules:
                        with dockerignore.open("a", encoding="utf-8") as handle:
                            if ignore_text and not ignore_text.endswith("\n"):
                                handle.write("\n")
                            handle.write("\n".join(missing_rules) + "\n")
                    log(deployment.id, f"[平台产物] 已生成并校验 {relative_artifact}。\n")

        # The source repository's Dockerfile/Compose files are references.
        # Only the platform-generated runtime files may enter image packaging.
        if build_type == "compose":
            validate_runtime_only_dockerfiles(work, build_file, compose_override)
            # Role/artifact types are a hard contract, not a best-effort
            # heuristic. A static frontend can only run on Nginx and a Java
            # backend can never be published from Nginx. Stop before registry
            # upload if any late rewrite crosses those identities.
            final_document = yaml.safe_load(
                (Path(work) / build_file).read_text(encoding="utf-8", errors="ignore")
            ) or {}
            final_roles = _traffic_service_roles(
                _project_traffic_plan(
                    project,
                    (project.source_analysis or {}).get("deployment_plan") or {},
                )
            )
            for final_name, final_service in (final_document.get("services") or {}).items():
                if not isinstance(final_service, dict) or not final_service.get("build"):
                    continue
                final_build = final_service["build"]
                final_build = {"context": final_build} if isinstance(final_build, str) else dict(final_build)
                final_context = (Path(work) / str(final_build.get("context") or ".")).resolve()
                final_file = final_context / str(final_build.get("dockerfile") or "Dockerfile")
                if not final_file.is_file():
                    continue
                final_text = final_file.read_text(encoding="utf-8", errors="ignore")
                final_lower = str(final_name).lower()
                final_role = str((final_roles.get(str(final_name)) or ("", False))[0]).lower()
                expects_frontend = final_role in {"frontend", "web", "ui"} or any(
                    token in final_lower for token in ("web", "front", "ui")
                )
                expects_backend = final_role in {"backend", "api", "server"} or any(
                    token in final_lower for token in ("api", "backend", "server")
                )
                uses_nginx = bool(re.search(r"(?im)^\s*FROM\s+[^\n]*nginx", final_text))
                uses_java = bool(re.search(r"(?im)^\s*FROM\s+[^\n]*(?:temurin|openjdk)|ENTRYPOINT\s*\[\s*[\"']java", final_text))
                if expects_frontend and uses_java:
                    raise RuntimeError(f"[平台封装校验] 前端服务 {final_name} 错误引用 Java 产物，已阻止发布")
                if expects_backend and uses_nginx and not uses_java:
                    raise RuntimeError(f"[平台封装校验] 后端服务 {final_name} 错误引用 Nginx 静态产物，已阻止发布")
            log(deployment.id, "[封装校验] 所有服务均为平台生成的纯运行镜像；未发现重复编译命令。\n")
        snapshot_deployment_files(deployment.id, work, build_file)
        log(deployment.id, "[发布文件] 已保存本次最终实际使用的 Dockerfile、Compose、Nginx 与脱敏环境配置快照。\n")

        if build_type == "compose":
            # Service discovery may replace an early AI plan (for example
            # warehouse-web/api) with names proven by the actual repository
            # (wms-ui/api).  The image list created before that rewrite is
            # stale and must never drive registry push/pull distribution.
            # Rebuild it from the final effective Compose artifacts so build,
            # registry, transfer and runtime startup share one identity map.
            final_images: list[str] = []
            image_prefix = f"yunzhou/{project.slug}-"
            for final_compose_name in (build_file, compose_override):
                if not final_compose_name:
                    continue
                final_compose_path = Path(work) / final_compose_name
                if not final_compose_path.is_file():
                    continue
                try:
                    final_document = yaml.safe_load(
                        final_compose_path.read_text(encoding="utf-8", errors="ignore")
                    ) or {}
                except Exception:
                    continue
                for final_service in (final_document.get("services") or {}).values():
                    if not isinstance(final_service, dict):
                        continue
                    final_image = str(final_service.get("image") or "").strip()
                    if final_image.startswith(image_prefix) and final_image.endswith(f":{release}"):
                        final_images.append(final_image)
            final_images = list(dict.fromkeys(final_images))
            if final_images:
                if final_images != images:
                    log(
                        deployment.id,
                        "[镜像映射] 已以最终 Compose 校正构建与分发清单："
                        + "、".join(final_images) + "。\n",
                    )
                images = final_images
            files = f"-f {shlex.quote(build_file)}" + (f" -f {shlex.quote(compose_override)}" if compose_override else "")
            if proxy_compose_override:
                files += f" -f {shlex.quote(proxy_compose_override)}"
            build_owners: list[str] = []
            for compose_name in (build_file, compose_override):
                if not compose_name:
                    continue
                try:
                    compose_document = yaml.safe_load((Path(work) / compose_name).read_text(encoding="utf-8")) or {}
                    for name, service in (compose_document.get("services") or {}).items():
                        if isinstance(service, dict) and service.get("build") and str(name) not in build_owners:
                            build_owners.append(str(name))
                except Exception:
                    continue
            compose_prefix = (
                f"cd {shlex.quote(builder_dir)} && "
                # Use Docker's classic builder.  The generated Dockerfiles are
                # multi-stage: Node/Maven stages compile artifacts and the
                # final runtime image only receives the built files.  This
                # keeps runtime images small without accumulating Buildx
                # history and local-cache directories.
                f"DOCKER_BUILDKIT=0 COMPOSE_DOCKER_CLI_BUILD=0 DOCKER_DEFAULT_PLATFORM={shlex.quote(platform)} "
                f"{build_env_prefix} "
                # Compose otherwise builds every service concurrently inside
                # this single job, bypassing the outer deployment lock.  Some
                # Docker/containerd versions then lose ingest leases while
                # exporting layers.  Keep service image commits serial too.
                f"docker compose --env-file .yunzhou.build.env --parallel 1 -p {shlex.quote('yz-build-' + project.slug)} {files} build"
            )
            build_commands = [
                (service, compose_prefix + " " + shlex.quote(service))
                for service in build_owners
                if service not in eager_packaged_services
            ]
            if not build_owners:
                build_commands = [("应用镜像", compose_prefix)]
        else:
            command = (
                f"cd {shlex.quote(builder_dir)} && DOCKER_BUILDKIT=0 DOCKER_DEFAULT_PLATFORM={shlex.quote(platform)} "
                f"docker build {proxy_build_args} -f {shlex.quote(build_file)} -t {shlex.quote(image_name)} ."
            )
            build_commands = [("应用镜像", command)]
        # Dependency preparation and classic image packaging may run across
        # deployments concurrently. Cleanup is scheduled separately and only
        # runs when the deployment queue is idle.
        for service_index, (service_name, service_command) in enumerate(build_commands, start=1):
            # Dependency compilation remains fully concurrent. Only the final
            # classic-Docker image write is serialized per builder node;
            # concurrent commits against this node's shared containerd store
            # have repeatedly lost ingest/snapshot files.
            lock_path = "/tmp/yunzhou-image-commit.lock"
            lock_probe, _ = build_ssh.run(
                f"flock -n {shlex.quote(lock_path)} true",
                timeout=10,
            )
            if lock_probe:
                log(
                    deployment.id,
                    f"[构建队列] 服务 {service_index}/{len(build_commands)}：{service_name} 的依赖编译已完成；"
                    "同一服务的镜像正在写入，当前仅等待该服务的安全封装时段。\n",
                )
            else:
                log(
                    deployment.id,
                    f"[镜像封装] 服务 {service_index}/{len(build_commands)}：{service_name}，该服务写入通道空闲，立即开始。\n",
                )
            locked_command = (
                f"flock -w 1200 {shlex.quote(lock_path)} sh -lc "
                + shlex.quote(
                    "printf '[镜像封装] 已取得该服务镜像写入时段，开始生成运行镜像。\\n'; "
                    + service_command
                )
            )
            code, output = tracked_run(
                build_ssh, deployment.id, locked_command, stream=stream, timeout=1500,
                pid_prefix=f"yunzhou-build-{service_index}",
            )
            # Docker installations backed by containerd occasionally lose an
            # ingest lease while committing a classic-builder layer. This is
            # an engine storage failure rather than a source failure. Retry
            # only this service, still with the classic builder.
            infrastructure_build_error = any(marker in output.lower() for marker in (
                "lease does not exist",
                "creatediff",
                "failed to commit",
                "failed to export layer",
                "io.containerd.content.v1.content/ingest",
                "failed to export image",
                "failed to unpack image",
                "mount callback failed",
                "failed to write compressed diff",
                "failed to create diff tar stream",
                "failed to get reader from content store",
                "content store: content digest",
                "snapshot ",
                "snapshotter",
                "does not exist: not found",
            ))
            if code and infrastructure_build_error:
                log(
                    deployment.id,
                    f"[平台自愈] {service_name} 发生 Docker 存储异常，仅使用经典构建器重试该服务。\n",
                )
                code, output = tracked_run(
                    build_ssh, deployment.id, locked_command, stream=stream, timeout=1500,
                    pid_prefix=f"yunzhou-build-{service_index}-retry",
                )
            if code:
                if code == 1 and not output.strip():
                    raise RuntimeError(f"{service_name} 等待镜像构建队列超时，平台已释放本次任务，请稍后安全重试。")
                raise RuntimeError(f"{service_name} 镜像构建失败：" + output[-2000:])
            log(deployment.id, f"[平台构建] {service_name} 镜像封装完成，已释放提交锁。\n")
        distribution_label = "本机加载" if builder.id == target.id else "镜像分发"
        log(
            deployment.id,
            f"[构建通道] distribute|{distribution_label}|开始|{datetime.now(timezone.utc).isoformat()}\n",
        )
        registry_pairs: list[tuple[str, str]] = []
        registry_ready = True
        for value in images:
            repository, separator, tag = value.rpartition(":")
            if not separator:
                repository, tag = value, "latest"
            safe_repository = re.sub(r"[^a-z0-9._/-]+", "-", repository.lower()).strip("-/")
            policy = db.get(DeploymentSettings, "default")
            endpoint = (policy.registry_endpoint if policy else "yunzhou.hub:5000").strip().rstrip("/")
            namespace = (policy.registry_namespace if policy else "yunzhou").strip("/")
            repository_tail = safe_repository.split("/", 1)[-1]
            safe_repository = f"{namespace}/{repository_tail}"
            registry_reference = f"{endpoint}/{safe_repository}:{tag}"
            code, registry_output = 1, ""
            for push_attempt in range(1, 4):
                code, registry_output = build_ssh.run(
                    f"docker tag {shlex.quote(value)} {shlex.quote(registry_reference)} && "
                    f"docker push {shlex.quote(registry_reference)}",
                    timeout=1800,
                )
                if code == 0:
                    break
                transient_push_error = any(marker in registry_output.lower() for marker in (
                    " eof", "connection reset", "connection refused", "tls handshake timeout",
                    "i/o timeout", "unexpected status", "service unavailable", "bad gateway",
                ))
                if not transient_push_error or push_attempt >= 3:
                    break
                log(
                    deployment.id,
                    f"[镜像仓库] {safe_repository}:{tag} 第 {push_attempt} 次推送遇到临时网络异常，3 秒后自动重试。\n",
                )
                time.sleep(3)
            if code:
                registry_ready = False
                log(
                    deployment.id,
                    "[镜像仓库] 写入失败，将使用镜像打包传输兜底："
                    + ANSI_RE.sub("", registry_output or "未返回详细错误")[-800:] + "\n",
                )
                break
            if not verify_registry_tag(safe_repository, tag):
                registry_ready = False
                log(
                    deployment.id,
                    f"[镜像仓库] 推送后未能核实 {safe_repository}:{tag}，"
                    "将使用镜像打包传输兜底。\n",
                )
                break
            build_ssh.run(f"docker image rm -f {shlex.quote(registry_reference)} >/dev/null 2>&1 || true", timeout=120)
            log(deployment.id, f"[镜像仓库] 已入库 {safe_repository}:{tag}。\n")
            registry_pairs.append((value, registry_reference))
            removed_tags = cleanup_registry_versions(db, project, safe_repository)
            if removed_tags:
                log(deployment.id, f"[镜像仓库] 已按保留策略清理旧版本：{', '.join(removed_tags)}。\n")
        # Classic Docker's reusable layer cache is represented by untagged
        # intermediate images. Never prune it at the end of each deployment;
        # the worker's age/capacity policy performs bounded cleanup later.
        # Prefer deterministic archive transfer. The registry remains a fully
        # populated fallback/rollback source, but a normal release must not
        # depend on target-side registry credentials or short-name parsing.
        pulled_from_registry = builder.id == target.id
        if builder.id != target.id:
            image_args = " ".join(shlex.quote(value) for value in images)
            local_archive = None
            try:
                log(
                    deployment.id,
                    f"[镜像分发] 默认由构建节点 {builder.name} 打包并传送 "
                    f"{len(images)} 个运行镜像到 {target.name}。\n",
                )
                code, output = build_ssh.run(
                    f"docker save {image_args} | gzip -1 > {shlex.quote(archive)}",
                    timeout=1800,
                )
                if code:
                    raise RuntimeError(ANSI_RE.sub("", output or "镜像打包失败")[-1200:])
                _, archive_size = build_ssh.run(
                    f"du -h {shlex.quote(archive)} 2>/dev/null | awk '{{print $1}}'",
                    timeout=30,
                )
                archive_size = archive_size.strip() or "未知大小"
                with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as handle:
                    local_archive = handle.name
                build_ssh.download_file(archive, local_archive)
                with SSHNode(target) as target_ssh:
                    remote_archive = f"/tmp/yunzhou-images-{deployment.id}.tar.gz"
                    target_ssh.upload_file(local_archive, remote_archive)
                    code, output = target_ssh.run(
                        f"gzip -dc {shlex.quote(remote_archive)} | docker load; "
                        f"rm -f {shlex.quote(remote_archive)}",
                        timeout=1800,
                    )
                    if code:
                        raise RuntimeError(ANSI_RE.sub("", output or "镜像导入失败")[-1200:])
                    inspect_args = " ".join(shlex.quote(value) for value in images)
                    code, output = target_ssh.run(
                        "for image in " + inspect_args + "; do docker image inspect \"$image\" >/dev/null || exit 41; done",
                        timeout=120,
                    )
                    if code:
                        raise RuntimeError(ANSI_RE.sub("", output or "导入后校验失败")[-800:])
                pulled_from_registry = True
                log(
                    deployment.id,
                    f"[镜像分发] 打包传输完成（{archive_size}），目标节点已导入并校验全部镜像。\n",
                )
            except Exception as direct_exc:
                log(
                    deployment.id,
                    "[镜像分发] 打包传输未完成，自动改用平台镜像仓库备用通道："
                    + str(direct_exc)[-1000:] + "\n",
                )
            finally:
                if local_archive:
                    Path(local_archive).unlink(missing_ok=True)
                build_ssh.run(f"rm -f -- {shlex.quote(archive)}", timeout=120)
        if (
            builder.id != target.id
            and not pulled_from_registry
            and registry_ready
            and len(registry_pairs) == len(images)
        ):
            log(
                deployment.id,
                f"[镜像分发] 备用通道：由部署节点 {target.name} 从平台仓库拉取 "
                f"{len(registry_pairs)} 个运行镜像。\n",
            )
            pull_errors = []
            with SSHNode(target) as target_ssh:
                for local_reference, registry_reference in registry_pairs:
                    pull_code, pull_output = target_ssh.run(
                        f"docker pull {shlex.quote(registry_reference)} && "
                        f"docker tag {shlex.quote(registry_reference)} {shlex.quote(local_reference)} && "
                        f"docker image inspect {shlex.quote(local_reference)} >/dev/null",
                        timeout=1800,
                    )
                    if pull_code:
                        pull_errors.append(
                            f"{registry_reference}: {ANSI_RE.sub('', pull_output or '拉取校验失败')[-500:]}"
                        )
                        break
                if not pull_errors:
                    pulled_from_registry = True
                    cleanup_refs = " ".join(shlex.quote(reference) for _, reference in registry_pairs)
                    target_ssh.run(f"docker image rm {cleanup_refs} >/dev/null 2>&1 || true", timeout=120)
                    log(
                        deployment.id,
                        "[镜像分发] 目标节点已从平台仓库拉取并校验全部镜像，无需打包上传。\n",
                    )
                else:
                    log(
                        deployment.id,
                        "[镜像分发] 仓库拉取未通过，自动回退为打包传输："
                        + "；".join(pull_errors) + "\n",
                    )
        if builder.id != target.id and not pulled_from_registry:
            image_args = " ".join(shlex.quote(value) for value in images)
            log(
                deployment.id,
                f"[镜像分发] 构建节点 {builder.name} 与部署节点 {target.name} 不同，"
                "正在打包运行镜像；大镜像在此步骤可能需要数分钟。\n",
            )
            code, output = build_ssh.run(f"docker save {image_args} | gzip -1 > {shlex.quote(archive)}", timeout=1800)
            if code:
                raise RuntimeError("平台镜像打包失败：" + output[-1200:])
            _, archive_size = build_ssh.run(
                f"du -h {shlex.quote(archive)} 2>/dev/null | awk '{{print $1}}'",
                timeout=30,
            )
            archive_size = archive_size.strip() or "未知大小"
            log(deployment.id, f"[镜像分发] 打包完成（{archive_size}），正在下载到平台中转区。\n")
            with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as handle:
                local_archive = handle.name
            try:
                build_ssh.download_file(archive, local_archive)
                local_size_mb = max(1, round(Path(local_archive).stat().st_size / 1024 / 1024))
                log(
                    deployment.id,
                    f"[镜像分发] 已下载 {local_size_mb} MiB，正在上传到部署节点 {target.name}。\n",
                )
                with SSHNode(target) as target_ssh:
                    remote_archive = f"/tmp/yunzhou-images-{deployment.id}.tar.gz"
                    target_ssh.upload_file(local_archive, remote_archive)
                    log(deployment.id, "[镜像分发] 上传完成，正在导入目标节点 Docker 镜像库。\n")
                    code, output = target_ssh.run(f"gzip -dc {shlex.quote(remote_archive)} | docker load; rm -f {shlex.quote(remote_archive)}", timeout=1800)
                    if code:
                        raise RuntimeError("目标服务器导入平台镜像失败：" + output[-1200:])
                    log(deployment.id, f"[镜像分发] 镜像已导入部署节点 {target.name}，即将启动应用。\n")
            finally:
                Path(local_archive).unlink(missing_ok=True)
                # ``builder_dir`` is the live worker checkout on installations
                # where the worker and build node share /data/yunzhou.  Removing
                # it here deletes Compose/runtime files before the start stage.
                # The execute() finally block owns workspace cleanup; image
                # distribution only owns its temporary archive.
                build_ssh.run(f"rm -f -- {shlex.quote(archive)}")
        elif builder.id != target.id:
            build_ssh.run(f"rm -f -- {shlex.quote(archive)}")
        else:
            # Shared checkout; retained until execute() finishes.
            pass
        log(
            deployment.id,
            f"[构建通道] distribute|{distribution_label}|完成|{datetime.now(timezone.utc).isoformat()}\n",
        )
    return builder

