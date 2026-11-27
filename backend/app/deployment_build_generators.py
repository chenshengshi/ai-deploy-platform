from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Protocol

from .deployment_build_profiles import BuildProfile, compatible_node_image


@dataclass(frozen=True)
class GeneratedBuild:
    dockerfile: str
    port: int
    supporting_files: dict[str, str] | None = None


class BuildGenerator(Protocol):
    profile_key: str

    def generate(self, root: Path, *, nginx_image: str, java_version: Callable[[str], int]) -> GeneratedBuild | None: ...


class NodeBuildGenerator:
    profile_key = "node"

    def generate(self, root: Path, *, nginx_image: str, java_version: Callable[[str], int]) -> GeneratedBuild | None:
        package = root / "package.json"
        if not package.exists():
            return None
        try:
            meta = json.loads(package.read_text(errors="ignore"))
        except Exception:
            meta = {}
        dependencies = {**meta.get("dependencies", {}), **meta.get("devDependencies", {})}
        scripts = meta.get("scripts", {})
        node_image = compatible_node_image(root, "node:22-alpine")
        if "vite" in dependencies or "build" in scripts:
            return GeneratedBuild(
                f"FROM {node_image} AS build\nWORKDIR /app\nCOPY package*.json ./\n"
                "RUN npm config set registry https://registry.npmmirror.com && npm install\nCOPY . .\nRUN npm run build\n"
                f"FROM {nginx_image}\nCOPY --from=build /app/dist /usr/share/nginx/html\nEXPOSE 80\n",
                80,
            )
        return GeneratedBuild(
            f"FROM {node_image}\nWORKDIR /app\nCOPY package*.json ./\n"
            "RUN npm config set registry https://registry.npmmirror.com && npm install --omit=dev\n"
            "COPY . .\nENV NODE_ENV=production\nEXPOSE 3000\nCMD [\"npm\",\"start\"]\n",
            3000,
        )


class MavenBuildGenerator:
    profile_key = "java_maven"

    def generate(self, root: Path, *, nginx_image: str, java_version: Callable[[str], int]) -> GeneratedBuild | None:
        if not (root / "pom.xml").exists():
            return None
        version = java_version(str(root))
        settings = '<settings xmlns="http://maven.apache.org/SETTINGS/1.0.0"><mirrors><mirror><id>aliyun</id><mirrorOf>*</mirrorOf><name>Aliyun Maven</name><url>https://maven.aliyun.com/repository/public</url></mirror></mirrors></settings>'
        return GeneratedBuild(
            f"FROM maven:3.9-eclipse-temurin-{version} AS build\nWORKDIR /app\nCOPY .yunzhou.maven-settings.xml /tmp/settings.xml\nCOPY . .\nRUN mvn -s /tmp/settings.xml -DskipTests package\n"
            "RUN jar=\"$(find /app -path '*/target/*.jar' ! -name '*-sources.jar' ! -name '*-javadoc.jar' ! -name 'original-*.jar' -type f -printf '%s %p\\n' | sort -nr | head -n1 | cut -d' ' -f2-)\" && test -n \"$jar\" && cp \"$jar\" /tmp/app.jar\n"
            f"FROM eclipse-temurin:{version}-jre\nWORKDIR /app\nCOPY --from=build /tmp/app.jar app.jar\n"
            "EXPOSE 8080\nCMD [\"java\",\"-jar\",\"app.jar\"]\n",
            8080,
            {".yunzhou.maven-settings.xml": settings},
        )


class GradleBuildGenerator:
    profile_key = "java_gradle"

    def generate(self, root: Path, *, nginx_image: str, java_version: Callable[[str], int]) -> GeneratedBuild | None:
        build_file = "build.gradle.kts" if (root / "build.gradle.kts").exists() else "build.gradle"
        if not (root / build_file).exists():
            return None
        version = java_version(str(root))
        wrapper = "./gradlew" if (root / "gradlew").exists() else "gradle"
        prepare = "RUN chmod +x gradlew\n" if wrapper == "./gradlew" else ""
        return GeneratedBuild(
            f"FROM gradle:8-jdk{version} AS build\nWORKDIR /app\nCOPY . .\n{prepare}"
            f"RUN {wrapper} clean build -x test --no-daemon\n"
            "RUN jar=\"$(find /app -path '*/build/libs/*.jar' ! -name '*-plain.jar' ! -name '*-sources.jar' -type f | head -n1)\" && test -n \"$jar\" && cp \"$jar\" /tmp/app.jar\n"
            f"FROM eclipse-temurin:{version}-jre\nWORKDIR /app\nCOPY --from=build /tmp/app.jar app.jar\n"
            "EXPOSE 8080\nCMD [\"java\",\"-jar\",\"app.jar\"]\n",
            8080,
        )


class PythonBuildGenerator:
    profile_key = "python"

    def generate(self, root: Path, *, nginx_image: str, java_version: Callable[[str], int]) -> GeneratedBuild | None:
        if not ((root / "requirements.txt").exists() or (root / "pyproject.toml").exists()):
            return None
        candidates = list(root.rglob("*.py"))
        app_file = next((path for path in candidates if "FastAPI(" in path.read_text(errors="ignore")), None)
        module = app_file.relative_to(root).with_suffix("").as_posix().replace("/", ".") if app_file else "app"
        install = "pip install -i https://pypi.tuna.tsinghua.edu.cn/simple -r requirements.txt" if (root / "requirements.txt").exists() else "pip install -i https://pypi.tuna.tsinghua.edu.cn/simple ."
        command = f"uvicorn {module}:app --host 0.0.0.0 --port 8000" if app_file else "python app.py"
        return GeneratedBuild(
            f"FROM python:3.12-slim\nWORKDIR /app\nCOPY . .\nRUN {install}\nEXPOSE 8000\nCMD [\"sh\",\"-c\",\"{command}\"]\n",
            8000,
        )


class GoBuildGenerator:
    profile_key = "go"

    def generate(self, root: Path, *, nginx_image: str, java_version: Callable[[str], int]) -> GeneratedBuild | None:
        if not (root / "go.mod").exists():
            return None
        return GeneratedBuild(
            "FROM golang:1.24-alpine AS build\nWORKDIR /src\nCOPY go.mod go.sum* ./\n"
            "RUN go env -w GOPROXY=https://goproxy.cn,direct && go mod download\nCOPY . .\n"
            "RUN CGO_ENABLED=0 GOOS=linux go build -o /tmp/app .\n"
            "FROM alpine:3.21\nRUN apk add --no-cache ca-certificates tzdata\nWORKDIR /app\n"
            "COPY --from=build /tmp/app ./app\nEXPOSE 8080\nCMD [\"./app\"]\n",
            8080,
        )


class DotnetBuildGenerator:
    profile_key = "dotnet"

    def generate(self, root: Path, *, nginx_image: str, java_version: Callable[[str], int]) -> GeneratedBuild | None:
        project = next(root.glob("*.csproj"), None) or next(root.rglob("*.csproj"), None)
        if project is None:
            return None
        relative = project.relative_to(root).as_posix()
        return GeneratedBuild(
            "FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build\nWORKDIR /src\nCOPY . .\n"
            f"RUN dotnet restore {relative} && dotnet publish {relative} -c Release -o /tmp/out --no-restore\n"
            "FROM mcr.microsoft.com/dotnet/aspnet:8.0\nWORKDIR /app\nCOPY --from=build /tmp/out .\n"
            "ENV ASPNETCORE_URLS=http://+:8080\nEXPOSE 8080\n"
            "CMD [\"sh\",\"-c\",\"dotnet $(find . -maxdepth 1 -name '*.dll' ! -name '*.Views.dll' | head -n1)\"]\n",
            8080,
        )


GENERATORS: tuple[BuildGenerator, ...] = (
    NodeBuildGenerator(),
    MavenBuildGenerator(),
    GradleBuildGenerator(),
    PythonBuildGenerator(),
    GoBuildGenerator(),
    DotnetBuildGenerator(),
)


def generate_profile_build(root: Path, profiles: dict[str, BuildProfile], *, nginx_image: str, java_version: Callable[[str], int]) -> GeneratedBuild | None:
    for generator in GENERATORS:
        if generator.profile_key not in profiles:
            continue
        result = generator.generate(root, nginx_image=nginx_image, java_version=java_version)
        if result is not None:
            return result
    return None


def generate_static_build(root: Path, *, nginx_image: str) -> GeneratedBuild | None:
    static_index = next(
        (
            item for item in root.rglob("index.html")
            if item.is_file()
            and not any(part in {".git", "node_modules", "target", "dist", "build"} for part in item.relative_to(root).parts)
        ),
        None,
    )
    if not static_index:
        return None
    static_dir = static_index.parent.relative_to(root).as_posix()
    copy_source = "." if static_dir == "." else static_dir + "/"
    return GeneratedBuild(
        f"FROM {nginx_image}\nCOPY {copy_source} /usr/share/nginx/html\nEXPOSE 80\n",
        80,
    )
