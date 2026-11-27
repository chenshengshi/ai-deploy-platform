from pathlib import Path


SOURCE_REPLACEMENTS = {
    "registry.npmjs.org": "registry.npmmirror.com",
    "https://pypi.org/simple": "https://pypi.tuna.tsinghua.edu.cn/simple",
    "https://repo.maven.apache.org/maven2": "https://maven.aliyun.com/repository/public",
    "http://deb.debian.org": "https://mirrors.tuna.tsinghua.edu.cn",
    "http://archive.ubuntu.com": "https://mirrors.tuna.tsinghua.edu.cn",
    "http://security.ubuntu.com": "https://mirrors.tuna.tsinghua.edu.cn",
}


def optimize_staged_sources(path: str) -> list[str]:
    """Rewrite only the isolated release copy to use reachable package mirrors."""
    root = Path(path)
    changed: list[str] = []
    for candidate in root.rglob("Dockerfile*"):
        if not candidate.is_file() or any(part in {".git", "node_modules", "target"} for part in candidate.parts):
            continue
        original = candidate.read_text(errors="ignore")
        optimized = original
        for old, new in SOURCE_REPLACEMENTS.items():
            optimized = optimized.replace(old, new)
        if "RUN apt-get update" in optimized and "mirrors.tuna.tsinghua.edu.cn|g" not in optimized:
            optimized = optimized.replace(
                "RUN apt-get update",
                "RUN sed -i 's|deb.debian.org|mirrors.tuna.tsinghua.edu.cn|g; "
                "s|security.debian.org|mirrors.tuna.tsinghua.edu.cn|g; "
                "s|archive.ubuntu.com|mirrors.tuna.tsinghua.edu.cn|g; "
                "s|security.ubuntu.com|mirrors.tuna.tsinghua.edu.cn|g' "
                "/etc/apt/sources.list /etc/apt/sources.list.d/debian.sources 2>/dev/null || true; apt-get update",
            )
        if optimized != original:
            candidate.write_text(optimized)
            changed.append(candidate.relative_to(root).as_posix())
    return changed
"""Deployment package component."""

