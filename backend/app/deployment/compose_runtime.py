"""Compose file discovery shared by start, stop, rollback and cleanup flows."""

import shlex

from ..deployment_architecture import COMPOSE_NAMES


def remote_compose_files(ssh, directory: str) -> list[str]:
    """Return only the release-owned application Compose files.

    Managed MySQL/Redis run in a stable data stack. Lifecycle operations must
    therefore prefer ``.yunzhou.app.yml`` so switching an application version
    never stops or recreates its persistent data services.
    """
    app_file = ".yunzhou.app.yml"
    if ssh.run(f"test -f {shlex.quote(directory + '/' + app_file)}")[0] == 0:
        files = [app_file]
        for override in (".yunzhou.app-images.yml", ".yunzhou.external-access.yml"):
            if ssh.run(f"test -f {shlex.quote(directory + '/' + override)}")[0] == 0:
                files.append(override)
        return files

    main = next(
        (
            name
            for name in COMPOSE_NAMES
            if ssh.run(f"test -f {shlex.quote(directory + '/' + name)}")[0] == 0
        ),
        None,
    )
    if not main:
        return []
    files = [main]
    for override in (".yunzhou.images.yml", ".yunzhou.external-access.yml"):
        if ssh.run(f"test -f {shlex.quote(directory + '/' + override)}")[0] == 0:
            files.append(override)
    return files


def compose_file_args(files: list[str]) -> str:
    """Build shell-safe Compose ``-f`` arguments."""
    return " ".join(f"-f {shlex.quote(name)}" for name in files)
