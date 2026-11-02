import io
import json
import os
import posixpath
import shlex
import socket
import tarfile
import tempfile
import time
from pathlib import Path

import paramiko

from .config import decrypt
from .models import AuthType, Node


class SSHNode:
    def __init__(self, node: Node, connect_timeout: int = 15):
        self.node = node
        self.connect_timeout = connect_timeout
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    def __enter__(self):
        kwargs = dict(
            hostname=self.node.host,
            port=self.node.port,
            username=self.node.username,
            timeout=self.connect_timeout,
            banner_timeout=self.connect_timeout,
            auth_timeout=self.connect_timeout,
        )
        secret = decrypt(self.node.secret_encrypted)
        if self.node.auth_type == AuthType.password:
            kwargs["password"] = secret
        else:
            if not secret:
                raise RuntimeError("节点未配置 SSH 私钥")
            kwargs["pkey"] = paramiko.RSAKey.from_private_key(io.StringIO(secret))
        self.client.connect(**kwargs)
        return self

    def __exit__(self, *_):
        self.client.close()

    def run(self, command: str, timeout: int = 1800, stream=None) -> tuple[int, str]:
        _, stdout, stderr = self.client.exec_command(command, timeout=timeout, get_pty=True)
        if stream is None:
            # Short commands can finish before the polling loop observes their
            # buffered output. Blocking reads reliably drain both streams.
            output = stdout.read().decode(errors="replace")
            error = stderr.read().decode(errors="replace")
            return stdout.channel.recv_exit_status(), output + error
        parts: list[str] = []
        while True:
            if stdout.channel.recv_ready():
                chunk = stdout.channel.recv(4096).decode(errors="replace")
                parts.append(chunk)
                stream(chunk)
            if stdout.channel.recv_stderr_ready():
                chunk = stdout.channel.recv_stderr(4096).decode(errors="replace")
                parts.append(chunk)
                stream(chunk)
            if stdout.channel.exit_status_ready() and not stdout.channel.recv_ready() and not stdout.channel.recv_stderr_ready():
                break
            time.sleep(0.02)
        tail = stdout.read().decode(errors="replace")
        if tail:
            parts.append(tail)
            stream(tail)
        err = stderr.read().decode(errors="replace")
        if err:
            parts.append(err)
            stream(err)
        return stdout.channel.recv_exit_status(), "".join(parts)

    def upload_tree(self, source: str, target: str) -> None:
        src = Path(source)
        if not src.exists():
            raise RuntimeError("上传源码不存在")
        with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as tmp:
            tmp_name = tmp.name
        try:
            with tarfile.open(tmp_name, "w:gz") as tar:
                for path in src.rglob("*"):
                    if ".git" in path.parts or "node_modules" in path.parts:
                        continue
                    tar.add(path, arcname=path.relative_to(src))
            remote_tar = f"/tmp/yunzhou-{os.getpid()}.tar.gz"
            sftp = self.client.open_sftp()
            sftp.put(tmp_name, remote_tar)
            sftp.close()
            cmd = f"mkdir -p {shlex.quote(target)} && tar -xzf {shlex.quote(remote_tar)} -C {shlex.quote(target)} && rm -f {shlex.quote(remote_tar)}"
            code, out = self.run(cmd)
            if code:
                raise RuntimeError(out)
        finally:
            Path(tmp_name).unlink(missing_ok=True)

    def upload_file(self, source: str, target: str) -> None:
        sftp = self.client.open_sftp()
        try:
            sftp.put(source, target)
        finally:
            sftp.close()

    def download_file(self, source: str, target: str) -> None:
        sftp = self.client.open_sftp()
        try:
            sftp.get(source, target)
        finally:
            sftp.close()


def test_node(node: Node) -> dict:
    started = socket.gethostbyname(node.host)
    with SSHNode(node) as ssh:
        code, out = ssh.run("docker --version && docker compose version && uname -srm", timeout=30)
        if code:
            raise RuntimeError(out)
    return {"resolved_ip": started, "detail": out.strip()}


def ensure_node_runtime(node: Node, registry_ip: str | None = None) -> dict:
    """Install the managed Docker runtime when missing and apply a conservative default mirror config."""
    mirrors = ["https://docker.m.daocloud.io", "https://hub-mirror.c.163.com"]
    registry_name = "yunzhou.hub:5000"
    with SSHNode(node) as ssh:
        privilege = "" if node.username == "root" else "sudo -n "
        code, release = ssh.run(". /etc/os-release 2>/dev/null; printf '%s|%s' \"${ID:-unknown}\" \"${VERSION_ID:-0}\"")
        if "centos|6" in release.lower() or "rhel|6" in release.lower():
            raise RuntimeError("该服务器为 CentOS/RHEL 6，现代 Docker 不支持；请升级到 CentOS 7 或更新系统")
        code, kernel = ssh.run("uname -r; uname -m; command -v systemctl")
        if code or "systemctl" not in kernel or not any(arch in kernel for arch in ("x86_64", "aarch64")):
            raise RuntimeError("服务器需要 64 位 Linux、systemd 和可运行现代 Docker 的内核")
        code, _ = ssh.run("command -v docker >/dev/null 2>&1")
        installed = code != 0
        if installed:
            kylin_install = (
                f"{privilege}sh -c 'if command -v apt-get >/dev/null; then apt-get update && "
                "(apt-get install -y docker.io docker-compose-plugin || apt-get install -y docker.io docker-compose); "
                "elif command -v yum >/dev/null; then yum install -y docker docker-compose-plugin; else exit 45; fi'"
            )
            standard_install = (
                "command -v curl >/dev/null 2>&1 || "
                f"{privilege}sh -c 'command -v apt-get >/dev/null && apt-get update && apt-get install -y curl ca-certificates || "
                "command -v yum >/dev/null && yum install -y curl ca-certificates'; "
                f"curl -fsSL https://get.docker.com | {privilege}sh"
            )
            install = kylin_install if "kylin|" in release.lower() or "uos|" in release.lower() else standard_install
            code, output = ssh.run(install, timeout=600)
            if code:
                raise RuntimeError("Docker 自动安装失败：" + output[-2000:])
        # Merge locally through SFTP so minimal target systems do not need
        # Python, jq or another JSON editor installed.
        daemon_config = {}
        sftp = ssh.client.open_sftp()
        try:
            try:
                with sftp.open("/etc/docker/daemon.json", "r") as handle:
                    daemon_config = json.loads(handle.read().decode() or "{}")
            except FileNotFoundError:
                daemon_config = {}
            daemon_config.setdefault("registry-mirrors", mirrors)
            insecure = daemon_config.setdefault("insecure-registries", [])
            if registry_name not in insecure:
                insecure.append(registry_name)
            with sftp.open("/tmp/yunzhou-daemon.json", "w") as handle:
                handle.write(json.dumps(daemon_config, ensure_ascii=False, indent=2) + "\n")
            sftp.chmod("/tmp/yunzhou-daemon.json", 0o600)
        finally:
            sftp.close()
        hosts = (
            f"{privilege}sed -i '/[[:space:]]yunzhou\\.hub$/d' /etc/hosts; "
            f"printf '%s\\n' {shlex.quote(registry_ip + ' yunzhou.hub')} | {privilege}tee -a /etc/hosts >/dev/null; "
        ) if registry_ip else ""
        configure = (
            hosts +
            f"{privilege}install -m 0644 /tmp/yunzhou-daemon.json /etc/docker/daemon.json; rm -f /tmp/yunzhou-daemon.json; "
            f"{privilege}systemctl enable docker; {privilege}systemctl restart docker; "
            f"docker --version; docker compose version; getent hosts yunzhou.hub; "
            f"docker info --format '{{{{json .RegistryConfig.IndexConfigs}}}}' | grep -F {shlex.quote(registry_name)}"
        )
        code, output = ssh.run(configure, timeout=180)
        if code:
            raise RuntimeError("Docker 环境配置失败：" + output[-2000:])
    return {"installed": installed, "mirrors": mirrors, "registry": registry_name, "detail": output.strip()}

