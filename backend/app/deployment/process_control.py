"""Remote process-group cancellation for interruptible deployment tasks."""

import re


def stop_tracked_process_groups(ssh, deployment_id: str) -> str:
    """Stop and verify every tracked subprocess belonging to one deployment."""
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", deployment_id or ""):
        raise RuntimeError("部署任务编号不安全，拒绝终止远端进程")
    pattern = f"/tmp/yunzhou-*-{deployment_id}.pid"
    script = (
        "groups=''; files=0; "
        f"for f in {pattern}; do "
        "[ -f \"$f\" ] || continue; files=$((files+1)); "
        "p=$(cat \"$f\" 2>/dev/null | tr -cd '0-9'); "
        "[ -z \"$p\" ] || { groups=\"$groups $p\"; kill -TERM -- -$p 2>/dev/null || true; }; "
        "done; "
        "[ -z \"$groups\" ] || sleep 2; "
        "for p in $groups; do kill -0 -- -$p 2>/dev/null && kill -KILL -- -$p 2>/dev/null || true; done; "
        "sleep 1; residual=''; "
        "for p in $groups; do kill -0 -- -$p 2>/dev/null && residual=\"$residual $p\" || true; done; "
        f"rm -f -- {pattern}; "
        "printf 'pid_files=%s groups=%s residual=%s' \"$files\" \"$groups\" \"$residual\"; "
        "[ -z \"$residual\" ]"
    )
    code, output = ssh.run(script, timeout=20)
    if code:
        raise RuntimeError("停止后仍有构建进程运行：" + output.strip())
    return output.strip()
