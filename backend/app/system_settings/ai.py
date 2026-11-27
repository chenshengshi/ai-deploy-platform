"""AI provider configuration and connectivity validation routes."""

from __future__ import annotations

import socket
import struct
import time
import uuid
from urllib.parse import urlsplit

import httpx
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..audit import audit
from ..auth import current_user, require
from ..config import decrypt, encrypt
from ..database import get_db
from ..models import AiConfig, Role, User
from ..proxy import proxy_for, redact_proxy
from ..schemas import AiConfigIn, AiConfigOut

router = APIRouter()

@router.get("/api/settings/ai", response_model=AiConfigOut | None)
def get_ai(db: Session = Depends(get_db), _: User = Depends(require(Role.admin))):
    item = db.scalar(select(AiConfig).order_by(AiConfig.is_default.desc(), AiConfig.provider_name))
    if not item:
        return None
    return ai_config_out(item)


def ai_config_out(item: AiConfig) -> AiConfigOut:
    return AiConfigOut(id=item.id, provider_name=item.provider_name, base_url=item.base_url, model=item.model, enabled=item.enabled, is_default=item.is_default, has_api_key=bool(item.api_key_encrypted))


@router.get("/api/settings/ai/configs", response_model=list[AiConfigOut])
def list_ai_configs(db: Session = Depends(get_db), _: User = Depends(current_user)):
    return [ai_config_out(x) for x in db.query(AiConfig).order_by(AiConfig.is_default.desc(), AiConfig.provider_name).all()]


@router.post("/api/settings/ai/configs", response_model=AiConfigOut)
def create_ai_config(body: AiConfigIn, db: Session = Depends(get_db), user: User = Depends(require(Role.admin))):
    if not body.api_key:
        raise HTTPException(400, "新配置必须填写 API Key")
    has_default = db.scalar(select(AiConfig.id).where(AiConfig.enabled.is_(True), AiConfig.is_default.is_(True)))
    item = AiConfig(provider_name=body.provider_name, base_url=body.base_url, model=body.model, enabled=body.enabled, is_default=bool(body.enabled and not has_default), api_key_encrypted=encrypt(body.api_key))
    db.add(item)
    db.flush()
    audit(db, user, "create_ai_config", "ai_config", item.id, item.provider_name)
    db.commit()
    db.refresh(item)
    return ai_config_out(item)


@router.patch("/api/settings/ai/configs/{item_id}", response_model=AiConfigOut)
def update_ai_config(item_id: str, body: AiConfigIn, db: Session = Depends(get_db), user: User = Depends(require(Role.admin))):
    item = db.get(AiConfig, item_id)
    if not item:
        raise HTTPException(404, "AI 配置不存在")
    item.provider_name, item.base_url, item.model, item.enabled = body.provider_name, body.base_url, body.model, body.enabled
    if item.is_default and not item.enabled:
        replacement = db.scalar(select(AiConfig).where(AiConfig.id != item.id, AiConfig.enabled.is_(True)).order_by(AiConfig.provider_name))
        if not replacement:
            raise HTTPException(400, "默认模型不能停用；请先启用另一个模型并设为默认")
        item.is_default = False
        replacement.is_default = True
    if body.api_key:
        item.api_key_encrypted = encrypt(body.api_key)
    audit(db, user, "update_ai_config", "ai_config", item.id, item.provider_name)
    db.commit()
    db.refresh(item)
    return ai_config_out(item)


@router.delete("/api/settings/ai/configs/{item_id}")
def delete_ai_config(item_id: str, db: Session = Depends(get_db), user: User = Depends(require(Role.admin))):
    item = db.get(AiConfig, item_id)
    if not item:
        raise HTTPException(404, "AI 配置不存在")
    if item.is_default:
        raise HTTPException(400, "默认模型不能删除，请先将其他模型设为默认")
    db.delete(item)
    audit(db, user, "delete_ai_config", "ai_config", item_id, item.provider_name)
    db.commit()
    return {"ok": True}


@router.post("/api/settings/ai/configs/{item_id}/default", response_model=AiConfigOut)
def set_default_ai_config(item_id: str, db: Session = Depends(get_db), user: User = Depends(require(Role.admin))):
    item = db.get(AiConfig, item_id)
    if not item:
        raise HTTPException(404, "AI 配置不存在")
    if not item.enabled:
        raise HTTPException(400, "请先启用该模型，再设为默认")
    db.query(AiConfig).update({AiConfig.is_default: False}, synchronize_session=False)
    item.is_default = True
    audit(db, user, "set_default_ai_config", "ai_config", item.id, f"{item.provider_name} · {item.model}")
    db.commit()
    db.refresh(item)
    return ai_config_out(item)


@router.put("/api/settings/ai", response_model=AiConfigOut)
def set_ai(body: AiConfigIn, db: Session = Depends(get_db), user: User = Depends(require(Role.admin))):
    item = db.query(AiConfig).first() or AiConfig()
    item.provider_name, item.base_url, item.model, item.enabled = body.provider_name, body.base_url, body.model, body.enabled
    if body.api_key:
        item.api_key_encrypted = encrypt(body.api_key)
    db.add(item)
    audit(db, user, "update_ai", "ai_config", item.id)
    db.commit()
    db.refresh(item)
    return ai_config_out(item)


@router.post("/api/settings/ai/test")
def test_ai(body: AiConfigIn, config_id: str | None = None, db: Session = Depends(get_db), _: User = Depends(require(Role.admin))):
    current = db.get(AiConfig, config_id) if config_id else db.query(AiConfig).first()
    api_key = body.api_key or (decrypt(current.api_key_encrypted) if current else None)
    if not api_key:
        raise HTTPException(400, "请先填写 API Key")
    try:
        url = body.base_url.rstrip("/") + "/chat/completions"
        selected_proxy = proxy_for(db, url)
        safe_proxy = redact_proxy(selected_proxy)
        trace_code = "NET-" + uuid.uuid4().hex[:12].upper()
        target = urlsplit(url)
        target_host, target_port = target.hostname or "", target.port or (443 if target.scheme == "https" else 80)
        dns_ips = sorted({item[4][0] for item in socket.getaddrinfo(target_host, target_port, type=socket.SOCK_STREAM)})
        connect_url = urlsplit(selected_proxy) if selected_proxy else target
        connect_host = connect_url.hostname or target_host
        connect_port = connect_url.port or (443 if connect_url.scheme == "https" else 80)
        route_socket = socket.create_connection((connect_host, connect_port), timeout=8)
        local_ip = route_socket.getsockname()[0]
        peer_ip = route_socket.getpeername()[0]
        route_socket.close()
        gateway = None
        try:
            with open("/proc/net/route", encoding="utf-8") as routes:
                for line in routes.readlines()[1:]:
                    fields = line.split()
                    if len(fields) > 2 and fields[1] == "00000000":
                        gateway = socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))
                        break
        except OSError:
            pass
        started = time.perf_counter()
        with httpx.Client(proxy=selected_proxy, trust_env=False, timeout=60) as client:
            response = None
            for attempt in range(3):
                response = client.post(
                    url,
                    headers={"Authorization": "Bearer " + api_key},
                    json={
                        "model": body.model,
                        "messages": [{"role": "user", "content": "只回复：连接正常"}],
                        "max_tokens": 30,
                    },
                )
                if response.status_code not in (502, 503, 504):
                    break
                if attempt < 2:
                    time.sleep(attempt + 1)
        latency_ms = round((time.perf_counter() - started) * 1000)
        if response.status_code in (502, 503, 504):
            raise HTTPException(502, f"AI 服务上游暂时不可用（HTTP {response.status_code}），平台已自动重试 3 次，请稍后再试")
        if response.status_code in (401, 403):
            raise HTTPException(502, "AI 接口拒绝认证，请检查 API Key 是否有效")
        if response.status_code == 404:
            raise HTTPException(502, "AI 接口地址或模型名称不存在，请检查接口地址和模型名称")
        if response.status_code == 429:
            raise HTTPException(502, "AI 服务当前请求过多或额度不足，请稍后再试或检查账户额度")
        if response.status_code == 400:
            try:
                provider_message = response.json().get("error", {}).get("message", "")
            except (ValueError, AttributeError):
                provider_message = ""
            detail = f"：{provider_message}" if provider_message else ""
            raise HTTPException(502, f"AI 接口不接受当前请求参数{detail}")
        response.raise_for_status()
        data = response.json()
        return {
            "ok": True,
            "model": data.get("model", body.model),
            "reply": data["choices"][0]["message"]["content"],
            "network_route": "proxy" if selected_proxy else "direct",
            "network_detail": safe_proxy or "服务器直连",
            "trace_code": trace_code,
            "target_host": target_host,
            "target_port": target_port,
            "dns_ips": dns_ips,
            "local_ip": local_ip,
            "gateway": gateway,
            "peer_ip": peer_ip,
            "latency_ms": latency_ms,
            "route_steps": [
                f"云舟 API ({local_ip})",
                *(([f"默认网关 ({gateway})"] if gateway else [])),
                *(([f"应用代理 ({safe_proxy})"] if selected_proxy else ["服务器直连"])),
                f"{target_host} ({', '.join(dns_ips)}):{target_port}",
            ],
        }
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(502, f"连接测试失败：{exc}") from exc

