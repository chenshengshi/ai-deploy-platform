"""Shared TLS certificate validation, storage and matching."""

import json
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID
from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import encrypt
from .models import CertificateStore, Project, ProjectDomainConfig

def _certificate_metadata(certificate_pem: str) -> tuple[x509.Certificate, list[str], str]:
    cert = x509.load_pem_x509_certificate(certificate_pem.encode())
    try:
        domains = list(cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        domains = [value.value for value in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)]
    return cert, list(dict.fromkeys(value.lower() for value in domains if value)), cert.fingerprint(hashes.SHA256()).hex()


def _domain_matches_pattern(domain: str, pattern: str) -> bool:
    domain, pattern = domain.lower(), pattern.lower()
    return domain == pattern or (pattern.startswith("*.") and domain.endswith(pattern[1:]) and domain.count(".") == pattern.count("."))


def _certificate_view(item: CertificateStore, db: Session | None = None, auto_selected: bool = False) -> dict:
    domains = json.loads(item.domains_json or "[]")
    referenced_projects = []
    if db is not None:
        configs = db.scalars(select(ProjectDomainConfig).where(ProjectDomainConfig.certificate_id == item.id)).all()
        project_ids = [config.project_id for config in configs]
        projects = db.scalars(select(Project).where(Project.id.in_(project_ids)).order_by(Project.name)).all() if project_ids else []
        referenced_projects = [{"id": project.id, "name": project.name, "slug": project.slug, "domain": project.domain or "未配置域名"} for project in projects]
    references = len(referenced_projects)
    days_left = max(0, int((item.expires_at - datetime.now(timezone.utc)).total_seconds() // 86400))
    status = "expired" if item.expires_at <= datetime.now(timezone.utc) else ("expiring" if days_left <= 30 else "valid")
    return {"id": item.id, "name": item.name, "domains": domains, "expires_at": item.expires_at.isoformat(), "fingerprint": item.fingerprint, "references": references, "referenced_projects": referenced_projects, "days_left": days_left, "status": status, "auto_selected": auto_selected}


def _validated_certificate_material(certificate_pem: str, private_key_pem: str) -> tuple[x509.Certificate, list[str], str]:
    cert, domains, fingerprint = _certificate_metadata(certificate_pem)
    if cert.not_valid_after_utc <= datetime.now(timezone.utc):
        raise HTTPException(400, "SSL 证书已经过期，请上传新的有效证书")
    private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
    cert_public = cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    key_public = private_key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    if cert_public != key_public:
        raise HTTPException(400, "SSL 证书与私钥不匹配")
    return cert, domains, fingerprint


def _save_shared_certificate(db: Session, name: str, certificate_pem: str, private_key_pem: str) -> CertificateStore:
    cert, domains, fingerprint = _validated_certificate_material(certificate_pem, private_key_pem)
    item = db.scalar(select(CertificateStore).where(CertificateStore.fingerprint == fingerprint))
    if not item:
        item = CertificateStore(fingerprint=fingerprint, name=name or domains[0])
    item.name = name or item.name
    item.domains_json = json.dumps(domains, ensure_ascii=False)
    item.certificate_encrypted = encrypt(certificate_pem)
    item.private_key_encrypted = encrypt(private_key_pem)
    item.expires_at = cert.not_valid_after_utc
    db.add(item)
    db.flush()
    return item


def _matching_certificates(db: Session, domain: str) -> list[CertificateStore]:
    now_value = datetime.now(timezone.utc)
    matched = []
    for item in db.scalars(select(CertificateStore).where(CertificateStore.expires_at > now_value).order_by(CertificateStore.expires_at.desc())).all():
        patterns = json.loads(item.domains_json or "[]")
        if any(_domain_matches_pattern(domain, pattern) for pattern in patterns):
            exact = any(domain.lower() == pattern.lower() for pattern in patterns)
            matched.append((0 if exact else 1, item))
    return [item for _, item in sorted(matched, key=lambda value: (value[0], -value[1].expires_at.timestamp()))]



