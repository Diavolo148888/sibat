"""Module: TLS posture check — protocol versions and cert sanity (lab-grade)."""

from __future__ import annotations

import datetime as _dt
import socket
import ssl

from ..core.models import Finding
from ..core.scope import ScopeGuard

MODULE = {
    "name": "tls_check",
    "title": "TLS posture check",
    "desc": "Connects with multiple TLS versions, flags ancient protocols and expiring/self-signed certs.",
    "risk": "low",
    "targeted": True,
}

_DEAD = {
    "TLSv1": ("high", "TLS 1.0 enabled — deprecated protocol"),
    "TLSv1.1": ("high", "TLS 1.1 enabled — deprecated protocol"),
}


def _handshake(ip: str, port: int, ctx) -> tuple[bool, str | None]:
    try:
        with socket.create_connection((ip, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
                return True, ssock.version()
    except (OSError, ssl.SSLError):
        return False, None


def run(guard: ScopeGuard, target: str, port: int | None = None) -> list[Finding]:
    guard.assert_target(target)
    port = port or 443
    out: list[Finding] = []

    # 1) Will it still speak a dead protocol?
    ctx_old = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx_old.minimum_version = ssl.TLSVersion.TLSv1
    ctx_old.maximum_version = ssl.TLSVersion.TLSv1_1
    ctx_old.check_hostname = False
    ctx_old.verify_mode = ssl.CERT_NONE
    ok, ver = _handshake(target, port, ctx_old)
    if ok and ver in _DEAD:
        sev, msg = _DEAD[ver]
        out.append(Finding(category="tls", host=target, port=port, severity=sev,
                           title=msg, detail=f"negotiated {ver}"))

    # 2) Modern handshake + certificate sanity
    ctx_new = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx_new.check_hostname = False
    ctx_new.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((target, port), timeout=5) as sock:
            with ctx_new.wrap_socket(sock, server_hostname=target) as ssock:
                out.append(Finding(
                    category="tls", host=target, port=port, severity="info",
                    title=f"TLS handshake OK ({ssock.version()})",
                    detail="modern handshake succeeded",
                ))
                cert_der = ssock.getpeercert(binary_form=True)
                if cert_der:
                    pem = ssl.DER_cert_to_PEM_cert(cert_der)
                    f = _cert_findings(target, port, pem)
                    if f:
                        out.append(f)
    except (OSError, ssl.SSLError) as e:
        out.append(Finding(
            category="tls", host=target, port=port, severity="medium",
            title="TLS handshake failed", detail=str(e)[:200],
        ))
    return out


def _cert_findings(host: str, port: int, pem: str) -> Finding | None:
    try:
        from cryptography import x509
    except ImportError:
        return None
    try:
        cert = x509.load_pem_x509_certificate(pem.encode())
        not_after = cert.not_valid_after_utc
        days = (not_after - _dt.datetime.now(_dt.timezone.utc)).days
        subject = cert.subject.rfc4514_string()
        if days < 0:
            return Finding(
                category="tls", host=host, port=port, severity="high",
                title="Certificate EXPIRED", detail=f"expired {-days} days ago ({subject})",
            )
        if days < 15:
            return Finding(
                category="tls", host=host, port=port, severity="medium",
                title=f"Certificate expires in {days} days", detail=subject,
            )
        if cert.issuer == cert.subject:
            return Finding(
                category="tls", host=host, port=port, severity="medium",
                title="Self-signed certificate", detail=f"issuer == subject ({subject})",
            )
        return Finding(
            category="tls", host=host, port=port, severity="info",
            title=f"Certificate valid ({days} days left)", detail=subject,
        )
    except Exception:  # noqa: BLE001
        return None
