"""Stage 4 — HTTP inspection: headers, security posture, common pitfalls.

Uses stdlib http.client so TLS verification can be relaxed deliberately
(lab targets often ship self-signed certs) while requests stay scope-guarded.
"""

from __future__ import annotations

import http.client
import ssl

from ..core.models import Finding
from ..core.scope import ScopeGuard
from .. import UA

_TIMEOUT = 6

SECURITY_HEADERS = {
    "strict-transport-security": ("low", "Missing HSTS header"),
    "content-security-policy": ("low", "Missing Content-Security-Policy header"),
    "x-frame-options": ("low", "Missing X-Frame-Options (clickjacking surface)"),
    "x-content-type-options": ("low", "Missing X-Content-Type-Options"),
}


def http_probe(ip: str, port: int, tls: bool, path: str = "/"):
    """Return (status, headers-dict, body-snippet) or None."""
    try:
        ctx = ssl._create_unverified_context() if tls else None
        cls = http.client.HTTPSConnection if tls else http.client.HTTPConnection
        conn = cls(ip, port, timeout=_TIMEOUT, context=ctx) if tls else cls(ip, port, timeout=_TIMEOUT)
        try:
            conn.request("GET", path, headers={"User-Agent": UA, "Host": ip})
            resp = conn.getresponse()
            body = resp.read(4096).decode("latin-1", "replace")
            return resp.status, {k.lower(): v for k, v in resp.getheaders()}, body
        finally:
            conn.close()
    except OSError:
        return None


def run(guard: ScopeGuard, findings: list[Finding]) -> list[Finding]:
    # Probe HTTP on every open port (httpx-style) — real attack surfaces
    # hide services on arbitrary ports. Non-HTTP ports return None fast.
    web_targets: list[tuple[str, int, bool]] = []
    seen: set[tuple[str, int]] = set()
    for f in findings:
        if f.category != "ports" or not f.port:
            continue
        if (f.host, f.port) in seen:
            continue
        seen.add((f.host, f.port))
        tls = f.port in (443, 8443, 9443)
        web_targets.append((f.host, f.port, tls))

    out: list[Finding] = []
    for ip, port, tls in web_targets:
        guard.assert_target(ip)
        result = http_probe(ip, port, tls)
        if result is None:
            continue
        status, headers, body = result
        scheme = "https" if tls else "http"
        out.append(Finding(
            category="web", host=ip, port=port, severity="info",
            title=f"HTTP {scheme}://{ip}:{port} -> {status}",
            detail=body[:180].replace("\n", " "),
        ))
        if status in (200, 301, 302, 401, 403):
            for hname, (sev, msg) in SECURITY_HEADERS.items():
                if hname not in headers:
                    out.append(Finding(
                        category="web", host=ip, port=port, severity=sev,
                        title=msg, detail=f"{scheme}://{ip}:{port} response lacks {hname}",
                    ))
        server = headers.get("server")
        if server:
            for tok, sev, msg in (
                ("apache/1", "medium", "Very old Apache — likely vulnerable to a pile of CVEs"),
                ("apache/2.0", "medium", "EOL Apache 2.0 branch"),
                ("apache/2.2", "medium", "EOL Apache 2.2 branch"),
                ("iis/6", "medium", "Ancient IIS 6 — EOL"),
                ("nginx/1.0", "low", "Very old nginx branch"),
            ):
                if tok in server.lower():
                    out.append(Finding(
                        category="web", host=ip, port=port, severity=sev,
                        title=f"Legacy software: {server}", detail=msg,
                    ))
                    break
    return out
