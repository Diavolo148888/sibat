"""Stage 4b — CORS misconfiguration probe.

Sends a fake cross-origin request with an attacker Origin and inspects
the response: reflected Origin + Allow-Credentials=true is the classic
reportable CORS bug (browsers will let the attacker's page read
authenticated responses).
"""

from __future__ import annotations

import http.client
import ssl

from ..core.models import Finding
from ..core.scope import ScopeGuard

EVIL_ORIGIN = "https://sibat-attacker.example"

# Probe several common paths: CORS middleware often guards only some routes
PROBE_PATHS = ["/", "/api", "/api/v1", "/api/v1/user", "/api/v1/users", "/user", "/users", "/account", "/admin", "/backup"]


def _probe(ip: str, port: int, tls: bool, path: str = "/"):
    try:
        ctx = ssl._create_unverified_context() if tls else None
        cls = http.client.HTTPSConnection if tls else http.client.HTTPConnection
        conn = cls(ip, port, timeout=6, context=ctx) if tls else cls(ip, port, timeout=6)
        try:
            conn.request("GET", path, headers={"Host": ip, "Origin": EVIL_ORIGIN,
                                               "User-Agent": "SIBAT"})
            resp = conn.getresponse()
            resp.read(1024)
            return {k.lower(): v for k, v in resp.getheaders()}
        finally:
            conn.close()
    except OSError:
        return None


def run(guard: ScopeGuard, findings: list[Finding]) -> list[Finding]:
    out: list[Finding] = []
    seen: set[tuple[str, int]] = set()
    for f in findings:
        if f.category != "web" or not f.port:
            continue
        key = (f.host, f.port)
        if key in seen:
            continue
        seen.add(key)
        guard.assert_target(f.host)
        tls = f.port in (443, 8443, 9443)
        scheme = "https" if tls else "http"
        where = f"{scheme}://{f.host}:{f.port}"
        for path in PROBE_PATHS:
            headers = _probe(f.host, f.port, tls, path)
            if headers is None:
                continue
            acao = headers.get("access-control-allow-origin", "")
            acac = headers.get("access-control-allow-credentials", "").lower()
            loc = where + path
            if acao == EVIL_ORIGIN and acac == "true":
                out.append(Finding(
                    category="cors", host=f.host, port=f.port, severity="high",
                    title="CORS: credentialed origin reflection",
                    detail=(f"{loc} reflects an arbitrary Origin with Allow-Credentials=true — "
                            "verify authenticated/sensitive endpoints are readable cross-origin, "
                            "then report with a proof-of-concept"),
                ))
            elif acao == EVIL_ORIGIN:
                out.append(Finding(
                    category="cors", host=f.host, port=f.port, severity="medium",
                    title="CORS: arbitrary origin reflection",
                    detail=f"{loc} reflects any Origin without credentials — verify impact before reporting",
                ))
            elif acao == "*":
                out.append(Finding(
                    category="cors", host=f.host, port=f.port, severity="low",
                    title="CORS: wildcard Access-Control-Allow-Origin",
                    detail=f"{loc} sends ACAO:* — only reportable if credentials are also allowed",
                ))
    return out
