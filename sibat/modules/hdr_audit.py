"""Module: HTTP header audit — flags missing security headers on any web port."""

from ..core.models import Finding
from ..core.scope import ScopeGuard
from ..recon.web import http_probe

MODULE = {
    "name": "hdr_audit",
    "title": "HTTP security header audit",
    "desc": "Checks a web target for missing security headers (HSTS, CSP, XFO, XCTO).",
    "risk": "low",
    "targeted": True,
}

CHECKS = {
    "strict-transport-security": "Missing HSTS — protocol downgrade surface",
    "content-security-policy": "Missing CSP — injected-content surface",
    "x-frame-options": "Missing X-Frame-Options — clickjacking surface",
    "x-content-type-options": "Missing X-Content-Type-Options — MIME sniffing surface",
}


def run(guard: ScopeGuard, target: str, port: int | None = None) -> list[Finding]:
    guard.assert_target(target)
    if port is None:
        # no port given: probe 80 then 443, use whichever answers
        for cand, is_tls in ((80, False), (443, True)):
            if http_probe(target, cand, is_tls) is not None:
                port, tls = cand, is_tls
                break
        else:
            return [Finding(category="hdr_audit", host=target, severity="info",
                            title="No HTTP response", detail="ports 80/443 did not answer")]
    else:
        tls = port in (443, 8443, 9443)

    res = http_probe(target, port, tls)
    if res is None:
        return [Finding(category="hdr_audit", host=target, port=port, severity="info",
                        title="No HTTP response", detail=f"target did not answer on {port}")]
    status, headers, _ = res
    out = []
    for hname, msg in CHECKS.items():
        if hname not in headers:
            out.append(Finding(
                category="hdr_audit", host=target, port=port, severity="low",
                title=msg, detail=f"response on port {port} lacks {hname}",
            ))
    if not out:
        out.append(Finding(
            category="hdr_audit", host=target, port=port, severity="info",
            title="All checked security headers present", detail=f"status {status}",
        ))
    return out
