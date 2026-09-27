"""Stage 3 — service probing: banners and HTTP fingerprints."""

from __future__ import annotations

import socket

from ..core.models import Finding
from ..core.scope import ScopeGuard

WEB_PORTS = {80, 443, 591, 3000, 4443, 5000, 7000, 7001, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090}  # noqa: F841 — informational only


def grab_banner(ip: str, port: int, timeout: float = 2.0) -> str | None:
    """Best-effort banner grab; returns None silently on any failure.

    Always sends an HTTP HEAD probe: real attack surfaces hide HTTP on
    arbitrary ports, and non-HTTP services simply ignore or reset.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            s.sendall(b"HEAD / HTTP/1.0\r\nHost: x\r\nUser-Agent: SIBAT\r\n\r\n")
            try:
                data = s.recv(1024)
            except socket.timeout:
                return ""
            return data.decode("latin-1", "replace")[:400]
    except OSError:
        return None


def run(guard: ScopeGuard, findings: list[Finding]) -> list[Finding]:
    """Enrich port findings with banners. Mutates and returns new findings."""
    port_findings = [f for f in findings if f.category == "ports"]
    for f in port_findings:
        guard.assert_target(f.host)
    out: list[Finding] = []
    for f in port_findings:
        banner = grab_banner(f.host, f.port or 0)
        if banner is None:
            continue
        if banner:
            out.append(Finding(
                category="services", host=f.host, port=f.port, severity="info",
                title="Banner", detail=" ".join(banner.split())[:200],
            ))
        server = None
        for line in banner.splitlines():
            if line.lower().startswith("server:"):
                server = line.split(":", 1)[1].strip()
                break
        if server:
            out.append(Finding(
                category="services", host=f.host, port=f.port, severity="info",
                title=f"Server header: {server}", detail=server,
            ))
    return out
