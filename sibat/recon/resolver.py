"""Stage 1 — name resolution (scope-guarded)."""

from __future__ import annotations

import socket

from ..core.models import Finding
from ..core.scope import ScopeGuard
from ..utils.net import is_ip, resolve_ips


def run(guard: ScopeGuard, target: str) -> tuple[list[str], list[Finding]]:
    guard.assert_target(target)
    if is_ip(target):
        ips = [target]
        findings = []
        try:
            name = socket.gethostbyaddr(target)[0]
            findings.append(Finding(
                category="recon", host=target, severity="info",
                title=f"PTR: {name}", detail=f"reverse DNS for {target} -> {name}",
            ))
        except OSError:
            pass
        return ips, findings

    ips = resolve_ips(target)
    findings = [
        Finding(
            category="recon", host=target, severity="info",
            title=f"Resolves to {ip}",
            detail=f"A/AAAA record for {target} -> {ip}",
        )
        for ip in ips
    ]
    # Guard every resolved IP too — a scope rule may cover the domain but
    # DNS could point it somewhere the engagement excludes.
    for ip in ips:
        guard.assert_target(ip)
    return ips, findings
