"""Recon pipeline — chains every stage under one scope guard, saves to store."""

from __future__ import annotations

import time

from ..core.db import Store, utcnow
from ..core.models import Finding
from ..core.scope import ScopeGuard
from .. import __version__
from . import resolver, ports, services, web, dirs, subdomains, cors, jslinks, takeover


def scan_target(guard: ScopeGuard, store: Store, target: str,
                port_spec: str = "top", store_findings: bool = True,
                run_dirs: bool = True, subdomain_enum: bool = False,
                rps: float = 0) -> dict:
    """Full pipeline for one target. Returns a dict with findings + stats."""
    t0 = time.time()
    started = utcnow()
    findings: list[Finding] = []

    # Stage 0 (optional): passive subdomain enumeration, scope-filtered.
    scan_targets = [target]
    if subdomain_enum:
        from ..utils.net import is_domainish
        if is_domainish(target):
            subs, sub_finds = subdomains.run(guard, target)
            findings.extend(sub_finds)
            scan_targets.extend(subs)
            # takeover check on every discovered + original host (pure DNS)
            findings.extend(takeover.run(guard, scan_targets))

    all_counts: dict[str, int] = {}
    for tgt in scan_targets:
        ips, resolve_findings = resolver.run(guard, tgt)
        findings.extend(resolve_findings)
        if not ips:
            continue

        port_findings = ports.run(guard, ips, port_spec=port_spec, rps=rps)
        findings.extend(port_findings)

        findings.extend(services.run(guard, port_findings))
        web_findings = web.run(guard, port_findings)
        findings.extend(web_findings)

        findings.extend(cors.run(guard, web_findings))
        findings.extend(jslinks.run(guard, web_findings))

        if run_dirs:
            findings.extend(dirs.run(guard, web_findings + port_findings, rps=rps))

    findings = Finding.dedupe(findings)
    elapsed = time.time() - t0

    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    result = {
        "target": target,
        "ips": ips,
        "findings": findings,
        "counts": counts,
        "elapsed": round(elapsed, 1),
        "started": started,
        "version": __version__,
    }

    if store_findings:
        scan_id = store.save_scan(target, guard.name, started, findings,
                                  {"counts": counts, "elapsed": result["elapsed"]})
        result["scan_id"] = scan_id
    return result
