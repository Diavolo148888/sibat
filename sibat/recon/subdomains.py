"""Stage 0 (optional) — passive subdomain enumeration via certificate logs.

Passive only: queries public certificate transparency sources, never the
target. Two sources with graceful degradation:
  1. crt.sh (certificate transparency, can be slow under load)
  2. certspotter.com (fallback, free tier)
Discovered names are resolved and scope-checked before being returned;
anything the guard refuses never gets scanned.
"""

from __future__ import annotations

import json
import urllib.parse
import urllib.request

from ..core.models import Finding
from ..core.scope import ScopeGuard

UA = "Mozilla/5.0 (sibat passive recon)"
CRT_TIMEOUT = 60
SPOTTER_TIMEOUT = 25


def _http_get(url: str, timeout: float) -> str | None:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read(3_000_000).decode("utf-8", "replace")
    except Exception:  # noqa: BLE001 — any source failure falls to the next
        return None


def _from_crtsh(domain: str) -> set[str]:
    base = domain.strip().lower()
    query = urllib.parse.quote(f"%.{base}")
    text = _http_get(f"https://crt.sh/?q={query}&output=json", CRT_TIMEOUT)
    if not text:
        return set()
    try:
        rows = json.loads(text)
    except json.JSONDecodeError:
        return set()
    names: set[str] = set()
    for row in rows:
        for nv in str(row.get("name_value", "")).splitlines():
            nv = nv.strip().lower().lstrip("*.")
            if nv.endswith("." + base) and nv != base:
                names.add(nv)
    return names


def _from_certspotter(domain: str) -> set[str]:
    base = domain.strip().lower()
    url = (f"https://api.certspotter.com/v1/issuances?domain={urllib.parse.quote(base)}"
           f"&include_subdomains=true&expand=dns_names")
    text = _http_get(url, SPOTTER_TIMEOUT)
    if not text:
        return set()
    try:
        rows = json.loads(text)
    except json.JSONDecodeError:
        return set()
    if isinstance(rows, dict):  # error payload
        return set()
    names: set[str] = set()
    for row in rows:
        for nv in row.get("dns_names", []):
            nv = nv.strip().lower().lstrip("*.")
            if nv.endswith("." + base) and nv != base:
                names.add(nv)
    return names


def run(guard: ScopeGuard, domain: str) -> tuple[list[str], list[Finding]]:
    guard.assert_target(domain)
    findings: list[Finding] = []

    discovered: set[str] = set()
    sources_used: list[str] = []
    for label, fn in (("crt.sh", _from_crtsh), ("certspotter", _from_certspotter)):
        got = fn(domain)
        if got:
            discovered |= got
            sources_used.append(label)
            break  # first source that answers is enough

    if not discovered:
        findings.append(Finding(
            category="subdomains", host=domain, severity="info",
            title="Subdomain enumeration unavailable",
            detail="no certificate-transparency source answered (crt.sh, certspotter) — "
                   "continuing without subdomains",
        ))
        return [], findings

    findings.append(Finding(
        category="subdomains", host=domain, severity="info",
        title=f"{len(discovered)} unique subdomain(s) via {', '.join(sources_used)}",
        detail="passive certificate-transparency discovery; only in-scope, "
               "resolvable names are scanned",
    ))

    allowed: list[str] = []
    for name in sorted(discovered):
        ok, _reason = guard.check(name)
        if ok and name not in allowed:
            allowed.append(name)
    return allowed, findings
