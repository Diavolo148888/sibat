"""Stage 4c — JavaScript/HTML secret and endpoint extraction.

Pulls inline scripts and same-origin JS files from web targets, then
hunts for secret-looking strings (API keys, tokens, JWTs) and API
endpoint paths. Every secret hit is a CANDIDATE — verify it is live
before reporting it; test keys and documentation examples are common.
"""

from __future__ import annotations

import http.client
import re
import ssl

from .. import UA
from ..core.models import Finding
from ..core.scope import ScopeGuard

MAX_JS_FILES = 6
MAX_ENDPOINT_FINDINGS = 15

SECRET_PATTERNS = [
    ("high", "AWS access key candidate", r"AKIA[0-9A-Z]{16}"),
    ("high", "Google API key candidate", r"AIza[0-9A-Za-z_\-]{35}"),
    ("high", "GitHub token candidate", r"gh[pousr]_[A-Za-z0-9]{36,}"),
    ("high", "Stripe LIVE secret key candidate", r"sk_live_[0-9a-zA-Z]{24,}"),
    ("medium", "Stripe test key exposed in client code", r"sk_test_[0-9a-zA-Z]{24,}"),
    ("medium", "Slack token candidate", r"xox[baprs]-[0-9A-Za-z\-]{10,}"),
    ("medium", "JWT candidate", r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
    ("low", "Hard-coded secret assignment candidate",
     r"(?i)\b(api[_-]?key|secret|token|password|passwd|pwd)\b\s*[:=]\s*[\"'][^\"']{8,}[\"']"),
]

SCRIPT_SRC_RE = re.compile(r"<script[^>]+src=[\"']([^\"']+)[\"']", re.IGNORECASE)
INLINE_SCRIPT_RE = re.compile(r"(?is)<script(?![^>]*\bsrc\b)[^>]*>(.*?)</script>")
ENDPOINT_RE = re.compile(r"[\"'](/[A-Za-z0-9_\-\.~/]{2,60})[\"']")


def _fetch(ip: str, port: int, tls: bool, path: str, cap: int = 100_000):
    try:
        ctx = ssl._create_unverified_context() if tls else None
        cls = http.client.HTTPSConnection if tls else http.client.HTTPConnection
        conn = cls(ip, port, timeout=8, context=ctx) if tls else cls(ip, port, timeout=8)
        try:
            conn.request("GET", path, headers={"User-Agent": UA, "Host": ip})
            resp = conn.getresponse()
            body = resp.read(cap).decode("latin-1", "replace")
            return resp.status, body
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

        home = _fetch(f.host, f.port, tls, "/")
        if home is None:
            continue
        status, home_body = home
        if status != 200:
            continue

        # collect JS text: inline scripts + same-origin script srcs
        js_chunks = INLINE_SCRIPT_RE.findall(home_body)
        srcs = [s for s in SCRIPT_SRC_RE.findall(home_body) if s.startswith("/")]
        for src in srcs[:MAX_JS_FILES]:
            got = _fetch(f.host, f.port, tls, src)
            if got and got[0] == 200:
                js_chunks.append(got[1])
        combined = "\n".join(js_chunks)
        if not combined.strip():
            continue

        # secrets — every hit is a candidate, dedup on the matched value
        found_vals: set[str] = set()
        for sev, title, pattern in SECRET_PATTERNS:
            for m in re.finditer(pattern, combined):
                val = m.group(0)[:60]
                if val in found_vals:
                    continue
                found_vals.add(val)
                out.append(Finding(
                    category="jssecrets", host=f.host, port=f.port, severity=sev,
                    title=f"{title}: {val[:28]}...",
                    detail=f"{title} in client-side code at {where} — VERIFY the value is "
                           f"live/valid before reporting (test keys are common): {val}",
                ))

        # endpoints — API surface map for manual testing
        endpoints = []
        for m in ENDPOINT_RE.finditer(combined):
            ep = m.group(1)
            if ep not in endpoints and not ep.endswith((".js", ".css", ".png", ".svg", ".ico")):
                endpoints.append(ep)
        for ep in endpoints[:MAX_ENDPOINT_FINDINGS]:
            out.append(Finding(
                category="jssecrets", host=f.host, port=f.port, severity="info",
                title=f"JS endpoint: {ep}",
                detail=f"referenced in client-side code at {where} — map these for manual testing",
            ))
    return out
