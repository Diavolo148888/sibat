"""Stage 5 — content discovery against web targets (scope-guarded)."""

from __future__ import annotations

import concurrent.futures as _cf

from ..core.models import Finding
from ..core.scope import ScopeGuard
from .web import http_probe

PATHS = [
    "admin", "admin/", "administrator", "backup", "backups", ".git/config", ".env",
    "config", "config.php", "console", "dashboard", "db", "debug", "docs",
    "graphql", "info.php", "jenkins", "login", "phpinfo.php", "phpmyadmin",
    "private", "readme.txt", "robots.txt", "root", "secret", "server-status",
    "setup", "sql", "test", "tmp", "uploads", "wp-admin", "wp-login.php",
    "xmlrpc.php", ".svn/entries", ".DS_Store",
]

INTERESTING = {".git/config": "high", ".env": "high", ".DS_Store": "low",
               ".svn/entries": "medium", "phpinfo.php": "medium", "phpmyadmin": "medium"}


def _check(ip: str, port: int, tls: bool, path: str):
    res = http_probe(ip, port, tls, path=f"/{path}")
    if res is None:
        return None
    status, headers, body = res
    if status in (200, 301, 302, 401, 403):
        sev = INTERESTING.get(path, "info" if status in (200, 301, 302) else "info")
        if status in (401, 403) and path not in INTERESTING:
            return None
        scheme = "https" if tls else "http"
        return Finding(
            category="dirs", host=ip, port=port, severity=sev,
            title=f"{status} /{path}", detail=f"{scheme}://{ip}:{port}/{path}",
        )
    return None


def run(guard: ScopeGuard, findings: list[Finding], workers: int = 12) -> list[Finding]:
    web_targets: list[tuple[str, int, bool]] = []
    for f in findings:
        if f.category == "web" and f.port:
            tls = f.port in (443, 8443, 9443)
            web_targets.append((f.host, f.port, tls))

    # unique on (ip, port, tls)
    seen: set[tuple[str, int, bool]] = set()
    targets: list[tuple[str, int, bool]] = []
    for t in web_targets:
        if t not in seen:
            seen.add(t)
            targets.append(t)

    out: list[Finding] = []
    for ip, port, tls in targets:
        guard.assert_target(ip)
    for ip, port, tls in targets:
        with _cf.ThreadPoolExecutor(max_workers=workers) as pool:
            futs = [pool.submit(_check, ip, port, tls, p) for p in PATHS]
            for fut in futs:
                try:
                    r = fut.result()
                except Exception:
                    r = None
                if r is not None:
                    out.append(r)
    return out
