"""Stage 5 — content discovery against web targets (scope-guarded)."""

from __future__ import annotations

import concurrent.futures as _cf

from ..core.models import Finding
from ..core.scope import ScopeGuard
from ..utils.net import RateLimiter
from .web import http_probe

PATHS = [
    # classics
    "admin", "admin/", "administrator", "backup", "backups", ".git/config", ".env",
    "config", "config.php", "console", "dashboard", "db", "debug", "docs",
    "graphql", "info.php", "jenkins", "login", "phpinfo.php", "phpmyadmin",
    "private", "readme.txt", "robots.txt", "root", "secret", "server-status",
    "setup", "sql", "test", "tmp", "uploads", "wp-admin", "wp-login.php",
    "xmlrpc.php", ".svn/entries", ".DS_Store",
    # env/backup/config sprawl (bounty-grade expansion)
    ".env.local", ".env.production", ".env.backup", ".env.save", ".env~",
    "env.json", ".env.example",
    "backup.zip", "backup.tar.gz", "backup.sql", "backups.zip",
    "db.sql", "dump.sql", "database.sql", "db_backup.sql",
    "config.json", "config.yml", "config.yaml", "config.bak", "config.old",
    "configuration.php", "settings.php", "settings.json", "settings.py",
    "credentials.json", "creds.txt", "secrets.json", "secrets.yml",
    # dev/CI/ops leaks
    ".git/HEAD", ".git/index", "Jenkinsfile", "Dockerfile", "docker-compose.yml",
    ".docker/config.json", ".gitlab-ci.yml", ".github/workflows", ".travis.yml",
    "composer.json", "package.json", "Gemfile", "requirements.txt", "pom.xml",
    ".svn/wc.db", ".DS_Store", "Thumbs.db",
    # panels and tooling
    "actuator", "actuator/health", "actuator/env", "manager/html", "solr",
    "kibana", "grafana", "prometheus", "airflow", "nexus", "rancher",
    "adminer.php", "admin.php", "panel", "cpanel", "webshell", "shell",
    # CMS depth
    "wp-content", "wp-config.php.bak", "wp-content/debug.log",
    "sites/default/settings.php", "administrator/index.php",
    # api/docs
    "api", "api/v1", "api/docs", "swagger", "swagger.json", "openapi.json",
    "swagger-ui", "swagger-ui.html", "api-docs", "v1", "v2", "graphiql",
    # misc quick wins
    "cgi-bin", "status", "health", "metrics", "info", "phpinfo.php5",
    "server-info", "autodiscover/autodiscover.xml", "web.config",
    ".well-known/security.txt", "security.txt", "sitemap.xml",
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


def _check_r(ip: str, port: int, tls: bool, path: str, limiter: RateLimiter):
    limiter.wait()
    return _check(ip, port, tls, path)


def run(guard: ScopeGuard, findings: list[Finding], workers: int = 12, rps: float = 0) -> list[Finding]:
    limiter = RateLimiter(rps)
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
            futs = [pool.submit(_check_r, ip, port, tls, p, limiter) for p in PATHS]
            for fut in futs:
                try:
                    r = fut.result()
                except Exception:
                    r = None
                if r is not None:
                    out.append(r)
    return out
