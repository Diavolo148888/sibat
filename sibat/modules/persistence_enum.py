"""Module: persistence_enum — LOCAL persistence surface enumeration.

Targets 127.0.0.1 ONLY. Read-only listing of where persistence lives on
a Linux host: systemd units, cron entries, user startup files. Never
modifies anything — this is the map a defender (or a post-exploit
enumerator on your own lab) uses.
"""

import pathlib
import subprocess

from ..core.models import Finding
from ..core.scope import ScopeGuard

MODULE = {
    "name": "persistence_enum",
    "title": "Local persistence enumeration (read-only)",
    "desc": "Lists systemd units, cron entries, and user startup files on 127.0.0.1 only.",
    "risk": "low",
    "targeted": True,
}


def run(guard: ScopeGuard, target: str, port: int | None = None) -> list[Finding]:
    guard.assert_target("127.0.0.1")
    if target.strip() not in ("127.0.0.1", "localhost", "::1"):
        return [Finding(
            category="persistence", host=target, severity="info",
            title="persistence_enum is local-only",
            detail="enumerates 127.0.0.1 (your own machine) and refuses other hosts by design",
        )]
    out: list[Finding] = []

    # systemd: enabled units that call shells or curl/wget at boot
    try:
        r = subprocess.run(["systemctl", "list-unit-files", "--type=service", "--state=enabled"],
                           capture_output=True, text=True, timeout=20)
        units = [l.split()[0] for l in r.stdout.splitlines()
                 if l and not l.startswith(("UNIT", "LIST", "")) and l.strip().endswith(".service")]
        out.append(Finding(
            category="persistence", host="127.0.0.1", severity="info",
            title=f"{len(units)} enabled systemd units",
            detail="review for anything you did not install: " + ", ".join(units[:8]) + ("..." if len(units) > 8 else ""),
        ))
    except (OSError, subprocess.TimeoutExpired):
        out.append(Finding(
            category="persistence", host="127.0.0.1", severity="info",
            title="systemd enumeration unavailable", detail="systemctl missing or timed out",
        ))

    # cron: user + system crontabs
    try:
        r = subprocess.run(["crontab", "-l"], capture_output=True, text=True, timeout=10)
        lines = [l for l in r.stdout.splitlines() if l.strip() and not l.startswith("#")]
        out.append(Finding(
            category="persistence", host="127.0.0.1", severity="info" if not lines else "medium",
            title=f"{len(lines)} user cron entries",
            detail="; ".join(lines[:4]) if lines else "no user crontab",
        ))
    except (OSError, subprocess.TimeoutExpired):
        out.append(Finding(
            category="persistence", host="127.0.0.1", severity="info",
            title="no user crontab", detail="crontab unavailable or empty",
        ))
    cron_dirs = [pathlib.Path("/etc/cron.d"),
                 pathlib.Path("/etc/cron.daily")]
    for d in cron_dirs:
        if d.exists():
            entries = [p.name for p in d.iterdir() if p.is_file()]
            out.append(Finding(
                category="persistence", host="127.0.0.1", severity="info",
                title=f"{d}: {len(entries)} entries",
                detail="review for anything foreign: " + ", ".join(entries[:8]) + ("..." if len(entries) > 8 else ""),
            ))

    # shell startup files (rc files with curl/wget pipes = remote-exec persistence)
    home = pathlib.Path.home()
    rc_hits = []
    for rc in (".bashrc", ".bash_profile", ".profile", ".zshrc"):
        p = home / rc
        if p.exists():
            try:
                text = p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for line in text.splitlines():
                ll = line.strip().lower()
                if ("curl" in ll or "wget" in ll) and ("|" in ll or "sh" in ll):
                    rc_hits.append(f"{rc}: {line.strip()[:70]}")
    if rc_hits:
        out.append(Finding(
            category="persistence", host="127.0.0.1", severity="high",
            title=f"{len(rc_hits)} curl/wget-to-shell lines in shell startup files",
            detail="remote-exec persistence pattern — review immediately: " + "; ".join(rc_hits[:3]),
        ))
    else:
        out.append(Finding(
            category="persistence", host="127.0.0.1", severity="info",
            title="Startup files clean", detail="no curl/wget-to-shell patterns in rc files",
        ))
    return out
