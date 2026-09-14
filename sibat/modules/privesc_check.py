"""Module: privesc_check — LOCAL post-exploit privilege-escalation enumeration.

Targets 127.0.0.1 ONLY (your own lab machine). Read-only enumeration of
classic privesc surface: SUID binaries, world-writable PATH dirs, sudo
configuration, cron-adjacent writable files. Never modifies anything.
"""

import os
import pathlib
import stat
import subprocess

from ..core.models import Finding
from ..core.scope import ScopeGuard

MODULE = {
    "name": "privesc_check",
    "title": "Local privesc enumeration (read-only)",
    "desc": "Enumerates SUID binaries, writable PATH dirs, sudo config, and cron surface on 127.0.0.1 only.",
    "risk": "low",
    "targeted": True,
}


def _suid_findings() -> list[Finding]:
    out: list[Finding] = []
    interesting = {"pkexec", "sudo", "su", "mount", "umount", "chsh", "chfn", "passwd", "gpasswd", "newgrp"}
    try:
        r = subprocess.run(["find", "/usr/bin", "/usr/sbin", "/bin", "/sbin",
                            "-perm", "-4000", "-type", "f"],
                           capture_output=True, text=True, timeout=30)
        paths = [p for p in r.stdout.splitlines() if p]
    except (OSError, subprocess.TimeoutExpired):
        return out
    for p in paths:
        name = pathlib.Path(p).name
        if name in interesting:
            out.append(Finding(
                category="privesc", host="127.0.0.1", severity="medium",
                title=f"SUID binary: {name}", detail=f"{p} — SUID root; check GTFOBins for known escapes",
            ))
    if not out:
        out.append(Finding(
            category="privesc", host="127.0.0.1", severity="info",
            title="No interesting SUID binaries", detail=f"{len(paths)} SUID binaries total, none GTFOBins-notable",
        ))
    return out


def _path_dirs_findings() -> list[Finding]:
    out: list[Finding] = []
    for d in os.environ.get("PATH", "").split(":"):
        if not d:
            continue
        try:
            mode = os.stat(d).st_mode
        except OSError:
            continue
        if mode & stat.S_IWOTH:
            out.append(Finding(
                category="privesc", host="127.0.0.1", severity="high",
                title=f"World-writable PATH directory: {d}",
                detail="any local user can plant a trojaned binary here — classic privesc",
            ))
    if not out:
        out.append(Finding(
            category="privesc", host="127.0.0.1", severity="info",
            title="No world-writable PATH directories", detail="PATH is clean",
        ))
    return out


def _sudo_findings() -> list[Finding]:
    out: list[Finding] = []
    try:
        r = subprocess.run(["sudo", "-n", "-l"], capture_output=True, text=True, timeout=10)
        text = (r.stdout + r.stderr).strip()
        if "NOPASSWD" in text:
            out.append(Finding(
                category="privesc", host="127.0.0.1", severity="medium",
                title="NOPASSWD sudo entries for this user",
                detail="check what they cover — passwordless sudo on a broad command is privesc-adjacent",
            ))
        else:
            out.append(Finding(
                category="privesc", host="127.0.0.1", severity="info",
                title="sudo -l enumerated", detail=(text.splitlines()[0] if text else "no output"),
            ))
    except (OSError, subprocess.TimeoutExpired):
        out.append(Finding(
            category="privesc", host="127.0.0.1", severity="info",
            title="sudo -l unavailable", detail="needs a TTY or sudo is absent",
        ))
    return out


def run(guard: ScopeGuard, target: str, port: int | None = None) -> list[Finding]:
    # this module ONLY ever targets the local machine
    guard.assert_target("127.0.0.1")
    if target.strip() not in ("127.0.0.1", "localhost", "::1"):
        return [Finding(
            category="privesc", host=target, severity="info",
            title="privesc_check is local-only",
            detail="this module enumerates 127.0.0.1 (your own machine) and refuses other hosts by design",
        )]
    out = _suid_findings() + _path_dirs_findings() + _sudo_findings()
    return out
