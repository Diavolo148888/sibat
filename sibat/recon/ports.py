"""Stage 2 — TCP port scanning (connect scan, thread pool, scope-guarded)."""

from __future__ import annotations

import socket

from ..core.models import Finding
from ..core.scope import ScopeGuard
from ..utils.net import pmap, parse_port_spec

TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 81, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1433, 1521, 2049, 2121, 2181, 3306, 3389, 4444, 5000, 5432, 5601, 5900,
    5985, 6379, 6380, 7001, 7002, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9001, 9200,
]

RISKY = {
    21: ("high", "FTP exposed — often anonymous or legacy"),
    23: ("high", "Telnet exposed — cleartext remote access"),
    135: ("high", "MSRPC exposed"),
    139: ("high", "NetBIOS exposed"),
    445: ("high", "SMB exposed — check for EternalBlue-class bugs"),
    1433: ("medium", "MSSQL exposed to the network"),
    3306: ("medium", "MySQL exposed to the network"),
    3389: ("medium", "RDP exposed — brute-force and BlueKeep surface"),
    5432: ("medium", "PostgreSQL exposed to the network"),
    5900: ("medium", "VNC exposed — often weakly authenticated"),
    6379: ("high", "Redis exposed — check for unauthenticated access"),
    9200: ("high", "Elasticsearch exposed — often unauthenticated"),
    27017: ("high", "MongoDB exposed — often unauthenticated"),
}


def _probe(ip: str, port: int, timeout: float):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) == 0:
                return port
    except OSError:
        pass
    return None


def run(guard: ScopeGuard, ips: list[str], port_spec: str = "top",
        timeout: float = 1.5, workers: int = 200) -> list[Finding]:
    for ip in ips:
        guard.assert_target(ip)
    ports = parse_port_spec(port_spec, TOP_PORTS)
    findings: list[Finding] = []
    for ip in ips:
        open_ports = pmap(lambda p: _probe(ip, p, timeout), ports, workers=workers)
        for port in sorted(open_ports):
            sev, note = RISKY.get(port, ("info", "port open"))
            findings.append(Finding(
                category="ports", host=ip, port=port, severity=sev,
                title=f"TCP/{port} open", detail=note,
            ))
    return findings
