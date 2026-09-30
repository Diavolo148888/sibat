"""Stage 0c — subdomain takeover detection via CNAME analysis.

Passive DNS: queries public resolvers for CNAME records of in-scope
subdomains, then checks whether the CNAME target is dangling (does not
resolve) and points at a recognizable service (S3, Heroku, GitHub Pages,
Azure, CloudFront, ...). Dangling + recognizable = the classic takeover
candidate — verify by claiming the service, then report.

Raw DNS over UDP, standard library only.
"""

from __future__ import annotations

import random
import socket
import struct

from ..core.models import Finding
from ..core.scope import ScopeGuard

RESOLVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]

TAKEOVER_FINGERPRINTS = [
    ("amazonaws.com", "AWS S3 bucket"),
    ("herokuapp.com", "Heroku app"),
    ("github.io", "GitHub Pages site"),
    ("azurewebsites.net", "Azure Web App"),
    ("cloudfront.net", "CloudFront distribution"),
    ("fastly.net", "Fastly service"),
    ("netlify.app", "Netlify site"),
    ("vercel.app", "Vercel deployment"),
    ("web.app", "Firebase hosting"),
    ("storage.googleapis.com", "Google Cloud Storage"),
    ("pantheonsite.io", "Pantheon site"),
    ("ghost.io", "Ghost blog"),
    ("myshopify.com", "Shopify store"),
    ("zendesk.com", "Zendesk"),
    ("helpjuice.com", "HelpJuice"),
    ("helpscoutdocs.com", "HelpScout docs"),
    ("surge.sh", "Surge"),
    ("bitbucket.io", "Bitbucket"),
    ("gitlab.io", "GitLab Pages"),
    ("readme.io", "ReadMe docs"),
    ("cargo.site", "Cargo"),
    ("cyclic.app", "Cyclic"),
    ("render.com", "Render"),
]


def _encode_qname(host: str) -> bytes:
    out = b""
    for label in host.strip(".").split("."):
        raw = label.encode("idna") if not label.isascii() else label.encode()
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def _read_name(data: bytes, offset: int) -> tuple[str, int]:
    """Parse a (possibly compressed) DNS name. Returns (name, next_offset)."""
    labels: list[str] = []
    jumped = False
    next_off = offset
    hops = 0
    while True:
        hops += 1
        if hops > 64 or offset >= len(data):
            return "", next_off
        length = data[offset]
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                return "", next_off
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                next_off = offset + 2
                jumped = True
            offset = ptr
        elif length == 0:
            if not jumped:
                next_off = offset + 1
            return ".".join(labels), next_off
        else:
            if offset + 1 + length > len(data):
                return "", next_off
            labels.append(data[offset + 1: offset + 1 + length].decode("latin-1", "replace"))
            offset += 1 + length


def _dns_query(host: str, qtype: int, resolver: str, timeout: float) -> bytes | None:
    txid = random.randint(0, 65535)
    header = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    packet = header + _encode_qname(host) + struct.pack(">HH", qtype, 1)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(packet, (resolver, 53))
            data, _ = sock.recvfrom(4096)
    except OSError:
        return None
    if len(data) < 12 or data[:2] != packet[:2]:
        return None
    return data


def query_cname(host: str, timeout: float = 4.0) -> str | None:
    """Return the first CNAME target for host, or None (no CNAME / query failed)."""
    for resolver in RESOLVERS:
        data = _dns_query(host, 5, resolver, timeout)  # 5 = CNAME
        if data is None:
            continue
        qd, an = struct.unpack(">HH", data[4:8])
        offset = 12
        for _ in range(qd):  # skip question section
            _, offset = _read_name(data, offset)
            offset += 4
        for _ in range(an):
            _, offset = _read_name(data, offset)
            if offset + 10 > len(data):
                return None
            rtype, _rclass, _ttl, rdlength = struct.unpack(">HHIH", data[offset:offset + 10])
            rdata_start = offset + 10
            if rtype == 5:  # CNAME
                name, _ = _read_name(data, rdata_start)
                return name or None
            offset = rdata_start + rdlength
    return None


def _resolves(host: str) -> bool:
    try:
        socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        return True
    except OSError:
        return False


def _classifies(cname: str, resolves: bool) -> tuple[str, str] | None:
    """Pure classification logic — unit-testable without the network."""
    if resolves:
        return None  # live alias, nothing to take over
    lower = cname.lower()
    for frag, service in TAKEOVER_FINGERPRINTS:
        if lower.endswith(frag) or frag in lower:
            return ("high", f"dangling CNAME to {service} ({cname}) — takeover candidate: "
                            f"claim the service, then report with proof")
    return ("medium", f"dangling CNAME to an unrecognized target ({cname}) — manual review")


def check_host(host: str, timeout: float = 4.0) -> Finding | None:
    cname = query_cname(host, timeout)
    if not cname:
        return None
    verdict = _classifies(cname, resolves=_resolves(cname))
    if verdict is None:
        return None
    sev, msg = verdict
    return Finding(
        category="takeover", host=host, severity=sev,
        title=f"Subdomain takeover candidate ({cname})", detail=msg,
    )


def run(guard: ScopeGuard, hosts: list[str], timeout: float = 4.0) -> list[Finding]:
    for h in hosts:
        guard.assert_target(h)
    out: list[Finding] = []
    for h in hosts:
        f = check_host(h, timeout)
        if f is not None:
            out.append(f)
    return out
