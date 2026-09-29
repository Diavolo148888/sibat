"""Network + parsing helpers (stdlib only)."""

from __future__ import annotations

import ipaddress
import socket
import threading
import time
import concurrent.futures as _cf
from typing import Callable, Iterable, Optional, TypeVar

T = TypeVar("T")
R = TypeVar("R")

_PRIVATE_HINTS = ("localhost", ".local", ".internal", ".lab", ".test")


class RateLimiter:
    """Thread-safe token pacing: at most ``rps`` events start per second.

    One limiter is shared across the whole scan (all threads call wait()
    before touching the network). rps=0 or None means unlimited.
    Used to honor program policies like "limit automated scanning to
    60 requests per second".
    """

    def __init__(self, rps: float | None):
        self.min_interval = (1.0 / rps) if (rps and rps > 0) else 0.0
        self._lock = threading.Lock()
        self._next_time = 0.0

    def wait(self) -> None:
        if self.min_interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            scheduled = max(now, self._next_time)
            self._next_time = scheduled + self.min_interval
        sleep_for = scheduled - time.monotonic()
        if sleep_for > 0:
            time.sleep(sleep_for)


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False


def resolve_ips(host: str, timeout: float = 4.0) -> list[str]:
    """Resolve a hostname to a deduplicated list of IP strings. Empty on failure."""
    if is_ip(host):
        return [host.strip()]
    try:
        infos = socket.getaddrinfo(host.strip(), None, proto=socket.IPPROTO_TCP)
    except OSError:
        return []
    return sorted({info[4][0] for info in infos})


def is_domainish(value: str) -> bool:
    v = value.strip().lower()
    return (not is_ip(v)) and ("." in v or v == "localhost" or any(h in v for h in _PRIVATE_HINTS))


def pmap(fn: Callable[[T], Optional[R]], items: Iterable[T], workers: int = 40) -> list[R]:
    """Thread-pool map that drops None/exception results (fn must swallow its own errors)."""
    out: list[R] = []
    with _cf.ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        for res in pool.map(fn, items):
            if res is not None:
                out.append(res)
    return out


def parse_port_spec(spec: str, top_ports: list[int]) -> list[int]:
    """Parse 'top' | 'all' | 'full' | '80,443,8080' | '1-1024'."""
    s = spec.strip().lower()
    if s in ("top", ""):
        return top_ports
    if s == "all":
        return list(range(1, 1025))
    if s == "full":
        return list(range(1, 65536))
    if "-" in s and "," not in s:
        lo, _, hi = s.partition("-")
        return list(range(int(lo), int(hi) + 1))
    ports: list[int] = []
    for chunk in s.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            lo, _, hi = chunk.partition("-")
            ports.extend(range(int(lo), int(hi) + 1))
        else:
            ports.append(int(chunk))
    return sorted(set(ports))
