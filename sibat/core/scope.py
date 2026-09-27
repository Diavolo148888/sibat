"""ScopeGuard — the rules-of-engagement enforcer.

Every network-touching component in SIBAT MUST call ``assert_target``
before sending a single packet. If the target is not explicitly inside
the loaded scope (and not excluded), ScopeError is raised and nothing
is sent. An empty scope means the weapon is locked: everything is denied.
"""

from __future__ import annotations

import ipaddress
import pathlib
from dataclasses import dataclass

try:  # prefer real YAML if installed
    import yaml as _yaml
except ImportError:  # stdlib fallback for SIBAT's own file format
    from ..utils import miniyaml as _yaml

from ..utils.net import is_ip, resolve_ips


class ScopeError(Exception):
    """Raised when an action would leave the rules of engagement."""


@dataclass
class _Rule:
    kind: str      # domain | suffix | ip | cidr
    value: object  # str | IPv4Address/IPv6Address | ip_network

    def matches_host(self, host: str, resolved_ips: list[str]) -> bool:
        h = host.strip().lower()
        if self.kind == "domain":
            return h == self.value or h.endswith("." + str(self.value))
        if self.kind == "suffix":
            return h == str(self.value) or h.endswith("." + str(self.value))
        if is_ip(h):
            return self._matches_ip(h)
        return any(self._matches_ip(ip) for ip in resolved_ips)

    def _matches_ip(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        if self.kind == "ip":
            return addr == self.value
        if self.kind == "cidr":
            return addr in self.value
        return False


class ScopeGuard:
    def __init__(self, config: dict):
        scope = config.get("scope", config)  # accept both flat and nested shapes
        meta = config.get("engagement", {})
        self.name: str = str(meta.get("name", scope.get("name", "unnamed engagement")))
        self.rules_file: str = str(meta.get("rules_file", ""))
        self.include: list[_Rule] = []
        self.exclude: list[_Rule] = []
        for raw in scope.get("in_scope", []) or []:
            self.include.append(self._parse(raw, allow_empty=True))
        for raw in scope.get("out_of_scope", []) or []:
            self.exclude.append(self._parse(raw, allow_empty=False))

    # ------------------------------------------------------------------ load

    @classmethod
    def load(cls, path: str | pathlib.Path) -> "ScopeGuard":
        p = pathlib.Path(path)
        if not p.exists():
            raise ScopeError(f"scope file not found: {p} (create one with `sibat scope init`)")
        data = _yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        guard = cls(data)
        guard.rules_file = str(p)
        return guard

    @staticmethod
    def _parse(raw: str, allow_empty: bool = False) -> _Rule:
        if raw is None:
            raise ScopeError("scope entry cannot be null")
        v = str(raw).strip().lower()
        if not v:
            raise ScopeError("scope entry cannot be empty")
        try:
            return _Rule("cidr", ipaddress.ip_network(v, strict=False))
        except ValueError:
            pass
        try:
            return _Rule("ip", ipaddress.ip_address(v))
        except ValueError:
            pass
        if v.startswith("*."):
            return _Rule("suffix", v[2:])
        if v.startswith("."):
            return _Rule("suffix", v[1:])
        if "." in v or v == "localhost":
            return _Rule("domain", v)
        raise ScopeError(f"cannot parse scope entry: {raw!r}")

    # ------------------------------------------------------------------ check

    def check(self, host: str) -> tuple[bool, str]:
        """Return (allowed, reason). Exclusions always win."""
        h = str(host).strip().lower()
        if not h:
            return False, "empty target"
        if not self.include:
            return False, "scope is empty — weapon locked (add in_scope entries to your scope file)"
        ips = [] if is_ip(h) else resolve_ips(h)
        if not is_ip(h) and not ips:
            return False, f"cannot resolve {h!r}; refusing to fire on unverifiable targets"
        for rule in self.exclude:
            if rule.matches_host(h, ips):
                return False, f"excluded by out_of_scope rule {rule.kind}:{rule.value}"
        for rule in self.include:
            if rule.matches_host(h, ips):
                return True, f"authorized by in_scope rule {rule.kind}:{rule.value}"
        return False, f"{h!r} (ips={ips or 'n/a'}) is not in scope {self.name!r}"

    def assert_target(self, host: str) -> None:
        ok, reason = self.check(host)
        if not ok:
            raise ScopeError(reason)
