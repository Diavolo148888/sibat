"""Small shared data models."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


@dataclass
class Finding:
    """A single observation produced by a module or the recon pipeline."""

    category: str          # e.g. recon, ports, web, dirs, tls
    host: str
    severity: str         # high | medium | low | info
    title: str
    detail: str = ""
    port: int | None = None

    def sort_key(self):
        return (SEVERITY_ORDER.get(self.severity, 9), self.host, self.port or 0, self.title)

    def to_dict(self) -> dict:
        return asdict(self)

    @staticmethod
    def dedupe(items: list["Finding"]) -> list["Finding"]:
        seen, out = set(), []
        for f in sorted(items, key=Finding.sort_key):
            key = (f.category, f.host, f.port, f.title, f.detail)
            if key in seen:
                continue
            seen.add(key)
            out.append(f)
        return out


@dataclass
class ScanRecord:
    """Everything needed to render a report for one scan."""

    scan_id: int
    target: str
    scope_name: str
    started: str
    finished: str
    stats: dict = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
