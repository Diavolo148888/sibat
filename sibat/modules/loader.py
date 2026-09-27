"""Module loader — discover, import, verify, run plugin modules."""

from __future__ import annotations

import importlib.util
import pathlib
import sys

from ..core.models import Finding
from ..core.scope import ScopeGuard

MODULE_DIR = pathlib.Path(__file__).parent
_REQUIRED_KEYS = {"name", "title", "desc", "risk"}


class ModuleError(Exception):
    pass


def _load_path(path: pathlib.Path) -> dict:
    # Load under the REAL package path (sibat.modules.<name>) so that
    # relative imports inside module files resolve correctly.
    name = f"sibat.modules.{path.stem}"
    spec = importlib.util.spec_from_file_location(name, path)
    if not spec or not spec.loader:
        raise ModuleError(f"cannot import {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    meta = getattr(mod, "MODULE", None)
    if not isinstance(meta, dict) or not _REQUIRED_KEYS.issubset(meta):
        raise ModuleError(f"{path.name}: missing MODULE metadata")
    if not hasattr(mod, "run"):
        raise ModuleError(f"{path.name}: missing run() function")
    meta["_file"] = str(path)
    meta["_run"] = mod.run
    return meta


def list_modules() -> list[dict]:
    out = []
    for path in sorted(MODULE_DIR.glob("*.py")):
        if path.stem.startswith("_") or path.stem == "loader":
            continue
        try:
            meta = _load_path(path)
            out.append({k: v for k, v in meta.items() if not k.startswith("_")})
        except Exception as e:  # noqa: BLE001 — list must survive one broken plugin
            out.append({"name": path.stem, "title": "BROKEN", "desc": str(e), "risk": "info",
                        "targeted": False, "_file": str(path)})
    return out


def run_module(mod_name: str, guard: ScopeGuard, target: str,
               port: int | None = None) -> list[Finding]:
    path = MODULE_DIR / f"{mod_name}.py"
    if not path.exists():
        raise ModuleError(f"no such module: {mod_name}")
    meta = _load_path(path)
    findings = meta["_run"](guard, target, port=port)
    if not isinstance(findings, list):
        raise ModuleError(f"{mod_name}: run() must return a list of Finding")
    for f in findings:
        if not isinstance(f, Finding):
            raise ModuleError(f"{mod_name}: run() returned non-Finding item")
    return findings
