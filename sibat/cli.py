"""CLI entry — argparse, stdlib only. Run as: python -m sibat <command>"""

from __future__ import annotations

import argparse
import pathlib
import sys

from . import __version__
from .core.db import Store
from .core.models import Finding
from .core.scope import ScopeGuard, ScopeError

# --- terminal style (ANSI, no emojis, no deps) -----------------------------

R = "\033[0m"
DIM, BOLD = "\033[2m", "\033[1m"
GREEN, RED, AMBER, CYAN = "\033[32m", "\033[31m", "\033[33m", "\033[36m"
SEV_COLOR = {"high": RED, "medium": AMBER, "low": AMBER, "info": DIM}

if not sys.stdout.isatty():
    DIM = BOLD = GREEN = RED = AMBER = CYAN = ""
    SEV_COLOR = {"high": "", "medium": "", "low": "", "info": ""}
    R = ""


def say(msg: str = "") -> None:
    print(msg)


def die(msg: str, code: int = 1) -> None:
    print(f"{RED}[sibat] {msg}{R}", file=sys.stderr)
    sys.exit(code)


def banner() -> None:
    say(f"{GREEN}{BOLD}  SIBAT{R} {DIM}v{__version__} — scope-locked recon framework{R}")
    say(f"{DIM}  rules of engagement enforced on every packet{R}")
    say()


def find_scope_file(path: str | None) -> str:
    if path:
        return path
    for guess in ("scopes/lab.yml", "scope.yml", "scopes/scope.yml"):
        if pathlib.Path(guess).exists():
            return guess
    die("no scope file found. Pass --scope or run `python -m sibat scope init`")


# --- scope templates ---------------------------------------------------------

LAB_SCOPE = """\
# SIBAT rules of engagement — LOCAL LAB
# Everything here is yours. Break it all you want.
engagement:
  name: Local Lab
scope:
  in_scope:
    - 127.0.0.1
    - ::1
    - localhost
  out_of_scope: []
"""

BOUNTY_SCOPE = """\
# SIBAT rules of engagement — BUG BOUNTY TEMPLATE
# Fill in ONLY what the program's policy authorizes. Read it twice.
engagement:
  name: Example Bounty Program
scope:
  in_scope:
    - example.com          # exact host
    - api.example.com      # exact host
    # - .example.com      # everything under example.com (subdomains)
  out_of_scope:
    - admin.example.com    # program said hands off
    # - 10.0.0.0/8        # their internal ranges, if listed
"""


def cmd_scope_init(args) -> None:
    scopes = pathlib.Path("scopes")
    scopes.mkdir(exist_ok=True)
    lab = scopes / "lab.yml"
    bounty = scopes / "bounty-template.yml"
    if lab.exists() or bounty.exists():
        die("scope files already exist in ./scopes (not overwriting)")
    lab.write_text(LAB_SCOPE, encoding="utf-8")
    bounty.write_text(BOUNTY_SCOPE, encoding="utf-8")
    say(f"{GREEN}[+] wrote {lab}{R}   (your own machine — use this for the demo lab)")
    say(f"{GREEN}[+] wrote {bounty}{R} (template for authorized bounty programs)")
    say(f"{DIM}    edit these before scanning anything beyond 127.0.0.1{R}")


def cmd_scope_show(args) -> None:
    guard = ScopeGuard.load(args.file)
    say(f"engagement : {BOLD}{guard.name}{R}")
    say(f"rules file : {guard.rules_file}")
    say(f"in_scope   :")
    for r in guard.include:
        say(f"  {GREEN}+{R} {r.kind:<8} {r.value}")
    say(f"out_of_scope:")
    for r in guard.exclude:
        say(f"  {RED}-{R} {r.kind:<8} {r.value}")
    if not guard.include:
        say(f"  {RED}(empty — weapon locked){R}")


def cmd_scope_check(args) -> None:
    guard = ScopeGuard.load(args.scope)
    for target in args.targets:
        try:
            guard.assert_target(target)
            say(f"{GREEN}[ALLOWED]{R}  {target}")
        except ScopeError as e:
            say(f"{RED}[DENIED ]{R}  {target} — {e}")


# --- recon -------------------------------------------------------------------

def _print_findings(findings: list[Finding]) -> None:
    if not findings:
        say(f"{DIM}  no findings{R}")
        return
    for f in Finding.dedupe(findings):
        c = SEV_COLOR.get(f.severity, "")
        loc = f"{f.host}::{f.port}" if f.port else f.host
        say(f"  {c}{f.severity.upper():<7}{R} {DIM}[{f.category}]{R} {loc:<24} {f.title}")
        if f.detail and args_verbose():
            say(f"          {DIM}{f.detail}{R}")


_VERBOSE = {"on": False}


def args_verbose() -> bool:
    return _VERBOSE["on"]


def cmd_recon(args) -> None:
    from .recon.pipeline import scan_target

    banner()
    try:
        guard = ScopeGuard.load(args.scope)
    except ScopeError as e:
        die(str(e))
    say(f"{DIM}scope     : {guard.name} ({guard.rules_file}){R}")

    store = Store()
    any_findings = False
    for target in args.targets:
        say(f"{BOLD}>> target {target}{R}")
        try:
            result = scan_target(guard, store, target,
                                 port_spec=args.ports, run_dirs=not args.no_dirs,
                                 subdomain_enum=args.subs)
        except ScopeError as e:
            say(f"  {RED}[SCOPE] refused: {e}{R}")
            continue
        any_findings = True
        ips = ", ".join(result["ips"]) or "n/a"
        say(f"  {DIM}resolved  : {ips}{R}")
        counts = result["counts"]
        say(f"  {DIM}findings  : {counts.get('high',0)} high / {counts.get('medium',0)} medium / "
            f"{counts.get('low',0)} low / {counts.get('info',0)} info{R}")
        say(f"  {DIM}elapsed   : {result['elapsed']}s{R}")
        _print_findings(result["findings"])
        say(f"  {GREEN}saved scan #{result['scan_id']}{R} — report: python -m sibat report {result['scan_id']}")
        say()
    if not any_findings:
        die("no targets were scanned (all refused by scope guard)")


# --- modules -------------------------------------------------------------------

def cmd_modules(args) -> None:
    from .modules.loader import list_modules

    banner()
    mods = list_modules()
    say(f"{BOLD}{len(mods)} module(s){R}")
    for m in mods:
        if m.get("title") == "BROKEN":
            say(f"  {RED}{m['name']:<12} BROKEN — {m['desc']}{R}")
            continue
        say(f"  {GREEN}{m['name']:<12}{R} {m['title']}")
        say(f"  {'':<12} {DIM}{m['desc']} (risk: {m['risk']}){R}")
    say(f"{DIM}drop new modules into sibat/modules/ as .py files — auto-discovered{R}")


def cmd_fire(args) -> None:
    from .modules.loader import run_module, list_modules, ModuleError

    try:
        guard = ScopeGuard.load(args.scope)
    except ScopeError as e:
        die(str(e))
    try:
        findings = run_module(args.module, guard, args.target, port=args.port)
    except ModuleError as e:
        known = ", ".join(m["name"] for m in list_modules() if m.get("title") != "BROKEN")
        die(f"{e} — known modules: {known}")
    except ScopeError as e:
        die(f"SCOPE GUARD refused: {e}")
    say(f"{BOLD}>> {args.module} @ {args.target}"
        + (f":{args.port}" if args.port else "") + f"{R}")
    _print_findings(findings)


# --- history / reports ----------------------------------------------------------

def cmd_scans(args) -> None:
    store = Store()
    rows = store.list_scans()
    if not rows:
        say(f"{DIM}no scans yet — run: python -m sibat recon <target>{R}")
        return
    say(f"{BOLD}{'ID':<5} {'TARGET':<22} {'SCOPE':<18} {'WHEN':<22} FINDINGS{R}")
    for r in rows:
        import json as _json
        counts = _json.loads(r["stats"]).get("counts", {})
        total = sum(counts.values())
        hot = (f"{RED}{counts.get('high',0)}h{R}/" if counts.get("high") else "")
        say(f"{r['id']:<5} {r['target']:<22} {r['scope_name']:<18} {r['finished']:<22} "
            f"{hot}{counts.get('medium',0)}m/{counts.get('low',0)}l/{counts.get('info',0)}i "
            f"{DIM}(total {total}){R}")


def cmd_report(args) -> None:
    from .report.html import write_report

    store = Store()
    if args.scan_id == "latest":
        rows = store.list_scans()
        if not rows:
            die("no scans yet — run: python -m sibat recon <target>")
        scan_id = rows[0]["id"]
    else:
        scan_id = int(args.scan_id)
    record = store.get_record(scan_id)
    if record is None:
        die(f"scan #{scan_id} not found")
    path = write_report(record, out_dir=args.out)
    uri = path.resolve().as_uri()
    say(f"{GREEN}[+]{R} report written: {path}")
    say(f"{DIM}open in browser: {uri}{R}")


# --- main ------------------------------------------------------------------------

def main(argv=None) -> None:
    p = argparse.ArgumentParser(
        prog="sibat",
        description="SIBAT — scope-locked recon framework (authorized targets only)",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("scope", help="manage rules of engagement")
    ssp = sp.add_subparsers(dest="scope_cmd", required=True)
    ssp.add_parser("init", help="write scope templates into ./scopes")
    show = ssp.add_parser("show", help="show a scope file")
    show.add_argument("file")
    check = ssp.add_parser("check", help="test targets against a scope")
    check.add_argument("--scope", "-s", required=True)
    check.add_argument("targets", nargs="+")

    rp = sub.add_parser("recon", help="run the recon pipeline on target(s)")
    rp.add_argument("targets", nargs="+")
    rp.add_argument("--scope", "-s", required=True)
    rp.add_argument("--ports", "-p", default="top",
                    help="top | all | full | 80,443 | 1-1024 (default: top)")
    rp.add_argument("--no-dirs", action="store_true", help="skip content discovery stage")
    rp.add_argument("--subs", action="store_true",
                    help="passive subdomain enumeration first (crt.sh, scope-filtered)")

    mp = sub.add_parser("modules", help="list modules")

    fp = sub.add_parser("fire", help="fire a module at a target")
    fp.add_argument("module")
    fp.add_argument("target")
    fp.add_argument("--scope", "-s", required=True)
    fp.add_argument("--port", type=int)

    hp = sub.add_parser("scans", help="list past scans")

    rep = sub.add_parser("report", help="render HTML report for a scan")
    rep.add_argument("scan_id", help="scan id or 'latest'")
    rep.add_argument("--out", default="reports")

    args = p.parse_args(argv)

    if args.cmd == "scope":
        {"init": cmd_scope_init, "show": cmd_scope_show, "check": cmd_scope_check}[args.scope_cmd](args)
    elif args.cmd == "recon":
        cmd_recon(args)
    elif args.cmd == "modules":
        cmd_modules(args)
    elif args.cmd == "fire":
        cmd_fire(args)
    elif args.cmd == "scans":
        cmd_scans(args)
    elif args.cmd == "report":
        cmd_report(args)


if __name__ == "__main__":
    main()
