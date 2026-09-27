# SIBAT

```
  scope-locked recon framework
  rules of engagement enforced on every packet
```

SIBAT (*sibat* — spear) is a reconnaissance and attack-surface mapping
framework built for one purpose: running professional-grade recon against
systems you are **explicitly authorized to test** — your own lab,
engagements with written permission, bug bounty programs inside their
policy.

Its defining feature is the **Scope Guard**: a rules-of-engagement engine
built into the core. Every network operation in every stage and every
module passes through it. If a target is not inside the loaded scope —
or is explicitly excluded — the weapon refuses to fire. Not a warning
banner. A hard refusal, before a single packet leaves the machine.

## Install

Python 3.10+. No required dependencies — the entire framework is stdlib.

    git clone https://github.com/Diavolo148888/sibat
    cd sibat
    python3 -m sibat modules

Optional: `pip install PyYAML cryptography` — PyYAML for full YAML
support (a built-in subset parser handles SIBAT's own files without it),
cryptography for deeper certificate analysis in the `tls_check` module.

## Quickstart — 90 seconds against the built-in lab

    # 1. start the deliberately vulnerable local lab
    python3 lab/vulhttp.py 8090 8091 &

    # 2. run the full pipeline against it (localhost is in the lab scope)
    python3 -m sibat recon 127.0.0.1 --scope scopes/lab.yml --ports 8080-8095

    # 3. render the engagement report
    python3 -m sibat report 1

The lab ships with an EOL Apache banner, missing security headers,
exposed `/.git/config` and `/.env`, and odd open ports — the scan lights
up like a real engagement. The report lands in `reports/` as a dark,
terminal-styled HTML page.

Docker users: `docker compose up -d` in `lab/` starts an alternative lab
on ports 8081-8082 (localhost-bound only).

## Commands

| Command | Purpose |
|---|---|
| `scope init` | write scope templates into `./scopes` |
| `scope show <file>` | display loaded rules of engagement |
| `scope check -s <file> <targets...>` | dry-run: allowed or refused, with reasons |
| `recon <targets...> -s <file>` | full pipeline: resolve, ports, services, web, dirs |
| `modules` | list loaded plugin modules |
| `fire <module> <target> -s <file>` | run one module against one target |
| `scans` | scan history from the SQLite store |
| `report <scan_id>` | render the HTML engagement report |

## The pipeline

    resolve -> ports -> services -> web -> dirs

1. **resolve** — DNS resolution, PTR records; every resolved IP is
   re-checked against scope (DNS pointing in-scope hosts at excluded
   infrastructure gets refused)
2. **ports** — TCP connect scan across the top 42 ports (or `top`, `all`,
   `full`, custom ranges), risk-ranked findings on exposed services
3. **services** — banner grabs, `Server:` header fingerprints
4. **web** — HTTP probes, missing security headers, legacy software
   detection
5. **dirs** — content discovery: `.git/`, `.env`, backups, admin panels,
   and other classics

Every stage is scope-guarded independently. Findings are deduplicated,
severity-ranked, and stored in SQLite (`~/.sibat/sibat.db` by default).

## Modules

Modules are single Python files dropped into `sibat/modules/`:

    MODULE = {
        "name": "example",
        "title": "Example module",
        "desc": "What it does",
        "risk": "low",
        "targeted": True,
    }

    def run(guard, target, port=None):
        guard.assert_target(target)   # mandatory — the loader enforces the habit
        ...

Shipped modules:

- **hdr_audit** — HTTP security header audit (HSTS, CSP, XFO, XCTO)
- **tls_check** — dead TLS protocol versions, expired and self-signed certificates

## Rules of engagement

Scope files define the engagement:

    engagement:
      name: Local Lab
    scope:
      in_scope:
        - 127.0.0.1
        - .example.com        # all subdomains
        - 10.0.0.0/24         # CIDR
      out_of_scope:
        - admin.example.com   # exclusions always win

An empty scope means the weapon is locked — everything is refused.
Unresolvable hostnames are refused (no firing at names that cannot be
verified). Keep real engagement scope files out of git — `.gitignore`
excludes `scopes/private/`.

## Ethics and legality

SIBAT is built for authorized testing. Full stop. The Scope Guard exists
because rules of engagement are not a suggestion — they are the difference
between a pentest and a crime. Scanning systems you do not own or are not
explicitly authorized to test is illegal in most jurisdictions. The
lab targets in this repository are the demo surface; everything beyond
them is your responsibility to authorize properly.

## Roadmap

- [x] Phase 1 — recon engine, Scope Guard, modules, HTML reports
- [ ] Phase 2 — exploit module library against the local lab
- [ ] Phase 3 — operator console (web UI)
- [ ] Phase 4 — post-exploitation and evasion research (lab only)

## Author

**John Mark "mako" Alojado** — [github.com/Diavolo148888](https://github.com/Diavolo148888)

MIT License — see LICENSE.
