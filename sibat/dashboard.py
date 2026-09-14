"""SIBAT operator dashboard — Phase 3.

A zero-dependency web command center: scan history, findings board,
module launcher. Stdlib http.server + the SQLite store.

Run:  python3 -m sibat.dashboard [port]     (default 127.0.0.1:8788)
Endpoints:
  GET  /                  the UI
  GET  /api/scans         scan history JSON
  GET  /api/scan/<id>     one scan + findings JSON
  GET  /api/modules       module list JSON
  POST /api/fire          {"module":"hdr_audit","target":"127.0.0.1","port":8080,
                           "scope":"scopes/lab.yml"}  -> findings JSON
Binds to 127.0.0.1 only. Every fire passes through the Scope Guard.
"""

from __future__ import annotations

import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from . import __version__
from .core.db import Store
from .core.models import Finding
from .core.scope import ScopeGuard, ScopeError

_PAGE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SIBAT operator console</title>
<style>
:root { color-scheme: dark; }
* { box-sizing: border-box; }
body { margin:0; background:#060809; color:#cfd8d3;
  font:13px/1.5 ui-monospace,'JetBrains Mono',Menlo,monospace; padding:32px 20px; }
.wrap { max-width:1080px; margin:0 auto; }
.brand { letter-spacing:.35em; color:#30d158; font-weight:700; font-size:12px; }
h1 { font-size:22px; color:#f2f2f2; margin:8px 0 20px; }
h2 { font-size:11px; letter-spacing:.22em; color:#6d7a72; margin:26px 0 10px; }
table { width:100%; border-collapse:collapse; font-size:12px; }
th { text-align:left; color:#6d7a72; padding:8px 10px; border-bottom:1px solid #1c211e; }
td { padding:8px 10px; border-bottom:1px solid #131715; vertical-align:top; }
tr:hover td { background:rgba(48,209,88,.05); cursor:pointer; }
.sev { font-size:10px; padding:1px 7px; border-radius:2px; letter-spacing:.12em; }
.high { color:#ff3b30; border:1px solid #ff3b3055; }
.medium { color:#ff9f0a; border:1px solid #ff9f0a55; }
.low { color:#ffd60a; border:1px solid #ffd60a55; }
.info { color:#30d158; border:1px solid #30d15855; }
.panel { border:1px solid #1c211e; background:#0b0f0d; padding:14px 16px; margin-bottom:10px; }
.row { display:flex; gap:8px; flex-wrap:wrap; }
input, select, button { font:12px ui-monospace,monospace; background:#060809; color:#eaeaea;
  border:1px solid #2a332c; padding:7px 10px; border-radius:3px; }
button { background:#123322; border-color:#30d158; color:#7ee2a8; cursor:pointer; letter-spacing:.1em; }
button:hover { background:#1a4a2f; }
#out { white-space:pre-wrap; color:#9aa8a0; margin-top:10px; min-height:40px; }
.muted { color:#6d7a72; }
</style></head><body><div class="wrap">
<div class="brand">SIBAT<b>//</b>OPERATOR CONSOLE</div>
<h1>v__VER__</h1>

<h2>LAUNCH MODULE</h2>
<div class="panel">
  <div class="row">
    <select id="module"></select>
    <input id="target" placeholder="127.0.0.1" value="127.0.0.1" size="22">
    <input id="port" placeholder="port" value="8090" size="6">
    <input id="scope" placeholder="scopes/lab.yml" value="scopes/lab.yml" size="22">
    <button onclick="fire()">FIRE</button>
  </div>
  <div id="out" class="muted">scope guard enforced on every fire</div>
</div>

<h2>SCAN HISTORY</h2>
<table><thead><tr><th>ID</th><th>TARGET</th><th>SCOPE</th><th>WHEN</th><th>FINDINGS</th></tr></thead>
<tbody id="scans"></tbody></table>

<h2>FINDINGS — SELECTED SCAN</h2>
<table><thead><tr><th>SEV</th><th>TYPE</th><th>TARGET</th><th>FINDING</th></tr></thead>
<tbody id="findings"></tbody></table>

</div>
<script>
const H = document.getElementById('findings');
const esc = s => { const d = document.createElement('div'); d.textContent = s ?? ''; return d.innerHTML; };

async function loadScans() {
  const rows = await (await fetch('/api/scans')).json();
  const tb = document.getElementById('scans');
  tb.innerHTML = rows.map(r => {
    const c = JSON.parse(r.stats).counts || {};
    return `<tr onclick="loadScan(${r.id})"><td>${r.id}</td><td>${esc(r.target)}</td>
      <td>${esc(r.scope_name)}</td><td>${esc(r.finished)}</td>
      <td><span class="sev high">${c.high||0}h</span> <span class="sev medium">${c.medium||0}m</span>
      <span class="sev low">${c.low||0}l</span> <span class="sev info">${c.info||0}i</span></td></tr>`;
  }).join('');
}

async function loadScan(id) {
  const rec = await (await fetch('/api/scan/' + id)).json();
  H.innerHTML = rec.findings.map(f => `<tr>
    <td><span class="sev ${f.severity}">${f.severity.toUpperCase()}</span></td>
    <td>${esc(f.category)}</td>
    <td>${esc(f.host)}${f.port ? ':' + f.port : ''}</td>
    <td>${esc(f.title)}<div class="muted">${esc(f.detail)}</div></td></tr>`).join('');
}

async function loadModules() {
  const mods = await (await fetch('/api/modules')).json();
  const sel = document.getElementById('module');
  sel.innerHTML = mods.map(m => `<option value="${esc(m.name)}">${esc(m.name)} — ${esc(m.title)}</option>`).join('');
}

async function fire() {
  const out = document.getElementById('out');
  out.className = ''; out.textContent = 'firing...';
  const payload = {
    module: document.getElementById('module').value,
    target: document.getElementById('target').value.trim(),
    port: parseInt(document.getElementById('port').value) || null,
    scope: document.getElementById('scope').value.trim(),
  };
  const res = await fetch('/api/fire', { method: 'POST',
    headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload) });
  const data = await res.json();
  if (data.error) { out.textContent = 'REFUSED: ' + data.error; return; }
  out.textContent = (data.findings || []).map(f =>
    `[${f.severity.toUpperCase()}] ${f.category} ${f.host}${f.port ? ':' + f.port : ''} — ${f.title}`).join('\\n') || 'no findings';
}

loadScans(); loadModules();
</script></body></html>"""


class Api(BaseHTTPRequestHandler):
    store: Store = None  # set in main()

    def log_message(self, fmt, *args):
        sys.stderr.write("[dashboard] %s\n" % (fmt % args))

    def _json(self, obj, code=200):
        body = json.dumps(obj, default=str).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _html(self, page):
        body = page.replace("__VER__", __version__).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        p = urlparse(self.path).path
        if p == "/" or p == "/index.html":
            self._html(_PAGE)
        elif p == "/api/scans":
            self._json(self.store.list_scans())
        elif p.startswith("/api/scan/"):
            try:
                sid = int(p.rsplit("/", 1)[1])
            except ValueError:
                return self._json({"error": "bad scan id"}, 400)
            rec = self.store.get_record(sid)
            if rec is None:
                return self._json({"error": f"scan {sid} not found"}, 404)
            self._json({
                "scan_id": rec.scan_id, "target": rec.target,
                "scope_name": rec.scope_name, "started": rec.started,
                "finished": rec.finished, "stats": rec.stats,
                "findings": [f.to_dict() for f in rec.findings],
            })
        elif p == "/api/modules":
            from .modules.loader import list_modules
            self._json(list_modules())
        else:
            self._json({"error": "not found"}, 404)

    def do_POST(self):
        if urlparse(self.path).path != "/api/fire":
            return self._json({"error": "not found"}, 404)
        try:
            length = int(self.headers.get("Content-Length", 0))
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
        except (ValueError, json.JSONDecodeError):
            return self._json({"error": "bad JSON body"}, 400)
        module = payload.get("module", "")
        target = payload.get("target", "")
        port = payload.get("port")
        scope_path = payload.get("scope", "scopes/lab.yml")
        if not module or not target:
            return self._json({"error": "module and target required"}, 400)
        try:
            guard = ScopeGuard.load(scope_path)
        except ScopeError as e:
            return self._json({"error": str(e)}, 403)
        from .modules.loader import run_module, ModuleError
        try:
            findings = run_module(module, guard, target, port=port)
        except ModuleError as e:
            return self._json({"error": str(e)}, 400)
        except ScopeError as e:
            return self._json({"error": f"SCOPE GUARD refused: {e}"}, 403)
        self._json({"findings": [f.to_dict() for f in findings]})


def main(port: int = 8788) -> None:
    Api.store = Store()
    srv = ThreadingHTTPServer(("127.0.0.1", port), Api)
    print(f"[dashboard] operator console on http://127.0.0.1:{port} — localhost only")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n[dashboard] down")


if __name__ == "__main__":
    main(int(sys.argv[1]) if len(sys.argv) > 1 else 8788)
