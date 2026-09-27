"""The SIBAT demo lab — a deliberately vulnerable local target.

Two ways to run it (both scope-locked to 127.0.0.1):

  A) Docker:   docker compose up -d        (ports 8081-8082)
  B) No Docker: python lab/vulhttp.py 8090 (ports 8090-8091)

Intentionally misconfigured so every SIBAT stage lights up:
  - EOL software banner, missing security headers
  - exposed /.git/config, /.env, backups, admin panel
  - CORS origin reflection with credentials (reportable-class bug)
  - live-looking API key patterns and endpoint refs in client JS
  - odd open ports (banner grab stage)
Never expose this to a network.
"""

import http.server
import sys
import threading
import os

INDEX_PAGE = """<!DOCTYPE html><html><head><title>Welcome to vulnhub-lite</title>
<script src="/static/app.js"></script></head>
<body><h1>It works - server at 127.0.0.1</h1>
<p>Admin panel at /admin. See /readme.txt for setup notes.</p></body></html>"""

APP_JS = """// app bundle — sloppy developer left secrets in the client
const AWS_KEY = "AKIAIOSFODNN7EXAMPLEXAMPLE";  // wait, that's the docs sample
const config = {
  apiKey: "sk_test_51H8xKqTestTestTestTestTestTestTest",
  apiToken: "ghp_ThisIsNotARealTokenButItLooksLikeOne1234567890",
  jwt: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dQw4w9WgXcQ",
};
function loadProfile() { fetch("/api/v1/profile"); }
function loadAdmin() { fetch("/api/admin/users"); }
function pay() { fetch("/api/v1/payments/charge"); }
"""

ADMIN_PAGE = "<html><body><h1>ADMIN LOGIN</h1><form><input name=user><input name=pass type=password></form></body></html>"
GIT_CONFIG = "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n[remote \"origin\"]\n\turl = https://github.com/example/dead-repo.git\n"
ENV_FILE = "DB_PASSWORD=s3cretpw\nAWS_SECRET_KEY=AKIAIOSFODNN7EXAMPLE\nDEBUG=true\n"
README = "TODO: remove backup folder before production deploy\n"
SWAGGER = '{"openapi":"3.0.0","info":{"title":"vuln-api"},"paths":{"/api/v1/users":{"get":{}}}}'

PAGE_404 = "<html><body>404 not found</body></html>"


class VulnHandler(http.server.BaseHTTPRequestHandler):
    server_version = "Apache/2.2.15"      # EOL banner on purpose
    sys_version = "(Unix) mod_ssl/2.2.15"

    def log_message(self, fmt, *args):
        sys.stderr.write("[vulhttp] %s\n" % (fmt % args))

    def _respond(self, code, body, ctype="text/html", extra_headers=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        # deliberately missing every security header
        if extra_headers:
            for k, v in extra_headers:
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/":
            self._respond(200, INDEX_PAGE)
        elif path == "/static/app.js":
            self._respond(200, APP_JS, "application/javascript")
        elif path == "/admin":
            self._respond(200, ADMIN_PAGE)
        elif path == "/.git/config":
            self._respond(200, GIT_CONFIG, "text/plain")
        elif path == "/.env":
            self._respond(200, ENV_FILE, "text/plain")
        elif path == "/readme.txt":
            self._respond(200, README, "text/plain")
        elif path == "/server-status":
            self._respond(200, "Apache Server Status for 127.0.0.1\n", "text/plain")
        elif path == "/backup":
            # CORS bug: reflects any Origin AND allows credentials — the classic
            self._respond(200, "backup listing\n", "text/plain",
                          extra_headers=[("Access-Control-Allow-Origin", self.headers.get("Origin", "")),
                                         ("Access-Control-Allow-Credentials", "true")])
        elif path in ("/api/v1/user", "/api/v1/users"):
            # same CORS bug on the API surface
            self._respond(200, '{"user":"mako","role":"user"}', "application/json",
                          extra_headers=[("Access-Control-Allow-Origin", self.headers.get("Origin", "")),
                                         ("Access-Control-Allow-Credentials", "true")])
        elif path == "/api/v1/profile":
            self._respond(200, '{"user":"mako","role":"user"}', "application/json",
                          extra_headers=[("Access-Control-Allow-Origin", self.headers.get("Origin", "")),
                                         ("Access-Control-Allow-Credentials", "true")])
        elif path in ("/api/admin/users", "/api/v1/payments/charge", "/api/v1/user/preferences"):
            self._respond(200, '{"ok":true}', "application/json")
        elif path == "/swagger.json":
            self._respond(200, SWAGGER, "application/json")
        elif path in ("/backup", "/uploads", "/setup", "/phpmyadmin"):
            self._respond(301, "")
        else:
            self._respond(404, PAGE_404)

    do_HEAD = do_GET


def plain_listener(port: int):
    """A socket that accepts connections and hangs — simulates an odd service."""
    import socket
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(8)
    while True:
        try:
            conn, _ = srv.accept()
            threading.Thread(target=lambda c: (c.settimeout(2), c.close()), args=(conn,), daemon=True).start()
        except OSError:
            return


def main(http_port=8090, extra_ports=(8091,)):
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", http_port), VulnHandler)
    print(f"[vulhttp] vulnerable HTTP  on 127.0.0.1:{http_port}")
    for p in extra_ports:
        threading.Thread(target=plain_listener, args=(p,), daemon=True).start()
        print(f"[vulhttp] dummy service    on 127.0.0.1:{p}")
    print("[vulhttp] lab is up — only ever bind this to 127.0.0.1")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n[vulhttp] down")


if __name__ == "__main__":
    main(int(sys.argv[1]) if len(sys.argv) > 1 else 8090,
         tuple(int(a) for a in sys.argv[2:]) or (8091,))
