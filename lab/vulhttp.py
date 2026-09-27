"""The SIBAT demo lab — a deliberately vulnerable local target.

Two ways to run it (both scope-locked to 127.0.0.1):

  A) Docker:   docker compose up -d        (ports 8081-8085)
  B) No Docker: python lab/vulhttp.py 8090 (ports 8090)

It is intentionally misconfigured: old software banner, missing security
headers, exposed .git/.env, ancient TLS, telnet-ish open socket. Point SIBAT
at it and the findings light up. Never expose this to a network.
"""

import http.server
import ssl
import subprocess
import sys
import threading
import os

BAD_HEADERS_PAGE = """<!DOCTYPE html><html><head><title>Welcome to vulnhub-lite</title></head>
<body><h1>It works - server at 127.0.0.1</h1>
<p>Admin panel at /admin. See /readme.txt for setup notes.</p></body></html>"""

ADMIN_PAGE = "<html><body><h1>ADMIN LOGIN</h1><form><input name=user><input name=pass type=password></form></body></html>"
GIT_CONFIG = "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n[remote \"origin\"]\n\turl = https://github.com/example/dead-repo.git\n"
ENV_FILE = "DB_PASSWORD=s3cretpw\nAWS_SECRET_KEY=AKIAIOSFODNN7EXAMPLE\nDEBUG=true\n"
README = "TODO: remove backup folder before production deploy\n"

PAGE_404 = "<html><body>404 not found</body></html>"


class VulnHandler(http.server.BaseHTTPRequestHandler):
    server_version = "Apache/2.2.15"      # EOL banner on purpose
    sys_version = "(Unix) mod_ssl/2.2.15"

    def log_message(self, fmt, *args):
        sys.stderr.write("[vulhttp] %s\n" % (fmt % args))

    def _respond(self, code, body, ctype="text/html"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        # deliberately missing every security header
        self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self):
        path = self.path.split("?")[0]
        routes = {
            "/": (200, BAD_HEADERS_PAGE),
            "/admin": (200, ADMIN_PAGE),
            "/.git/config": (200, GIT_CONFIG),
            "/.env": (200, ENV_FILE),
            "/readme.txt": (200, README, "text/plain"),
            "/server-status": (200, "Apache Server Status for 127.0.0.1\n"),
        }
        if path in routes:
            route = routes[path]
            self._respond(route[0], route[1], route[2] if len(route) > 2 else "text/html")
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
