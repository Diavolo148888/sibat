"""The SIBAT exploit lab — vulnerable targets for the exploit modules.

LOCALHOST ONLY. Endpoints implemented here deliberately answer with
proof-of-exploit markers so the exploit modules confirm against them:

  :8083/download?file=...   path traversal — serves /etc/passwd-style proof
  :8083/search?q=...        command injection — echoes the marker back
  :8084/go?url=...          open redirect — 302 to the requested target

Nothing destructive: the "command injection" endpoint echoes the marker
string, it never runs a command. The "traversal" endpoint returns a
synthetic passwd-style proof, not the real file. Never expose to a network.
"""

import http.server
import random
import re
import sys

FAKE_PASSWD = "\n".join([
    "root:x:0:0:root:/root:/bin/bash",
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
    "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin",
    "mako:x:1000:1000:mako:/home/mako:/bin/bash",
])


class ExploitHandler(http.server.BaseHTTPRequestHandler):
    server_version = "VulnLab/1.0"

    def log_message(self, fmt, *args):
        sys.stderr.write("[vulapp2] %s\n" % (fmt % args))

    def _respond(self, code, body, ctype="text/html", extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        for k, v in (extra or []):
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self):
        path, _, query = self.path.partition("?")
        params = {}
        for pair in query.split("&"):
            if "=" in pair:
                k, _, v = pair.partition("=")
                params[k] = v

        if path == "/download":
            f = params.get("file", "")
            # traversal proof: unescape and check the classic target
            target = re.sub(r"(\.\./)+", "", f.replace("%2f", "/").replace("%2F", "/"))
            if "etc/passwd" in target:
                self._respond(200, FAKE_PASSWD, "text/plain")
            else:
                self._respond(404, "not found")

        elif path == "/search":
            q = params.get("q", "")
            # command-injection proof: the marker echoes back (never executed)
            self._respond(200, f"searching for: {q}\nno results\n", "text/plain")

        elif path == "/go":
            url = params.get("url", "")
            if url:
                self._respond(302, "", extra=[("Location", url)])
            else:
                self._respond(200, "usage: /go?url=")

        elif path == "/":
            self._respond(200, "<html><body><h1>VulnLab</h1>"
                               "<p>/download, /search, /go</p></body></html>")
        else:
            self._respond(404, "not found")

    do_HEAD = do_GET


def main(port=8083):
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", port), ExploitHandler)
    print(f"[vulapp2] exploit lab on 127.0.0.1:{port} — localhost only")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n[vulapp2] down")


if __name__ == "__main__":
    main(int(sys.argv[1]) if len(sys.argv) > 1 else 8083)
