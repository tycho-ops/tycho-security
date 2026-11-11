"""Mock services for the live credentials tests (neutral domain acme)."""
import base64
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = int(sys.argv[1])
NAMESPACE = sys.argv[2]
# acme-server: factory account renamed (compliant); console: bootstrap login kept
ACCOUNTS = {"acme": {("acme-ops-4f2a", "Deployed-Passw0rd!")}, "console": {("admin", "console-deployed-pass")}}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def reply(self, code, body):
        self.send_response(code)
        self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self):
        if self.path == "/api/auth/validate":
            pair = None
            header = self.headers.get("Authorization", "")
            if header.startswith("Basic "):
                login, _, password = base64.b64decode(header[6:]).decode().partition(":")
                pair = (login, password)
            self.reply(200, '{"valid":%s}' % ("true" if pair in ACCOUNTS[NAMESPACE] else "false"))
        else:
            self.reply(200, "ok")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        form = urllib.parse.parse_qs(self.rfile.read(length).decode())
        pair = (form.get("username", [""])[0], form.get("password", [""])[0])
        self.reply(200 if pair in ACCOUNTS[NAMESPACE] else 401, "{}")


HTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
