"""A local practice site in two modes, used by the tests and by `asa lab`.

`vulnerable` makes every automated check fail (or warn where warn is its ceiling); `fixed` makes every one pass
(or skip where it needs HTTPS or DNS). tests/test_lab_e2e.py lists the exact expected status of each check.
All "secrets" here are built at runtime from fake parts and are not valid credentials anywhere.
It listens on 127.0.0.1 only.
"""

from __future__ import annotations

import base64
import json
import secrets
import threading
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

MODES = ("vulnerable", "fixed")


def _b64(obj):
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")


def fake_jwt(role):
    return ".".join([_b64({"alg": "HS256", "typ": "JWT"}), _b64({"iss": "supabase", "role": role, "ref": "x" * 20}),
                     "fakesignature" + "0" * 20])


# No Supabase project URL on purpose: any valid-looking *.supabase.co name could belong to a real project, and the
# lab must never lead a scan off this machine. ACCESS-01 therefore reports "not applicable" here.


def vulnerable_js():
    stripe = "sk_" + "live_" + "FAKE0000000000000000000000"
    return (f'const anon="{fake_jwt("anon")}";\n'
            f'const admin="{fake_jwt("service_role")}";const pay="{stripe}";\n'
            "console.log(anon, admin, pay);\n//# sourceMappingURL=app.js.map\n")


def fixed_js():
    return f'const anon="{fake_jwt("anon")}";console.log(anon);\n'


STACK = ("Error: lookup failed\n    at handler (/var/task/.next/server/app/api/route.js:12:9)\n"
         "    at process.processTicksAndRejections (node:internal/process/task_queues:95:5)\n")


# --- crawl and web-app fixtures (BROWSER-20..23, API-19..24) -------------------------------------------------------
# Pages reachable from the home page, robots.txt and sitemap.xml, so the scanner's crawl has a site to walk.
# The third-party host and the login form's action use the reserved .invalid TLD: nothing here ever resolves, and
# the scanner never requests another origin anyway. The jQuery files are version banners only, not the library.

LAB_THIRD_PARTY = "https://cdn.asa-lab.invalid/widget.js"
LAB_SRI = "sha384-" + "A" * 64  # fake hash, the file does not exist


def crawl_home_extra(vuln):
    script = (f'<script src="{LAB_THIRD_PARTY}"></script>' if vuln else
              f'<script src="{LAB_THIRD_PARTY}" integrity="{LAB_SRI}" crossorigin="anonymous"></script>')
    return (script + '<nav><a href="/about">About</a> <a href="/login">Log in</a> '
            '<a href="/redirect?url=/about">Continue</a> <a href="/logout">Log out</a></nav>')


def _page(title, body):
    return f"<!doctype html><html><head><title>{title}</title></head><body>{body}</body></html>"


def crawl_route(handler, path, query, vuln):
    """Answer a crawl fixture GET, or return False when the path is not one."""
    host = handler.headers.get("Host", "127.0.0.1")
    if path == "/robots.txt":
        handler._send(200, f"User-agent: *\nAllow: /\nSitemap: http://{host}/sitemap.xml\n", "text/plain")
    elif path == "/sitemap.xml":
        locs = "".join(f"<url><loc>http://{host}{p}</loc></url>" for p in ("/about", "/contact"))
        handler._send(200, f'<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
                      f"{locs}</urlset>", "application/xml")
    elif path == "/about":
        version = "3.4.1" if vuln else "3.7.1"
        handler._send(200, _page("About", f'<script src="/static/vendor/jquery-{version}.min.js"></script>'
                                 '<p>About the lab.</p><a href="/">Home</a>'))
    elif path == "/contact":
        handler._send(200, _page("Contact", '<p>Write to security@example.test.</p>'))
    elif path.startswith("/static/vendor/jquery-") and path.endswith(".min.js"):
        version = path.removeprefix("/static/vendor/jquery-").removesuffix(".min.js")
        if version not in ("3.4.1", "3.7.1"):
            return False
        handler._send(200, f"/*! jQuery v{version} | (c) OpenJS Foundation and other contributors | "
                      "jquery.org/license */\nwindow.labJquery=true;\n", "application/javascript")
    elif path == "/login":
        form = ('<form method="post" action="http://login.asa-lab.invalid/session">' if vuln else
                '<form method="post" action="/api/login">')
        handler._send(200, _page("Log in", form + '<input name="email" type="email">'
                                 '<input name="password" type="password"><button>Log in</button></form>'))
    elif path == "/redirect":
        dest = (parse_qs(query).get("url") or ["/"])[0]
        if not vuln and not (dest.startswith("/") and not dest.startswith(("//", "/\\"))):
            dest = "/"
        handler._send(302, "", extra=[("Location", dest)])
    elif path == "/logout":
        handler._send(200, _page("Logged out", "<p>Logged out.</p>"))
    elif vuln and path == "/uploads/":
        handler._send(200, "<html><head><title>Index of /uploads/</title></head><body><h1>Index of /uploads/</h1>"
                      '<a href="report.pdf">report.pdf</a></body></html>')
    elif vuln and path == "/actuator/env":
        handler._send(200, json.dumps({"activeProfiles": ["lab"], "propertySources": [
            {"name": "lab", "properties": {"LAB_SETTING": {"value": "not-a-secret"}}}]}), "application/json")
    elif vuln and path == "/openapi.json":
        handler._send(200, json.dumps({"openapi": "3.0.0", "info": {"title": "lab", "version": "1"},
                                       "paths": {"/api/login": {}}}), "application/json")
    else:
        return False
    return True


GRAPHQL_SCHEMA = {"data": {"__schema": {"queryType": {"name": "Query"}, "mutationType": {"name": "Mutation"},
                                        "types": [{"name": "Query"}, {"name": "Mutation"}, {"name": "String"}]}}}
GRAPHQL_REFUSED = {"errors": [{"message": "GraphQL introspection is not allowed"}]}

# --- end of crawl and web-app fixtures -----------------------------------------------------------------------------


class LabHandler(BaseHTTPRequestHandler):
    mode = "fixed"
    login_attempts = 0
    lock = threading.Lock()
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):  # keep test output quiet
        pass

    def version_string(self):
        # The vulnerable lab names its server and Python versions in Server (API-25); the fixed lab sends a bare name.
        return super().version_string() if self.mode == "vulnerable" else "asa-lab"

    # --- helpers -------------------------------------------------------------------------------------------------
    def _send(self, status, body=b"", ctype="text/html; charset=utf-8", extra=None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in self._security_headers():
            self.send_header(k, v)
        for k, v in extra or []:
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _security_headers(self):
        origin = self.headers.get("Origin")
        if self.mode == "vulnerable":
            out = [("X-Powered-By", "Next.js"), ("Referrer-Policy", "unsafe-url")]
            if origin:
                out += [("Access-Control-Allow-Origin", origin), ("Access-Control-Allow-Credentials", "true")]
            return out
        nonce = secrets.token_urlsafe(16)
        return [
            ("Content-Security-Policy", (f"default-src 'self'; script-src 'self' 'nonce-{nonce}' 'strict-dynamic'; "
             "object-src 'none'; base-uri 'none'; frame-ancestors 'none'")),
            ("X-Content-Type-Options", "nosniff"),
            ("X-Frame-Options", "DENY"),
            ("Referrer-Policy", "strict-origin-when-cross-origin"),
            ("Permissions-Policy", "camera=(), microphone=(), geolocation=()"),
            ("Cross-Origin-Opener-Policy", "same-origin"),
        ]

    def _home(self):
        cookie = ("session=lab123; Path=/" if self.mode == "vulnerable"
                  else "session=lab123; Path=/; Secure; HttpOnly; SameSite=Lax")
        html = ('<!doctype html><html><head><title>Lab</title>'
                '<script src="/_next/static/chunks/app.js"></script></head><body>agent-security-audit lab'
                + crawl_home_extra(self.mode == "vulnerable") + '</body></html>')
        self._send(200, html, extra=[("Set-Cookie", cookie)])

    # --- routes --------------------------------------------------------------------------------------------------
    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        path = self.path.split("?")[0]
        vuln = self.mode == "vulnerable"
        if path == "/":
            return self._home()
        if crawl_route(self, path, self.path.partition("?")[2], vuln):
            return None
        if path == "/_next/static/chunks/app.js":
            return self._send(200, vulnerable_js() if vuln else fixed_js(), "application/javascript")
        if vuln and path == "/_next/static/chunks/app.js.map":
            return self._send(200, '{"version":3,"sources":["app.ts"],"mappings":"AAAA"}', "application/json")
        if vuln and path == "/.env":
            return self._send(200, "DATABASE_URL=postgres://lab:lab@localhost/lab\nSTRIPE_KEY=fake\n", "text/plain")
        if vuln and path == "/.git/HEAD":
            return self._send(200, "ref: refs/heads/main\n", "text/plain")
        if not vuln and path == "/.well-known/security.txt":
            expires = (datetime.now(UTC) + timedelta(days=180)).strftime("%Y-%m-%dT%H:%M:%SZ")
            return self._send(200, f"Contact: mailto:security@example.test\nExpires: {expires}\n", "text/plain")
        if vuln:
            return self._send(404, f"<pre>{STACK}</pre>")
        # The fixed site behaves like a single-page app: unknown paths get the app shell, not the file.
        return self._send(200, "<!doctype html><html><body>Not found</body></html>")

    def do_TRACE(self):
        if self.mode != "vulnerable":
            return self._send(405, "", extra=[("Allow", "GET, HEAD, POST")])
        echo = f"{self.requestline}\r\n" + "".join(f"{k}: {v}\r\n" for k, v in self.headers.items())
        return self._send(200, echo, "message/http")

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(min(length, 65536))
        path = self.path.split("?")[0]
        vuln = self.mode == "vulnerable"
        if path in ("/graphql", "/api/graphql"):
            return self._send(200, json.dumps(GRAPHQL_SCHEMA if vuln else GRAPHQL_REFUSED), "application/json")
        if path == "/api/login":
            cls = type(self)
            with cls.lock:
                cls.login_attempts += 1
                n = cls.login_attempts
            if not vuln and n > 5:
                return self._send(429, '{"error":"too many attempts"}', "application/json", [("Retry-After", "60")])
            return self._send(401, '{"error":"invalid credentials"}', "application/json")
        if vuln:
            return self._send(500, STACK, "text/plain")
        return self._send(400, '{"error":"bad request"}', "application/json")


def serve(mode="fixed", port=0):
    """Start the lab in a background thread. Returns (server, base_url); call server.shutdown() to stop."""
    if mode not in MODES:
        raise ValueError(f"mode must be one of {MODES}")
    handler = type("Handler", (LabHandler,), {"mode": mode, "login_attempts": 0, "lock": threading.Lock()})
    server = ThreadingHTTPServer(("127.0.0.1", port), handler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"
