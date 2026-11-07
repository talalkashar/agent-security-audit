"""Scope gate, the bounded HTTP client, canonical target handling and how the runner reacts to blocks and budgets."""

import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

from agent_security_audit import lab, runner, scope
from agent_security_audit.http import Blocked, BudgetExceeded, Client, OffTarget, Response, challenge_of


def resp(status=200, headers=()):
    return Response("https://example.com/", status, "", list(headers), b"")


class RootStub:
    def __init__(self, root):
        self.root = root

    def get(self, path="/", **kw):
        return self.root


class ChallengeHandler(BaseHTTPRequestHandler):
    """Home page is normal; paths listed in `challenged` answer with a firewall challenge."""
    challenged = ()
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def do_GET(self):
        hit = self.path.split("?")[0] in self.challenged or "*" in self.challenged
        status = 403 if hit else 200
        self.send_response(status)
        if hit:
            self.send_header("x-vercel-mitigated", "challenge")
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", "0")
        self.end_headers()


def serve_challenge(paths):
    handler = type("H", (ChallengeHandler,), {"challenged": tuple(paths)})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"


class ScopeTest(unittest.TestCase):
    def test_local_hosts(self):
        for host in ("localhost", "LOCALHOST", "app.localhost", "site.test", "127.0.0.1", "::1", "[::1]", "127.8.9.1"):
            self.assertTrue(scope.is_local_host(host), host)
        for host in ("example.com", "localhost.example.com", "10.0.0.1", "test.com", "192.168.1.1"):
            self.assertFalse(scope.is_local_host(host), host)

    def test_normalize(self):
        self.assertEqual(scope.normalize_target("example.com/path?q=1"), "https://example.com")
        self.assertEqual(scope.normalize_target("http://LOCALHOST:3000/x"), "http://localhost:3000")
        self.assertEqual(scope.normalize_target("http://[::1]:8080"), "http://[::1]:8080")
        # A bare local host:port is a dev server, which speaks plain HTTP.
        self.assertEqual(scope.normalize_target("localhost:3000"), "http://localhost:3000")
        self.assertEqual(scope.normalize_target("127.0.0.1:8642/x"), "http://127.0.0.1:8642")
        self.assertEqual(scope.normalize_target("example.com:8443"), "https://example.com:8443")

    def test_local_suffix_must_resolve_locally(self):
        def fake(addr):
            return lambda host, port: [(2, 1, 6, "", (addr, 0))]
        with mock.patch("socket.getaddrinfo", fake("8.8.8.8")), self.assertRaises(scope.ScopeError) as cm:
            scope.check_authorized("http://evil.test", False)
        self.assertIn("8.8.8.8", str(cm.exception))
        with mock.patch("socket.getaddrinfo", fake("8.8.8.8")):
            scope.check_authorized("http://evil.test", True)
        for addr in ("127.0.0.1", "192.168.1.20", "::1"):
            with self.subTest(addr=addr), mock.patch("socket.getaddrinfo", fake(addr)):
                scope.check_authorized("http://site.test", False)
                scope.check_authorized("http://app.localhost", False)

    def test_rejects_credentials_and_schemes(self):
        for url in ("http://user:pw@localhost:3000", "https://user@example.com", "ftp://localhost",
                    "file:///etc/passwd", "javascript://localhost", "http://"):
            with self.subTest(url=url), self.assertRaises(scope.ScopeError):
                scope.normalize_target(url)

    def test_non_local_needs_authorized(self):
        with self.assertRaises(scope.ScopeError):
            scope.check_authorized("https://example.com", False)
        scope.check_authorized("https://example.com", True)
        scope.check_authorized("http://localhost:3000", False)

    def test_run_refuses_before_any_request(self):
        self.assertFalse(scope.owned("https://example.com", False))
        self.assertTrue(scope.owned("https://example.com", True))
        self.assertTrue(scope.owned("http://localhost:3000", False))
        with self.assertRaises(scope.ScopeError):
            runner.run("http://user:pw@localhost:9", ids=["NEXT-03"])

    def test_same_origin(self):
        self.assertTrue(scope.same_origin("https://a.test", "https://a.test/x"))
        self.assertFalse(scope.same_origin("https://a.test", "http://a.test/x"))
        self.assertFalse(scope.same_origin("https://a.test", "https://a.test:8443/x"))
        self.assertFalse(scope.same_origin("https://a.test", "https://b.test/"))


class ClientTest(unittest.TestCase):
    def test_refuses_off_origin(self):
        c = Client("http://127.0.0.1:9", delay=0)
        for url in ("http://evil.example/", "https://127.0.0.1:9/", "http://127.0.0.1:10/"):
            with self.subTest(url=url), self.assertRaises(OffTarget):
                c.get(url)
        self.assertEqual(c.sent, 0)
        self.assertEqual(c.url("//evil.example/x"), "http://127.0.0.1:9/evil.example/x")

    def test_same_host_and_external_guards(self):
        c = Client("https://localhost:9", delay=0)
        with self.assertRaises(OffTarget):
            c.same_host("GET", "http://other.test/")
        with self.assertRaises(OffTarget):
            c.external("GET", "http://dns.example/")
        self.assertEqual(c.sent, 0)

    def test_insecure_only_for_local(self):
        Client("https://localhost:8443", insecure=True)
        Client("https://site.test", insecure=True)
        with self.assertRaises(ValueError):
            Client("https://example.com", insecure=True)

    def test_tls_connections_count_against_budget(self):
        import ssl
        with self.assertRaises(BudgetExceeded):
            Client("https://localhost:9", budget=0, delay=0).open_tls(ssl.create_default_context())
        with self.assertRaises(OffTarget):
            Client("http://localhost:9", delay=0).open_tls(ssl.create_default_context())

    def test_budget(self):
        server, url = lab.serve("fixed", 0)
        try:
            c = Client(url, budget=2, delay=0)
            c.get("/")
            c.get("/")
            from agent_security_audit.http import BudgetExceeded
            with self.assertRaises(BudgetExceeded):
                c.get("/")
            self.assertEqual(c.sent, 2)
        finally:
            server.shutdown()
            server.server_close()

    def test_challenge_detection(self):
        self.assertIsNone(challenge_of(resp(200)))
        self.assertIsNone(challenge_of(resp(200, [("cf-mitigated", "none")])))
        self.assertTrue(challenge_of(resp(403, [("x-vercel-mitigated", "challenge")])))
        self.assertTrue(challenge_of(resp(403, [("cf-mitigated", "challenge")])))
        self.assertTrue(challenge_of(resp(429, [("x-vercel-challenge-token", "abc")])))
        self.assertIsNone(challenge_of(resp(200, [("x-vercel-challenge-token", "abc")])))

    def test_client_raises_blocked(self):
        server, url = serve_challenge(["*"])
        try:
            with self.assertRaises(Blocked):
                Client(url, delay=0).get("/")
        finally:
            server.shutdown()
            server.server_close()


class CanonicalTargetTest(unittest.TestCase):
    def test_no_redirect(self):
        self.assertEqual(runner.canonical_target("https://example.com", RootStub(resp(200))), "https://example.com")

    def test_same_origin_redirect_kept(self):
        stub = RootStub(resp(307, [("Location", "/en")]))
        self.assertEqual(runner.canonical_target("https://example.com", stub), "https://example.com")

    def test_www_twin_followed(self):
        stub = RootStub(resp(308, [("Location", "https://www.example.com/")]))
        self.assertEqual(runner.canonical_target("https://example.com", stub), "https://www.example.com")
        stub = RootStub(resp(301, [("Location", "https://example.com/")]))
        self.assertEqual(runner.canonical_target("https://www.example.com", stub), "https://example.com")

    def test_http_to_https_twin_followed(self):
        stub = RootStub(resp(301, [("Location", "https://www.example.com/")]))
        self.assertEqual(runner.canonical_target("http://example.com", stub), "https://www.example.com")

    def test_ip_has_no_www_twin(self):
        stub = RootStub(resp(308, [("Location", "https://www.127.0.0.1:8443/")]))
        with self.assertRaises(scope.ScopeError):
            runner.canonical_target("https://127.0.0.1:8443", stub)

    def test_off_site_redirect_refused(self):
        for loc in ("https://evil.example/", "https://login.example.com/", "http://www.example.com/",
                    "https://www.example.com.evil.example/"):
            stub = RootStub(resp(302, [("Location", loc)]))
            with self.subTest(loc=loc), self.assertRaises(scope.ScopeError):
                runner.canonical_target("https://example.com", stub)


class RunnerTest(unittest.TestCase):
    def test_challenge_on_home_aborts(self):
        server, url = serve_challenge(["*"])
        try:
            with self.assertRaises(scope.ScopeError) as cm:
                runner.run(url, ids=["NEXT-03"], delay=0)
            self.assertIn("challenge", str(cm.exception))
        finally:
            server.shutdown()
            server.server_close()

    def test_challenge_mid_scan_aborts(self):
        server, url = serve_challenge(["/.env"])
        try:
            with self.assertRaises(scope.ScopeError):
                runner.run(url, ids=["NEXT-03", "INFRA-04"], delay=0)
        finally:
            server.shutdown()
            server.server_close()

    def test_unreachable_is_scope_error(self):
        server, url = lab.serve("fixed", 0)
        server.shutdown()
        server.server_close()
        with self.assertRaises(scope.ScopeError):
            runner.run(url, ids=["NEXT-03"], delay=0, timeout=2)

    def test_budget_exceeded_is_error_result(self):
        server, url = lab.serve("fixed", 0)
        try:
            _, results = runner.run(url, ids=["INFRA-04"], budget=3, delay=0)
        finally:
            server.shutdown()
            server.server_close()
        self.assertEqual([(r.check_id, r.status) for r in results], [("INFRA-04", "error")])
        self.assertIn("budget", results[0].summary)

    def test_select_and_manual(self):
        chosen = runner.select(stacks=["supabase"])
        self.assertTrue(chosen)
        self.assertTrue(all({"any", "supabase"} & set(c.stacks) for c in chosen))
        with self.assertRaises(runner.catalog.CatalogError):
            runner.select(ids=["NOPE-01"])
        _, results = runner.run("http://localhost:9", ids=["AUTH-01"])
        self.assertEqual([r.status for r in results], ["manual"])


if __name__ == "__main__":
    unittest.main()
