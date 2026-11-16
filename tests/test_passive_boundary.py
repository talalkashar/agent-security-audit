"""Exercise the runner's authorization boundary with real checks and offline I/O."""

import unittest
from unittest import mock
from urllib.parse import urlsplit

from agent_security_audit import catalog, runner
from agent_security_audit.checks import load_all
from agent_security_audit.http import Client, Response
from tests.test_network import FakeTLS, cert


class BoundaryClient(Client):
    """Keep the HTTP interface, but record operations instead of opening connections."""

    def __init__(self, target):
        super().__init__(target, delay=0)
        self.requests = []
        self.ports = []
        self.tls = []

    def _addresses(self):
        return ["192.0.2.10"]

    def _send(self, method, url, headers, body, cache, verify=False):
        self.requests.append((method, url, headers or {}, body, verify))
        self._spend()
        path = urlsplit(url).path
        if "dns-query?" in url:
            status, content_type, payload = 200, "application/dns-json", b'{"Status":0,"Answer":[]}'
        elif path == "/":
            status, content_type, payload = 200, "text/html", (
                b'<html><a href="/login?next=/account">Login</a>'
                b'<script src="/app.js"></script></html>'
            )
        elif path == "/app.js":
            status, content_type, payload = 200, "application/javascript", b'fetch("/api/items")'
        elif path == "/api/auth/login":
            status, content_type, payload = 401, "application/json", b'{}'
        else:
            status, content_type, payload = 404, "text/plain", b"Not found"
        return Response(url, status, "", [("Content-Type", content_type)], payload)

    def probe_port(self, port, timeout=2.0):
        self.ports.append(port)
        self._spend()
        return "closed"

    def open_tls(self, context):
        self.tls.append(context)
        self._spend()
        return FakeTLS(cert())


class PassiveBoundaryTest(unittest.TestCase):
    def run_checks(self, *, owned=False, ids=None):
        registry = load_all()
        checks = {c.id: c for c in catalog.load() if c.mode == "auto"}
        self.assertEqual(set(registry), set(checks))
        spies = {cid: mock.Mock(wraps=fn) for cid, fn in registry.items()}
        client = BoundaryClient("https://boundary.example")
        # Fail closed even if a future check bypasses the client. Inspect these mocks
        # afterwards too: the runner converts exceptions into result objects.
        with mock.patch.object(runner, "RecordingClient", return_value=client), \
                mock.patch.object(runner, "load_all", return_value=spies), \
                mock.patch("socket.socket", side_effect=AssertionError("real socket forbidden")) as sockets, \
                mock.patch("socket.getaddrinfo", side_effect=AssertionError("real DNS forbidden")) as dns:
            _, results = runner.run(
                client.target, authorized=owned, include_manual=False, ids=ids,
                options={"rate_limit_path": "/api/auth/login", "rate_limit_attempts": 1,
                         "rate_limit_body": "{}"},
            )
        sockets.assert_not_called()
        dns.assert_not_called()
        self.assertFalse([(r.check_id, r.summary) for r in results if r.status == "error"])
        self.assertEqual({r.check_id for r in results}, set(ids) if ids else set(checks))
        return checks, spies, client, {r.check_id: r for r in results}

    def assert_read_only(self, client):
        self.assertTrue(client.requests, "the runner must actually fetch the target")
        self.assertEqual(client.ports, [], "unauthorized execution attempted a port probe")
        self.assertEqual(
            [(m, u) for m, u, _, _, _ in client.requests if m not in ("GET", "HEAD")], [],
            "unauthorized execution attempted a non-read HTTP method",
        )
        self.assertEqual(
            [(m, u) for m, u, _, body, external in client.requests
             if external and (m not in ("GET", "HEAD") or body is not None)], [],
            "unauthorized execution attempted an external write",
        )

    def test_unowned_run_never_calls_active_checks(self):
        checks, spies, client, results = self.run_checks()
        active = {cid for cid, check in checks.items() if check.probe == "active"}
        self.assertTrue(active)
        self.assertTrue(set(checks) - active)
        for cid, spy in spies.items():
            with self.subTest(check=cid):
                if cid in active:
                    spy.assert_not_called()
                    self.assertEqual(results[cid].status, "skip")
                    self.assertIn("--authorized", results[cid].summary)
                else:
                    spy.assert_called_once()
                    self.assertFalse(spy.call_args.args[0].owned)
                    self.assertFalse(spy.call_args.args[0].authorized)
        self.assert_read_only(client)
        # DNS reads and TLS observations are allowed; do not turn passive into no I/O.
        self.assertTrue(any(external for _, _, _, _, external in client.requests))
        self.assertTrue(client.tls)

    def test_explicit_selection_does_not_bypass_active_gate(self):
        active = [c.id for c in catalog.load() if c.mode == "auto" and c.probe == "active"]
        self.assertTrue(active)
        for cid in active:
            with self.subTest(check=cid):
                _, spies, client, results = self.run_checks(ids=[cid])
                for spy in spies.values():
                    spy.assert_not_called()
                self.assertEqual(results[cid].status, "skip")
                self.assertIn("--authorized", results[cid].summary)
                self.assert_read_only(client)
                self.assertEqual(len(client.requests), 1)  # canonical root fetch only
                self.assertEqual(client.tls, [])

    def test_owned_positive_control_reaches_active_operations(self):
        # Same offline fixture with only ownership changed: it must be capable of
        # exposing a missing gate, including active GETs that a method filter misses.
        checks, spies, client, _ = self.run_checks(owned=True)
        for cid in checks:
            with self.subTest(check=cid):
                spies[cid].assert_called_once()
                self.assertTrue(spies[cid].call_args.args[0].owned)
                self.assertTrue(spies[cid].call_args.args[0].authorized)
        self.assertTrue(client.ports)
        self.assertTrue({"POST", "TRACE"} <= {m for m, _, _, _, _ in client.requests})


if __name__ == "__main__":
    unittest.main()
