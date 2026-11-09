"""The practice lab: every automated check fails or warns on `vulnerable` and passes on `fixed` over local HTTP."""

import unittest
from unittest import mock

from agent_security_audit import lab, runner
from agent_security_audit.checks import load_all

# Over plain HTTP on a local host these have nothing to test. The lab ships no Supabase project URL, so ACCESS-01
# never leads a practice scan off the machine.
SKIP_LOCAL = {"INFRA-01", "INFRA-02", "INFRA-03", "INFRA-06", "INFRA-07", "BROWSER-01", "BROWSER-20", "ACCESS-01",
              "INFRA-11", "INFRA-12", "INFRA-24", "INFRA-25", "INFRA-26", "INFRA-27", "INFRA-28"}
SKIP_LOCAL.update({"CMS-02", "CMS-03"})  # This lab is not a CMS; CMS fixtures live in test_cms.py.
MANUAL = {"CMS-01", "CMS-04"}  # No CMS markers: absence does not prove disclosure/login protection.
# The lab names no Next.js version, so no practice scan sends anything to OSV; live NEXT-04 never passes anyway.
MANUAL.add("NEXT-04")


def scan(url):
    _, results = runner.run(url, options={"rate_limit_path": "/api/login"}, include_manual=False, delay=0)
    return {r.check_id: r for r in results}


class LabTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.results = {}
        for mode in lab.MODES:
            server, url = lab.serve(mode, 0)
            try:
                cls.results[mode] = scan(url)
            finally:
                server.shutdown()
                server.server_close()

    def test_every_auto_check_ran(self):
        for mode in lab.MODES:
            self.assertEqual(set(self.results[mode]), set(load_all()))

    def test_vulnerable_fails(self):
        for cid, r in self.results["vulnerable"].items():
            with self.subTest(check=cid):
                if cid in SKIP_LOCAL:
                    self.assertEqual(r.status, "skip", r.summary)
                elif cid in MANUAL:
                    self.assertEqual(r.status, "manual", r.summary)
                else:
                    self.assertIn(r.status, ("fail", "warn"), r.summary)

    def test_fixed_passes(self):
        for cid, r in self.results["fixed"].items():
            with self.subTest(check=cid):
                if cid in SKIP_LOCAL:
                    self.assertEqual(r.status, "skip", r.summary)
                elif cid in MANUAL:
                    self.assertEqual(r.status, "manual", r.summary)
                else:
                    self.assertEqual(r.status, "pass", r.summary)

    def test_secrets_masked_in_evidence(self):
        r = self.results["vulnerable"]["NEXT-01"]
        self.assertTrue(any("service_role" in e for e in r.evidence))
        self.assertFalse(any(lab.fake_jwt("service_role") in e for e in r.evidence))

    def test_post_with_a_bad_content_length_still_answers(self):
        import socket
        server, _ = lab.serve("fixed", 0)
        try:
            for length in (b"-1", b"abc"):
                with socket.create_connection(("127.0.0.1", server.server_address[1]), timeout=3) as sock:
                    sock.sendall(b"POST /api/login HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: " + length
                                 + b"\r\n\r\n")
                    self.assertTrue(sock.recv(64).startswith(b"HTTP/1."), length)
        finally:
            server.shutdown()
            server.server_close()

    def test_serve_rejects_unknown_mode(self):
        with self.assertRaises(ValueError):
            lab.serve("broken", 0)

    def test_windows_reserves_port_before_binding(self):
        server = object.__new__(lab.LabServer)
        server.socket = mock.Mock()
        events = []
        server.socket.setsockopt.side_effect = lambda *args: events.append("exclusive")
        with mock.patch.object(lab.socket, "SO_EXCLUSIVEADDRUSE", -5, create=True), \
                mock.patch.object(lab.ThreadingHTTPServer, "server_bind", side_effect=lambda: events.append("bind")):
            server.server_bind()
        server.socket.setsockopt.assert_called_once_with(lab.socket.SOL_SOCKET, -5, 1)
        self.assertEqual(events, ["exclusive", "bind"])


if __name__ == "__main__":
    unittest.main()
