"""Network, TLS and DNS depth checks (INFRA-02 expiry, 11, 12, 24-28), driven by fakes. The only real sockets are
ephemeral listeners on 127.0.0.1."""

import json
import socket
import ssl
import unittest
from datetime import UTC, datetime, timedelta
from unittest import mock

from agent_security_audit.checks import Context, network, transport
from agent_security_audit.http import BudgetExceeded, Client, Response


def resp(status=200, body="", headers=()):
    return Response("https://example.com/", status, "", list(headers), body.encode())


class FakeTLS:
    def __init__(self, cert=None, cipher="ECDHE-RSA-AES128-GCM-SHA256"):
        self.cert, self._cipher = cert, cipher

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def getpeercert(self):
        return self.cert

    def version(self):
        return "TLSv1.3"

    def cipher(self):
        return (self._cipher, "TLSv1.2", 128)


class FakeClient:
    """dns: {(name, TYPE): {"Status":..,"AD":..,"Answer":[..]}} plus (name, TYPE, "cd") for checking-disabled queries.
    pages: {url: Response or exception}. ports: {port: state}. tls: callable(context) -> FakeTLS or raise."""

    timeout = 1.0

    def __init__(self, target, dns=None, pages=None, ports=None, tls=None, home=""):
        self.target, self.dns, self.pages, self.ports, self.tls = target, dns or {}, pages or {}, ports or {}, tls
        self.home_body = home
        self.calls = []

    def external(self, method, url, *, headers=None, body=None):
        self.calls.append(url)
        if "dns-query?" in url:
            q = dict(p.split("=", 1) for p in url.split("?", 1)[1].split("&"))
            key = (q["name"], q["type"]) + (("cd",) if q.get("cd") == "1" else ())
            return resp(200, json.dumps(self.dns.get(key, {"Status": 0})), [("Content-Type", "application/dns-json")])
        page = self.pages.get(url, resp(404))
        if isinstance(page, Exception):
            raise page
        return page

    def home(self):
        self.calls.append("home")
        return resp(200, self.home_body)

    def target_address(self):
        return "203.0.113.7"

    def probe_port(self, port, timeout=2.0):
        self.calls.append(port)
        return self.ports.get(port, "filtered")

    def open_tls(self, context):
        self.calls.append("tls")
        return self.tls(context)


def ctx(target="https://example.com", **kw):
    options = kw.pop("options", {})
    return Context(target, FakeClient(target, **kw), options, authorized=True)


def ans(name, rtype, *data):
    return [{"name": name, "type": rtype, "data": d} for d in data]


def cert(issuer="Let's Encrypt", sans=("example.com", "www.example.com"), days_left=60, lifetime=90):
    now = datetime.now(UTC)
    fmt = "%b %d %H:%M:%S %Y GMT"
    return {"issuer": ((("organizationName", issuer),),), "subjectAltName": tuple(("DNS", s) for s in sans),
            "notAfter": (now + timedelta(days=days_left, hours=1)).strftime(fmt),
            "notBefore": (now + timedelta(days=days_left - lifetime, hours=1)).strftime(fmt)}


# --- ports -------------------------------------------------------------------------------------------------------

class PortsTest(unittest.TestCase):
    def test_all_closed_passes(self):
        c = ctx(ports={5432: "closed"})
        r = network.data_ports(c)
        self.assertEqual(r.status, "pass", r.summary)
        self.assertEqual(set(c.client.calls), set(network.DATA_PORTS))
        self.assertTrue(any("203.0.113.7:5432" in e for e in r.evidence))

    def test_open_database_fails(self):
        r = network.data_ports(ctx(ports={5432: "open", 6379: "open"}))
        self.assertEqual(r.status, "fail")
        self.assertIn("5432 (PostgreSQL)", r.summary)
        self.assertIn("6379 (Redis)", r.summary)

    def test_every_port_open_is_manual(self):
        r = network.data_ports(ctx(ports={5432: "open", network.CONTROL_PORT: "open"}))
        self.assertEqual(r.status, "manual")

    def test_ssh_warns_rdp_fails(self):
        self.assertEqual(network.admin_ports(ctx(ports={22: "open"})).status, "warn")
        self.assertEqual(network.admin_ports(ctx(ports={22: "open", 3389: "open"})).status, "fail")
        self.assertEqual(network.admin_ports(ctx()).status, "pass")

    def test_each_port_probed_once_per_run(self):
        c = ctx(ports={22: "open"})
        network.data_ports(c)
        network.admin_ports(c)
        network.admin_ports(c)
        probed = [x for x in c.client.calls if isinstance(x, int)]
        self.assertEqual(len(probed), len(set(probed)))

    def test_skips_without_connecting(self):
        for target, options in (("http://localhost:3000", {}), ("https://app.test", {}), ("http://127.0.0.1:8000", {}),
                                ("https://example.com", {"no_ports": True})):
            with self.subTest(target=target):
                c = ctx(target, options=options, ports={5432: "open"})
                self.assertEqual(network.data_ports(c).status, "skip")
                self.assertEqual(network.admin_ports(c).status, "skip")
                self.assertEqual(c.client.calls, [])


class ProbePortTest(unittest.TestCase):
    """The real Client against ephemeral listeners on 127.0.0.1."""

    def setUp(self):
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen()
        self.open_port = self.listener.getsockname()[1]
        spare = socket.socket()
        spare.bind(("127.0.0.1", 0))
        self.closed_port = spare.getsockname()[1]
        spare.close()

    def tearDown(self):
        self.listener.close()

    def test_open_and_closed(self):
        client = Client("http://127.0.0.1:1", delay=0, budget=5)
        self.assertEqual(client.probe_port(self.open_port, timeout=1), "open")
        # A host firewall may silently drop rather than refuse an unused local port.
        self.assertIn(client.probe_port(self.closed_port, timeout=1), ("closed", "filtered"))
        self.assertEqual(client.sent, 2)

    def test_counts_against_budget(self):
        client = Client("http://127.0.0.1:1", delay=0, budget=1)
        client.probe_port(self.open_port, timeout=1)
        with self.assertRaises(BudgetExceeded):
            client.probe_port(self.open_port, timeout=1)

    def test_probe_through_context(self):
        c = Context("http://127.0.0.1:1", Client("http://127.0.0.1:1", delay=0), {})
        states = network._probe(c, [self.open_port, self.closed_port])
        self.assertEqual(states[self.open_port], "open")
        self.assertIn(states[self.closed_port], ("closed", "filtered"))

    def test_refusal_and_timeout_remain_distinct(self):
        for error, expected in ((ConnectionRefusedError(), "closed"), (TimeoutError(), "filtered")):
            with self.subTest(expected=expected), mock.patch("socket.create_connection", side_effect=error):
                client = Client("http://127.0.0.1:1", delay=0)
                self.assertEqual(client.probe_port(self.closed_port), expected)


# --- TLS ---------------------------------------------------------------------------------------------------------

class CipherTest(unittest.TestCase):
    def run_with(self, broken, static_rsa):
        def fake(client, ciphers):
            return broken if ciphers == network.BROKEN_CIPHERS else static_rsa
        with mock.patch.object(network, "_try_ciphers", fake):
            return network.weak_ciphers(ctx())

    def test_statuses(self):
        cases = [((None, None), "pass"), (("DES-CBC3-SHA", None), "fail"), ((None, "AES128-GCM-SHA256"), "warn"),
                 ((None, "client"), "skip"), (("cert", None), "error")]
        for (broken, rsa), want in cases:
            with self.subTest(broken=broken, rsa=rsa):
                self.assertEqual(self.run_with(broken, rsa).status, want)

    def test_try_ciphers_reports_accepted_and_refused(self):
        accepted = FakeClient("https://example.com", tls=lambda context: FakeTLS(cipher="AES128-GCM-SHA256"))
        got = network._try_ciphers(accepted, network.STATIC_RSA)
        if got == "client":
            self.skipTest("this OpenSSL cannot offer static RSA suites")
        self.assertEqual(got, "AES128-GCM-SHA256")

        def refuse(context):
            raise ssl.SSLError("handshake failure")
        self.assertIsNone(network._try_ciphers(FakeClient("https://example.com", tls=refuse), network.STATIC_RSA))

    def test_skips(self):
        self.assertEqual(network.weak_ciphers(ctx("http://example.com")).status, "skip")
        self.assertEqual(network.weak_ciphers(ctx("https://localhost:8443")).status, "skip")


class CertificateExpiryTest(unittest.TestCase):
    def status(self, **kw):
        return transport.certificate(ctx(tls=lambda context: FakeTLS(cert(**kw)))).status

    def test_thresholds(self):
        self.assertEqual(self.status(days_left=60), "pass")
        self.assertEqual(self.status(days_left=25), "warn")
        self.assertEqual(self.status(days_left=10), "fail")

    def test_short_lived_certificates_scale(self):
        self.assertEqual(self.status(days_left=4, lifetime=6), "pass")
        self.assertEqual(self.status(days_left=0, lifetime=6), "fail")


# --- DNS ---------------------------------------------------------------------------------------------------------

class CaaTest(unittest.TestCase):
    def run_caa(self, records, issuer="Let's Encrypt", target="https://www.example.com", at="example.com",
                sans=("example.com", "www.example.com")):
        dns = {(at, "CAA"): {"Status": 0, "Answer": ans(at, 257, *records)}}
        c = ctx(target, dns=dns, tls=lambda context: FakeTLS(cert(issuer, sans)))
        return network.caa(c)

    def test_matching_issuer_passes_after_climbing(self):
        r = self.run_caa(['0 issue "letsencrypt.org"'])
        self.assertEqual(r.status, "pass", r.summary)
        self.assertTrue(any(e.startswith("CAA example.com") for e in r.evidence))

    def test_other_ca_only_fails(self):
        self.assertEqual(self.run_caa(['0 issue "digicert.com"']).status, "fail")
        self.assertEqual(self.run_caa(['0 issue ";"']).status, "fail")

    def test_unknown_issuer_is_manual(self):
        self.assertEqual(self.run_caa(['0 issue "letsencrypt.org"'], issuer="Example CA").status, "manual")

    def test_none_warns(self):
        self.assertEqual(self.run_caa([]).status, "warn")

    def test_hex_form(self):
        value = b"letsencrypt.org"
        raw = bytes([0, 5]) + b"issue" + value
        hexed = f"\\# {len(raw)} " + raw.hex()
        self.assertEqual(network.parse_caa(hexed), ("issue", "letsencrypt.org"))
        self.assertEqual(self.run_caa([hexed]).status, "pass")

    def test_wildcard_uses_issuewild(self):
        recs = ['0 issue "letsencrypt.org"', '0 issuewild "digicert.com"']
        self.assertEqual(self.run_caa(recs, sans=("*.example.com",)).status, "fail")
        self.assertEqual(self.run_caa(recs).status, "pass")

    def test_plain_http_checks_presence_only(self):
        dns = {("example.com", "CAA"): {"Status": 0, "Answer": ans("example.com", 257, '0 issue "pki.goog"')}}
        c = ctx("http://example.com", dns=dns)
        self.assertEqual(network.caa(c).status, "pass")
        self.assertNotIn("tls", c.client.calls)

    def test_skips(self):
        for target, options in (("https://localhost", {}), ("https://203.0.113.9", {}), ("https://app.vercel.app", {}),
                                ("https://example.com", {"no_dns": True})):
            with self.subTest(target=target):
                c = ctx(target, options=options)
                self.assertEqual(network.caa(c).status, "skip")
                self.assertEqual(network.dnssec(c).status, "skip")
                self.assertEqual(c.client.calls, [])


DS = {("example.com", "DS"): {"Status": 0, "Answer": ans("example.com", 43, "2371 13 2 abcd")}}


class DnssecTest(unittest.TestCase):

    def test_unsigned_warns(self):
        self.assertEqual(network.dnssec(ctx()).status, "warn")

    def test_signed_and_validated_passes(self):
        dns = {**DS, ("example.com", "A"): {"Status": 0, "AD": True}}
        self.assertEqual(network.dnssec(ctx(dns=dns)).status, "pass")

    def test_broken_validation_fails(self):
        dns = {**DS, ("example.com", "A"): {"Status": 2}, ("example.com", "A", "cd"): {"Status": 0}}
        r = network.dnssec(ctx(dns=dns))
        self.assertEqual(r.status, "fail")
        self.assertTrue(any("cd=1" in e for e in r.evidence))

    def test_servfail_both_ways_is_error(self):
        dns = {**DS, ("example.com", "A"): {"Status": 2}, ("example.com", "A", "cd"): {"Status": 2}}
        self.assertEqual(network.dnssec(ctx(dns=dns)).status, "error")

    def test_signed_without_ad_warns(self):
        dns = {**DS, ("example.com", "A"): {"Status": 0, "AD": False}}
        self.assertEqual(network.dnssec(ctx(dns=dns)).status, "warn")


class DanglingCnameTest(unittest.TestCase):
    def test_no_cname_passes_and_checks_twin(self):
        c = ctx()
        self.assertEqual(network.dangling_cname(c).status, "pass")
        self.assertTrue(any("name=www.example.com" in u for u in c.client.calls))

    def test_claimable_nxdomain_fails(self):
        dns = {("www.example.com", "A"): {"Status": 3, "Answer": ans("www.example.com", 5, "old-app.azurewebsites.net.")}}
        r = network.dangling_cname(ctx(dns=dns))
        self.assertEqual(r.status, "fail")
        self.assertIn("old-app.azurewebsites.net", r.summary)

    def test_unknown_provider_nxdomain_warns(self):
        dns = {("www.example.com", "A"): {"Status": 3, "Answer": ans("www.example.com", 5, "gone.example.net.")}}
        self.assertEqual(network.dangling_cname(ctx(dns=dns)).status, "warn")

    def test_resolving_cname_passes(self):
        dns = {("example.com", "A"): {"Status": 0, "Answer": ans("example.com", 5, "x.azurewebsites.net.")
                                      + ans("x.azurewebsites.net", 1, "203.0.113.8")}}
        self.assertEqual(network.dangling_cname(ctx(dns=dns)).status, "pass")

    def test_unclaimed_page_fingerprint(self):
        dns = {("example.com", "A"): {"Status": 0, "Answer": ans("example.com", 5, "owner.github.io.")}}
        page = "<h1>404</h1><p>There isn't a GitHub Pages site here.</p>"
        self.assertEqual(network.dangling_cname(ctx(dns=dns, home=page)).status, "fail")
        self.assertEqual(network.dangling_cname(ctx(dns=dns, home="<h1>My site</h1>")).status, "pass")


MX = {("example.com", "MX"): {"Status": 0, "Answer": ans("example.com", 15, "10 mx1.mail.example.net.",
                                                          "20 mx2.mail.example.net.")}}
STS = {("_mta-sts.example.com", "TXT"): {"Status": 0, "Answer": ans("_mta-sts.example.com", 16, '"v=STSv1; id=1"')}}
RPT = {("_smtp._tls.example.com", "TXT"): {"Status": 0, "Answer": ans(
    "_smtp._tls.example.com", 16, '"v=TLSRPTv1; rua=mailto:tls@example.com"')}}


class MtaStsTest(unittest.TestCase):
    URL = "https://mta-sts.example.com/.well-known/mta-sts.txt"

    def run_sts(self, dns, policy=None, target="https://www.example.com"):
        pages = {self.URL: policy} if policy is not None else {}
        return network.mta_sts(ctx(target, dns=dns, pages=pages))

    def policy(self, mode="enforce", mx=("*.mail.example.net",)):
        lines = ["version: STSv1", f"mode: {mode}", *[f"mx: {m}" for m in mx], "max_age: 604800"]
        return resp(200, "\r\n".join(lines))

    def test_no_mx_skips(self):
        self.assertEqual(self.run_sts({}).status, "skip")
        null = {("example.com", "MX"): {"Status": 0, "Answer": ans("example.com", 15, "0 .")}}
        self.assertEqual(self.run_sts(null).status, "skip")

    def test_missing_record_warns(self):
        self.assertEqual(self.run_sts(MX).status, "warn")

    def test_enforce_with_reports_passes(self):
        r = self.run_sts({**MX, **STS, **RPT}, self.policy())
        self.assertEqual(r.status, "pass", r.summary)

    def test_testing_mode_and_missing_rpt_warn(self):
        self.assertEqual(self.run_sts({**MX, **STS, **RPT}, self.policy("testing")).status, "warn")
        self.assertEqual(self.run_sts({**MX, **STS}, self.policy()).status, "warn")

    def test_unlisted_mx_fails(self):
        r = self.run_sts({**MX, **STS, **RPT}, self.policy(mx=("mx1.mail.example.net",)))
        self.assertEqual(r.status, "fail")
        self.assertIn("mx2.mail.example.net", r.summary)

    def test_policy_missing_or_untrusted_fails(self):
        self.assertEqual(self.run_sts({**MX, **STS}, resp(404)).status, "fail")
        bad = ssl.SSLCertVerificationError("certificate verify failed")
        bad.verify_message = "self-signed certificate"
        self.assertEqual(self.run_sts({**MX, **STS}, bad).status, "fail")
        self.assertEqual(self.run_sts({**MX, **STS}, resp(200, "hello")).status, "fail")

    def test_unreachable_policy_is_error(self):
        self.assertEqual(self.run_sts({**MX, **STS}, TimeoutError("timed out")).status, "error")

    def test_mx_pattern_matches_one_label(self):
        self.assertTrue(network._mx_match("mx1.mail.example.net", ["*.mail.example.net"]))
        self.assertFalse(network._mx_match("a.mx1.mail.example.net", ["*.mail.example.net"]))
        self.assertFalse(network._mx_match("mail.example.net", ["*.mail.example.net"]))
        self.assertTrue(network._mx_match("mx.example.net", ["mx.example.net"]))


if __name__ == "__main__":
    unittest.main()
