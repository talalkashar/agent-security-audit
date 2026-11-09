"""Regression tests for false passes and unsafe inputs found in review (2026-11-08). Each test fails on the code
before its fix: a check must not pass on missing, partial or inconclusive evidence."""

import errno
import socket
import ssl
import threading
import time
import unittest
from datetime import date, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
from unittest import mock

from agent_security_audit import crawl as crawl_mod
from agent_security_audit import http as http_mod
from agent_security_audit.checks import Context, browser, cms, exposure, network, ratelimit, transport, webapp
from agent_security_audit.http import Client, Response

T = "https://example.test"


def resp(status=200, headers=(), body=b"", url=T + "/"):
    if isinstance(body, str):
        body = body.encode()
    return Response(url, status, "", list(headers), body)


def html(body, *headers, status=200):
    return resp(status, [("Content-Type", "text/html; charset=utf-8"), *headers], f"<html><body>{body}</body></html>")


class Stub:
    """Serves {path: Response | callable(method, url, headers, body)}; anything else is 404. Records every call."""

    timeout = 1.0

    def __init__(self, target, routes, budget=None):
        self.target, self.routes, self.calls, self.sent = target, routes, [], 0
        if budget is not None:
            self.budget = budget

    def url(self, path):
        return path if path.startswith(("http://", "https://")) else self.target + "/" + path.lstrip("/")

    def request(self, method, path="/", *, headers=None, body=None, cache=False):
        url = self.url(path)
        self.calls.append((method, url, headers or {}))
        self.sent += 1
        rel = url[len(self.target):] or "/"
        route = self.routes.get(rel, self.routes.get(rel.split("?")[0]))
        out = resp(404) if route is None else route(method, url, headers or {}, body) if callable(route) else route
        return Response(url, out.status, out.reason, out.headers, out.body)

    def get(self, path="/", **kw):
        return self.request("GET", path, **kw)

    def home(self):
        return self.get("/")


def ctx(routes, target=T, budget=None, **options):
    return Context(target, Stub(target, routes, budget), options)


# 1. ReDoS ----------------------------------------------------------------------------------------------------------

class ChunkScanTimeTest(unittest.TestCase):
    def test_hostile_chunk_text_is_linear(self):
        for text in ("~static/chunks/" * 16000, "~static/chunks/" * 140_000):  # 240 KB and 2 MB
            start = time.monotonic()
            crawl_mod.next_chunks(text)
            self.assertLess(time.monotonic() - start, 5.0, len(text))  # quadratic takes minutes; CI can be slow

    def test_real_chunks_still_found(self):
        text = '"static/chunks/app/page-abc.js","/_next/static/chunks/main-1.js"'
        self.assertEqual(crawl_mod.next_chunks(text), ["/_next/static/chunks/app/page-abc.js",
                                                       "/_next/static/chunks/main-1.js"])

    def test_a_chunk_named_late_in_a_large_bundle_is_found(self):
        late = "x" * 1_500_000 + ' "static/chunks/late.js"'
        self.assertEqual(crawl_mod.next_chunks(late), ["/_next/static/chunks/late.js"])


# 2. INFRA-04 .env --------------------------------------------------------------------------------------------------

class EnvFileTest(unittest.TestCase):
    def run_with(self, body, ctype="text/plain"):
        def route(m, u, h, b):
            return resp(200, [("Content-Type", ctype)], body) if u.endswith("/.env") else resp(404)
        return exposure.sensitive_files(ctx({"/.env": route}))

    def test_one_line_env_fails(self):
        self.assertEqual(self.run_with("DATABASE_URL=postgres://u:p@h/db\n").status, "fail")

    def test_lowercase_keys_fail(self):
        self.assertEqual(self.run_with("db_password=x\napi_key=y\n").status, "fail")

    def test_error_pages_and_scripts_are_not_env_files(self):
        for body in ("Not Found", "Cannot GET /.env", '{"error":"a=b"}', "var a=1;\nfoo();\nbar();\n"):
            with self.subTest(body=body):
                self.assertEqual(self.run_with(body).status, "pass")
        self.assertEqual(self.run_with("<!doctype html><p>a=b</p>", "text/html").status, "pass")


# 3. BROWSER-02 CSP -------------------------------------------------------------------------------------------------

class CspElemAttrTest(unittest.TestCase):
    TAIL = "; object-src 'none'; base-uri 'none'"

    def judge(self, policy):
        return browser._csp(resp(headers=[("Content-Security-Policy", policy + self.TAIL)])).status

    def test_script_src_elem_unsafe_inline_fails(self):
        self.assertEqual(self.judge("script-src 'self'; script-src-elem 'self' 'unsafe-inline' https:"), "fail")

    def test_script_src_elem_any_host_fails(self):
        self.assertEqual(self.judge("script-src 'self'; script-src-elem *"), "fail")

    def test_script_src_attr_unsafe_inline_fails(self):
        self.assertEqual(self.judge("script-src 'self'; script-src-attr 'unsafe-inline'"), "fail")

    def test_strict_elem_and_attr_pass(self):
        self.assertEqual(self.judge("script-src 'self'; script-src-elem 'self'; script-src-attr 'none'"), "pass")


class StaticNonceTest(unittest.TestCase):
    POLICY = "script-src 'nonce-{n}' 'strict-dynamic'; object-src 'none'; base-uri 'none'"

    def run_with(self, fresh):
        served = []

        def route(m, u, h, b):
            served.append(u)
            n = f"r{len(served)}" if fresh else "static123"
            return html("x", ("Content-Security-Policy", self.POLICY.format(n=n)))
        return browser.csp(ctx({"/": route}))

    def test_repeated_nonce_fails(self):
        r = self.run_with(fresh=False)
        self.assertEqual(r.status, "fail")
        self.assertIn("nonce", r.summary)
        self.assertNotIn("static123", " ".join(r.evidence[-1:]))

    def test_fresh_nonce_passes(self):
        self.assertEqual(self.run_with(fresh=True).status, "pass")


# 4. BROWSER-01 HSTS ------------------------------------------------------------------------------------------------

class HstsDuplicateTest(unittest.TestCase):
    def test_duplicate_max_age_fails(self):
        value = "max-age=0; max-age=63072000; includeSubDomains"
        r = browser._hsts(resp(headers=[("Strict-Transport-Security", value)]))
        self.assertEqual(r.status, "fail")
        self.assertIn("max-age", r.summary)

    def test_single_directives_pass(self):
        r = browser._hsts(resp(headers=[("Strict-Transport-Security", "max-age=63072000; includeSubDomains")]))
        self.assertEqual(r.status, "pass")


# 5. BROWSER-07 CORS ------------------------------------------------------------------------------------------------

class CorsApiTest(unittest.TestCase):
    def test_reflecting_api_route_fails_when_home_is_clean(self):
        def api(m, u, h, b):
            origin = h.get("Origin")
            if not origin:
                return resp(200, [("Content-Type", "application/json")], "{}")
            return resp(200, [("Access-Control-Allow-Origin", origin), ("Access-Control-Allow-Credentials", "true")])
        c = ctx({"/": html('<a href="/api/user">me</a>'), "/api/user": api})
        r = browser.cors(c)
        self.assertEqual(r.status, "fail")
        self.assertIn("/api/user", r.summary)

    def test_api_literal_in_inline_script_is_probed(self):
        c = ctx({"/": html("<script>fetch('/api/orders')</script>"), "/api/orders": resp(200)})
        r = browser.cors(c)
        self.assertEqual(r.status, "pass")
        self.assertIn("/api/orders", r.summary)

    def test_home_only_is_manual(self):
        r = browser.cors(ctx({"/": html("<p>no api</p>")}))
        self.assertEqual(r.status, "manual")

    def test_api_routes_that_404_are_not_tested(self):
        r = browser.cors(ctx({"/": html('<a href="/api/gone">x</a>')}))
        self.assertEqual(r.status, "manual")


# 6. BROWSER-06 cookies ---------------------------------------------------------------------------------------------

class CookieSessionTest(unittest.TestCase):
    def test_no_session_cookie_is_manual(self):
        r = browser.cookies(ctx({"/": html("x", ("Set-Cookie", "theme=dark; Secure; HttpOnly; SameSite=Lax"))}))
        self.assertEqual(r.status, "manual")
        self.assertIn("session", r.summary)

    def test_pass_names_the_session_cookie_and_the_name_heuristic(self):
        r = browser.cookies(ctx({"/": html("x", ("Set-Cookie", "sid=1; Secure; HttpOnly; SameSite=Lax"))}))
        self.assertEqual(r.status, "pass")
        self.assertIn("sid", r.summary)
        self.assertIn("by name", r.summary)


# 7. Inconclusive network evidence ----------------------------------------------------------------------------------

class TlsClient:
    def __init__(self, error):
        self.error = error

    def open_tls(self, context):
        raise self.error


def ssl_error(reason):
    exc = ssl.SSLError(1, f"[SSL: {reason}] {reason.lower().replace('_', ' ')}")
    exc.reason = reason
    return exc


class TlsInconclusiveTest(unittest.TestCase):
    def version(self, error):
        return transport._try_version(TlsClient(error), ssl.TLSVersion.TLSv1_2)

    def test_protocol_version_alert_is_a_refusal(self):
        self.assertIsNone(self.version(ssl_error("TLSV1_ALERT_PROTOCOL_VERSION")))
        self.assertIsNone(self.version(ssl_error("UNSUPPORTED_PROTOCOL")))

    def test_other_handshake_errors_are_inconclusive(self):
        for error in (ssl_error("SSLV3_ALERT_HANDSHAKE_FAILURE"), ConnectionResetError(), ssl_error("UNEXPECTED_EOF")):
            with self.subTest(error=repr(error)):
                self.assertIsInstance(self.version(error), tuple)

    def test_infra03_manual_on_handshake_failure(self):
        c = Context("https://example.com", SimpleNamespace(), {})
        with mock.patch.object(transport, "_try_version", lambda client, v: ("inconclusive", "HANDSHAKE_FAILURE")):
            self.assertEqual(transport.legacy_tls(c).status, "manual")

    def test_cipher_reset_is_inconclusive(self):
        got = network._try_ciphers(TlsClient(ConnectionResetError()), network.STATIC_RSA)
        if got == "client":
            self.skipTest("this OpenSSL cannot offer static RSA suites")
        self.assertIsInstance(got, tuple)
        c = Context("https://example.com", SimpleNamespace(), {})
        with mock.patch.object(network, "_try_ciphers", lambda client, ciphers: ("inconclusive", "reset")):
            self.assertEqual(network.weak_ciphers(c).status, "manual")

    def test_untestable_family_is_not_a_pass(self):
        # This machine can offer only NULL suites (as OpenSSL 3 often can), and the server refuses them. RC4, 3DES,
        # DES and export were never offered, so the check must not pass.
        def fake(client, ciphers):
            offers_null = "eNULL" in ciphers.replace("!eNULL", "")
            return None if offers_null or ciphers == network.STATIC_RSA else "client"
        c = Context("https://example.com", SimpleNamespace(), {})
        with mock.patch.object(network, "_try_ciphers", fake):
            self.assertEqual(network.weak_ciphers(c).status, "skip")


class PortReachTest(unittest.TestCase):
    def test_network_unreachable_is_not_filtered(self):
        client = Client("https://example.com", delay=0)
        client._all_addresses = ["2001:db8::1"]
        with mock.patch("socket.create_connection", side_effect=OSError(errno.ENETUNREACH, "unreachable")):
            self.assertEqual(client.probe_port(5432), "unreachable")

    def test_unreachable_ipv6_falls_back_to_ipv4(self):
        client = Client("https://example.com", delay=0)
        client._all_addresses = ["2001:db8::1", "203.0.113.7"]

        def connect(address, timeout):
            if ":" in address[0]:
                raise OSError(errno.ENETUNREACH, "unreachable")
            raise ConnectionRefusedError()
        with mock.patch("socket.create_connection", side_effect=connect):
            self.assertEqual(client.probe_port(5432), "closed")
        self.assertEqual(client.target_address(), "203.0.113.7")
        self.assertEqual(client.sent, 1)

    def fake_ctx(self, states):
        client = SimpleNamespace(target_address=lambda: "203.0.113.7",
                                 probe_port=lambda port, timeout=2.0: states.get(port, "filtered"))
        return Context("https://example.com", client, {})

    def test_unreachable_ports_are_an_error(self):
        r = network.data_ports(self.fake_ctx({5432: "unreachable", 3306: "closed"}))
        self.assertEqual(r.status, "error")

    def test_all_filtered_is_manual(self):
        self.assertEqual(network.data_ports(self.fake_ctx({})).status, "manual")
        self.assertEqual(network.data_ports(self.fake_ctx({5432: "closed"})).status, "pass")


# 8. Crawl cut by its own cap ---------------------------------------------------------------------------------------

class CrawlCapTest(unittest.TestCase):
    def test_cap_with_pages_left_marks_the_crawl_cut(self):
        links = "".join(f'<a href="/p{i}">p</a>' for i in range(30))
        routes = {"/": html(links), **{f"/p{i}": html("page") for i in range(30)}}
        c = ctx(routes, budget=12)  # the crawl may spend half: 6 requests
        site = crawl_mod.crawl(c)
        self.assertLess(len(site.pages), 31)
        self.assertTrue(site.cut)
        self.assertTrue(c.cache.get("data_cut"))

    def test_finished_crawl_is_not_cut(self):
        c = ctx({"/": html('<a href="/a">a</a>'), "/a": html("a")}, budget=300)
        self.assertFalse(crawl_mod.crawl(c).cut)


# 9. CMS ------------------------------------------------------------------------------------------------------------

class CmsCurrencyTest(unittest.TestCase):
    def context(self, generator):
        page = SimpleNamespace(text=f'<meta name="generator" content="{generator}">', url=T + "/",
                               get=lambda name, default=None: default)
        c = Context(T, SimpleNamespace(calls=[]), {})
        c.cache["crawl"] = SimpleNamespace(pages=[page], cut=False)
        return c

    def at(self, days_after_snapshot):
        when = date.fromisoformat(cms.SUPPORT_DATE) + timedelta(days=days_after_snapshot)
        return mock.patch.object(cms, "_today", lambda: when)

    def test_old_patch_of_supported_line_is_not_a_pass(self):
        with self.at(0):
            self.assertEqual(cms.outdated_core(self.context("WordPress 7.1.0")).status, "warn")
            self.assertEqual(cms.outdated_core(self.context("WordPress 7.1.4")).status, "pass")

    def test_stale_snapshot_is_manual(self):
        with self.at(cms.SUPPORT_MAX_AGE_DAYS + 1):
            r = cms.outdated_core(self.context("WordPress 7.1.4"))
        self.assertEqual(r.status, "manual")
        self.assertIn("stale", r.summary)

    def test_stale_snapshot_still_fails_ended_lines(self):
        with self.at(cms.SUPPORT_MAX_AGE_DAYS + 1):
            self.assertEqual(cms.outdated_core(self.context("Drupal 9.5")).status, "fail")


# 10. API-01 rate-limit probe ---------------------------------------------------------------------------------------

class RateLimitMethodTest(unittest.TestCase):
    def test_only_post_is_allowed(self):
        self.assertEqual(ratelimit.ALLOWED_METHODS, ("POST",))

    def test_other_methods_send_nothing(self):
        for method in ("DELETE", "PUT", "PATCH", "GET", "PURGE"):
            with self.subTest(method=method):
                c = ctx({"/": resp(401)}, rate_limit_path="/api/login", rate_limit_method=method)
                r = ratelimit.login_rate_limit(c)
                self.assertEqual(r.status, "error")
                self.assertEqual(c.client.calls, [])

    def test_explicit_signup_or_reset_path_sends_nothing(self):
        for path in ("/api/auth/sign-up", "/reset-password", "/api/users/create"):
            with self.subTest(path=path):
                c = ctx({"/": resp(401)}, rate_limit_path=path)
                self.assertEqual(ratelimit.login_rate_limit(c).status, "error")
                self.assertEqual(c.client.calls, [])

    def test_login_path_still_probed(self):
        c = ctx({"/api/login": resp(401)}, rate_limit_path="/api/login", rate_limit_attempts=10)
        self.assertEqual(ratelimit.login_rate_limit(c).status, "warn")
        self.assertEqual({m for m, _, _ in c.client.calls}, {"POST"})


# 11. Response cache memory and API-19 ------------------------------------------------------------------------------

class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"x" * 1000
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class CacheCapTest(unittest.TestCase):
    def test_cache_stops_at_the_byte_cap(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        client = Client(f"http://127.0.0.1:{server.server_address[1]}", delay=0)
        with mock.patch.object(http_mod, "MAX_CACHE_BYTES", 1500):
            client.get("/a", cache=True)
            client.get("/a", cache=True)  # cached
            client.get("/b", cache=True)  # over the cap: not cached
            client.get("/b", cache=True)
        self.assertEqual(client.sent, 3)
        self.assertLessEqual(client._cache_bytes, 1500)


class OpenRedirectCoverageTest(unittest.TestCase):
    def test_unprobed_parameters_are_not_a_pass(self):
        links = "".join(f'<a href="/r{i}?next=/home">r</a>' for i in range(webapp.MAX_REDIRECT_PROBES + 2))
        c = ctx({"/": html(links)})
        r = webapp.open_redirect(c)
        self.assertEqual(r.status, "manual")
        self.assertIn("untested", r.summary)

    def test_all_probed_can_pass_and_says_js_is_not_covered(self):
        # /r redirects, but only to its own site, so every probe form was exercised and refused.
        r = webapp.open_redirect(ctx({"/": html('<a href="/r?next=/home">r</a>'),
                                      "/r": html("", ("Location", "/home"), status=302)}))
        self.assertEqual(r.status, "pass")
        self.assertIn("JavaScript", r.summary)


if __name__ == "__main__":
    socket.setdefaulttimeout(5)
    unittest.main()
