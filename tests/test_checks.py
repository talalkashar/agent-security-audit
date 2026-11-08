"""Unit tests for each proof function, driven by stub clients and canned responses (no network)."""

import base64
import json
import unittest

from agent_security_audit.checks import Context, browser, dns_email, exposure, ratelimit, supabase, transport
from agent_security_audit.http import Response


def resp(status=200, headers=(), body=b"", url="https://example.test/"):
    if isinstance(body, str):
        body = body.encode()
    return Response(url, status, "", list(headers), body)


class StubClient:
    """Answers from a function route(method, url, headers, body) -> Response. Records every call."""

    timeout = 1.0

    def __init__(self, target, route):
        self.target = target
        self.route = route
        self.calls = []

    def url(self, path):
        return path if path.startswith(("http://", "https://")) else self.target + "/" + path.lstrip("/")

    def request(self, method, path="/", *, headers=None, body=None, cache=False):
        url = self.url(path)
        self.calls.append((method, url, headers or {}))
        return self.route(method, url, headers or {}, body)

    def get(self, path="/", **kw):
        return self.request("GET", path, **kw)

    def home(self):
        return self.get("/")

    def external(self, method, url, *, headers=None, body=None):
        self.calls.append((method, url, headers or {}))
        return self.route(method, url, headers or {}, body)

    def same_host(self, method, url, *, headers=None, body=None):
        raise AssertionError("same_host must not be called in these tests")


def ctx_for(route, target="https://example.test", **options):
    return Context(target, StubClient(target, route), options)


def home_with(*headers, target="https://example.test", **options):
    return ctx_for(lambda m, u, h, b: resp(200, headers, "<html></html>"), target, **options)


def b64(obj):
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")


def fake_jwt(role):
    # Built at runtime from fake parts; not a credential anywhere.
    return ".".join([b64({"alg": "HS256", "typ": "JWT"}), b64({"role": role, "ref": "q" * 20}), "fakesig" + "0" * 20])


class CspTest(unittest.TestCase):
    def status(self, *headers):
        return browser.csp(home_with(*headers)).status

    def test_parse(self):
        p = browser.parse_csp("default-src 'self'; script-src 'self' 'nonce-a'; script-src *")
        self.assertEqual(p["script-src"], ["'self'", "'nonce-a'"])
        self.assertEqual(p["default-src"], ["'self'"])

    def test_unsafe_inline_with_nonce_ok(self):
        csp = "script-src 'self' 'nonce-abc' 'unsafe-inline'; object-src 'none'; base-uri 'none'"
        self.assertEqual(self.status(("Content-Security-Policy", csp)), "pass")

    def test_unsafe_inline_without_nonce_fails(self):
        csp = "script-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'none'"
        self.assertEqual(self.status(("Content-Security-Policy", csp)), "fail")

    def test_report_only_warns(self):
        self.assertEqual(self.status(("Content-Security-Policy-Report-Only", "script-src 'self'")), "warn")

    def test_missing_fails(self):
        self.assertEqual(self.status(), "fail")

    def test_strict_dynamic_with_https_ok(self):
        csp = "script-src 'nonce-abc' 'strict-dynamic' https: 'unsafe-inline'; object-src 'none'; base-uri 'none'"
        self.assertEqual(self.status(("Content-Security-Policy", csp)), "pass")

    def test_https_without_strict_dynamic_fails(self):
        csp = "script-src 'self' https:; object-src 'none'; base-uri 'none'"
        self.assertEqual(self.status(("Content-Security-Policy", csp)), "fail")

    def test_no_script_directive_fails(self):
        self.assertEqual(self.status(("Content-Security-Policy", "frame-ancestors 'none'")), "fail")

    def test_gaps_warn(self):
        self.assertEqual(self.status(("Content-Security-Policy", "script-src 'self'")), "warn")

    def test_any_host_sources_fail(self):
        tail = "; object-src 'none'; base-uri 'none'"
        for src in ("http:", "https:", "https://*", "http://*", "*.com", "wss:", "blob:", "data:", "*",
                    "https://*:443"):
            with self.subTest(src=src):
                self.assertEqual(self.status(("Content-Security-Policy", f"script-src 'self' {src}{tail}")), "fail")

    def test_scoped_hosts_pass(self):
        csp = "script-src 'self' https://cdn.example.com *.example.com; object-src 'none'; base-uri 'none'"
        self.assertEqual(self.status(("Content-Security-Policy", csp)), "pass")

    def test_strict_dynamic_needs_nonce_to_excuse_any_host(self):
        tail = "; object-src 'none'; base-uri 'none'"
        self.assertEqual(self.status(("Content-Security-Policy",
                                      f"script-src 'nonce-a' 'strict-dynamic' https: http:{tail}")), "pass")
        self.assertEqual(self.status(("Content-Security-Policy", f"script-src 'strict-dynamic' https:{tail}")), "fail")

    def test_policies_combine(self):
        # Two enforced policies both apply, so the strict one protects scripts.
        self.assertEqual(self.status(("Content-Security-Policy", "frame-ancestors 'none'"),
                                     ("Content-Security-Policy", "default-src 'self'; object-src 'none'; base-uri 'none'")),
                         "pass")
        self.assertEqual(self.status(("Content-Security-Policy", "script-src *; base-uri 'none'"),
                                     ("Content-Security-Policy", "script-src 'self'; object-src 'none'")), "pass")
        self.assertEqual(self.status(("Content-Security-Policy", "script-src * 'unsafe-inline'"),
                                     ("Content-Security-Policy", "script-src https: 'unsafe-inline'")), "fail")
        self.assertEqual(self.status(("Content-Security-Policy",
                                      "frame-ancestors 'none', default-src 'self'; object-src 'none'; base-uri 'none'")),
                         "pass")


class HeaderChecksTest(unittest.TestCase):
    def test_hsts(self):
        cases = [((("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),), "pass"),
                 ((("Strict-Transport-Security", "max-age=300"),), "fail"),
                 ((("Strict-Transport-Security", "max-age=600; includeSubDomains"),), "fail"),
                 ((("Strict-Transport-Security", "max-age=0; includeSubDomains"),), "fail"),
                 ((("Strict-Transport-Security", "max-age=31536000"),), "warn"),
                 ((("Strict-Transport-Security", 'max-age="63072000"; includesubdomains; preload'),), "pass"),
                 ((("Strict-Transport-Security", "max-age=abc"),), "fail"),
                 ((("Strict-Transport-Security", "includeSubDomains"),), "fail"),
                 ((), "fail")]
        for headers, want in cases:
            with self.subTest(headers=headers):
                self.assertEqual(browser.hsts(home_with(*headers)).status, want)

    def test_hsts_skips_http(self):
        self.assertEqual(browser.hsts(home_with(target="http://example.test")).status, "skip")

    def test_referrer(self):
        cases = [("strict-origin-when-cross-origin", "pass"), ("no-referrer", "pass"),
                 ("unsafe-url", "fail"), ("no-referrer-when-downgrade", "fail"),
                 ("no-referrer, unsafe-url", "fail"), ("unsafe-url, strict-origin", "pass"), ("origin", "warn"),
                 ("strict-origin-when-cross-origin, x-future", "pass"), ("x-future", "warn")]
        for value, want in cases:
            with self.subTest(value=value):
                self.assertEqual(browser.referrer(home_with(("Referrer-Policy", value))).status, want)
        self.assertEqual(browser.referrer(home_with()).status, "warn")

    def test_nosniff_and_framing(self):
        self.assertEqual(browser.nosniff(home_with(("X-Content-Type-Options", "nosniff"))).status, "pass")
        self.assertEqual(browser.nosniff(home_with()).status, "fail")
        self.assertEqual(browser.framing(home_with(("X-Frame-Options", "DENY"))).status, "pass")
        self.assertEqual(browser.framing(home_with(("Content-Security-Policy", "frame-ancestors *"),
                                                   ("X-Frame-Options", "DENY"))).status, "fail")
        self.assertEqual(browser.framing(home_with(("Content-Security-Policy", "frame-ancestors 'self'"))).status, "pass")
        self.assertEqual(browser.framing(home_with()).status, "fail")
        # Several policies combine: one restrictive frame-ancestors is enough.
        self.assertEqual(browser.framing(home_with(("Content-Security-Policy", "frame-ancestors *"),
                                                   ("Content-Security-Policy", "frame-ancestors 'none'"))).status, "pass")
        self.assertEqual(browser.framing(home_with(("Content-Security-Policy", "frame-ancestors https:"))).status, "fail")

    def test_powered_by(self):
        self.assertEqual(exposure.powered_by(home_with(("X-Powered-By", "Next.js"))).status, "fail")
        self.assertEqual(exposure.powered_by(home_with()).status, "pass")

    def test_isolation(self):
        ok = home_with(("Permissions-Policy", "camera=()"), ("Cross-Origin-Opener-Policy", "same-origin"))
        self.assertEqual(browser.isolation(ok).status, "pass")
        self.assertEqual(browser.isolation(home_with()).status, "warn")


class CookieTest(unittest.TestCase):
    def test_parse_set_cookie(self):
        name, attrs = browser.parse_set_cookie("sid=abc=def; Path=/; Secure; HttpOnly; SameSite=Lax")
        self.assertEqual(name, "sid")
        self.assertEqual(attrs["samesite"], "Lax")
        self.assertIn("secure", attrs)
        self.assertIn("httponly", attrs)
        self.assertEqual(attrs["path"], "/")

    def status(self, *cookies, target="https://example.test"):
        return browser.cookies(home_with(*[("Set-Cookie", c) for c in cookies], target=target)).status

    def test_safe_cookie_passes(self):
        self.assertEqual(self.status("session=x; Secure; HttpOnly; SameSite=Lax"), "pass")

    def test_missing_secure_on_https_fails(self):
        self.assertEqual(self.status("session=x; HttpOnly; SameSite=Lax"), "fail")

    def test_session_without_httponly_fails(self):
        self.assertEqual(self.status("auth_token=x; Secure; SameSite=Lax"), "fail")
        self.assertEqual(self.status("__Host-session=x; Path=/; Secure; SameSite=Lax"), "fail")

    def test_prefix_alone_is_not_a_session(self):
        self.assertEqual(self.status("__Host-theme=dark; Path=/; Secure; SameSite=Lax"), "pass")
        self.assertEqual(self.status("__Secure-lang=en; Secure; SameSite=Lax"), "pass")

    def test_supabase_cookie_without_httponly_warns(self):
        self.assertEqual(self.status("sb-abc-auth-token=x; Secure; SameSite=Lax"), "warn")

    def test_samesite_none_without_secure_fails(self):
        self.assertEqual(self.status("theme=dark; SameSite=None", target="http://example.test"), "fail")

    def test_no_samesite_warns(self):
        self.assertEqual(self.status("theme=dark; Secure"), "warn")

    def test_no_cookies_skips(self):
        self.assertEqual(self.status(), "skip")


class CorsTest(unittest.TestCase):
    def run_cors(self, reflect, credentials):
        def route(m, u, h, b):
            headers = []
            if reflect and "Origin" in h:
                headers.append(("Access-Control-Allow-Origin", h["Origin"]))
                if credentials:
                    headers.append(("Access-Control-Allow-Credentials", "true"))
            return resp(200, headers)
        return browser.cors(ctx_for(route))

    def test_reflection_with_credentials_fails(self):
        self.assertEqual(self.run_cors(True, True).status, "fail")

    def test_reflection_without_credentials_warns(self):
        self.assertEqual(self.run_cors(True, False).status, "warn")

    def test_no_reflection_passes(self):
        self.assertEqual(self.run_cors(False, False).status, "pass")

    def test_wildcard_is_not_reflection(self):
        ctx = ctx_for(lambda m, u, h, b: resp(200, [("Access-Control-Allow-Origin", "*")]))
        self.assertEqual(browser.cors(ctx).status, "pass")


class SensitiveFilesTest(unittest.TestCase):
    def test_spa_catch_all_is_not_a_finding(self):
        html = "<!doctype html><html><body><div id=root></div></body></html>"
        ctx = ctx_for(lambda m, u, h, b: resp(200, [("Content-Type", "text/html")], html))
        self.assertEqual(exposure.sensitive_files(ctx).status, "pass")

    def test_spa_catch_all_without_content_type(self):
        ctx = ctx_for(lambda m, u, h, b: resp(200, [], "<html><body>app</body></html>"))
        self.assertEqual(exposure.sensitive_files(ctx).status, "pass")

    def test_real_env_file_fails_without_showing_contents(self):
        env = "DATABASE_URL=postgres://x\nAPI_TOKEN=supersecretvalue\n"

        def route(m, u, h, b):
            if u.endswith("/.env"):
                return resp(200, [("Content-Type", "text/plain")], env)
            return resp(404)
        r = exposure.sensitive_files(ctx_for(route))
        self.assertEqual(r.status, "fail")
        self.assertNotIn("supersecretvalue", " ".join(r.evidence) + r.summary)

    def test_all_404_passes(self):
        self.assertEqual(exposure.sensitive_files(ctx_for(lambda m, u, h, b: resp(404))).status, "pass")


class SecurityTxtTest(unittest.TestCase):
    def test_cases(self):
        cases = [("Contact: mailto:a@b.test\nExpires: 2999-01-01T00:00:00Z\n", "pass"),
                 ("Contact: mailto:a@b.test\nExpires: 2000-01-01T00:00:00Z\n", "warn"),
                 ("Contact: mailto:a@b.test\n", "warn"),
                 ("Contact: mailto:a@b.test\nExpires: soon\n", "warn")]
        for body, want in cases:
            with self.subTest(body=body):
                ctx = ctx_for(lambda m, u, h, b, body=body: resp(200, [("Content-Type", "text/plain")], body))
                self.assertEqual(exposure.security_txt(ctx).status, want)
        html = ctx_for(lambda m, u, h, b: resp(200, [("Content-Type", "text/html")], "<html>Contact: x</html>"))
        self.assertEqual(exposure.security_txt(html).status, "warn")


class SecretDetectionTest(unittest.TestCase):
    def test_service_role_jwt_flags(self):
        hits = exposure.find_secrets(f'const k="{fake_jwt("service_role")}";')
        self.assertEqual([k for k, _ in hits], ["Supabase service_role JWT"])
        self.assertTrue(hits[0][1].endswith("..."))

    def test_anon_jwt_does_not_flag(self):
        self.assertEqual(exposure.find_secrets(f'const k="{fake_jwt("anon")}";'), [])

    def test_publishable_key_does_not_flag(self):
        key = "sb_" + "publishable_" + "A1b2C3d4E5f6G7h8I9j0K1"
        self.assertEqual(exposure.find_secrets(f'const k="{key}";'), [])

    def test_supabase_secret_key_flags(self):
        key = "sb_" + "secret_" + "A1b2C3d4E5f6G7h8I9j0K1"
        self.assertEqual([k for k, _ in exposure.find_secrets(key)], ["Supabase secret key"])

    def test_stripe_live_key_flags(self):
        key = "sk_" + "live_" + "0" * 24
        self.assertEqual([k for k, _ in exposure.find_secrets(key)], ["Stripe live secret key"])

    def test_plain_code_does_not_flag(self):
        self.assertEqual(exposure.find_secrets("function skip_live(){return 'sk_test_' + token}"), [])

    def test_check_uses_cached_scripts(self):
        ctx = ctx_for(lambda m, u, h, b: resp(404))
        ctx.cache["scripts"] = [("/app.js", f'x="{fake_jwt("service_role")}"')]
        r = exposure.client_secrets(ctx)
        self.assertEqual(r.status, "fail")
        self.assertNotIn(fake_jwt("service_role"), " ".join(r.evidence))
        ctx.cache["scripts"] = [("/app.js", f'x="{fake_jwt("anon")}"')]
        self.assertEqual(exposure.client_secrets(ctx).status, "pass")
        ctx.cache["scripts"] = []
        self.assertEqual(exposure.client_secrets(ctx).status, "skip")

    def test_scripts_found_from_home_page(self):
        html = ('<html><script src="/a.js"></script><script src="https://cdn.other.test/b.js"></script>'
                '<link rel="modulepreload" href="/c.js"><script>var inline=1</script></html>')

        def route(m, u, h, b):
            if u == "https://example.test/":
                return resp(200, [("Content-Type", "text/html")], html)
            return resp(200, [("Content-Type", "application/javascript")], "var x=1")
        ctx = ctx_for(route)
        labels = [label for label, _ in exposure.scripts(ctx)]
        self.assertEqual(labels, ["home page inline scripts", "/a.js", "/c.js"])
        self.assertFalse(any("cdn.other.test" in u for _, u, _ in ctx.client.calls))


class SourceMapTest(unittest.TestCase):
    def ctx(self, map_status, comment=""):
        def route(m, u, h, b):
            if u.endswith(".map"):
                return resp(map_status, [], '{"version":3,"mappings":"AAAA"}' if map_status == 200 else "")
            return resp(404)
        ctx = ctx_for(route)
        ctx.cache["scripts"] = [("/_next/app.js", "var a=1;\n" + comment)]
        return ctx

    def test_public_map_fails(self):
        self.assertEqual(exposure.source_maps(self.ctx(200)).status, "fail")

    def test_comment_pointing_to_map_fails(self):
        ctx = self.ctx(200, "//# sourceMappingURL=app.js.map")
        self.assertEqual(exposure.source_maps(ctx).status, "fail")
        self.assertIn("https://example.test/_next/app.js.map", [u for _, u, _ in ctx.client.calls])

    def test_missing_map_passes(self):
        self.assertEqual(exposure.source_maps(self.ctx(404)).status, "pass")

    def test_inline_data_map_not_fetched(self):
        ctx = self.ctx(404, "//# sourceMappingURL=data:application/json;base64,e30=")
        self.assertEqual(exposure.source_maps(ctx).status, "pass")
        self.assertFalse(any("data:" in u for _, u, _ in ctx.client.calls))

    def test_no_scripts_skips(self):
        ctx = ctx_for(lambda m, u, h, b: resp(404))
        ctx.cache["scripts"] = [("home page inline scripts", "var a")]
        self.assertEqual(exposure.source_maps(ctx).status, "skip")


NORMAL_HTML = """<!doctype html><html lang="en"><head><meta charset="utf-8"><title>404: This page could not be found
</title><link rel="stylesheet" href="/_next/static/css/app.css"></head><body><main><h1>404</h1><p>This page could
not be found. Go back <a href="/">home</a> or read the <a href="/docs/getting-started">docs</a>.</p>
<p>Questions? Email support at example.test, Monday at 9:00.</p></main>
<script>self.__next_f=self.__next_f||[];self.__next_f.push([1,"0:[\\"$\\",\\"html\\",null]"])</script>
</body></html>"""


class ErrorLeakTest(unittest.TestCase):
    def test_markers(self):
        self.assertIn("Python traceback", exposure.find_leaks("Traceback (most recent call last):\n  File x"))
        self.assertIn("JavaScript stack frame",
                      exposure.find_leaks("Error: boom\n    at handler (/var/task/route.js:12:9)\n"))
        self.assertIn("database error", exposure.find_leaks('ERROR: duplicate key value violates unique constraint'))
        self.assertIn("server file path", exposure.find_leaks("open /home/deploy/app/config.js failed"))

    def test_home_route_link_is_not_a_path_leak(self):
        self.assertEqual(exposure.find_leaks('<html><a href="/home/pricing/">Pricing</a> Page not found</html>'), [])
        self.assertEqual(exposure.find_leaks('<a href="/Users/settings/">Users</a>'), [])

    def test_no_false_positive_on_normal_html(self):
        self.assertEqual(exposure.find_leaks(NORMAL_HTML), [])
        self.assertEqual(exposure.find_leaks('{"error":"Not found"}'), [])

    def test_check_passes_on_generic_errors(self):
        ctx = ctx_for(lambda m, u, h, b: resp(404 if m == "GET" else 400, [("Content-Type", "text/html")], NORMAL_HTML))
        self.assertEqual(exposure.error_leaks(ctx).status, "pass")

    def test_not_found_pages_alone_prove_nothing(self):
        ctx = ctx_for(lambda m, u, h, b: resp(404, [("Content-Type", "text/html")], NORMAL_HTML))
        self.assertEqual(exposure.error_leaks(ctx).status, "manual")

    def test_check_fails_on_stack(self):
        stack = "Error: x\n    at fn (/var/task/.next/server/app.js:1:2)\n"
        ctx = ctx_for(lambda m, u, h, b: resp(500, [("Content-Type", "text/plain")], stack))
        self.assertEqual(exposure.error_leaks(ctx).status, "fail")


class RateLimitTest(unittest.TestCase):
    def ctx(self, statuses, retry_after="60", **opts):
        seq = list(statuses)

        def route(m, u, h, b):
            status = seq.pop(0) if seq else statuses[-1]
            headers = [("Retry-After", retry_after)] if status == 429 and retry_after else []
            return resp(status, headers, '{"error":"x"}')
        return ctx_for(route, rate_limit_path="/api/login", **opts)

    def test_429_passes(self):
        r = ratelimit.login_rate_limit(self.ctx([401] * 5 + [429]))
        self.assertEqual(r.status, "pass")
        self.assertIn("5 attempts", r.summary)

    def test_429_without_retry_after_warns(self):
        self.assertEqual(ratelimit.login_rate_limit(self.ctx([401, 429], retry_after="")).status, "warn")

    def test_no_limit_observed_warns(self):
        ctx = self.ctx([401], rate_limit_attempts=10)
        r = ratelimit.login_rate_limit(ctx)
        self.assertEqual(r.status, "warn")
        self.assertIn("No limit observed up to 10", r.summary)
        self.assertEqual(len(ctx.client.calls), 10)

    def test_too_few_attempts_warns(self):
        for n in (0, 3):
            with self.subTest(attempts=n):
                self.assertEqual(ratelimit.login_rate_limit(self.ctx([401], rate_limit_attempts=n)).status, "warn")

    def test_attempts_capped(self):
        ctx = self.ctx([401], rate_limit_attempts=1000)
        ratelimit.login_rate_limit(ctx)
        self.assertEqual(len(ctx.client.calls), ratelimit.MAX_ATTEMPTS)

    def test_no_path_is_manual(self):
        ctx = ctx_for(lambda m, u, h, b: resp(401))
        self.assertEqual(ratelimit.login_rate_limit(ctx).status, "manual")
        self.assertEqual([c for c in ctx.client.calls if c[0] != "GET"], [])

    def test_404_first_is_error(self):
        ctx = self.ctx([404])
        self.assertEqual(ratelimit.login_rate_limit(ctx).status, "error")
        self.assertEqual(len(ctx.client.calls), 1)


def doh(*records):
    return json.dumps({"Status": 0, "Answer": [{"name": "x", "type": 16, "data": r} for r in records]})


class DnsTest(unittest.TestCase):
    def ctx(self, txt, target="https://www.example.com", status=200, **opts):
        """txt: {name: [record data strings as the resolver returns them]}"""
        def route(m, u, h, b):
            name = u.split("name=")[1].split("&")[0]
            return resp(status, [("Content-Type", "application/dns-json")], doh(*txt.get(name, [])))
        return ctx_for(route, target, **opts)

    def test_txt_records_joins_quoted_strings(self):
        ctx = self.ctx({"example.com": ['"v=spf1 include:_spf.example.com " "-all"']})
        self.assertEqual(dns_email.txt_records(ctx, "example.com"), ["v=spf1 include:_spf.example.com -all"])
        self.assertTrue(ctx.client.calls[0][1].startswith(dns_email.DEFAULT_RESOLVER))

    def test_resolver_error_raises(self):
        with self.assertRaises(OSError):
            dns_email.txt_records(self.ctx({}, status=500), "example.com")

    def test_mail_domain_drops_www(self):
        self.assertEqual(dns_email.mail_domain(self.ctx({})), "example.com")

    def test_spf(self):
        mail = {"mail.test": ['"v=spf1 ip4:192.0.2.0/24 -all"'], "_spf.mail.test": ['"v=spf1 ip4:192.0.2.0/24 ~all"']}
        cases = [(['"v=spf1 include:mail.test -all"'], "pass"), (['"v=spf1 ~all"'], "pass"),
                 (['"v=spf1 +all"'], "fail"), (['"v=spf1 all"'], "fail"), (['"v=spf1 ?all"'], "warn"),
                 (['"v=spf1 include:mail.test"'], "warn"), (['"v=spf1 redirect=_spf.mail.test"'], "pass"),
                 (['"v=spf1 -all"', '"v=spf1 ~all"'], "fail"), (['"google-site-verification=x"'], "fail"), ([], "fail")]
        for records, want in cases:
            with self.subTest(records=records):
                self.assertEqual(dns_email.spf(self.ctx({"example.com": records, **mail})).status, want)

    def spf_ctx(self, zone, nxdomain=()):
        """zone: {name: [SPF strings]}; names in nxdomain answer NXDOMAIN. Every query is recorded."""
        def route(m, u, h, b):
            name = u.split("name=")[1].split("&")[0]
            if name in nxdomain:
                return resp(200, [], json.dumps({"Status": 3}))
            return resp(200, [], doh(*[f'"{r}"' for r in zone.get(name, [])]))
        return ctx_for(route, "https://www.example.com")

    def test_spf_redirect_is_walked(self):
        c = self.spf_ctx({"example.com": ["v=spf1 redirect=_spf.example.com"], "_spf.example.com": ["v=spf1 +all"]})
        r = dns_email.spf(c)
        self.assertEqual(r.status, "fail")
        self.assertIn("redirects to a record that ends in +all", r.summary)
        c = self.spf_ctx({"example.com": ["v=spf1 redirect=_spf.example.com"], "_spf.example.com": ["v=spf1 ?all"]})
        self.assertEqual(dns_email.spf(c).status, "warn")
        c = self.spf_ctx({"example.com": ["v=spf1 redirect=_spf.example.com"],
                          "_spf.example.com": ["v=spf1 include:x.test -all"], "x.test": ["v=spf1 a -all"]})
        r = dns_email.spf(c)
        self.assertEqual(r.status, "pass")
        self.assertIn("needs 3 of 10 DNS lookups", r.summary)

    def test_spf_more_than_ten_lookups_fails(self):
        zone = {"example.com": ["v=spf1 include:a.test include:b.test mx -all"],
                "a.test": ["v=spf1 a mx ptr exists:x.a.test include:c.test -all"],
                "b.test": ["v=spf1 a:h.b.test mx:m.b.test -all"],
                "c.test": ["v=spf1 ip4:192.0.2.1 -all"]}
        r = dns_email.spf(self.spf_ctx(zone))  # 3 at the top + 5 in a.test + 2 in b.test = 10: still allowed
        self.assertEqual(r.status, "pass", r.summary)
        self.assertIn("10 of 10", r.summary)
        zone["example.com"] = ["v=spf1 include:a.test include:b.test mx a -all"]  # 11
        r = dns_email.spf(self.spf_ctx(zone))
        self.assertEqual(r.status, "fail")
        self.assertIn("RFC 7208 4.6.4", r.summary)

    def test_spf_exactly_ten_and_eleven(self):
        ten = {"example.com": ["v=spf1 " + " ".join(["a"] * 10) + " -all"]}
        self.assertEqual(dns_email.spf(self.spf_ctx(ten)).status, "pass")
        eleven = {"example.com": ["v=spf1 " + " ".join(["a"] * 9) + " mx include:i.test -all"],
                  "i.test": ["v=spf1 -all"]}
        r = dns_email.spf(self.spf_ctx(eleven))
        self.assertEqual(r.status, "fail")
        self.assertIn("more than 10 DNS lookups", r.summary)

    def test_spf_include_loop_is_bounded(self):
        zone = {"example.com": ["v=spf1 include:loop.test -all"], "loop.test": ["v=spf1 include:loop.test -all"]}
        c = self.spf_ctx(zone)
        self.assertEqual(dns_email.spf(c).status, "fail")
        self.assertLessEqual(len(c.client.calls), dns_email.MAX_LOOKUPS + 1)

    def test_spf_broken_include_or_redirect_fails(self):
        cases = [
            ({"example.com": ["v=spf1 include:gone.test -all"]}, ("gone.test",), "does not exist (NXDOMAIN)"),
            ({"example.com": ["v=spf1 include:empty.test -all"]}, (), "has no SPF record"),
            ({"example.com": ["v=spf1 redirect=gone.test"]}, ("gone.test",), "redirect gone.test does not exist"),
            ({"example.com": ["v=spf1 include:two.test -all"], "two.test": ["v=spf1 -all", "v=spf1 ~all"]}, (),
             "has 2 SPF records"),
            ({"example.com": ["v=spf1 include:open.test -all"], "open.test": ["v=spf1 +all"]}, (), "ends in +all"),
            ({"example.com": ["v=spf1 include:a.test -all"], "a.test": ["v=spf1 redirect=b.test"],
              "b.test": ["v=spf1 +all"]}, (), "include a.test ends in +all"),
        ]
        for zone, nx, words in cases:
            with self.subTest(zone=zone):
                r = dns_email.spf(self.spf_ctx(zone, nx))
                self.assertEqual(r.status, "fail")
                self.assertIn(words, r.summary)

    def test_spf_redirect_ignored_when_all_present_and_macros_not_walked(self):
        c = self.spf_ctx({"example.com": ["v=spf1 -all redirect=gone.test"]}, ("gone.test",))
        self.assertEqual(dns_email.spf(c).status, "pass")
        c = self.spf_ctx({"example.com": ["v=spf1 include:%{i}._spf.example.com -all"]})
        self.assertEqual(dns_email.spf(c).status, "pass")
        self.assertEqual(len(c.client.calls), 1)

    def test_dmarc(self):
        cases = [(['"v=DMARC1; p=reject; rua=mailto:d@example.com"'], "pass"), (['"v=DMARC1; p=quarantine; rua=mailto:d@example.com"'], "pass"),
                 (['"v=DMARC1; p=quarantine"'], "warn"),
                 (['"v=DMARC1; p=none"'], "warn"), (['"v=DMARC1; p=reject; pct=50"'], "warn"),
                 (['"v=DMARC1"'], "warn"), ([], "fail")]
        for records, want in cases:
            with self.subTest(records=records):
                self.assertEqual(dns_email.dmarc(self.ctx({"_dmarc.example.com": records})).status, want)

    def test_dmarc_inherits_from_organizational_domain(self):
        org = {"_dmarc.example.com": ['"v=DMARC1; p=reject; sp=reject; rua=mailto:d@example.com"']}
        r = dns_email.dmarc(self.ctx(org, target="https://app.example.com"))
        self.assertEqual(r.status, "pass", r.summary)
        self.assertTrue(any("_dmarc.example.com" in e for e in r.evidence))
        weak_sp = {"_dmarc.example.com": ['"v=DMARC1; p=reject; sp=none"']}
        self.assertEqual(dns_email.dmarc(self.ctx(weak_sp, target="https://app.example.com")).status, "warn")
        self.assertEqual(dns_email.dmarc(self.ctx({}, target="https://app.example.com")).status, "fail")

    def test_organizational_domain(self):
        for host, want in (("app.example.com", "example.com"), ("a.b.example.co.uk", "example.co.uk"),
                           ("myapp.vercel.app", "myapp.vercel.app"), ("example.com", "example.com")):
            with self.subTest(host=host):
                self.assertEqual(dns_email.organizational_domain(host), want)

    def test_skips(self):
        for target, opts in (("http://localhost:3000", {}), ("https://app.test", {}), ("https://203.0.113.9", {}),
                             ("https://example.com", {"no_dns": True})):
            with self.subTest(target=target):
                ctx = self.ctx({}, target=target, **opts)
                self.assertEqual(dns_email.spf(ctx).status, "skip")
                self.assertEqual(dns_email.dmarc(ctx).status, "skip")
                self.assertEqual(ctx.client.calls, [])


class SupabaseTest(unittest.TestCase):
    PROJECT = "https://" + "abcdefghijklmnopqrst" + ".supabase.co"
    ROW_SECRET = "row-content-must-never-appear"

    def ctx(self, table_status, rows=True, listed=("profiles", "orders"), allow=True, key=None, tables=None,
            target="https://example.com", authorized=True, js="", root_status=200):
        key = key or fake_jwt("anon")

        def route(m, u, h, b):
            assert u.startswith(self.PROJECT + "/rest/v1/"), u
            assert h.get("apikey") == key
            if u == self.PROJECT + "/rest/v1/":
                if root_status != 200:
                    return resp(root_status, [("Content-Type", "application/json")], "{}")
                paths = {"/": {}, "/rpc/fn": {}, **{f"/{t}": {} for t in listed}}
                return resp(200, [("Content-Type", "application/json")], json.dumps({"paths": paths}))
            table = u.split("/rest/v1/")[1].split("?")[0]
            status = table_status.get(table, 401)
            # Row-free probe: HEAD with an exact count; the count comes back in Content-Range, no row in a body.
            assert m == "HEAD" and h.get("Prefer") == "count=exact", (m, h)
            headers = [("Content-Type", "application/json")]
            if status == 200:
                headers.append(("Content-Range", "0-0/3" if rows else "*/0"))
            return resp(status, headers, "")
        ctx = ctx_for(route, target, allow_supabase=allow, supabase_tables=tables)
        ctx.authorized = authorized
        ctx.cache["scripts"] = [("/app.js", f'const u="{self.PROJECT}";const k="{key}";{js}')]
        return ctx

    def everything(self, r):
        return r.summary + " ".join(r.evidence)

    def test_readable_table_fails(self):
        r = supabase.anon_tables(self.ctx({"profiles": 200}))
        self.assertEqual(r.status, "fail")
        self.assertIn("profiles", self.everything(r))
        self.assertNotIn(self.ROW_SECRET, self.everything(r))

    def test_refused_passes(self):
        r = supabase.anon_tables(self.ctx({}))
        self.assertEqual(r.status, "pass")
        self.assertNotIn(self.ROW_SECRET, self.everything(r))

    def test_empty_warns(self):
        r = supabase.anon_tables(self.ctx({"profiles": 200, "orders": 200}, rows=False))
        self.assertEqual(r.status, "warn")

    def test_no_allow_flag_is_manual_and_offline(self):
        ctx = self.ctx({"profiles": 200}, allow=False)
        r = supabase.anon_tables(ctx)
        self.assertEqual(r.status, "manual")
        self.assertEqual(ctx.client.calls, [])

    def test_publishable_key_and_named_tables(self):
        key = "sb_" + "publishable_" + "A1b2C3d4E5f6G7h8I9j0K1"
        ctx = self.ctx({"notes": 200}, key=key, tables=["notes", "bad;name"])
        r = supabase.anon_tables(ctx)
        self.assertEqual(r.status, "fail")
        self.assertNotIn("Authorization", ctx.client.calls[0][2])
        self.assertEqual(len(ctx.client.calls), 1)

    def test_tables_from_bundle_before_api_root(self):
        js = 'x.from("profiles").select();Array.from("ab");Buffer.from("cd");y.from(\'orders\')'
        ctx = self.ctx({"orders": 200}, js=js, root_status=401)
        r = supabase.anon_tables(ctx)
        self.assertEqual(r.status, "fail")
        tried = [u.split("/rest/v1/")[1].split("?")[0] for _, u, _ in ctx.client.calls]
        self.assertEqual(tried, ["profiles", "orders"])

    def test_api_root_refused_is_manual(self):
        r = supabase.anon_tables(self.ctx({}, root_status=401))
        self.assertEqual(r.status, "manual")
        self.assertIn("--supabase-table", r.summary)

    def test_local_target_needs_authorized(self):
        ctx = self.ctx({"profiles": 200}, target="http://localhost:3000", authorized=False)
        r = supabase.anon_tables(ctx)
        self.assertEqual(r.status, "manual")
        self.assertIn("--authorized", r.summary)
        self.assertEqual(ctx.client.calls, [])
        ctx = self.ctx({"profiles": 200}, target="http://localhost:3000", authorized=True)
        self.assertEqual(supabase.anon_tables(ctx).status, "fail")

    def test_no_project_skips(self):
        ctx = ctx_for(lambda m, u, h, b: resp(404), allow_supabase=True)
        ctx.cache["scripts"] = [("/app.js", "var a=1")]
        self.assertEqual(supabase.anon_tables(ctx).status, "skip")

    def test_project_without_key_is_manual(self):
        ctx = ctx_for(lambda m, u, h, b: resp(404), allow_supabase=True)
        ctx.cache["scripts"] = [("/app.js", f'const u="{self.PROJECT}";const k="{fake_jwt("service_role")}"')]
        self.assertEqual(supabase.anon_tables(ctx).status, "manual")


class TransportLocalTest(unittest.TestCase):
    def test_local_skips_without_network(self):
        for target in ("https://localhost:3000", "https://app.localhost", "https://site.test", "https://127.0.0.1:8443"):
            ctx = ctx_for(lambda m, u, h, b: resp(200), target)
            with self.subTest(target=target):
                self.assertEqual(transport.https_redirect(ctx).status, "skip")
                self.assertEqual(transport.certificate(ctx).status, "skip")
                self.assertEqual(transport.legacy_tls(ctx).status, "skip")
                self.assertEqual(ctx.client.calls, [])

    def test_plain_http_non_local(self):
        ctx = ctx_for(lambda m, u, h, b: resp(200), "http://example.com")
        self.assertEqual(transport.https_redirect(ctx).status, "fail")
        self.assertEqual(transport.certificate(ctx).status, "skip")
        self.assertEqual(transport.legacy_tls(ctx).status, "skip")


if __name__ == "__main__":
    unittest.main()
