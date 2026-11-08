"""Regression tests for live-check accuracy: a pass needs observed evidence, a fail needs an observed flaw, and hostile
responses never crash a check. Stub clients only; nothing leaves the machine."""

import json
import unittest
from urllib.parse import parse_qs, unquote, urlsplit

from agent_security_audit import catalog, runner, scope
from agent_security_audit.checks import (
    Context,
    browser,
    count,
    dns_email,
    exposure,
    ratelimit,
    supabase,
    transport,
    webapp,
)
from agent_security_audit.crawl import crawl
from agent_security_audit.http import Response

T = "https://example.test"


def resp(status=200, headers=(), body=b"", url=T + "/"):
    if isinstance(body, str):
        body = body.encode()
    return Response(url, status, "", list(headers), body)


def html(body, *headers, status=200):
    return resp(status, [("Content-Type", "text/html; charset=utf-8"), *headers], f"<html><body>{body}</body></html>")


class Stub:
    """Serves {path_or_path_with_query: Response | callable(method, url, headers, body)}; anything else is 404.
    Refuses any URL outside the target origin."""

    timeout = 1.0

    def __init__(self, target, routes):
        self.target, self.routes, self.calls, self.sent = target, routes, [], 0

    def url(self, path):
        return path if path.startswith(("http://", "https://")) else self.target + "/" + path.lstrip("/")

    def request(self, method, path="/", *, headers=None, body=None, cache=False):
        url = self.url(path)
        if not scope.same_origin(self.target, url):
            raise AssertionError(f"off-origin request {url}")
        self.calls.append((method, url, headers or {}, body))
        self.sent += 1
        parts = urlsplit(url)
        route = self.routes.get(parts.path + ("?" + parts.query if parts.query else ""), self.routes.get(parts.path))
        out = resp(404) if route is None else route(method, url, headers or {}, body) if callable(route) else route
        return Response(url, out.status, out.reason, out.headers, out.body)

    def get(self, path="/", **kw):
        return self.request("GET", path, **kw)

    def home(self):
        return self.get("/")

    def external(self, method, url, *, headers=None, body=None):
        self.calls.append((method, url, headers or {}, body))
        return self.routes["external"](method, url, headers or {}, body)


def ctx(routes, target=T, **options):
    return Context(target, Stub(target, routes), options)


class GraphqlProofTest(unittest.TestCase):
    """API-23 passes only when the answer is provably GraphQL."""

    def run_check(self, status, body, ctype="application/json"):
        r = resp(status, [("Content-Type", ctype)], json.dumps(body))
        return webapp.graphql_introspection(ctx({"/graphql": r, "/api/graphql": r}))

    def test_generic_json_404_is_not_graphql(self):
        self.assertEqual(self.run_check(404, {"errors": [{"message": "Route not found"}]}).status, "skip")
        # A 404 that echoes the path names "graphql" but is still not GraphQL.
        self.assertEqual(self.run_check(404, {"errors": [{"message": "Cannot POST /graphql"}]}).status, "skip")

    def test_generic_json_errors_elsewhere_are_manual(self):
        self.assertEqual(self.run_check(400, {"errors": [{"message": "Bad request"}]}).status, "manual")

    def test_echoed_probe_is_not_a_refusal(self):
        # A REST validator that echoes the request body back contains __schema and the probe's name, not GraphQL.
        query = json.loads(webapp.INTROSPECTION)["query"]
        for status in (400, 404, 422):
            with self.subTest(status=status):
                body = {"errors": [{"message": f"invalid body: {query}", "value": query}]}
                self.assertNotEqual(self.run_check(status, body).status, "pass")

    def test_status_comes_before_media_type(self):
        gql = "application/graphql-response+json"
        self.assertEqual(self.run_check(404, {"errors": [{"message": "x"}]}, gql).status, "skip")
        for status in (401, 403, 429, 503):
            with self.subTest(status=status):
                self.assertEqual(self.run_check(status, {"errors": [{"message": "x"}]}, gql).status, "manual")
                self.assertEqual(self.run_check(status, {"errors": [{"message": "GraphQL introspection is not allowed"}]})
                                 .status, "manual")

    def test_auth_or_throttle_answer_without_graphql_errors_names_the_status(self):
        # A plain 401, 429 or firewall page proves neither an endpoint nor its absence: skip, but say so.
        answers = [resp(401, [("Content-Type", "application/json")], json.dumps({"error": "unauthorized"})),
                   resp(429, [("Content-Type", "text/plain")], "slow down"),
                   resp(403, [("Content-Type", "text/html"), ("cf-mitigated", "challenge")], "<html>challenge</html>")]
        for r in answers:
            with self.subTest(status=r.status):
                out = webapp.graphql_introspection(ctx({"/graphql": r, "/api/graphql": r}))
                self.assertEqual(out.status, "skip")
                self.assertIn(f"/graphql ({r.status})", out.summary)
                self.assertNotIn("No GraphQL endpoint", out.summary)

    def test_challenge_answer_is_manual(self):
        r = resp(400, [("Content-Type", "application/graphql-response+json"), ("cf-mitigated", "challenge")],
                 json.dumps({"errors": [{"message": "x"}]}))
        self.assertEqual(webapp.graphql_introspection(ctx({"/graphql": r})).status, "manual")

    def test_echoed_probe_alone_is_manual(self):
        query = json.loads(webapp.INTROSPECTION)["query"]
        for status in (200, 400, 422):
            with self.subTest(status=status):
                self.assertEqual(self.run_check(status, {"errors": [{"message": query}]}).status, "manual")
                self.assertEqual(self.run_check(status, {"errors": [{"message": "AsaIntrospectionProbe failed"}]})
                                 .status, "manual")

    def test_graphql_media_type_with_parameters_passes(self):
        self.assertEqual(self.run_check(400, {"errors": [{"message": "x"}]},
                                        "application/graphql-response+json; charset=utf-8").status, "pass")
        self.assertEqual(self.run_check(400, {"errors": [{"message": "x"}]}, "text/x-graphql-ish").status, "manual")

    def test_graphql_media_type_or_error_passes(self):
        self.assertEqual(self.run_check(400, {"errors": [{"message": "x"}]}, "application/graphql-response+json").status,
                         "pass")
        for msg in ('Cannot query field "__schema" on type "Query".', "GraphQL introspection is not allowed"):
            with self.subTest(msg=msg):
                self.assertEqual(self.run_check(400, {"errors": [{"message": msg}]}).status, "pass")
        coded = {"errors": [{"message": "x", "extensions": {"code": "GRAPHQL_VALIDATION_FAILED"}}]}
        self.assertEqual(self.run_check(400, coded).status, "pass")


class SupabaseProofTest(unittest.TestCase):
    PROJECT = "https://" + "abcdefghijklmnopqrst" + ".supabase.co"

    def run_check(self, answers, js=""):
        """answers: {table: (status, content_range or None)}"""
        def external(m, u, h, b):
            table = u.split("/rest/v1/")[1].split("?")[0]
            status, cr = answers.get(table, (401, None))
            return resp(status, [("Content-Range", cr)] if cr else [], "")
        c = ctx({"external": external}, allow_supabase=True)
        c.authorized = True
        c.cache["scripts"] = [("/app.js", f'const u="{self.PROJECT}";const k="sb_publishable_{"a" * 22}";'
                                          + (js or "".join(f'db.from("{t}");' for t in answers)))]
        return c, supabase.anon_tables(c)

    def test_404_is_not_a_refusal(self):
        _, r = self.run_check({"typo": (404, None)})
        self.assertEqual(r.status, "manual")
        _, r = self.run_check({"profiles": (401, None), "typo": (404, None)})
        self.assertEqual(r.status, "manual")
        _, r = self.run_check({"profiles": (500, None)})
        self.assertEqual(r.status, "manual")

    def test_401_and_403_pass(self):
        _, r = self.run_check({"profiles": (401, None), "orders": (403, None)})
        self.assertEqual(r.status, "pass", r.summary)

    def test_row_free_probe(self):
        c, r = self.run_check({"profiles": (200, "0-0/42"), "notes": (200, "*/0")})
        self.assertEqual(r.status, "fail")
        self.assertIn("profiles (42 rows)", " ".join(r.evidence))
        for method, url, headers, body in c.client.calls:
            self.assertEqual(method, "HEAD")
            self.assertEqual(headers.get("Prefer"), "count=exact")
            self.assertIsNone(body)
        _, r = self.run_check({"notes": (200, "*/0")})
        self.assertEqual(r.status, "warn")
        _, r = self.run_check({"notes": (200, None)})  # no count: nothing proven
        self.assertEqual(r.status, "manual")

    def test_storage_buckets_are_not_tables(self):
        c, _ = self.run_check({}, js='supabase.storage.from("avatars").upload(x);db.from("profiles");')
        tried = [u.split("/rest/v1/")[1].split("?")[0] for _, u, _, _ in c.client.calls]
        self.assertEqual(tried, ["profiles"])

    def test_catalog_proof_says_no_rows_are_fetched(self):
        proof = catalog.by_id()["ACCESS-01"].proof
        self.assertIn("HEAD", proof)
        self.assertIn("count=exact", proof)


class HttpsRedirectTest(unittest.TestCase):
    def run_check(self, exc):
        c = ctx({}, target="https://example.com")

        def same_host(method, url, **kw):
            raise exc
        c.client.same_host = same_host
        return transport.https_redirect(c)

    def test_timeout_is_not_a_pass(self):
        self.assertEqual(self.run_check(TimeoutError("timed out")).status, "manual")

    def test_slow_drip_cut_is_not_a_pass(self):
        from agent_security_audit.http import ResponseTooSlow
        self.assertEqual(self.run_check(ResponseTooSlow("no complete response within 1 s")).status, "error")

    def test_refused_passes(self):
        self.assertEqual(self.run_check(ConnectionRefusedError()).status, "pass")


class RateLimitVerdictTest(unittest.TestCase):
    def run_check(self, answer, attempts=30, routes=None, **opts):
        n = {"i": 0}

        def login(m, u, h, b):
            n["i"] += 1
            return answer(n["i"])
        routes = dict(routes or {})
        routes.setdefault("/api/login", login)
        c = ctx(routes, rate_limit_attempts=attempts, **opts)
        return c, ratelimit.login_rate_limit(c)

    def test_status_change_is_throttling(self):
        # Firebase style: 400 TOO_MANY_ATTEMPTS_TRY_LATER after five 401s.
        def answer(i):
            if i > 5:
                return resp(400, [], '{"error":{"message":"TOO_MANY_ATTEMPTS_TRY_LATER"}}')
            return resp(401, [], '{"error":"bad creds"}')
        c, r = self.run_check(answer, rate_limit_path="/api/login")
        self.assertEqual(r.status, "warn")
        self.assertIn("after 5 attempts", r.summary)
        self.assertEqual(len([x for x in c.client.calls if x[0] == "POST"]), 6)

    def test_lockout_text_with_same_status_is_throttling(self):
        def answer(i):
            return resp(401, [], "Account locked, try again later" if i > 3 else "Wrong password")
        _, r = self.run_check(answer, rate_limit_path="/api/login")
        self.assertEqual(r.status, "warn")
        self.assertIn("after 3 attempts", r.summary)

    def test_single_server_error_is_not_throttling(self):
        _, r = self.run_check(lambda i: resp(502 if i == 7 else 401, [], "x"), rate_limit_path="/api/login")
        self.assertEqual(r.status, "warn")
        self.assertNotIn("Throttled", r.summary)
        self.assertIn("Inconsistent responses, no limit proven: 1 server error (502)", r.summary)

    def test_intermittent_and_repeated_server_errors_are_not_throttling(self):
        for answer in (lambda i: resp(503 if i % 4 == 0 else 401, [], "x"),
                       lambda i: resp(500 if i > 8 else 401, [], "x")):
            with self.subTest(answer=answer):
                _, r = self.run_check(answer, rate_limit_path="/api/login")
                self.assertEqual(r.status, "warn")
                self.assertNotIn("Throttled", r.summary)
                self.assertIn("Inconsistent responses, no limit proven", r.summary)
                self.assertIn("server errors", r.summary)

    def test_new_status_without_limit_wording_is_not_throttling(self):
        for status in (400, 403):
            with self.subTest(status=status):
                _, r = self.run_check(lambda i, s=status: resp(s if i > 8 else 401, [], "x"),
                                      rate_limit_path="/api/login")
                self.assertNotIn("Throttled", r.summary)
                self.assertIn("No limit observed", r.summary)

    def test_captcha_wording_is_throttling(self):
        _, r = self.run_check(lambda i: resp(403 if i > 6 else 401, [], "Complete the captcha" if i > 6 else "x"),
                              rate_limit_path="/api/login")
        self.assertIn("Throttled after 6 attempts", r.summary)

    def test_lockout_status_counts_at_once(self):
        c, r = self.run_check(lambda i: resp(423 if i > 4 else 401, [], "x"), rate_limit_path="/api/login")
        self.assertIn("Throttled after 4 attempts", r.summary)
        self.assertEqual(len([x for x in c.client.calls if x[0] == "POST"]), 5)

    def test_no_change_is_a_warning_not_a_fail(self):
        _, r = self.run_check(lambda i: resp(401, [], "Wrong password"), rate_limit_path="/api/login")
        self.assertEqual(r.status, "warn")
        self.assertIn("No limit observed up to 30", r.summary)

    def test_login_form_detected_from_crawl(self):
        page = html('<form method="post" action="/session"><input name="username"><input name="csrf" type="hidden">'
                    '<input name="pass" type="password"></form>')
        c, r = self.run_check(None, attempts=12, routes={
            "/": html('<a href="/login">in</a><a href="/signup">up</a>'),
            "/login": page,
            "/signup": html('<form method="post" action="/users"><input name="email" type="email">'
                            '<input name="password" type="password"></form>'),
            "/session": lambda m, u, h, b: resp(429 if b and "pass=" in b else 401, [("Retry-After", "30")]),
        })
        self.assertEqual(r.status, "pass", r.summary)
        posts = [x for x in c.client.calls if x[0] == "POST"]
        self.assertTrue(posts)
        self.assertTrue(all(urlsplit(u).path == "/session" for _, u, _, _ in posts))
        sent = parse_qs(posts[0][3])
        self.assertEqual(sent, {"username": [ratelimit.FAKE_EMAIL], "pass": [ratelimit.FAKE_PASSWORD]})
        self.assertIn("password form on /login", " ".join(r.evidence))

    def test_signup_and_off_site_forms_are_never_used(self):
        c, r = self.run_check(None, routes={
            "/": html('<form method="post" action="/register"><input name="password" type="password"></form>'
                      '<form method="post" action="https://auth.other.test/login">'
                      '<input name="password" type="password"></form>')})
        self.assertEqual(r.status, "manual")
        self.assertFalse([x for x in c.client.calls if x[0] == "POST"])

    def test_detected_form_refused_by_csrf_is_manual(self):
        c, r = self.run_check(None, routes={
            "/": html('<form method="post" action="/login"><input name="password" type="password"></form>'),
            "/login": lambda m, u, h, b: resp(403, [], "CSRF token missing") if m == "POST" else html("x")})
        self.assertEqual(r.status, "manual")
        self.assertEqual(len([x for x in c.client.calls if x[0] == "POST"]), 1)


class CookieNameTest(unittest.TestCase):
    def status(self, *cookies):
        return browser.cookies(ctx({"/": html("x", *[("Set-Cookie", c) for c in cookies])})).status

    def test_double_submit_csrf_cookies_are_exempt(self):
        for name in ("csrftoken", "XSRF-TOKEN", "_csrf", "csrf_token", "__Host-csrf"):
            with self.subTest(name=name):
                self.assertEqual(self.status(f"{name}=abc; Secure; SameSite=Lax"), "pass")

    def test_generic_substrings_are_not_sessions(self):
        for name in ("author", "consider_banner", "authorized_view", "tokenizer_pref"):
            with self.subTest(name=name):
                self.assertEqual(self.status(f"{name}=1; Secure; SameSite=Lax"), "pass")

    def test_real_session_names_still_fail(self):
        for name in ("connect.sid", "authToken", "PHPSESSID", "laravel_session", "next-auth.session-token",
                     "refresh_token"):
            with self.subTest(name=name):
                self.assertEqual(self.status(f"{name}=1; Secure; SameSite=Lax"), "fail")


    def test_run_together_platform_session_names_fail(self):
        for name in (".ASPXAUTH", "ASPSESSIONIDQQAB", "SESSa1b2c3d4", "SSESSa1b2c3d4", "MOODLESESSION", "CFTOKEN"):
            with self.subTest(name=name):
                self.assertEqual(self.status(f"{name}=abc; Secure; SameSite=Lax"), "fail")

    def test_known_platform_session_names_fail(self):
        for name in (".ASPXAUTH", "ASPSESSIONIDQACRBTCT", "ASP.NET_SessionId", "SESS0123abcdef", "SSESS0123abcdef",
                     "MOODLESESSION", "CFID", "CFTOKEN", "JSESSIONID", "PHPSESSID", "laravel_session", "connect.sid",
                     "sid", "myapp_session", "myapp-session", "__Host-sid", "__Secure-sid", "__Host-PHPSESSID",
                     "__Secure-myapp_session"):
            with self.subTest(name=name):
                self.assertEqual(self.status(f"{name}=abc; Secure; SameSite=Lax"), "fail")

    def test_prefixed_csrf_cookies_stay_exempt(self):
        for name in ("__Host-XSRF-TOKEN", "__Secure-csrftoken"):
            with self.subTest(name=name):
                self.assertEqual(self.status(f"{name}=abc; Secure; SameSite=Lax"), "pass")

    def test_home_page_is_counted_once(self):
        r = browser.cookies(ctx({"/": html("x", ("Set-Cookie", "a=1; Secure; HttpOnly; SameSite=Lax"))}))
        self.assertEqual(r.status, "pass")
        self.assertIn("1 crawled page", r.summary)


class ErrorPathProofTest(unittest.TestCase):
    """API-02 passes only when a handler's error path answered, not auth middleware, a CDN or a WAF."""

    def run_check(self, status, headers=()):
        class Every(dict):
            def get(self, key, default=None):
                return resp(status, [("Content-Type", "text/html"), *headers], "Blocked")
        c = ctx({})
        c.client.routes = Every()
        return exposure.error_leaks(c)

    def test_auth_and_block_answers_are_manual(self):
        for status in (401, 403, 407, 429):
            with self.subTest(status=status):
                self.assertEqual(self.run_check(status).status, "manual")

    def test_handler_error_passes(self):
        self.assertEqual(self.run_check(400).status, "pass")

    def test_gateway_and_challenge_answers_are_manual(self):
        for status, headers in ((503, ()), (502, ()), (504, ()), (403, [("cf-mitigated", "challenge")]),
                                (400, [("cf-mitigated", "challenge")]), (500, [("x-vercel-mitigated", "challenge")])):
            with self.subTest(status=status, headers=headers):
                self.assertEqual(self.run_check(status, headers).status, "manual")


class LibraryBannerTest(unittest.TestCase):
    def test_requires_line_in_a_plugin_header_is_not_jquery(self):
        text = "/*!\n * jQuery Form Plugin\n * version: 4.3.0\n * Requires jQuery v1.7.2 or later\n */\n;(function(){})();"
        self.assertEqual(webapp.find_libraries("x", text=text), [])
        self.assertEqual(webapp.find_libraries("x", text="// works with jQuery v1.12.4 and up\n"), [])

    def test_banner_inside_a_bundle_still_counts(self):
        text = "var a=1;\n/*! jQuery v3.4.1 | (c) JS Foundation */\n!function(){}();"
        self.assertEqual(webapp.find_libraries("x", text=text)[0][:2], ("jquery", "3.4.1"))
        text = "/*!\n * jQuery JavaScript Library v1.7.2\n * http://jquery.com/\n */"
        self.assertEqual(webapp.find_libraries("x", text=text)[0][:2], ("jquery", "1.7.2"))


class OpenRedirectFormsTest(unittest.TestCase):
    def run_check(self, answer):
        def route(m, u, h, b):
            return answer(parse_qs(urlsplit(u).query).get("next", ["/"])[0])
        c = ctx({"/": html('<a href="/login?next=/account">in</a>'), "/login": route})
        return c, webapp.open_redirect(c)

    def test_scheme_relative_and_backslash_forms(self):
        # Blocks absolute URLs only: "//host" still leaves the site.
        _, r = self.run_check(lambda d: resp(302, [("Location", d if d.startswith("/") else "/")]))
        self.assertEqual(r.status, "fail")
        self.assertIn("//<probe>/", " ".join(r.evidence))
        # Blocks "//" but not "/\": browsers read a backslash as a slash.
        _, r = self.run_check(lambda d: resp(302, [("Location", d if d.startswith("/") and not d.startswith("//")
                                                    else "/")]))
        self.assertEqual(r.status, "fail")

    def test_double_decoding_app(self):
        def answer(d):
            d = unquote(d)
            return resp(302, [("Location", d if d.startswith("/") and not d.startswith(("//", "/\\")) else "/")]) \
                if not d.startswith("//") or "%" in d else resp(302, [("Location", d)])
        _, r = self.run_check(answer)
        self.assertEqual(r.status, "fail")

    def test_refresh_header_and_meta_refresh(self):
        _, r = self.run_check(lambda d: resp(200, [("Refresh", f"0; url={d}")]) if "://" in d else html("x"))
        self.assertEqual(r.status, "fail")
        self.assertIn("Refresh header", " ".join(r.evidence))
        _, r = self.run_check(lambda d: html(f'<meta http-equiv="refresh" content="0;URL=\'{d}\'">'))
        self.assertEqual(r.status, "fail")
        self.assertIn("meta refresh", " ".join(r.evidence))

    def test_safe_redirects_pass_after_every_form(self):
        c, r = self.run_check(lambda d: resp(302, [("Location", "/account")]))
        self.assertEqual(r.status, "pass")
        self.assertEqual(len([u for _, u, _, _ in c.client.calls if "asa-redirect-probe" in unquote(unquote(u))]),
                         len(webapp.REDIRECT_PROBES))

    def test_probes_only_name_the_reserved_host(self):
        for value in webapp.REDIRECT_PROBES:
            self.assertIn(webapp.REDIRECT_HOST, unquote(value))
        self.assertTrue(webapp.REDIRECT_HOST.endswith(".invalid"))

    def test_redirect_host_reads_urls_like_a_browser(self):
        base = "https://site.test/login?next=x"
        cases = {"//evil.invalid/": "evil.invalid", "/\\evil.invalid/": "evil.invalid", "\\\\evil.invalid": "evil.invalid",
                 " //evil.invalid": "evil.invalid", "/\t/evil.invalid": "evil.invalid",
                 "https:evil.invalid": "site.test", "http:evil.invalid": "evil.invalid", "/account": "site.test",
                 "http://[::1": None}
        for loc, want in cases.items():
            with self.subTest(loc=loc):
                self.assertEqual(webapp.redirect_host(base, loc), want)


class PerPageHeaderTest(unittest.TestCase):
    def site(self, home_headers, about_headers, about_body="about"):
        return ctx({"/": html('<a href="/about">a</a>', *home_headers), "/about": html(about_body, *about_headers)})

    def test_header_missing_on_a_deeper_page_fails_and_names_it(self):
        nosniff = ("X-Content-Type-Options", "nosniff")
        r = browser.nosniff(self.site([nosniff], []))
        self.assertEqual(r.status, "fail")
        self.assertIn("/about", r.summary)
        self.assertIn("page: /about", r.evidence)
        r = browser.nosniff(self.site([nosniff], [nosniff]))
        self.assertEqual(r.status, "pass")
        self.assertIn("all 2 crawled pages", r.summary)

    def test_meta_csp_counts(self):
        meta = '<meta http-equiv="Content-Security-Policy" content="default-src \'self\'; object-src \'none\'; base-uri \'none\'">'
        c = ctx({"/": html(meta)})
        self.assertEqual(browser.csp(c).status, "pass")
        weak = '<meta http-equiv="content-security-policy" content="script-src * \'unsafe-inline\'">'
        self.assertEqual(browser.csp(ctx({"/": html(weak)})).status, "fail")

    def test_meta_frame_ancestors_is_ignored(self):
        meta = '<meta http-equiv="Content-Security-Policy" content="frame-ancestors \'none\'">'
        self.assertEqual(browser.framing(ctx({"/": html(meta)})).status, "fail")

    def test_hsts_without_subdomains_warns(self):
        r = browser.hsts(ctx({"/": html("x", ("Strict-Transport-Security", "max-age=31536000"))}))
        self.assertEqual(r.status, "warn")


class DefaultPortTest(unittest.TestCase):
    def test_default_ports_are_the_same_origin(self):
        self.assertTrue(scope.same_origin("https://example.com", "https://example.com:443/en/"))
        self.assertTrue(scope.same_origin("http://example.com:80", "http://example.com/"))
        self.assertFalse(scope.same_origin("https://example.com", "https://example.com:8443/"))
        self.assertFalse(scope.same_origin("https://example.com", "http://example.com:443/"))
        self.assertFalse(scope.same_origin("https://example.com", "https://example.com:abc/"))
        self.assertEqual(scope.normalize_target("https://example.com:443"), "https://example.com")
        self.assertEqual(scope.normalize_target("http://localhost:80"), "http://localhost")
        self.assertEqual(scope.normalize_target("http://localhost:3000"), "http://localhost:3000")

    def test_redirect_to_explicit_443_does_not_abort(self):
        class Root:
            def get(self, path, cache=False):
                return resp(301, [("Location", "https://example.com:443/en/")])
        self.assertEqual(runner.canonical_target("https://example.com", Root()), "https://example.com")

    def test_crawl_keeps_explicit_443_links(self):
        c = ctx({"/": html('<a href="https://example.test:443/about">a</a>'), "/about": html("about")})
        self.assertIn("/about", [urlsplit(p.url).path for p in crawl(c).pages])


class CalibrationTest(unittest.TestCase):
    def test_missing_security_txt_warns(self):
        self.assertEqual(exposure.security_txt(ctx({})).status, "warn")

    def test_security_txt_redirect_followed_on_site(self):
        body = "Contact: mailto:s@example.test\nExpires: 2999-01-01T00:00:00Z\n"
        c = ctx({"/.well-known/security.txt": resp(301, [("Location", "/security.txt")]),
                 "/security.txt": resp(200, [("Content-Type", "text/plain")], body)})
        self.assertEqual(exposure.security_txt(c).status, "pass")

    def test_security_txt_redirect_off_site_is_manual(self):
        c = ctx({"/.well-known/security.txt": resp(301, [("Location", "https://other.test/.well-known/security.txt")])})
        self.assertEqual(exposure.security_txt(c).status, "manual")
        self.assertEqual(len(c.client.calls), 1)

    def test_catalog_calibration(self):
        checks = catalog.by_id()
        self.assertEqual(checks["INFRA-06"].severity, "medium")
        self.assertEqual(checks["INFRA-07"].severity, "medium")
        self.assertFalse({"CWE-298", "CWE-295"} & set(checks["INFRA-02"].cwe))


class CorsVariantTest(unittest.TestCase):
    def run_check(self, allowed, credentials=True):
        def route(m, u, h, b):
            origin = h.get("Origin", "")
            headers = []
            if allowed(origin):
                headers = [("Access-Control-Allow-Origin", origin)]
                if credentials:
                    headers.append(("Access-Control-Allow-Credentials", "true"))
            return resp(200, headers)
        c = ctx({"/": route}, target="https://example.com")
        return c, browser.cors(c)

    def test_ends_with_allowlist_fails(self):
        _, r = self.run_check(lambda o: o.endswith("example.com"))
        self.assertEqual(r.status, "fail")
        self.assertIn("asa-origin-probe-example.com", r.summary)

    def test_starts_with_allowlist_fails(self):
        _, r = self.run_check(lambda o: o.startswith("https://example.com"))
        self.assertEqual(r.status, "fail")
        self.assertIn("example.com.asa-origin-probe.invalid", r.summary)

    def test_any_subdomain_warns(self):
        _, r = self.run_check(lambda o: o.endswith(".example.com"))
        self.assertEqual(r.status, "warn")

    def test_exact_allowlist_passes(self):
        _, r = self.run_check(lambda o: o == "https://app.example.com")
        self.assertEqual(r.status, "pass")

    def test_probe_origins_are_inert(self):
        c, _ = self.run_check(lambda o: False)
        origins = [h["Origin"] for _, _, h, _ in c.client.calls]
        self.assertEqual(len(origins), 5)
        for o in origins:
            self.assertTrue(o == "null" or "asa-origin-probe" in o, o)
        self.assertTrue(all(scope.same_origin("https://example.com", u) for _, u, _, _ in c.client.calls))


class HostileResponseTest(unittest.TestCase):
    """Malformed links, redirects, encodings and huge bodies must not crash any check."""

    HOSTILE_PAGE = ('<a href="http://[::1">v6</a><a href="http://example.test:abc/">port</a><base href="http://[bad">'
                    '<a href="/ok?next=/x">ok</a><form action="http://[::1" method="post"><input type="password">'
                    '</form><script src="http://x:99999/a.js"></script><meta http-equiv="refresh" content="garbage">'
                    '<meta http-equiv="Content-Security-Policy" content=";;;">')

    def routes(self):
        bad_bytes = b"\xff\xfe\x00<html>\x80\x81" + b"<a href=/x>" * 20000
        return {
            "/": resp(200, [("Content-Type", "text/html; charset=no-such-charset"),
                            ("Set-Cookie", ";;="), ("Strict-Transport-Security", "max-age=abc;;"),
                            ("Content-Security-Policy", ",,, ;")], self.HOSTILE_PAGE),
            "/ok": lambda m, u, h, b: resp(302, [("Location", "http://[::1"), ("Refresh", "x;url=http://x:abc")]),
            "/x": resp(200, [("Content-Type", "text/html")], bad_bytes),
            "/robots.txt": resp(200, [("Content-Type", "text/plain")], "Sitemap: http://[::1\nDisallow: /\x00\n"),
            "/sitemap.xml": resp(200, [("Content-Type", "application/xml")], "<loc>http://[::1</loc><loc>:::</loc>"),
            "/graphql": resp(200, [("Content-Type", "application/json")], "[1, 2]"),
            "/api/graphql": resp(200, [("Content-Type", "application/json")], '{"data": [], "errors": "x"}'),
            "/.well-known/security.txt": resp(302, [("Location", "http://[::1")]),
            "/api/login": resp(401, [("Content-Type", "application/json; charset=utf-16")], b"\xff\xfe\xff"),
            "/openapi.json": resp(200, [("Content-Type", "application/json")], '{"openapi": 3, "paths": []}'),
        }

    def test_checks_survive(self):
        fns = [browser.hsts, browser.csp, browser.nosniff, browser.framing, browser.referrer, browser.cookies,
               browser.cors, browser.isolation, webapp.mixed_content, webapp.subresource_integrity,
               webapp.password_forms, webapp.vulnerable_libraries, webapp.open_redirect, webapp.directory_listing,
               webapp.debug_endpoints, webapp.api_docs, webapp.graphql_introspection, webapp.trace_method,
               exposure.sensitive_files, exposure.security_txt, exposure.client_secrets, exposure.source_maps,
               exposure.powered_by, exposure.error_leaks, ratelimit.login_rate_limit]
        for fn in fns:
            with self.subTest(check=fn.check_id):
                c = ctx(self.routes(), rate_limit_path="/api/login", rate_limit_attempts=12)
                r = fn(c)
                self.assertIn(r.status, ("pass", "fail", "warn", "manual", "skip"), r.summary)

    def test_dns_answer_that_is_not_an_object(self):
        for body in ("[1]", "not json", '{"Answer": [1, {"type": 16, "data": 5}]}'):
            with self.subTest(body=body):
                c = ctx({"external": lambda m, u, h, b, body=body: resp(200, [], body)}, target="https://example.com")
                try:
                    dns_email.txt_records(c, "example.com")
                except OSError:
                    pass


class VerbAgreementTest(unittest.TestCase):
    def test_count(self):
        self.assertEqual(count(1, "file"), "1 file")
        self.assertEqual(count(2, "file"), "2 files")
        self.assertEqual(count(1, "library", "libraries"), "1 library")

    def source_maps(self, n):
        files = {f"/s{i}.js": resp(200, [], "x//# sourceMappingURL=s.map") for i in range(n)}
        routes = {"/": html("".join(f'<script src="/s{i}.js"></script>' for i in range(n))), **files}
        routes["/s.map"] = resp(200, [], '{"version":3,"mappings":"A"}')
        files = {f"/s{i}.js": resp(200, [], f"x//# sourceMappingURL=s{i}.map") for i in range(n)}
        routes.update(files)
        routes.update({f"/s{i}.map": resp(200, [], '{"version":3,"mappings":"A"}') for i in range(n)})
        return exposure.source_maps(ctx(routes)).summary

    def test_source_maps(self):
        self.assertTrue(self.source_maps(1).startswith("1 source map is public"), self.source_maps(1))
        self.assertTrue(self.source_maps(2).startswith("2 source maps are public"), self.source_maps(2))

    def test_libraries(self):
        one = webapp.vulnerable_libraries(ctx({"/": html('<script src="https://cdn.test/jquery-3.4.1.min.js"></script>')}))
        self.assertTrue(one.summary.startswith("1 client library version with published vulnerabilities is served"),
                        one.summary)
        two = webapp.vulnerable_libraries(ctx({"/": html('<script src="https://cdn.test/jquery-3.4.1.min.js"></script>'
                                                         '<script src="https://cdn.test/npm/moment@2.29.3/m.js"></script>')}))
        self.assertTrue(two.summary.startswith("2 client library versions with published vulnerabilities are served"),
                        two.summary)

    def test_no_placeholder_plurals_in_summaries(self):
        results = [self.source_maps(1), self.source_maps(2),
                   webapp.vulnerable_libraries(ctx({"/": html('<script src="/a.js"></script>')})).summary,
                   browser.cookies(ctx({"/": html("x", ("Set-Cookie", "a=1; Secure; SameSite=Lax"))})).summary,
                   webapp.password_forms(ctx({"/": html('<form method="post"><input type="password"></form>')})).summary]
        for summary in results:
            with self.subTest(summary=summary):
                self.assertNotIn("(s)", summary)

    def test_no_placeholder_plural_in_any_check_string(self):
        import pathlib
        import tokenize
        root = pathlib.Path(webapp.__file__).resolve().parent.parent
        for path in sorted([*(root / "checks").glob("*.py"), *(root / "code_audit").glob("*.py")]):
            with path.open("rb") as fh:
                for tok in tokenize.tokenize(fh.readline):
                    if tok.type == tokenize.STRING or tok.type == getattr(tokenize, "FSTRING_MIDDLE", -1):
                        with self.subTest(file=path.name, line=tok.start[0]):
                            self.assertNotIn("(s)", tok.string)

    def rate_limit(self, answer, attempts=30):
        c = ctx({"/api/login": lambda m, u, h, b, n={"i": 0}: (n.__setitem__("i", n["i"] + 1), answer(n["i"]))[1]},
                rate_limit_path="/api/login", rate_limit_attempts=attempts)
        return ratelimit.login_rate_limit(c)

    def test_rate_limit_counts_agree_at_one_and_two(self):
        r = self.rate_limit(lambda i: resp(429 if i > 1 else 401, [("Retry-After", "60")], "x"))
        self.assertIn("after 1 attempt (429", r.summary)
        self.assertIn("1 attempt accepted", r.evidence[0])
        r = self.rate_limit(lambda i: resp(429 if i > 2 else 401, [("Retry-After", "60")], "x"))
        self.assertIn("after 2 attempts (429", r.summary)
        r = self.rate_limit(lambda i: resp(423 if i > 1 else 401, [], "x"))
        self.assertIn("Throttled after 1 attempt:", r.summary)
        self.assertIn(": attempt 1 -> 401", r.evidence[0])
        r = self.rate_limit(lambda i: resp(423 if i > 2 else 401, [], "x"))
        self.assertIn("Throttled after 2 attempts:", r.summary)
        self.assertIn("No limit seen within 1 attempt,", self.rate_limit(lambda i: resp(401, [], "x"), 1).summary)
        self.assertIn("No limit seen within 2 attempts,", self.rate_limit(lambda i: resp(401, [], "x"), 2).summary)


if __name__ == "__main__":
    unittest.main()
