"""The shared crawl and the whole-site checks that use it: stub sites for edge cases, the lab for both modes."""

import json
import unittest

from agent_security_audit import crawl as crawl_mod
from agent_security_audit import lab, runner
from agent_security_audit.checks import Context, browser, exposure, webapp
from agent_security_audit.http import Client, Response

T = "https://example.test"


def resp(status=200, headers=(), body=b"", url=T + "/"):
    if isinstance(body, str):
        body = body.encode()
    return Response(url, status, "", list(headers), body)


def html(body, *headers, status=200):
    return resp(status, [("Content-Type", "text/html; charset=utf-8"), *headers], f"<html><body>{body}</body></html>")


class StubClient:
    """Serves a dict {path_or_url: Response | callable(method, url, headers, body)}; anything else is 404."""

    timeout = 1.0

    def __init__(self, target, routes, budget=None):
        self.target, self.routes, self.calls, self.sent = target, routes, [], 0
        if budget is not None:
            self.budget = budget

    def url(self, path):
        return path if path.startswith(("http://", "https://")) else self.target + "/" + path.lstrip("/")

    def request(self, method, path="/", *, headers=None, body=None, cache=False):
        url = self.url(path)
        if not url.startswith(self.target + "/"):
            raise AssertionError(f"off-origin request {url}")
        self.calls.append((method, url))
        self.sent += 1
        rel = url[len(self.target):]
        route = self.routes.get(url, self.routes.get(rel, self.routes.get(rel.split("?")[0])))
        if route is None:
            out = resp(404)
        elif callable(route):
            out = route(method, url, headers or {}, body)
        else:
            out = route
        out = Response(url, out.status, out.reason, out.headers, out.body)
        return out

    def get(self, path="/", **kw):
        return self.request("GET", path, **kw)

    def home(self):
        return self.get("/")


def serve(handle):
    """127.0.0.1 server whose every GET is answered by handle(handler)."""
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        def do_GET(self):
            handle(self)
    server = ThreadingHTTPServer(("127.0.0.1", 0), H)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"


def ctx(routes, target=T, budget=None, **options):
    return Context(target, StubClient(target, routes, budget), options)


def paths(c):
    return [u[len(c.client.target):] for _, u in c.client.calls]


class CrawlTest(unittest.TestCase):
    def test_follows_links_robots_and_sitemap_same_origin_only(self):
        c = ctx({
            "/": html('<a href="/a">a</a><a href="https://other.test/x">x</a><a href="mailto:a@b.test">m</a>'
                      '<a href="/a#frag">a</a>'),
            "/a": html('<a href="/b?id=1">b</a>'),
            "/b": html("b"),
            "/robots.txt": resp(200, [("Content-Type", "text/plain")],
                                "User-agent: *\nDisallow: /private/*\nAllow: /open\nSitemap: https://example.test/sm.xml\n"
                                "Sitemap: https://other.test/sm.xml\n"),
            "/sm.xml": resp(200, [("Content-Type", "application/xml")], "<urlset><url><loc>https://example.test/c</loc>"
                            "</url><url><loc>https://other.test/d</loc></url></urlset>"),
            "/open": html("open"),
            "/c": html("c"),
        })
        site = crawl_mod.crawl(c)
        got = [p.url for p in site.pages]
        self.assertEqual(got[0], T + "/")
        self.assertEqual(set(got), {T + "/", T + "/a", T + "/b?id=1", T + "/open", T + "/c"})
        self.assertNotIn("/private/*", paths(c))
        self.assertTrue(all(m == "GET" for m, _ in c.client.calls))
        self.assertIs(crawl_mod.crawl(c), site)  # cached
        self.assertEqual(site.params(), {("/b", "id"): T + "/b?id=1"})

    def test_not_owned_honors_robots_disallow(self):
        routes = {
            "/": html('<a href="/admin/x">a</a><a href="/blog">b</a>'),
            "/admin/x": html("admin"), "/blog": html("blog"), "/secret": html("s"),
            "/robots.txt": resp(200, [("Content-Type", "text/plain")], "User-agent: *\nDisallow: /admin\nDisallow: /secret\n"),
        }
        c = ctx(routes)
        got = {p.url for p in crawl_mod.crawl(c).pages}
        self.assertEqual(got, {T + "/", T + "/blog"})
        self.assertNotIn("/admin/x", paths(c))
        self.assertNotIn("/secret", paths(c))
        owned = ctx(routes)
        owned.owned = True
        self.assertIn(T + "/admin/x", {p.url for p in crawl_mod.crawl(owned).pages})

    def test_sitemap_index_is_followed(self):
        c = ctx({"/": html(""), "/sitemap.xml": resp(200, [("Content-Type", "application/xml")],
                                                     "<sitemapindex><sitemap><loc>https://example.test/s1.xml</loc>"
                                                     "</sitemap></sitemapindex>"),
                 "/s1.xml": resp(200, [("Content-Type", "application/xml")], "<urlset><loc>https://example.test/p"
                                 "</loc></urlset>"),
                 "/p": html("p")})
        self.assertIn(T + "/p", [p.url for p in crawl_mod.crawl(c).pages])

    def test_logout_and_state_changing_links_never_requested(self):
        links = ("/logout", "/auth/sign-out", "/account/delete", "/signoff", "/?action=logout", "/unsubscribe?u=1",
                 "/api/auth/signout")
        c = ctx({"/": html("".join(f'<a href="{href}">x</a>' for href in links) + '<a href="/deleted-posts">ok</a>'
                           '<a href="/removals">ok</a>')})
        site = crawl_mod.crawl(c)
        requested = paths(c)
        for href in links:
            with self.subTest(href=href):
                self.assertNotIn(href, requested)
        self.assertIn("/deleted-posts", requested)
        self.assertIn("/removals", requested)
        self.assertTrue(any("not requested" in n for n in site.notes))

    def test_forms_recorded_not_submitted(self):
        c = ctx({"/": html('<form action="/search" method="get"><input name="q"></form>'
                           '<form method="POST" action="/login"><input type="password" name="pw"></form>')})
        site = crawl_mod.crawl(c)
        self.assertEqual([(f.action, f.method, f.has_password) for f in site.forms],
                         [(T + "/search", "get", False), (T + "/login", "post", True)])
        self.assertNotIn("/search", paths(c))
        self.assertNotIn("/login", paths(c))

    def test_max_pages_and_note(self):
        pages = {f"/p{i}": html("p") for i in range(10)}
        c = ctx({"/": html("".join(f'<a href="/p{i}">p</a>' for i in range(10))), **pages}, max_pages=3)
        site = crawl_mod.crawl(c)
        self.assertEqual(len(site.pages), 3)
        self.assertTrue(any("page limit 3 reached" in n for n in site.notes))

    def test_max_depth(self):
        c = ctx({"/": html('<a href="/1">1</a>'), "/1": html('<a href="/2">2</a>'), "/2": html("2")}, max_depth=1)
        self.assertEqual([p.url for p in crawl_mod.crawl(c).pages], [T + "/", T + "/1"])

    def test_query_variants_capped(self):
        c = ctx({"/": html("".join(f'<a href="/cal?d={i}">d</a>' for i in range(10))), "/cal": html("cal")})
        crawl_mod.crawl(c)
        self.assertEqual(sum(1 for p in paths(c) if p.startswith("/cal?")), crawl_mod.MAX_VARIANTS)

    def test_assets_not_crawled_as_pages(self):
        c = ctx({"/": html('<a href="/file.pdf">pdf</a><a href="/img.png">img</a><a href="/page">p</a>'),
                 "/page": html("p")})
        crawl_mod.crawl(c)
        self.assertNotIn("/file.pdf", paths(c))
        self.assertIn("/page", paths(c))

    def test_same_origin_redirect_followed(self):
        c = ctx({"/": html('<a href="/old">old</a>'), "/old": resp(301, [("Location", "/new")]), "/new": html("n"),
                 "/away": resp(302, [("Location", "https://other.test/")])})
        self.assertIn(T + "/new", [p.url for p in crawl_mod.crawl(c).pages])

    def test_crawl_keeps_half_the_budget(self):
        pages = {f"/p{i}": html("p") for i in range(100)}
        c = ctx({"/": html("".join(f'<a href="/p{i}">p</a>' for i in range(100))), **pages}, budget=40, max_pages=100)
        site = crawl_mod.crawl(c)
        self.assertLessEqual(c.client.sent, 21)
        self.assertTrue(any("budget" in n for n in site.notes))

    def test_real_client_budget_respected(self):
        server, url = lab.serve("fixed", 0)
        try:
            client = Client(url, budget=12, delay=0)
            site = crawl_mod.crawl(Context(url, client, {}))
            self.assertLessEqual(client.sent, 7)
            self.assertTrue(site.pages)
        finally:
            server.shutdown()
            server.server_close()

    def test_request_budget_cut_marks_crawl_incomplete(self):
        from agent_security_audit.http import BudgetExceeded

        def broke(*_):
            raise BudgetExceeded("request budget used up")
        c = ctx({"/": html('<a href="/a">a</a>'), "/a": broke})
        site = crawl_mod.crawl(c)
        self.assertIn("request budget", site.cut)
        self.assertIn("request budget", c.cache["data_cut"])

    def test_slow_page_marks_crawl_incomplete(self):
        from agent_security_audit.http import ResponseTooSlow

        def slow(*_):
            raise ResponseTooSlow("no complete response within 1 s")
        c = ctx({"/": html('<a href="/a">a</a>'), "/a": slow})
        self.assertIn("/a answered too slowly", crawl_mod.crawl(c).cut)

    def test_unreadable_page_marks_crawl_incomplete(self):
        def reset(*_):
            raise ConnectionResetError(54, "Connection reset by peer")
        c = ctx({"/": html('<a href="/a">a</a>'), "/a": reset})
        self.assertIn("/a could not be read (ConnectionResetError)", crawl_mod.crawl(c).cut)
        self.assertTrue(c.cache["data_cut"])

    def test_links_with_spaces_and_non_ascii_are_encoded_and_visited(self):
        # http.client refuses a raw space (InvalidURL) and raises UnicodeEncodeError on non-ASCII, which used to stop
        # the whole crawl. Browsers percent-encode both; so does the crawl.
        self.assertEqual(crawl_mod._join(T + "/", "/caf\u00e9 menu?q=\u00e9#x"), T + "/caf%C3%A9%20menu?q=%C3%A9")
        self.assertEqual(crawl_mod._join(T + "/", "/a%20b"), T + "/a%20b")  # already encoded: left alone
        hits = []

        def page(handler):
            hits.append(handler.path)
            body = b'<html><a href="/caf\xc3\xa9">c</a> <a href="/a b">s</a></html>' if handler.path == "/" else b"<p>x"
            handler.send_response(200)
            handler.send_header("Content-Type", "text/html; charset=utf-8")
            handler.send_header("Content-Length", str(len(body)))
            handler.end_headers()
            handler.wfile.write(body)
        server, url = serve(page)
        try:
            c = Context(url, Client(url, delay=0), {"max_depth": 1})
            site = crawl_mod.crawl(c)
        finally:
            server.shutdown()
            server.server_close()
        self.assertIn("/caf%C3%A9", hits)
        self.assertIn("/a%20b", hits)
        self.assertEqual(len(site.pages), 3)
        self.assertEqual(site.cut, "")

    def test_script_budget_cut_blocks_a_pass(self):
        from agent_security_audit.http import BudgetExceeded

        def broke(*_):
            raise BudgetExceeded("request budget used up")
        c = ctx({"/": html('<script src="/a.js"></script>'), "/a.js": broke})
        exposure.scripts(c)
        self.assertIn("request budget", c.cache["data_cut"])
        c.cache.pop("data_cut")
        exposure.scripts(c)  # cached: a later check reading the same partial set is flagged too
        self.assertIn("request budget", c.cache["data_cut"])

    def test_script_cap_cut_blocks_a_pass(self):
        n = exposure.MAX_SCRIPTS + 5
        tags = "".join(f'<script src="/s{k}.js"></script>' for k in range(n))
        routes = {"/": html(tags), **{f"/s{k}.js": resp(200, [("Content-Type", "text/javascript")], "var a=1;")
                                      for k in range(n)}}
        c = ctx(routes)
        exposure.scripts(c)
        self.assertIn(f"more than {exposure.MAX_SCRIPTS} script files", c.cache["data_cut"])
        few = ctx({"/": html('<script src="/s0.js"></script>'), "/s0.js": routes["/s0.js"]})
        exposure.scripts(few)
        self.assertNotIn("data_cut", few.cache)

    def test_runner_turns_pass_on_cut_data_into_error(self):
        from unittest import mock
        from urllib.parse import urlsplit

        from agent_security_audit.http import BudgetExceeded
        server, url = lab.serve("fixed", 0)
        try:
            real = Client.request

            def req(self, method, path="/", **kw):
                if urlsplit(self.url(path)).path not in ("", "/"):
                    raise BudgetExceeded("request budget used up")
                return real(self, method, path, **kw)
            with mock.patch.object(Client, "request", req):
                _, results = runner.run(url, ids=["BROWSER-22"], delay=0)
        finally:
            server.shutdown()
            server.server_close()
        self.assertEqual(results[0].status, "error")
        self.assertIn("request budget", results[0].summary)

    def test_next_chunks_is_linear_on_hostile_text(self):
        # Every "~static/chunks/" is a match start; an unbounded lazy run made this quadratic (about 23 s for 240 KB),
        # which hung the single-threaded MCP server.
        import time
        for text in ("~static/chunks/" * 20000, "static/chunks/" + "a/" * 1_000_000):
            start = time.monotonic()
            self.assertEqual(crawl_mod.next_chunks(text), [])
            self.assertLess(time.monotonic() - start, 1.0)

    def test_next_chunks(self):
        text = ('"static/chunks/pages/about-1a2b.js" \\"static/chunks/app/page-9f.js\\" '
                '"/_next/static/chunks/main-77.js" "https://cdn.other.test/_next/static/chunks/x.js" '
                '"static/chunks/data.json"')
        self.assertEqual(crawl_mod.next_chunks(text), ["/_next/static/chunks/pages/about-1a2b.js",
                                                       "/_next/static/chunks/app/page-9f.js",
                                                       "/_next/static/chunks/main-77.js"])


def fake_service_role():
    import base64

    def b64(o):
        return base64.urlsafe_b64encode(json.dumps(o).encode()).decode().rstrip("=")
    return ".".join([b64({"alg": "HS256"}), b64({"role": "service_role", "ref": "q" * 20}), "fakesig" + "0" * 20])


class UpgradedChecksTest(unittest.TestCase):
    def test_next01_finds_secret_on_a_deeper_page_and_in_a_manifest_chunk(self):
        secret = fake_service_role()
        c = ctx({"/": html('<a href="/pricing">p</a><script src="/_next/static/chunks/main.js"></script>'),
                 "/pricing": html("<script>self.__next_f.push([1,\"static/chunks/app/pricing-1.js\"])</script>"),
                 "/_next/static/chunks/main.js": resp(200, [], "var a=1"),
                 "/_next/static/chunks/app/pricing-1.js": resp(200, [], f'const k="{secret}"')})
        r = exposure.client_secrets(c)
        self.assertEqual(r.status, "fail")
        self.assertIn("/_next/static/chunks/app/pricing-1.js", " ".join(r.evidence))
        self.assertNotIn(secret, " ".join(r.evidence))

    def test_next01_labels_inline_scripts_per_page(self):
        c = ctx({"/": html('<script>var a</script><a href="/x">x</a>'), "/x": html("<script>var b</script>")})
        self.assertEqual([label for label, _ in exposure.scripts(c)], ["home page inline scripts", "/x inline scripts"])

    def test_next02_checks_scripts_from_other_pages(self):
        c = ctx({"/": html('<a href="/docs">d</a>'),
                 "/docs": html('<script src="/static/docs.js"></script>'),
                 "/static/docs.js": resp(200, [], "x()\n//# sourceMappingURL=docs.js.map"),
                 "/static/docs.js.map": resp(200, [], '{"version":3,"mappings":"AAAA"}')})
        self.assertEqual(exposure.source_maps(c).status, "fail")

    def test_browser06_checks_cookies_on_other_pages(self):
        c = ctx({"/": html('<a href="/account">a</a>', ("Set-Cookie", "theme=dark; Secure; SameSite=Lax")),
                 "/account": html("acct", ("Set-Cookie", "sid=1; Secure; SameSite=Lax"))})
        r = browser.cookies(c)
        self.assertEqual(r.status, "fail")
        self.assertIn("sid (set on /account)", " ".join(r.evidence))

    def test_browser06_same_cookie_on_many_pages_counted_once(self):
        cookie = ("Set-Cookie", "sid=1; Secure; HttpOnly; SameSite=Lax")
        c = ctx({"/": html('<a href="/a">a</a>', cookie), "/a": html("a", cookie)})
        r = browser.cookies(c)
        self.assertEqual(r.status, "pass")
        self.assertEqual(len(r.evidence), 1)


class MixedContentTest(unittest.TestCase):
    def status(self, body, *headers, target=T):
        return webapp.mixed_content(ctx({"/": html(body, *headers)}, target=target)).status

    def test_cases(self):
        self.assertEqual(self.status('<script src="http://cdn.test/a.js"></script>'), "fail")
        self.assertEqual(self.status('<link rel="stylesheet" href="http://cdn.test/a.css">'), "fail")
        self.assertEqual(self.status('<iframe src="http://x.test/"></iframe>'), "fail")
        self.assertEqual(self.status('<img src="http://cdn.test/a.png">'), "warn")
        self.assertEqual(self.status('<img src="//cdn.test/a.png"><script src="/a.js"></script>'
                                     '<a href="http://x.test/">link</a>'), "pass")
        self.assertEqual(self.status('<script src="http://cdn.test/a.js"></script>',
                                     ("Content-Security-Policy", "upgrade-insecure-requests")), "pass")

    def test_http_target_skips(self):
        self.assertEqual(self.status('<script src="http://cdn.test/a.js"></script>', target="http://example.test"),
                         "skip")


class SriTest(unittest.TestCase):
    def status(self, body):
        return webapp.subresource_integrity(ctx({"/": html(body)})).status

    def test_cases(self):
        self.assertEqual(self.status('<script src="https://cdn.test/lib.js"></script>'), "warn")
        self.assertEqual(self.status('<link rel="stylesheet" href="https://cdn.test/a.css">'), "warn")
        self.assertEqual(self.status('<script src="https://cdn.test/lib.js" integrity="sha384-x" '
                                     'crossorigin="anonymous"></script>'), "pass")
        self.assertEqual(self.status('<script src="https://js.stripe.com/v3/"></script>'), "pass")
        self.assertEqual(self.status('<script src="/own.js"></script><img src="https://cdn.test/a.png">'), "skip")


class PasswordFormTest(unittest.TestCase):
    def status(self, form, target=T):
        return webapp.password_forms(ctx({"/": html(form)}, target=target)).status

    def test_cases(self):
        pw = '<input type="password" name="p">'
        self.assertEqual(self.status(f'<form method="post" action="/login">{pw}</form>'), "pass")
        self.assertEqual(self.status(f'<form method="post" action="https://auth.other.test/x">{pw}</form>'), "pass")
        self.assertEqual(self.status(f'<form action="/login">{pw}</form>'), "fail")  # GET by default
        self.assertEqual(self.status(f'<form method="post" action="http://example.test/login">{pw}</form>'), "fail")
        self.assertEqual(self.status(f'<form method="post" action="/login">{pw}</form>',
                                     target="http://example.com"), "fail")
        self.assertEqual(self.status(f'<form method="post" action="/login">{pw}</form>',
                                     target="http://127.0.0.1:3000"), "pass")
        self.assertEqual(self.status('<form><input name="q"></form>'), "skip")


class LibraryTest(unittest.TestCase):
    def test_url_versions(self):
        cases = {
            "https://code.jquery.com/jquery-3.4.1.min.js": ("jquery", "3.4.1"),
            "https://cdnjs.cloudflare.com/ajax/libs/jquery/3.4.1/jquery.min.js": ("jquery", "3.4.1"),
            "https://cdn.jsdelivr.net/npm/bootstrap@4.3.0/dist/js/bootstrap.min.js": ("bootstrap", "4.3.0"),
            "https://ajax.googleapis.com/ajax/libs/angularjs/1.8.2/angular.min.js": ("angularjs", "1.8.2"),
            "https://cdnjs.cloudflare.com/ajax/libs/lodash.js/4.17.15/lodash.min.js": ("lodash", "4.17.15"),
            "https://cdnjs.cloudflare.com/ajax/libs/moment.js/2.29.1/moment.min.js": ("moment", "2.29.1"),
        }
        for url, want in cases.items():
            with self.subTest(url=url):
                self.assertEqual(webapp.find_libraries("x", url=url)[0][:2], want)
        for url in ("https://cdn.test/jquery-ui-1.12.1.min.js", "https://cdn.test/jquery.min.js",
                    "https://cdn.test/bootstrap-datepicker@1.9.0/x.js"):
            with self.subTest(url=url):
                self.assertEqual(webapp.find_libraries("x", url=url), [])

    def test_banners(self):
        cases = {
            "/*! jQuery v3.4.1 | (c) JS Foundation */": ("jquery", "3.4.1"),
            "/*! jQuery UI - v1.12.1 */": None,
            "/**\n * @license AngularJS v1.8.2\n */": ("angularjs", "1.8.2"),
            "/*!\n  * Bootstrap v4.1.3 (https://getbootstrap.com/)": ("bootstrap", "4.1.3"),
            "//! moment.js\n//! version : 2.29.1\n": ("moment", "2.29.1"),
            "/** @license Lodash <https://lodash.com/> */ var VERSION = '4.17.15';": ("lodash", "4.17.15"),
            "/** @license Lodash lodash.com/license */ var t,r=\"4.17.11\",e=200,": ("lodash", "4.17.11"),
            "var VERSION = '1.0.0';": None,
        }
        for text, want in cases.items():
            with self.subTest(text=text):
                hits = webapp.find_libraries("x", text=text)
                self.assertEqual(hits[0][:2] if hits else None, want)

    def status(self, src):
        return webapp.vulnerable_libraries(ctx({"/": html(f'<script src="{src}"></script>')})).status

    def test_thresholds(self):
        self.assertEqual(self.status("https://cdn.test/jquery-3.4.1.min.js"), "fail")
        self.assertEqual(self.status("https://cdn.test/jquery-3.5.0.min.js"), "pass")
        self.assertEqual(self.status("https://cdn.test/bootstrap/3.4.0/js/b.js"), "fail")
        self.assertEqual(self.status("https://cdn.test/bootstrap/3.4.1/js/b.js"), "pass")
        self.assertEqual(self.status("https://cdn.test/bootstrap/4.3.0/js/b.js"), "fail")
        self.assertEqual(self.status("https://cdn.test/bootstrap/4.3.1/js/b.js"), "pass")
        self.assertEqual(self.status("https://cdn.test/npm/lodash@4.17.21/lodash.js"), "pass")
        self.assertEqual(self.status("https://cdn.test/npm/moment@2.29.3/moment.js"), "fail")
        self.assertEqual(self.status("https://cdn.test/npm/angular@1.8.3/angular.js"), "warn")

    def test_no_scripts_skips(self):
        self.assertEqual(webapp.vulnerable_libraries(ctx({"/": html("hi")})).status, "skip")


class OpenRedirectTest(unittest.TestCase):
    def run_check(self, redirect):
        def route(m, u, h, b):
            dest = u.split("next=", 1)[1] if "next=" in u else "/"
            from urllib.parse import unquote
            return resp(302, [("Location", redirect(unquote(dest)))])
        c = ctx({"/": html('<a href="/login?next=/account&x=1">in</a><a href="/logout?next=/">out</a>'),
                 "/login": route})
        return c, webapp.open_redirect(c)

    def test_open_redirect_fails(self):
        c, r = self.run_check(lambda d: d)
        self.assertEqual(r.status, "fail")
        probes = [u for _, u in c.client.calls if "asa-redirect-probe" in u]
        self.assertEqual(len(probes), 1)
        self.assertIn("x=1", probes[0])
        self.assertFalse(any("logout" in u for _, u in c.client.calls))

    def test_relative_only_passes(self):
        _, r = self.run_check(lambda d: d if d.startswith("/") and not d.startswith(("//", "/\\")) else "/")
        self.assertEqual(r.status, "pass")

    def test_no_params_skips(self):
        self.assertEqual(webapp.open_redirect(ctx({"/": html('<a href="/a?id=1">a</a>')})).status, "skip")


class EndpointChecksTest(unittest.TestCase):
    SPA = html('<div id="root"></div>')

    def test_directory_listing(self):
        listing = html("<h1>Index of /uploads/</h1>")
        self.assertEqual(webapp.directory_listing(ctx({"/": self.SPA, "/uploads/": listing})).status, "fail")
        spa = ctx({"/": html('<script src="/js/app.js"></script>')})
        spa.client.routes = {k: self.SPA for k in ("/", "/uploads/", "/static/", "/js/")} | spa.client.routes
        r = webapp.directory_listing(spa)
        self.assertEqual(r.status, "pass")
        self.assertIn("/js/", paths(spa))

    def test_debug_endpoints(self):
        env = resp(200, [("Content-Type", "application/json")],
                   json.dumps({"activeProfiles": [], "propertySources": [{"name": "x"}]}))
        r = webapp.debug_endpoints(ctx({"/actuator/env": env}))
        self.assertEqual(r.status, "fail")
        php = resp(200, [("Content-Type", "text/html")], "<html><head><title>PHP 8.2.1 - phpinfo()</title></head></html>")
        self.assertEqual(webapp.debug_endpoints(ctx({"/info.php": php})).status, "fail")
        catch_all = {p: self.SPA for p in webapp.DEBUG_ENDPOINTS}
        self.assertEqual(webapp.debug_endpoints(ctx(catch_all)).status, "pass")

    def test_api_docs(self):
        doc = resp(200, [("Content-Type", "application/json")], json.dumps({"openapi": "3.1.0", "paths": {"/a": {}}}))
        self.assertEqual(webapp.api_docs(ctx({"/openapi.json": doc})).status, "warn")
        ui = html('<div id="swagger-ui"></div><script src="./swagger-ui-bundle.js"></script>')
        self.assertEqual(webapp.api_docs(ctx({"/swagger-ui.html": ui})).status, "warn")
        self.assertEqual(webapp.api_docs(ctx({p: self.SPA for p in webapp.API_DOCS})).status, "pass")

    def test_graphql(self):
        schema = resp(200, [("Content-Type", "application/json")], json.dumps(lab.GRAPHQL_SCHEMA))
        refused = resp(400, [("Content-Type", "application/json")], json.dumps(lab.GRAPHQL_REFUSED))
        r = webapp.graphql_introspection(ctx({"/graphql": schema}))
        self.assertEqual(r.status, "warn")
        self.assertNotIn("Mutation", " ".join(r.evidence))
        self.assertEqual(webapp.graphql_introspection(ctx({"/api/graphql": refused})).status, "pass")
        self.assertEqual(webapp.graphql_introspection(ctx({})).status, "skip")
        rest = resp(400, [("Content-Type", "application/json")], json.dumps({"errors": "bad"}))
        self.assertEqual(webapp.graphql_introspection(ctx({"/graphql": rest})).status, "skip")

    def test_trace(self):
        def echo(m, u, h, b):
            return resp(200, [("Content-Type", "message/http")],
                        "TRACE / HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in h.items()))
        self.assertEqual(webapp.trace_method(ctx({"/": echo})).status, "fail")
        self.assertEqual(webapp.trace_method(ctx({"/": resp(405)})).status, "pass")
        self.assertEqual(webapp.trace_method(ctx({"/": self.SPA})).status, "pass")


NEW = ("BROWSER-21", "BROWSER-22", "BROWSER-23", "API-19", "API-20", "API-21", "API-22", "API-23", "API-24")


class HtmlTypeTest(unittest.TestCase):
    def test_media_type_not_a_parameter_decides_html(self):
        # "html" in a parameter (charset=html) used to mark the body as a page, so a meta policy in plain text
        # was read as the page's Content-Security-Policy.
        page = resp(200, [("Content-Type", "text/html; charset=utf-8")], "<html></html>")
        self.assertTrue(crawl_mod.is_html(page))
        xhtml = resp(200, [("Content-Type", "application/xhtml+xml")], "<html/>")
        self.assertTrue(crawl_mod.is_html(xhtml))
        plain = resp(200, [("Content-Type", "text/plain; charset=html")],
                     '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'">')
        self.assertFalse(crawl_mod.is_html(plain))
        self.assertEqual(browser.meta_csp(plain), [])
        sniffed = resp(200, [], b"\n<!DOCTYPE html><html></html>")
        self.assertTrue(crawl_mod.is_html(sniffed))


class ActiveContentTest(unittest.TestCase):
    def test_media_is_not_active_content(self):
        page = "http://h/"
        self.assertTrue(crawl_mod.Resource(page, "script", "script", page + "a.js").active)
        self.assertTrue(crawl_mod.Resource(page, "link", "style", page + "a.css").active)
        self.assertTrue(crawl_mod.Resource(page, "iframe", "frame", page + "f").active)
        self.assertFalse(crawl_mod.Resource(page, "video", "media", page + "a.mp4").active)


class LabCrawlTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.results, cls.sites = {}, {}
        for mode in lab.MODES:
            server, url = lab.serve(mode, 0)
            try:
                _, results = runner.run(url, ids=list(NEW) + ["BROWSER-20", "NEXT-01", "BROWSER-06"],
                                        include_manual=False, delay=0)
                cls.results[mode] = {r.check_id: r for r in results}
                c = Context(url, Client(url, delay=0), {})
                cls.sites[mode] = crawl_mod.crawl(c)
            finally:
                server.shutdown()
                server.server_close()

    def test_vulnerable_flags_every_new_check(self):
        for cid in NEW:
            with self.subTest(check=cid):
                self.assertIn(self.results["vulnerable"][cid].status, ("fail", "warn"))

    def test_fixed_passes_every_new_check(self):
        for cid in NEW:
            with self.subTest(check=cid):
                self.assertEqual(self.results["fixed"][cid].status, "pass", self.results["fixed"][cid].summary)

    def test_mixed_content_skips_on_http_lab(self):
        for mode in lab.MODES:
            self.assertEqual(self.results[mode]["BROWSER-20"].status, "skip")

    def test_lab_crawl_reaches_sitemap_page_and_skips_logout(self):
        for mode in lab.MODES:
            site = self.sites[mode]
            urls = [p.url.split("/", 3)[3] for p in site.pages]
            self.assertIn("contact", urls)  # only linked from sitemap.xml
            self.assertNotIn("logout", urls)
            self.assertTrue(any(u.endswith("/logout") for u in site.skipped))

    def test_evidence_has_no_lab_secrets(self):
        text = json.dumps({cid: r.evidence for cid, r in self.results["vulnerable"].items()})
        self.assertNotIn("not-a-secret", text)
        self.assertNotIn(lab.fake_jwt("service_role"), text)


if __name__ == "__main__":
    unittest.main()
