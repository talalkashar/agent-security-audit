"""--rate, --exclude-path and the Retry-After backoff: pacing, paths never requested, no pass on skipped evidence."""

import contextlib
import io
import json
import socket
import ssl
import threading
import time
import unittest
from datetime import UTC, datetime, timedelta
from email.utils import format_datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

from agent_security_audit import cli, http, mcp_server, pacing, report, runner
from agent_security_audit.checks import REGISTRY, load_all
from agent_security_audit.crawl import crawl
from agent_security_audit.http import Client, Excluded, TimeBudgetExceeded
from agent_security_audit.model import passed
from agent_security_audit.pacing import Exclusions, retry_after

load_all()
SECURITY_TXT = "Contact: mailto:security@example.invalid\nExpires: 2099-01-01T00:00:00Z\n"
HOME = '<html><body><a href="/about">About</a> <a href="/admin/panel">Admin</a></body></html>'


class Stub:
    """A 127.0.0.1 site that counts hits per path. busy maps a path to the 429 answers it gives before a 200."""

    def __init__(self, busy=None, login_limit=None, pages=None, always_busy=False):
        self.hits, self.busy, self.login_limit = {}, {k: list(v) for k, v in (busy or {}).items()}, login_limit
        # pages: path -> (status, body, headers) answered before the defaults; always_busy: 429 on every path but GET /.
        self.pages, self.always_busy = dict(pages or {}), always_busy
        stub = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def answer(self, status, body=b"", ctype="text/html", headers=()):
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                for k, v in headers:
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                path = self.path.split("?")[0]
                stub.hits[path] = stub.hits.get(path, 0) + 1
                if stub.busy.get(path):
                    retry = stub.busy[path].pop(0)
                    self.answer(429, b"slow down", headers=[("Retry-After", retry)] if retry is not None else [])
                elif stub.always_busy and path != "/":
                    self.answer(429, b"slow down", headers=[("Retry-After", "0")])
                elif path in stub.pages:
                    status, body, headers = stub.pages[path]
                    self.answer(status, body.encode(), "application/javascript" if path.endswith(".js") else
                                "text/html", headers)
                elif path == "/":
                    self.answer(200, HOME.encode())
                elif path == "/.well-known/security.txt":
                    self.answer(200, SECURITY_TXT.encode(), "text/plain")
                elif path in ("/about", "/x"):
                    self.answer(200, b"<html><body>ok</body></html>")
                else:
                    self.answer(404, b"not found")

            def do_TRACE(self):
                stub.hits[self.path] = stub.hits.get(self.path, 0) + 1
                self.answer(429 if stub.always_busy else 405, b"no", headers=[("Retry-After", "0")])

            def do_POST(self):
                path = self.path
                stub.hits[path] = stub.hits.get(path, 0) + 1
                self.rfile.read(int(self.headers.get("Content-Length") or 0))
                if stub.login_limit and stub.hits[path] > stub.login_limit:
                    self.answer(429, b"too many", headers=[("Retry-After", "60")])
                else:
                    self.answer(401, b'{"error":"bad credentials"}', "application/json")

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"

    def total(self):
        return sum(self.hits.values())

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class StubCase(unittest.TestCase):
    def stub_args(self):
        return {}

    def setUp(self):
        self.stub = Stub(**self.stub_args())
        self.addCleanup(self.stub.close)
        # Waits are recorded, never slept, so no test waits for real.
        self.waits = []
        patcher = mock.patch.object(http, "_pause", self.waits.append)
        patcher.start()
        self.addCleanup(patcher.stop)

    def run_with(self, check_id, fn, **kw):
        with mock.patch.dict(REGISTRY, {check_id: fn}):
            record = {}
            _, results = runner.run(self.stub.url, ids=[check_id], delay=0, record=record, **kw)
        return results[0], record


class PacingTest(StubCase):
    def test_rate_spaces_http_requests(self):
        c = Client(self.stub.url, delay=1 / 2)
        for _ in range(3):
            c.get("/x")
        self.assertEqual(len(self.waits), 2)  # the first request goes at once
        self.assertTrue(all(0.4 < w <= 0.5 for w in self.waits), self.waits)

    def test_rate_spaces_tls_and_port_probes(self):
        c = Client(self.stub.url, delay=1 / 2)
        c.get("/x")
        self.assertIn(c.probe_port(self.stub.server.server_address[1]), ("open", "closed", "filtered"))
        tls = Client("https" + self.stub.url[4:], delay=1 / 2)
        for _ in range(2):  # the stub speaks plain HTTP, so each handshake fails after the client paced it
            with contextlib.suppress(ssl.SSLError, OSError):
                tls.open_tls(ssl.create_default_context()).close()
        self.assertEqual(tls.sent, 2)
        self.assertEqual(len(self.waits), 2)
        self.assertTrue(all(0.4 < w <= 0.5 for w in self.waits), self.waits)

    def test_runner_rate_sets_the_delay_and_is_recorded(self):
        seen = {}

        def fn(ctx):
            seen["delay"] = ctx.client.delay
            return passed("INFRA-05", "ok")
        with mock.patch.dict(REGISTRY, {"INFRA-05": fn}):
            record = {}
            runner.run(self.stub.url, ids=["INFRA-05"], rate=4, record=record)
        self.assertEqual(seen["delay"], 0.25)
        self.assertEqual(record["pacing"]["rate"], 4)
        self.assertEqual(record["pacing"]["slowed"], 0)


class ExclusionPatternTest(unittest.TestCase):
    def test_regex_fullmatch_and_percent_decoding(self):
        ex = Exclusions([r"/admin/.*"])
        self.assertTrue(ex.match("http://h/admin/users"))
        self.assertTrue(ex.match("http://h/%61dmin/users"))
        self.assertFalse(ex.match("http://h/administrator"))
        self.assertFalse(ex.match("http://h/x/admin/y"))  # fullmatch, not search
        self.assertFalse(Exclusions().match("http://h/admin/users"))

    def test_glob_subset(self):
        ex = Exclusions(["/admin/*", "*.pdf", "/a*b*c"], glob=True)
        self.assertTrue(ex.match("http://h/admin/users/1"))
        self.assertTrue(ex.match("http://h/files/report.pdf"))
        self.assertTrue(ex.match("http://h/aXbYc"))
        self.assertFalse(ex.match("http://h/abd"))
        self.assertFalse(ex.match("http://h/about"))

    def test_glob_rejects_regex_and_is_linear(self):
        for bad in ["/admin/(a+)+", "/a[bc]", "/a?b", "/x\\y", "admin", "/(.*)*"]:
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                Exclusions([bad], glob=True)
        ex = Exclusions(["/" + "a*" * 90 + "b"], glob=True)
        start = time.monotonic()
        self.assertFalse(ex.match("http://h/" + "a" * 2000))
        self.assertLess(time.monotonic() - start, 0.5)

    def test_home_page_and_bounds_rejected(self):
        for bad in ([r"/.*"], [r".*"], ["/?"], [""], ["/x"] * 21, ["/" + "a" * 200], ["("]):
            with self.subTest(bad=bad[:2]), self.assertRaises(ValueError):
                Exclusions(bad)
        with self.assertRaises(ValueError):
            Exclusions(["*"], glob=True)

    def test_long_paths_count_as_excluded(self):
        ex = Exclusions([r"/admin/.*"])
        self.assertTrue(ex.match("http://h/" + "a" * (pacing.MAX_MATCH_PATH + 1)))


class RetryAfterTest(unittest.TestCase):
    def test_values_are_bounded(self):
        now = datetime(2026, 1, 1, tzinfo=UTC)
        cases = {"3": 3.0, "0": 0.0, "99999999999999999999": pacing.MAX_BACKOFF, "31": pacing.MAX_BACKOFF,
                 "-5": pacing.DEFAULT_BACKOFF, "soon": pacing.DEFAULT_BACKOFF, "": pacing.DEFAULT_BACKOFF,
                 "1.5": pacing.DEFAULT_BACKOFF, "²": pacing.DEFAULT_BACKOFF, "x" * 5000: pacing.DEFAULT_BACKOFF,
                 format_datetime(now + timedelta(seconds=10), usegmt=True): 10.0,
                 format_datetime(now + timedelta(days=9), usegmt=True): pacing.MAX_BACKOFF,
                 format_datetime(now - timedelta(days=9), usegmt=True): 0.0,
                 "Mon, 99 Foo 2026 99:99:99 GMT": pacing.DEFAULT_BACKOFF}
        for value, want in cases.items():
            with self.subTest(value=value[:40]):
                self.assertEqual(retry_after(value, now=now), want)
        self.assertEqual(retry_after(None), pacing.DEFAULT_BACKOFF)


class ExcludeTest(StubCase):
    def test_excluded_path_is_never_sent_and_costs_nothing(self):
        c = Client(self.stub.url, delay=0, budget=5, exclude=Exclusions([r"/\.well-known/.*"]))
        with self.assertRaises(Excluded):
            c.get("/.well-known/security.txt")
        self.assertEqual((self.stub.total(), c.sent, c.excluded), (0, 0, 1))

    def test_fully_excluded_check_is_skip(self):
        record = {}
        _, results = runner.run(self.stub.url, ids=["INFRA-05"], delay=0, record=record,
                                exclude=Exclusions([r"/\.well-known/.*"]))
        self.assertEqual(results[0].status, "skip")
        self.assertIn(pacing.EXCLUDED_REASON, results[0].summary)
        self.assertNotIn("/.well-known/security.txt", self.stub.hits)
        self.assertEqual(record["pacing"]["excluded_not_sent"], 1)

    def test_same_check_passes_without_the_exclusion(self):
        _, results = runner.run(self.stub.url, ids=["INFRA-05"], delay=0)
        self.assertEqual(results[0].status, "pass")

    def test_check_that_wanted_an_excluded_path_cannot_pass(self):
        def stops(ctx):  # stops at the excluded path after a real request
            ctx.client.get("/x")
            ctx.client.get("/admin/a")
            return passed("INFRA-05", "never reached")

        def forgets(ctx):  # swallows the exclusion and claims a pass anyway
            ctx.client.get("/x")
            with contextlib.suppress(Excluded):
                ctx.client.get("/admin/a")
            return passed("INFRA-05", "nothing found")
        for fn in (stops, forgets):
            with self.subTest(fn=fn.__name__):
                result, _ = self.run_with("INFRA-05", fn, exclude=Exclusions([r"/admin/.*"]))
                self.assertEqual(result.status, "manual")
                self.assertIn(pacing.EXCLUDED_REASON, result.summary)
        self.assertNotIn("/admin/a", self.stub.hits)

    def test_crawl_skips_excluded_links_and_its_readers_cannot_pass(self):
        def reads_crawl(ctx):
            site = crawl(ctx)
            return passed("INFRA-05", f"{len(site.pages)} pages clean")
        result, _ = self.run_with("INFRA-05", reads_crawl, exclude=Exclusions([r"/admin/.*"]))
        self.assertEqual(result.status, "manual")
        self.assertIn("the crawl left out 1 link", result.summary)
        self.assertNotIn("/admin/panel", self.stub.hits)
        self.assertIn("/about", self.stub.hits)

    def test_crawl_without_exclusions_still_passes(self):
        result, _ = self.run_with("INFRA-05", lambda ctx: passed("INFRA-05", str(len(crawl(ctx).pages))))
        self.assertEqual(result.status, "pass")
        self.assertIn("/admin/panel", self.stub.hits)


class BackoffTest(StubCase):
    def stub_args(self):
        return {"busy": {"/x": ["3"]}}

    def test_429_waits_retries_once_and_halves_the_rate(self):
        c = Client(self.stub.url, delay=0.05)
        resp = c.get("/x")
        self.assertEqual(resp.status, 200)
        self.assertEqual(self.stub.hits["/x"], 2)
        self.assertIn(3.0, self.waits)
        self.assertEqual((c.slowed, c.delay), (1, 0.1))

    def test_retry_is_only_once(self):
        self.stub.busy["/x"] = ["1", "1", "1"]
        c = Client(self.stub.url, delay=0)
        self.assertEqual(c.get("/x").status, 429)
        self.assertEqual(self.stub.hits["/x"], 2)

    def test_429_is_not_cached(self):
        c = Client(self.stub.url, delay=0)
        self.assertEqual(c.get("/x", cache=True).status, 200)
        self.assertEqual(c.get("/x", cache=True).status, 200)
        self.assertEqual(self.stub.hits["/x"], 2)

    def test_wait_never_passes_the_time_budget(self):
        self.stub.busy["/x"] = ["30"]
        c = Client(self.stub.url, delay=0, deadline=time.monotonic() + 5)
        with self.assertRaises(TimeBudgetExceeded):
            c.get("/x")
        self.assertNotIn(30.0, self.waits)
        self.assertEqual(self.stub.hits["/x"], 1)

    def test_check_cut_by_backoff_reports_error(self):
        self.stub.busy["/x"] = ["30"]

        def fn(ctx):
            ctx.client.get("/x")
            return passed("INFRA-05", "ok")
        with mock.patch.dict(REGISTRY, {"INFRA-05": fn}):
            _, results = runner.run(self.stub.url, ids=["INFRA-05"], delay=0, max_time=5)
        self.assertEqual(results[0].status, "error")
        self.assertIn("time budget", results[0].summary)

    def test_slowdown_shows_in_the_scope_block(self):
        def fn(ctx):
            ctx.client.get("/x")
            return passed("INFRA-05", "ok")
        _, record = self.run_with("INFRA-05", fn, rate=20)
        self.assertEqual(record["pacing"]["slowed"], 1)
        self.assertEqual(record["pacing"]["final_rate"], 10)
        scope = report.run_scope(interface="cli", mode="scan", flags={"rate": 20, "exclude_path": ["/admin/.*"]},
                                 pacing=record["pacing"])
        text = dict(report.scope_lines(scope))
        self.assertIn("20 requests/s", text["Rate"])
        self.assertIn("slow down 1 time", text["Rate"])
        self.assertIn("ended at 10 requests/s", text["Rate"])
        self.assertIn('"/admin/.*"', text["Excluded paths"])
        self.assertNotIn("exclude_path", text["Flags"])


class RateLimitProbeTest(StubCase):
    def stub_args(self):
        return {"login_limit": 5}

    def test_api01_still_sees_its_429(self):
        record = {}
        _, results = runner.run(self.stub.url, ids=["API-01"], delay=0, record=record,
                                options={"rate_limit_path": "/api/login"})
        self.assertEqual(results[0].status, "pass", results[0].summary)
        self.assertEqual(self.stub.hits["/api/login"], 6)
        self.assertEqual(record["pacing"]["slowed"], 0)
        self.assertNotIn(60.0, self.waits)


def call(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = cli.main(list(argv))
        except SystemExit as exc:
            code = exc.code
    return code, out.getvalue(), err.getvalue()


class CliTest(StubCase):
    def test_bad_rate_exits_2_before_any_request(self):
        for value in ("0", "0.05", "21", "abc", "nan", "inf", "-1"):
            with self.subTest(value=value):
                code, _, err = call("scan", self.stub.url, "--rate", value, "--check", "INFRA-05")
                self.assertEqual(code, 2)
                self.assertIn("rate", err)
        self.assertEqual(self.stub.total(), 0)

    def test_bad_patterns_exit_2_before_any_request(self):
        for args in (["("], ["/.*"], ["/x"] * 21, ["/" + "a" * 201]):
            with self.subTest(args=args[:1]):
                argv = ["scan", self.stub.url, "--check", "INFRA-05"]
                for a in args:
                    argv += ["--exclude-path", a]
                code, _, err = call(*argv)
                self.assertEqual(code, 2)
                self.assertTrue(err.strip())
        code, _, err = call("scan", self.stub.url, "--exclude-path", "/.*", "--check", "INFRA-05")
        self.assertIn("home page", err)
        self.assertEqual(self.stub.total(), 0)

    def test_scope_records_rate_and_patterns(self):
        code, out, _ = call("scan", self.stub.url, "--check", "INFRA-05", "--rate", "5", "--exclude-path",
                            r"/\.well-known/.*", "--format", "json", "-q")
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertEqual(data["scope"]["flags"]["rate"], 5)
        self.assertEqual(data["scope"]["flags"]["max_depth"], 3)
        self.assertEqual(data["scope"]["flags"]["exclude_path"], [r"/\.well-known/.*"])
        self.assertEqual(data["scope"]["pacing"]["excluded_not_sent"], 1)
        self.assertEqual(data["results"][0]["status"], "skip")
        _, out, _ = call("scan", self.stub.url, "--check", "INFRA-05", "--exclude-path", "/admin/.*",
                         "--format", "md", "-q")
        self.assertIn("Rate: 20 requests/s", out)
        self.assertIn("Excluded paths:", out)
        code, out, _ = call("scan", self.stub.url, "--check", "INFRA-05", "--max-depth", "0", "--format", "json", "-q")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["scope"]["flags"]["max_depth"], 0)


class McpTest(StubCase):
    def call(self, **args):
        return mcp_server.call_tool({"name": "run_scan", "arguments": {"target": self.stub.url, "no_dns": True,
                                                                        "checks": ["INFRA-05"], **args}})

    def test_bounds(self):
        for args in ({"rate": 0.05}, {"rate": 21}, {"rate": "2"}, {"rate": True}, {"exclude_path": ["/x"] * 21},
                     {"exclude_path": ["/admin/(a+)+"]}, {"exclude_path": ["*"]}, {"exclude_path": ["/" + "a" * 201]},
                     {"exclude_path": "/admin/*"}, {"exclude_path": [r"/\.well-known/.*"]},
                     {"budget": 0}, {"budget": 2001}, {"budget": True},
                     {"timeout": 0}, {"timeout": 61}, {"timeout": "10"},
                     {"max_depth": -1}, {"max_depth": 21}, {"max_depth": True},
                     {"insecure": "yes"}, {"target": self.stub.url + "\n"},
                     {"rate_limit_body": "a" * 4097}, {"rate_limit_body": "ok\x00"},
                     {"rate_limit_content_type": "a" * 129}, {"checks": ["X" * 33]}):
            with self.subTest(args=str(args)[:60]):
                out = self.call(**args)
                self.assertTrue(out["isError"], out)
        self.assertEqual(self.stub.total(), 0)

    def test_glob_exclusion_and_rate_recorded(self):
        out = self.call(rate=2.5, exclude_path=["/.well-known/*"])
        self.assertFalse(out["isError"], out)
        data = json.loads(out["content"][1]["text"])
        self.assertEqual(data["scope"]["flags"]["rate"], 2.5)
        self.assertEqual(data["scope"]["flags"]["exclude_path"], ["/.well-known/*"])
        self.assertEqual(data["results"][0]["status"], "skip")
        self.assertNotIn("/.well-known/security.txt", self.stub.hits)

    def test_schema_states_the_bounds(self):
        props = mcp_server.TOOLS_BY_NAME["run_scan"]["inputSchema"]["properties"]
        self.assertEqual((props["rate"]["minimum"], props["rate"]["maximum"]), (0.1, 20))
        self.assertEqual(props["exclude_path"]["maxItems"], 20)
        self.assertEqual((props["max_depth"]["minimum"], props["max_depth"]["maximum"], props["max_depth"]["default"]),
                         (0, 20, 3))
        self.assertEqual((props["budget"]["minimum"], props["budget"]["maximum"], props["budget"]["default"]),
                         (1, 2000, 300))
        self.assertEqual((props["timeout"]["minimum"], props["timeout"]["maximum"], props["timeout"]["default"]),
                         (1, 60, 10))
        self.assertIs(props["insecure"]["default"], False)
        self.assertEqual(props["rate_limit_content_type"]["maxLength"], 128)
        self.assertEqual(props["rate_limit_content_type"]["default"], "application/json")
        self.assertEqual(props["rate_limit_body"]["maxLength"], 4096)
        self.assertEqual(props["target"]["maxLength"], 2048)

    def test_rate_limit_body_may_contain_newlines(self):
        out = self.call(rate_limit_body='{"password":"x"}\n')
        self.assertFalse(out["isError"], out)

    def test_depth_zero_and_budget_are_recorded(self):
        out = self.call(max_depth=0, budget=50, timeout=10, insecure=True)
        self.assertFalse(out["isError"], out)
        flags = json.loads(out["content"][1]["text"])["scope"]["flags"]
        self.assertEqual(flags["max_depth"], 0)
        self.assertEqual(flags["budget"], 50)
        self.assertIs(flags["insecure"], True)

    def test_knobs_reach_the_runner(self):
        mcp_server.session["protocol"] = mcp_server.LATEST
        with mock.patch.object(runner, "run", return_value=("http://127.0.0.1:9", [])) as run:
            res = mcp_server.call_tool({"name": "run_scan", "arguments": {
                "target": "http://127.0.0.1:9", "max_depth": 0, "budget": 50, "timeout": 10, "insecure": True,
                "rate_limit_content_type": "text/plain"}})
        self.assertFalse(res["isError"], res)
        kw = run.call_args.kwargs
        self.assertEqual((kw["budget"], kw["timeout"], kw["insecure"]), (50, 10, True))
        self.assertEqual(kw["options"]["max_depth"], 0)
        self.assertEqual(kw["options"]["rate_limit_content_type"], "text/plain")
        flags = res["structuredContent"]["scope"]["flags"]
        self.assertEqual((flags["max_depth"], flags["budget"], flags["insecure"]), (0, 50, True))
        run.assert_called_once()

    def test_insecure_public_host_is_refused_before_a_request(self):
        res = mcp_server.call_tool({"name": "run_scan", "arguments": {
            "target": "https://example.com", "insecure": True, "no_dns": True, "checks": ["INFRA-05"]}})
        self.assertTrue(res["isError"], res)
        self.assertIn("local", res["content"][0]["text"])
        self.assertEqual(self.stub.total(), 0)


class ProbePortPacedTest(unittest.TestCase):
    def test_closed_port_probe_is_paced(self):
        waits = []
        # The refusal is instant here: Windows retries a refused connection for about 2 s, which already spends
        # the 1 s delay before the second probe, so no pause would be needed.
        refused = mock.patch.object(http.socket, "create_connection", side_effect=ConnectionRefusedError)
        with mock.patch.object(http, "_pause", waits.append), refused:
            s = socket.socket()
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
            s.close()
            c = Client(f"http://127.0.0.1:{port}", delay=1)
            self.assertEqual(c.probe_port(port), "closed")
            c.probe_port(port)
        self.assertEqual(len(waits), 1)
        self.assertGreater(waits[0], 0.9)


KEY = "sk_" + "live_" + "FAKE0000000000000000000000"  # built at run time so secret scanners leave this file alone
SCRIPT_SITE = {
    "/": (200, '<html><body><script src="/static/app.js"></script><a href="/private/page">p</a></body></html>', ()),
    "/private/page": (200, '<html><body><script src="/static/secret.js"></script></body></html>', ()),
    "/static/app.js": (200, "console.log(1)", ()),
    "/static/secret.js": (200, f'const pay="{KEY}";', ()),
}


class SharedCacheExclusionTest(StubCase):
    """Script sets and CMS hints are built once from the crawl: every later reader carries its exclusion mark."""

    def stub_args(self):
        return {"pages": SCRIPT_SITE}

    def run_ids(self, ids, **kw):
        record = {}
        _, results = runner.run(self.stub.url, ids=ids, delay=0, record=record, **kw)
        return {r.check_id: r for r in results}, record

    def test_later_readers_of_the_script_set_cannot_pass(self):
        results, _ = self.run_ids(["BROWSER-23", "NEXT-01", "NEXT-02"], exclude=Exclusions([r"/private/.*"]))
        for cid, r in results.items():
            self.assertNotEqual(r.status, "pass", f"{cid}: {r.summary}")
        self.assertEqual(results["NEXT-01"].status, "manual", results["NEXT-01"].summary)
        self.assertNotIn("/static/secret.js", self.stub.hits)

    def test_two_generic_readers_of_scripts_and_cms(self):
        from agent_security_audit.checks import cms, exposure
        for name, build in (("scripts", exposure.scripts), ("cms", cms.detect)):
            with self.subTest(cache=name):
                def reads(ctx, build=build):
                    build(ctx)
                    return passed("INFRA-05", "nothing found")
                with mock.patch.dict(REGISTRY, {"INFRA-05": reads, "INFRA-04": reads}):
                    results, _ = self.run_ids(["INFRA-04", "INFRA-05"], exclude=Exclusions([r"/private/.*"]))
                self.assertEqual([r.status for r in results.values()], ["manual", "manual"])

    def test_excluding_one_script_keeps_the_finding_in_another(self):
        results, record = self.run_ids(["BROWSER-23", "NEXT-01", "NEXT-02"],
                                       exclude=Exclusions([r"/static/app\.js"]))
        self.assertEqual(results["NEXT-01"].status, "fail", results["NEXT-01"].summary)
        self.assertNotEqual(results["NEXT-02"].status, "pass")
        self.assertNotIn("/static/app.js", self.stub.hits)
        self.assertEqual(record["pacing"]["excluded_not_sent"], 1)  # distinct paths, not attempts


class StillBusyTest(StubCase):
    def stub_args(self):
        return {"always_busy": True}

    def test_answers_still_429_after_the_retry_never_pass(self):
        _, results = runner.run(self.stub.url, ids=["INFRA-04", "API-21", "API-22", "API-24"], delay=0)
        for r in results:
            self.assertEqual(r.status, "error", f"{r.check_id}: {r.summary}")
            self.assertIn("429", r.summary)

    def test_a_crawl_page_still_429_marks_the_crawl_cut(self):
        site = None

        def fn(ctx):
            nonlocal site
            site = crawl(ctx)
            return passed("INFRA-05", "clean")
        result, _ = self.run_with("INFRA-05", fn)
        self.assertEqual(result.status, "error")
        self.assertIn("kept answering 429", site.cut)

    def test_rate_is_halved_once_per_run(self):
        c = Client(self.stub.url, delay=0.05)
        for path in ("/a", "/b", "/c", "/d"):
            c.get(path)
        self.assertEqual((c.slowed, c.throttled, c.delay), (4, 4, 0.1))


class SlowRateLoginProbeTest(StubCase):
    def test_no_limit_seen_at_a_slow_rate_is_manual(self):
        opts = {"rate_limit_path": "/api/login", "rate_limit_attempts": 12}
        _, results = runner.run(self.stub.url, ids=["API-01"], rate=1, options=opts)
        self.assertEqual(results[0].status, "manual", results[0].summary)
        self.assertIn("attempts sent at 1 requests/s", results[0].evidence)
        _, results = runner.run(self.stub.url, ids=["API-01"], delay=0, options=opts)
        self.assertEqual(results[0].status, "warn")  # the default pace keeps the old verdict


class HomeRedirectExcludedTest(StubCase):
    def stub_args(self):
        return {"pages": {"/": (302, "", (("Location", "/app/"),)), "/app/": (200, "<html>app</html>", ())}}

    def test_exclusion_of_the_page_home_redirects_to_exits_2(self):
        with self.assertRaises(runner.ScopeError):
            runner.run(self.stub.url, ids=["INFRA-05"], delay=0, exclude=Exclusions([r"/app/.*"]))
        self.assertNotIn("/app/", self.stub.hits)
        code, _, err = call("scan", self.stub.url, "--exclude-path", "/app/.*", "--check", "INFRA-05")
        self.assertEqual(code, 2)
        self.assertIn("redirects to /app/", err)


class ExclusionTextTest(unittest.TestCase):
    def test_regex_paths_over_256_count_as_excluded_and_stay_fast(self):
        ex = Exclusions([r"/.*/.*/.*/.*\.php"])
        long_path = "http://h" + "/a" * 200
        start = time.monotonic()
        self.assertTrue(ex.match(long_path))
        self.assertFalse(ex.match("http://h" + "/a" * 127))
        self.assertLess(time.monotonic() - start, 1)
        self.assertFalse(Exclusions(["/x*"], glob=True).match(long_path))  # the linear glob keeps the long limit

    def test_errors_name_the_option_of_the_interface(self):
        with self.assertRaisesRegex(ValueError, r"^exclude_path '/\*'"):
            Exclusions(["/*"], glob=True)
        with self.assertRaisesRegex(ValueError, r"^--exclude-path '/\.\*'"):
            Exclusions(["/.*"])

    def test_scope_shows_the_pattern_as_given(self):
        scope = report.run_scope(interface="cli", mode="scan", flags={"exclude_path": [r"/\.well-known/.*"]})
        self.assertEqual(dict(report.scope_lines(scope))["Excluded paths"], '"/\\.well-known/.*"')


if __name__ == "__main__":
    unittest.main()
