"""The code audit (`asa code`): analyzers on a vulnerable and a fixed fake project, OSV (mocked), git index
parsing, merging with a live scan, and the CLI, SARIF and MCP surfaces.

Fake secrets are assembled at runtime and written only into temporary copies of the fixtures, so the repository
holds no secret-shaped strings. `*.fixture` files are renamed at copy time so dependency scanners ignore them.
"""

import base64
import contextlib
import io
import json
import os
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from agent_security_audit import catalog, cli, code_audit, lab, mcp_server, report
from agent_security_audit.code_audit import deps, project, sql
from agent_security_audit.model import Result

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _b64(obj):
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")


SERVICE_JWT = (_b64({"alg": "HS256", "typ": "JWT"}) + "." + _b64({"role": "service_role", "ref": "notarealproject"})
               + "." + "Zm9yLXRlc3RzLW9ubHktbm90LWEtcmVhbC1zaWduYXR1cmU")
STRIPE = "sk_" + "live_" + "Fake4TestsOnly9qWx2Lm7Zp3Rt"


def copy_fixture(name, tmp):
    dst = Path(tmp) / name
    shutil.copytree(FIXTURES / name, dst)
    for p in list(dst.rglob("*.fixture")):
        p.rename(p.with_suffix(""))
    return dst


def fake_osv(pkgs, timeout):
    return {p: ["GHSA-test-0001"] for p in pkgs if (p[1], p[2]) in {("next", "14.0.0"), ("lodash", "4.17.20")}}


def by_id(results):
    return {r.check_id: r for r in results}


def call(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(list(argv))
    return code, out.getvalue(), err.getvalue()


class FixtureTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.vuln = copy_fixture("code_vuln", cls.tmp)
        (cls.vuln / ".env").write_text(f"NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY={SERVICE_JWT}\nPAYMENTS={STRIPE}\n")
        cls.fixed = copy_fixture("code_fixed", cls.tmp)
        # Gitignored local env file: read for public variables, never reported as committed.
        (cls.fixed / ".env.local").write_text(f"NEXT_PUBLIC_SUPABASE_URL=https://x.supabase.co\n"
                                              f"SUPABASE_SERVICE_ROLE_KEY={SERVICE_JWT}\n")
        _, cls.vuln_results = code_audit.run(cls.vuln, osv_query=fake_osv)
        _, cls.fixed_results = code_audit.run(cls.fixed, osv_query=fake_osv)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_vulnerable_project(self):
        got = {cid: r.status for cid, r in by_id(self.vuln_results).items()}
        expected = {
            "INFRA-08": "fail", "NEXT-01": "fail", "ACCESS-01": "fail", "ACCESS-02": "fail", "ACCESS-06": "warn",
            "NEXT-05": "warn", "NEXT-06": "warn", "ACCESS-11": "warn", "AUTH-01": "fail", "ACCESS-08": "fail",
            "NEXT-15": "fail", "NEXT-02": "fail", "NEXT-03": "warn", "NEXT-07": "fail", "NEXT-11": "fail",
            "BROWSER-01": "warn", "BROWSER-02": "warn", "BROWSER-09": "warn", "API-30": "fail", "API-31": "fail",
            "API-32": "fail", "API-05": "warn", "INFRA-13": "fail", "NEXT-04": "fail", "INFRA-15": "fail",
        }
        for cid, status in expected.items():
            with self.subTest(check=cid):
                self.assertEqual(got.get(cid), status, by_id(self.vuln_results).get(cid))

    def test_fixed_project(self):
        results = by_id(self.fixed_results)
        bad = {cid: r.summary for cid, r in results.items() if r.status in ("fail", "warn", "error")}
        self.assertEqual(bad, {})
        for cid in ("NEXT-02", "NEXT-03", "NEXT-07", "NEXT-11", "BROWSER-01", "BROWSER-02", "BROWSER-03",
                    "BROWSER-04", "BROWSER-05", "BROWSER-08", "NEXT-04"):
            with self.subTest(check=cid):
                self.assertEqual(results[cid].status, "pass", results[cid].summary)
        # A search for known bad patterns finds none: that is not proof, so these are manual on a clean project.
        for cid in ("NEXT-01", "BROWSER-09", "API-30", "API-31", "API-32", "API-05", "INFRA-13", "INFRA-15"):
            with self.subTest(check=cid):
                self.assertEqual(results[cid].status, "manual", results[cid].summary)
                self.assertTrue(results[cid].summary.startswith("Not proven:"), results[cid].summary)
        # Guards and RLS found by a static read are evidence, not proof: manual, never pass.
        for cid in ("ACCESS-01", "ACCESS-02", "ACCESS-06", "NEXT-05", "NEXT-06", "ACCESS-11", "AUTH-01",
                    "NEXT-15"):
            with self.subTest(check=cid):
                self.assertEqual(results[cid].status, "manual", results[cid].summary)
                self.assertTrue(results[cid].summary.startswith("Not proven:"), results[cid].summary)
        self.assertTrue(any(e.startswith("app/api/notes/route.ts:6:") for e in results["NEXT-05"].evidence))
        self.assertIn("app/actions.ts:7:", results["NEXT-06"].evidence[0])
        self.assertIn("app/api/cron/cleanup/route.ts:4:", results["NEXT-15"].evidence[0])
        self.assertIn("rejects a mismatch here", results["NEXT-15"].evidence[0])
        # Server-side secret-key use is listed for review, not passed.
        self.assertEqual(results["ACCESS-08"].status, "manual")
        # A clean working tree says nothing about git history, so INFRA-08 is never a pass from the code.
        self.assertEqual(results["INFRA-08"].status, "manual")
        self.assertIn("Git history was not read", results["INFRA-08"].summary)

    def test_evidence_points_at_lines(self):
        results = by_id(self.vuln_results)
        self.assertIn("middleware.ts:5:", results["AUTH-01"].evidence[0])
        self.assertIn("supabase/migrations/0001_init.sql:2:", results["ACCESS-01"].evidence[0])
        loc = dict(results["NEXT-02"].locations[0])
        self.assertRegex(loc.pop("finding_id"), r"^asa1-[0-9a-f]{16}$")
        self.assertEqual(loc, {"path": "next.config.js", "line": 2, "message": "source maps on in production"})
        paths = {loc["path"] for loc in results["API-32"].locations}
        self.assertEqual(paths, {"app/api/notes/route.ts", "app.py"})

    def test_secrets_never_printed_in_full(self):
        for render in (report.to_json, report.to_markdown, report.to_sarif):
            text = render("x", self.vuln_results)
            self.assertNotIn(STRIPE, text)
            self.assertNotIn(SERVICE_JWT, text)
            self.assertNotIn(SERVICE_JWT.split(".")[1], text)
        self.assertIn("sk_live_Fa...", report.to_json("x", self.vuln_results))

    def test_every_result_is_a_known_code_check(self):
        known = catalog.by_id()
        for r in self.vuln_results + self.fixed_results:
            self.assertIn(r.check_id, known)
            self.assertIn(r.check_id, code_audit.CHECKS)
            if r.status in ("fail", "warn"):
                self.assertTrue(r.fix)

    def test_filters(self):
        _, results = code_audit.run(self.vuln, osv=False, ids=["auth-01", "NEXT-02"])
        self.assertEqual({r.check_id for r in results}, {"AUTH-01", "NEXT-02"})
        _, results = code_audit.run(self.vuln, osv=False, areas=["access"])
        self.assertTrue(results and all(r.check_id.startswith("ACCESS-") for r in results))

    def test_osv_off_and_offline(self):
        _, results = code_audit.run(self.vuln, osv=False)
        self.assertEqual(by_id(results)["INFRA-13"].status, "manual")
        self.assertEqual(by_id(results)["NEXT-04"].status, "manual")

        def offline(pkgs, timeout):
            raise deps.OsvError("URLError: offline")

        _, results = code_audit.run(self.vuln, osv_query=offline)
        self.assertEqual(by_id(results)["INFRA-13"].status, "error")
        self.assertEqual(by_id(results)["NEXT-04"].status, "error")

    def test_never_reads_outside_root(self):
        outside = Path(self.tmp) / "outside.ts"
        outside.write_text(f'const k = "{STRIPE}";\n')
        link = self.fixed / "lib" / "linked.ts"
        os.symlink(outside, link)
        try:
            _, results = code_audit.run(self.fixed, osv=False, ids=["INFRA-08"])
            self.assertEqual(results[0].status, "manual")
            self.assertNotIn("linked.ts", json.dumps(results[0].to_dict()))
        finally:
            link.unlink()


class CliTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.vuln = copy_fixture("code_vuln", cls.tmp)
        cls.fixed = copy_fixture("code_fixed", cls.tmp)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_code_command_exit_codes(self):
        code, out, _ = call("code", str(self.vuln), "--no-osv")
        self.assertEqual(code, 1)
        self.assertIn("# Security proof report: ", out)
        self.assertIn("AUTH-01", out)
        code, _, _ = call("code", str(self.fixed), "--no-osv")
        self.assertEqual(code, 0)
        code, _, err = call("code", str(Path(self.tmp) / "missing"))
        self.assertEqual(code, 2)
        self.assertIn("not a directory", err)

    def test_code_sarif_has_file_locations(self):
        code, out, _ = call("code", str(self.vuln), "--no-osv", "--format", "sarif", "--check", "AUTH-01,API-31")
        data = json.loads(out)
        results = data["runs"][0]["results"]
        self.assertEqual({r["ruleId"] for r in results}, {"AUTH-01", "API-31"})
        locs = [r["locations"][0]["physicalLocation"] for r in results]
        self.assertIn({"uri": "middleware.ts", "uriBaseId": "%SRCROOT%"}, [loc["artifactLocation"] for loc in locs])
        self.assertTrue(all(loc["region"]["startLine"] >= 1 for loc in locs))
        self.assertEqual(code, 1)

    def test_code_json_out(self):
        out_path = Path(self.tmp) / "reports" / "code.json"
        code, _, err = call("code", str(self.vuln), "--no-osv", "--format", "json", "--out", str(out_path),
                            "--fail-on", "none")
        self.assertEqual(code, 0)
        self.assertIn("wrote", err)
        data = json.loads(out_path.read_text())
        self.assertTrue(any(r.get("locations") for r in data["results"]))

    def test_scan_with_code_merges(self):
        server, url = lab.serve("fixed", 0)
        try:
            code, out, _ = call("scan", url, "--code", str(self.vuln), "--no-osv", "--no-dns", "--format", "json",
                                "--check", "NEXT-02,NEXT-03,AUTH-01,ACCESS-11", "--fail-on", "none")
        finally:
            server.shutdown()
            server.server_close()
        self.assertEqual(code, 0)
        results = {r["check_id"]: r for r in json.loads(out)["results"]}
        self.assertEqual(results["AUTH-01"]["status"], "fail")    # code settles a manual check
        self.assertEqual(results["NEXT-02"]["status"], "fail")    # a code fail beats the live result
        self.assertEqual(results["NEXT-03"]["status"], "pass")    # a live pass beats a code warn
        self.assertTrue(any(e.startswith("code (warn)") for e in results["NEXT-03"]["evidence"]))
        self.assertEqual(results["ACCESS-11"]["status"], "warn")
        self.assertEqual(len(results), 4)


class MergeTest(unittest.TestCase):
    def test_live_fail_always_stands(self):
        live = [Result("NEXT-01", "fail", "live saw a key", ["/app.js: key"])]
        code = [Result("NEXT-01", "pass", "code clean")]
        merged = code_audit.merge(live, code)
        self.assertEqual(merged[0].status, "fail")
        self.assertEqual(merged[0].summary, "live saw a key")
        self.assertIn("code (pass): code clean", merged[0].evidence)

    def test_code_pass_never_replaces_live_manual(self):
        # Used to merge to pass: a static guess beat the live "not proven".
        live = [Result("AUTH-01", "manual", "Not visible from outside", ["proof steps"])]
        code = [Result("AUTH-01", "pass", "verified", ["middleware.ts:3: getClaims"]),
                Result("NEXT-03", "pass", "poweredByHeader: false")]
        merged = by_id(code_audit.merge(live, code))
        self.assertEqual(merged["AUTH-01"].status, "manual")
        self.assertEqual(merged["AUTH-01"].summary, "Not visible from outside")
        self.assertIn("code (pass): verified", merged["AUTH-01"].evidence)
        self.assertIn("code: middleware.ts:3: getClaims", merged["AUTH-01"].evidence)
        self.assertEqual(merged["NEXT-03"].status, "pass")  # no live result: a provable code result is added as is

    def test_code_pass_never_replaces_live_error(self):
        merged = code_audit.merge([Result("NEXT-02", "error", "timeout")], [Result("NEXT-02", "pass", "off")])
        self.assertEqual(merged[0].status, "error")
        self.assertIn("code (pass): off", merged[0].evidence)

    def test_code_fail_warn_and_manual_still_fill_in(self):
        for live_status in ("manual", "error", "skip"):
            for code_status in ("fail", "warn", "manual"):
                with self.subTest(live=live_status, code=code_status):
                    merged = code_audit.merge([Result("NEXT-05", live_status, "live")],
                                              [Result("NEXT-05", code_status, "code", ["route.ts:3: x"])])
                    self.assertEqual(merged[0].status, code_status)
        merged = code_audit.merge([Result("NEXT-02", "skip", "n/a")], [Result("NEXT-02", "pass", "off")])
        self.assertEqual(merged[0].status, "pass")  # a skip is not a live observation to protect


class GitIndexTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def git(self, *args):
        subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.com", *args], cwd=self.tmp,
                       check=True, capture_output=True)

    @unittest.skipUnless(shutil.which("git"), "git not installed")
    def test_tracked_env_file_and_index_versions(self):
        root = Path(self.tmp)
        (root / "a" / "deep").mkdir(parents=True)
        (root / "a" / "deep" / "x.ts").write_text("export const x = 1;\n")
        (root / "a" / "deep" / "y.ts").write_text("export const y = 2;\n")
        (root / ".env.production").write_text("DATABASE_PASSWORD=hunter2hunter2\n")
        (root / "untracked.ts").write_text(f'const k = "{STRIPE}";\n')
        self.git("init", "-q")
        self.git("add", ".env.production", "a")
        for version in ("2", "4"):
            with self.subTest(index_version=version):
                self.git("update-index", "--index-version", version)
                proj = project.Project(root)
                self.assertTrue(proj.source.startswith("git index"))
                self.assertIn("plus 1 untracked file not ignored", proj.source)
                # Untracked files that git would commit are read too; the index decides what is "tracked".
                self.assertEqual(proj.files, [".env.production", "a/deep/x.ts", "a/deep/y.ts", "untracked.ts"])
                self.assertEqual(proj.tracked, {".env.production", "a/deep/x.ts", "a/deep/y.ts"})
        _, results = code_audit.run(root, osv=False, ids=["INFRA-08"])
        self.assertEqual(results[0].status, "fail")
        self.assertIn("untracked.ts:1:", results[0].evidence[0])
        self.assertIn("tracked in git", results[0].evidence[1])
        self.assertNotIn("hunter2", json.dumps(results[0].to_dict()))


class UnitTest(unittest.TestCase):
    def test_gitignore(self):
        ig = project.GitIgnore()
        ig.add("", ".env*\n!.env.example\n/build\nlogs/\n**/secret-*.json\n*.log\n")
        ig.add("pkg", "local.txt\n")
        self.assertTrue(ig.ignored(".env.local", False))
        self.assertFalse(ig.ignored(".env.example", False))
        self.assertTrue(ig.ignored("build", True))
        self.assertFalse(ig.ignored("src/build", True))
        self.assertTrue(ig.ignored("src/logs", True))
        self.assertFalse(ig.ignored("src/logs", False))
        self.assertTrue(ig.ignored("a/b/secret-1.json", False))
        self.assertTrue(ig.ignored("x/y.log", False))
        self.assertTrue(ig.ignored("pkg/local.txt", False))
        self.assertFalse(ig.ignored("local.txt", False))

    def test_split_sql_keeps_function_bodies(self):
        text = "create function f() returns void as $body$ begin; select 1; end; $body$ language plpgsql;\n" \
               "-- a comment; with a semicolon\nselect ';' ; /* block; */ select 2"
        stmts = [s for _, s in sql.split_sql(text)]
        self.assertEqual(len(stmts), 3)
        self.assertTrue(stmts[0].startswith("create function"))
        self.assertEqual(stmts[1], "select ';'")
        self.assertEqual(stmts[2].strip(), "select 2")

    def test_strip_js_comments(self):
        code = 'const a = "http://x"; // eval(x)\n/* eval(y) */ const b = `//not a comment`;\n'
        out = project.strip_js_comments(code)
        self.assertNotIn("eval", out)
        self.assertIn('"http://x"', out)
        self.assertIn("`//not a comment`", out)
        self.assertEqual(out.count("\n"), code.count("\n"))

    def test_redact(self):
        line = f'const stripe = new Stripe("{STRIPE}"); const password = "correct-horse-battery";'
        out = project.redact(line)
        self.assertNotIn(STRIPE, out)
        self.assertNotIn("correct-horse-battery", out)

    def test_lockfile_parsers(self):
        pnpm = ("lockfileVersion: '9.0'\n\npackages:\n\n  next@14.0.0:\n    resolution: {}\n\n"
                "  '@supabase/ssr@0.5.1':\n    resolution: {}\n\nsnapshots:\n\n  react-dom@18.2.0(react@18.2.0):\n"
                "    dependencies: {}\n")
        self.assertEqual(deps.parse_pnpm_lock(pnpm), {("next", "14.0.0"), ("@supabase/ssr", "0.5.1"),
                                                      ("react-dom", "18.2.0")})
        pnpm6 = "lockfileVersion: 5.4\npackages:\n  /next/13.4.0_react@18.2.0:\n    resolution: {}\n"
        self.assertEqual(deps.parse_pnpm_lock(pnpm6), {("next", "13.4.0")})
        yarn1 = ('# yarn lockfile v1\n\n"@babel/core@^7.0.0", "@babel/core@^7.1.0":\n  version "7.22.5"\n\n'
                 'next@^14:\n  version "14.0.0"\n')
        self.assertEqual(deps.parse_yarn_lock(yarn1), {("@babel/core", "7.22.5"), ("next", "14.0.0")})
        berry = '__metadata:\n  version: 6\n\n"next@npm:^14.0.0":\n  version: 14.0.0\n  resolution: "x"\n'
        self.assertEqual(deps.parse_yarn_lock(berry), {("next", "14.0.0")})
        v1 = json.dumps({"lockfileVersion": 1, "dependencies": {"a": {"version": "1.0.0", "dependencies": {
            "b": {"version": "2.0.0"}}}}})
        self.assertEqual(deps.parse_package_lock(v1), {("a", "1.0.0"), ("b", "2.0.0")})
        self.assertEqual(deps.parse_requirements("Django==4.2.0\nrequests[socks]==2.31.0\n# c\nflask>=2\n"),
                         {("django", "4.2.0"), ("requests", "2.31.0")})
        poetry = '[[package]]\nname = "Jinja2"\nversion = "3.1.2"\n'
        self.assertEqual(deps.parse_poetry_lock(poetry), {("jinja2", "3.1.2")})

    def test_query_osv_request(self):
        sent = {}

        class Resp:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self, n):
                return json.dumps({"results": [{"vulns": [{"id": "GHSA-1"}]}, {}]}).encode()

        def fake_urlopen(req, timeout, context):
            sent.update(url=req.full_url, body=json.loads(req.data), context=context, timeout=timeout)
            return Resp()

        with mock.patch("urllib.request.urlopen", fake_urlopen):
            found = deps.query_osv({("npm", "next", "14.0.0"), ("PyPI", "django", "4.2.0")}, timeout=3)
        self.assertEqual(sent["url"], "https://api.osv.dev/v1/querybatch")
        self.assertEqual(sent["body"]["queries"][0], {"package": {"ecosystem": "PyPI", "name": "django"},
                                                      "version": "4.2.0"})
        self.assertTrue(sent["context"].check_hostname)
        self.assertEqual(found, {("PyPI", "django", "4.2.0"): ["GHSA-1"]})

        def boom(req, timeout, context):
            raise OSError("network down")

        with mock.patch("urllib.request.urlopen", boom), self.assertRaises(deps.OsvError):
            deps.query_osv({("npm", "next", "14.0.0")})


class McpTest(unittest.TestCase):
    def test_run_code_audit_tool(self):
        tool = mcp_server.TOOLS_BY_NAME["run_code_audit"]
        self.assertEqual(tool["inputSchema"]["required"], ["path"])
        with tempfile.TemporaryDirectory() as tmp:
            vuln = copy_fixture("code_vuln", tmp)
            res = mcp_server.call_tool({"name": "run_code_audit",
                                        "arguments": {"path": str(vuln), "no_osv": True, "checks": ["AUTH-01"]}})
            self.assertFalse(res["isError"], res)
            data = json.loads(res["content"][-1]["text"])  # the summary block comes first, the report last
            self.assertEqual([r["check_id"] for r in data["results"]], ["AUTH-01"])
            self.assertEqual(data["results"][0]["status"], "fail")
            res = mcp_server.call_tool({"name": "run_code_audit", "arguments": {"path": str(Path(tmp) / "nope")}})
            self.assertTrue(res["isError"])


if __name__ == "__main__":
    unittest.main()


def audit_files(files, **kw):
    """Run the code audit on a temporary project made of {path: text}."""
    with tempfile.TemporaryDirectory() as tmp:
        for rel, text in files.items():
            (Path(tmp) / rel).parent.mkdir(parents=True, exist_ok=True)
            (Path(tmp) / rel).write_text(text)
        return by_id(code_audit.run(tmp, osv=kw.pop("osv", False), **kw)[1])


class EdgeFixtureTest(unittest.TestCase):
    """Regression cases where a static read used to pass, or stay silent, without evidence."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.root = copy_fixture("code_edge", cls.tmp)
        _, results = code_audit.run(cls.root, osv_query=fake_osv)
        cls.results = by_id(results)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_weak_header_values_fail(self):
        for cid in ("BROWSER-01", "BROWSER-02", "BROWSER-03", "BROWSER-04", "BROWSER-05"):
            with self.subTest(check=cid):
                self.assertEqual(self.results[cid].status, "fail", self.results[cid].summary)
        self.assertIn("max-age is 0", self.results["BROWSER-01"].summary)
        self.assertIn("any host", self.results["BROWSER-02"].summary)
        self.assertIn("unsafe-url", self.results["BROWSER-05"].summary)
        self.assertEqual(self.results["BROWSER-08"].status, "pass")
        self.assertTrue(any("next.config.js:" in e and "max-age=0" in e for e in self.results["BROWSER-01"].evidence))

    def test_sanitizer_lookalikes_and_json_in_script(self):
        r = self.results["BROWSER-09"]
        self.assertEqual(r.status, "warn")
        lines = sorted(loc["line"] for loc in r.locations)
        self.assertEqual(lines, [5, 10, 14])
        self.assertTrue(any("</script>" in e for e in r.evidence))

    def test_aliased_and_promisified_shell_calls(self):
        r = self.results["API-31"]
        self.assertEqual(r.status, "fail")
        self.assertEqual(sorted(loc["line"] for loc in r.locations), [9, 10])
        self.assertIn("2 shell commands are built", r.summary)

    def test_auth_in_one_method_does_not_cover_another(self):
        r = self.results["NEXT-05"]
        self.assertEqual(r.status, "warn")
        self.assertEqual(len(r.locations), 1)
        self.assertIn("GET touches data", r.evidence[0])

    def test_unsupported_lockfile_is_not_silent(self):
        self.assertEqual(self.results["INFRA-13"].status, "manual")
        self.assertIn("bun.lock", self.results["INFRA-13"].summary)
        self.assertEqual(self.results["NEXT-04"].status, "manual")
        _, results = code_audit.run(self.root, osv=False)
        self.assertEqual(by_id(results)["INFRA-13"].status, "manual")


class AccuracyTest(unittest.TestCase):
    def test_header_values_from_host_config(self):
        vercel = json.dumps({"headers": [{"source": "/(.*)", "headers": [
            {"key": "Strict-Transport-Security", "value": "max-age=63072000; includeSubDomains"},
            {"key": "X-Frame-Options", "value": "ALLOWALL"}]}]})
        r = audit_files({"vercel.json": vercel, "_headers": "/*\n  Referrer-Policy: unsafe-url\n"})
        self.assertEqual(r["BROWSER-01"].status, "pass")
        self.assertEqual(r["BROWSER-04"].status, "fail")
        self.assertEqual(r["BROWSER-05"].status, "fail")

    def test_dynamic_header_value_is_manual(self):
        r = audit_files({"next.config.js": 'const csp = process.env.CSP;\nmodule.exports = { async headers() { '
                         'return [{ source: "/(.*)", headers: [{ key: "Content-Security-Policy", value: csp }, '
                         '{ key: "X-Content-Type-Options", value: `${process.env.NOSNIFF}` }] }]; } };\n'})
        self.assertEqual(r["BROWSER-02"].status, "manual")
        self.assertIn("built at run time", r["BROWSER-02"].summary)
        self.assertEqual(r["BROWSER-03"].status, "manual")

    def test_header_value_built_from_a_constant(self):
        mw = ("export function middleware() {\n  const nonce = crypto.randomUUID();\n"
              "  const cspHeader = `\n    default-src 'self';\n    script-src 'self' 'nonce-${nonce}' 'strict-dynamic';\n"
              "    base-uri 'none';\n  `;\n  const res = NextResponse.next();\n"
              "  res.headers.set('Content-Security-Policy', cspHeader.replace(/\\s{2,}/g, ' ').trim());\n"
              "  res.headers.set('Permissions-Policy', ['camera=()', 'microphone=()'].join(', '));\n"
              "  return res;\n}\n")
        r = audit_files({"middleware.ts": mw})
        self.assertEqual(r["BROWSER-02"].status, "pass", r["BROWSER-02"].summary)
        self.assertEqual(r["BROWSER-08"].status, "warn")  # no Cross-Origin-Opener-Policy, as the live check says

    def test_middleware_headers_in_separate_branches_are_manual(self):
        pp = "res.headers.set('Permissions-Policy', 'camera=()');\n"
        coop = "res.headers.set('Cross-Origin-Opener-Policy', 'same-origin');\n"
        hsts = "res.headers.set('Strict-Transport-Security', 'max-age=63072000; includeSubDomains');\n"
        head = "export function middleware(req) {\n  const res = NextResponse.next();\n"
        cases = {
            "if/else": head + "  if (req.nextUrl.pathname.startsWith('/api')) {\n    " + pp + "  } else {\n    " + coop
                       + "  }\n  return res;\n}\n",
            "early return": head + "  if (!req.cookies.get('sid')) {\n    return NextResponse.redirect('/login');\n  }\n  "
                            + pp + "  " + coop + "  return res;\n}\n",
            "brace-less early return": head + "  if (req.method === 'OPTIONS') return res;\n  " + pp + "  " + coop
                                       + "  return res;\n}\n",
            "brace-less if": head + "  if (prod) " + pp + "  " + coop + "  return res;\n}\n",
            "switch": head + "  switch (kind) {\n    case 'a': " + pp + "      " + coop + "      break;\n  }\n"
                      "  return res;\n}\n",
        }
        for name, mw in cases.items():
            with self.subTest(name=name):
                r = audit_files({"middleware.ts": mw})
                self.assertEqual(r["BROWSER-08"].status, "manual", r["BROWSER-08"].summary)
                self.assertIn("only in some branches", r["BROWSER-08"].summary)
        r = audit_files({"middleware.ts": cases["early return"].replace(pp, pp + "  " + hsts)})
        self.assertEqual(r["BROWSER-01"].status, "manual")

    def test_semicolon_free_middleware_sets_after_a_braceless_if_pass(self):
        # A brace-less if guards one statement; in code without semicolons later sets still run on every request.
        xfo = "  response.headers.set('X-Frame-Options', 'DENY')\n  response.headers.set('X-Content-Type-Options', 'nosniff')\n"
        for guard in ("  if (process.env.DEBUG) console.log(request.url)\n",
                      "  if (isProtectedRoute(req)) await auth.protect()\n",
                      "  if (process.env.DEBUG)\n    console.log(request.url)\n"):
            with self.subTest(guard=guard):
                mw = ("export default function middleware(request) {\n" + guard
                      + "  const response = NextResponse.next()\n" + xfo + "  return response\n}\n")
                r = audit_files({"middleware.ts": mw})
                self.assertEqual(r["BROWSER-03"].status, "pass", r["BROWSER-03"].summary)
                self.assertEqual(r["BROWSER-04"].status, "pass", r["BROWSER-04"].summary)
        # The set that is the guarded statement, on the same or the next line, is still conditional.
        for guard in ("  if (prod) ", "  if (prod)\n    ", "  if (a) foo()\n  else "):
            with self.subTest(guard=guard):
                mw = ("export default function middleware(request) {\n  const response = NextResponse.next()\n"
                      + guard + "response.headers.set('X-Frame-Options', 'DENY')\n  return response\n}\n")
                self.assertEqual(audit_files({"middleware.ts": mw})["BROWSER-04"].status, "manual")

    def test_middleware_early_return_inside_a_loop_is_manual(self):
        xfo = "  res.headers.set('X-Frame-Options', 'DENY')\n  res.headers.set('X-Content-Type-Options', 'nosniff')\n"
        loops = {
            "for of": "  for (const p of SKIP) {\n    if (path.startsWith(p)) return NextResponse.next()\n  }\n",
            "classic for": "  for (let i = 0; i < SKIP.length; i++) {\n    if (path.startsWith(SKIP[i])) return NextResponse.next();\n  }\n",
            "while": "  while (i < n) {\n    if (skip(i)) return NextResponse.next()\n    i++\n  }\n",
            "brace-less for": "  for (const p of SKIP) if (path.startsWith(p)) return NextResponse.next()\n",
        }
        for name, loop in loops.items():
            with self.subTest(name=name):
                mw = ("export function middleware(req) {\n  const path = req.nextUrl.pathname\n" + loop
                      + "  const res = NextResponse.next()\n" + xfo + "  return res\n}\n")
                r = audit_files({"middleware.ts": mw})
                self.assertEqual(r["BROWSER-03"].status, "manual", r["BROWSER-03"].summary)
                self.assertEqual(r["BROWSER-04"].status, "manual", r["BROWSER-04"].summary)

    def test_sanitized_html_count_agrees(self):
        one = audit_files({"a.jsx": "export const A = () => <div dangerouslySetInnerHTML={{ __html: '<b>x</b>' }} />;\n"})
        self.assertIn("(1 literal or sanitized use)", one["BROWSER-09"].summary)
        two = audit_files({"a.jsx": "export const A = () => <div dangerouslySetInnerHTML={{ __html: '<b>x</b>' }} />;\n"
                                    "export const B = () => <p dangerouslySetInnerHTML={{ __html: '<i>y</i>' }} />;\n"})
        self.assertIn("(2 literal or sanitized uses)", two["BROWSER-09"].summary)

    def test_middleware_headers_on_every_path_still_pass(self):
        # A helper with its own early return, a nonce template and a final return do not make the sets conditional.
        mw = ("function pick(x) {\n  if (!x) return 'a';\n  return x;\n}\n"
              "export function middleware(req) {\n  const nonce = crypto.randomUUID();\n"
              "  const res = NextResponse.next();\n"
              "  res.headers.set('Permissions-Policy', `camera=()`);\n"
              "  res.headers.set('Cross-Origin-Opener-Policy', 'same-origin');\n"
              "  if (req.nextUrl.pathname === '/x') { console.log(pick(nonce)); }\n  return res;\n}\n")
        r = audit_files({"middleware.ts": mw})
        self.assertEqual(r["BROWSER-08"].status, "pass", r["BROWSER-08"].summary)
        # A weak value set in one branch is still a fail: that value is observed in the code.
        weak = ("export function middleware(req) {\n  if (a) {\n"
                "    res.headers.set('Strict-Transport-Security', 'max-age=0');\n  }\n}\n")
        self.assertEqual(audit_files({"middleware.ts": weak})["BROWSER-01"].status, "fail")

    def test_header_value_from_import_and_ternary(self):
        r = audit_files({
            "src/config/headers.ts": 'export const HSTS = "max-age=100";\n',
            "src/proxy.ts": 'import { HSTS } from "@/config/headers";\nexport function proxy(req) {\n'
                            '  res.headers.set("Strict-Transport-Security", HSTS);\n'
                            '  res.headers.set("Referrer-Policy", req.auth ? "strict-origin" : "unsafe-url");\n}\n'})
        self.assertEqual(r["BROWSER-01"].status, "fail")  # max-age under a year, read from the imported constant
        self.assertIn("max-age is 100", r["BROWSER-01"].summary)
        self.assertEqual(r["BROWSER-05"].status, "fail")  # the weaker branch decides

    def test_more_shell_aliases(self):
        r = audit_files({"lib/a.js": "const { exec: run } = require('child_process');\nrun(`rm ${x}`);\n",
                         "lib/b.ts": "import * as cp2 from 'node:child_process';\ncp2.execSync('ls ' + dir);\n",
                         "lib/c.ts": "import { exec as sh } from 'child_process';\nsh('ls -la');\n"})
        self.assertEqual(r["API-31"].status, "fail")
        self.assertEqual({loc["path"] for loc in r["API-31"].locations}, {"lib/a.js", "lib/b.ts"})

    def test_headers_on_different_routes_are_not_one_response(self):
        def cfg(*routes):
            return ("module.exports = { async headers() { return [" + ", ".join(
                f'{{ source: "{src}", headers: [' + ", ".join(f'{{ key: "{k}", value: "{v}" }}' for k, v in hs) + "] }"
                for src, hs in routes) + "]; } };\n")
        pp, coop = ("Permissions-Policy", "camera=()"), ("Cross-Origin-Opener-Policy", "same-origin")
        r = audit_files({"next.config.js": cfg(("/a", [pp]), ("/b", [coop]))})
        self.assertEqual(r["BROWSER-08"].status, "manual", r["BROWSER-08"].summary)
        self.assertIn("different routes", r["BROWSER-08"].summary)
        r = audit_files({"next.config.js": cfg(("/(.*)", [pp, coop]))})
        self.assertEqual(r["BROWSER-08"].status, "pass")
        vercel = json.dumps({"headers": [{"source": "/a", "headers": [{"key": pp[0], "value": pp[1]}]},
                                         {"source": "/b", "headers": [{"key": coop[0], "value": coop[1]}]}]})
        self.assertEqual(audit_files({"vercel.json": vercel})["BROWSER-08"].status, "manual")
        headers = f"/a\n  {pp[0]}: {pp[1]}\n/b\n  {coop[0]}: {coop[1]}\n"
        self.assertEqual(audit_files({"_headers": headers})["BROWSER-08"].status, "manual")
        # A strong X-Frame-Options on one route does not cover a frame-ancestors * on another.
        r = audit_files({"next.config.js": cfg(("/a", [("X-Frame-Options", "DENY")]),
                                               ("/b", [("Content-Security-Policy", "frame-ancestors *")]))})
        self.assertEqual(r["BROWSER-04"].status, "fail")
        r = audit_files({"next.config.js": "module.exports = {};\n"})
        self.assertIn("Cross-Origin-Opener-Policy are not set", r["BROWSER-08"].summary)
        self.assertIn("Set them there", r["BROWSER-08"].summary)

    def test_every_route_header_value_is_judged(self):
        hsts = [(f"/r{i}", [("Strict-Transport-Security", f"max-age={63072000 + i}; includeSubDomains")])
                for i in range(17)] + [("/z", [("Strict-Transport-Security", "max-age=0")])]
        code = "module.exports = { async headers() { return [" + ", ".join(
            f'{{ source: "{s}", headers: [{{ key: "{k}", value: "{v}" }}] }}' for s, [(k, v)] in hsts) + "]; } };\n"
        self.assertEqual(audit_files({"next.config.js": code})["BROWSER-01"].status, "fail")
        mw = "export function middleware() {\n  res.headers.set('Strict-Transport-Security', hsts);\n}\n"
        with mock.patch("agent_security_audit.code_audit.nextjs._branches", lambda e: [
                f'"max-age={63072000 + i}; includeSubDomains"' for i in range(300)]):
            r = audit_files({"middleware.ts": mw})
        self.assertEqual(r["BROWSER-01"].status, "manual")  # too many values to judge them all is never a pass

    def test_shell_alias_with_named_import_and_inline_require(self):
        r = audit_files({"a.js": "import child, { spawn } from 'child_process';\nchild.exec(`ls ${x}`);\n"})
        self.assertEqual(r["API-31"].status, "fail")
        r = audit_files({"b.js": "const run = promisify(require('child_process').exec);\nrun(`ls ${x}`);\n"})
        self.assertEqual(r["API-31"].status, "fail")
        r = audit_files({"c.js": "require('node:child_process').execSync('ls ' + dir);\n"})
        self.assertEqual(r["API-31"].status, "fail")

    def test_sanitizer_must_wrap_the_whole_value_and_be_real(self):
        # A sanitized value is no finding, so the read is clean: manual (a pattern search proves nothing), not warn.
        def html(value, head=""):
            return audit_files({"a.jsx": head + "export const A = () => "
                                f"<div dangerouslySetInnerHTML={{{{ __html: {value} }}}} />;\n"})["BROWSER-09"].status
        self.assertEqual(html("DOMPurify.sanitize(x) + b"), "warn")
        self.assertEqual(html("sanitize(x)", "const sanitize = (s) => s;\n"), "warn")
        self.assertEqual(html("renderToString(x)"), "warn")
        # A receiver that is not imported from a sanitizer package proves nothing (a global or local object).
        self.assertEqual(html("DOMPurify.sanitize(x)"), "warn")
        self.assertEqual(html("DOMPurify.sanitize(x)", "import DOMPurify from 'dompurify';\n"), "manual")
        self.assertEqual(html("he.decode(x)", "import he from 'he';\n"), "warn")
        self.assertEqual(html("he.encode(x)", "import he from 'he';\n"), "manual")
        self.assertEqual(html("escape(x)", "const { escape } = require('html-escaper');\n"), "manual")
        self.assertEqual(html("decode(x)", "import { decode as escape2, decode } from 'he';\n"), "warn")
        self.assertEqual(html("sanitize(x)", "import sanitize from 'sanitize-html';\nfunction sanitize(s) { return s; }\n"),
                         "warn")
        self.assertEqual(html("xss(x)", "import { sanitize } from 'other';\nimport xss from 'xss';\n"), "manual")
        # The old cross-statement regex let a name in one statement pair with a package in a later one.
        self.assertEqual(html("sanitize(x)", "import { sanitize } from './local';\nimport x from 'dompurify';\n"), "warn")
        self.assertEqual(html("sanitize(x, { allowedTags: [] })", "import sanitize from 'sanitize-html';\n"), "manual")
        self.assertEqual(html("renderToString(x)", "import { renderToString } from 'react-dom/server';\n"), "manual")

    def test_shared_header_list_across_routes_is_manual(self):
        cfg = ("const common = [{ key: 'X-Content-Type-Options', value: 'nosniff' }];\n"
               "module.exports = { async headers() { return [\n"
               "  { source: '/a', headers: common },\n  { source: '/b', headers: [] },\n] } };\n")
        r = audit_files({"next.config.js": cfg})
        self.assertNotEqual(r["BROWSER-03"].status, "pass")

    def test_shared_header_list_shapes_are_manual(self):
        for shape in ("headers", "headers: [...common]", "headers: common.slice()", "headers: [{ key: 'A', value: 'b' }, ...common]"):
            cfg = ("const common = [{ key: 'X-Content-Type-Options', value: 'nosniff' }];\n"
                   "const headers = common;\n"
                   "module.exports = { async headers() { return [\n"
                   f"  {{ source: '/a', {shape} }},\n  {{ source: '/b', headers: [] }},\n] }} }};\n")
            r = audit_files({"next.config.js": cfg})
            self.assertNotEqual(r["BROWSER-03"].status, "pass", shape)
        inline = ("module.exports = { async headers() { return [\n"
                  "  { source: '/(.*)', headers: [{ key: 'X-Content-Type-Options', value: 'nosniff' }] },\n"
                  "  { source: '/:path*', headers: [{ key: 'X-Content-Type-Options', value: 'nosniff' }] },\n] } };\n")
        self.assertEqual(audit_files({"next.config.js": inline})["BROWSER-03"].status, "pass")

    def test_middleware_header_on_some_requests_is_manual(self):
        csp = "default-src 'self'; script-src 'self'; frame-ancestors 'none'"
        body = (f"  res.headers.set('Content-Security-Policy', \"{csp}\");\n"
                "  res.headers.set('X-Frame-Options', 'DENY');\n")
        branch = ("import { NextResponse } from 'next/server';\nexport function middleware(req) {\n"
                  "  const res = NextResponse.next();\n  if (req.nextUrl.pathname.startsWith(\"/admin\")) {\n"
                  + body + "  }\n  return res;\n}\n")
        early = ("import { NextResponse } from 'next/server';\nexport function middleware(req) {\n"
                 "  const res = NextResponse.next();\n  if (!req.nextUrl.pathname.startsWith('/admin')) return res;\n"
                 + body + "  return res;\n}\n")
        matcher = ("import { NextResponse } from 'next/server';\nexport function middleware(req) {\n"
                   "  const res = NextResponse.next();\n" + body + "  return res;\n}\n"
                   "export const config = { matcher: '/admin/:path*' };\n")
        for mw in (branch, early, matcher):
            r = audit_files({"middleware.ts": mw})
            self.assertEqual(r["BROWSER-02"].status, "manual", mw)
            self.assertEqual(r["BROWSER-04"].status, "manual", mw)
        always = ("import { NextResponse } from 'next/server';\nexport function middleware(req) {\n"
                  "  const res = NextResponse.next();\n" + body + "  return res;\n}\n")
        self.assertEqual(audit_files({"middleware.ts": always})["BROWSER-04"].status, "pass")

    def test_regex_literal_quotes_do_not_merge_a_helper_into_get(self):
        code = ("import { supabase } from '@/db';\nexport async function GET(req) {\n  const a = /'/;\n"
                "  const { data } = await supabase.from(\"notes\").select();\n  return Response.json(data);\n}\n"
                "async function helper() {\n  await supabase.auth.getUser();\n  const b = /'/;\n}\n")
        self.assertNotEqual(audit_files({"app/api/x/route.ts": code})["NEXT-05"].status, "pass")

    def test_string_blanking_is_linear(self):
        from agent_security_audit.code_audit import nextjs
        route = ("import { supabase } from '@/db';\nexport async function GET() {\n"
                 "  return Response.json(await supabase.from('notes').select());\n}\nconst junk = 1; ")
        for tail in ('"\\' * 50000, "'\\" * 50000, "`\\" * 50000, '"\n' * 50000):
            start = time.monotonic()
            nextjs._has_auth(route + tail)
            audit_files({"app/api/x/route.ts": route + tail})
            self.assertLess(time.monotonic() - start, 5.0)
        self.assertFalse(nextjs._has_auth("const m = 'call getUser() later';"))
        self.assertTrue(nextjs._has_auth("const m = 'x'; const { data: { user } } = await supabase.auth.getUser();"
                                         " if (!user) return deny();"))

    def test_sanitizer_bindings_are_read_once_per_file(self):
        from agent_security_audit.code_audit import patterns
        code = "import escape from 'escape-html';\n" + "<div dangerouslySetInnerHTML={{__html: escape(x)}} />\n" * 20000
        start = time.monotonic()
        r = audit_files({"app/page.tsx": code})
        self.assertLess(time.monotonic() - start, 10.0)
        self.assertEqual(r["BROWSER-09"].status, "manual")  # every use sanitized: no warn
        self.assertIsNotNone(patterns._bindings.cache_info())

    def test_sanitizer_import_scan_is_linear(self):
        from agent_security_audit.code_audit import patterns
        for code in ["import " + "a," * 25000, "import x " + " " * 50000 + "from", "const " + "{" * 50000,
                     "const a = require(" + "'" * 50000, "import {" + "a as b," * 7000]:
            start = time.monotonic()
            patterns._bindings(code + "\n" + "sanitize")
            patterns._sanitized(code, "sanitize(x)")
            self.assertLess(time.monotonic() - start, 1.0)

    def test_next04_manual_when_next_lockfile_unread(self):
        r = audit_files({"package.json": json.dumps({"dependencies": {"next": "15.0.0"}}), "bun.lock": "{}",
                         "py/poetry.lock": '[[package]]\nname = "requests"\nversion = "2.31.0"\n'})
        self.assertEqual(r["NEXT-04"].status, "manual")
        self.assertIn("bun.lock", r["NEXT-04"].summary)

    def test_column_zero_statement_stays_in_its_handler(self):
        code = ("import { db } from '@/db';\nexport async function GET(req) {\nconst id = req.nextUrl.searchParams;\n"
                "const rows = await db.select().from(t);\nreturn Response.json(rows);\n}\n")
        r = audit_files({"app/api/x/route.ts": code})
        self.assertIn(r["NEXT-05"].status, ("fail", "warn"), r["NEXT-05"].summary)

    def test_route_helper_auth_counts_and_all_guarded_stay_manual(self):
        code = ("async function requireOwner() { return supabase.auth.getUser(); }\n"
                "export async function GET() {\n  await requireOwner();\n  return supabase.from('notes').select();\n}\n"
                "export const DELETE = withAuth(async () => supabase.from('notes').delete());\n"
                "export function OPTIONS() {\n  return new Response(null);\n}\n")
        r = audit_files({"app/api/notes/route.ts": code})
        self.assertEqual(r["NEXT-05"].status, "manual", r["NEXT-05"].evidence)  # was pass: presence is not proof
        self.assertIn("2 of 2", r["NEXT-05"].summary)
        self.assertIn("app/api/notes/route.ts:3:", r["NEXT-05"].evidence[0])
        r = audit_files({"app/api/ping/route.ts": "export function GET() {\n  return Response.json({ ok: 1 });\n}\n"})
        self.assertEqual(r["NEXT-05"].status, "manual")  # no data seen is not proof that every handler is guarded

    def test_auth_lookalike_or_unchecked_auth_is_never_a_pass(self):
        # getUserById matches the auth heuristic but checks nothing; auth() whose result is ignored gates nothing.
        for body in ("const user = await getUserById(params.id);\n  return db.select().from(t);",
                     "const session = await auth();\n  return prisma.post.deleteMany({});"):
            code = f"import {{ db, prisma }} from '@/db';\nexport async function GET(req, {{ params }}) {{\n  {body}\n}}\n"
            with self.subTest(body=body):
                self.assertNotEqual(audit_files({"app/api/x/route.ts": code})["NEXT-05"].status, "pass")
        action = ("'use server';\nexport async function remove(id) {\n  await getUserById(id);\n"
                  "  return db.delete(t);\n}\n")
        r = audit_files({"app/actions.ts": action})
        for cid in ("NEXT-06", "ACCESS-11"):
            with self.subTest(check=cid):
                self.assertNotEqual(r[cid].status, "pass", r[cid].summary)
        server = "export async function GET() {\n  const { data } = await supabase.auth.getUser();\n}\n"
        self.assertEqual(audit_files({"app/api/me/route.ts": server})["AUTH-01"].status, "manual")

    def test_authorization_word_in_a_string_is_not_a_guard(self):
        code = ("export async function GET() {\n  if (!ok) return Response.json({ error: \"authorization required\" });\n"
                "  return supabase.from('notes').select();\n}\n")
        r = audit_files({"app/api/notes/route.ts": code})
        self.assertEqual(r["NEXT-05"].status, "warn")
        code = ("export async function GET(req) {\n  if (req.headers.get('authorization') !== key) return deny();\n"
                "  return supabase.from('notes').select();\n}\n")
        self.assertEqual(audit_files({"app/api/notes/route.ts": code})["NEXT-05"].status, "manual")

    def test_unbalanced_scan_never_lends_a_sibling_guard(self):
        # The regex literal holds a quote, so the depth scan stays inside a "string" and the sibling declaration
        # below would look nested in GET. Its auth call must not count as GET's guard.
        code = ("export async function GET() {\n  const re = /'/;\n  return supabase.from('notes').select();\n}\n"
                "async function requireUser() { return supabase.auth.getUser(); }\n")
        r = audit_files({"app/api/notes/route.ts": code})
        self.assertIn(r["NEXT-05"].status, ("warn", "manual"))
        code = ("export async function GET() {\n  const re = /'/;\n  const { data } = await supabase.auth.getUser();\n"
                "  if (!data.user) return deny();\n  return supabase.from('notes').select();\n}\n")
        self.assertEqual(audit_files({"app/api/notes/route.ts": code})["NEXT-05"].status, "manual")

    def test_file_cap_makes_passes_manual(self):
        files = {"next.config.js": "module.exports = { poweredByHeader: false };\n",
                 **{f"z/f{i}.ts": "export const x = 1;\n" for i in range(4)}}
        self.assertEqual(audit_files(files)["NEXT-03"].status, "pass")
        with mock.patch.object(project, "MAX_FILES", 2):
            r = audit_files(files)
        self.assertEqual(r["NEXT-03"].status, "manual")
        self.assertIn("only the first 2 of 5 files", r["NEXT-03"].summary)
        self.assertFalse([cid for cid, x in r.items() if x.status == "pass"])

    def test_oversized_file_makes_pass_manual(self):
        small = "module.exports = { poweredByHeader: false };\n"
        files = {"apps/a/next.config.js": small, "apps/b/next.config.js": small + "//\n" * 400}
        with mock.patch.object(project, "MAX_BYTES", 200):
            r = audit_files(files)
        self.assertEqual(r["NEXT-02"].status, "manual")  # the unread config may turn source maps on
        self.assertIn("apps/b/next.config.js", r["NEXT-02"].summary)
        with mock.patch.object(project, "MAX_BYTES", 200):
            r = audit_files({"apps/a/next.config.js": small, "img.png": "\0" * 400})
        self.assertEqual(r["NEXT-02"].status, "pass")  # a large binary file is not a coverage gap

    @unittest.skipUnless(shutil.which("git"), "git not installed")
    def test_ignored_untracked_files_stay_out(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".gitignore").write_text("secret.ts\n")
            (root / "secret.ts").write_text(f'const k = "{STRIPE}";\n')
            (root / "new.ts").write_text("export const n = 1;\n")
            (root / "a.ts").write_text("export const a = 1;\n")
            subprocess.run(["git", "init", "-q"], cwd=tmp, check=True)
            subprocess.run(["git", "add", "a.ts", ".gitignore"], cwd=tmp, check=True)
            proj = project.Project(root)
            self.assertEqual(proj.files, [".gitignore", "a.ts", "new.ts"])
            self.assertEqual(proj.tracked, {".gitignore", "a.ts"})


# One project per summary, with n findings, and the words the summary must use at n = 1 and n = 2.
def _verb_cases():
    def route(n):
        return {f"app/api/r{i}/route.ts": "export async function GET() { return db.select(); }\n" for i in range(n)}

    def action(n):
        return {"app/actions.ts": "'use server';\n" + "".join(
            f"export async function a{i}() {{ await db.insert(); }}\n" for i in range(n))}

    def sql(n, body):
        return {"supabase/migrations/1.sql": "".join(body(i) for i in range(n))}

    def lock(n):
        pkgs = {"node_modules/lodash": {"version": "4.17.20"}}
        if n == 2:
            pkgs["node_modules/next"] = {"version": "14.0.0"}
        return {"package.json": "{}", "package-lock.json": json.dumps({"lockfileVersion": 3, "packages": pkgs})}

    return [
        ("BROWSER-09", lambda n: {f"c{i}.jsx": "export const C = (p) => <div dangerouslySetInnerHTML={{ __html: "
                                  "p.h }} />;\n" for i in range(n)}, "place puts", "places put"),
        ("API-30", lambda n: {f"e{i}.js": "eval(code);\n" for i in range(n)}, "place runs", "places run"),
        ("API-31", lambda n: {"s.js": "import { exec } from 'child_process';\n" + "exec(`ls ${d}`);\n" * n},
         "shell command is", "shell commands are"),
        ("API-32", lambda n: {"q.js": "pool.query(`SELECT * FROM t WHERE id = ${id}`);\n" * n},
         "query is", "queries are"),
        ("API-05", lambda n: {"f.js": "import { createClient } from '@supabase/supabase-js';\n"
                              + "supabase.from('t').select().or(`name.eq.${x}`);\n" * n},
         "filter string for .or()/.filter() is", "filter strings for .or()/.filter() are"),
        ("NEXT-05", route, "route handler reads or writes", "route handlers read or write"),
        ("NEXT-06", action, "Server Action changes or reads", "Server Actions change or read"),
        ("AUTH-01", lambda n: {f"app/p{i}/page.ts": "await supabase.auth.getSession();\n" for i in range(n)},
         "server file trusts", "server files trust"),
        ("NEXT-15", lambda n: {"vercel.json": json.dumps({"crons": [{"path": f"/api/c{i}"} for i in range(n)]})},
         "cron route runs", "cron routes run"),
        ("NEXT-01", lambda n: {".env.example": "".join(f"NEXT_PUBLIC_S{i}_SECRET=\n" for i in range(n))},
         "variable with a secret-looking name", "variables with secret-looking names"),
        ("INFRA-13", lock, "package has", "packages have"),
        ("INFRA-15", lambda n: {".github/workflows/ci.yml": "permissions: {}\njobs:\n  a:\n    steps:\n"
                                + "      - run: echo ${{ github.event.issue.title }}\n" * n},
         "workflow step lets", "workflow steps let"),
        ("ACCESS-01", lambda n: sql(n, lambda i: f"create table public.t{i} (id int);\n"),
         "table in an exposed schema never enables", "tables in an exposed schema never enable"),
        ("ACCESS-02", lambda n: sql(n, lambda i: f"create table public.profiles{i} (id int, user_id uuid);\n"
                                    f"alter table public.profiles{i} enable row level security;\n"
                                    f"create policy p{i} on public.profiles{i} for update using (true);\n"),
         "policy on user-data tables allows", "policies on user-data tables allow"),
        ("ACCESS-06", lambda n: sql(n, lambda i: f"create function public.f{i}() returns void language sql "
                                    "security definer as $$ select 1 $$;\n"),
         "1 view or function in", "2 views or functions in"),
    ]


class VerbAgreementTest(unittest.TestCase):
    def test_each_summary_at_one_and_two(self):
        for cid, files, one, two in _verb_cases():
            for n, words in ((1, one), (2, two)):
                with self.subTest(check=cid, n=n):
                    r = audit_files(files(n), osv_query=fake_osv, osv=True)[cid]
                    self.assertIn(words, r.summary)
                    self.assertIn(f" {n} ", f" {r.summary.replace(SUSPECTED, '')}")


SUSPECTED = "Suspected, from a static read of the code: "


class HostileInputTest(unittest.TestCase):
    """Project files written to stall or crash the audit, and passes a static read cannot prove."""

    def quick(self, fn, limit=3.0):
        start = time.monotonic()
        out = fn()
        self.assertLess(time.monotonic() - start, limit)
        return out

    def test_gitignore_glob_does_not_backtrack(self):
        ig = project.GitIgnore()
        ig.add("", "*a*a*a*a*a*a*a*a*a*a*b\n")
        self.assertFalse(self.quick(lambda: ig.ignored("a" * 4000, False), 1.0))
        self.assertTrue(ig.ignored("xaaaaaaaaaayb", False))

    def test_gitignore_odd_bracket_is_literal_and_never_crosses_slash(self):
        ig = project.GitIgnore()
        ig.add("", "[[\nx[&&]y\nd[/]e\n")
        self.assertTrue(ig.ignored("[[", False))
        self.assertTrue(ig.ignored("x&y", False))
        self.assertFalse(ig.ignored("d/e", False))

    @unittest.skipUnless(hasattr(os, "mkfifo"), "needs named pipes")
    def test_named_pipes_are_not_read(self):
        import threading
        with tempfile.TemporaryDirectory() as tmp:
            os.mkfifo(Path(tmp) / ".gitignore")
            os.mkfifo(Path(tmp) / "app.js")
            (Path(tmp) / "page.js").write_text("export default 1;\n")
            done = []
            t = threading.Thread(target=lambda: done.append(code_audit.run(tmp, osv=False)), daemon=True)
            t.start()
            t.join(10)
            self.assertTrue(done, "the audit blocked on a named pipe")

    def test_oversized_git_index_is_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / ".git").mkdir()
            (Path(tmp) / ".git" / "index").write_bytes(b"DIRC" + b"\0" * 4096)
            (Path(tmp) / "a.js").write_text("export const a = 1;\n")
            with mock.patch.object(project, "MAX_INDEX_BYTES", 100):
                self.assertIn("a.js", project.Project(tmp).files)

    def test_line_numbers_count_newlines_only(self):
        text = "a\x0cb\r\nc\x1cd\ne"
        self.assertEqual(project.line_of(text, text.index("e")), 3)
        self.assertEqual(project.line_text(text, 2), "c\x1cd")
        self.assertEqual(project.line_text(text, 1), "a\x0cb")

    def test_long_project_text_is_clipped_in_evidence(self):
        f = project.Finding("a.js", 1, "x " * 5000, "y" * 5000)
        self.assertLess(len(f.evidence()), 800)

    def test_unclosed_parens_in_route_do_not_stall(self):
        bodies = {
            "app/api/cron/route.ts": "export async function GET(req) {\n" + "if (" * 3000 + "\n}\n",
            "app/api/a/route.ts": "export async function GET() {\n" + "const a = verifyToken(\n" * 3000
                                  + "return db.select().from(t);\n}\n",
            "app/api/b/route.ts": "export async function POST() {\n requireA" + "a" * 20000 + "\n}\n",
            "vercel.json": json.dumps({"crons": [{"path": "/api/cron", "schedule": "0 0 * * *"}]}),
        }
        self.quick(lambda: audit_files(bodies), 6.0)

    def test_many_route_handlers_do_not_stall(self):
        many_handlers = "export function GET() { db.select(); }\n" * 3000
        many_helpers = "".join(f"function h{i}() {{ }}\n" for i in range(3000)) + \
            "export function GET() { h1(); db.select(); }\n" * 100
        for code in (many_handlers, many_helpers):
            self.quick(lambda c=code: audit_files({"app/api/x/route.ts": c}), 6.0)

    def test_odd_vercel_crons_do_not_crash(self):
        for crons in (5, "x", [{"path": 5}], [{"path": None}], None):
            with self.subTest(crons=crons):
                r = audit_files({"vercel.json": json.dumps({"crons": crons}), "app/page.js": "export default 1;\n"})
                self.assertFalse([x for x in r.values() if x.status == "error"])

    def test_every_next_config_is_judged(self):
        clean = "module.exports = { poweredByHeader: false };\n"
        bad = "module.exports = { poweredByHeader: false, productionBrowserSourceMaps: true };\n"
        r = audit_files({"apps/a/next.config.js": clean, "apps/b/next.config.js": bad})
        self.assertEqual(r["NEXT-02"].status, "fail")

    def test_next_config_cap_makes_passes_manual(self):
        # Used to judge the first 50 next.config files and pass, though the rest were never read.
        clean = "module.exports = { poweredByHeader: false };\n"
        files = {f"apps/a{i:02}/next.config.js": clean for i in range(52)}
        r = audit_files(files)
        for cid in ("NEXT-02", "NEXT-03", "NEXT-07", "NEXT-11"):
            with self.subTest(check=cid):
                self.assertEqual(r[cid].status, "manual", r[cid].summary)
                self.assertIn("2 more next.config files were not read (cap 50)", r[cid].summary)
        files = {f"apps/a{i:02}/next.config.js": clean for i in range(50)}
        self.assertEqual(audit_files(files)["NEXT-03"].status, "pass")
        files["apps/z/next.config.js"] = clean
        r = audit_files(files)
        self.assertEqual(r["NEXT-03"].status, "manual")
        self.assertIn("1 more next.config file was not read", r["NEXT-03"].summary)

    def test_next_config_values_not_written_out_are_manual(self):
        cases = {
            "NEXT-02": "productionBrowserSourceMaps: process.env.MAPS === '1'",
            "NEXT-07": "experimental: { serverActions: { allowedOrigins: process.env.ORIGINS.split(',') } }",
            "NEXT-11": "images: { remotePatterns: [{ hostname: process.env.IMG_HOST }] }",
        }
        for cid, setting in cases.items():
            with self.subTest(check=cid):
                r = audit_files({"next.config.js": f"module.exports = {{ poweredByHeader: false, {setting} }};\n"})
                self.assertEqual(r[cid].status, "manual", r[cid].summary)

    def test_wildcards_on_shared_platforms_fail(self):
        cases = {
            "NEXT-07": "experimental: { serverActions: { allowedOrigins: ['my.app.com', '*.vercel.app'] } }",
            "NEXT-11": "images: { remotePatterns: [{ hostname: '**.vercel.app' }] }",
        }
        for cid, setting in cases.items():
            with self.subTest(check=cid):
                r = audit_files({"next.config.js": f"module.exports = {{ {setting} }};\n"})
                self.assertEqual(r[cid].status, "fail", r[cid].summary)
        url = "module.exports = { images: { remotePatterns: [new URL('https://**/**')] } };\n"
        self.assertEqual(audit_files({"next.config.js": url})["NEXT-11"].status, "fail")
        many = ("module.exports = { experimental: { serverActions: { allowedOrigins: ["
                + "'a'      " * 3000 + "x] } } };\n")
        self.assertEqual(self.quick(lambda: audit_files({"next.config.js": many}), 3.0)["NEXT-07"].status, "manual")
        own = "module.exports = { images: { remotePatterns: [{ hostname: '*.example.com' }] } };\n"
        self.assertEqual(audit_files({"next.config.js": own})["NEXT-11"].status, "manual")

    def test_next_config_keys_in_any_shape(self):
        # Each used to pass: the reader only knew `key: value` with an unquoted key and an inline literal.
        cases = [
            ("NEXT-02", '"productionBrowserSourceMaps": true', "fail"),
            ("NEXT-02", "productionBrowserSourceMaps", "manual"),  # shorthand: a variable
            ("NEXT-03", "poweredByHeader: false, ...(dev ? { poweredByHeader: true } : {})", "warn"),
            ("NEXT-03", "poweredByHeader: false, poweredByHeader", "manual"),
            ("NEXT-07", "experimental: { serverActions: { 'allowedOrigins': ['*'] } }", "fail"),
            ("NEXT-07", "experimental: { serverActions: { allowedOrigins } }", "manual"),
            ("NEXT-11", 'images: { remotePatterns: [{ "hostname": "**" }] }', "fail"),
            ("NEXT-11", "images: { remotePatterns: [{ hostname }] }", "manual"),
            ("NEXT-11", "images: { remotePatterns: patterns }", "manual"),
            ("NEXT-11", "images: { remotePatterns: [...extra, { hostname: 'a.example.com' }] }", "manual"),
            ("NEXT-11", 'images: { "dangerouslyAllowSVG": true }', "warn"),
        ]
        for cid, setting, want in cases:
            with self.subTest(setting=setting):
                r = audit_files({"next.config.js": f"module.exports = {{ {setting} }};\n"})
                self.assertEqual(r[cid].status, want, r[cid].summary)
        assigned = ("const c = { poweredByHeader: false, experimental: { serverActions: {} } };\n"
                    "c.productionBrowserSourceMaps = true;\nc.experimental.serverActions.allowedOrigins = ['*'];\n"
                    "module.exports = c;\n")
        r = audit_files({"next.config.js": assigned})
        self.assertEqual((r["NEXT-02"].status, r["NEXT-07"].status), ("fail", "fail"))
        ok = ("module.exports = { 'poweredByHeader': false, productionBrowserSourceMaps: false, images: { "
              "remotePatterns: [{ protocol: 'https', hostname: 'img.example.com' }, "
              "new URL('https://cdn.example.com/**')] } };\n")
        r = audit_files({"next.config.js": ok})
        for cid in ("NEXT-02", "NEXT-03", "NEXT-07", "NEXT-11"):
            self.assertEqual(r[cid].status, "pass", r[cid].summary)
        many = "module.exports = { " + "allowedOrigins: [" * 30000 + "remotePatterns: [" * 30000 + " };\n"
        r = self.quick(lambda: audit_files({"next.config.js": many}), 4.0)
        self.assertEqual((r["NEXT-07"].status, r["NEXT-11"].status), ("manual", "manual"))

    def test_wildcard_hosts_are_never_a_pass(self):
        # These used to pass: only a wildcard on a known shared platform was judged unsafe.
        def judge(host):
            origins = f"experimental: {{ serverActions: {{ allowedOrigins: ['my.app.com', '{host}'] }} }}"
            images = f"images: {{ remotePatterns: [{{ hostname: '{host}' }}, new URL('https://{host}/**')] }}"
            cfg = f"module.exports = {{ poweredByHeader: false, {origins}, {images} }};\n"
            r = audit_files({"next.config.js": cfg})
            return r["NEXT-07"], r["NEXT-11"]
        for host in ("*.com", "**.io", "*.", "foo.*.example.com", "*.*.example.com", "img-*.example.com",
                     "https://*.vercel.app", "*.com:443"):
            for r in judge(host):
                with self.subTest(host=host, check=r.check_id):
                    self.assertEqual(r.status, "fail", r.summary)
        for host in ("*.example.com", "**.co.uk", "https://*.example.com:8443"):
            for r in judge(host):
                with self.subTest(host=host, check=r.check_id):
                    self.assertEqual(r.status, "manual", r.summary)
                    self.assertIn("control every subdomain", r.summary)
        url = "module.exports = { images: { remotePatterns: [new URL('https://*.com/**')] } };\n"
        self.assertEqual(audit_files({"next.config.js": url})["NEXT-11"].status, "fail")
        for r in judge("cdn.example.com"):
            with self.subTest(host="literal", check=r.check_id):
                self.assertEqual(r.status, "pass", r.summary)

    def test_headers_on_one_path_only_are_not_a_pass(self):
        rule = "{ key: 'X-Content-Type-Options', value: 'nosniff' }"
        cfg = ("module.exports = { async headers() { return [{ source: '/api/:path*', headers: ["
               + rule + "] }]; } };\n")
        self.assertEqual(audit_files({"next.config.js": cfg})["BROWSER-03"].status, "manual")
        vercel = {"headers": [{"source": "/api/(.*)", "headers": [{"key": "X-Content-Type-Options",
                                                                    "value": "nosniff"}]}]}
        self.assertEqual(audit_files({"vercel.json": json.dumps(vercel)})["BROWSER-03"].status, "manual")
        vercel["headers"][0]["source"] = "/(.*)"
        self.assertEqual(audit_files({"vercel.json": json.dumps(vercel)})["BROWSER-03"].status, "pass")

    def test_header_route_is_the_enclosing_object(self):
        # These used to pass: the route was the nearest source: above the header, and none above meant catch-all.
        n = "{ key: 'X-Content-Type-Options', value: 'nosniff' }"
        r = "{ key: 'Referrer-Policy', value: 'no-referrer' }"

        def cfg(routes, head=""):
            return audit_files({"next.config.js": head + "module.exports = { async headers() { return ["
                                + routes + "]; } };\n"})["BROWSER-03"].status
        self.assertEqual(cfg(f"{{ headers: [{n}], source: '/api/:path*' }}"), "manual")
        self.assertEqual(cfg(f"{{ source: '/(.*)', headers: [{r}] }}, {{ headers: [{n}], source: '/api/:path*' }}"),
                         "manual")
        self.assertEqual(cfg(f"{{ headers: [{n}] }}"), "manual")  # no source: the path is unknown
        for cond in ("has: [{ type: 'host', value: 'a.example' }]", "missing: [{ type: 'header', key: 'x' }]"):
            self.assertEqual(cfg(f"{{ source: '/(.*)', {cond}, headers: [{n}] }}"), "manual")
            self.assertEqual(cfg(f"{{ source: '/(.*)', {cond}, headers: [{n}] }}, {{ source: '/a', headers: [{n}] }}"),
                             "manual")
        self.assertEqual(cfg(f"{{ source: '/(.*)', headers: [{n}] }}, {{ source: '/a', headers: [{r}] }}"), "pass")
        self.assertEqual(cfg(f"{{ source: `${{base}}/(.*)`, headers: [{n}] }}"), "manual")
        self.assertEqual(cfg("{ source: '/(.*)', headers: [" + n + "] }, { source: '/[}', headers: [] }"), "pass")
        self.assertEqual(cfg("{ source: '/(.*)', headers: [" + n + "] }]}; const re = /[/; ({"), "manual")
        # Keys in any order, and a const list on the one route that uses it, still pass.
        self.assertEqual(cfg(f"{{ headers: [{n}], source: '/(.*)' }}"), "pass")
        self.assertEqual(cfg("{ headers: sec, source: '/:path*' }", f"const sec = [{n}];\n"), "pass")
        self.assertEqual(cfg("{ source: '/api/:path*', headers: sec }", f"const sec = [{n}];\n"), "manual")
        self.assertEqual(cfg("{ source: '/(.*)', headers: [] }", f"const sec = [{n}];\n"), "manual")
        vercel = {"headers": [{"headers": [{"key": "X-Content-Type-Options", "value": "nosniff"}], "source": "/(.*)"}]}
        self.assertEqual(audit_files({"vercel.json": json.dumps(vercel)})["BROWSER-03"].status, "pass")
        for cond in ("has", "missing"):
            vercel["headers"][0][cond] = [{"type": "header", "key": "x"}]
            self.assertEqual(audit_files({"vercel.json": json.dumps(vercel)})["BROWSER-03"].status, "manual")
            del vercel["headers"][0][cond]
        loose = {"routes": [{"src": "/(.*)", "key": "X-Content-Type-Options", "value": "nosniff"}]}
        self.assertEqual(audit_files({"vercel.json": json.dumps(loose)})["BROWSER-03"].status, "manual")

    def test_crlf_files_read_like_lf_files(self):
        # A project saved on Windows (or checked out with autocrlf) used to fail netlify.toml and misread _headers.
        pp, coop = "Permissions-Policy: camera=()", "Cross-Origin-Opener-Policy: same-origin"
        toml = '[[headers]]\n  for = "/*"\n  [headers.values]\n    X-Content-Type-Options = "nosniff"\n'
        cases = {"netlify.toml": (toml, "BROWSER-03"),
                 "_headers": (f"/a\n  {pp}\n/b\n  {coop}\n", "BROWSER-08")}
        for rel, (text, cid) in cases.items():
            got = []
            for nl in ("\n", "\r\n"):
                with tempfile.TemporaryDirectory() as tmp:
                    (Path(tmp) / rel).write_bytes(text.replace("\n", nl).encode())
                    got.append(by_id(code_audit.run(tmp, osv=False)[1])[cid].status)
            self.assertEqual(got[0], got[1], rel)

    def test_text_header_files_need_their_block(self):
        def status(rel, text):
            return audit_files({rel: text})["BROWSER-03"].status
        ok = '[[headers]]\n  for = "/*"\n  [headers.values]\n    X-Content-Type-Options = "nosniff"\n'
        self.assertEqual(status("netlify.toml", ok), "pass")
        # These used to pass: a header line outside any [[headers]] values table, or a conditional block.
        self.assertEqual(status("netlify.toml", 'X-Content-Type-Options = "nosniff"\n'), "manual")
        self.assertEqual(status("netlify.toml", ok.replace("  [headers.values]", "  [headers.conditions]\n"
                                                           "    Language = [\"en\"]\n  [headers.values]")), "manual")
        self.assertEqual(status("netlify.toml", ok + '[build.environment]\n  X-Frame-Options = "x"\n'), "pass")
        self.assertEqual(status("netlify.toml", ok.replace("[headers.values]", "[build.environment]")), "manual")
        self.assertEqual(status("public/_headers", "/*\n  X-Content-Type-Options: nosniff\n"), "pass")
        self.assertEqual(status("public/_headers", "X-Content-Type-Options: nosniff\n"), "manual")
        self.assertEqual(status("public/_headers", "# all\nX-Content-Type-Options: nosniff\n/*\n"), "manual")
        self.assertEqual(status("public/_headers", "/*\n  X-Content-Type-Options: nosniff\n/admin/*\n"
                                                   "  ! X-Content-Type-Options\n"), "manual")

    def test_header_route_reader_is_linear(self):
        from agent_security_audit.code_audit import nextjs
        n = "{ key: 'X-Content-Type-Options', value: 'nosniff' }"
        for code in ("{" * 200000, "[" * 200000 + n * 2000, "{ source: '/(.*)', headers: [" * 20000 + n * 1000,
                     ("const a = [" + n + "];\n") * 20000, "{ headers: a, source: '/' }," * 30000,
                     "(" * 100000 + n * 1000 + ")" * 100000):
            self.quick(lambda code=code: nextjs._headers_in("next.config.js", code), 3.0)
        for text in ("[[headers]]\n" * 100000, "[headers.values]\nX-Frame-Options = 'DENY'\n" * 50000,
                     "/*\n" + "  X-Frame-Options: DENY\n" * 100000):
            self.quick(lambda text=text: nextjs._headers_in("netlify.toml", text), 3.0)
            self.quick(lambda text=text: nextjs._headers_in("_headers", text), 3.0)

    def test_hostile_sql_does_not_stall(self):
        text = ("create function public.f() returns int language sql as $$ select 1 $$;\n"
                "grant execute on function public.f to " + "to " * 20000 + "(;\n"
                "create table public.t (user_id uuid);\n"
                "create policy p on public.t " + "to " * 20000 + "(;\n")
        self.quick(lambda: audit_files({"supabase/migrations/1.sql": text}), 4.0)
        deep = "(" * 1900 + "true" + ")" * 1900
        self.assertEqual(self.quick(lambda: sql.classify(deep), 1.0), "open")
        self.assertEqual(sql.classify("(" * 3000 + "true" + ")" * 3000), "unknown")

    def test_grant_and_policy_roles_still_read(self):
        text = ("create function public.f() returns int language sql security definer as $$ select 1 $$;\n"
                "revoke execute on function public.f() from public, anon;\n")
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "supabase" / "migrations").mkdir(parents=True)
            (Path(tmp) / "supabase" / "migrations" / "1.sql").write_text(
                text + "create table public.t (user_id uuid);\n"
                "create policy p on public.t for select to authenticated using (auth.uid() = user_id);\n")
            _, _, policies, _, functions = sql.parse(project.Project(tmp))
        self.assertEqual(functions["public.f"]["revoked"], {"public", "anon"})
        self.assertEqual(policies[0]["roles"], "authenticated")

    def test_odd_supabase_config_does_not_crash(self):
        for config in ('api = "x"\n', '[api]\nschemas = "api"\n', "[api]\nschemas = [1, 2]\n"):
            with self.subTest(config=config):
                r = audit_files({"supabase/config.toml": config,
                                 "supabase/migrations/1.sql": "create table public.t (id int);\n"})
                self.assertEqual(r["ACCESS-01"].status, "fail", r["ACCESS-01"].summary)

    def test_workflow_blank_lines_do_not_stall(self):
        wf = "on: push\npermissions: {}\njobs:\n  a:\n    steps:\n" + "\n" * 100000 + "      - run: |\n" * 3000
        self.quick(lambda: audit_files({".github/workflows/ci.yml": wf}), 4.0)
        self.quick(lambda: audit_files({".github/workflows/ci.yml": "on: push\n" + " " * 200000 + "x\n"}), 4.0)

    def test_hostile_js_and_toml_do_not_stall(self):
        files = {"netlify.toml": "\n" * 60000 + "[[headers]]\n" * 2000,
                 "app/api/a/route.ts": "import { a " * 20000 + "\nexport async function POST(req) {\n  " + "a" * 60000
                                       + "\n  return db.from('t').insert(await req.json());\n}\n"}
        self.quick(lambda: audit_files(files), 6.0)

    def test_github_script_injection_fails(self):
        wf = ("on: issues\npermissions: {}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n"
              "      - uses: actions/github-script@v7\n        with:\n          script: |\n"
              "            console.log('${{ github.event.issue.title }}')\n")
        self.assertEqual(audit_files({".github/workflows/ci.yml": wf})["INFRA-15"].status, "fail")

    def test_template_raw_html_is_a_sink(self):
        for rel, src in (("a.vue", '<template><div v-html="post.body"></div></template>\n'),
                         ("b.svelte", "<div>{@html post.body}</div>\n"),
                         ("c.astro", "<div set:html={post.body} />\n")):
            with self.subTest(file=rel):
                self.assertEqual(audit_files({rel: src})["BROWSER-09"].status, "warn")
        # A literal is no finding: the read is clean, which is manual for a pattern search.
        self.assertEqual(audit_files({"d.vue": "<div v-html=\"'<b>hi</b>'\"></div>\n"})["BROWSER-09"].status,
                         "manual")

    def test_template_raw_html_sink_shapes(self):
        # These used to read clean: a quoted value over two lines, an unquoted value and a bound innerHTML.
        for src in ('<div v-html="\n  post.body"></div>\n', "<div v-html='post.body\n'></div>\n",
                    "<div v-html=post.body></div>\n", '<div :innerHTML="post.body"></div>\n',
                    '<div v-bind:innerHTML="post.body"></div>\n', '<div :inner-html.prop="post.body"></div>\n',
                    '<div v-html="post.body></div>\n'):
            with self.subTest(src=src):
                self.assertEqual(audit_files({"a.vue": src})["BROWSER-09"].status, "warn")
        self.assertEqual(audit_files({"b.vue": "<div :innerHTML=\"'<b>hi</b>'\"></div>\n"})["BROWSER-09"].status,
                         "manual")
        self.assertEqual(audit_files({"c.vue": '<div :title="post.body"></div>\n'})["BROWSER-09"].status, "manual")

    def test_template_raw_html_scan_is_linear(self):
        from agent_security_audit.code_audit import patterns
        for code in ('v-html="' * 100000, "v-html='" * 100000, ":innerHTML=" * 100000, 'v-html="' + "a" * 500000,
                     "v-html" + " " * 500000, ':innerHTML="' + "'" * 500000):
            start = time.monotonic()
            list(patterns.TEMPLATE_HTML.finditer(code))
            self.assertLess(time.monotonic() - start, 1.0)

    def test_next_versions_unproven_when_a_lockfile_is_not_read(self):
        lock = json.dumps({"lockfileVersion": 3, "packages": {"node_modules/next": {"version": "15.5.9"}}})
        files = {"package.json": '{"dependencies": {"next": "15.5.9"}}', "package-lock.json": lock,
                 "apps/old/package.json": '{"dependencies": {"next": "13.0.0"}}', "apps/old/bun.lockb": "\0"}
        r = audit_files(files, osv=True, osv_query=lambda pkgs, timeout: {})
        self.assertEqual(r["NEXT-04"].status, "manual", r["NEXT-04"].summary)

    def test_only_static_proof_checks_pass(self):
        self.assertLessEqual(code_audit.STATIC_PROOF, set(code_audit.CHECKS))
        self.assertEqual(code_audit.NO_STATIC_PASS, set(code_audit.CHECKS) - code_audit.STATIC_PROOF)
        with tempfile.TemporaryDirectory() as tmp:
            for name in ("code_vuln", "code_fixed"):
                for r in code_audit.run(copy_fixture(name, tmp), osv_query=fake_osv)[1]:
                    if r.check_id not in code_audit.STATIC_PROOF:
                        self.assertNotEqual(r.status, "pass", r.check_id)
        fake = Result("NEXT-01", "pass", "no keys found")
        self.assertEqual(code_audit.merge([], [fake])[0].status, "manual")
        self.assertEqual(code_audit.merge([Result("NEXT-01", "skip", "x")], [fake])[0].status, "manual")
