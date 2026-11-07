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
        for cid in ("INFRA-08", "NEXT-01", "ACCESS-01", "ACCESS-02", "ACCESS-06", "NEXT-05", "NEXT-06", "AUTH-01",
                    "NEXT-15", "NEXT-02", "NEXT-03", "NEXT-07", "NEXT-11", "BROWSER-01", "BROWSER-02", "BROWSER-03",
                    "BROWSER-04", "BROWSER-05", "BROWSER-08", "BROWSER-09", "API-30", "API-31", "API-32", "API-05",
                    "INFRA-13", "NEXT-04", "INFRA-15"):
            with self.subTest(check=cid):
                self.assertEqual(results[cid].status, "pass", results[cid].summary)
        # Server-side secret-key use is listed for review, not passed.
        self.assertEqual(results["ACCESS-08"].status, "manual")

    def test_evidence_points_at_lines(self):
        results = by_id(self.vuln_results)
        self.assertIn("middleware.ts:5:", results["AUTH-01"].evidence[0])
        self.assertIn("supabase/migrations/0001_init.sql:2:", results["ACCESS-01"].evidence[0])
        self.assertEqual(results["NEXT-02"].locations[0], {"path": "next.config.js", "line": 2,
                                                           "message": "source maps on in production"})
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
            self.assertEqual(results[0].status, "pass")
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

    def test_code_fills_manual_and_adds_new(self):
        live = [Result("AUTH-01", "manual", "Not visible from outside", ["proof steps"])]
        code = [Result("AUTH-01", "pass", "verified", ["middleware.ts:3: getClaims"]),
                Result("API-30", "pass", "no eval")]
        merged = by_id(code_audit.merge(live, code))
        self.assertEqual(merged["AUTH-01"].status, "pass")
        self.assertEqual(merged["AUTH-01"].evidence, ["code: middleware.ts:3: getClaims"])
        self.assertEqual(merged["API-30"].status, "pass")

    def test_live_error_replaced_by_code(self):
        merged = code_audit.merge([Result("NEXT-02", "error", "timeout")], [Result("NEXT-02", "pass", "off")])
        self.assertEqual(merged[0].status, "pass")


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
                self.assertEqual(proj.files, [".env.production", "a/deep/x.ts", "a/deep/y.ts"])
        _, results = code_audit.run(root, osv=False, ids=["INFRA-08"])
        self.assertEqual(results[0].status, "fail")
        self.assertIn("tracked in git", results[0].evidence[0])
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
            data = json.loads(res["content"][0]["text"])
            self.assertEqual([r["check_id"] for r in data["results"]], ["AUTH-01"])
            self.assertEqual(data["results"][0]["status"], "fail")
            res = mcp_server.call_tool({"name": "run_code_audit", "arguments": {"path": str(Path(tmp) / "nope")}})
            self.assertTrue(res["isError"])


if __name__ == "__main__":
    unittest.main()
