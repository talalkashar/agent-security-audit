"""The command line, called in-process through cli.main([...])."""

import contextlib
import io
import json
import os
import tempfile
import unittest

from agent_security_audit import cli, lab


def call(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(list(argv))
    return code, out.getvalue(), err.getvalue()


class CatalogCommandsTest(unittest.TestCase):
    def test_list(self):
        code, out, _ = call("list")
        self.assertEqual(code, 0)
        self.assertEqual(len(out.strip().splitlines()), 112)
        self.assertTrue(out.startswith("ACCESS-01"))

    def test_list_json_filters(self):
        code, out, _ = call("list", "--area", "browser", "--json")
        data = json.loads(out)
        self.assertEqual(code, 0)
        self.assertTrue(data and all(c["area"] == "browser" for c in data))

    def test_show(self):
        code, out, _ = call("show", "next-01")
        self.assertEqual(code, 0)
        self.assertTrue(out.startswith("# NEXT-01 "))
        for heading in ("## Risk", "## Build rule", "## Proof test", "## Sources"):
            self.assertIn(heading, out)
        code, out, _ = call("show", "NEXT-01", "--json")
        self.assertEqual(json.loads(out)["id"], "NEXT-01")

    def test_show_unknown(self):
        code, _, err = call("show", "NOPE-01")
        self.assertEqual(code, 2)
        self.assertIn("NOPE-01", err)

    def test_rules_stack(self):
        code, out, _ = call("rules", "--stack", "supabase")
        self.assertEqual(code, 0)
        self.assertTrue(out.startswith("# Build rules"))
        self.assertIn("ACCESS-01", out)
        _, all_rules, _ = call("rules")
        self.assertLess(out.count("\n- **"), all_rules.count("\n- **"))
        self.assertEqual(all_rules.count("\n- **"), 112)


class ScanCommandTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.servers = {}
        for mode in lab.MODES:
            cls.servers[mode] = lab.serve(mode, 0)

    @classmethod
    def tearDownClass(cls):
        for server, _ in cls.servers.values():
            server.shutdown()
            server.server_close()

    def scan(self, mode, *extra):
        return call("scan", self.servers[mode][1], "--auto-only", *extra)

    def test_json(self):
        code, out, _ = self.scan("vulnerable", "--format", "json", "--fail-on", "none")
        data = json.loads(out)
        self.assertEqual(code, 0)
        self.assertEqual(data["tool"], "agent-security-audit")
        self.assertGreater(data["counts"]["fail"], 5)
        self.assertEqual(len(data["results"]), 31)
        self.assertEqual(data["results"][0]["status"], "fail")

    def test_sarif(self):
        code, out, _ = self.scan("vulnerable", "--format", "sarif", "--check", "NEXT-03,INFRA-05")
        data = json.loads(out)
        self.assertEqual(data["version"], "2.1.0")
        run = data["runs"][0]
        self.assertEqual({r["ruleId"] for r in run["results"]}, {"NEXT-03", "INFRA-05"})
        self.assertEqual({r["id"] for r in run["tool"]["driver"]["rules"]}, {"NEXT-03", "INFRA-05"})
        self.assertEqual(code, 0)  # both are low severity, below the default --fail-on high

    def test_markdown(self):
        code, out, _ = self.scan("fixed", "--format", "md")
        self.assertEqual(code, 0)
        self.assertTrue(out.startswith("# Security proof report: http://127.0.0.1:"))
        self.assertIn("| pass |", out)
        self.assertIn("not a guarantee", out)

    def test_fail_on(self):
        self.assertEqual(self.scan("vulnerable", "--format", "json")[0], 1)
        self.assertEqual(self.scan("vulnerable", "--format", "json", "--fail-on", "critical")[0], 1)
        self.assertEqual(self.scan("vulnerable", "--format", "json", "--fail-on", "none")[0], 0)
        self.assertEqual(self.scan("vulnerable", "--check", "NEXT-03", "--fail-on", "medium")[0], 0)
        self.assertEqual(self.scan("vulnerable", "--check", "NEXT-03", "--fail-on", "low")[0], 1)
        self.assertEqual(self.scan("fixed", "--format", "json", "--fail-on", "low")[0], 0)

    def test_out_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "report.json")
            code, out, err = self.scan("fixed", "--format", "json", "--out", path)
            self.assertEqual((code, out), (0, ""))
            self.assertIn("wrote", err)
            with open(path, encoding="utf-8") as fh:
                self.assertEqual(json.load(fh)["counts"]["fail"], 0)

    def test_out_file_creates_parent_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, ".asa", "report.json")
            code, _, err = self.scan("fixed", "--format", "json", "--check", "NEXT-03", "--out", path)
            self.assertEqual(code, 0, err)
            self.assertTrue(os.path.exists(path))

    def test_out_file_unwritable_exits_2(self):
        with tempfile.NamedTemporaryFile() as f:  # a file where a directory is needed
            code, _, err = self.scan("fixed", "--check", "NEXT-03", "--out", os.path.join(f.name, "r.json"))
        self.assertEqual(code, 2)
        self.assertTrue(err.startswith("asa: could not write"), err)

    def test_scheme_less_local_target_uses_http(self):
        hostport = self.servers["fixed"][1].removeprefix("http://")
        code, out, err = call("scan", hostport, "--auto-only", "--check", "NEXT-03")
        self.assertEqual(code, 0, err)
        self.assertIn("http://127.0.0.1:", out)

    def test_lab_port_in_use_exits_2(self):
        port = int(self.servers["fixed"][1].rsplit(":", 1)[1])
        code, _, err = call("lab", "--port", str(port))
        self.assertEqual(code, 2)
        self.assertIn("pass another --port", err)

    def test_unauthorized_non_local_exits_2(self):
        code, out, err = call("scan", "https://example.com")
        self.assertEqual((code, out), (2, ""))
        self.assertIn("--authorized", err)

    def test_bad_scheme_and_unknown_check_exit_2(self):
        self.assertEqual(call("scan", "ftp://localhost")[0], 2)
        self.assertEqual(self.scan("fixed", "--check", "NOPE-01")[0], 2)
        self.assertEqual(call("scan", "https://example.com", "--authorized", "--insecure")[0], 2)


if __name__ == "__main__":
    unittest.main()
