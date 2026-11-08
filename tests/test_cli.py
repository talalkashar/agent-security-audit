"""The command line, called in-process through cli.main([...])."""

import contextlib
import io
import json
import os
import tempfile
import unittest
from unittest import mock

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
        self.assertEqual(len(out.strip().splitlines()), 126)
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
        self.assertEqual(all_rules.count("\n- **"), 126)


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
        self.assertEqual(len(data["results"]), 43)
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
        with mock.patch("time.sleep", side_effect=AssertionError("lab accepted an occupied port")):
            code, _, err = call("lab", "--port", str(port))
        self.assertEqual(code, 2)
        self.assertIn("pass another --port", err)

    def test_non_local_without_authorized_runs_passive_only(self):
        hostport = self.servers["vulnerable"][1]
        with mock.patch("agent_security_audit.runner.owned", return_value=False):
            code, out, _ = call("scan", hostport, "--auto-only", "--format", "json")
        by_id = {r["check_id"]: r for r in json.loads(out)["results"]}
        self.assertEqual(by_id["INFRA-04"]["status"], "skip")
        self.assertIn("--authorized", by_id["INFRA-04"]["summary"])
        self.assertEqual(by_id["NEXT-03"]["status"], "fail")
        self.assertEqual(code, 1)

    def test_bad_scheme_and_unknown_check_exit_2(self):
        self.assertEqual(call("scan", "ftp://localhost")[0], 2)
        self.assertEqual(self.scan("fixed", "--check", "NOPE-01")[0], 2)
        self.assertEqual(call("scan", "https://example.com", "--authorized", "--insecure")[0], 2)



class StackAndHintTest(unittest.TestCase):
    def test_unknown_stack_lists_valid_values(self):
        for argv in (("rules", "--stack", "django"), ("list", "--stack", "nextjs,rails")):
            code, out, err = call(*argv)
            self.assertEqual(code, 2, argv)
            self.assertEqual(out, "")
            self.assertIn("valid values: any, nextjs, supabase, vercel, node", err)

    def test_valid_stack_still_works(self):
        code, out, _ = call("rules", "--stack", "nextjs,supabase")
        self.assertEqual(code, 0)
        self.assertIn("NEXT-01", out)

    def test_negative_max_time_exits_2(self):
        code, _, err = call("scan", "http://localhost:9", "--max-time", "-1")
        self.assertEqual(code, 2)
        self.assertIn("--max-time", err)

    def test_code_hint_for_local_project_folder(self):
        server, url = lab.serve("fixed", 0)
        cwd = os.getcwd()
        try:
            # Restore cwd before TemporaryDirectory cleanup (required by Windows).
            with tempfile.TemporaryDirectory() as tmp, contextlib.chdir(tmp):
                with open(os.path.join(tmp, "package.json"), "w") as fh:
                    fh.write("{}")
                _, _, err = call("scan", url, "--auto-only", "--check", "BROWSER-03", "--format", "json")
                self.assertIn("add --code .", err)
                _, _, err = call("scan", url, "--auto-only", "--check", "BROWSER-03", "--format", "json",
                                 "--code", tmp, "--no-osv")
                self.assertNotIn("add --code .", err)
                os.remove("package.json")
                _, _, err = call("scan", url, "--auto-only", "--check", "BROWSER-03", "--format", "json")
                self.assertNotIn("add --code .", err)
        finally:
            os.chdir(cwd)
            server.shutdown()
            server.server_close()

    def test_no_code_hint_for_remote_target(self):
        args = cli.build_parser().parse_args(["scan", "https://example.com"])
        with mock.patch("os.path.isfile", return_value=True):
            self.assertIsNone(cli._code_hint(args))
            local = cli.build_parser().parse_args(["scan", "localhost:3000"])
            self.assertIn("--code .", cli._code_hint(local))


if __name__ == "__main__":
    unittest.main()
