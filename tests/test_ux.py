"""The scan experience: `asa <url>`, the ownership prompt, progress, the terminal summary and the HTML report."""

import contextlib
import io
import re
import unittest
from unittest import mock

from agent_security_audit import catalog, cli, lab, report
from agent_security_audit.model import Result, failed, passed

HOSTILE = "<img src=x onerror=alert(1)><script>alert(2)</script>\"' & ](https://evil.example)\r\n## Injected"


class Tty(io.StringIO):
    def isatty(self):
        return True


def call(*argv, stdin_tty=False, stderr_tty=False, stdout_tty=False, answer=None):
    out = Tty() if stdout_tty else io.StringIO()
    err = Tty() if stderr_tty else io.StringIO()
    stdin = Tty() if stdin_tty else io.StringIO()
    with contextlib.ExitStack() as stack:
        stack.enter_context(contextlib.redirect_stdout(out))
        stack.enter_context(contextlib.redirect_stderr(err))
        stack.enter_context(mock.patch("sys.stdin", stdin))
        ask = stack.enter_context(mock.patch("builtins.input", return_value=answer or ""))
        code = cli.main(list(argv))
    return code, out.getvalue(), err.getvalue(), ask


def by_severity():
    """One check id per severity, from the catalog."""
    out = {}
    for c in catalog.load():
        out.setdefault(c.severity, c.id)
    return out


class LabTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, cls.url = lab.serve("vulnerable", 0)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_bare_url_is_scan(self):
        code, out, err, _ = call(self.url, "--auto-only", "--check", "NEXT-03", "--fail-on", "none")
        self.assertEqual(code, 0, err)
        self.assertTrue(out.startswith("# Security proof report: http://127.0.0.1:"))

    def test_subcommands_still_dispatch(self):
        code, out, _, _ = call("show", "NEXT-03")
        self.assertEqual(code, 0)
        self.assertTrue(out.startswith("# NEXT-03 "))

    def test_progress_only_on_a_terminal(self):
        args = (self.url, "--auto-only", "--check", "NEXT-03,BROWSER-03", "--format", "json")
        _, out, err, _ = call(*args, stderr_tty=True)
        self.assertIn("[2/2]", err)
        self.assertTrue(out.startswith("{"))
        self.assertNotIn("[1/2]", call(*args)[2])
        self.assertNotIn("[1/2]", call(*args, "--quiet", stderr_tty=True)[2])

    def test_terminal_gets_summary(self):
        _, out, _, _ = call(self.url, "--auto-only", "--check", "NEXT-03,BROWSER-03", stdout_tty=True)
        self.assertIn("Fix these first:", out)
        self.assertIn("Full report with evidence: asa scan http://127.0.0.1:", out)
        self.assertNotIn("| Status |", out)
        _, out, _, _ = call(self.url, "--auto-only", "--check", "NEXT-03", "--format", "md", stdout_tty=True)
        self.assertTrue(out.startswith("# Security proof report"))

    def test_out_extension_picks_format(self):
        import os
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "r.html")
            code, _, err, _ = call(self.url, "--auto-only", "--check", "NEXT-03", "--out", path, "--fail-on", "none")
            self.assertEqual(code, 0, err)
            with open(path, encoding="utf-8") as fh:
                self.assertTrue(fh.read().startswith("<!doctype html>"))


class NoPromptTest(unittest.TestCase):
    def scan(self, answer, **tty):
        with mock.patch.object(cli.runner, "run", return_value=("https://example.com", [])) as run:
            code, _, err, ask = call("https://example.com", "--format", "json", answer=answer, **tty)
        return code, err, ask, run

    def test_any_url_scans_without_asking(self):
        for tty in ({}, {"stdin_tty": True, "stderr_tty": True}):
            code, err, ask, run = self.scan("n", **tty)
            self.assertEqual(code, 0, err)
            ask.assert_not_called()
            self.assertFalse(run.call_args.kwargs["authorized"])

    def test_authorized_flag_skips_prompt(self):
        with mock.patch.object(cli.runner, "run", return_value=("https://example.com", [])):
            code, _, _, ask = call("https://example.com", "--authorized", "--format", "json",
                                   stdin_tty=True, stderr_tty=True)
        self.assertEqual(code, 0)
        ask.assert_not_called()

    def test_local_target_never_asks(self):
        with mock.patch.object(cli.runner, "run", return_value=("http://localhost:3000", [])) as run:
            code, _, _, ask = call("localhost:3000", "--format", "json", stdin_tty=True, stderr_tty=True)
        self.assertEqual(code, 0)
        ask.assert_not_called()
        self.assertFalse(run.call_args.kwargs["authorized"])


class FixFirstAndLayersTest(unittest.TestCase):
    def setUp(self):
        sev = by_severity()
        self.results = [failed(sev["low"], "low one"), passed(sev["high"], "ok"),
                        failed(sev["critical"], "critical one"), Result(sev["medium"], "manual", "look")]
        self.sev = sev

    def test_fix_first_most_severe_first_with_fix(self):
        first = report.fix_first(self.results)
        self.assertEqual([r.check_id for r, _, _ in first], [self.sev["critical"], self.sev["low"]])
        checks = catalog.by_id()
        self.assertEqual(first[0][2], checks[self.sev["critical"]].build)  # no fix on the result: the build rule

    def test_fix_first_capped_at_ten(self):
        many = [failed(c.id, "x") for c in catalog.load()[:15]]
        self.assertEqual(len(report.fix_first(many)), 10)
        md = report.to_markdown("http://127.0.0.1", many)
        section = md.split("## Fix these first", 1)[1].split("## Coverage", 1)[0]
        self.assertEqual(len(re.findall(r"^\d+\. ", section, re.MULTILINE)), 10)

    def test_layer_coverage(self):
        cov = report.layer_coverage(self.results)
        self.assertEqual(sorted(cov), [1, 2, 3, 4, 5, 6, 7])
        checks = catalog.by_id()
        layer = checks[self.sev["critical"]].layer
        self.assertGreaterEqual(cov[layer]["fail"], 1)
        self.assertEqual(sum(row["fail"] for row in cov.values()), 2)
        self.assertEqual(sum(row["manual"] for row in cov.values()), 1)

    def test_markdown_sections_in_order(self):
        md = report.to_markdown("http://127.0.0.1", self.results)
        order = [md.index(h) for h in ("## Fix these first", "## Coverage by OSI layer", "## All results",
                                       "## Details", "not a guarantee")]
        self.assertEqual(order, sorted(order))
        for n, name in report.LAYERS.items():
            self.assertIn(f"| {n} {name} |", md)

    def test_json_adds_fields_only(self):
        import json
        data = json.loads(report.to_json("http://127.0.0.1", self.results))
        for key in ("tool", "version", "target", "generated", "counts", "results"):
            self.assertIn(key, data)
        self.assertEqual(data["fix_first"][0]["check_id"], self.sev["critical"])
        self.assertEqual(set(data["osi_layers"]), {str(n) for n in range(1, 8)})

    def test_markdown_fix_first_is_inert(self):
        md = report.to_markdown("http://127.0.0.1", [failed("NEXT-03", HOSTILE, [HOSTILE], fix=HOSTILE)])
        section = md.split("## Fix these first", 1)[1].split("## Coverage", 1)[0]
        self.assertNotIn("\n## Injected", section)
        self.assertIsNone(re.search(r"(?<!\\)<img", section))
        self.assertIsNone(re.search(r"(?<!\\)\]\(", section))

    def test_summary_strips_terminal_escapes(self):
        text = report.summary_text("http://127.0.0.1", [failed("NEXT-03", "a\x1b[2Jb\x9b31mc", fix="f\x07")])
        self.assertIsNone(re.search(r"[\x00-\x09\x0b-\x1f\x7f-\x9f]", text))


class HtmlReportTest(unittest.TestCase):
    def test_target_text_is_escaped(self):
        page = report.to_html("http://127.0.0.1\"><script>x</script>", [
            failed("NEXT-03", HOSTILE, [HOSTILE, "</pre><b>" + HOSTILE], fix=HOSTILE),
            Result("BROWSER-03", "warn", HOSTILE, [HOSTILE]),
        ])
        self.assertNotIn("<img", page)
        self.assertNotIn("<script", page)
        self.assertNotIn("</pre><b>", page)
        self.assertNotIn("\"><", page.split("<style>", 1)[0].split("<title>", 1)[1])
        self.assertIn("&lt;img src=x onerror=alert(1)&gt;", page)
        self.assertIn("&quot;", page)
        self.assertNotIn("\r", page)

    def test_self_contained(self):
        page = report.to_html("http://127.0.0.1", [failed("NEXT-03", "see https://evil.example/x.png")])
        self.assertTrue(page.startswith("<!doctype html>"))
        self.assertIn("default-src 'none'", page)
        self.assertIsNone(re.search(r"<(script|link|img|iframe)\b", page))
        self.assertIsNone(re.search(r"(src|href)\s*=", page))
        self.assertIn("prefers-color-scheme:dark", page)
        self.assertIn("@media print", page)

    def test_sections(self):
        sev = by_severity()
        page = report.to_html("http://127.0.0.1", [failed(sev["low"], "low"), failed(sev["critical"], "crit"),
                                                   passed("BROWSER-03", "ok")])
        order = [page.index(h) for h in ("Fix these first", "Coverage by OSI layer", "All results", "Details",
                                         "not a guarantee")]
        self.assertEqual(order, sorted(order))
        first = page.split("Fix these first", 1)[1].split("Coverage by OSI layer", 1)[0]
        self.assertLess(first.index(sev["critical"]), first.index(sev["low"]))
        for n, name in report.LAYERS.items():
            self.assertIn(f"<td>{n} {name}</td>", page)


if __name__ == "__main__":
    unittest.main()
