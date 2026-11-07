"""Markdown reports must not let a scanned site's own text become Markdown structure."""

import re
import unittest

from agent_security_audit import report
from agent_security_audit.checks import Context, exposure
from agent_security_audit.http import Response
from agent_security_audit.model import failed

HOSTILE = "Next`](https://evil.example) <img src=x onerror=alert(1)>\r\n ## Injected heading\r\n - fake: pass"


class Stub:
    def __init__(self, response):
        self.response = response

    def home(self):
        return self.response


class MarkdownInjectionTest(unittest.TestCase):
    def assert_inert(self, md):
        body = md.split("## Details", 1)[1]
        for line in body.splitlines():
            self.assertFalse(line.lstrip().startswith("## Injected"), line)
            self.assertFalse(line.lstrip().startswith("- fake"), line)
        # Text inside a code span is literal; outside one, every Markdown character must be escaped.
        prose = re.sub(r"(`+)(?!`).*?(?<!`)\1(?!`)", "", body)
        self.assertIsNone(re.search(r"(?<!\\)\]\(", prose), prose)
        self.assertIsNone(re.search(r"(?<!\\)<img", prose), prose)
        self.assertIsNone(re.search(r"(?<!\\)`", prose.split("Fix:")[0]), prose)

    def test_obs_fold_header_through_a_check(self):
        resp = Response("http://127.0.0.1/", 200, "OK", [("X-Powered-By", HOSTILE)], b"")
        result = exposure.powered_by(Context("http://127.0.0.1", Stub(resp), {}))
        self.assertEqual(result.status, "fail")
        self.assert_inert(report.to_markdown("http://127.0.0.1", [result]))

    def test_raw_values_in_summary_and_evidence(self):
        result = failed("NEXT-03", "X-Powered-By: " + HOSTILE, ["x-powered-by: " + HOSTILE, "``" + HOSTILE])
        md = report.to_markdown("http://127.0.0.1", [result])
        self.assert_inert(md)
        self.assertIn("- ```", md)  # the evidence fence is longer than the value's own backtick run

    def test_long_values_are_capped(self):
        result = failed("NEXT-03", "x" * 5000, ["y" * 5000])
        md = report.to_markdown("http://127.0.0.1", [result])
        self.assertLess(max(len(line) for line in md.splitlines()), 1100)


class CodeSpanTest(unittest.TestCase):
    """Backtick pairs in summaries and fixes render as code; everything else stays escaped."""

    def result(self, summary, fix="Set `Cache-Control: no-store` on the route."):
        return failed("NEXT-03", summary, ["evidence"], fix)

    def test_html_renders_code_and_keeps_escaping(self):
        page = report.to_html("http://127.0.0.1", [self.result("Served by `" + HOSTILE + "` today")])
        self.assertIn("<code>Cache-Control: no-store</code>", page)
        self.assertIn("<code>Next</code>", page)  # the first backtick pair in the hostile text
        self.assertNotIn("<img", page)
        self.assertEqual(page.count("<code>"), page.count("</code>"))

    def test_html_code_span_cannot_hold_markup(self):
        page = report.to_html("http://127.0.0.1", [self.result("x `<script>alert(1)</script>` y")])
        self.assertIn("<code>&lt;script&gt;alert(1)&lt;/script&gt;</code>", page)
        self.assertNotIn("<script", page)

    def test_markdown_code_spans_are_not_escaped(self):
        md = report.to_markdown("http://127.0.0.1", [self.result("Run `asa show NEXT-03` for the steps")])
        self.assertIn("`asa show NEXT-03`", md)
        self.assertIn("Fix: Set `Cache-Control: no-store` on the route.", md)
        self.assertNotIn("\\`", md)

    def test_markdown_code_span_is_literal_and_unpaired_backtick_escaped(self):
        md = report.to_markdown("http://127.0.0.1", [self.result("a `[x](https://evil.example)` b ` c *d*")])
        self.assertIn("`[x](https://evil.example)`", md)  # inert inside a code span
        self.assertIn("b \\` c \\*d\\*", md)

    def test_markdown_table_span_with_pipe_stays_escaped(self):
        md = report.to_markdown("http://127.0.0.1", [self.result("a `x | y` b")])
        row = next(line for line in md.splitlines() if line.startswith("| fail |"))
        self.assertIn("\\`x \\| y\\`", row)
        self.assertEqual(row.count("|") - row.count("\\|"), 5)


if __name__ == "__main__":
    unittest.main()
