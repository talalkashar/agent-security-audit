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


if __name__ == "__main__":
    unittest.main()
