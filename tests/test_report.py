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


class HiddenCarrierTest(unittest.TestCase):
    def test_variation_selectors_and_fillers_are_dropped(self):
        from agent_security_audit import mcp_server
        text = "ok" + "".join(chr(c) for c in range(0xE0100, 0xE0105)) + "\ufe0f\u3164\u115f\u034f\uffa0end"
        self.assertEqual(report.strip_invisible(text), "okend")
        self.assertEqual(mcp_server._data(text, 100), "okend")


class SarifTest(unittest.TestCase):
    """Structure required by the SARIF 2.1.0 schema and by GitHub code scanning. The full OASIS schema (112 KB) was
    used to validate real lab and code-audit output; these assertions pin the parts GitHub relies on."""

    def sarif(self, results, target="http://127.0.0.1:8080"):
        import json
        return json.loads(report.to_sarif(target, results))

    def results(self):
        from agent_security_audit.model import Result, passed, warned
        loc = [{"path": "app/a b.ts", "line": 0, "message": "service key"}, {"path": "lib/x.ts", "line": 7}]
        return [failed("NEXT-03", "X-Powered-By: " + HOSTILE, ["e"]), warned("BROWSER-02", "weak"),
                passed("INFRA-04", "fine", ["ok"]), failed("NEXT-01", "key in code", ["k"]),
                Result("NEXT-02", "fail", "map", [], "", loc)]

    def test_top_level_and_driver(self):
        doc = self.sarif(self.results())
        self.assertEqual(doc["version"], "2.1.0")
        self.assertTrue(doc["$schema"].endswith("sarif-2.1.0.json"))
        self.assertEqual(len(doc["runs"]), 1)
        driver = doc["runs"][0]["tool"]["driver"]
        self.assertEqual(driver["name"], "agent-security-audit")
        self.assertTrue(driver["version"])
        self.assertTrue(driver["informationUri"].startswith("https://"))

    def test_rules_carry_what_github_shows(self):
        rules = self.sarif(self.results())["runs"][0]["tool"]["driver"]["rules"]
        self.assertEqual([r["id"] for r in rules], sorted(r["id"] for r in rules))
        for rule in rules:
            self.assertTrue(rule["shortDescription"]["text"])
            self.assertTrue(rule["fullDescription"]["text"])
            self.assertTrue(rule["help"]["text"])
            self.assertIn("**Fix:**", rule["help"]["markdown"])
            self.assertRegex(rule["helpUri"], r"^https://github\.com/.+/docs/checks/\w+\.md#[a-z0-9_-]+$")
            self.assertIn(rule["defaultConfiguration"]["level"], ("error", "warning", "note"))
            props = rule["properties"]
            self.assertIsInstance(props["security-severity"], str)
            self.assertGreater(float(props["security-severity"]), 0)
            self.assertIn("security", props["tags"])
            self.assertTrue(all(isinstance(t, str) for t in props["tags"]))

    def test_cwe_tags_use_github_form(self):
        self.assertEqual(report._cwe_tags(("CWE-79", "CWE-1021", "x")), ["external/cwe/cwe-079", "external/cwe/cwe-1021"])

    def test_results_have_level_location_rule_index_and_fingerprint(self):
        doc = self.sarif(self.results())
        run = doc["runs"][0]
        rules = run["tool"]["driver"]["rules"]
        res = run["results"]
        self.assertNotIn("INFRA-04", {r["ruleId"] for r in res})  # a pass is not a result
        self.assertEqual(len(res), 5)  # 3 live findings plus 2 code locations
        for r in res:
            self.assertEqual(rules[r["ruleIndex"]]["id"], r["ruleId"])
            self.assertIn(r["level"], ("error", "warning", "note"))
            self.assertTrue(r["message"]["text"])
            self.assertEqual(len(r["locations"]), 1)
            self.assertTrue(r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"])
            self.assertRegex(r["partialFingerprints"]["asaFinding/v1"], r"^[0-9a-f]{32}$")
        self.assertEqual(len({r["partialFingerprints"]["asaFinding/v1"] for r in res}), len(res))
        warn = next(r for r in res if r["ruleId"] == "BROWSER-02")
        self.assertEqual(warn["level"], "note")

    def test_code_locations_are_relative_and_one_based(self):
        res = self.sarif(self.results())["runs"][0]["results"]
        code = [r["locations"][0]["physicalLocation"] for r in res if r["ruleId"] == "NEXT-02"]
        self.assertEqual(code[0]["artifactLocation"], {"uri": "app/a%20b.ts", "uriBaseId": "%SRCROOT%"})
        self.assertEqual([c["region"]["startLine"] for c in code], [1, 7])

    def test_messages_are_cleaned(self):
        res = self.sarif(self.results())["runs"][0]["results"]
        msg = next(r for r in res if r["ruleId"] == "NEXT-03")["message"]["text"]
        self.assertNotIn("\n", msg)
        self.assertNotIn("\r", msg)

    def test_fingerprints_are_stable(self):
        a = self.sarif(self.results())["runs"][0]["results"]
        b = self.sarif(self.results())["runs"][0]["results"]
        self.assertEqual([r["partialFingerprints"] for r in a], [r["partialFingerprints"] for r in b])


class CountLineTest(unittest.TestCase):
    def test_counts_follow_the_status_words(self):
        from agent_security_audit.model import Result
        results = [Result("NEXT-01", "fail", "x"), Result("NEXT-01", "pass", "y"), Result("NEXT-01", "pass", "z")]
        self.assertEqual(report.count_line(results), "1 fail · 0 warn · 0 error · 0 manual · 2 pass · 0 skip")
        self.assertEqual(report.count_line([]), "0 fail · 0 warn · 0 error · 0 manual · 0 pass · 0 skip")
        legend = report.status_legend()
        self.assertIn("fail: a defense is missing; fix it", legend)
        self.assertIn("pass: observed working", legend)
        self.assertEqual(legend.count(" · "), 5)


if __name__ == "__main__":
    unittest.main()
