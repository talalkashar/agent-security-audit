"""JUnit XML and JSON Lines reports, and several --out files from one run."""

import contextlib
import http.server
import io
import json
import os
import tempfile
import threading
import unittest
import xml.etree.ElementTree as ET
from unittest import mock

from agent_security_audit import cli, findings, lab, report
from agent_security_audit.model import Result, failed, passed, warned

# Control characters, a CDATA terminator, a terminal escape, a bidi override and XML noncharacters.
HOSTILE = "x\x00\x01\x08\x0b\x1b[31mred\x1b]0;title\x07 ]]> <a>&amp; \u202e\ufffe\uffff\x85\x9b end"
SCOPE = {"tool": "agent-security-audit", "version": "0", "interface": "cli", "mode": "scan",
         "flags": {"authorized": False, "checks": ["NEXT-03"]}, "hosts_contacted": ["127.0.0.1"], "requests_sent": 7,
         "started": "2026-01-01T00:00:00+00:00", "finished": "2026-01-01T00:00:04+00:00"}


def results():
    loc = [{"path": "app/a.ts", "line": 3, "message": "key " + HOSTILE}, {"path": "lib/x.ts", "line": 7}]
    return [failed("NEXT-03", HOSTILE, [HOSTILE]), warned("INFRA-05", "weak " + HOSTILE),
            Result("AUTH-01", "manual", "needs a login " + HOSTILE), Result("NEXT-02", "fail", "map", [], "", loc),
            Result("INFRA-04", "error", "timed out"), Result("ACCESS-01", "skip", "no Supabase"),
            passed("NEXT-01", "fine")]


def call(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(list(argv))
    return code, out.getvalue(), err.getvalue()


class JUnitTest(unittest.TestCase):
    def junit(self, rs=None, scope=SCOPE):
        text = report.to_junit("http://127.0.0.1:8080", results() if rs is None else rs, scope)
        return text, ET.fromstring(text.encode("utf-8"))

    def test_counts_match_report_counts(self):
        rs = results()
        _, root = self.junit(rs)
        c = report.counts(rs)
        suite = root.find("testsuite")
        for node in (root, suite):
            self.assertEqual(node.get("tests"), str(len(rs)))
            self.assertEqual(node.get("failures"), str(c["fail"] + c["warn"]))
            self.assertEqual(node.get("errors"), str(c["error"]))
            self.assertEqual(node.get("skipped"), str(c["manual"] + c["skip"]))
        self.assertEqual(len(suite.findall("testcase")), len(rs))
        self.assertEqual(len(suite.findall("testcase/failure")), c["fail"] + c["warn"])
        self.assertEqual(len(suite.findall("testcase/error")), c["error"])
        self.assertEqual(len(suite.findall("testcase/skipped")), c["manual"] + c["skip"])
        self.assertEqual(suite.get("time"), "4.000")

    def test_only_pass_is_a_bare_testcase(self):
        _, root = self.junit()
        by_name = {case.get("name").split()[0]: case for case in root.iter("testcase")}
        self.assertEqual([k for k, case in by_name.items() if len(case) == 0], ["NEXT-01"])
        self.assertEqual(by_name["NEXT-03"].find("failure").get("type"), "low")
        self.assertEqual(by_name["INFRA-05"].find("failure").get("type"), "warn")
        self.assertIsNotNone(by_name["INFRA-04"].find("error"))
        self.assertTrue(by_name["AUTH-01"].find("skipped").get("message").startswith("manual: "))
        self.assertTrue(by_name["ACCESS-01"].find("skipped").get("message").startswith("skip: "))
        self.assertEqual(by_name["NEXT-03"].get("classname"), "asa.nextjs")
        self.assertTrue(by_name["NEXT-03"].get("name").startswith("NEXT-03 Framework"))

    def test_every_status_is_mapped(self):
        for status in report.ORDER:
            _, root = self.junit([Result("NEXT-03", status, "s")])
            case = root.find("testsuite/testcase")
            self.assertEqual(len(case) == 0, status == "pass", status)

    def test_hostile_text_stays_well_formed(self):
        text, root = self.junit()
        self.assertNotIn("\x1b", text)
        self.assertNotIn("\x00", text)
        self.assertNotIn("\ufffe", text)
        self.assertNotIn("\u202e", text)
        self.assertNotIn("<!DOCTYPE", text.upper())
        failure = root.find("testsuite/testcase/failure")
        self.assertIn("]]>", failure.text)  # kept as text, escaped by the serializer
        self.assertIn("<a>&amp;", failure.text)
        locs = next(c for c in root.iter("testcase") if c.get("name").startswith("NEXT-02")).find("failure").text
        self.assertIn("app/a.ts:3: key x", locs)

    def test_scope_in_properties(self):
        _, root = self.junit()
        props = {p.get("name"): p.get("value") for p in root.iter("property")}
        self.assertEqual(props["asa.target"], "http://127.0.0.1:8080")
        self.assertEqual(props["asa.requests_sent"], "7")
        self.assertEqual(props["asa.flag.checks"], "NEXT-03")
        self.assertEqual(props["asa.hosts_contacted"], "127.0.0.1")
        _, root = self.junit(scope=None)
        self.assertEqual(root.find("testsuite").get("time"), "0")

    def test_hostile_target_and_huge_text(self):
        rs = [failed("NEXT-03", HOSTILE * 500, [HOSTILE * 500] * 100)]
        text = report.to_junit("/tmp/" + HOSTILE, rs)
        ET.fromstring(text.encode("utf-8"))
        self.assertLess(len(text), 60_000)


class JsonLinesTest(unittest.TestCase):
    def lines(self, rs=None, scope=SCOPE, target="http://127.0.0.1:8080"):
        text = report.to_jsonl(target, results() if rs is None else rs, scope, now=lambda: "NOW")
        self.assertTrue(text.endswith("\n"))
        return [json.loads(line) for line in text.splitlines()]

    def test_each_line_parses_with_schema_and_run_last(self):
        rs = results()
        rows = self.lines(rs)
        self.assertTrue(all(r["asa"]["schema"] == 1 for r in rows))
        self.assertEqual([r["event"]["kind"] for r in rows[:-1]], ["finding"] * (len(rows) - 1))
        run = rows[-1]
        self.assertEqual(run["event"]["kind"], "run")
        self.assertEqual(run["asa"]["counts"], report.counts(rs))
        self.assertEqual(run["asa"]["scope"], SCOPE)
        # One line per result, plus one more for each location after the first.
        self.assertEqual(len(rows) - 1, len(rs) + 1)
        self.assertTrue(all(r["@timestamp"] == SCOPE["finished"] for r in rows))

    def test_fields(self):
        rows = self.lines()
        first = next(r for r in rows if r.get("rule", {}).get("id") == "NEXT-03")
        self.assertEqual(first["asa"]["status"], "fail")
        self.assertEqual(first["asa"]["severity"], "low")
        self.assertEqual(first["event"], {"kind": "finding", "dataset": "asa", "severity": 1})
        self.assertEqual(first["url"], {"original": "http://127.0.0.1:8080", "domain": "127.0.0.1"})
        self.assertEqual(first["asa"]["finding_id"], findings.finding_id("NEXT-03", "http://127.0.0.1:8080"))
        self.assertTrue(first["rule"]["reference"].startswith("https://github.com/"))
        self.assertEqual((first["rule"]["name"], first["rule"]["category"]),
                         ("Framework not advertised (X-Powered-By)", "nextjs"))
        self.assertIn("CWE-200", first["asa"]["cwe"])
        self.assertTrue(first["asa"]["owasp"])
        # The field names are a contract under asa.schema 1.
        self.assertEqual(set(first), {"@timestamp", "event", "rule", "url", "asa", "message"})
        self.assertEqual(set(first["asa"]), {"schema", "target", "status", "severity", "finding_id", "cwe", "owasp"})
        code = [r for r in rows if r.get("rule", {}).get("id") == "NEXT-02"]
        self.assertEqual([(r["file"]["path"], r["file"]["line"]) for r in code], [("app/a.ts", 3), ("lib/x.ts", 7)])
        self.assertEqual(len({r["asa"]["finding_id"] for r in code}), 2)
        self.assertTrue(all(findings.ID_RE.match(r["asa"]["finding_id"]) for r in rows[:-1]))

    def test_hostile_text_is_cleaned_and_capped(self):
        rows = self.lines([failed("NEXT-03", HOSTILE * 400)])
        msg = rows[0]["message"]
        self.assertLessEqual(len(msg), report.MAX_TEXT + 3)
        for bad in ("\x1b", "\x00", "\x07", "\x85", "\x9b", "\u202e"):
            self.assertNotIn(bad, msg)

    def test_no_clock_without_scope(self):
        rows = self.lines(scope=None, target="/work/app")
        self.assertTrue(all(r["@timestamp"] == "NOW" for r in rows))
        self.assertNotIn("url", rows[0])
        self.assertEqual(rows[-1]["asa"]["scope"], {})


class CountingHandler(http.server.BaseHTTPRequestHandler):
    hits = 0

    def do_GET(self):
        type(self).hits += 1
        self.send_response(200)
        self.end_headers()

    do_HEAD = do_POST = do_GET

    def log_message(self, *args):
        pass


class OutFilesTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, cls.url = lab.serve("vulnerable", 0)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def scan(self, *extra):
        return call("scan", self.url, "--auto-only", "--check", "NEXT-03,INFRA-05,NEXT-01", "--fail-on", "none",
                    *extra)

    def test_several_files_from_one_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = {ext: os.path.join(tmp, f"r.{ext}") for ext in ("sarif", "json", "md", "html", "xml", "jsonl")}
            args = [a for p in paths.values() for a in ("--out", p)]
            with mock.patch.object(cli.runner, "run", wraps=cli.runner.run) as run:
                code, out, err = self.scan(*args)
            self.assertEqual((code, out), (0, ""), err)
            self.assertEqual(run.call_count, 1)
            self.assertEqual(err.count("asa: wrote "), 6)
            read = {}
            for ext, p in paths.items():
                with open(p, encoding="utf-8") as fh:
                    read[ext] = fh.read()
        data = json.loads(read["json"])
        root = ET.fromstring(read["xml"].encode("utf-8"))
        rows = [json.loads(line) for line in read["jsonl"].splitlines()]
        sarif = json.loads(read["sarif"])
        self.assertEqual(rows[-1]["asa"]["counts"], data["counts"])
        self.assertEqual(rows[-1]["asa"]["scope"], data["scope"])
        self.assertEqual(root.get("tests"), str(len(data["results"])))
        self.assertEqual(root.get("failures"), str(data["counts"]["fail"] + data["counts"]["warn"]))
        self.assertEqual({r["ruleId"] for r in sarif["runs"][0]["results"]},
                         {r["check_id"] for r in data["results"] if r["status"] in ("fail", "warn")})
        self.assertTrue(read["md"].startswith("# Security proof report"))
        self.assertTrue(read["html"].startswith("<!doctype html>"))

    def test_format_with_one_out_overrides_extension(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "results.txt")
            code, _, err = self.scan("--format", "junit", "--out", path)
            self.assertEqual(code, 0, err)
            ET.parse(path)

    def test_stdout_formats(self):
        code, out, _ = self.scan("--format", "jsonl")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out.splitlines()[-1])["event"]["kind"], "run")
        code, out, _ = self.scan("--format", "junit")
        self.assertEqual(ET.fromstring(out.encode("utf-8")).tag, "testsuites")

    def test_one_unwritable_path_still_writes_the_others(self):
        with tempfile.TemporaryDirectory() as tmp, tempfile.NamedTemporaryFile() as f:
            good = [os.path.join(tmp, "a.json"), os.path.join(tmp, "b.xml")]
            bad = os.path.join(f.name, "r.sarif")  # a file where a directory is needed
            code, _, err = self.scan("--out", good[0], "--out", bad, "--out", good[1])
            self.assertEqual(code, 2)
            self.assertIn("could not write", err)
            self.assertEqual(err.count("asa: wrote "), 2)
            self.assertTrue(all(os.path.getsize(p) for p in good))


class BadOutTest(unittest.TestCase):
    """A bad --out or --format exits 2 before a single request reaches the target."""

    @classmethod
    def setUpClass(cls):
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), CountingHandler)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.url = f"http://127.0.0.1:{cls.server.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_refused_before_any_request(self):
        with tempfile.TemporaryDirectory() as tmp:
            cases = [("--out", os.path.join(tmp, "r.txt")), ("--out", os.path.join(tmp, "report")),
                     ("--out", os.path.join(tmp, "a.json"), "--out", os.path.join(tmp, "b.pdf")),
                     ("--format", "json", "--out", os.path.join(tmp, "a.json"), "--out", os.path.join(tmp, "b.xml"))]
            for extra in cases:
                CountingHandler.hits = 0
                code, _, err = call("scan", self.url, "--auto-only", *extra)
                self.assertEqual(code, 2, extra)
                self.assertEqual(CountingHandler.hits, 0, extra)
                self.assertTrue(err.startswith("asa: --"), err)
                self.assertEqual(os.listdir(tmp), [])
            with mock.patch.object(cli.runner, "audit_code") as audit:
                code, _, _ = call("code", tmp, "--out", os.path.join(tmp, "r.txt"))
            self.assertEqual(code, 2)
            audit.assert_not_called()


if __name__ == "__main__":
    unittest.main()
