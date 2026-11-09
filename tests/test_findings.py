"""Stable finding ids and `asa diff`: the id contract (pinned), every bucket transition, comparability warnings,
the exit-code matrix, hostile report files, and an end-to-end diff of the lab's vulnerable and fixed modes."""

import contextlib
import io
import json
import os
import tempfile
import time
import unittest
from unittest import mock

from agent_security_audit import cli, diff, findings, lab, mcp_server, report, runner
from agent_security_audit.code_audit import project as code_project
from agent_security_audit.model import UNLISTED, Result
from tests.test_code_audit import STRIPE, audit_files

TARGET = "http://127.0.0.1:8642"


def call(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(list(argv))
    return code, out.getvalue(), err.getvalue()


def scope(**flags):
    base = {"authorized": True, "no_dns": False, "no_ports": False, "auto_only": False, "checks": []}
    return report.run_scope(interface="cli", mode="scan", flags={**base, **flags})


def report_json(results, target=TARGET, scope_block="default"):
    return json.loads(report.to_json(target, results, scope=scope() if scope_block == "default" else scope_block))


class FindingIdTest(unittest.TestCase):
    def test_pinned_ids(self):
        # A public contract once 0.2.0 ships: stored reports match on these. Never change them under "asa1-".
        self.assertEqual(findings.finding_id("BROWSER-02", "https://example.com"), "asa1-28bfb4ca159a674b")
        self.assertEqual(findings.finding_id("INFRA-04", "http://127.0.0.1:8642"), "asa1-d170f3406aee6c2b")
        self.assertEqual(findings.finding_id("NEXT-02", "/home/x/project"), "asa1-d4ea5f0544086242")
        self.assertEqual(findings.finding_id("NEXT-01", path="app/page.tsx", token="sk_live_Fa...", occurrence=0),
                         "asa1-21522b2d977aeff5")
        self.assertEqual(findings.finding_id("NEXT-01", path="app/page.tsx", token="sk_live_Fa...", occurrence=1),
                         "asa1-365d43d05d89dc5e")
        self.assertEqual(findings.finding_id("API-32", path="app/api/notes/route.ts",
                                             token='const id = "42"; db.query(`select ${id}`)'),
                         "asa1-d902bb2444b6f549")

    def test_origin_is_normalized(self):
        self.assertEqual(findings.origin("HTTPS://Example.com:443/"), "https://example.com")
        self.assertEqual(findings.finding_id("X-1", "HTTPS://Example.com:443/"),
                         findings.finding_id("X-1", "https://example.com"))
        self.assertEqual(findings.origin("http://h:80/a?b"), "http://h")
        self.assertEqual(findings.origin("http://h:8080"), "http://h:8080")
        self.assertEqual(findings.origin("/srv/project"), "")
        self.assertEqual(findings.origin("http://h:99999"), "")  # a bad port is not an origin

    def test_token_normalization(self):
        self.assertEqual(findings.normalize_token('next  14.1.0 "a b"'), 'next 0.0.0 ""')
        self.assertEqual(findings.normalize_path(".\\app//x.ts"), "app/x.ts")

    def test_moved_code_finding_keeps_its_id(self):
        line = f'export const key = "{STRIPE}";\n'
        before = audit_files({"lib/pay.ts": line})["INFRA-08"].locations
        after = audit_files({"lib/pay.ts": "// note\n" * 10 + line})["INFRA-08"].locations
        self.assertEqual(after[0]["line"], before[0]["line"] + 10)
        self.assertEqual(after[0]["finding_id"], before[0]["finding_id"])

    def test_identical_findings_in_one_file_get_different_ids(self):
        line = f'export const key = "{STRIPE}";\n'
        locs = audit_files({"lib/pay.ts": line * 2})["INFRA-08"].locations
        self.assertEqual(len(locs), 2)
        self.assertNotEqual(locs[0]["finding_id"], locs[1]["finding_id"])

    def test_occurrence_follows_line_order_not_list_order(self):
        locs = [{"path": "a.ts", "line": 9, "message": "m"}, {"path": "a.ts", "line": 3, "message": "m"}]
        ids = findings.location_ids("NEXT-01", locs, ["t", "t"])
        self.assertEqual(findings.location_ids("NEXT-01", locs[::-1], ["t", "t"]), ids[::-1])
        self.assertEqual(ids[1], findings.finding_id("NEXT-01", path="a.ts", token="t", occurrence=0))

    def test_json_report_carries_schema_and_ids(self):
        line = f'export const key = "{STRIPE}";\n'
        results = list(audit_files({"lib/pay.ts": line * 2}).values())
        data = json.loads(report.to_json("/tmp/p", results))
        self.assertEqual(data["report_schema"], 1)
        for row in data["results"]:
            self.assertRegex(row["finding_id"], findings.ID_RE)
            for loc in row.get("locations", []):
                self.assertRegex(loc["finding_id"], findings.ID_RE)

    def test_ids_derived_from_an_old_report_match(self):
        """A report written without ids gets the same ids back from its evidence lines."""
        line = f'export const key = "{STRIPE}";\n'
        results = list(audit_files({"lib/pay.ts": "x\n" + line * 2}).values())
        data = json.loads(report.to_json("/tmp/p", results))
        for row in data["results"]:
            want = [loc["finding_id"] for loc in row.get("locations", [])]
            stripped = {**row, "locations": [{k: v for k, v in loc.items() if k != "finding_id"}
                                             for loc in row.get("locations", [])]}
            got, derived = findings.annotate(stripped, "/tmp/p")
            self.assertEqual([loc["finding_id"] for loc in got.get("locations", [])], want)
            self.assertEqual(derived, bool(want))


class SarifFingerprintTest(unittest.TestCase):
    def results(self):
        from tests.test_report import HOSTILE
        loc = [{"path": "app/a b.ts", "line": 0, "message": "service key"}, {"path": "lib/x.ts", "line": 7}]
        return [Result("NEXT-03", "fail", "X-Powered-By: " + HOSTILE, ["e"]), Result("BROWSER-02", "warn", "weak"),
                Result("INFRA-04", "pass", "fine", ["ok"]), Result("NEXT-01", "fail", "key in code", ["k"]),
                Result("NEXT-02", "fail", "map", [], "", loc)]

    def test_v1_is_unchanged_and_v2_is_the_finding_id(self):
        res = json.loads(report.to_sarif("http://127.0.0.1:8080", self.results()))["runs"][0]["results"]
        v1 = [(r["ruleId"], r["partialFingerprints"]["asaFinding/v1"]) for r in res]
        # Captured from 0.2.0 before asaFinding/v2 existed: v1 must stay byte-for-byte the same.
        self.assertEqual(v1, [("NEXT-01", "f0e02768acaa01a9c925b01e26b23bdf"),
                              ("NEXT-02", "7609c43486508fbf2739005cba31342a"),
                              ("NEXT-02", "87b150caaa946a533f7531d298762fb2"),
                              ("NEXT-03", "cc00c7782bc4988920b008903b4a29ea"),
                              ("BROWSER-02", "2cfba2cef99a524a1f59dcedd09862c4")])
        data = json.loads(report.to_json("http://127.0.0.1:8080", self.results()))
        ids = {r["check_id"]: r for r in data["results"]}
        self.assertEqual(res[0]["partialFingerprints"]["asaFinding/v2"], ids["NEXT-01"]["finding_id"])
        self.assertEqual([r["partialFingerprints"]["asaFinding/v2"] for r in res[1:3]],
                         [loc["finding_id"] for loc in ids["NEXT-02"]["locations"]])


class DiffCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def write(self, name, data):
        path = os.path.join(self.tmp, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(data if isinstance(data, str) else json.dumps(data))
        return path

    def diff(self, old, new, *extra):
        code, out, err = call("diff", self.write("old.json", old), self.write("new.json", new), *extra)
        return code, out, err

    def buckets(self, old, new, *extra):
        code, out, err = self.diff(old, new, "--format", "json", *extra)
        self.assertNotEqual(code, 2, err)
        data = json.loads(out)
        return {k: sorted((e["check_id"], e["old_status"], e["new_status"]) for e in v)
                for k, v in data["buckets"].items() if v}, data, code


class BucketTest(DiffCase):
    def test_every_transition(self):
        old = report_json([Result("NEXT-03", "fail", "x"), Result("BROWSER-02", "fail", "x"),
                           Result("BROWSER-03", "fail", "x"), Result("BROWSER-04", "fail", "x"),
                           Result("BROWSER-05", "warn", "x"), Result("BROWSER-06", "pass", "x"),
                           Result("API-24", "manual", "x"), Result("API-25", "skip", "x"),
                           Result("API-19", "fail", "x"), Result("API-20", "fail", "x"),
                           Result("API-21", "pass", "x")])
        new = report_json([Result("NEXT-03", "pass", "x"), Result("BROWSER-02", "error", "x"),
                           Result("BROWSER-03", "manual", "x"), Result("BROWSER-04", "fail", "x"),
                           Result("BROWSER-05", "fail", "x"), Result("BROWSER-06", "fail", "x"),
                           Result("API-24", "fail", "x"), Result("API-25", "warn", "x"),
                           Result("API-20", "skip", "x"), Result("API-21", "manual", "x"),
                           Result("API-02", "fail", "x")])
        got, data, _ = self.buckets(old, new)
        self.assertEqual(got, {
            "fixed": [("NEXT-03", "fail", "pass")],
            "still_open": [("BROWSER-04", "fail", "fail"), ("BROWSER-05", "warn", "fail")],
            "regressed": [("BROWSER-06", "pass", "fail")],
            "not_proven": [("API-19", "fail", "missing"), ("API-20", "fail", "skip"), ("API-21", "pass", "manual"),
                           ("BROWSER-02", "fail", "error"), ("BROWSER-03", "fail", "manual")],
            "new": [("API-02", "missing", "fail"), ("API-24", "manual", "fail"), ("API-25", "skip", "warn")],
        })
        still = {e["check_id"]: e for e in data["buckets"]["still_open"]}
        self.assertIn("warn -> fail", still["BROWSER-05"]["note"])

    def test_not_selected_is_not_compared(self):
        old = report_json([Result("NEXT-03", "fail", "x"), Result("BROWSER-02", "pass", "x")])
        new = report_json([Result("BROWSER-02", "fail", "x")], scope_block=scope(checks=["BROWSER-02"]))
        got, _, _ = self.buckets(old, new)
        self.assertEqual(got["not_compared"], [("NEXT-03", "fail", "missing")])
        self.assertNotIn("fixed", got)
        self.assertNotIn("not_proven", got)

    def test_missing_from_a_report_without_scope_is_not_proven(self):
        old = report_json([Result("NEXT-03", "fail", "x")])
        new = report_json([Result("BROWSER-02", "pass", "x")], scope_block=None)
        got, data, _ = self.buckets(old, new)
        self.assertEqual(got["not_proven"], [("NEXT-03", "fail", "missing")])
        self.assertIn("flags unknown", data["buckets"]["not_proven"][0]["note"])

    def test_code_locations(self):
        line = f'export const key = "{STRIPE}";\n'
        a = list(audit_files({"lib/pay.ts": line * 2, "lib/b.ts": line}).values())
        b = list(audit_files({"lib/pay.ts": "\n" * 10 + line, "lib/c.ts": line}).values())
        _, data, _ = self.buckets(report_json(a, "/p"), report_json(b, "/p"))
        where = {k: sorted(e["where"] for e in v) for k, v in data["buckets"].items() if v and k != "not_compared"}
        # The second identical finding in pay.ts is gone: by order, the first one keeps its id.
        self.assertEqual(where["still_open"], ["lib/pay.ts:11"])
        self.assertEqual(where["fixed"], ["lib/b.ts:1", "lib/pay.ts:2"])
        self.assertEqual(where["new"], ["lib/c.ts:1"])


class HeaderAndTargetTest(DiffCase):
    def test_scope_mismatch_warns(self):
        old = report_json([Result("NEXT-03", "fail", "x")], scope_block=scope(authorized=True))
        new = report_json([Result("NEXT-03", "fail", "x")], scope_block=scope(authorized=False, no_dns=True))
        new["scope"]["version"] = "0.1.9"
        code, out, _ = self.diff(old, new)
        self.assertEqual(code, 0)
        self.assertIn("WARNING: flag authorized differs: old yes, new no", out)
        self.assertIn("WARNING: flag no_dns differs", out)
        self.assertIn("WARNING: different asa versions", out)

    def test_old_report_without_scope_or_ids(self):
        old = report_json([Result("NEXT-03", "fail", "x", locations=[{"path": "a.ts", "line": 2, "message": "m"}])],
                          scope_block=None)
        del old["report_schema"]
        for row in old["results"]:
            row.pop("finding_id")
            for loc in row.get("locations", []):
                loc.pop("finding_id")
        code, out, err = self.diff(old, report_json([Result("NEXT-03", "pass", "x")]))
        self.assertEqual(code, 0, err)
        self.assertIn("the old report has no scope block", out)
        self.assertIn("finding ids in the old report were derived", out)
        # The new run was a live scan: it never read a.ts, so the location is not proven fixed.
        self.assertIn("NOT PROVEN: 1", out)
        self.assertIn("did not read the source code", out)

    def test_different_targets_refused(self):
        old = report_json([Result("NEXT-03", "fail", "x")], target="https://a.example")
        new = report_json([Result("NEXT-03", "fail", "x")], target="https://b.example")
        code, out, err = self.diff(old, new)
        self.assertEqual((code, out), (2, ""))
        self.assertIn("different targets", err)
        code, out, _ = self.diff(old, new, "--allow-different-target")
        self.assertEqual(code, 0)
        self.assertIn("WARNING: different targets", out)

    def test_equivalent_targets_compare(self):
        old = report_json([Result("NEXT-03", "fail", "x")], target="HTTPS://Example.com:443/")
        new = report_json([Result("NEXT-03", "fail", "x")], target="https://example.com")
        got, _, code = self.buckets(old, new)
        self.assertEqual((code, list(got)), (0, ["still_open"]))

    def test_formats_and_out(self):
        old = report_json([Result("NEXT-03", "fail", "x")])
        new = report_json([Result("NEXT-03", "pass", "x")])
        code, out, _ = self.diff(old, new, "--format", "md")
        self.assertIn("## FIXED (1)", out)
        dest = os.path.join(self.tmp, "sub", "d.json")
        code, out, _ = self.diff(old, new, "--format", "json", "--out", dest)
        self.assertEqual((code, out), (0, ""))
        with open(dest, encoding="utf-8") as fh:
            self.assertEqual(json.load(fh)["counts"]["fixed"], 1)


class ExitCodeTest(DiffCase):
    def test_matrix(self):
        # NEXT-03 is low, BROWSER-02 high, NEXT-01 critical (catalog severities).
        cases = [
            ([], [Result("BROWSER-02", "fail", "x")], {"critical": 0, "high": 1, "medium": 1, "low": 1, "none": 0}),
            ([Result("NEXT-03", "pass", "x")], [Result("NEXT-03", "fail", "x")],
             {"critical": 0, "high": 0, "medium": 0, "low": 1, "none": 0}),
            ([Result("NEXT-01", "fail", "x")], [Result("NEXT-01", "fail", "x")],
             {"critical": 0, "high": 0, "low": 0}),   # still open never fails the diff
            ([], [Result("BROWSER-02", "warn", "x")], {"high": 0, "low": 0}),  # a warn is not a fail
            ([Result("NEXT-01", "pass", "x")], [Result("NEXT-01", "fail", "x")], {"critical": 1, "none": 0}),
            ([Result("NEXT-01", "fail", "x")], [Result("NEXT-01", "error", "x")], {"critical": 0, "low": 0}),
        ]
        for old, new, want in cases:
            for level, code in want.items():
                with self.subTest(old=old, new=new, level=level):
                    got, _, _ = self.diff(report_json(old), report_json(new), "--fail-on-new", level)
                    self.assertEqual(got, code)

    def test_default_is_high(self):
        code, _, _ = self.diff(report_json([]), report_json([Result("BROWSER-02", "fail", "x")]))
        self.assertEqual(code, 1)


class HostileInputTest(DiffCase):
    def refused(self, data, needle):
        code, out, err = self.diff(data, report_json([]))
        self.assertEqual((code, out), (2, ""), err)
        self.assertIn(needle, err)
        self.assertNotIn("Traceback", err)

    def test_refused_inputs(self):
        good = report_json([Result("NEXT-03", "fail", "x")])
        self.refused("{not json", "not valid JSON")
        self.refused("[" * 200000 + "]" * 200000, "not valid JSON")
        self.refused([1, 2], "not an asa JSON report")
        self.refused({"results": []}, "not an asa JSON report")
        self.refused({**good, "tool": "other"}, "not an asa JSON report")
        self.refused({**good, "report_schema": 2}, "report_schema 2")
        self.refused({**good, "report_schema": "1"}, "report_schema")
        self.refused({**good, "results": "x"}, "no results list")
        self.refused({**good, "results": [{"check_id": "x; rm", "status": "fail"}]}, "valid check_id")
        self.refused({**good, "results": [{"check_id": "NEXT-03", "status": "broken"}]}, "valid check_id")
        self.refused({**good, "results": good["results"] * 2}, "twice")
        self.refused({**good, "target": 5}, "no target")

    def test_many_locations_stay_bounded(self):
        rows = [{"check_id": f"ZZ-{i}", "status": "fail", "evidence": ["x"] * 5000,
                 "locations": [{"path": "a.ts", "line": n, "message": "m" * 1000} for n in range(diff.MAX_LOCATIONS)]}
                for i in range(diff.MAX_TOTAL_LOCATIONS // diff.MAX_LOCATIONS)]
        old = {"tool": "agent-security-audit", "target": "/p", "results": rows}
        new = {"tool": "agent-security-audit", "target": "/p", "results": []}
        _, data, code = self.buckets(old, new)
        self.assertEqual(code, 0)
        self.assertEqual(data["counts"]["not_proven"], diff.MAX_TOTAL_LOCATIONS)
        rows.append({"check_id": "ZZ-999", "status": "fail", "locations": [{"path": "b.ts"}]})
        self.refused(old, "more than")

    def test_invalid_utf8_and_missing_file(self):
        path = os.path.join(self.tmp, "bin.json")
        with open(path, "wb") as fh:
            fh.write(b'{"tool": "\xff"}')
        code, _, err = call("diff", path, path)
        self.assertEqual(code, 2)
        self.assertIn("not valid JSON", err)
        code, _, err = call("diff", os.path.join(self.tmp, "nope.json"), path)
        self.assertEqual(code, 2)
        self.assertIn("not a file", err)

    def test_huge_file_is_refused_before_reading(self):
        path = os.path.join(self.tmp, "huge.json")
        with open(path, "wb") as fh:
            fh.truncate(diff.MAX_BYTES + 1)  # sparse: no 50 MB written
        err = io.StringIO()
        with mock.patch("builtins.open", side_effect=AssertionError("read")) as opened:
            code = diff.run(path, path, say=lambda m: print(m, file=err))
        self.assertEqual(code, 2)
        self.assertIn("over 50 MB", err.getvalue())
        opened.assert_not_called()

    def test_control_characters_and_escapes_are_cleaned(self):
        evil = "\x1b[31mRED\x1b]0;title\x07 \u202egnp.exe \x9b2J\r\nFAKE: all fixed"
        old = report_json([Result("NEXT-03", "fail", "x", locations=[{"path": "a" + evil, "line": 1, "message": evil}]),
                           Result("NEXT-01", "fail", "x")], target="http://127.0.0.1:8642")
        new = report_json([Result("NEXT-03", "pass", "x"), Result("NEXT-01", "fail", "x")])
        for doc in (old, new):
            doc["version"] = doc["scope"]["version"] = "9" + evil
            doc["generated"] = evil
            doc["scope"]["flags"]["checks"] = [evil]
        old["target"] = "http://127.0.0.1:8642/" + evil
        old["results"].append({"check_id": "ZZZ-1", "status": "fail", "title": evil, "severity": evil})
        for fmt in ("text", "md", "json"):
            code, out, err = self.diff(old, new, "--format", fmt)
            with self.subTest(fmt=fmt):
                self.assertEqual(code, 0, err)
                for bad in ("\x1b", "\x07", "\u202e", "\x9b", "\r"):
                    self.assertNotIn(bad, out)
                self.assertFalse(any(line.startswith("FAKE") for line in out.splitlines()))


class LabDiffTest(unittest.TestCase):
    """vulnerable -> a.json, fixed -> b.json on the same port, then diff both ways."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.paths = {}
        port = 0
        for mode in ("vulnerable", "fixed"):
            server, url = lab.serve(mode, port)
            port = server.server_address[1]
            try:
                out = os.path.join(cls.tmp, f"{mode}.json")
                with contextlib.redirect_stderr(io.StringIO()):
                    code = cli.main(["scan", url, "--authorized", "--auto-only", "--quiet", "--format", "json",
                                     "--out", out, "--rate-limit-path", "/api/login", "--fail-on", "none"])
                assert code == 0, code
                cls.paths[mode] = out
            finally:
                server.shutdown()
                server.server_close()

    def run_diff(self, old, new):
        code, out, _ = call("diff", self.paths[old], self.paths[new], "--format", "json")
        return code, json.loads(out)

    def test_vulnerable_to_fixed(self):
        code, data = self.run_diff("vulnerable", "fixed")
        self.assertEqual(code, 0)
        self.assertGreater(data["counts"]["fixed"], 10)
        for key in ("new", "regressed", "not_proven", "not_compared", "still_open"):
            self.assertEqual(data["counts"][key], 0, key)
        self.assertEqual(data["warnings"], [])

    def test_vulnerable_again_is_still_open(self):
        code, data = self.run_diff("vulnerable", "vulnerable")
        self.assertEqual(code, 0)
        self.assertGreater(data["counts"]["still_open"], 10)
        self.assertEqual(data["counts"]["fixed"] + data["counts"]["new"], 0)

    def test_fixed_to_vulnerable_regresses(self):
        code, data = self.run_diff("fixed", "vulnerable")
        self.assertEqual(code, 1)
        self.assertGreater(data["counts"]["regressed"], 10)
        self.assertEqual(data["counts"]["fixed"], 0)


def code_scope(mode="code", **flags):
    return report.run_scope(interface="cli", mode=mode, flags=flags)


class ReviewFindingsTest(DiffCase):
    """Cases a review found where the diff claimed a fix it had not seen, or hid a lost pass."""

    def test_unread_file_is_not_fixed(self):
        line = f'export const key = "{STRIPE}";\n'
        big = line + "// " + "x" * code_project.MAX_BYTES + "\n"
        a = list(audit_files({"lib/pay.ts": line, "lib/big.ts": line, "lib/c.ts": line}).values())
        b = audit_files({"lib/pay.ts": line, "lib/big.ts": big, "lib/c.ts": "export {};\n"})
        self.assertEqual(b["INFRA-08"].status, "fail")
        self.assertEqual(b["INFRA-08"].unread, ["lib/big.ts"])
        _, data, _ = self.buckets(report_json(a, "/p", code_scope()), report_json(list(b.values()), "/p", code_scope()))
        where = {k: sorted((e["where"], e["note"]) for e in v if e["check_id"] == "INFRA-08")
                 for k, v in data["buckets"].items()}
        self.assertEqual(where["fixed"], [("lib/c.ts:1", "no longer reported; the check still fails elsewhere")])
        self.assertEqual(where["not_proven"], [("lib/big.ts:1", "the new run could not read this file")])

    def test_file_cap_gap_is_not_fixed(self):
        loc = [{"path": "a.ts", "line": 1, "message": "m"}, {"path": "b.ts", "line": 1, "message": "n"}]
        old = report_json([Result("NEXT-01", "fail", "x", locations=loc)], "/p", code_scope())
        new = report_json([Result("NEXT-01", "fail", "x", locations=loc[:1], unread=[UNLISTED])], "/p", code_scope())
        got, _, _ = self.buckets(old, new)
        self.assertEqual(got["not_proven"], [("NEXT-01", "fail", "fail")])
        self.assertNotIn("fixed", got)

    def test_old_report_past_the_evidence_list_is_compared_by_check(self):
        lines = "".join(f'export const k{i} = "{STRIPE}";\n' for i in range(30))
        res = list(audit_files({"lib/pay.ts": lines}).values())
        self.assertEqual(len(res[0].locations), 30)
        old = report_json(res, "/p", None)
        del old["report_schema"]
        for row in old["results"]:
            for loc in row.get("locations", []):
                loc.pop("finding_id")
        got, data, code = self.buckets(old, report_json(res, "/p", code_scope()))
        self.assertEqual((code, list(got)), (0, ["still_open"]))
        self.assertIn("compared by check", data["buckets"]["still_open"][0]["note"])
        self.assertTrue(any("cannot be matched" in w for w in data["warnings"]))

    def test_lost_pass_is_not_proven(self):
        for status in ("error", "manual", "skip"):
            with self.subTest(status=status):
                got, data, code = self.buckets(report_json([Result("API-01", "pass", "x")]),
                                               report_json([Result("API-01", status, "x")]))
                self.assertEqual((code, got), (0, {"not_proven": [("API-01", "pass", status)]}))
                self.assertEqual(data["buckets"]["not_proven"][0]["note"], f"passed before, now {status}")

    def test_area_and_stack_selection_is_recorded(self):
        with mock.patch.object(runner, "run", return_value=(TARGET, [])):
            _, out, err = call("scan", TARGET, "--authorized", "--area", "browser", "--stack", "supabase",
                               "--format", "json", "--fail-on", "none", "--quiet")
            res = mcp_server.call_tool({"name": "run_scan", "arguments": {
                "target": TARGET, "authorized": True, "areas": ["browser"], "stacks": ["supabase"]}})
        flags = json.loads(out)["scope"]["flags"]
        self.assertEqual((flags["areas"], flags["stacks"]), (["browser"], ["supabase"]), err)
        flags = res["structuredContent"]["scope"]["flags"]
        self.assertEqual((flags["areas"], flags["stacks"]), (["browser"], ["supabase"]))
        old = report_json([Result("NEXT-03", "fail", "x"), Result("BROWSER-02", "fail", "x")])
        new = report_json([Result("BROWSER-02", "fail", "x")], scope_block=scope(areas=["browser"]))
        got, data, _ = self.buckets(old, new)
        self.assertEqual(got["not_compared"], [("NEXT-03", "fail", "missing")])
        self.assertIn("areas selection differs: old -, new browser", data["warnings"])

    def test_same_site_different_path_warns(self):
        old = report_json([Result("NEXT-03", "fail", "x")], target="http://127.0.0.1:8761/staging-app")
        new = report_json([Result("NEXT-03", "pass", "x")], target="http://127.0.0.1:8761/other-app")
        _, data, _ = self.buckets(old, new)
        self.assertTrue(any(w.startswith("same site, different paths") for w in data["warnings"]))
        _, data, _ = self.buckets(old, report_json([], target="http://127.0.0.1:8761/staging-app/"))
        self.assertEqual(data["warnings"], [])

    def test_live_only_pass_does_not_fix_code_locations(self):
        old = report_json([Result("NEXT-01", "fail", "x", locations=[{"path": "lib/a.ts", "line": 3, "message": "m"}])],
                          scope_block=code_scope("scan+code"))
        got, data, _ = self.buckets(old, report_json([Result("NEXT-01", "pass", "x")]))
        self.assertEqual(got, {"not_proven": [("NEXT-01", "fail", "pass")]})
        self.assertEqual(data["buckets"]["not_proven"][0]["note"], "the new run did not read the source code")
        new = report_json([Result("NEXT-01", "pass", "x")], scope_block=code_scope("scan+code"))
        got, _, _ = self.buckets(old, new)
        self.assertEqual(got, {"fixed": [("NEXT-01", "fail", "pass")]})

    def test_huge_strings_are_cut_before_work(self):
        token = "a.ts:1: m: " + "x " * 2_500_000
        row = {"check_id": "NEXT-01", "status": "fail", "evidence": [token],
               "locations": [{"path": "a.ts", "line": 1, "message": "m"}] * diff.MAX_LOCATIONS}
        doc = {"tool": "agent-security-audit", "target": "/p", "results": [row]}
        start = time.monotonic()
        code, _, err = self.diff(doc, doc)
        self.assertEqual(code, 0, err)
        self.assertLess(time.monotonic() - start, 10)
        code, _, err = self.diff({**doc, "target": "/p" + "x" * diff.MAX_TARGET}, doc)
        self.assertEqual(code, 2)
        self.assertIn("over 4096 characters", err)

    def test_jsonl_run_event_scope_is_cleaned(self):
        evil = "\x1b[31m\x00x\u202e"
        sc = {**report.run_scope(interface="cli", mode=evil, flags={"checks": [evil], evil: evil}, finished=evil),
              "extra": {"k": evil}}
        text = report.to_jsonl(TARGET, [Result("NEXT-03", "fail", "x")], sc)
        for bad in ("\\u001b", "\\u0000", "\\u202e"):
            self.assertNotIn(bad, text)


if __name__ == "__main__":
    unittest.main()
