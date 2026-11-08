"""OWASP Top 10 (2021, 2025) and API Security Top 10 (2023) mapping: validation, filters and generated docs."""

import json
import unittest
from pathlib import Path

from agent_security_audit import catalog, mcp_server
from tests.test_cli import call
from tests.test_docs_sync import load_gen_docs

ROOT = Path(__file__).resolve().parent.parent


def _raw(check_id, **extra):
    d = catalog.by_id()[check_id].to_dict()
    raw = {"id": d["id"], "title": d["title"], "severity": d["severity"], "layer": d["osi_layer"], "cwe": d["cwe"],
           "risk": d["risk"], "build": d["build"], "proof": d["proof"], "mode": d["mode"], "stacks": d["stacks"],
           "sources": d["sources"]}
    raw.update(extra)
    return raw


class OwaspCatalogTest(unittest.TestCase):
    def test_lists_are_complete(self):
        for key, n in (("2021", 10), ("2025", 10), ("API2023", 10)):
            self.assertEqual(sum(catalog.owasp_list(o) == key for o in catalog.OWASP), n)

    def test_every_category_has_a_check(self):
        mapped = {o for c in catalog.load() for o in c.owasp}
        self.assertEqual(mapped, set(catalog.OWASP))

    def test_parse_rejects_unknown_or_duplicate_ids(self):
        for bad in (["A11:2021"], ["A03"], ["API11:2023"], "A01:2021", ["A01:2021", "A01:2021"]):
            with self.subTest(owasp=bad), self.assertRaises(catalog.CatalogError):
                catalog._parse("nextjs", _raw("NEXT-03", owasp=bad))

    def test_parse_orders_ids(self):
        c = catalog._parse("nextjs", _raw("NEXT-03", owasp=["API8:2023", "A02:2025", "A05:2021"]))
        self.assertEqual(c.owasp, ("A05:2021", "A02:2025", "API8:2023"))

    def test_owasp_is_optional(self):
        self.assertEqual(catalog._parse("nextjs", _raw("NEXT-03")).owasp, ())

    def test_key_mappings(self):
        """Spot checks a reviewer would make: SSRF moved into A01 in 2025, injection moved to A05."""
        by_id = catalog.by_id()
        self.assertIn("A10:2021", by_id["API-08"].owasp)
        self.assertIn("A01:2025", by_id["API-08"].owasp)
        self.assertIn("API7:2023", by_id["API-08"].owasp)
        self.assertIn("A03:2021", by_id["API-32"].owasp)
        self.assertIn("A05:2025", by_id["API-32"].owasp)
        self.assertIn("A06:2021", by_id["BROWSER-23"].owasp)
        self.assertIn("A03:2025", by_id["BROWSER-23"].owasp)
        self.assertIn("A08:2021", by_id["BROWSER-21"].owasp)
        self.assertIn("API1:2023", by_id["ACCESS-10"].owasp)
        self.assertEqual(by_id["INFRA-19"].owasp, ())

    def test_match(self):
        c = catalog.by_id()["INFRA-13"]
        self.assertTrue(catalog.owasp_match(c, "a03"))
        self.assertTrue(catalog.owasp_match(c, "A03:2025"))
        self.assertFalse(catalog.owasp_match(c, "A03:2021"))
        self.assertFalse(catalog.owasp_match(c, "A0"))


class OwaspFilterTest(unittest.TestCase):
    def test_cli_filter(self):
        code, out, _ = call("list", "--owasp", "A10:2021")
        self.assertEqual(code, 0)
        ids = {line.split()[0] for line in out.strip().splitlines()}
        self.assertIn("API-08", ids)
        self.assertTrue(all("A10:2021" in catalog.by_id()[i].owasp for i in ids))

    def test_cli_filter_bare_number_spans_lists(self):
        _, out, _ = call("list", "--owasp", "A03", "--json")
        ids = {c["id"] for c in json.loads(out)}
        self.assertIn("API-32", ids)      # Injection, 2021
        self.assertIn("INFRA-13", ids)    # Software Supply Chain Failures, 2025

    def test_cli_filter_rejects_typo(self):
        code, _, err = call("list", "--owasp", "A11")
        self.assertEqual(code, 2)
        self.assertIn("unknown OWASP category", err)

    def test_show_names_owasp(self):
        _, out, _ = call("show", "API-08")
        self.assertIn("OWASP A10:2021", out)

    def test_mcp_filter(self):
        data = json.loads(mcp_server.tool_list_checks(owasp="API7:2023"))
        self.assertTrue(data["count"] >= 1)
        self.assertTrue(all("API7:2023" in c["owasp"] for c in data["checks"]))
        schema = next(t for t in mcp_server.TOOLS if t["name"] == "list_checks")["inputSchema"]
        self.assertIn("A03", schema["properties"]["owasp"]["enum"])


class OwaspDocsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.gen = load_gen_docs()
        cls.outputs = cls.gen.outputs()

    def test_owasp_doc_generated_and_complete(self):
        text = self.outputs["docs/OWASP.md"]
        for oid in catalog.OWASP:
            self.assertIn(f"### {oid}", text)
        for c in catalog.load():
            self.assertIn(f"[{c.id}]", text)

    def test_readme_block_present(self):
        readme = self.outputs.get("README.md", "")
        self.assertIn("<!-- owasp:start", readme)
        self.assertIn("A09:2021 Security Logging and Monitoring Failures", readme)

    def test_gap_notes(self):
        none = {"total": 0, "live": 0, "code": 0, "guided": 0}
        self.assertTrue(self.gen.owasp_gap("A02:2021", none).startswith("Not covered"))
        guided = {"total": 2, "live": 0, "code": 0, "guided": 2}
        self.assertTrue(self.gen.owasp_gap("API3:2023", guided).startswith("Guided only"))
        strong = {"total": 4, "live": 3, "code": 1, "guided": 0}
        self.assertEqual(self.gen.owasp_gap("A05:2021", strong), "")


if __name__ == "__main__":
    unittest.main()
