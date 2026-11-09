"""The catalog loads, its ids are clean, and every automated check has exactly one proof function."""

import re
import unittest
from collections import defaultdict

from agent_security_audit import catalog
from agent_security_audit.checks import load_all

PREFIX = {"access": "ACCESS", "api": "API", "auth": "AUTH", "browser": "BROWSER", "cms": "CMS", "infra": "INFRA", "nextjs": "NEXT"}


class CatalogTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.checks = catalog.load()

    def test_loads_all_areas(self):
        self.assertEqual(len(self.checks), 126)
        self.assertEqual({c.area for c in self.checks}, set(PREFIX))

    def test_ids_unique(self):
        ids = [c.id for c in self.checks]
        self.assertEqual(len(ids), len(set(ids)))

    def test_ids_ascending_per_area(self):
        # Numbers rise within each area. Gaps are allowed: some blocks are reserved (for example API-30.. for the
        # code audit checks).
        by_area = defaultdict(list)
        for c in self.checks:
            by_area[c.area].append(c.id)
        for area, ids in by_area.items():
            with self.subTest(area=area):
                self.assertTrue(all(i.startswith(PREFIX[area] + "-") for i in ids))
                nums = [int(i.rsplit("-", 1)[1]) for i in ids]
                self.assertEqual(nums, sorted(set(nums)))
                self.assertEqual(nums[0], 1)

    def test_fields_valid(self):
        for c in self.checks:
            with self.subTest(check=c.id):
                self.assertIn(c.severity, catalog.SEVERITIES)
                self.assertIn(c.mode, catalog.MODES)
                self.assertTrue(1 <= c.layer <= 7)
                self.assertTrue(all(re.fullmatch(r"CWE-\d+", w) for w in c.cwe))
                self.assertTrue(c.title and c.risk and c.build and c.proof)
                self.assertTrue(set(c.stacks) <= set(catalog.STACKS))

    def test_every_source_url_https(self):
        for c in self.checks:
            self.assertTrue(c.sources, c.id)
            for s in c.sources:
                with self.subTest(check=c.id, url=s.url):
                    self.assertTrue(s.url.startswith("https://"))
                    self.assertTrue(s.title.strip())

    def test_auto_checks_match_registry(self):
        registry = load_all()
        auto_ids = {c.id for c in self.checks if c.mode == "auto"}
        self.assertEqual(set(registry), auto_ids)
        self.assertEqual(len(auto_ids), 44)
        for cid, fn in registry.items():
            self.assertEqual(fn.check_id, cid)

    def test_find(self):
        self.assertEqual(catalog.find("next-01").id, "NEXT-01")
        with self.assertRaises(catalog.CatalogError):
            catalog.find("NOPE-99")

    def test_parse_rejects_http_source(self):
        raw = catalog.by_id()["NEXT-03"].to_dict()
        raw = {"id": raw["id"], "title": raw["title"], "severity": raw["severity"], "layer": raw["osi_layer"],
               "cwe": raw["cwe"], "risk": raw["risk"], "build": raw["build"], "proof": raw["proof"],
               "mode": raw["mode"], "stacks": raw["stacks"], "sources": [{"title": "x", "url": "http://example.com"}]}
        with self.assertRaises(catalog.CatalogError):
            catalog._parse("nextjs", raw)


if __name__ == "__main__":
    unittest.main()
