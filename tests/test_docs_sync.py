"""The generated check reference must match the catalog. Fix with: python3 scripts/gen_docs.py"""

import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def load_gen_docs():
    spec = importlib.util.spec_from_file_location("gen_docs", ROOT / "scripts" / "gen_docs.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class DocsSyncTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.gen = load_gen_docs()
        cls.outputs = cls.gen.outputs()

    def test_generated_files_match_disk(self):
        for rel, expected in self.outputs.items():
            with self.subTest(path=rel):
                path = ROOT / rel
                self.assertTrue(path.exists(), f"{rel} is missing; run python3 scripts/gen_docs.py")
                self.assertEqual(path.read_text(encoding="utf-8"), expected,
                                 f"{rel} is out of date; run python3 scripts/gen_docs.py")

    def test_every_area_and_check_documented(self):
        checks = self.gen.catalog.load()
        for area in {c.area for c in checks}:
            self.assertIn(f"docs/checks/{area}.md", self.outputs)
        index = self.outputs["docs/checks/README.md"]
        for c in checks:
            self.assertIn(f"## {c.id} ", self.outputs[f"docs/checks/{c.area}.md"])
            self.assertIn(f"[{c.id}]", index)

    def test_readme_has_catalog_block(self):
        self.assertIn("README.md", self.outputs, "README.md lost its catalog markers")
        self.assertIn(f"**{len(self.gen.catalog.load())}**", self.outputs["README.md"])

    def test_no_stray_generated_files(self):
        on_disk = {f"docs/checks/{p.name}" for p in (ROOT / "docs" / "checks").glob("*.md")}
        self.assertEqual(on_disk, {k for k in self.outputs if k.startswith("docs/checks/")})


if __name__ == "__main__":
    unittest.main()
