"""The generated check reference must match the catalog. Fix with: python3 scripts/gen_docs.py"""

import contextlib
import importlib.util
import io
import re
import shlex
import unittest
from pathlib import Path

from agent_security_audit import cli

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


    def test_headline_and_osi_table_are_generated(self):
        readme = self.outputs["README.md"]
        for start, end, _ in self.gen.BLOCKS:
            self.assertIn(start, readme)
            self.assertIn(end, readme)
        checks = self.gen.catalog.load()
        automated = {cid for cid in self.gen.load_all() if self.gen.catalog.by_id().get(cid)}
        n = self.gen.coverage(checks, automated)
        self.assertEqual(n["total"], len(checks))
        self.assertIn(f"**{n['total']} checks, mapped to OSI layers 1 to 7:** {n['live']} live proof tests", readme)
        self.assertIn(f"{n['code']} settled from source code", readme)
        self.assertIn(f"{n['guided']} guided checks", readme)
        self.assertEqual(n["guided"], n["total"] - n["live"] - n["code"] + n["both"])
        for layer, name in self.gen.LAYERS.items():
            self.assertIn(f"| {layer} {name} | {self.gen.LAYER_SCOPE[layer]} |", readme)

    def test_readme_makes_no_overclaims(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8").lower()
        for phrase in ("every security flaw", "every flaw", "no accounts to create", "proves the site is secure",
                       "site is secure", "zero flaws"):
            self.assertFalse(phrase in readme, f"README overclaims: {phrase!r}")

    def test_readme_screenshot_exists_and_is_small(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        images = re.findall(r"!\[[^\]]*\]\((docs/assets/[^)]+)\)", readme)
        self.assertTrue(images, "README lost its report screenshot")
        for rel in images:
            path = ROOT / rel
            self.assertTrue(path.is_file(), rel)
            self.assertLess(path.stat().st_size, 400_000, rel)


def readme_asa_commands():
    """Every `asa ...` command line in the README's sh, text and yaml code blocks, comments and `&` removed."""
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    commands = []
    for block in re.findall(r"^ *```(?:sh|text|yaml)\n(.*?)^ *```", readme, re.DOTALL | re.MULTILINE):
        for line in block.splitlines():
            line = line.strip().removeprefix("$ ").removeprefix("- run: ")
            if not line.startswith("asa "):
                continue
            words = shlex.split(line, comments=True)
            commands.append([w for w in words if w != "&"][1:])
    return commands


class ReadmeCommandsTest(unittest.TestCase):
    """Every asa command the README shows must parse with the real CLI parser (subcommands and flags exist)."""

    def test_commands_found(self):
        self.assertGreaterEqual(len(readme_asa_commands()), 15)

    def test_every_command_parses(self):
        for argv in readme_asa_commands():
            with self.subTest(command="asa " + " ".join(argv)):
                if argv and argv[0] not in cli.COMMANDS and not argv[0].startswith("-"):
                    argv = ["scan", *argv]  # the `asa <url>` shortcut, as cli.main applies it
                stderr = io.StringIO()
                try:
                    with contextlib.redirect_stderr(stderr):
                        cli.build_parser().parse_args(argv)
                except SystemExit:
                    self.fail(stderr.getvalue())

    def test_parser_rejects_unknown_flags(self):
        # Guard for the test above: a made-up flag must not parse.
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            cli.build_parser().parse_args(["scan", "http://127.0.0.1", "--no-such-flag"])


if __name__ == "__main__":
    unittest.main()
