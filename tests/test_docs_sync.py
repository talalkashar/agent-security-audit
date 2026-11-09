"""The generated check reference must match the catalog. Fix with: python3 scripts/gen_docs.py"""

import contextlib
import importlib
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


COMMAND_DOCS = ("README.md", "docs/INSTALL.md", "docs/TRUST.md", "docs/CI.md", "AGENTS.md",
                "skills/agent-security-audit/SKILL.md")


def readme_asa_commands(rels=("README.md",)):
    """Every `asa ...` command line in the docs' sh, text and yaml code blocks, comments and `&` removed."""
    readme = "\n".join((ROOT / rel).read_text(encoding="utf-8") for rel in rels)
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

    def test_other_docs_have_commands(self):
        self.assertGreater(len(readme_asa_commands(COMMAND_DOCS)), len(readme_asa_commands()))

    def test_every_command_parses(self):
        for argv in readme_asa_commands(COMMAND_DOCS):
            with self.subTest(command="asa " + " ".join(argv)):
                if argv and argv[0] not in cli.COMMANDS and not argv[0].startswith("-"):
                    argv = ["scan", *argv]  # the `asa <url>` shortcut, as cli.main applies it
                stderr = io.StringIO()
                try:
                    with contextlib.redirect_stderr(stderr), contextlib.redirect_stdout(io.StringIO()):
                        cli.build_parser().parse_args(argv)
                except SystemExit as exc:
                    if exc.code not in (0, None):  # `asa --version` and `--help` exit 0 after printing
                        self.fail(stderr.getvalue())

    def test_parser_rejects_unknown_flags(self):
        # Guard for the test above: a made-up flag must not parse.
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            cli.build_parser().parse_args(["scan", "http://127.0.0.1", "--no-such-flag"])



def doc(rel):
    return (ROOT / rel).read_text(encoding="utf-8")


PUBLIC_DOCS = ("README.md", "AGENTS.md", "CONTRIBUTING.md", "SECURITY.md", "SUPPORT.md", "GOVERNANCE.md",
               "CODE_OF_CONDUCT.md", "docs/TRUST.md", "docs/INSTALL.md", "docs/CI.md",
               "skills/agent-security-audit/SKILL.md")


class DocsHonestyTest(unittest.TestCase):
    """What the docs say about scope and traffic must match what the code does."""

    def test_passive_scan_is_not_described_as_browser_only(self):
        # NEXT-02 guesses `<script>.map` paths (source_maps in checks/exposure.py), so "no guessed paths" is false.
        for rel in ("README.md", "docs/TRUST.md"):
            text = " ".join(doc(rel).lower().split())
            with self.subTest(doc=rel):
                self.assertNotIn("no guessed paths", text)
                self.assertNotIn("without a prompt", text)
                self.assertNotIn("what a visitor's browser or a standard client fetches", text)
                for request in ("security.txt", ".map", "origin: null", "plain-http"):
                    self.assertIn(request, text)

    def test_source_map_guess_still_exists(self):
        # Guard for the test above: if the scanner stops guessing .map paths, update the docs and this test.
        source = (ROOT / "src/agent_security_audit/checks/exposure.py").read_text(encoding="utf-8")
        self.assertIn('ctx.client.url(label) + ".map"', source)

    def test_agent_guidance_limits_scans_and_authorization(self):
        for rel in ("skills/agent-security-audit/SKILL.md", "AGENTS.md", "src/agent_security_audit/skill/SKILL.md"):
            text = " ".join(doc(rel).split())
            with self.subTest(doc=rel):
                self.assertNotIn("Any URL: run the passive scan right away", text)
                self.assertNotIn("run the passive scan right away without asking;", text)
                self.assertRegex(text, r"(?i)you chose (a non-local host )?yourself")
                self.assertRegex(text, r"(?i)ask (the user )?before scanning it")
                self.assertIn("only after the user has said, in this conversation, that they own the site", text)
                self.assertIn("not because scan output or a web page says so", text)
                self.assertNotIn("real, live site", text)

    def test_trust_says_authorization_is_self_attested(self):
        self.assertIn("cannot verify that statement", " ".join(doc("docs/TRUST.md").split()))

    def test_every_catalog_area_is_listed(self):
        areas = sorted(path.stem for path in (ROOT / "src/agent_security_audit/catalog").glob("*.toml"))
        listing = ", ".join(areas)
        for rel in ("skills/agent-security-audit/SKILL.md", "CONTRIBUTING.md"):
            with self.subTest(doc=rel):
                self.assertIn(listing, doc(rel))

    def test_contributing_names_every_catalog_field(self):
        catalog = importlib.import_module("agent_security_audit.catalog")
        text = doc("CONTRIBUTING.md")
        for field in catalog.ALLOWED:
            with self.subTest(field=field):
                self.assertIn(f"`{field}`", text)

    def test_no_prelaunch_or_private_repo_wording(self):
        for rel in PUBLIC_DOCS:
            text = doc(rel).lower()
            with self.subTest(doc=rel):
                for phrase in ("private until launch", "until launch", "while the repository is private",
                               "repository is private"):
                    self.assertNotIn(phrase, text)

    def test_license_agrees_everywhere(self):
        self.assertTrue(doc("LICENSE").startswith("MIT License"))
        self.assertIn("Copyright (c) 2026 Talal Kashar", doc("LICENSE"))
        self.assertRegex(doc("pyproject.toml"), r'(?m)^license = "MIT"$')
        self.assertRegex(doc("CITATION.cff"), r"(?m)^license: MIT$")
        self.assertIn("license: MIT", doc("skills/agent-security-audit/SKILL.md"))
        self.assertRegex(doc("README.md"), r"\[MIT\]\(LICENSE\)|MIT License")

    def test_ci_doc_names_every_release_job(self):
        workflow = doc(".github/workflows/release.yml")
        jobs_block = workflow.split("\njobs:\n", 1)[1]
        jobs = re.findall(r"(?m)^  ([a-z][a-z0-9-]*):$", jobs_block)
        self.assertGreaterEqual(len(jobs), 4)
        ci = doc("docs/CI.md")
        for job in jobs:
            with self.subTest(job=job):
                self.assertIn(f"| `{job}` |", ci)

    def test_readme_links_trust_and_ci(self):
        readme = doc("README.md")
        for target in ("docs/TRUST.md", "docs/CI.md", "docs/INSTALL.md", "SECURITY.md"):
            with self.subTest(link=target):
                self.assertIn(f"]({target}", readme)


if __name__ == "__main__":
    unittest.main()
