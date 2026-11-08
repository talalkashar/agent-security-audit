"""Release consistency: one version everywhere, pinned install commands, and the release workflow's fixed parts."""

import base64
import json
import re
import tomllib
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from agent_security_audit import __version__, install

ROOT = Path(__file__).resolve().parent.parent
PINNED_DOCS = ("README.md", "AGENTS.md", "docs/INSTALL.md", "docs/TRUST.md", "skills/agent-security-audit/SKILL.md",
               "src/agent_security_audit/skill/SKILL.md")


def text(rel):
    return (ROOT / rel).read_text(encoding="utf-8")


class VersionTest(unittest.TestCase):
    def test_every_version_field_matches(self):
        pyproject = tomllib.loads(text("pyproject.toml"))["project"]["version"]
        plugin = json.loads(text(".claude-plugin/plugin.json"))["version"]
        citation = re.search(r"(?m)^version:\s*(\S+)\s*$", text("CITATION.cff")).group(1)
        self.assertEqual({"pyproject.toml": pyproject, "__init__.py": __version__, "plugin.json": plugin,
                          "CITATION.cff": citation}, dict.fromkeys(
            ("pyproject.toml", "__init__.py", "plugin.json", "CITATION.cff"), __version__))

    def test_changelog_has_an_entry_for_the_version(self):
        self.assertRegex(text("CHANGELOG.md"), rf"(?m)^## {re.escape(__version__)}\b")

    def test_build_backend_floor_supports_spdx_license(self):
        requires = tomllib.loads(text("pyproject.toml"))["build-system"]["requires"]
        self.assertIn("setuptools>=77", requires)


class PinnedInstallTest(unittest.TestCase):
    def test_documented_pins_match_the_version(self):
        for rel in PINNED_DOCS:
            pins = set(re.findall(r"agent-security-audit==([0-9][^\s\"'`),]*)", text(rel)))
            self.assertTrue(pins, f"{rel} has no pinned install command")
            self.assertEqual(pins, {__version__}, rel)

    def test_uvx_commands_use_the_pinned_release(self):
        # git+ installs stay as a "latest from source" option, but never as the uvx command an agent runs.
        for rel in PINNED_DOCS:
            for line in text(rel).splitlines():
                self.assertNotRegex(line, r"uvx --from git\+|\"--from\",\s*\"git\+", f"{rel}: {line}")

    def test_install_writes_the_pinned_release(self):
        self.assertEqual(install.UVX_ARGS, ["--from", f"agent-security-audit=={__version__}", "asa-mcp"])

    def test_cursor_deep_link_runs_the_pinned_release(self):
        link = re.search(r"cursor://\S+", text("docs/INSTALL.md")).group(0)
        config = parse_qs(urlsplit(link).query)["config"][0]
        self.assertEqual(json.loads(base64.b64decode(config)), {"command": "uvx", "args": install.UVX_ARGS})


class WorkflowTest(unittest.TestCase):
    def test_actions_are_pinned_by_full_sha(self):
        for path in sorted((ROOT / ".github" / "workflows").glob("*.yml")):
            for line in path.read_text(encoding="utf-8").splitlines():
                m = re.search(r"uses:\s*(\S+)", line)
                if m:
                    self.assertRegex(m.group(1), r"@[0-9a-f]{40}$", f"{path.name}: {line.strip()}")
                    self.assertRegex(line, r"# v\d", f"{path.name}: version comment missing: {line.strip()}")

    def test_release_keeps_the_trusted_publisher_binding(self):
        # PyPI's trusted publisher is bound to this file name and environment; renaming either breaks publishing.
        release = text(".github/workflows/release.yml")
        self.assertIn("name: pypi", release)
        self.assertIn("pypa/gh-action-pypi-publish@", release)
        self.assertRegex(release, r"(?m)^permissions:\s*\n\s+contents: read")


if __name__ == "__main__":
    unittest.main()
