"""`asa install <agent>`, the skill's frontmatter against the Agent Skills spec, and the install files."""

import io
import json
import os
import re
import stat
import tempfile
import tomllib
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from agent_security_audit import cli, install

ROOT = Path(__file__).resolve().parent.parent
SKILL = ROOT / "skills" / "agent-security-audit" / "SKILL.md"
FAKE_MCP = "/opt/asa/bin/asa-mcp"


class InstallTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.home = Path(tmp.name) / "home"
        self.cwd = Path(tmp.name) / "project"
        self.home.mkdir()
        self.cwd.mkdir()
        env = mock.patch.dict(os.environ, {"HOME": str(self.home), "APPDATA": str(self.home / "AppData")})
        env.start()
        self.addCleanup(env.stop)
        which = mock.patch.object(install.shutil, "which", lambda name: FAKE_MCP if name == "asa-mcp" else None)
        which.start()
        self.addCleanup(which.stop)
        old = os.getcwd()
        os.chdir(self.cwd)
        self.addCleanup(os.chdir, old)

    def asa(self, *argv):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = cli.main(["install", *argv])
        return code, buf.getvalue()

    def files(self):
        return sorted(str(p.relative_to(self.home.parent)) for p in self.home.parent.rglob("*") if p.is_file())

    def test_dry_run_writes_nothing(self):
        for agent in install.AGENTS:
            code, out = self.asa(agent)
            self.assertEqual(code, 0, agent)
            self.assertIn("Dry run: nothing was written", out)
            self.assertIn("would create", out)
        self.assertEqual(self.files(), [])

    def test_cursor_merges_and_keeps_other_servers(self):
        path = self.home / ".cursor" / "mcp.json"
        path.parent.mkdir()
        original = {"mcpServers": {"other": {"command": "x"}}, "keep": 1}
        path.write_text(json.dumps(original))
        code, out = self.asa("cursor", "--yes")
        self.assertEqual(code, 0)
        data = json.loads(path.read_text())
        self.assertEqual(data["mcpServers"]["other"], {"command": "x"})
        self.assertEqual(data["keep"], 1)
        self.assertEqual(data["mcpServers"]["agent-security-audit"], {"command": FAKE_MCP, "args": []})
        self.assertEqual(json.loads((path.parent / "mcp.json.bak").read_text()), original)
        # Idempotent: a second run changes nothing and makes no new backup.
        (path.parent / "mcp.json.bak").unlink()
        code, out = self.asa("cursor", "--yes")
        self.assertIn("already set up", out)
        self.assertIn("Nothing to change", out)
        self.assertFalse((path.parent / "mcp.json.bak").exists())

    def test_existing_entry_with_other_settings_is_left_alone(self):
        path = self.home / ".gemini" / "settings.json"
        path.parent.mkdir()
        path.write_text(json.dumps({"mcpServers": {"agent-security-audit": {"command": "mine"}}}))
        code, out = self.asa("gemini", "--yes")
        self.assertEqual(code, 1)
        self.assertIn("left as is", out)
        self.assertEqual(json.loads(path.read_text())["mcpServers"]["agent-security-audit"], {"command": "mine"})

    def test_invalid_json_is_never_overwritten(self):
        path = self.cwd / ".vscode" / "mcp.json"
        path.parent.mkdir()
        path.write_text('{ // comment\n "servers": {} }')
        err = io.StringIO()
        with mock.patch("sys.stderr", err):
            code, _ = self.asa("vscode", "--yes")
        self.assertEqual(code, 2)
        self.assertIn("not plain JSON", err.getvalue())
        self.assertEqual(path.read_text(), '{ // comment\n "servers": {} }')

    def test_non_ascii_text_is_kept_as_written(self):
        path = self.home / ".cursor" / "mcp.json"
        path.parent.mkdir()
        path.write_text('{"mcpServers": {"café": {"command": "x"}}}', encoding="utf-8")
        self.asa("cursor", "--yes")
        text = path.read_text(encoding="utf-8")
        self.assertIn('"café"', text)
        self.assertNotIn("\\u00e9", text)

    @unittest.skipIf(os.name == "nt", "POSIX file modes")
    def test_private_config_stays_private(self):
        path = self.home / ".cursor" / "mcp.json"
        path.parent.mkdir()
        path.write_text('{"mcpServers": {"other": {"command": "x", "env": {"API_KEY": "k"}}}}')
        path.chmod(0o600)
        self.asa("cursor", "--yes")
        self.assertIn("agent-security-audit", json.loads(path.read_text())["mcpServers"])
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE((path.parent / "mcp.json.bak").stat().st_mode), 0o600)

    def test_symlinked_config_is_written_through_the_link(self):
        dotfiles = self.home / "dotfiles"
        dotfiles.mkdir()
        real = dotfiles / "config.toml"
        real.write_text('model = "x"\n')
        link = self.home / ".codex" / "config.toml"
        link.parent.mkdir()
        try:
            link.symlink_to(real)
        except OSError:
            self.skipTest("symlinks not available")
        code, _ = self.asa("codex", "--yes")
        self.assertEqual(code, 0)
        self.assertTrue(link.is_symlink())
        self.assertIn("agent-security-audit", tomllib.loads(real.read_text())["mcp_servers"])
        self.assertEqual((link.parent / "config.toml.bak").read_text(), 'model = "x"\n')
        self.assertEqual(sorted(p.name for p in dotfiles.iterdir()), ["config.toml"])

    def test_vscode_uses_servers_with_type(self):
        self.asa("vscode", "--yes")
        data = json.loads((self.cwd / ".vscode" / "mcp.json").read_text())
        self.assertEqual(data, {"servers": {"agent-security-audit": {"type": "stdio", "command": FAKE_MCP,
                                                                     "args": []}}})

    def test_claude_code_writes_project_mcp_json_and_skill(self):
        self.asa("claude-code", "--yes")
        data = json.loads((self.cwd / ".mcp.json").read_text())
        self.assertIn("agent-security-audit", data["mcpServers"])
        skill = self.home / ".claude" / "skills" / "agent-security-audit" / "SKILL.md"
        self.assertEqual(skill.read_text(), SKILL.read_text())

    def test_claude_desktop_paths(self):
        home, cwd = Path("/h"), Path("/c")
        self.assertEqual(install.mcp_targets("claude-desktop", home, cwd, "darwin")[0][0],
                         home / "Library/Application Support/Claude/claude_desktop_config.json")
        self.assertEqual(install.mcp_targets("claude-desktop", home, cwd, "linux")[0][0],
                         home / ".config/Claude/claude_desktop_config.json")

    def test_windsurf_writes_devin_path_and_legacy_when_present(self):
        (self.home / ".codeium" / "windsurf").mkdir(parents=True)
        with mock.patch.object(install.sys, "platform", "linux"):
            self.asa("windsurf", "--yes")
        for path in (self.home / ".config/devin/mcp_config.json", self.home / ".codeium/windsurf/mcp_config.json"):
            self.assertIn("agent-security-audit", json.loads(path.read_text())["mcpServers"], path)

    def test_codex_appends_a_table_and_never_rewrites(self):
        path = self.home / ".codex" / "config.toml"
        path.parent.mkdir()
        original = 'model = "x"\n\n[mcp_servers.other]\ncommand = "o"  # keep this comment\n'
        path.write_text(original)
        code, _ = self.asa("codex", "--yes", "--uvx")
        self.assertEqual(code, 0)
        text = path.read_text()
        self.assertTrue(text.startswith(original))
        data = tomllib.loads(text)
        self.assertEqual(data["mcp_servers"]["other"], {"command": "o"})
        self.assertEqual(data["mcp_servers"]["agent-security-audit"],
                         {"command": "uvx", "args": ["--from", f"git+{install.REPO}", "asa-mcp"]})
        self.assertEqual((path.parent / "config.toml.bak").read_text(), original)
        self.asa("codex", "--yes")
        self.assertEqual(path.read_text(), text)  # already there: untouched
        skill = self.home / ".agents" / "skills" / "agent-security-audit" / "SKILL.md"
        self.assertTrue(skill.is_file())

    def test_codex_file_without_trailing_newline_and_inline_table(self):
        path = self.home / ".codex" / "config.toml"
        path.parent.mkdir()
        path.write_text('model = "x"')
        self.asa("codex", "--yes")
        self.assertEqual(tomllib.loads(path.read_text())["mcp_servers"]["agent-security-audit"]["command"], FAKE_MCP)
        path.write_text('mcp_servers = { other = { command = "o" } }\n')
        code, out = self.asa("codex", "--yes")
        self.assertEqual(code, 1)
        self.assertIn("inline table", out)
        self.assertEqual(path.read_text(), 'mcp_servers = { other = { command = "o" } }\n')

    def test_codex_server_already_under_an_mcp_servers_table_is_not_declared_twice(self):
        path = self.home / ".codex" / "config.toml"
        path.parent.mkdir()
        for original in ('[mcp_servers]\nagent-security-audit = { command = "x" }\n',
                         '[mcp_servers]\nagent-security-audit.command = "x"\n',
                         'mcp_servers.agent-security-audit.command = "x"\n'):
            path.write_text(original)
            code, out = self.asa("codex", "--yes")
            self.assertEqual(code, 0, original)
            self.assertIn("already set up", out)
            self.assertEqual(path.read_text(), original)

    def test_codex_never_writes_toml_that_does_not_parse(self):
        path = self.home / ".codex" / "config.toml"
        path.parent.mkdir()
        original = '[mcp_servers]\nother = { command = "o" }\n[mcp_servers.other.env]\nK = "v"\n'
        self.assertRaises(tomllib.TOMLDecodeError, tomllib.loads, original)
        path.write_text(original)
        err = io.StringIO()
        with mock.patch("sys.stderr", err):
            code, _ = self.asa("codex", "--yes")
        self.assertEqual(code, 2)
        self.assertIn("not valid TOML", err.getvalue())
        self.assertEqual(path.read_text(), original)
        path.write_text('model = "x"\n')  # appended text that would not parse is never written
        with mock.patch.object(install.tomllib, "loads", side_effect=[{}, tomllib.TOMLDecodeError("x")]):
            change = install.toml_change(path, "c", [])
        self.assertEqual((change.action, change.new_text), ("conflict", None))

    def test_throwaway_uvx_environment_is_not_written_into_configs(self):
        # Run through `uvx --from ... asa install`, the only asa-mcp on PATH is in uv's cache and may vanish.
        cached = str(Path.home() / ".cache/uv/archive-v0/abc/bin/asa-mcp")
        temp = os.path.join(tempfile.gettempdir(), ".tmpX", "bin", "asa-mcp")
        for path in (cached, temp):
            with mock.patch.object(install.shutil, "which", lambda name, p=path: p):
                self.assertEqual(install.server_command()[0], "uvx", path)
        self.assertEqual(install.server_command(), (FAKE_MCP, []))

    def test_packaged_skill_matches_repo_skill(self):
        self.assertEqual(install.skill_text(), SKILL.read_text(encoding="utf-8"))


def frontmatter(text):
    m = re.match(r"---\n(.*?)\n---\n", text, re.DOTALL)
    assert m, "no frontmatter"
    fields = {}
    for line in m.group(1).splitlines():
        key, _, value = line.partition(":")
        fields[key.strip()] = value.strip()
    return fields


class SkillSpecTest(unittest.TestCase):
    """https://agentskills.io/specification"""

    def test_frontmatter_follows_the_agent_skills_spec(self):
        fields = frontmatter(SKILL.read_text(encoding="utf-8"))
        allowed = {"name", "description", "license", "compatibility", "metadata", "allowed-tools"}
        self.assertLessEqual(set(fields), allowed)
        name = fields["name"]
        self.assertRegex(name, r"^[a-z0-9]+(-[a-z0-9]+)*$")
        self.assertLessEqual(len(name), 64)
        self.assertEqual(name, SKILL.parent.name)
        self.assertTrue(1 <= len(fields["description"]) <= 1024)
        self.assertTrue(1 <= len(fields.get("compatibility", "x")) <= 500)

    def test_skill_needs_no_agent_specific_tool(self):
        text = SKILL.read_text(encoding="utf-8")
        self.assertNotIn("allowed-tools", frontmatter(text))
        for tool in ("Bash(", "WebFetch", "TodoWrite", "mcp__"):
            self.assertNotIn(tool, text)
        self.assertLess(len(text.splitlines()), 500)

    def test_marketplace_points_at_the_repo_root(self):
        market = json.loads((ROOT / ".claude-plugin" / "marketplace.json").read_text())
        plugin = json.loads((ROOT / ".claude-plugin" / "plugin.json").read_text())
        self.assertEqual(market["plugins"][0]["name"], plugin["name"])
        self.assertTrue((ROOT / market["plugins"][0]["source"] / "skills" / plugin["name"] / "SKILL.md").is_file())


class ReleaseWorkflowTest(unittest.TestCase):
    def test_release_uses_trusted_publishing_with_pinned_actions(self):
        text = (ROOT / ".github" / "workflows" / "release.yml").read_text()
        self.assertIn("id-token: write", text)
        self.assertIn("types: [published]", text)
        self.assertNotIn("password:", text)
        uses = re.findall(r"uses:\s*(\S+)", text)
        self.assertTrue(uses)
        for ref in uses:
            self.assertRegex(ref, r"@[0-9a-f]{40}$", ref)


class DocsAccuracyTest(unittest.TestCase):
    def test_allow_supabase_is_described_as_the_check_runs(self):
        from agent_security_audit import mcp_server
        desc = mcp_server.TOOLS_BY_NAME["run_scan"]["inputSchema"]["properties"]["allow_supabase"]["description"]
        self.assertIn("HEAD", desc)
        self.assertIn("count=exact", desc)
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("one `HEAD` request per table with `Prefer: count=exact`", readme)


if __name__ == "__main__":
    unittest.main()
