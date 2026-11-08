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

from agent_security_audit import __version__, cli, install

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
        if "--yes" in argv and not install._anchored_writes_available():
            self.skipTest("secure automatic writes require directory-descriptor support; use the dry run here")
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = cli.main(["install", *argv])
        return code, buf.getvalue()

    def files(self):
        return sorted(str(p.relative_to(self.home.parent)) for p in self.home.parent.rglob("*") if p.is_file())

    def asa_err(self, *argv):
        err = io.StringIO()
        with mock.patch("sys.stderr", err):
            code, out = self.asa(*argv)
        return code, out, err.getvalue()

    def link(self, path, dest):
        try:
            path.symlink_to(dest, target_is_directory=dest.is_dir())
        except OSError:
            self.skipTest("symlinks not available")

    def project_in_home(self):
        project = self.home / "project"
        project.mkdir(exist_ok=True)
        os.chdir(project)
        return project

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

    def test_home_symlink_within_home_updates_real_file_and_backup_beside_it(self):
        dotfiles = self.home / "dotfiles"
        dotfiles.mkdir()
        real = dotfiles / "config.toml"
        real.write_text('model = "x"\n')
        real.chmod(0o640)
        link = self.home / ".codex" / "config.toml"
        link.parent.mkdir()
        self.link(link, real)
        # A backup symlink next to the link must not receive the copy.
        secret = self.home.parent / "outside-secret"
        secret.write_text("secret")
        logical_bak = link.with_name("config.toml.bak")
        self.link(logical_bak, secret)
        code, out = self.asa("codex", "--yes")
        self.assertEqual(code, 0)
        # The message names the backup where it was written: beside the real file, not beside the link.
        self.assertIn(f"backup: {os.path.realpath(real)}.bak", out)
        self.assertTrue(link.is_symlink())
        self.assertEqual(os.readlink(link), str(real))
        merged = tomllib.loads(real.read_text())
        self.assertEqual(merged["mcp_servers"]["agent-security-audit"]["command"], FAKE_MCP)
        backup = dotfiles / "config.toml.bak"
        self.assertEqual(backup.read_text(), 'model = "x"\n')
        self.assertEqual(stat.S_IMODE(backup.stat().st_mode), 0o640)
        self.assertEqual(stat.S_IMODE(real.stat().st_mode), 0o640)
        self.assertTrue(logical_bak.is_symlink())
        self.assertEqual(secret.read_text(), "secret")
        self.assertEqual(sorted(p.name for p in dotfiles.iterdir()), ["config.toml", "config.toml.bak"])

    def test_home_directory_symlink_within_home_is_followed(self):
        real_dir = self.home / "dotfiles" / "cursor"
        real_dir.mkdir(parents=True)
        real = real_dir / "mcp.json"
        original = '{"mcpServers": {"other": {"command": "x"}}, "keep": 1}\n'
        real.write_text(original)
        self.link(self.home / ".cursor", real_dir)
        code, _ = self.asa("cursor", "--yes")
        self.assertEqual(code, 0)
        data = json.loads(real.read_text())
        self.assertEqual(data["mcpServers"]["other"], {"command": "x"})
        self.assertEqual(data["keep"], 1)
        self.assertIn("agent-security-audit", data["mcpServers"])
        self.assertEqual(json.loads((real_dir / "mcp.json.bak").read_text()), json.loads(original))
        self.assertTrue((self.home / ".cursor").is_symlink())

    def test_symlinked_cwd_target_is_refused(self):
        project = self.project_in_home()
        real = self.home / "planted.json"
        real.write_text("{}\n")
        parent = project / ".vscode"
        parent.mkdir()
        link = parent / "mcp.json"
        self.link(link, real)
        code, _, err = self.asa_err("vscode", "--yes")
        self.assertEqual(code, 2, err)
        self.assertIn("symlink", err)
        self.assertEqual(real.read_text(), "{}\n")
        self.assertFalse((self.home / "planted.json.bak").exists())
        self.assertFalse((parent / "mcp.json.bak").exists())
        self.assertTrue(link.is_symlink())
        self.assertEqual(sorted(p.name for p in parent.iterdir()), ["mcp.json"])

    def test_symlinked_cwd_parent_is_refused(self):
        project = self.project_in_home()
        real_dir = self.home / "vscode-real"
        real_dir.mkdir()
        (real_dir / "keep.txt").write_text("keep")
        link = project / ".vscode"
        self.link(link, real_dir)
        code, _, err = self.asa_err("vscode", "--yes")
        self.assertEqual(code, 2, err)
        self.assertIn("symlink", err)
        self.assertEqual((real_dir / "keep.txt").read_text(), "keep")
        self.assertFalse((real_dir / "mcp.json").exists())
        self.assertFalse((real_dir / "mcp.json.bak").exists())
        self.assertTrue(link.is_symlink())

    def test_project_mcp_and_cursor_symlinks_are_refused(self):
        project = self.project_in_home()
        for rel in (".mcp.json", ".cursor/mcp.json"):
            real = self.home / rel.replace("/", "-")
            real.write_text("{}\n")
            link = project / rel
            link.parent.mkdir(parents=True, exist_ok=True)
            self.link(link, real)
            change = install.json_change(link, "mcpServers", {"command": "x", "args": []})
            install._stamp(change, self.home, project)
            self.assertTrue(change.strict, rel)
            self.assertEqual(install._abs(change.root), install._abs(project))
            with self.assertRaises(install.InstallError) as caught:
                install.apply([change])
            expected = "symlink" if install._anchored_writes_available() else "unavailable"
            self.assertIn(expected, str(caught.exception))
            self.assertEqual(real.read_text(), "{}\n")
            self.assertFalse(real.with_name(real.name + ".bak").exists())
            self.assertTrue(link.is_symlink())

    def test_home_symlink_outside_home_is_refused(self):
        outside = self.home.parent / "outside"
        outside.mkdir()
        real = outside / "config.toml"
        real.write_text('model = "x"\n')
        link = self.home / ".codex" / "config.toml"
        link.parent.mkdir()
        self.link(link, real)
        code, _, err = self.asa_err("codex", "--yes")
        self.assertEqual(code, 2, err)
        self.assertIn("outside", err)
        self.assertEqual(real.read_text(), 'model = "x"\n')
        self.assertFalse((outside / "config.toml.bak").exists())
        self.assertFalse((link.parent / "config.toml.bak").exists())
        self.assertFalse((self.home / ".agents").exists())
        self.assertTrue(link.is_symlink())

        link.unlink()
        link.parent.rmdir()
        real_dir = outside / "cursor"
        real_dir.mkdir()
        planted = real_dir / "mcp.json"
        planted.write_text("{}\n")
        parent = self.home / ".cursor"
        self.link(parent, real_dir)
        code, _, err = self.asa_err("cursor", "--yes")
        self.assertEqual(code, 2, err)
        self.assertIn("outside", err)
        self.assertEqual(planted.read_text(), "{}\n")
        self.assertFalse((real_dir / "mcp.json.bak").exists())
        self.assertTrue(parent.is_symlink())

    def test_cursor_from_home_follows_in_home_symlink_and_project_file_does_not(self):
        os.chdir(self.home)
        dotfiles = self.home / "dotfiles"
        dotfiles.mkdir()
        real = dotfiles / "mcp.json"
        real.write_text("{}\n")
        self.link(self.home / ".cursor", dotfiles)
        code, _ = self.asa("cursor", "--yes")
        self.assertEqual(code, 0)
        self.assertIn("agent-security-audit", json.loads(real.read_text())["mcpServers"])
        self.assertTrue((self.home / ".cursor").is_symlink())
        self.assertEqual((dotfiles / "mcp.json.bak").read_text(), "{}\n")

        planted = dotfiles / "project.json"
        planted.write_text("{}\n")
        project_link = self.home / ".mcp.json"
        self.link(project_link, planted)
        code, _, err = self.asa_err("claude-code", "--yes")
        self.assertEqual(code, 2, err)
        self.assertIn("symlink", err)
        self.assertEqual(planted.read_text(), "{}\n")
        self.assertFalse((dotfiles / "project.json.bak").exists())
        self.assertTrue(project_link.is_symlink())

    def test_backup_symlink_and_existing_backup_are_refused(self):
        outside = self.home.parent / "outside"
        outside.mkdir()
        secret = outside / "secret"
        secret.write_text("secret")
        path = self.home / ".cursor" / "mcp.json"
        path.parent.mkdir()
        original = '{"mcpServers": {"other": {"command": "x"}}}\n'
        path.write_text(original)
        bak = path.with_name("mcp.json.bak")
        self.link(bak, secret)
        code, _, err = self.asa_err("cursor", "--yes")
        self.assertEqual(code, 2, err)
        self.assertIn("backup", err)
        self.assertEqual(path.read_text(), original)
        self.assertTrue(bak.is_symlink())
        self.assertEqual(os.readlink(bak), str(secret))
        self.assertEqual(secret.read_text(), "secret")
        self.assertEqual(sorted(p.name for p in path.parent.iterdir()), ["mcp.json", "mcp.json.bak"])

        bak.unlink()
        bak.write_text("keep")
        code, _, err = self.asa_err("cursor", "--yes")
        self.assertEqual(code, 2, err)
        self.assertIn("backup", err)
        self.assertEqual(bak.read_text(), "keep")
        self.assertEqual(path.read_text(), original)
        self.assertEqual(sorted(p.name for p in path.parent.iterdir()), ["mcp.json", "mcp.json.bak"])

    @unittest.skipIf(os.name == "nt", "POSIX file modes")
    def test_new_file_is_private_and_user_temp_name_is_kept(self):
        planted = self.cwd / ".vscode" / "mcp.json.asa-tmp"
        planted.parent.mkdir()
        planted.write_text("user file")
        planted.chmod(0o640)
        old = os.umask(0)
        try:
            code, _ = self.asa("vscode", "--yes")
        finally:
            os.umask(old)
        self.assertEqual(code, 0)
        path = self.cwd / ".vscode" / "mcp.json"
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(planted.read_text(), "user file")
        self.assertEqual(stat.S_IMODE(planted.stat().st_mode), 0o640)
        self.assertEqual(sorted(p.name for p in path.parent.iterdir()), ["mcp.json", "mcp.json.asa-tmp"])

    @unittest.skipIf(os.name == "nt", "POSIX file modes")
    def test_update_keeps_existing_mode_on_file_and_backup(self):
        path = self.home / ".cursor" / "mcp.json"
        path.parent.mkdir()
        path.write_text('{"mcpServers": {"other": {"command": "x"}}}')
        path.chmod(0o640)
        code, _ = self.asa("cursor", "--yes")
        self.assertEqual(code, 0)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o640)
        self.assertEqual(stat.S_IMODE((path.parent / "mcp.json.bak").stat().st_mode), 0o640)
        self.assertIn("agent-security-audit", json.loads(path.read_text())["mcpServers"])

    def test_parent_swap_cannot_redirect_a_config_write(self):
        if not install._anchored_writes_available():
            self.skipTest("directory-descriptor support required")
        path = self.home / ".cursor" / "mcp.json"
        path.parent.mkdir()
        path.write_text('{"mcpServers": {"other": {"command": "x"}}}')
        outside = self.home.parent / "outside"
        outside.mkdir()
        secret = outside / "mcp.json"
        secret.write_text("outside file must stay untouched")
        held = self.home / "held-cursor"
        replace = install._replace_config

        def swap(parent, name, text):
            path.parent.rename(held)
            self.link(path.parent, outside)
            replace(parent, name, text)

        changes = install.plan("cursor", home=self.home, cwd=self.cwd)
        with mock.patch.object(install, "_replace_config", side_effect=swap):
            install.apply(changes)
        self.assertEqual(secret.read_text(), "outside file must stay untouched")
        self.assertFalse((outside / "mcp.json.bak").exists())
        self.assertIn("agent-security-audit", json.loads((held / "mcp.json").read_text())["mcpServers"])
        self.assertTrue((held / "mcp.json.bak").is_file())

    def test_unsupported_write_platform_fails_closed_without_writing(self):
        changes = install.plan("cursor", home=self.home, cwd=self.cwd)
        with (mock.patch.object(install, "_anchored_writes_available", return_value=False),
              self.assertRaisesRegex(install.InstallError, "run without --yes")):
            install.apply(changes)
        self.assertEqual(self.files(), [])

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
                         {"command": "uvx", "args": ["--from", f"agent-security-audit=={__version__}", "asa-mcp"]})
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

    def test_uvx_fallback_is_the_pinned_pypi_release_not_git_head(self):
        with mock.patch.object(install.shutil, "which", lambda name: None), \
                mock.patch.object(install.sys, "argv", [str(self.home / "nowhere" / "asa")]):
            command, args, reason = install.server_choice()
        self.assertEqual((command, args), ("uvx", ["--from", f"agent-security-audit=={__version__}", "asa-mcp"]))
        self.assertIn("pinned", reason)
        self.assertFalse(any("git+" in a for a in args))

    def test_project_virtualenv_asa_mcp_is_not_written_into_configs(self):
        # A project venv can be deleted at any time; the pinned uvx command is written instead.
        root = Path(tempfile.mkdtemp(dir=self.home))
        venv = root / "proj" / ".venv"
        (venv / "bin").mkdir(parents=True)
        (venv / "pyvenv.cfg").write_text("home = /usr/bin\n")
        entry = str(venv / "bin" / "asa-mcp")
        with mock.patch.object(install.shutil, "which", lambda name: entry), \
                mock.patch.object(install, "_ephemeral", lambda path: False):
            command, _, reason = install.server_choice()
            self.assertEqual(command, "uvx")
            self.assertIn("virtual environment", reason)
            code, out = self.asa("cursor")
            written = install.plan("cursor", self.home, self.cwd)[0].new_text
        self.assertEqual(code, 0)
        self.assertIn(f"Server command: uvx --from agent-security-audit=={__version__} asa-mcp", out)
        self.assertIn("virtual environment", out)
        self.assertNotIn(entry, written)
        self.assertEqual(json.loads(written)["mcpServers"]["agent-security-audit"]["command"], "uvx")

    def test_pipx_and_uv_tool_environments_are_stable(self):
        root = Path(tempfile.mkdtemp(dir=self.home))
        for managed in (root / "pipx" / "venvs" / "agent-security-audit",
                        root / "uv" / "tools" / "agent-security-audit"):
            (managed / "bin").mkdir(parents=True)
            (managed / "pyvenv.cfg").write_text("home = /usr/bin\n")
            entry = str(managed / "bin" / "asa-mcp")
            with mock.patch.object(install.shutil, "which", lambda name, e=entry: e), \
                    mock.patch.object(install, "_ephemeral", lambda path: False):
                self.assertEqual(install.server_command(), (entry, []), entry)

    def test_dry_run_explains_the_server_command(self):
        code, out = self.asa("cursor")
        self.assertEqual(code, 0)
        self.assertIn(f"Server command: {FAKE_MCP}", out)
        self.assertIn("installed asa-mcp", out)

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
