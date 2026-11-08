"""`asa install <agent>`: add the asa-mcp server (and, where the agent loads skills from a known folder, the skill)
to one agent's config.

Every path and file shape here comes from the agent's own documentation (see docs/INSTALL.md for the links).
The default is a dry run that prints what would change. With --yes it writes, after copying an existing file to
<file>.bak. It never removes or rewrites another server: JSON configs get one key merged in, and Codex's TOML gets
one table appended to the end of the file.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import sys
import tempfile
from dataclasses import dataclass
from importlib import resources
from pathlib import Path

NAME = "agent-security-audit"
REPO = "https://github.com/talalkashar/agent-security-audit"
AGENTS = ("claude-code", "claude-desktop", "cursor", "vscode", "windsurf", "codex", "gemini", "antigravity")
CODEX_TABLE = re.compile(r'^\s*\[\s*mcp_servers\s*\.\s*(?:"agent-security-audit"|agent-security-audit)\s*\]',
                         re.MULTILINE)
INLINE_SERVERS = re.compile(r"^\s*mcp_servers\s*=", re.MULTILINE)


class InstallError(Exception):
    pass


@dataclass
class Change:
    path: Path
    action: str  # create, update, unchanged, conflict
    added: str  # what is added, as the file's own syntax
    new_text: str | None = None  # full new file text when action is create or update
    note: str = ""


def server_command(uvx=False):
    """The command and args the agent runs: the installed asa-mcp by absolute path, else uvx from the repository."""
    if not uvx:
        found = shutil.which("asa-mcp")
        if not found:
            beside = Path(sys.argv[0]).resolve().parent / ("asa-mcp.exe" if os.name == "nt" else "asa-mcp")
            found = str(beside) if beside.is_file() else None
        if found and not _ephemeral(found):
            return found, []
    return "uvx", ["--from", f"git+{REPO}", "asa-mcp"]


def _ephemeral(path):
    """True for an asa-mcp inside a throwaway environment (`uvx` caches, temp folders) that may vanish later."""
    real = Path(path).resolve()
    if any(part.startswith("archive-v") for part in real.parts):  # uv's cached tool environments
        return True
    return Path(tempfile.gettempdir()).resolve() in real.parents


def _appdata(home):
    return Path(os.environ.get("APPDATA") or home / "AppData" / "Roaming")


def mcp_targets(agent, home, cwd, platform=None):
    """(path, servers key, stdio entry needs "type") for each MCP config file the agent reads."""
    platform = platform or sys.platform
    if agent == "claude-code":
        return [(cwd / ".mcp.json", "mcpServers", False)]
    if agent == "claude-desktop":
        if platform == "darwin":
            base = home / "Library" / "Application Support" / "Claude"
        elif platform.startswith("win"):
            base = _appdata(home) / "Claude"
        else:
            base = home / ".config" / "Claude"
        return [(base / "claude_desktop_config.json", "mcpServers", False)]
    if agent == "cursor":
        return [(home / ".cursor" / "mcp.json", "mcpServers", False)]
    if agent == "vscode":
        return [(cwd / ".vscode" / "mcp.json", "servers", True)]
    if agent == "windsurf":
        # Windsurf is now Devin Desktop; its docs name ~/.config/devin/mcp_config.json. Older Windsurf builds read
        # ~/.codeium/windsurf/mcp_config.json, so that file is updated too when the folder exists.
        base = _appdata(home) / "devin" if platform.startswith("win") else home / ".config" / "devin"
        out = [(base / "mcp_config.json", "mcpServers", False)]
        legacy = home / ".codeium" / "windsurf"
        if legacy.is_dir():
            out.append((legacy / "mcp_config.json", "mcpServers", False))
        return out
    if agent == "codex":
        return [(home / ".codex" / "config.toml", None, False)]
    if agent == "gemini":
        return [(home / ".gemini" / "settings.json", "mcpServers", False)]
    if agent == "antigravity":
        return [(home / ".gemini" / "config" / "mcp_config.json", "mcpServers", False)]
    raise InstallError(f"unknown agent {agent}; choose from: {', '.join(AGENTS)}")


def skill_targets(agent, home):
    """Folders the agent loads personal skills from, per its docs."""
    if agent == "claude-code":
        return [home / ".claude" / "skills" / NAME / "SKILL.md"]
    if agent == "codex":
        return [home / ".agents" / "skills" / NAME / "SKILL.md"]
    return []


def skill_text():
    return resources.files("agent_security_audit").joinpath("skill", "SKILL.md").read_text(encoding="utf-8")


def _read(path):
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise InstallError(f"cannot read {path}: {exc.strerror or exc}") from exc


def json_change(path, key, entry):
    text = _read(path)
    added = json.dumps({key: {NAME: entry}}, indent=2)
    if text is None or not text.strip():
        return Change(path, "create" if text is None else "update", added,
                      json.dumps({key: {NAME: entry}}, indent=2) + "\n")
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise InstallError(f"{path} is not plain JSON ({exc.msg}, line {exc.lineno}); it was left as is. Add this "
                           f"by hand:\n{added}") from exc
    if not isinstance(data, dict) or not isinstance(data.get(key, {}), dict):
        raise InstallError(f"{path}: expected an object with a \"{key}\" object; it was left as is")
    servers = data.get(key, {})
    if NAME in servers:
        if servers[NAME] == entry:
            return Change(path, "unchanged", added)
        return Change(path, "conflict", added, note=f"an \"{NAME}\" entry with other settings is already there; "
                      "it was left as is (remove it first to replace it)")
    data[key] = {**servers, NAME: entry}
    return Change(path, "update", added, json.dumps(data, indent=2) + "\n")


def _toml_str(value):
    return json.dumps(value)  # a JSON string is a valid TOML basic string


def toml_change(path, command, args):
    text = _read(path)
    lines = [f"[mcp_servers.{NAME}]", f"command = {_toml_str(command)}"]
    if args:
        lines.append("args = [" + ", ".join(_toml_str(a) for a in args) + "]")
    added = "\n".join(lines) + "\n"
    if text is None:
        return Change(path, "create", added, added)
    if CODEX_TABLE.search(text):
        return Change(path, "unchanged", added, note=f"[mcp_servers.{NAME}] is already in the file; it was left as is")
    if INLINE_SERVERS.search(text):
        return Change(path, "conflict", added, note="mcp_servers is an inline table there, so a table cannot be "
                      "appended; it was left as is (add the server to that inline table by hand)")
    body = text if not text or text.endswith("\n") else text + "\n"
    return Change(path, "update", added, body + ("\n" if body.strip() else "") + added)


def skill_change(path, text):
    old = _read(path)
    if old == text:
        return Change(path, "unchanged", "the agent-security-audit skill")
    return Change(path, "create" if old is None else "update", "the agent-security-audit skill", text)


def plan(agent, home=None, cwd=None, uvx=False, platform=None):
    home = Path(home) if home else Path.home()
    cwd = Path(cwd) if cwd else Path.cwd()
    command, args = server_command(uvx)
    changes = []
    for path, key, typed in mcp_targets(agent, home, cwd, platform):
        if key is None:
            changes.append(toml_change(path, command, args))
            continue
        entry = {"type": "stdio"} if typed else {}
        entry.update({"command": command, "args": args})
        changes.append(json_change(path, key, entry))
    for path in skill_targets(agent, home):
        changes.append(skill_change(path, skill_text()))
    return changes


def apply(changes):
    for c in changes:
        if c.new_text is None or c.action not in ("create", "update"):
            continue
        c.path.parent.mkdir(parents=True, exist_ok=True)
        if c.path.exists():
            shutil.copy2(c.path, c.path.with_name(c.path.name + ".bak"))
        tmp = c.path.with_name(c.path.name + ".asa-tmp")
        tmp.write_text(c.new_text, encoding="utf-8")
        os.replace(tmp, c.path)


def describe(changes, wrote):
    out = []
    for c in changes:
        verb = {"create": "created" if wrote else "would create", "update": "updated" if wrote else "would update",
                "unchanged": "already set up", "conflict": "left as is"}[c.action]
        note = c.note or (f"backup: {c.path.name}.bak" if c.action == "update" and c.path.exists() else "")
        out.append(f"{verb}: {c.path}" + (f" ({note})" if note else ""))
        if c.action in ("create", "update", "conflict"):
            out += ["    " + line for line in c.added.splitlines()]
    return "\n".join(out)


def run(agent, yes=False, uvx=False, home=None, cwd=None, out=None):
    out = out or sys.stdout
    changes = plan(agent, home, cwd, uvx)
    pending = any(c.action in ("create", "update") for c in changes)
    if yes and pending:
        apply(changes)
    print(describe(changes, wrote=yes), file=out)
    if pending and not yes:
        print(f"Dry run: nothing was written. Run `asa install {agent} --yes` to write it "
              "(an existing file is copied to <file>.bak first).", file=out)
    elif pending:
        print(f"Done. Restart {agent} so it loads the server.", file=out)
    else:
        print("Nothing to change.", file=out)
    command, _ = server_command(uvx)
    if command == "uvx" and not shutil.which("uvx"):
        print("Note: the server runs through uvx, which is not on PATH; install uv (https://docs.astral.sh/uv/).",
              file=out)
    return 1 if any(c.action == "conflict" for c in changes) else 0
