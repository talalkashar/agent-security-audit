"""`asa install <agent>`: add the asa-mcp server (and, where the agent loads skills from a known folder, the skill)
to one agent's config.

Every path and file shape here comes from the agent's own documentation (see docs/INSTALL.md for the links).
The default is a dry run that prints what would change. With --yes it writes, after copying an existing file to
<file>.bak next to the real file. It never removes or rewrites another server: JSON configs get one key merged in,
and Codex's TOML gets one table appended to the end of the file.

Project configs (.mcp.json, .vscode/mcp.json, .cursor/mcp.json under the current directory) are not written through
a symlink. A home config may follow a symlink only when the real file stays inside the home directory it was given.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import stat
import sys
import tempfile
import tomllib
from contextlib import contextmanager
from dataclasses import dataclass
from importlib import resources
from pathlib import Path

NAME = "agent-security-audit"
REPO = "https://github.com/talalkashar/agent-security-audit"
AGENTS = ("claude-code", "claude-desktop", "cursor", "vscode", "windsurf", "codex", "gemini", "antigravity")
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
    root: Path | None = None  # home or cwd; the real parent must stay under this directory
    strict: bool = False  # cwd project config: refuse a symlink in any component


# Relative to the current directory. ~/.cursor/mcp.json is a home file, not one of these, when it is the home path.
_PROJECT_CONFIGS = (".mcp.json", ".vscode/mcp.json", ".cursor/mcp.json")
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


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
    return Change(path, "update", added, json.dumps(data, indent=2, ensure_ascii=False) + "\n")


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
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise InstallError(f"{path} is not valid TOML ({exc}); it was left as is. Add this by hand:\n{added}") from exc
    servers = data.get("mcp_servers")
    if isinstance(servers, dict) and NAME in servers:  # a [mcp_servers.<name>] table, a dotted key or an inline table
        return Change(path, "unchanged", added, note=f"mcp_servers.{NAME} is already in the file; it was left as is")
    body = text if not text or text.endswith("\n") else text + "\n"
    new_text = body + ("\n" if body.strip() else "") + added
    try:
        tomllib.loads(new_text)
    except tomllib.TOMLDecodeError:
        if INLINE_SERVERS.search(text):
            note = ("mcp_servers is an inline table there, so a table cannot be appended; it was left as is (add the "
                    "server to that inline table by hand)")
        else:
            note = "the file would not parse with the table appended; it was left as is (add the server by hand)"
        return Change(path, "conflict", added, note=note)
    return Change(path, "update", added, new_text)


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
            change = toml_change(path, command, args)
        else:
            entry = {"type": "stdio"} if typed else {}
            entry.update({"command": command, "args": args})
            change = json_change(path, key, entry)
        changes.append(_stamp(change, home, cwd))
    for path in skill_targets(agent, home):
        changes.append(_stamp(skill_change(path, skill_text()), home, cwd))
    return changes


def _abs(path):
    return Path(os.path.abspath(path))


def _rel_posix(path, root):
    try:
        return _abs(path).relative_to(_abs(root)).as_posix()
    except ValueError:
        return None


def _inside(path, root):
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _stamp(change, home, cwd):
    """Bind the anchor `plan` used. Project files stay strict even when the project directory is inside home."""
    rel_cwd = _rel_posix(change.path, cwd)
    rel_home = _rel_posix(change.path, home)
    # ~/.cursor/mcp.json is the home Cursor file when the command is run from home. A different directory's
    # .cursor/mcp.json is a project file.
    project = rel_cwd in _PROJECT_CONFIGS and not (rel_cwd == ".cursor/mcp.json" and rel_home == ".cursor/mcp.json")
    change.root = cwd if project else home
    change.strict = project
    return change


def _is_link(path):
    try:
        return path.is_symlink()
    except OSError as exc:
        raise InstallError(f"cannot inspect {path}: {exc.strerror or exc}") from exc


def _reject_project_symlinks(path, root):
    """cwd project config: every component, including a symlink directory, is refused."""
    path_abs = _abs(path)
    root_abs = _abs(root)
    if not _inside(path_abs, root_abs):
        raise InstallError(f"refusing to write {path}: it is outside {root}")
    current = root_abs
    final = path_abs
    for part in path_abs.relative_to(root_abs).parts:
        current = current / part
        if _is_link(current):
            raise InstallError(f"refusing to follow symlink {current}")
        if current != final and current.exists() and not current.is_dir():
            raise InstallError(f"refusing to write {path}: {current} is not a directory")
    parent = path_abs.parent
    if not _inside(parent, root_abs):
        raise InstallError(f"refusing to write {path}: the directory is outside {root}")
    return path_abs


def _home_destination(path, root):
    """Follow symlinks only when the real file and its parent stay under the supplied home directory."""
    try:
        root_real = Path(os.path.realpath(root))
        resolved = Path(os.path.realpath(path))
        parent = Path(os.path.realpath(resolved.parent))
    except OSError as exc:
        raise InstallError(f"refusing to resolve {path}: {exc.strerror or exc}") from exc
    if not _inside(resolved, root_real):
        raise InstallError(f"refusing to write {path}: it resolves outside {root}")
    if not _inside(parent, root_real):
        raise InstallError(f"refusing to write {path}: the directory resolves outside {root}")
    return resolved


def _destination(change):
    if change.strict:
        return _reject_project_symlinks(change.path, change.root)
    return _home_destination(change.path, change.root)


def _anchored_writes_available():
    needed = (os.open, os.mkdir, os.stat, os.unlink, os.rename)
    return (all(fn in os.supports_dir_fd for fn in needed)
            and bool(getattr(os, "O_DIRECTORY", 0)) and bool(_NOFOLLOW) and hasattr(os, "fchmod"))


@contextmanager
def _parent_directory(change, target):
    """Hold the destination directory open; later path swaps cannot redirect the write."""
    root = Path(os.path.realpath(change.root))
    if change.strict:
        relative = _abs(target).relative_to(_abs(change.root))
    else:
        relative = target.relative_to(root)
    flags = os.O_RDONLY | os.O_DIRECTORY | _NOFOLLOW
    fd = os.open(root, flags)
    try:
        for part in relative.parts[:-1]:
            try:
                child = os.open(part, flags, dir_fd=fd)
            except FileNotFoundError:
                try:
                    os.mkdir(part, 0o700, dir_fd=fd)
                except FileExistsError:
                    pass  # The no-follow open still checks a concurrently created entry.
                child = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = child
        yield fd, relative.name
    finally:
        os.close(fd)


def _remove_owned(parent, name, owned):
    try:
        current = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if (current.st_dev, current.st_ino) == (owned.st_dev, owned.st_ino):
            os.unlink(name, dir_fd=parent)
    except FileNotFoundError:
        pass


def _replace_config(parent, name, text):
    """All reads, backups, permissions and rename use the held parent or open file descriptors."""
    backup, tmp = name + ".bak", None
    backup_owned = tmp_owned = None
    mode = None
    try:
        try:
            source = os.open(name, os.O_RDONLY | _NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        except FileNotFoundError:
            source = None
        if source is not None:
            with os.fdopen(source, "rb") as original:
                st = os.fstat(original.fileno())
                if not stat.S_ISREG(st.st_mode):
                    raise InstallError(f"refusing to replace {name}: not a regular file")
                mode = stat.S_IMODE(st.st_mode)
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW
                try:
                    fd = os.open(backup, flags, 0o600, dir_fd=parent)
                except FileExistsError as exc:
                    raise InstallError(f"refusing to replace existing backup {backup}") from exc
                with os.fdopen(fd, "wb") as saved:
                    backup_owned = os.fstat(saved.fileno())
                    shutil.copyfileobj(original, saved)
                    os.fchmod(saved.fileno(), mode)
        # Unpredictable, exclusive names in the anchored directory. No user temp name is removed.
        for _ in range(16):
            tmp = f".{name}.{secrets.token_hex(12)}"
            try:
                fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW, 0o600, dir_fd=parent)
                break
            except FileExistsError:
                tmp = None
        else:
            raise InstallError(f"cannot create a private temporary file for {name}")
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            tmp_owned = os.fstat(handle.fileno())
            handle.write(text)
            if mode is not None:
                os.fchmod(handle.fileno(), mode)
        # rename replaces the directory entry itself; it never follows a newly planted target symlink.
        os.rename(tmp, name, src_dir_fd=parent, dst_dir_fd=parent)
        tmp = None
    except Exception:
        if backup_owned is not None:
            _remove_owned(parent, backup, backup_owned)
        raise
    finally:
        if tmp is not None and tmp_owned is not None:
            _remove_owned(parent, tmp, tmp_owned)


def apply(changes):
    for c in changes:
        if c.new_text is None or c.action not in ("create", "update"):
            continue
        if c.root is None:
            raise InstallError(f"refusing to write {c.path} without an anchor directory")
        if not _anchored_writes_available():
            raise InstallError("secure automatic config writes are unavailable on this platform; "
                               "run without --yes to see the configuration and add it manually")
        try:
            target = _destination(c)
            with _parent_directory(c, target) as (parent, name):
                _replace_config(parent, name, c.new_text)
        except OSError as exc:
            raise InstallError(f"refusing to write {c.path}: {exc.strerror or exc}") from exc


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
