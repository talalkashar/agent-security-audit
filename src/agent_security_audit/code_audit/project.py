"""The files of one project: which ones to read, how to read them, and how to quote them safely.

Nothing here runs project code or git. Tracked files come from parsing `.git/index` directly, and untracked files
that `.gitignore` does not exclude are added from a walk of the tree; without a git index, only the walk is used.
Only files under the project root are read. When a cap stops the read (file count or file size), the project
records it so results that need full coverage can say so instead of passing.
"""

from __future__ import annotations

import os
import posixpath
import re
import struct
from dataclasses import dataclass
from pathlib import Path

from ..checks.exposure import JWT, SECRET_PATTERNS, mask

# Build output, dependencies and caches: never audited, tracked or not. A ".nosync" suffix is ignored.
SKIP_DIRS = {"node_modules", ".next", ".git", "dist", "build", "out", ".vercel", ".turbo", "coverage", ".svelte-kit",
             ".nuxt", ".output", "__pycache__", ".venv", "venv", ".cache", ".parcel-cache", ".expo", "storybook-static",
             ".pnpm-store", ".yarn"}
LOCKFILES = {"package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "bun.lockb", "bun.lock",
             "poetry.lock", "Pipfile.lock", "Cargo.lock", "composer.lock", "go.sum", "Gemfile.lock", "uv.lock"}
MAX_BYTES = 2_000_000
MAX_LOCK_BYTES = 30_000_000  # lockfiles of large projects pass 2 MB; they are parsed, not quoted
MAX_FILES = 20_000
WALK_LIMIT = 100_000  # the tree walk stops here, so pointing the audit at a home folder still ends
JS_EXT = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mts", ".cts", ".svelte", ".vue", ".astro")


def _skip_dir(name):
    return name.removesuffix(".nosync") in SKIP_DIRS


# --- git index -----------------------------------------------------------------------------------------------

def read_git_index(data):
    """Paths in a git index file (versions 2-4). Submodule entries are left out. Raises ValueError if malformed."""
    if data[:4] != b"DIRC":
        raise ValueError("not a git index")
    version, count = struct.unpack(">II", data[4:12])
    if version not in (2, 3, 4):
        raise ValueError(f"unsupported git index version {version}")
    pos, prev, paths = 12, b"", []
    for _ in range(count):
        mode = struct.unpack(">I", data[pos + 24:pos + 28])[0]
        flags = struct.unpack(">H", data[pos + 60:pos + 62])[0]
        head = 62 + (2 if version >= 3 and flags & 0x4000 else 0)
        start = pos + head
        if version == 4:
            strip, i = 0, start
            c = data[i]
            strip = c & 127
            while c & 128:
                i += 1
                c = data[i]
                strip = ((strip + 1) << 7) | (c & 127)
            end = data.index(b"\0", i + 1)
            name = prev[:len(prev) - strip] + data[i + 1:end]
            pos = end + 1
        else:
            end = data.index(b"\0", start)
            name = data[start:end]
            pos += (head + len(name) + 8) // 8 * 8
        prev = name
        if mode & 0o170000 != 0o160000:
            paths.append(name.decode("utf-8", "replace"))
    return paths


# --- .gitignore ----------------------------------------------------------------------------------------------

def _glob_to_regex(glob):
    out, i = "", 0
    while i < len(glob):
        c = glob[i]
        if glob.startswith("**/", i):
            out += "(?:.*/)?"
            i += 3
            continue
        if glob.startswith("/**", i) and i + 3 == len(glob):
            out += "/.*"
            i += 3
            continue
        if c == "*":
            out += ".*" if glob.startswith("**", i) else "[^/]*"
            i += 2 if glob.startswith("**", i) else 1
            continue
        if c == "?":
            out += "[^/]"
        elif c == "[":
            j = glob.find("]", i + 1)
            if j == -1:
                out += re.escape(c)
            else:
                out += "[" + glob[i + 1:j].replace("!", "^", 1).replace("\\", "\\\\") + "]"
                i = j
        else:
            out += re.escape(c)
        i += 1
    return out


class GitIgnore:
    """The subset of gitignore rules projects use: globs, **, anchoring, directory-only and negation."""

    def __init__(self):
        self.rules = []  # (base_dir, regex, negate, dir_only)

    def add(self, base, text):
        for line in text.splitlines():
            line = line.rstrip()
            if not line or line.startswith("#"):
                continue
            negate = line.startswith("!")
            line = line[1:] if negate else line
            dir_only = line.endswith("/")
            line = line.rstrip("/")
            if not line:
                continue
            anchored = "/" in line
            pat = _glob_to_regex(line.lstrip("/"))
            regex = re.compile(("^" if anchored else "^(?:.*/)?") + pat + "$")
            self.rules.append((base, regex, negate, dir_only))

    def ignored(self, rel, is_dir):
        result = False
        for base, regex, negate, dir_only in self.rules:
            if base and not rel.startswith(base + "/"):
                continue
            if dir_only and not is_dir:
                continue
            if regex.match(rel[len(base) + 1:] if base else rel):
                result = not negate
        return result


# --- the project -----------------------------------------------------------------------------------------------

@dataclass
class Finding:
    path: str
    line: int
    note: str
    snippet: str = ""

    def evidence(self):
        return f"{self.path}:{self.line}: {self.note}" + (f": {self.snippet}" if self.snippet else "")

    def location(self):
        return {"path": self.path, "line": self.line, "message": self.note}


ASSIGNED_SECRET = re.compile(r"""((?:secret|token|password|passwd|pwd|api[_-]?key|private[_-]?key|service[_-]?role)"""
                             r"""\w*["']?\s*[:=]\s*["'`])([^"'`\s]{6,})""", re.IGNORECASE)


def redact(line, limit=160):
    """One source line made safe to print: secret formats and quoted secret-looking values are masked."""
    for _, pattern in SECRET_PATTERNS:
        line = pattern.sub(lambda m: mask(m.group(0)), line)
    line = JWT.sub(lambda m: mask(m.group(0)), line)
    line = ASSIGNED_SECRET.sub(lambda m: m.group(1) + mask(m.group(2)), line)
    line = " ".join(line.split())
    return line if len(line) <= limit else line[:limit] + "..."


class Project:
    def __init__(self, root):
        self.root = Path(root).resolve()
        if not self.root.is_dir():
            raise ValueError(f"{root} is not a directory")
        self._text = {}
        self.source = ""
        self.tracked = set()
        self.omitted = 0  # files left out because MAX_FILES was reached
        self.walk_stopped = False  # the walk hit WALK_LIMIT, so omitted is a lower bound
        self.oversized = set()  # text files over the size cap, so never read
        self.unread = []  # oversized files asked for since the last reset (run() attributes them to an analyzer)
        self.files = self._list_files()

    def _inside(self, path):
        try:
            real = Path(os.path.realpath(path))
        except OSError:
            return False
        return real == self.root or self.root in real.parents

    def _list_files(self):
        index = self.root / ".git" / "index"
        if index.is_file():
            try:
                paths = read_git_index(index.read_bytes())
            except (ValueError, IndexError, struct.error, OSError):
                paths = None
            if paths is not None:
                self.tracked = {p for p in paths if self._keep(p)}
                exclude = self.root / ".git" / "info" / "exclude"
                untracked = [p for p in self._walk(exclude) if p not in self.tracked]
                self.source = (f"git index (tracked files) plus {len(untracked)} untracked file"
                               f"{'' if len(untracked) == 1 else 's'} not ignored")
                return self._cap(sorted(self.tracked | set(untracked)))
        self.source = "file walk (.gitignore respected)"
        return self._cap(self._walk(None))

    def _cap(self, files):
        self.omitted = max(0, len(files) - MAX_FILES)
        return files[:MAX_FILES]

    def _walk(self, exclude):
        ignore, out = GitIgnore(), []
        if exclude is not None and exclude.is_file():
            try:
                ignore.add("", exclude.read_text(encoding="utf-8", errors="replace"))
            except OSError:
                pass
        for dirpath, dirnames, filenames in os.walk(self.root):
            rel_dir = os.path.relpath(dirpath, self.root).replace(os.sep, "/")
            rel_dir = "" if rel_dir == "." else rel_dir
            if ".gitignore" in filenames:
                try:
                    ignore.add(rel_dir, (Path(dirpath) / ".gitignore").read_text(encoding="utf-8", errors="replace"))
                except OSError:
                    pass
            keep = []
            for d in sorted(dirnames):
                rel = f"{rel_dir}/{d}" if rel_dir else d
                if _skip_dir(d) or os.path.islink(os.path.join(dirpath, d)) or ignore.ignored(rel, True):
                    continue
                keep.append(d)
            dirnames[:] = keep
            for f in sorted(filenames):
                rel = f"{rel_dir}/{f}" if rel_dir else f
                if not ignore.ignored(rel, False) and self._keep(rel):
                    out.append(rel)
                    if len(out) >= WALK_LIMIT:
                        self.walk_stopped = True
                        return out
        return out

    def _keep(self, rel):
        parts = rel.split("/")
        if any(_skip_dir(p) for p in parts[:-1]):
            return False
        full = self.root / rel
        return full.is_file() and not full.is_symlink() and self._inside(full)

    def text(self, rel):
        """File text, or "" for binary, oversized or unreadable files. Oversized text files are recorded."""
        if rel not in self._text:
            full = self.root / rel
            limit = MAX_LOCK_BYTES if posixpath.basename(rel) in LOCKFILES else MAX_BYTES
            try:
                if not self._inside(full):
                    raise OSError
                if full.stat().st_size > limit:
                    with open(full, "rb") as fh:
                        if b"\0" not in fh.read(8192):
                            self.oversized.add(rel)
                    raise OSError
                data = full.read_bytes()
                self._text[rel] = "" if b"\0" in data[:8192] else data.decode("utf-8", "replace")
            except OSError:
                self._text[rel] = ""
        if rel in self.oversized:
            self.unread.append(rel)
        return self._text[rel]

    def coverage_gap(self):
        """A sentence saying which files a cap left out, or "" when every listed file was read in full."""
        parts = []
        if self.omitted or self.walk_stopped:
            more = "more than " if self.walk_stopped else ""
            parts.append(f"only the first {len(self.files)} of {more}{len(self.files) + self.omitted} files were "
                         f"read (cap {MAX_FILES})")
        return "; ".join(parts)

    def extra_text(self, rel):
        """Read a file under the root that is not in the file list (for example a gitignored .env.local)."""
        full = self.root / rel
        if full.is_file() and not full.is_symlink() and self._inside(full):
            return self.text(rel)
        return ""

    def matching(self, pattern):
        rx = re.compile(pattern)
        return [f for f in self.files if rx.search(f)]

    def code_files(self):
        return [f for f in self.files if f.endswith(JS_EXT) and not f.endswith((".min.js", ".d.ts"))
                and not is_test_path(f)]


TEST_PATH = re.compile(r"(^|/)(__tests__|__mocks__|tests?|spec|e2e|cypress|fixtures?)/|\.(test|spec|stories)\.[^/]+$")


def is_test_path(rel):
    return TEST_PATH.search(rel) is not None


def line_of(text, offset):
    return text.count("\n", 0, offset) + 1


def line_text(text, line):
    lines = text.splitlines()
    return lines[line - 1] if 0 < line <= len(lines) else ""


def strip_js_comments(text):
    """Blank out // and /* */ comments, keeping strings, offsets and line numbers intact."""
    out, i, n = list(text), 0, len(text)
    state = None  # None, a quote char, "//" or "/*"
    while i < n:
        c = text[i]
        if state is None:
            if c in "'\"`":
                state = c
            elif c == "/" and i + 1 < n and text[i + 1] == "/":
                state = "//"
                out[i] = " "
            elif c == "/" and i + 1 < n and text[i + 1] == "*":
                state = "/*"
                out[i] = out[i + 1] = " "
                i += 2
                continue
        elif state == "//":
            if c == "\n":
                state = None
            else:
                out[i] = " "
        elif state == "/*":
            if c == "*" and i + 1 < n and text[i + 1] == "/":
                out[i] = out[i + 1] = " "
                state = None
                i += 2
                continue
            if c != "\n":
                out[i] = " "
        else:  # inside a string
            if c == "\\":
                i += 2
                continue
            if c == state or (c == "\n" and state != "`"):
                state = None
        i += 1
    return "".join(out)
