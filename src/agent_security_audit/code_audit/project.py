"""The files of one project: which ones to read, how to read them, and how to quote them safely.

Nothing here runs project code or git. Tracked files come from parsing `.git/index` directly, and untracked files
that `.gitignore` does not exclude are added from a walk of the tree; without a git index, only the walk is used.
Only files under the project root are read. When a cap stops the read (file count or file size), the project
records it so results that need full coverage can say so instead of passing.
"""

from __future__ import annotations

import bisect
import os
import posixpath
import re
import stat
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
MAX_INDEX_BYTES = 64_000_000  # a git index for hundreds of thousands of files; a larger one is not read
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

def _glob_tokens(glob):
    """A gitignore glob as tokens: ("lit", c), ("one",), ("cls", text), ("star",) for *, ("dstar",) for ** and
    ("dslash",) for a leading or inner **/ (any run of whole directories, or none)."""
    out, i = [], 0
    while i < len(glob):
        c = glob[i]
        if glob.startswith("**/", i):
            out.append(("dslash",))
            i += 3
            continue
        if glob.startswith("/**", i) and i + 3 == len(glob):
            out += [("lit", "/"), ("dstar",)]
            i += 3
            continue
        if c == "*":
            out.append(("dstar",) if glob.startswith("**", i) else ("star",))
            i += 2 if glob.startswith("**", i) else 1
            continue
        if c == "?":
            out.append(("one",))
        elif c == "[" and (j := glob.find("]", i + 1)) != -1 and _valid_class(cls := glob[i + 1:j]):
            out.append(("cls", cls))
            i = j
        else:
            out.append(("lit", c))
        i += 1
    return out


def _class_regex(cls):
    """A bracket class as a regex that never matches "/" (git's rule). Every member is escaped, so text such as [[
    or && cannot become a nested set; only a "-" between two members keeps its range meaning."""
    neg = cls[:1] in ("!", "^")
    body = cls[neg:]
    body = "".join(c if c == "-" and 0 < k < len(body) - 1 and "-" not in (body[k - 1], body[k + 1]) else re.escape(c)
                   for k, c in enumerate(body))
    return "(?!/)[" + ("^" if neg else "") + body + "]"


def _valid_class(cls):
    try:
        re.compile(_class_regex(cls))
    except re.error:  # [z-a] or an empty class: git reads such a bracket as text, and so do we
        return False
    return True


_TOKEN_REGEX = {"one": "[^/]", "star": "[^/]*", "dstar": ".*", "dslash": "(?:.*/)?"}
# A pattern with more wildcards than this backtracks polynomially in the path length (degree = wildcard count), so a
# hostile .gitignore could stall the walk: such patterns run on the linear matcher in _nfa_match instead.
_REGEX_WILDCARDS = 2


def _glob_to_regex(tokens):
    return "".join(re.escape(t[1]) if t[0] == "lit" else _class_regex(t[1]) if t[0] == "cls" else _TOKEN_REGEX[t[0]]
                   for t in tokens)


def _nfa_match(tokens, classes, path):
    """Whether path matches the whole token list, in O(len(path) * len(tokens)) with no backtracking. A state is a
    token index; -1 - i marks being inside the directory run of the dslash token i."""
    end = len(tokens)

    def closure(states):
        out, todo = set(), list(states)
        while todo:
            s = todo.pop()
            if s in out:
                continue
            out.add(s)
            if 0 <= s < end and tokens[s][0] in ("star", "dstar", "dslash"):
                todo.append(s + 1)
        return out

    states = closure({0})
    for ch in path:
        nxt = set()
        for s in states:
            if s < 0:
                nxt.add(s)
                if ch == "/":
                    nxt.add(-1 - s + 1)
                continue
            if s == end:
                continue
            kind = tokens[s][0]
            if (kind == "lit" and ch == tokens[s][1]) or (kind == "one" and ch != "/") or \
                    (kind == "cls" and ch != "/" and classes[s].fullmatch(ch)):
                nxt.add(s + 1)
            elif kind == "star" and ch != "/" or kind == "dstar":
                nxt.add(s)
            elif kind == "dslash":
                nxt.add(-1 - s)
                if ch == "/":
                    nxt.add(s + 1)
        states = closure(nxt)
        if not states:
            return False
    return end in states


class _Glob:
    """One compiled rule: a regex when it has few wildcards, else the linear token matcher."""

    def __init__(self, tokens):
        self.tokens = tokens
        if sum(t[0] in _TOKEN_REGEX and t[0] != "one" for t in tokens) <= _REGEX_WILDCARDS:
            self.regex, self.classes = re.compile(_glob_to_regex(tokens) + r"\Z", re.DOTALL), None
        else:
            self.regex = None
            self.classes = {i: re.compile(_class_regex(t[1])) for i, t in enumerate(tokens) if t[0] == "cls"}

    def match(self, path):
        if self.regex is not None:
            return self.regex.match(path) is not None
        return _nfa_match(self.tokens, self.classes, path)


MAX_IGNORE_RULES = 5_000
MAX_IGNORE_BYTES = 1_000_000


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
            if len(self.rules) >= MAX_IGNORE_RULES:
                return  # more rules than any real project has: the rest are dropped, so more files are read, not fewer
            anchored = "/" in line
            tokens = _glob_tokens(line.lstrip("/"))
            self.rules.append((base, _Glob(tokens if anchored else [("dslash",)] + tokens), negate, dir_only))

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
        return f"{self.path}:{self.line}: {_clip(self.note)}" + (f": {_clip(self.snippet)}" if self.snippet else "")

    def location(self):
        return {"path": self.path, "line": self.line, "message": _clip(self.note)}


def _clip(note, limit=300):
    """Notes quote names from the project (tables, cron paths, env vars); a hostile one must not flood the report."""
    note = " ".join(note.split())
    return note if len(note) <= limit else note[:limit] + "..."


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
        if index_bytes := self._small_file(index, MAX_INDEX_BYTES, binary=True):
            try:
                paths = read_git_index(index_bytes)
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
        if exclude is not None:
            ignore.add("", self._small_file(exclude, MAX_IGNORE_BYTES))
        for dirpath, dirnames, filenames in os.walk(self.root):
            rel_dir = os.path.relpath(dirpath, self.root).replace(os.sep, "/")
            rel_dir = "" if rel_dir == "." else rel_dir
            if ".gitignore" in filenames:
                ignore.add(rel_dir, self._small_file(Path(dirpath) / ".gitignore", MAX_IGNORE_BYTES))
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

    def _small_file(self, path, limit, binary=False):
        """A regular file under the root, read whole when it is at most limit bytes; otherwise empty. A FIFO, device
        or symlink named .gitignore or .git/index must not block or flood the walk."""
        try:
            st = os.lstat(path)
            if not stat.S_ISREG(st.st_mode) or st.st_size > limit or not self._inside(path):
                return b"" if binary else ""
            data = Path(path).read_bytes()
        except OSError:
            return b"" if binary else ""
        return data if binary else data.decode("utf-8", "replace")

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
                st = full.stat()
                # Only regular files: reading a FIFO or device named like a source file would block or never end.
                if not stat.S_ISREG(st.st_mode) or not self._inside(full):
                    raise OSError
                if st.st_size > limit:
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


_LINES = {}  # id(text) -> (text, newline offsets, lines): analyzers ask for many lines of the same few texts


def _lines(text):
    hit = _LINES.get(id(text))
    if hit is None or hit[0] is not text:
        if len(_LINES) >= 16:
            _LINES.clear()
        hit = _LINES[id(text)] = (text, [m.start() for m in re.finditer("\n", text)], text.split("\n"))
    return hit


def line_of(text, offset):
    """The 1-based line of offset. Indexed once per text, so a file with many findings stays linear."""
    return bisect.bisect_left(_lines(text)[1], offset) + 1


def line_text(text, line):
    """Line number `line` counted the same way as line_of (by "\\n" only), without its trailing "\\r"."""
    lines = _lines(text)[2]
    return lines[line - 1].removesuffix("\r") if 0 < line <= len(lines) else ""


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
