"""Request input that reaches an outbound fetch (API-08, server-side request forgery) or a whole database write
(API-33, mass assignment), read statically from JavaScript and TypeScript server code."""

from __future__ import annotations

import re

from .base import SUSPECTED, make, plural
from .nextjs import INLINE_SERVER, ROUTE, _at, _code, _directive
from .patterns import LITERAL, _arg

# Where request input comes from in route handlers, Server Actions, pages and Express-style handlers.
REQ = re.compile(r"\b(?:req|request)\.(?:query|body|params)\b|\b(?:req|request)\.(?:json|formData|text)\(\s*\)|"
                 r"\bsearchParams\b|\bformData\.get\(|\bnextUrl\b")
# A request body as a whole object (not one named field).
BODY = re.compile(r"^\s*(?:await\s+)?(?:req|request)\.(?:json\(\s*\)|body)\s*$|"
                  r"^\s*Object\.fromEntries\(\s*(?:await\s+)?\w+(?:\.formData\(\s*\))?\s*\)\s*$|"
                  r"^\s*JSON\.parse\(\s*(?:await\s+)?(?:req|request)\.(?:body|text\(\s*\))\s*\)\s*$")
SCHEMA = re.compile(r"([A-Za-z_$][\w$]*)\s*\.\s*(?:parse|safeParse|parseAsync|safeParseAsync|validate|validateSync)\(")
# Receivers whose .parse() decodes text and checks no fields: JSON.parse(req.body) is still the whole body.
NOT_SCHEMA = {"JSON", "qs", "querystring", "url", "URL", "Date", "cookie", "path"}
# Client-only React hooks: a file that calls one runs in the browser even without its own 'use client'.
CLIENT_HOOK = re.compile(r"\buse(?:Effect|LayoutEffect|State|Reducer|SearchParams|Router|Pathname|Params)\s*\(")
SERVER_EXPORT = re.compile(r"\bget(?:ServerSideProps|StaticProps|InitialProps)\b")
IDENT = re.compile(r"[A-Za-z_$][\w$]*")

FETCH = re.compile(r"(?<![\w$.])fetch\(\s*|\baxios(?:\.(?:get|post|put|patch|delete|head|request))?\(\s*|"
                   r"(?<![\w$.])got(?:\.(?:get|post|put|patch|delete|head))?\(\s*|\b(?:https?|undici)\.(?:get|request)\(\s*|"
                   r"(?<![\w$.])ky(?:\.(?:get|post|put|patch|delete))?\(\s*")
# A URL whose origin is fixed in the source: a literal scheme and host followed by a slash, or a relative path.
FIXED_ORIGIN = re.compile(r"""^\s*[`'"](?:https?://[^/`'"$\s]+/|/(?!/))""")
ENV = re.compile(r"^\s*process\.env\.[A-Z0-9_]+\s*$")
ENV_OBJECT = re.compile(r"^\s*process\.env\s*$")
# A template literal that starts with one ${...} and a slash: the origin is whatever that expression is.
TEMPLATE_BASE = re.compile(r"^\s*`\$\{([^{}`]+)\}/")
HOST_CHECK = re.compile(r"\.hostname\b|\ballow(?:ed)?[_-]?(?:hosts?|list|origins?|domains?)\b|\ballowlist\b",
                        re.IGNORECASE)

WRITES = (
    # Supabase / PostgREST: supabase.from("t").insert(x) | .upsert(x) | .update(x)
    re.compile(r"\.from\(\s*['\"`][\w.-]+['\"`]\s*\)\s*\.(?:insert|upsert|update)\(\s*"),
    # Drizzle: db.insert(table).values(x), db.update(table).set(x)
    re.compile(r"\.(?:insert|update)\(\s*[\w$.]+\s*\)\s*\.(?:values|set)\(\s*"),
)
PRISMA = re.compile(r"\bprisma\.\w+\.(?:create|createMany|update|updateMany|upsert)\(\s*")
DATA = re.compile(r"\b(?:data|create|update)\s*:\s*")
# One fetch argument or one write payload may resolve this many names, total, across the whole recursion.
# Spending the budget is "not proven", which the callers report as manual — never as a fixed URL or a safe write.
_LOOKUP_BUDGET = 64
# A destructuring pattern longer than this is left untraced. The old `[^}]*` scan backtracks over a long brace.
_DESTRUCTURE = re.compile(r"\b(?:const|let|var)\s*\{([^{}]{0,400})\}\s*=\s*")
_PLAIN_ASSIGN = re.compile(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::\s*[\w<>\[\]]+\s*)?=\s*")
_REASSIGN = re.compile(r"(?<![\w$.])([A-Za-z_$][\w$]*)\s*(?:\+|\?\?|\|\||&&)?=(?![=>])")
_DECL_BEFORE = re.compile(r"\b(?:const|let|var)\s+$")
_CYCLE = object()


def _read_arg(code, start, limit=400, stops=","):
    """Leave a capped expression unknown, rather than treating its prefix as a complete safe value."""
    value = _arg(code, start, limit=limit + 1, stops=stops)
    return value if len(value) <= limit else ""


def _all(n, word):
    return f"The one {word}" if n == 1 else f"All {plural(n, word)}"


def _server_files(project):
    out = []
    for rel in project.code_files():
        code = _code(project, rel)
        if _directive(code) == "client":
            continue
        server = ROUTE.search(rel) or _directive(code) == "server" or INLINE_SERVER.search(code)
        # Otherwise request input marks server code, unless the file calls client-only hooks.
        if server or (REQ.search(code) and (SERVER_EXPORT.search(code) or not CLIENT_HOOK.search(code))):
            out.append((rel, code))
    return out


class _Budget:
    """Lookup counter shared by every recursive step of one fetch argument or one payload."""

    def __init__(self):
        self.left = _LOOKUP_BUDGET
        self.exhausted = False

    def charge(self):
        if self.left <= 0:
            self.exhausted = True
            return False
        self.left -= 1
        return True


class _Memo:
    """Source and reassignment lookups for one file, each name scanned once."""

    def __init__(self, code):
        self.code = code
        self._ready = False
        self.assign = {}
        self.destructures = []
        self.re_buckets = {}
        self.re_truncated = set()
        self.source = {}

    def ensure(self):
        if self._ready:
            return
        self._ready = True
        code = self.code
        for m in _PLAIN_ASSIGN.finditer(code):
            self.assign.setdefault(m.group(1), _read_arg(code, m.end(), stops=",;"))
        for m in _DESTRUCTURE.finditer(code):
            self.destructures.append((m.group(1), _read_arg(code, m.end(), stops=",;")))
        buckets = self.re_buckets
        for m in _REASSIGN.finditer(code):
            name = m.group(1)
            if _DECL_BEFORE.search(code[max(0, m.start() - 20):m.start()]):
                continue
            bucket = buckets.get(name)
            if bucket is None:
                buckets[name] = [_read_arg(code, m.end(), stops=",;")]
            elif len(bucket) < _LOOKUP_BUDGET:
                bucket.append(_read_arg(code, m.end(), stops=",;"))
            else:
                self.re_truncated.add(name)

    def get_source(self, name):
        """(expression, how): "assign", "field", "rest", or ("", "") when this file does not set the name."""
        hit = self.source.get(name)
        if hit is not None:
            return hit
        self.ensure()
        if name in self.assign:
            hit = self.assign[name], "assign"
        else:
            hit = self._destructured(name)
        self.source[name] = hit
        return hit

    def _destructured(self, name):
        name_rx = re.compile(r"\b" + re.escape(name) + r"\b")
        rest_rx = re.compile(r"\.\.\.\s*" + re.escape(name) + r"\b")
        for body, rhs in self.destructures:
            if name_rx.search(body):
                return rhs, "rest" if rest_rx.search(body) else "field"
        return "", ""

    def get_reassigned(self, name):
        """Later assignments to name, and whether that list was cut at the lookup budget."""
        self.ensure()
        return tuple(self.re_buckets.get(name, ())), name in self.re_truncated


class _Walk:
    """Visited names plus the shared budget for one argument."""

    def __init__(self, memo, budget):
        self.memo = memo
        self.budget = budget
        self.visited = set()
        self.payload = {}

    def expand(self, name):
        """(source, reassigned, truncated), the cycle sentinel, or None when the budget is spent."""
        if name in self.visited:
            return _CYCLE
        if not self.budget.charge():
            return None
        self.visited.add(name)
        return self.memo.get_source(name), *self.memo.get_reassigned(name)


def _schema(text):
    return any(m.group(1) not in NOT_SCHEMA for m in SCHEMA.finditer(text))


def _walk_for(code, walk):
    return walk if walk is not None else _Walk(_Memo(code), _Budget())


def _from_request(code, expr, depth=0, walk=None):
    walk = _walk_for(code, walk)
    if REQ.search(expr):
        return True
    if depth > 2 or walk.budget.exhausted:
        return False
    for name in dict.fromkeys(IDENT.findall(expr)):
        found = walk.expand(name)
        if found is None:
            return False
        if found is _CYCLE:
            continue
        (src, _), reassigned, truncated = found
        for value in ([src] if src else []) + list(reassigned):
            if value.strip() != expr.strip() and _from_request(code, value, depth + 1, walk):
                return True
            if walk.budget.exhausted:
                return False
        if truncated:
            walk.budget.exhausted = True
            return False
    return False


def _fixed_url(code, arg, depth=0, walk=None):
    """True when the URL's origin is fixed in the source: a literal, a fixed-origin template, an environment variable,
    or a name set once in this file to one of those (an UPPER_CASE name proves nothing by itself)."""
    walk = _walk_for(code, walk)
    if walk.budget.exhausted:
        return False
    if LITERAL.match(arg) or FIXED_ORIGIN.match(arg) or ENV.match(arg):
        return True
    if depth > 2:
        return False
    base = TEMPLATE_BASE.match(arg)
    if base:
        return _fixed_url(code, base.group(1), depth + 1, walk)
    name = arg.strip()
    if not IDENT.fullmatch(name):
        return False
    found = walk.expand(name)
    if found is None or found is _CYCLE:
        return False
    (src, how), reassigned, truncated = found
    if reassigned or truncated:
        return False
    if how == "field":
        return ENV_OBJECT.match(src) is not None  # const { API_URL } = process.env
    return how == "assign" and _fixed_url(code, src, depth + 1, walk)


def outbound_requests(project):
    suspect, checked, unresolved, total, files = [], [], [], 0, 0
    for rel, code in _server_files(project):
        calls = list(FETCH.finditer(code))
        if calls:
            files += 1
        memo = _Memo(code)
        for m in calls:
            total += 1
            arg = _read_arg(code, m.end())
            # Fixed-origin and request-origin share one budget. A spent budget is not a fixed URL.
            budget = _Budget()
            if _fixed_url(code, arg, walk=_Walk(memo, budget)) and not budget.exhausted:
                continue
            if _from_request(code, arg, walk=_Walk(memo, budget)):
                if HOST_CHECK.search(code):
                    checked.append(_at(project, rel, code, m.start(), "URL from request input; a host check is in "
                                       "the file, confirm it runs before the fetch"))
                else:
                    suspect.append(_at(project, rel, code, m.start(), "server-side request to a URL from request input"))
            else:
                unresolved.append(_at(project, rel, code, m.start(), "server-side request to a URL the read could "
                                      "not trace"))
    if suspect:
        return [make("API-08", "warn", SUSPECTED + f"{plural(len(suspect), 'server-side request')} "
                     f"{'takes' if len(suspect) == 1 else 'take'} its URL from request input with no host check in "
                     "the file. A caller can point it at internal addresses such as cloud metadata or localhost.",
                     suspect + checked + unresolved)]
    if checked or unresolved:
        n = len(checked) + len(unresolved)
        return [make("API-08", "manual", f"Not proven: {plural(n, 'server-side request')} "
                     f"{'uses' if n == 1 else 'use'} a URL that is not fixed in the source. Confirm each one allows "
                     "only known hosts and refuses private addresses (proof steps: asa show API-08).",
                     checked + unresolved)]
    if total:
        return [make("API-08", "pass", f"{_all(total, 'server-side request')} in {plural(files, 'file')} "
                     f"{'goes' if total == 1 else 'go'} to an origin fixed in the source (literal, constant or "
                     "environment variable).")]
    return []


def _payload_kind(code, value, depth=0, walk=None):
    """'raw' (the whole request body), 'safe' (named fields or a schema-parsed value) or 'unknown'."""
    walk = _walk_for(code, walk)
    value = value.strip()
    if depth > 3 or walk.budget.exhausted:
        return "unknown"
    if BODY.match(value):
        return "raw"
    if value.startswith("{"):
        if not value.endswith("}"):
            return "unknown"
        for spread in re.findall(r"\.\.\.\s*([^,}]+)", value):
            kind = _payload_kind(code, spread, depth + 1, walk)
            if kind != "safe":
                return kind
        # A spread we stopped before reading is not proof that every field is named.
        return "unknown" if walk.budget.exhausted else "safe"
    if _schema(value):
        return "safe"
    base = re.match(r"^([A-Za-z_$][\w$]*)(?:\s*\.\s*data)?$", value)
    if not base:
        return "unknown"
    name = base.group(1)
    if name in walk.payload:
        return walk.payload[name]
    found = walk.expand(name)
    if found is None or found is _CYCLE:
        return "unknown"
    (src, how), reassigned, truncated = found
    if not src or how == "field":
        kind = "unknown"
    elif BODY.match(src):
        kind = "raw"  # const body = await req.json(), or const { role, ...rest } = await req.json()
    elif _schema(src):
        kind = "safe"
    elif how == "assign" and src.lstrip().startswith("{"):
        kind = _payload_kind(code, src, depth + 1, walk)
    else:
        kind = "unknown"
    for rhs in reassigned:
        if kind == "raw":
            break
        later = _payload_kind(code, rhs, depth + 1, walk)
        if later == "raw" or kind == "safe":
            kind = later
    if truncated:
        walk.budget.exhausted = True
    if walk.budget.exhausted and kind != "raw":
        kind = "unknown"
    # Completed proofs may be reused by repeated spreads. A name currently being resolved remains unknown.
    if kind != "unknown":
        walk.payload[name] = kind
    return kind


def _writes(code):
    for rx in WRITES:
        for m in rx.finditer(code):
            yield m.start(), _read_arg(code, m.end())
    for m in PRISMA.finditer(code):
        call = _read_arg(code, m.end(), limit=2000)
        if not call:
            yield m.start(), ""
            continue
        for d in DATA.finditer(call):
            yield m.start(), _read_arg(call, d.end())


def mass_assignment(project):
    raw, unknown, total, files = [], [], 0, 0
    for rel, code in _server_files(project):
        found = list(_writes(code))
        if found:
            files += 1
        memo = _Memo(code)
        for offset, value in found:
            total += 1
            budget = _Budget()
            kind = _payload_kind(code, value, walk=_Walk(memo, budget))
            # Exhaustion is not a schema. A raw body already found stays a warning.
            if budget.exhausted and kind != "raw":
                kind = "unknown"
            if kind == "raw":
                raw.append(_at(project, rel, code, offset, "database write takes the request body as a whole"))
            elif kind == "unknown":
                unknown.append(_at(project, rel, code, offset, "database write payload could not be traced"))
    if raw:
        return [make("API-33", "warn", SUSPECTED + f"{plural(len(raw), 'database write')} "
                     f"{'stores' if len(raw) == 1 else 'store'} the request body as a whole. A caller can add "
                     "fields such as role, owner or price unless the database refuses them.", raw + unknown)]
    if unknown:
        return [make("API-33", "manual", f"Not proven: {plural(len(unknown), 'database write')} "
                     f"{'takes' if len(unknown) == 1 else 'take'} a payload the read could not trace to named fields "
                     "or a schema (proof steps: asa show API-33).", unknown)]
    if total:
        return [make("API-33", "pass", f"{_all(total, 'database write')} in {plural(files, 'server file')} "
                     f"{'takes' if total == 1 else 'take'} named fields or a schema-parsed value, never the raw "
                     "request body.")]
    return []


ANALYZERS = (outbound_requests, mass_assignment)
CHECKS = ("API-08", "API-33")
