"""Request input that reaches an outbound fetch (API-08, server-side request forgery) or a whole database write
(API-33, mass assignment), read statically from JavaScript and TypeScript server code."""

from __future__ import annotations

import re

from .base import SUSPECTED, make, plural
from .nextjs import INLINE_SERVER, ROUTE, _at, _code, _directive
from .patterns import LITERAL, _arg, _assigned

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


def _source(code, name):
    """(expression, how) a name was set from: `const name = ...` ("assign"), `const { name } = ...` ("field") or
    `const { ...name } = ...` ("rest"). ("", "") when the file does not set it."""
    value = _assigned(code, name)
    if value:
        return value, "assign"
    m = re.search(r"\b(?:const|let|var)\s*\{([^}]*?\b" + re.escape(name) + r"\b[^}]*)\}\s*=\s*", code)
    if not m:
        return "", ""
    rest = re.search(r"\.\.\.\s*" + re.escape(name) + r"\b", m.group(1))
    return _arg(code, m.end()).split(";")[0], "rest" if rest else "field"


def _reassigned(code, name):
    """Right-hand sides of later assignments to a name (`target = body.url`, `target ??= x`), not its declaration."""
    out = []
    for m in re.finditer(r"(?<![\w$.])" + re.escape(name) + r"\s*(?:\+|\?\?|\|\||&&)?=(?![=>])", code):
        if not re.search(r"\b(?:const|let|var)\s+$", code[max(0, m.start() - 20):m.start()]):
            out.append(_arg(code, m.end()).split(";")[0])
    return out


def _schema(text):
    return any(m.group(1) not in NOT_SCHEMA for m in SCHEMA.finditer(text))


def _from_request(code, expr, depth=0):
    if REQ.search(expr):
        return True
    if depth > 2:
        return False
    for name in set(IDENT.findall(expr)):
        src, _ = _source(code, name)
        for value in ([src] if src else []) + _reassigned(code, name):
            if value.strip() != expr.strip() and _from_request(code, value, depth + 1):
                return True
    return False


def _fixed_url(code, arg, depth=0):
    """True when the URL's origin is fixed in the source: a literal, a fixed-origin template, an environment variable,
    or a name set once in this file to one of those (an UPPER_CASE name proves nothing by itself)."""
    if LITERAL.match(arg) or FIXED_ORIGIN.match(arg) or ENV.match(arg):
        return True
    if depth > 2:
        return False
    base = TEMPLATE_BASE.match(arg)
    if base:
        return _fixed_url(code, base.group(1), depth + 1)
    name = arg.strip()
    if not IDENT.fullmatch(name) or _reassigned(code, name):
        return False
    src, how = _source(code, name)
    if how == "field":
        return ENV_OBJECT.match(src) is not None  # const { API_URL } = process.env
    return how == "assign" and _fixed_url(code, src, depth + 1)


def outbound_requests(project):
    suspect, checked, unresolved, total, files = [], [], [], 0, 0
    for rel, code in _server_files(project):
        calls = list(FETCH.finditer(code))
        if calls:
            files += 1
        for m in calls:
            total += 1
            arg = _arg(code, m.end())
            if _fixed_url(code, arg):
                continue
            if _from_request(code, arg):
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


def _payload_kind(code, value, depth=0):
    """'raw' (the whole request body), 'safe' (named fields or a schema-parsed value) or 'unknown'."""
    value = value.strip()
    if depth > 3:
        return "unknown"
    if BODY.match(value):
        return "raw"
    if value.startswith("{"):
        for spread in re.findall(r"\.\.\.\s*([^,}]+)", value):
            kind = _payload_kind(code, spread, depth + 1)
            if kind != "safe":
                return kind
        return "safe"
    if _schema(value):
        return "safe"
    base = re.match(r"^([A-Za-z_$][\w$]*)(?:\s*\.\s*data)?$", value)
    if not base:
        return "unknown"
    src, how = _source(code, base.group(1))
    if not src or how == "field":
        return "unknown"
    if _schema(src):
        return "safe"
    if BODY.match(src):
        return "raw"  # const body = await req.json(), or const { role, ...rest } = await req.json()
    if how == "assign" and src.lstrip().startswith("{"):
        return _payload_kind(code, src, depth + 1)
    return "unknown"


def _writes(code):
    for rx in WRITES:
        for m in rx.finditer(code):
            yield m.start(), _arg(code, m.end())
    for m in PRISMA.finditer(code):
        call = _arg(code, m.end(), limit=2000)
        for d in DATA.finditer(call):
            yield m.start(), _arg(call, d.end())


def mass_assignment(project):
    raw, unknown, total, files = [], [], 0, 0
    for rel, code in _server_files(project):
        found = list(_writes(code))
        if found:
            files += 1
        for offset, value in found:
            total += 1
            kind = _payload_kind(code, value)
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
