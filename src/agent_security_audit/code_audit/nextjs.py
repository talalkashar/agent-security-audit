"""Next.js code: route handlers and Server Actions without an auth call (NEXT-05, NEXT-06, ACCESS-11), getSession()
on the server (AUTH-01), the secret-key client in client components (ACCESS-08), cron secrets (NEXT-15) and
next.config / header settings (NEXT-02, NEXT-03, NEXT-07, NEXT-11, BROWSER-01..05, BROWSER-08)."""

from __future__ import annotations

import itertools
import json
import posixpath
import re

from ..checks import browser as live
from ..http import Response
from .base import SUSPECTED, make, plural
from .patterns import _arg
from .project import Finding, line_of, line_text, redact, strip_js_comments

EXT = r"\.[cm]?[jt]sx?$"
ROUTE = re.compile(r"(^|/)app/(.*/)?route" + EXT + r"|(^|/)pages/api/.+" + EXT)
MIDDLEWARE = re.compile(r"(^|/)(src/)?(middleware|proxy)" + EXT)
DIRECTIVE = re.compile(r"""^\s*(?:(['"])use strict\1;?\s*)?(['"])use (client|server)\2""")
INLINE_SERVER = re.compile(r"""(['"])use server\1""")
DB = re.compile(r"(?<!Array)(?<!Buffer)(?<!Object)\.from\(\s*['\"`][\w.-]+['\"`]\s*\)|\.rpc\(|\bprisma\.\w+\.|"
                r"\bdb\.(?:select|insert|update|delete|query|execute|transaction)\b|\b(?:pool|client|knex)\.query\(|"
                r"\bsql`|\.collection\(|createAdminClient|createServiceRoleClient|SERVICE_ROLE|service_role|"
                r"SUPABASE_SECRET_KEY|\bsupabaseAdmin\b")
# A gate stops an unauthorised caller by itself (it throws, redirects or wraps the handler), so calling it is enough.
GUARD_WORDS = r"(?:User|Auth|Session|Admin|Role|Owner|Permission|Signature|Secret|Token|Claims)"
GATE = re.compile(r"\bauth\.protect\(|\bjwtVerify\(|\bjwt\.verify\(|\bconstructEvent\(|"
                  r"\b(?:require|ensure|assert|with)(?:[A-Z_][\w$]*?)?" + GUARD_WORDS + r"[\w$]*\s*\(")
# A verifier only returns who the caller is (or whether a secret matched): it guards nothing unless its result is
# checked. getUserById(id) or getUsers() look a user up; they are not authentication and do not match.
VERIFIER = re.compile(r"\.auth\.(?:getUser|getClaims|getSession)\(|\bgetServerSession\(|\bauth\(\s*\)|"
                      r"\bcurrentUser\(\s*\)|\bgetAuth\(|\bget(?:Current)?(?:User|Session|Claims|AuthUser)\(\s*\)|"
                      r"\b(?:verify|check|validate)(?:[A-Z_][\w$]*?)?" + GUARD_WORDS + r"[\w$]*\s*\(|"
                      r"\btimingSafeEqual\(|\bCRON_SECRET\b")
# Reading the Authorization header counts as a guard; the word inside a message ("authorization required") does not.
AUTH_HEADER = re.compile(r"""(?:\.get|getHeader|header)\(\s*(['"`])authorization\1|"""
                         r"""headers\s*(?:\.\s*authorization\b|\[\s*(['"`])authorization\2\s*\])""", re.IGNORECASE)


def _blank_strings(code):
    """code with string literals, template text and comments blanked to spaces, in one linear pass. A ' or " string
    with no closing quote on its line is blanked to the line end, and an unclosed template or block comment to the
    end of the file: an odd quote hides code (no auth seen, so warn) rather than exposing string text as code."""
    out, i, n = [], 0, len(code)
    while i < n:
        c = code[i]
        if c == "/" and code.startswith("//", i):
            end = code.find("\n", i)
            end = n if end < 0 else end
        elif c == "/" and code.startswith("/*", i):
            end = code.find("*/", i + 2)
            end = n if end < 0 else end + 2
        elif c in "'\"`":
            end = i + 1
            while end < n and code[end] != c and (c == "`" or code[end] != "\n"):
                end += 2 if code[end] == "\\" else 1
            end = min(end + 1, n) if end < n and code[end] == c else min(end, n)
        else:
            j = i
            while j < n and code[j] not in "/'\"`":
                j += 1
            out.append(code[i:max(j, i + 1)])
            i = max(j, i + 1)
            continue
        out.append(" " * (end - i))
        i = end
    return "".join(out)


def _has_auth(code):
    """A guard in code, not counting words inside string literals or comments: a gate call, or a verifier call (or a
    read of the Authorization header) whose result reaches a condition. `await auth()` whose result is never
    checked guards nothing."""
    return _guard_at(code) is not None


def _guard_at(code):
    """Offset of the first guard in code (see _has_auth), or None."""
    blank = _blank_strings(code)
    found = [m.start() for m in GATE.finditer(blank) if not DECLARED.search(blank, max(0, m.start() - 40), m.start())][:1]
    found += [m.start() for m in itertools.chain(VERIFIER.finditer(blank), AUTH_HEADER.finditer(code))
              if _checked(blank, m.start(), m.end())][:1]
    return min(found) if found else None


DECLARED = re.compile(r"\bfunction\s*\*?\s*$")  # `function requireUser(` declares a gate, it does not call it
CHECK_WINDOW = 2000  # a guard checks the verifier's result within this many characters of the call
COND_HEAD = re.compile(r"\b(?:if|while)\s*\(")
COMPARE = r"(?:[!=]==?|&&|\|\||\?\?)"
ASSIGN = re.compile(r"(?:\b(?:const|let|var)\s+([\[{][^;]*?[\]}]|[A-Za-z_$][\w$]*)|(?:^|[;{}\n(])\s*([A-Za-z_$][\w$]*))"
                    r"\s*=\s*(?:await\s+)?(?:\(\s*)?$")


def _checked(blank, start, end):
    """Whether the verifier expression at blank[start:end] gates something: it sits inside an if/while condition or a
    comparison, or it is assigned to names that a condition or comparison reads within CHECK_WINDOW."""
    depth = blank[start:end].count("(") - blank[start:end].count(")")
    while depth > 0 and end < len(blank):
        depth += {"(": 1, ")": -1}.get(blank[end], 0)
        end += 1
    while start > 0 and (blank[start - 1].isalnum() or blank[start - 1] in "_$."):
        start -= 1
    stmt = blank[max(0, start - 300):start]
    stmt = stmt[max(stmt.rfind(";"), stmt.rfind("{"), stmt.rfind("}")) + 1:]
    heads = list(COND_HEAD.finditer(stmt))
    if heads and stmt[heads[-1].end():].count("(") >= stmt[heads[-1].end():].count(")"):
        return True
    if re.search(COMPARE + r"|!\s*(?:\(\s*)?(?:await\s+)?$", stmt) or \
            re.match(r"[\s)]*(?:" + COMPARE + r"|\?(?![.?]))", blank[end:end + 80]):
        return True
    m = ASSIGN.search(blank[max(0, start - 300):start])
    if not m:
        return False
    lhs = m.group(1) or m.group(2)
    names = set(re.findall(r"[A-Za-z_$][\w$]*(?![\w$]|\s*:)", lhs)) - {"await"}
    after = blank[end:end + CHECK_WINDOW]
    conds = [_paren(after, h.end()) for h in COND_HEAD.finditer(after)]
    for name in names:
        word = r"(?<![\w$.])" + re.escape(name) + r"(?![\w$])"
        if any(re.search(word, c) for c in conds) or \
                re.search(r"(?:!|" + COMPARE + r")\s*" + word, after) or \
                re.search(word + r"(?:\s*\??\.\s*[\w$]+)*\s*(?:" + COMPARE + r"|\?(?![.?]))", after):
            return True
    return False


def _paren(text, i):
    """The text from i up to the ) that closes the ( just before i."""
    depth, j = 1, i
    while j < len(text) and depth:
        depth += {"(": 1, ")": -1}.get(text[j], 0)
        j += 1
    return text[i:j - 1]


SERVICE = re.compile(r"SERVICE_ROLE|service_role|SUPABASE_SECRET_KEY|\bsb_secret_|createAdminClient|"
                     r"createServiceRoleClient|\bsupabaseAdmin\b")
SERVER_ONLY = re.compile(r"""import\s+['"]server-only['"]""")
IMPORT = re.compile(r"""(?:from\s+|import\s*\(\s*|require\(\s*|import\s+)['"]((?:\.{1,2}|@|~)/[^'"]+)['"]""")
GET_SESSION = re.compile(r"\.auth\.getSession\(")
VERIFIED = re.compile(r"\.auth\.(?:getUser|getClaims)\(")
SERVER_HINT = re.compile(r"""['"](?:next/headers|server-only)['"]|createServerClient\(""")
EXPORT = re.compile(r"^export\s+(?:default\s+)?(?:async\s+function\*?\s*(\w*)|function\s*(\w*)|const\s+(\w+)\s*=)",
                    re.MULTILINE)
NEXT_CONFIG = re.compile(r"(^|/)next\.config\.(?:[cm]?js|[cm]?ts)$")
HEADER_FILES = re.compile(r"(^|/)(next\.config\.(?:[cm]?js|[cm]?ts)|vercel\.json|netlify\.toml|_headers|"
                          r"(src/)?(middleware|proxy)" + EXT[:-1] + r")$")
# Each header check is settled by the live check's per-response logic, run on the values the code sets.
HEADERS = [
    ("BROWSER-01", "Strict-Transport-Security", ("strict-transport-security",), live._hsts),
    ("BROWSER-02", "Content-Security-Policy", ("content-security-policy",), live._csp),
    ("BROWSER-03", "X-Content-Type-Options", ("x-content-type-options",), live._nosniff),
    ("BROWSER-04", "X-Frame-Options or frame-ancestors", ("x-frame-options", "content-security-policy"),
     live._framing),
    ("BROWSER-05", "Referrer-Policy", ("referrer-policy",), live._referrer),
    ("BROWSER-08", "Permissions-Policy and Cross-Origin-Opener-Policy",
     ("permissions-policy", "cross-origin-opener-policy"), live._isolation),
]
HEADER_NAMES = sorted({n for _, _, names, _ in HEADERS for n in names}, key=len, reverse=True)
QUOTED_NAME = r"""(['"`])(""" + "|".join(re.escape(n) for n in HEADER_NAMES) + r")\1"
JS_HEADER = re.compile(r"\bkey\s*:\s*" + QUOTED_NAME + r"\s*,\s*value\s*:\s*|"
                       r"\.(?:set|append)\(\s*" + QUOTED_NAME.replace("\\1", "\\3") + r"\s*,\s*|"
                       + QUOTED_NAME.replace("\\1", "\\5") + r"\s*:\s*", re.IGNORECASE)
ANY_NAME = re.compile(QUOTED_NAME, re.IGNORECASE)
TEXT_HEADER = re.compile(r"""^\s*["']?(""" + "|".join(re.escape(n) for n in HEADER_NAMES)
                         + r""")["']?\s*[:=]\s*(.*?)\s*$""", re.IGNORECASE | re.MULTILINE)
CHAIN = re.compile(r"\.(?:trim|replace|replaceAll)\((?:[^()]|\([^()]*\))*\)\s*$")
JOINED = re.compile(r"""^\[([\s\S]*)\]\s*\.join\(\s*(['"])((?:(?!\2).)*)\2\s*\)$""")
STRING = re.compile(r"""'((?:[^'\\\n]|\\.)*)'|"((?:[^"\\\n]|\\.)*)\"""")
# Where one route's header block starts: headers after it land on the same responses.
ROUTE_START = {"js": re.compile(r"\bsource\s*:"), "toml": re.compile(r"^\s*\[\[headers\]\]", re.MULTILINE),
               "_headers": re.compile(r"^(?![#\s])\S", re.MULTILINE)}
MAX_COMBOS = 256


def _code(project, rel):
    return strip_js_comments(project.text(rel))


def _directive(code):
    m = DIRECTIVE.match(code)
    return m.group(3) if m else None


def _at(project, rel, code, offset, note):
    line = line_of(code, offset)
    return Finding(rel, line, note, redact(line_text(project.text(rel), line)))


def _resolve(project, rel, spec):
    if spec.startswith("."):
        base = posixpath.normpath(posixpath.join(posixpath.dirname(rel), spec))
        bases = [base]
    else:
        tail = spec[2:]
        bases = [f"src/{tail}", tail]
    files = set(project.files)
    for b in bases:
        for cand in [b] + [b + e for e in (".ts", ".tsx", ".js", ".jsx", ".mjs")] + [f"{b}/index{e}" for e in
                                                                                     (".ts", ".tsx", ".js")]:
            if cand in files:
                return cand
    return None


METHOD = re.compile(r"^export\s+(?:async\s+)?(?:function\s*\*?\s*|(?:const|let|var)\s+)"
                    r"(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b", re.MULTILINE)
TOP_LEVEL = re.compile(r"^(?:export|async|function|const|let|var|class|import)\b", re.MULTILINE)
DECL = re.compile(r"^(?:export\s+)?(?:async\s+)?(?:function\s*\*?\s*([A-Za-z_$][\w$]*)|"
                  r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=)", re.MULTILINE)


def _depths(code):
    """Brace depth at each offset, skipping strings and template text. An export always starts a top-level block,
    so a miscount here cannot merge two exported handlers."""
    out, depth, stack, i, confused = [0] * (len(code) + 1), 0, [], 0, 0
    while i < len(code):
        out[i] = depth
        c = code[i]
        if stack and stack[-1] in "'\"`":
            if c == "\\":
                out[i + 1:i + 2] = [depth] * len(out[i + 1:i + 2])
                i += 2
                continue
            if c == stack[-1]:
                stack.pop()
            elif c == "\n" and stack[-1] != "`":  # a ' or " string cannot cross a line: a regex literal fooled us
                stack.pop()
                confused = 1
            elif stack[-1] == "`" and code.startswith("${", i):
                stack.append("{")
                depth += 1
                i += 1
                out[i] = depth
        elif c in "'\"`":
            stack.append(c)
        elif c == "{":
            stack.append(c)
            depth += 1
        elif c == "}" and depth:
            depth -= 1
            if stack and stack[-1] == "{":
                stack.pop()
        i += 1
    # non-zero: the scan ended inside a block, string or template, or a quote ran past its line on the way
    out[len(code)] = depth + len(stack) + confused
    return out


def _blocks(code, rx):
    """[(name, start, end)] for each top-level declaration rx finds, ending where the next top-level one starts.
    When the depth scan ends unbalanced (a regex literal or odd string fooled it), every line that starts like a
    declaration ends the block before it, so a sibling declaration is never read as part of a handler."""
    depth = _depths(code)
    balanced = depth[-1] == 0
    tops = [m.start() for m in TOP_LEVEL.finditer(code)
            if not balanced or depth[m.start()] == 0 or code.startswith("export", m.start())] + [len(code)]
    out = []
    for m in rx.finditer(code):
        end = next(t for t in tops if t > m.start())
        out.append((next(g for g in m.groups() if g), m.start(), end))
    return out


def _route_methods(code):
    """Judge each exported HTTP method on its own, so an auth call in POST does not cover GET. A method touches data
    when it, or a helper in the file it calls, reaches the database; it is guarded when it, or such a helper, calls
    an auth check. Returns ([(offset, note)] for unguarded methods, guarded count, data-touching count, unsure
    count). In a file whose braces could not be matched, a guard is not trusted: the method counts as unsure."""
    balanced = _depths(code)[-1] == 0
    methods = _blocks(code, METHOD)
    if not methods:  # pages/api default handler, or methods re-exported: judge the file as one handler
        db = DB.search(code)
        if not db:
            return [], 0, 0, 0
        if _has_auth(code):
            return [], 1, 1, 0
        return [(db.start(), "touches data with no auth or session call in the handler")], 0, 1, 0
    helpers = {name: code[a:b] for name, a, b in _blocks(code, DECL) if (a, b) not in {(x, y) for _, x, y in methods}}
    open_, guarded, touching, unsure = [], 0, 0, 0
    for name, a, b in methods:
        seg = code[a:b]
        called = [h for h in helpers if re.search(r"(?<![\w$.])" + re.escape(h) + r"\s*\(", seg)]
        db = DB.search(seg)
        if not db and not any(DB.search(helpers[h]) for h in called):
            continue
        touching += 1
        if _has_auth(seg) or any(_has_auth(helpers[h]) for h in called):
            if balanced:
                guarded += 1
            else:
                unsure += 1
        elif _has_auth(code):
            open_.append((a + (db.start() if db else 0), (f"{name} touches data; the file has an auth call, but not "
                          f"in {name} or a helper it calls")))
        else:
            open_.append((a + (db.start() if db else 0), f"{name} touches data with no auth or session call"))
    return open_, guarded, touching, unsure


def route_handlers(project):
    routes = [f for f in project.code_files() if ROUTE.search(f)]
    if not routes:
        return []
    open_routes, guarded, touching, unsure, guards = [], 0, 0, [], []
    for rel in routes:
        code = _code(project, rel)
        found, ok, n, maybe = _route_methods(code)
        guarded += ok
        touching += n
        if ok and (at := _guard_at(code)) is not None:
            guards.append(_at(project, rel, code, at, "auth check found; confirm it gates the response"))
        if maybe:
            unsure.append(rel)
        open_routes += [_at(project, rel, code, off, note) for off, note in found]
    if open_routes:
        n = len(open_routes)
        return [make("NEXT-05", "warn", SUSPECTED + f"{plural(n, 'route handler')} "
                     f"{'reads or writes' if n == 1 else 'read or write'} data without an auth, session or secret "
                     "check in that handler. Middleware alone does not protect a route handler.", open_routes)]
    if unsure:
        return [make("NEXT-05", "manual", f"{plural(len(unsure), 'route file')} could not be split into handlers "
                     "reliably (unbalanced braces, strings, template or regex literals), so an auth call there may "
                     "belong to another declaration. Confirm each handler checks the caller: " + ", ".join(unsure[:5])
                     + ".")]
    if not touching:  # nothing seen is not proof: data reached through imported modules is not traced
        return [make("NEXT-05", "manual", f"No route handler in {plural(len(routes), 'route file')} reaches data "
                     "directly in its file. Handlers that reach data through imported modules are not traced; "
                     "confirm each one checks the caller.")]
    # A guard found by pattern is not proof that it gates the response, so this stays manual (never pass).
    return [make("NEXT-05", "manual", f"Not proven: every route handler that touches data ({guarded} of {touching}, "
                 f"in {plural(len(routes), 'route file')}) calls an auth, session or secret check whose result is "
                 "checked. A static read cannot prove the check gates the response; confirm each handler refuses a "
                 "caller who is not signed in or does not own the data.", guards)]


def server_actions(project):
    actions, open_actions, guards = 0, [], []
    for rel in project.code_files():
        code = _code(project, rel)
        if _directive(code) == "server":
            exports = list(EXPORT.finditer(code))
            for i, m in enumerate(exports):
                end = exports[i + 1].start() if i + 1 < len(exports) else len(code)
                segment = code[m.start():end]
                actions += 1
                db = DB.search(segment)
                name = next((g for g in m.groups() if g), "default")
                if db and (at := _guard_at(segment)) is None:
                    open_actions.append(_at(project, rel, code, m.start() + db.start(),
                                            f"Server Action {name} touches data with no auth or session call"))
                elif db:
                    guards.append(_at(project, rel, code, m.start() + at, f"Server Action {name}: auth check "
                                      "found; confirm it gates the action"))
        elif INLINE_SERVER.search(code) and _directive(code) != "client":
            actions += 1
            db = DB.search(code)
            if db and (at := _guard_at(code)) is None:
                open_actions.append(_at(project, rel, code, db.start(), "inline Server Action file touches data with "
                                        "no auth or session call"))
            elif db:
                guards.append(_at(project, rel, code, at, "inline Server Action: auth check found; confirm it gates "
                                  "the action"))
    if not actions:
        return []
    out = []
    for cid in ("NEXT-06", "ACCESS-11"):
        if open_actions:
            out.append(make(cid, "warn", SUSPECTED + f"{plural(len(open_actions), 'Server Action')} "
                            f"{'changes or reads' if len(open_actions) == 1 else 'change or read'} data without an auth or session call. Every action is a public POST endpoint.",
                            open_actions))
        else:
            out.append(make(cid, "manual", f"Not proven: {plural(actions, 'Server Action')} found; every one that "
                            "touches data calls an auth or session check whose result is checked. A static read "
                            "cannot prove the check gates the action; confirm each one refuses other users and "
                            "checks ownership.", guards))
    return out


def _server_file(rel, code):
    d = _directive(code)
    if d == "client":
        return False
    return (d == "server" or ROUTE.search(rel) is not None or MIDDLEWARE.search(rel) is not None
            or re.search(r"(^|/)app/", rel) is not None or SERVER_HINT.search(code) is not None)


def session_trust(project):
    flagged, verified, uses, verified_at = [], 0, False, []
    for rel in project.code_files():
        code = _code(project, rel)
        has_get, has_verified = GET_SESSION.search(code), VERIFIED.search(code)
        uses = uses or bool(has_get or has_verified)
        if not _server_file(rel, code):
            continue
        if has_verified:
            verified += 1
            verified_at.append(_at(project, rel, code, has_verified.start(), "verified user read here; confirm "
                                   "server-side decisions use it"))
        elif has_get:
            flagged.append(_at(project, rel, code, has_get.start(), "server code reads the user from getSession() "
                               "with no getUser() or getClaims() in the file"))
    if flagged:
        return [make("AUTH-01", "fail", f"{plural(len(flagged), 'server file')} "
                     f"{'trusts' if len(flagged) == 1 else 'trust'} getSession(), which reads the "
                     "cookie without verifying it. Use getClaims() or getUser() for every server-side decision.",
                     flagged)]
    if verified:
        return [make("AUTH-01", "manual", f"Not proven: {plural(verified, 'server file')} "
                     f"{'calls' if verified == 1 else 'call'} getUser() or getClaims() and no server file calls "
                     "getSession() alone. A static read cannot prove every server-side decision uses the verified "
                     "user; confirm a forged or expired session cookie is refused.", verified_at)]
    if uses:
        return [make("AUTH-01", "skip", "Supabase auth is only used in client code.")]
    return []


def secret_client(project):
    client_hits, server_files = [], []
    for rel in project.code_files():
        code = _code(project, rel)
        m = SERVICE.search(code)
        if _directive(code) != "client":
            if m:
                server_files.append(_at(project, rel, code, m.start(), "uses the secret-key (service role) client"))
            continue
        if m:
            client_hits.append(_at(project, rel, code, m.start(), "client component references the secret key"))
            continue
        for imp in IMPORT.finditer(code):
            target = _resolve(project, rel, imp.group(1))
            if not target:
                continue
            tcode = _code(project, target)
            if SERVICE.search(tcode) and not SERVER_ONLY.search(tcode):
                client_hits.append(_at(project, rel, code, imp.start(), f"client component imports {target}, which "
                                       "builds the secret-key client"))
    if client_hits:
        return [make("ACCESS-08", "fail", "The secret-key (service role) client is reachable from client components. "
                     "Keep it in server-only modules (import 'server-only') and rotate the key if it shipped.",
                     client_hits)]
    if server_files:
        return [make("ACCESS-08", "manual", "The secret-key client is used in "
                     f"{plural(len(server_files), 'server file')} and no client component. Confirm each use runs off user request paths or only "
                     "after an auth check.", server_files)]
    return [make("ACCESS-08", "pass", "No code uses the Supabase secret key or a service-role client.")] \
        if any(f.endswith("package.json") for f in project.files) else []


def cron_secret(project):
    try:
        config = json.loads(project.text("vercel.json") or "{}")
    except ValueError:
        return []
    crons = [c.get("path", "") for c in config.get("crons", []) if isinstance(c, dict)] \
        if isinstance(config, dict) else []
    if not crons:
        return []
    bad, ok = [], []
    for path in crons:
        segs = [re.escape(s) for s in path.split("?")[0].strip("/").split("/") if s]
        group = r"(?:/\([^/]+\))*"
        rx = re.compile(r"(^|/)(src/)?(app" + group + "".join("/" + s + group for s in segs) + "/route|pages/"
                        + "/".join(segs) + r"(/index)?)" + EXT)
        files = [f for f in project.files if rx.search(f)]
        if not files:
            bad.append(Finding("vercel.json", 1, f"cron path {path} has no route file in the project"))
        elif "CRON_SECRET" in project.text(files[0]):
            ok.append(files[0])
        else:
            bad.append(Finding(files[0], 1, f"cron route {path} never checks CRON_SECRET"))
    if bad:
        return [make("NEXT-15", "fail", f"{plural(len(bad), 'cron route')} "
                     f"{'runs' if len(bad) == 1 else 'run'} for anyone who calls the URL. Compare "
                     "the Authorization header with Bearer ${CRON_SECRET}.", bad)]
    return [make("NEXT-15", "pass", f"Every cron route ({len(ok)}) checks CRON_SECRET.", evidence=ok)]


def next_config(project):
    configs = [f for f in project.files if NEXT_CONFIG.search(f)]
    out = []
    if configs:
        rel = configs[0]
        code = _code(project, rel)

        def find(pattern):
            return re.search(pattern, code)

        if m := find(r"productionBrowserSourceMaps\s*:\s*true"):
            out.append(make("NEXT-02", "fail", "next.config turns on productionBrowserSourceMaps, so the original "
                            "source is public.", [_at(project, rel, code, m.start(), "source maps on in production")]))
        else:
            out.append(make("NEXT-02", "pass", f"{rel} does not turn on production browser source maps."))
        if find(r"poweredByHeader\s*:\s*false"):
            out.append(make("NEXT-03", "pass", f"{rel} sets poweredByHeader: false."))
        else:
            out.append(make("NEXT-03", "warn", f"{rel} does not set poweredByHeader: false, so Next.js sends "
                            "X-Powered-By unless a proxy strips it.", [Finding(rel, 1, "no poweredByHeader: false")]))
        origins = find(r"allowedOrigins\s*:\s*\[([^\]]*)\]")
        if origins and re.search(r"""['"`]\*{1,2}['"`]""", origins.group(1)):
            out.append(make("NEXT-07", "fail", "serverActions.allowedOrigins accepts any origin, which turns off the "
                            "Server Action CSRF check.", [_at(project, rel, code, origins.start(), "wildcard origin")]))
        else:
            out.append(make("NEXT-07", "pass", f"{rel} does not widen serverActions.allowedOrigins to any origin."))
        wild = find(r"""hostname\s*:\s*['"`]\*{1,2}['"`]""")
        svg = find(r"dangerouslyAllowSVG\s*:\s*true")
        if wild:
            out.append(make("NEXT-11", "fail", "images.remotePatterns allows any host, so the image optimizer fetches "
                            "anything for anyone.", [_at(project, rel, code, wild.start(), "wildcard image host")]))
        elif svg and not find(r"contentSecurityPolicy\s*:"):
            out.append(make("NEXT-11", "warn", "dangerouslyAllowSVG is on without an images.contentSecurityPolicy.",
                            [_at(project, rel, code, svg.start(), "SVG allowed without a CSP")]))
        else:
            out.append(make("NEXT-11", "pass", f"{rel} lists no wildcard image host."))
    header_files = [f for f in project.files if HEADER_FILES.search(f) and not f.endswith(".d.ts")]
    if not header_files:
        return out
    texts = {f: (_code(project, f) if re.search(EXT, f) else project.text(f)) for f in header_files}
    found = {f: _headers_in(f, t, project) for f, t in texts.items()}
    for cid, label, names, check in HEADERS:
        files = [f for f in found if any(h[0] in names for h in found[f])]
        if not files:  # headers are often kept in a helper module that next.config or the proxy imports
            for f in project.code_files():
                if f not in found and ANY_NAME.search(t := _code(project, f)):
                    texts[f], found[f] = t, _headers_in(f, t, project, loose=False)
                    if any(h[0] in names for h in found[f]):
                        files.append(f)
                        break
        if not files:
            out.append(make(cid, "warn", _not_set(label, header_files),
                            [Finding(header_files[0], 1, f"no {label} header configured")]))
            continue
        out.append(_header_result(project, cid, label, names, check, files, texts, found))
    return out


def _js_string(body):
    return re.sub(r"\\(.)", r"\1", body)


def _static(code, expr, depth=0, imported=None):
    """The text a header value expression evaluates to, or None when it is only known at run time. A plain name is
    followed to its const in the same file, or (through imported) to an exported const in an imported module."""
    e, prev = expr.strip(), None
    while e != prev:  # .replace(/\s{2,}/g, " ").trim() only tidies whitespace
        prev, e = e, CHAIN.sub("", e).strip()
    if m := STRING.fullmatch(e):
        return _js_string(m.group(1) if m.group(1) is not None else m.group(2))
    if e.startswith("`") and e.endswith("`") and len(e) > 1:
        body = re.sub(r"'nonce-\$\{[^{}]*\}'", "'nonce-generated'", e[1:-1])  # a per-request nonce is still a nonce
        return None if "${" in body else _js_string(body)
    if m := JOINED.fullmatch(e):
        items = list(STRING.finditer(m.group(1)))
        if not items or STRING.sub("", m.group(1)).replace(",", "").strip():
            return None
        return m.group(3).join(_js_string(i.group(1) if i.group(1) is not None else i.group(2)) for i in items)
    if depth < 3 and re.fullmatch(r"[A-Za-z_$][\w$]*", e):
        m = re.search(r"\b(?:const|let|var)\s+" + re.escape(e) + r"\s*(?::\s*string\s*)?=\s*", code)
        if m:
            return _static(code, _arg(code, m.end(), 4000, ",;"), depth + 1, imported)
        if imported and (other := imported(code, e)):
            return _static(other, e, depth + 1)
    return None


def _branches(expr):
    """[a, b] for a top-level `cond ? a : b`, else [expr]."""
    depth, quote, q, i = 0, None, -1, 0
    while i < len(expr):
        c = expr[i]
        if quote:
            if c == "\\":
                i += 1
            elif c == quote:
                quote = None
        elif c in "'\"`":
            quote = c
        elif c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif depth == 0 and c == "?" and q < 0 and expr[i + 1:i + 2] not in ("?", "."):
            q = i
        elif depth == 0 and c == ":" and q >= 0:
            return [expr[q + 1:i], expr[i + 1:]]
        i += 1
    return [expr]


def _importer(project, rel):
    """A function (code, name) -> the text of the module that `import { name } from "..."` in code points to."""
    def find(code, name):
        m = re.search(r"\bimport\s*\{[^}]*(?<![\w$])" + re.escape(name) + r"""(?![\w$])[^}]*\}\s*from\s*['"]"""
                      r"""((?:\.{1,2}|@|~)/[^'"]+)['"]""", code)
        if not m or re.search(r"\bas\s+" + re.escape(name) + r"\b", m.group(0)):
            return None
        target = _resolve(project, rel, m.group(1))
        return _code(project, target) if target else None
    return find


def _headers_in(rel, text, project=None, loose=True):
    """[(name, value or None, offset, route)] for the security headers a file sets. None means the value is built
    at run time (or written in a way this reader does not follow). Headers with the same route come from one route
    block (one source pattern), so they land on the same responses; other routes may not overlap."""
    out = []
    if rel.endswith(".json"):
        try:
            data = json.loads(text)
        except ValueError:
            data = None
        stack, routes = [(data, 0)], 0
        while stack:
            node, route = stack.pop()
            if isinstance(node, list):
                stack.extend((n, route) for n in reversed(node))
            elif isinstance(node, dict):
                key, value = node.get("key"), node.get("value")
                if isinstance(key, str) and key.lower() in HEADER_NAMES:
                    pos = text.find(key)
                    out.append((key.lower(), value if isinstance(value, str) else None, max(pos, 0), route))
                if isinstance(node.get("headers"), list):
                    routes += 1
                    route = routes
                stack.extend((n, route) for n in node.values())
        return out
    if not re.search(EXT, rel):  # netlify.toml, _headers
        starts = ROUTE_START["toml" if rel.endswith(".toml") else "_headers"]
        for m in TEXT_HEADER.finditer(text):
            value = m.group(2)
            if rel.endswith(".toml"):
                sm = STRING.fullmatch(value)
                value = _js_string(sm.group(1) if sm.group(1) is not None else sm.group(2)) if sm else None
            out.append((m.group(1).lower(), value, m.start(1), _route(starts, text, m.start(1))))
        return out
    seen = set()
    imported = project and _importer(project, rel)
    # With several source: routes, a headers list held in a variable (headers: common) is not inside any one
    # route's braces, so which responses get which value cannot be told: every value is then unknown.
    shared = len(ROUTE_START["js"].findall(text)) > 1 and _shared_headers(text)
    some = _some_requests(text) if MIDDLEWARE.search(rel) else lambda off: False
    for m in JS_HEADER.finditer(text):
        name = next(g for g in (m.group(2), m.group(4), m.group(6)) if g)
        partial = some(m.start())
        for expr in _branches(_arg(text, m.end(), 4000)):  # cond ? a : b sends a or b: judge both
            value = _static(text, expr, imported=imported)
            out.append((name.lower(), None if value is None or shared or partial else " ".join(value.split()),
                        m.start(),
                        _route(ROUTE_START["js"], text, m.start())))
        seen.add(m.start(next(i for i in (2, 4, 6) if m.group(i))) - 1)
    for m in ANY_NAME.finditer(text) if loose else ():
        if m.start() not in seen:  # named, but not set in a way this reader follows
            out.append((m.group(2).lower(), None, m.start(), _route(ROUTE_START["js"], text, m.start())))
    return out


MATCHER = re.compile(r"\bmatcher\s*:")


def _some_requests(text):
    """A matcher or unbalanced source prevents proving that headers reach every request.
    Per-statement branches are judged after their literal values, so weak values still fail."""
    code = _blank_strings(text)
    partial = bool(MATCHER.search(code) or _depths(code)[-1])
    return lambda off: partial


SHORTHAND_HEADERS = re.compile(r"[{,]\s*headers\s*[,}]")
HEADERS_KEY = re.compile(r"\bheaders\s*:\s*")


def _shared_headers(text):
    """True when some route's headers are not written inline as an array of objects: a shorthand `headers`, a
    variable, a call (common.slice()) or a spread ([...common]). Such a list may sit on several routes at once."""
    if SHORTHAND_HEADERS.search(text):
        return True
    for m in HEADERS_KEY.finditer(text):
        value = _arg(text, m.end(), 4000).strip()
        if not value.startswith("[") or "..." in value or not value.endswith("]"):
            return True
    return False


def _route(rx, text, offset):
    """The offset of the route block a header at offset belongs to (-1 when the file has one block)."""
    starts = [m.start() for m in rx.finditer(text, 0, offset)]
    return starts[-1] if starts else -1


_RANK = {"fail": 0, "warn": 1, "manual": 2, "pass": 3}
# A block opened by if, else, switch, case, try, catch, finally or a loop runs on some requests only (a loop body
# may run zero times, and a return inside it leaves the whole function).
COND_OPEN = re.compile(r"(?:\b(?:if|switch|catch|while)\s*\([^{};]*\)|\bfor\s*(?:await\s*)?\([^{}]*\)|"
                       r"\belse|\btry|\bfinally|\bdo|\bcase\b[^{};:]*:|\bdefault\s*:)\s*$")
BRACELESS_IF = re.compile(r"\b(?:if|for)\s*\(|\belse\b")
STATEMENT = re.compile(r"\s*[^;\n]*")  # one statement: up to the next ; or line break


def _conditional(text, offsets):
    """The offsets (header sets in a middleware or proxy file) that do not run on every request: inside an if, else,
    switch, try or loop block, as the body of a brace-less if, else or for, or after a conditional early return in
    the same function."""
    clean = _blank_strings(text)

    def braceless(pos):
        """True when pos is the body of a brace-less if, else or for in the same statement run. Code without
        semicolons ends a statement at the line break, so an earlier brace-less if guards its own line only.
        Looks back 400 characters and at the last three keywords, which keeps the scan linear on any input."""
        start = max(clean.rfind(c, max(0, pos - 400), pos) for c in ";{}") + 1 or max(0, pos - 400)
        for m in list(BRACELESS_IF.finditer(clean, start, pos))[-3:]:
            body, depth = m.end(), 0
            if clean[body - 1] == "(":  # skip the condition to its closing parenthesis
                depth = 1
                while body < pos and depth:
                    depth += {"(": 1, ")": -1}.get(clean[body], 0)
                    body += 1
            if not depth and STATEMENT.match(clean, body, pos).end() >= pos:
                return True
        return False

    # Each open block is [conditional, holds a conditional return]; the counts keep every event O(1).
    stack, plain, ncond, nreturn, out = [], [], 0, 0, set()
    events = sorted([(m.start(), m.group()) for m in re.finditer(r"[{}]|\breturn\b", clean)]
                    + [(o, "set") for o in offsets])
    for pos, kind in events:
        if kind == "{":
            cond = bool(COND_OPEN.search(clean[max(0, pos - 300):pos]))
            ncond += cond
            if not cond:
                plain.append(len(stack))
            stack.append([cond, False])
        elif kind == "}":
            if stack:
                cond, returned = stack.pop()
                ncond -= cond
                nreturn -= returned
                if not cond:
                    plain.pop()
        elif kind == "return":
            if plain and not stack[plain[-1]][1] and (ncond or braceless(pos)):
                stack[plain[-1]][1] = True  # later sets in this function run on some requests only
                nreturn += 1
        elif ncond or nreturn or braceless(pos):
            out.add(pos)
    return out


def _header_result(project, cid, label, names, check, files, texts, found):
    """Judge each file's header values with the live check; the weakest file decides."""
    per_file = []
    for f in files:
        hits = [h for h in found[f] if h[0] in names]
        if cid == "BROWSER-04":  # a CSP only matters here when it may hold frame-ancestors
            hits = [h for h in hits if h[0] != "content-security-policy" or h[1] is None
                    or "frame-ancestors" in h[1].lower()]
            if not hits:
                continue
        findings = [_at(project, f, texts[f], off, f"{name}: " + (redact(value, 120) if value is not None else
                                                                  "value built at run time"))
                    for name, value, off, _ in hits]
        if any(v is None for _, v, _, _ in hits):
            per_file.append(("manual", (f"{f} sets {label} from a value built at run time, or only on some requests "
                             "(a branch, an early return or a matcher in middleware), so the code alone does not "
                             "show what browsers get. Confirm it on the live site."), findings))
            continue
        # Judge each route block on its own: headers set on different routes may never meet on one response.
        routes = {}
        for name, value, _, route in hits:
            vals = routes.setdefault(route, {}).setdefault(name, [])
            if value not in vals:
                vals.append(value)
        present = {n for own in routes.values() for n in own}
        judged = []
        for route, own in routes.items():
            status, summary = _judge(check, own)
            if status != "pass" and set(own) < present:
                others = {n: [v for r, o in routes.items() if r != route for v in o.get(n, ())]
                          for n in present - set(own)}
                if _judge(check, {**own, **others})[0] == "pass":
                    status, summary = "manual", (f"sets {label} on different routes, so the code does not show "
                                                 "one response that carries them together. Confirm it on the live "
                                                 "site.")
            judged.append((status, f"{f}: {summary}"))
        status, summary = min(judged, key=lambda x: _RANK[x[0]])
        if status != "fail" and MIDDLEWARE.search(f) and _conditional(texts[f], [off for _, _, off, _ in hits]):
            status, summary = "manual", (f"{f} sets {label} only in some branches (if/else, switch or after an early "
                                         "return), so the code does not show that every response carries it. Confirm "
                                         "it on the live site.")
        per_file.append((status, summary, findings))
    if not per_file:
        return make(cid, "warn", _not_set(label, files), [Finding(files[0], 1, f"no {label} header configured")])
    per_file.sort(key=lambda x: _RANK[x[0]])
    status, summary, _ = per_file[0]
    findings = [fd for _, _, fds in per_file for fd in fds]
    if status == "pass":
        summary = f"{label} in the code: " + summary.split(": ", 1)[1]
    return make(cid, status, summary, findings)


def _not_set(label, files):
    both = " and " in label
    return (f"{label} {'are' if both else 'is'} not set in the code or host config ({', '.join(files[:4])}). Set "
            f"{'them' if both else 'it'} there, or confirm that the host adds {'them' if both else 'it'}.")


def _judge(check, values):
    """(status, summary) for the weakest combination of the values one route sets, run through the live check.
    Too many combinations to judge them all: never a pass."""
    judged = []
    for i, combo in enumerate(itertools.product(*([(n, v) for v in vs] for n, vs in values.items()))):
        if i == MAX_COMBOS:
            if all(s == "pass" for s, _ in judged):
                return "manual", "sets too many value combinations to judge them all. Confirm it on the live site."
            break
        r = check(Response("https://code-audit.invalid/", 200, "OK", list(combo)))
        judged.append((r.status if r.status in _RANK else "manual", r.summary))
    return min(judged, key=lambda x: _RANK[x[0]])


ANALYZERS = (route_handlers, server_actions, session_trust, secret_client, cron_secret, next_config)
CHECKS = ("NEXT-05", "NEXT-06", "ACCESS-11", "AUTH-01", "ACCESS-08", "NEXT-15", "NEXT-02", "NEXT-03", "NEXT-07",
          "NEXT-11", "BROWSER-01", "BROWSER-02", "BROWSER-03", "BROWSER-04", "BROWSER-05", "BROWSER-08")
