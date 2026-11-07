"""Next.js code: route handlers and Server Actions without an auth call (NEXT-05, NEXT-06, ACCESS-11), getSession()
on the server (AUTH-01), the secret-key client in client components (ACCESS-08), cron secrets (NEXT-15) and
next.config / header settings (NEXT-02, NEXT-03, NEXT-07, NEXT-11, BROWSER-01..05, BROWSER-08)."""

from __future__ import annotations

import json
import posixpath
import re

from .base import SUSPECTED, make, plural
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
AUTH = re.compile(r"\.auth\.(?:getUser|getClaims|getSession)\(|getServerSession\(|\bauth\(\s*\)|\bcurrentUser\(|"
                  r"\bgetAuth\(|\bauth\.protect\(|\b(?:require|ensure|assert|verify|check|get|validate|with)\w*"
                  r"(?:User|Auth|Session|Admin|Role|Owner|Permission|Signature|Secret|Token|Claims)\w*\s*\(|"
                  r"\bauthorization\b|CRON_SECRET|constructEvent\(|timingSafeEqual|jwtVerify\(|jwt\.verify\(",
                  re.IGNORECASE)
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
HEADERS = [
    ("BROWSER-01", "Strict-Transport-Security", re.compile(r"strict-transport-security", re.IGNORECASE)),
    ("BROWSER-02", "Content-Security-Policy", re.compile(r"content-security-policy(?!-report-only)", re.IGNORECASE)),
    ("BROWSER-03", "X-Content-Type-Options", re.compile(r"x-content-type-options", re.IGNORECASE)),
    ("BROWSER-04", "X-Frame-Options or frame-ancestors", re.compile(r"x-frame-options|frame-ancestors", re.IGNORECASE)),
    ("BROWSER-05", "Referrer-Policy", re.compile(r"referrer-policy", re.IGNORECASE)),
    ("BROWSER-08", "Permissions-Policy", re.compile(r"permissions-policy", re.IGNORECASE)),
]
UNSAFE_INLINE = re.compile(r"(?:script-src|default-src)[^;\n]*?'unsafe-inline'", re.IGNORECASE)
NONCE = re.compile(r"'nonce-|'strict-dynamic'|'sha(?:256|384|512)-", re.IGNORECASE)


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


def route_handlers(project):
    routes = [f for f in project.code_files() if ROUTE.search(f)]
    if not routes:
        return []
    open_routes, guarded = [], 0
    for rel in routes:
        code = _code(project, rel)
        db = DB.search(code)
        if not db:
            continue
        if AUTH.search(code):
            guarded += 1
        else:
            open_routes.append(_at(project, rel, code, db.start(), "touches data with no auth or session call in "
                                   "the handler"))
    if open_routes:
        return [make("NEXT-05", "warn", SUSPECTED + f"{plural(len(open_routes), 'route handler')} read or write data "
                     "without any auth, session or secret check in the file. Middleware alone does not protect them.",
                     open_routes)]
    return [make("NEXT-05", "pass", f"Every route handler that touches data ({guarded} of {len(routes)}) calls an "
                 "auth, session or secret check. Presence only: confirm the check gates the action.")]


def server_actions(project):
    actions, open_actions = 0, []
    for rel in project.code_files():
        code = _code(project, rel)
        if _directive(code) == "server":
            exports = list(EXPORT.finditer(code))
            for i, m in enumerate(exports):
                end = exports[i + 1].start() if i + 1 < len(exports) else len(code)
                segment = code[m.start():end]
                actions += 1
                db = DB.search(segment)
                if db and not AUTH.search(segment):
                    name = next((g for g in m.groups() if g), "default")
                    open_actions.append(_at(project, rel, code, m.start() + db.start(),
                                            f"Server Action {name} touches data with no auth or session call"))
        elif INLINE_SERVER.search(code) and _directive(code) != "client":
            actions += 1
            db = DB.search(code)
            if db and not AUTH.search(code):
                open_actions.append(_at(project, rel, code, db.start(), "inline Server Action file touches data with "
                                        "no auth or session call"))
    if not actions:
        return []
    out = []
    for cid in ("NEXT-06", "ACCESS-11"):
        if open_actions:
            out.append(make(cid, "warn", SUSPECTED + f"{plural(len(open_actions), 'Server Action')} change or read "
                            "data without an auth or session call. Every action is a public POST endpoint.",
                            open_actions))
        else:
            out.append(make(cid, "pass", f"{plural(actions, 'Server Action')} found; every one that touches data "
                            "calls an auth or session check. Presence only: confirm it also checks ownership."))
    return out


def _server_file(rel, code):
    d = _directive(code)
    if d == "client":
        return False
    return (d == "server" or ROUTE.search(rel) is not None or MIDDLEWARE.search(rel) is not None
            or re.search(r"(^|/)app/", rel) is not None or SERVER_HINT.search(code) is not None)


def session_trust(project):
    flagged, verified, uses = [], 0, False
    for rel in project.code_files():
        code = _code(project, rel)
        has_get, has_verified = GET_SESSION.search(code), VERIFIED.search(code)
        uses = uses or bool(has_get or has_verified)
        if not _server_file(rel, code):
            continue
        if has_verified:
            verified += 1
        elif has_get:
            flagged.append(_at(project, rel, code, has_get.start(), "server code reads the user from getSession() "
                               "with no getUser() or getClaims() in the file"))
    if flagged:
        return [make("AUTH-01", "fail", f"{plural(len(flagged), 'server file')} trust getSession(), which reads the "
                     "cookie without verifying it. Use getClaims() or getUser() for every server-side decision.",
                     flagged)]
    if verified:
        return [make("AUTH-01", "pass", f"{plural(verified, 'server file')} use getUser() or getClaims(); no server "
                     "file relies on getSession() alone.")]
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
        return [make("NEXT-15", "fail", f"{plural(len(bad), 'cron route')} run for anyone who calls the URL. Compare "
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
    for cid, label, rx in HEADERS:
        hit = next(((f, m) for f, t in texts.items() if (m := rx.search(t))), None)
        if not hit:  # headers are often kept in a helper module that next.config or the proxy imports
            for f in project.code_files():
                if (m := rx.search(t := _code(project, f))) and re.search(r"['\"`](?:" + rx.pattern + ")", t, re.IGNORECASE):
                    texts[f] = t
                    hit = (f, m)
                    break
        if not hit:
            out.append(make(cid, "warn", f"{label} is not set in the code or host config ({', '.join(header_files[:4])})"
                            ". Set it there, or confirm that the host adds it.",
                            [Finding(header_files[0], 1, f"no {label} header configured")]))
            continue
        f, m = hit
        if cid == "BROWSER-02":
            unsafe = UNSAFE_INLINE.search(texts[f])
            if unsafe and not NONCE.search(unsafe.group(0)):
                out.append(make(cid, "warn", "The CSP in the code allows 'unsafe-inline' scripts without a nonce or "
                                "hash.", [_at(project, f, texts[f], unsafe.start(), "script-src allows unsafe-inline")]))
                continue
        out.append(make(cid, "pass", f"{label} is set in the code.", [_at(project, f, texts[f], m.start(),
                                                                          f"{label} configured")]))
    return out


ANALYZERS = (route_handlers, server_actions, session_trust, secret_client, cron_secret, next_config)
CHECKS = ("NEXT-05", "NEXT-06", "ACCESS-11", "AUTH-01", "ACCESS-08", "NEXT-15", "NEXT-02", "NEXT-03", "NEXT-07",
          "NEXT-11", "BROWSER-01", "BROWSER-02", "BROWSER-03", "BROWSER-04", "BROWSER-05", "BROWSER-08")
