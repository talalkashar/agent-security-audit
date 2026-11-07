"""What the site gives away: files, secrets in JavaScript, source maps, framework banners, error details."""

from __future__ import annotations

import base64
import json
import re
import secrets
from datetime import UTC, datetime
from urllib.parse import urljoin, urlsplit

from ..crawl import crawl, next_chunks
from ..http import BudgetExceeded
from ..model import failed, passed, skipped, warned
from ..scope import same_origin
from . import auto

MAX_SCRIPTS = 40

# path -> (description, test(body_bytes, content_type) -> bool). A test must match the real file, not an HTML page.
ENV_LINE = re.compile(rb"^\s*(export\s+)?[A-Z][A-Z0-9_]{2,}\s*=", re.MULTILINE)


def _not_html(ctype, body):
    head = body[:200].lstrip().lower()
    return "html" not in (ctype or "").lower() and not head.startswith((b"<!doctype", b"<html"))


def _env(body, ctype):
    return _not_html(ctype, body) and len(ENV_LINE.findall(body[:20000])) >= 2


SENSITIVE_FILES = {
    "/.env": ("environment file", _env),
    "/.env.local": ("environment file", _env),
    "/.env.production": ("environment file", _env),
    "/.git/HEAD": ("git metadata", lambda b, c: _not_html(c, b) and (b.startswith(b"ref: refs/")
                                                                      or re.fullmatch(rb"[0-9a-f]{40}\s*", b) is not None)),
    "/.git/config": ("git config", lambda b, c: _not_html(c, b) and b"[core]" in b[:4000]),
    "/.DS_Store": ("macOS folder index", lambda b, c: b[:8] == b"\x00\x00\x00\x01Bud1"),
    "/.npmrc": ("npm config with token", lambda b, c: _not_html(c, b) and b"_authToken" in b[:8000]),
    "/.vercel/project.json": ("Vercel project link", lambda b, c: _not_html(c, b) and b'"projectId"' in b[:4000]),
    "/backup.sql": ("database dump", lambda b, c: _not_html(c, b) and re.search(rb"CREATE TABLE|INSERT INTO", b[:200000]) is not None),
    "/dump.sql": ("database dump", lambda b, c: _not_html(c, b) and re.search(rb"CREATE TABLE|INSERT INTO", b[:200000]) is not None),
    "/backup.zip": ("site archive", lambda b, c: b[:4] == b"PK\x03\x04"),
    "/docker-compose.yml": ("container config", lambda b, c: _not_html(c, b) and b"services:" in b[:8000]),
}


@auto("INFRA-04")
def sensitive_files(ctx):
    exposed, ev = [], []
    for path, (what, test) in SENSITIVE_FILES.items():
        resp = ctx.client.get(path)
        if resp.status == 200 and resp.body and test(resp.body, resp.get("content-type")):
            exposed.append(f"{path} ({what})")
            ev.append(f"GET {path} -> 200, content matches a real {what} (contents not shown)")
        else:
            ev.append(f"GET {path} -> {resp.status}")
    if exposed:
        return failed("INFRA-04", f"Sensitive files are downloadable: {', '.join(exposed)}. Treat every secret in them "
                      "as leaked and rotate it.", ev)
    return passed("INFRA-04", f"None of {len(SENSITIVE_FILES)} well-known sensitive files are served.", ev)


@auto("INFRA-05")
def security_txt(ctx):
    resp = ctx.client.get("/.well-known/security.txt")
    ev = [f"GET /.well-known/security.txt -> {resp.status}"]
    text = resp.text if resp.status == 200 and _not_html(resp.get("content-type"), resp.body) else ""
    if not text:
        return failed("INFRA-05", "No /.well-known/security.txt, so people who find a bug have no clear way to "
                      "report it.", ev)
    fields = {}
    for line in text.splitlines():
        k, sep, v = line.partition(":")
        if sep and not line.lstrip().startswith("#"):
            fields.setdefault(k.strip().lower(), v.strip())
    missing = [f for f in ("contact", "expires") if f not in fields]
    if missing:
        return warned("INFRA-05", f"security.txt is missing required field(s): {', '.join(missing)} (RFC 9116).", ev)
    try:
        expires = datetime.fromisoformat(fields["expires"])
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=UTC)
        if expires < datetime.now(UTC):
            return warned("INFRA-05", f"security.txt expired on {fields['expires']}.", ev)
    except ValueError:
        return warned("INFRA-05", "security.txt Expires is not an ISO 8601 date.", ev)
    return passed("INFRA-05", "security.txt lists a contact and a future expiry date.", ev + [f"Contact: {fields['contact']}"])


def scripts(ctx):
    """[(label, text)] for inline scripts and same-origin script files on every crawled page, plus Next.js chunks
    those reference (build manifest, RSC payload). At most MAX_SCRIPTS files. Cached per run."""
    if "scripts" in ctx.cache:
        return ctx.cache["scripts"]
    site = crawl(ctx)
    home = site.pages[0].url if site.pages else None
    out, by_page = [], {}
    for page, text in site.inline:
        by_page.setdefault(page, []).append(text)
    for page, texts in by_page.items():
        label = "home page inline scripts" if page == home else f"{urlsplit(page).path or '/'} inline scripts"
        out.append((label, "\n".join(texts)))
    queue = [r.url for r in site.resources if r.kind == "script"]
    for _, text in out:
        queue += [ctx.client.url(p) for p in next_chunks(text)]
    seen, i = set(), 0
    while i < len(queue) and len(seen) < MAX_SCRIPTS:
        url = queue[i]
        i += 1
        if url in seen or not same_origin(ctx.target, url):
            continue
        seen.add(url)
        try:
            resp = ctx.client.get(url, cache=True)
        except BudgetExceeded:
            break
        if resp.status == 200:
            out.append((urlsplit(url).path, resp.text))
            queue += [ctx.client.url(p) for p in next_chunks(resp.text)]
    ctx.cache["scripts"] = out
    return out


def _jwt_role(token):
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload)).get("role")
    except (ValueError, IndexError, AttributeError):
        return None


SECRET_PATTERNS = [
    ("Supabase secret key", re.compile(r"\bsb_secret_[A-Za-z0-9_-]{20,}")),
    ("Stripe live secret key", re.compile(r"\b[sr]k_live_[0-9A-Za-z]{20,}")),
    ("AWS access key id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("private key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----")),
    ("GitHub token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{50,})")),
    ("Anthropic API key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}")),
    ("OpenAI API key", re.compile(r"\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}")),
    ("Slack token", re.compile(r"\bxox[abprs]-[0-9A-Za-z-]{10,}")),
    ("SendGrid API key", re.compile(r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}")),
]
JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")


def mask(value):
    return value[:10] + "..." if len(value) > 14 else value[:4] + "..."


def find_secrets(text):
    """[(kind, masked)] for secret-looking strings. Public keys (Supabase anon/publishable) are not secrets."""
    hits = []
    for kind, pattern in SECRET_PATTERNS:
        for m in pattern.finditer(text):
            hits.append((kind, mask(m.group(0))))
    for m in JWT.finditer(text):
        if _jwt_role(m.group(0)) == "service_role":
            hits.append(("Supabase service_role JWT", mask(m.group(0))))
    return hits


@auto("NEXT-01")
def client_secrets(ctx):
    found = scripts(ctx)
    if not found:
        return skipped("NEXT-01", "No JavaScript found on the crawled pages to scan. Run a code review of "
                       "NEXT_PUBLIC_ variables instead.")
    ev, seen = [], set()
    for label, text in found:
        for kind, masked in find_secrets(text):
            if (kind, masked) not in seen:
                seen.add((kind, masked))
                ev.append(f"{label}: {kind} {masked}")
    if ev:
        return failed("NEXT-01", "Secret keys are shipped to every visitor's browser. Rotate them now, then move them "
                      "to server-only code.", ev)
    return passed("NEXT-01", f"No secret key formats found in {len(found)} script(s) from the crawled pages.",
                  [label for label, _ in found][:10])


SOURCEMAP = re.compile(r"[#@]\s*sourceMappingURL=([^\s'\"*]+)")


@auto("NEXT-02")
def source_maps(ctx):
    found = [(label, text) for label, text in scripts(ctx) if label.startswith("/")]
    if not found:
        return skipped("NEXT-02", "No same-origin script files found on the crawled pages.")
    exposed, ev, tried = [], [], 0
    for label, text in found:
        m = SOURCEMAP.search(text[-2000:])
        candidates = []
        if m and not m.group(1).startswith("data:"):
            candidates.append(urljoin(ctx.client.url(label), m.group(1)))
        elif tried < 3:
            candidates.append(ctx.client.url(label) + ".map")
            tried += 1
        for url in candidates:
            if not same_origin(ctx.target, url):
                continue
            resp = ctx.client.get(url)
            if resp.status == 200 and b'"mappings"' in resp.body[:500000]:
                exposed.append(urlsplit(url).path)
                ev.append(f"GET {urlsplit(url).path} -> 200 (source map)")
    if exposed:
        return failed("NEXT-02", f"{len(exposed)} source map(s) are public, so anyone can read the original source "
                      "code, comments and internal paths.", ev)
    return passed("NEXT-02", f"No source maps served for {len(found)} script(s).")


@auto("NEXT-03")
def powered_by(ctx):
    resp = ctx.client.home()
    value = resp.get("x-powered-by")
    if value:
        return failed("NEXT-03", f"X-Powered-By: {value} tells attackers which framework to target. "
                      "Set poweredByHeader: false in next.config.", [f"x-powered-by: {value}"])
    return passed("NEXT-03", "No X-Powered-By header.")


LEAK_MARKERS = [
    ("Python traceback", re.compile(r"Traceback \(most recent call last\)")),
    ("JavaScript stack frame", re.compile(r"\n\s+at [\w$.<>\[\] ]+ \(?(?:/|[A-Za-z]:\\|file:|webpack:|node:)[^\n)]*:\d+:\d+")),
    # Home directories only count with a source file after them, so links such as /home/pricing/ do not match.
    ("server file path", re.compile(r"(?:/var/task/|/app/node_modules/|[A-Za-z]:\\\\Users\\\\|"
                                    r"/(?:home|Users)/[\w.-]+/(?:[\w.@-]+/)*[\w.-]+\.(?:[cm]?[jt]sx?|py|rb|php|go|java)\b)")),
    ("Next.js development error overlay", re.compile(r"__nextjs_original-stack-frame|nextjs__container_errors")),
    ("database error", re.compile(r"SQLSTATE\[|PG::\w+Error|PrismaClient\w*Error|duplicate key value violates|syntax error at or near")),
    ("framework debug page", re.compile(r"Whoops, looks like something went wrong|DEBUG = True|Werkzeug Debugger")),
]


def find_leaks(text):
    return [name for name, pattern in LEAK_MARKERS if pattern.search(text)]


@auto("API-02")
def error_leaks(ctx):
    token = secrets.token_hex(6)
    probes = [
        ("GET", f"/asa-missing-{token}", None, {}),
        ("POST", f"/api/asa-missing-{token}", "{", {"Content-Type": "application/json"}),
    ]
    extra = ctx.opt("rate_limit_path")
    if extra:
        probes.append(("POST", extra, "{", {"Content-Type": "application/json"}))
    leaks, ev = [], []
    for method, path, body, headers in probes:
        resp = ctx.client.request(method, path, body=body, headers=headers)
        hit = find_leaks(resp.text)
        ev.append(f"{method} {path} -> {resp.status}" + (f": shows {', '.join(hit)}" if hit else ""))
        leaks += hit
    if leaks:
        return failed("API-02", "Error responses reveal internals (" + ", ".join(sorted(set(leaks))) + "). "
                      "Return a generic message and log details on the server.", ev)
    return passed("API-02", "Error responses show no stack traces, file paths or database errors.", ev)
