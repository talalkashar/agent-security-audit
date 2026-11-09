"""What the site gives away: files, secrets in JavaScript, source maps, framework banners, error details."""

from __future__ import annotations

import base64
import json
import re
import secrets
from datetime import UTC, datetime
from urllib.parse import urljoin, urlsplit

from ..crawl import crawl, next_chunks
from ..http import (
    TIME_BUDGET_MESSAGE,
    BudgetExceeded,
    Excluded,
    ResponseTooSlow,
    TimeBudgetExceeded,
    busy,
    challenge_of,
)
from ..model import Result, failed, passed, skipped, warned
from ..scope import same_origin
from . import are, auto, count
from .ratelimit import login_endpoint

MAX_SCRIPTS = 40
# Inline scripts are labelled "<page> inline scripts". The label is display text, never a URL to request.
INLINE_LABEL = " inline scripts"

# path -> (description, test(body_bytes, content_type) -> bool). A test must match the real file, not an HTML page.
# KEY=value, any case, optionally after "export". A dotenv file may hold a single line.
ENV_LINE = re.compile(rb"(?:export[ \t]+)?[A-Za-z_][A-Za-z0-9_.-]*[ \t]*=")


def _not_html(ctype, body):
    """security.txt: a text/html type, or a body that opens as an HTML document, is not the text file."""
    head = body[:200].lstrip().lower()
    return "html" not in (ctype or "").lower() and not head.startswith((b"<!doctype", b"<html"))


def _file_bytes(ctype, body):
    """True when a sensitive-path body can be the real file rather than an HTML page.

    nginx's default_type is text/html, so that type alone must not hide KEY=VALUE, git, SQL, npmrc,
    Vercel or compose bytes. A page opens with <!doctype or <html, or the type says html and the body
    opens with a tag.
    """
    head = body[:200].lstrip().lower()
    if head.startswith((b"<!doctype", b"<html")):
        return False
    return not ("html" in (ctype or "").lower() and head.startswith(b"<"))


def _env(body, ctype):
    """A dotenv file: not an HTML page, and most of its first lines (comments and blanks aside) are KEY=value lines.
    One line is enough; an error page or script with a stray assignment is not."""
    if not _file_bytes(ctype, body):
        return False
    lines = [ln.strip() for ln in body[:20000].splitlines()[:50]]
    lines = [ln for ln in lines if ln and not ln.startswith(b"#")]
    hits = sum(ENV_LINE.match(ln) is not None for ln in lines)
    return hits >= 1 and hits * 2 > len(lines)


SENSITIVE_FILES = {
    "/.env": ("environment file", _env),
    "/.env.local": ("environment file", _env),
    "/.env.production": ("environment file", _env),
    "/.git/HEAD": ("git metadata", lambda b, c: _file_bytes(c, b) and (b.startswith(b"ref: refs/")
                                                                       or re.fullmatch(rb"[0-9a-f]{40}\s*", b) is not None)),
    "/.git/config": ("git config", lambda b, c: _file_bytes(c, b) and b"[core]" in b[:4000]),
    "/.DS_Store": ("macOS folder index", lambda b, c: b[:8] == b"\x00\x00\x00\x01Bud1"),
    "/.npmrc": ("npm config with token", lambda b, c: _file_bytes(c, b) and b"_authToken" in b[:8000]),
    "/.vercel/project.json": ("Vercel project link", lambda b, c: _file_bytes(c, b) and b'"projectId"' in b[:4000]),
    "/backup.sql": ("database dump", lambda b, c: _file_bytes(c, b) and re.search(rb"CREATE TABLE|INSERT INTO", b[:200000]) is not None),
    "/dump.sql": ("database dump", lambda b, c: _file_bytes(c, b) and re.search(rb"CREATE TABLE|INSERT INTO", b[:200000]) is not None),
    "/backup.zip": ("site archive", lambda b, c: b[:4] == b"PK\x03\x04"),
    "/docker-compose.yml": ("container config", lambda b, c: _file_bytes(c, b) and b"services:" in b[:8000]),
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
    return passed("INFRA-04", f"None of these {len(SENSITIVE_FILES)} well-known sensitive paths serves the file "
                  "(other paths were not tried).", ev)


@auto("INFRA-05")
def security_txt(ctx):
    resp = ctx.client.get("/.well-known/security.txt")
    ev = [f"GET /.well-known/security.txt -> {resp.status}"]
    # RFC 9116 section 3 lets the file redirect; same-origin hops are followed, other hosts are not visited.
    for _ in range(3):
        loc = resp.get("location") if resp.is_redirect else None
        if not loc:
            break
        try:
            nxt = urljoin(resp.url, loc)
            off_site = not same_origin(ctx.target, nxt)
        except ValueError:
            break
        if off_site:
            return Result("INFRA-05", "manual", "/.well-known/security.txt redirects to another host, which this scan "
                          "does not visit (RFC 9116 allows the redirect). Open it and check Contact and Expires.",
                          ev + [f"location: {loc[:200]}"])
        resp = ctx.client.get(nxt)
        ev.append(f"redirected to {urlsplit(nxt).path or '/'} -> {resp.status}")
    text = resp.text if resp.status == 200 and _not_html(resp.get("content-type"), resp.body) else ""
    if not text:
        return warned("INFRA-05", "No /.well-known/security.txt, so people who find a bug have no clear way to "
                      "report it.", ev)
    fields = {}
    for line in text.splitlines():
        k, sep, v = line.partition(":")
        if sep and not line.lstrip().startswith("#"):
            fields.setdefault(k.strip().lower(), v.strip())
    missing = [f for f in ("contact", "expires") if f not in fields]
    if missing:
        return warned("INFRA-05", f"security.txt is missing required {'field' if len(missing) == 1 else 'fields'}: "
                      f"{', '.join(missing)} (RFC 9116).", ev)
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
        if ctx.cache.get("scripts_cut"):  # built from a crawl or fetches a budget cut short
            ctx.cache["data_cut"] = ctx.cache["scripts_cut"]
        if ctx.cache.get("scripts_excluded"):  # built without excluded pages or files: no reader may pass on it
            ctx.cache["excluded"] = ctx.cache["scripts_excluded"]
        return ctx.cache["scripts"]
    site = crawl(ctx)
    crawl_mark, left_out = ctx.cache.get("excluded"), 0
    if site.cut:
        ctx.cache["scripts_cut"] = site.cut
    home = site.pages[0].url if site.pages else None
    out, by_page = [], {}
    for page, text in site.inline:
        by_page.setdefault(page, []).append(text)
    for page, texts in by_page.items():
        label = ("home page" if page == home else urlsplit(page).path or "/") + INLINE_LABEL
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
        except TimeBudgetExceeded:
            ctx.cache["scripts_cut"] = ctx.cache["data_cut"] = TIME_BUDGET_MESSAGE
            break
        except BudgetExceeded:
            ctx.cache["scripts_cut"] = ctx.cache["data_cut"] = ("not run: request budget used up before every "
                                                                "script was read")
            break
        except ResponseTooSlow as exc:
            ctx.cache["scripts_cut"] = ctx.cache["data_cut"] = (f"{urlsplit(url).path} answered too slowly to read "
                                                                f"({exc})")
            continue
        except Excluded:  # never requested; the other scripts are still read, so a finding in them stands
            left_out += 1
            continue
        if busy(resp):  # still 429 after the client's retry: this script was never seen
            ctx.cache["scripts_cut"] = ctx.cache["data_cut"] = (f"{urlsplit(url).path} kept answering {resp.status} "
                                                                "(the target asked the scan to slow down)")
            continue
        if resp.status == 200:
            out.append((urlsplit(url).path, resp.text))
            queue += [ctx.client.url(p) for p in next_chunks(resp.text)]
    if len(seen) >= MAX_SCRIPTS and not ctx.cache.get("scripts_cut") and any(
            u not in seen and same_origin(ctx.target, u) for u in queue[i:]):
        ctx.cache["scripts_cut"] = ctx.cache["data_cut"] = (f"not run: more than {MAX_SCRIPTS} script files; only "
                                                            f"the first {MAX_SCRIPTS} were read")
    if crawl_mark or left_out:
        ctx.cache["scripts_excluded"] = ctx.cache["excluded"] = "; ".join(
            filter(None, [crawl_mark, left_out and f"{left_out} script file{'s' if left_out != 1 else ''} not read"]))
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
    return passed("NEXT-01", f"No secret key formats found in {count(len(found), 'script')} from the crawled pages.",
                  [label for label, _ in found][:10])


MAX_MAP_GUESSES = 10
SOURCEMAP = re.compile(r"[#@]\s*sourceMappingURL=([^\s'\"*]+)")


@auto("NEXT-02")
def source_maps(ctx):
    found = [(label, text) for label, text in scripts(ctx)
             if label.startswith("/") and not label.endswith(INLINE_LABEL)]
    if not found:
        return skipped("NEXT-02", "No same-origin script files found on the crawled pages.")
    exposed, ev, tried, probed, covered, unread = [], [], 0, 0, 0, []
    for label, text in found:
        m = SOURCEMAP.search(text[-2000:])
        candidates = []
        if m and m.group(1).lower().startswith("data:"):  # the map ships inside the script itself
            exposed.append(f"{label} (inline source map)")
            ev.append(f"{label}: sourceMappingURL is an inline data: URL")
            covered += 1
            continue
        if m:
            candidates.append(urljoin(ctx.client.url(label), m.group(1)))
        elif tried < MAX_MAP_GUESSES:
            candidates.append(ctx.client.url(label) + ".map")
            tried += 1
        candidates = [u for u in candidates if same_origin(ctx.target, u)]
        covered += bool(candidates)
        for url in candidates:
            resp = ctx.client.get(url)
            probed += 1
            # The client keeps the whole body up to its cap. A long sources list can put "mappings" past
            # the first 500 KB, and a body cut off at the cap must not pass: the key may be in the unread tail.
            if resp.status == 200 and b'"mappings"' in resp.body:
                exposed.append(urlsplit(url).path)
                ev.append(f"GET {urlsplit(url).path} -> 200 (source map)")
            elif resp.status == 200 and resp.truncated:
                unread.append(urlsplit(url).path)
                ev.append(f"GET {urlsplit(url).path} -> 200, body cut off before a source map could be ruled out")
    if exposed:
        return failed("NEXT-02", f"{count(len(exposed), 'source map')} {are(len(exposed))} public, so anyone can read the original source "
                      "code, comments and internal paths.", ev)
    if not probed:
        return Result("NEXT-02", "manual", f"None of {count(len(found), 'same-origin script')} could be probed for a "
                      "source map. Open each script's URL with .map appended.")
    if covered * 2 < len(found):  # a sample this small says little about the rest of the build
        return Result("NEXT-02", "manual", f"No source map served for the {count(covered, 'script')} probed, but "
                      f"{len(found) - covered} of {count(len(found), 'same-origin script')} were not probed. Open the "
                      "others with .map appended.", ev)
    if unread:
        return Result("NEXT-02", "manual", f"{count(len(unread), 'map URL')} returned more than this scan keeps, so a "
                      "source map in the unread bytes was not ruled out.", ev)
    return passed("NEXT-02", f"No source map served: {count(probed, 'map URL')} probed for {covered} of "
                  f"{count(len(found), 'same-origin script')} (each script that names a map, plus .map guesses for "
                  f"{count(tried, 'script')}).", ev)


@auto("NEXT-03")
def powered_by(ctx):
    resp = ctx.client.home()
    value = resp.get("x-powered-by")
    if value:
        return failed("NEXT-03", f"X-Powered-By: {value} tells attackers which framework to target. "
                      "Set poweredByHeader: false in next.config.", [f"x-powered-by: {value}"])
    if resp.status >= 400:  # a proxy or firewall answer, not the app's own headers
        return Result("NEXT-03", "manual", f"Not proven: the home page answered {resp.status}, which a proxy or "
                      "firewall may have sent, so the app's own headers were not observed.", [f"GET / -> {resp.status}"])
    return passed("NEXT-03", "No X-Powered-By header on the home page.", [f"GET / -> {resp.status}"])


BANNERS = ("server", "x-aspnet-version", "x-aspnetmvc-version")
VERSION = re.compile(r"\d+\.\d+")


@auto("API-25")
def version_banners(ctx):
    resp = ctx.client.home()
    seen = [(name, resp.get(name)) for name in BANNERS if resp.get(name)]
    versioned = [f"{name}: {value}" for name, value in seen if VERSION.search(value)]
    if versioned:
        return failed("API-25", f"{count(len(versioned), 'response header')} {are(len(versioned))} giving away the "
                      "server software version, which maps straight to known CVEs.", versioned)
    shown = [f"{name}: {value}" for name, value in seen] or ["no Server, X-AspNet-Version or X-AspNetMvc-Version header"]
    if resp.status >= 400:
        return Result("API-25", "manual", f"Not proven: the home page answered {resp.status}, which a proxy or "
                      "firewall may have sent, so the origin's own headers were not observed.",
                      [f"GET / -> {resp.status}"] + shown)
    return passed("API-25", "No version number in the Server or ASP.NET version headers.",
                  [f"GET / -> {resp.status}"] + shown)


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


NOT_A_HANDLER = (401, 403, 404, 405, 407, 429, 502, 503, 504)


@auto("API-02")
def error_leaks(ctx):
    token = secrets.token_hex(6)
    probes = [
        ("GET", f"/asa-missing-{token}", None, {}),
        ("POST", f"/api/asa-missing-{token}", "{", {"Content-Type": "application/json"}),
    ]
    extra = login_endpoint(ctx)
    if extra and not extra["refused"]:
        # API-01 may just have tripped this endpoint's limiter: take its 429 as an answer (NOT_A_HANDLER below)
        # instead of waiting it out.
        probes.append(("POST", extra["path"], "{", {"Content-Type": "application/json"}, False))
    leaks, handled, ev = [], [], []
    for method, path, body, headers, *backoff in probes:
        resp = ctx.client.request(method, path, body=body, headers=headers, backoff=all(backoff))
        hit = find_leaks(resp.text)
        ev.append(f"{method} {path} -> {resp.status}" + (f": shows {', '.join(hit)}" if hit else ""))
        leaks += hit
        # Not-found and wrong-method answers come from the router; auth, proxy-auth and throttle answers often come
        # from middleware, a CDN or a WAF before any route handler runs; gateway errors and firewall challenges come from
        # the proxy. None of them proves a handler's error path ran.
        if resp.status >= 400 and resp.status not in NOT_A_HANDLER and not challenge_of(resp):
            handled.append(path)
    if leaks:
        return failed("API-02", "Error responses reveal internals (" + ", ".join(sorted(set(leaks))) + "). "
                      "Return a generic message and log details on the server.", ev)
    if not handled:
        return Result("API-02", "manual", "Only not-found, auth or block answers came back, and they show no "
                      "internals, but no request reached a handler's error path. Name an API route with --rate-limit-path, or check "
                      "the error handler in code.", ev)
    return passed("API-02", "Error responses show no stack traces, file paths or database errors, including a "
                  "handler error on " + ", ".join(dict.fromkeys(handled)) + ".", ev)
