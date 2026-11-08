"""Browser-side defenses proven from response headers and cookies (OSI layer 7).

Header checks read every HTML page of the shared crawl (home first) and report the worst page, because a header set
only on the home page leaves the rest of the site open."""

from __future__ import annotations

import html
import ipaddress
import re
from urllib.parse import urlsplit

from ..crawl import crawl, is_html
from ..model import Result, failed, passed, skipped, warned
from . import auto, count

ONE_YEAR = 31536000
PROBE_ORIGIN = "https://asa-origin-probe.invalid"
# Whole words in a cookie name (split on punctuation and camelCase) that mark a session or auth cookie. Whole words, so
# "author" or "consider" do not count.
SESSION_WORDS = {"session", "sess", "sessid", "sessionid", "sid", "auth", "token", "jwt", "login", "remember",
                 "refresh", "jsessionid", "phpsessid", "cfid"}
# Run-together platform names: ASP.NET .ASPXAUTH and ASPSESSIONID<suffix>, Drupal SESS<hash> and SSESS<hash>,
# MOODLESESSION, ColdFusion CFTOKEN (CFID is a whole word above). A word counts when it starts with sess or ssess, contains session, or ends with
# auth or token; "author", "authorized" and "tokenizer" still do not.
SESSION_RUN_ON = re.compile(r"^s?sess|session|(auth|token)$")
# Double-submit CSRF cookies (Django csrftoken, Laravel/Angular XSRF-TOKEN, csurf _csrf) must be readable by
# JavaScript, so a missing HttpOnly on them is by design.
CSRF_WORDS = {"csrf", "xsrf", "csrftoken", "xsrftoken"}
SAFE_REFERRER = {"no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin"}
KNOWN_REFERRER = SAFE_REFERRER | {"no-referrer-when-downgrade", "origin", "origin-when-cross-origin", "unsafe-url"}
NONCE_OR_HASH = ("'nonce-", "'sha256-", "'sha384-", "'sha512-")


def _hdr(resp, name):
    value = resp.get(name)
    return f"{name}: {value}" if value is not None else f"{name}: (not set)"


META_TAG = re.compile(r"(?is)<meta\b[^>]*>")
META_ATTR = re.compile(r"""(?is)([\w:-]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))""")
# Browsers ignore these directives when the policy comes from a <meta> tag (CSP3, section 3.3).
META_IGNORED = ("frame-ancestors", "report-uri", "sandbox")


def meta_csp(resp):
    """Policies delivered in <meta http-equiv="Content-Security-Policy" content="..."> on an HTML page."""
    if not is_html(resp):
        return []
    out = []
    for tag in META_TAG.findall(resp.text[:65536]):
        attrs = {m.group(1).lower(): html.unescape(m.group(2) or m.group(3) or m.group(4) or "")
                 for m in META_ATTR.finditer(tag[5:])}
        if attrs.get("http-equiv", "").strip().lower() == "content-security-policy" and attrs.get("content", "").strip():
            out.append(attrs["content"].strip())
    return out


def _csp_ev(resp):
    return [_hdr(resp, "content-security-policy")] + [f'<meta http-equiv="Content-Security-Policy">: {v}'
                                                      for v in meta_csp(resp)]


RANK = {"fail": 0, "warn": 1, "manual": 2, "pass": 3}


def _page_path(resp):
    parts = urlsplit(resp.url)
    return (parts.path or "/") + (f"?{parts.query}" if parts.query else "")


def per_page(ctx, judge):
    """Run judge(resp) -> Result on every crawled HTML page (or the home page when the crawl found none) and return
    the worst result, naming the page it came from and how many pages share it."""
    pages = list(crawl(ctx).pages) or [ctx.client.home()]
    judged = [(page, judge(page)) for page in pages]
    page, worst = min(judged, key=lambda pr: RANK.get(pr[1].status, 3))
    same = [_page_path(p) for p, r in judged if (r.status, r.summary) == (worst.status, worst.summary)]
    worst.evidence = [f"page: {_page_path(page)}"] + worst.evidence
    if worst.status == "pass":  # say how much of the site the pass covers
        worst.summary = worst.summary.rstrip(".") + (f" (all {len(pages)} crawled pages)." if len(pages) > 1
                                                     else " (1 page examined).")
    elif len(pages) > 1:
        listed = ", ".join(same[:5]) + (", ..." if len(same) > 5 else "")
        worst.summary += f" Seen on {len(same)} of {count(len(pages), 'crawled page')}: {listed}."
    return worst


def parse_csp(value):
    """Return {directive: [sources]} for one CSP header value. The first occurrence of a directive wins."""
    out = {}
    for part in (value or "").split(";"):
        tokens = part.strip().split()
        if tokens and tokens[0].lower() not in out:
            out[tokens[0].lower()] = [t for t in tokens[1:]]
    return out


def _merged_csp(resp):
    """One dict per enforced CSP. Several headers (or one header with comma-separated policies) and <meta> policies
    all apply: a load must pass every policy, so the strictest policy decides each question."""
    policies = [parse_csp(p) for v in resp.get_all("content-security-policy") for p in v.split(",") if p.strip()]
    for value in meta_csp(resp):
        policy = {k: v for k, v in parse_csp(value).items() if k not in META_IGNORED}
        if policy:
            policies.append(policy)
    return policies


def _any_host(source):
    """True for a script source that matches every host: *, a bare scheme (https:, data:, blob:...),
    scheme://*, or a wildcard over a whole top-level domain such as *.com."""
    s = source.lower()
    if s.startswith("'"):
        return False
    if s == "*" or (s.endswith(":") and "/" not in s):
        return True
    host = s.split("://", 1)[1] if "://" in s else s
    host = host.split("/", 1)[0].rsplit(":", 1)[0] if not host.startswith("[") else host
    return host == "*" or (host.startswith("*.") and "." not in host[2:])


def _script_problems(policy):
    """Problems with one policy's script directive, as a set of keys."""
    script = policy.get("script-src", policy.get("default-src"))
    lowered = [s.lower() for s in script]
    has_nonce_or_hash = any(s.startswith(NONCE_OR_HASH) for s in lowered)
    out = set()
    if "'unsafe-inline'" in lowered and not has_nonce_or_hash:
        out.add("inline")
    # 'strict-dynamic' with a nonce or hash makes CSP3 browsers ignore host and scheme sources.
    if any(_any_host(s) for s in lowered) and not ("'strict-dynamic'" in lowered and has_nonce_or_hash):
        out.add("any-host")
    if "'unsafe-eval'" in lowered:
        out.add("eval")
    return out


@auto("BROWSER-01")
def hsts(ctx):
    if not ctx.https:
        return skipped("BROWSER-01", "Target is plain HTTP; HSTS only applies to HTTPS sites. Scan the https:// URL.")
    return per_page(ctx, _hsts)


def _hsts(resp):
    value = resp.get("strict-transport-security")
    ev = [_hdr(resp, "strict-transport-security")]
    if not value:
        return failed("BROWSER-01", "No Strict-Transport-Security header, so a first visit can be downgraded to HTTP.", ev)
    max_age, subdomains = None, False
    for part in value.split(";"):
        k, _, v = part.strip().partition("=")
        if k.strip().lower() == "max-age":
            try:
                max_age = int(v.strip().strip('"'))
            except ValueError:
                max_age = None
        elif k.strip().lower() == "includesubdomains":
            subdomains = True
    if max_age is None:
        return failed("BROWSER-01", "HSTS header has no valid max-age, so browsers ignore it.", ev)
    if max_age == 0:
        return failed("BROWSER-01", "HSTS max-age is 0, which turns HSTS off in browsers.", ev)
    if max_age < ONE_YEAR:
        return failed("BROWSER-01", f"HSTS max-age is {max_age}s; use at least {ONE_YEAR} (one year).", ev)
    if not subdomains:
        return warned("BROWSER-01", "HSTS has no includeSubDomains, so subdomains (and cookies scoped to the parent "
                      "domain) can still be reached over HTTP.", ev)
    return passed("BROWSER-01", f"HSTS is on with max-age {max_age} and includeSubDomains.", ev)


@auto("BROWSER-02")
def csp(ctx):
    return per_page(ctx, _csp)


def _csp(resp):
    policies = _merged_csp(resp)
    ev = _csp_ev(resp)
    if not policies:
        ro = resp.get("content-security-policy-report-only")
        if ro:
            return failed("BROWSER-02", "CSP is report-only, so it blocks nothing yet.",
                          ev + [f"content-security-policy-report-only: {ro}"])
        return failed("BROWSER-02", "No Content-Security-Policy (header or meta tag); injected scripts would run.", ev)
    scripted = [p for p in policies if "script-src" in p or "default-src" in p]
    if not scripted:
        return failed("BROWSER-02", "CSP does not stop injected scripts: no script-src or default-src directive, so "
                      "scripts are unrestricted.", ev)
    # A script loads only if every policy allows it, so a problem counts only when every policy has it.
    common = set.intersection(*(_script_problems(p) for p in scripted))
    problems = []
    if "inline" in common:
        problems.append("script-src allows 'unsafe-inline' without a nonce or hash")
    if "any-host" in common:
        problems.append("script-src allows scripts from any host (*, a bare scheme such as https: or data:, or a "
                        "wildcard host)")
    if problems:
        return failed("BROWSER-02", "CSP does not stop injected scripts: " + "; ".join(problems) + ".", ev)
    notes = []
    if "eval" in common:
        notes.append("script-src allows 'unsafe-eval'")
    if not any("object-src" in p or "default-src" in p for p in policies):
        notes.append("no object-src (set object-src 'none')")
    if not any("base-uri" in p for p in policies):
        notes.append("no base-uri (set base-uri 'self' or 'none')")
    if notes:
        return warned("BROWSER-02", "CSP blocks inline scripts, with gaps: " + "; ".join(notes) + ".", ev)
    return passed("BROWSER-02", "CSP blocks inline and third-party scripts that are not allowed.", ev)


@auto("BROWSER-03")
def nosniff(ctx):
    return per_page(ctx, _nosniff)


def _nosniff(resp):
    value = (resp.get("x-content-type-options") or "").strip().lower()
    ev = [_hdr(resp, "x-content-type-options")]
    if value == "nosniff":
        return passed("BROWSER-03", "X-Content-Type-Options is nosniff.", ev)
    return failed("BROWSER-03", "X-Content-Type-Options: nosniff is missing, so browsers may guess content types.", ev)


@auto("BROWSER-04")
def framing(ctx):
    return per_page(ctx, _framing)


def _framing(resp):
    # _merged_csp drops frame-ancestors from <meta> policies, as browsers do.
    ev = [_hdr(resp, "content-security-policy"), _hdr(resp, "x-frame-options")]
    ancestors = [p["frame-ancestors"] for p in _merged_csp(resp) if "frame-ancestors" in p]
    if ancestors:
        # Every policy must allow the framing site, so one restrictive frame-ancestors is enough.
        # When frame-ancestors is present, browsers ignore X-Frame-Options.
        strict = [fa for fa in ancestors if not any(_any_host(s) for s in fa)]
        if not strict:
            return failed("BROWSER-04", "frame-ancestors allows any site to frame this page.", ev)
        return passed("BROWSER-04", f"frame-ancestors is {' '.join(strict[0]) or '(empty)'}.", ev)
    xfo = (resp.get("x-frame-options") or "").strip().upper()
    if xfo in ("DENY", "SAMEORIGIN"):
        return passed("BROWSER-04", f"X-Frame-Options is {xfo}.", ev)
    return failed("BROWSER-04", "Any site can load this page in a frame (no frame-ancestors or X-Frame-Options).", ev)


@auto("BROWSER-05")
def referrer(ctx):
    return per_page(ctx, _referrer)


def _referrer(resp):
    value = resp.get("referrer-policy")
    ev = [_hdr(resp, "referrer-policy")]
    if not value:
        return warned("BROWSER-05", "No Referrer-Policy; modern browsers default to strict-origin-when-cross-origin, "
                      "older ones may send full URLs.", ev)
    # The last recognised token wins in browsers; unknown tokens are ignored.
    tokens = [t.strip().lower() for t in value.split(",") if t.strip().lower() in KNOWN_REFERRER]
    if not tokens:
        return warned("BROWSER-05", "Referrer-Policy has no value browsers recognise, so they use their default; set "
                      "strict-origin-when-cross-origin.", ev)
    effective = tokens[-1]
    if effective in SAFE_REFERRER:
        return passed("BROWSER-05", f"Referrer-Policy is {effective}.", ev)
    if effective in ("unsafe-url", "no-referrer-when-downgrade"):
        return failed("BROWSER-05", f"Referrer-Policy {effective} sends full URLs (with tokens in them) to other sites.", ev)
    return warned("BROWSER-05", f"Referrer-Policy {effective} sends the origin to other sites; "
                  "strict-origin-when-cross-origin is the usual choice.", ev)


def parse_set_cookie(value):
    parts = [p.strip() for p in value.split(";")]
    name = parts[0].split("=", 1)[0].strip()
    attrs = {}
    for p in parts[1:]:
        k, _, v = p.partition("=")
        attrs[k.strip().lower()] = v.strip()
    return name, attrs


def _words(name):
    return re.findall(r"[a-z0-9]+", re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name).lower())


def is_csrf_cookie(name):
    return any(w in CSRF_WORDS for w in _words(name))


def _looks_like_session(name):
    # __Host- and __Secure- are hardening prefixes, not a sign of a session; judge the name after them.
    low = name.lower().removeprefix("__host-").removeprefix("__secure-")
    if is_csrf_cookie(name):
        return False
    return low.startswith("sb-") or any(w in SESSION_WORDS or SESSION_RUN_ON.search(w) for w in _words(name))


@auto("BROWSER-06")
def cookies(ctx):
    home = ctx.client.home()
    responses = [home] + [p for p in crawl(ctx).pages if p is not home and p.url != home.url]
    raw, where = [], {}
    for resp in responses:
        for value in resp.get_all("set-cookie"):
            if value not in where:
                raw.append(value)
                where[value] = urlsplit(resp.url).path or "/"
    if not raw:
        return skipped("BROWSER-06", f"None of the {count(len(responses), 'crawled page')} set a cookie. Log in with a test "
                       "account and re-check the session cookie (see the proof steps).")
    fails, warns, ev = [], [], []
    for value in raw:
        name, attrs = parse_set_cookie(value)
        flags = [k for k in ("secure", "httponly") if k in attrs]
        same = attrs.get("samesite", "")
        ev.append(f"{name} (set on {where[value]}): {', '.join(flags) or 'no flags'}"
                  + (f", SameSite={same}" if same else ", no SameSite")
                  + (" (CSRF cookie, readable by JavaScript by design)" if is_csrf_cookie(name) else ""))
        session = _looks_like_session(name)
        if ctx.https and "secure" not in attrs:
            fails.append(f"{name} lacks Secure")
        if same.lower() == "none" and "secure" not in attrs:
            fails.append(f"{name} has SameSite=None without Secure")
        if session and "httponly" not in attrs:
            if name.lower().startswith("sb-"):
                warns.append(f"{name} is readable by JavaScript (Supabase browser client default; an XSS bug can steal it)")
            else:
                fails.append(f"{name} looks like a session cookie but lacks HttpOnly")
        if not same:
            warns.append(f"{name} has no SameSite (browsers default to Lax)")
    fails, warns = list(dict.fromkeys(fails)), list(dict.fromkeys(warns))
    if fails:
        return failed("BROWSER-06", "Cookie flags are missing: " + "; ".join(fails) + ".", ev)
    if warns:
        return warned("BROWSER-06", "Cookies are mostly safe: " + "; ".join(warns) + ".", ev)
    return passed("BROWSER-06", f"{'The' if len(raw) == 1 else 'All'} {count(len(raw), 'cookie')} set on "
                  f"{count(len(responses), 'crawled page')} {'has' if len(raw) == 1 else 'have'} safe flags.", ev)


def cors_origins(target):
    """[(kind, Origin)] to send. Every name is under the reserved .invalid TLD or is only a header value: the Origin
    header is never contacted. The suffix and prefix forms catch allowlists that test "ends with" or "starts with" the
    site's name; the subdomain form shows whether every subdomain is trusted."""
    parts = urlsplit(target)
    host = parts.hostname or ""
    out = [("any site", PROBE_ORIGIN), ("null", "null")]
    if ":" not in host:  # not an IPv6 literal
        out += [("suffix", f"https://{host}.asa-origin-probe.invalid"), ("prefix", f"https://asa-origin-probe-{host}")]
        try:
            ipaddress.ip_address(host)
        except ValueError:
            out.append(("subdomain", f"{parts.scheme}://asa-origin-probe.{parts.netloc}"))
    return out


@auto("BROWSER-07")
def cors(ctx):
    findings, ev = [], []
    for kind, origin in cors_origins(ctx.target):
        resp = ctx.client.get("/", headers={"Origin": origin})
        acao = resp.get("access-control-allow-origin")
        acac = (resp.get("access-control-allow-credentials") or "").strip().lower() == "true"
        ev.append(f"Origin: {origin} ({kind}) -> access-control-allow-origin: {acao or '(not set)'}, "
                  f"allow-credentials: {'true' if acac else 'no'}")
        if acao and acao.strip().lower() == origin.lower():
            findings.append((kind, origin, acac))
    untrusted = [(o, c) for k, o, c in findings if k != "subdomain"]
    subdomain = [o for k, o, c in findings if k == "subdomain" and c]
    if any(c for _, c in untrusted):
        bad = ", ".join(o for o, c in untrusted if c)
        return failed("BROWSER-07", f"The site echoes untrusted origins ({bad}) with credentials allowed, so other sites "
                      "can read logged-in responses.", ev)
    if untrusted:
        return warned("BROWSER-07", "The site echoes untrusted origins without credentials; fine for public data only.",
                      ev)
    if subdomain:
        return warned("BROWSER-07", "The site lets any subdomain read logged-in responses (credentials allowed). That is "
                      "safe only if every subdomain is trusted: one with an XSS bug or a dangling DNS record can read "
                      "your users' data. Allow exact origins instead.", ev)
    return passed("BROWSER-07", "Untrusted origins are not allowed to read responses.", ev)


@auto("BROWSER-08")
def isolation(ctx):
    return per_page(ctx, _isolation)


# COOP is a structured token Item, not a list. Validate the entire value, including parameters, before trusting
# the token (HTML's opener policy algorithm; RFC 9651 section 4.2). Byte sequences, dates and display strings
# are left for manual review. A non-string report-to is ignored by HTML, but does not invalidate the policy.
COOP_TOKEN = r"[A-Za-z*][A-Za-z0-9!#$%&'*+.^_`|~:/-]*"
COOP_STRING = r'"(?:[\x20-\x21\x23-\x5b\x5d-\x7e]|\\["\\])*"'
COOP_PARAM_VALUE = rf"(?:{COOP_STRING}|{COOP_TOKEN}|\?[01]|-?[0-9]{{1,12}}\.[0-9]{{1,3}}|-?[0-9]{{1,15}})"
COOP_ITEM = re.compile(rf"({COOP_TOKEN})(?:; *[a-z*][a-z0-9_.*-]*(?:={COOP_PARAM_VALUE})?)* *")


def _isolation(resp):
    pp = resp.get("permissions-policy")
    # Do not use get/get_all for parsing: their control-character cleanup can turn malformed syntax into a pass.
    values = [v.strip(" \t") for k, v in resp.headers if k.lower() == "cross-origin-opener-policy"]
    value = ", ".join(values)
    item = COOP_ITEM.fullmatch(value) if len(value) <= 8192 else None
    coop = item[1] if item else None
    ev = [_hdr(resp, "permissions-policy")] + ([f"cross-origin-opener-policy: {v}"
          for v in resp.get_all("cross-origin-opener-policy")] or ["cross-origin-opener-policy: (not set)"])
    missing = []
    if not pp:
        missing.append("Permissions-Policy (turn off camera, microphone, geolocation and other features you do not use)")
    if not values:
        missing.append("Cross-Origin-Opener-Policy: same-origin")
    elif coop is None:
        return Result("BROWSER-08", "manual", "Cross-Origin-Opener-Policy could not be validated as a supported "
                      "structured token item; review the complete header syntax and parameters."
                      + (" Missing: " + "; ".join(missing) + "." if missing else ""), ev)
    elif coop not in ("same-origin", "same-origin-allow-popups"):
        return warned("BROWSER-08", f"Cross-Origin-Opener-Policy is {coop}; this check expects same-origin or "
                      "same-origin-allow-popups."
                      + (" Missing: " + "; ".join(missing) + "." if missing else ""), ev)
    if missing:
        return warned("BROWSER-08", "Missing: " + "; ".join(missing) + ".", ev)
    return passed("BROWSER-08", f"Permissions-Policy and Cross-Origin-Opener-Policy are set (COOP: {coop}).", ev)
