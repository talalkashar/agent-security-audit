"""Browser-side defenses proven from response headers and cookies (OSI layer 7)."""

from __future__ import annotations

from urllib.parse import urlsplit

from ..crawl import crawl
from ..model import failed, passed, skipped, warned
from . import auto

ONE_YEAR = 31536000
PROBE_ORIGIN = "https://asa-origin-probe.invalid"
SESSION_HINTS = ("session", "sess", "auth", "token", "jwt", "sid", "login", "remember")
SAFE_REFERRER = {"no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin"}
KNOWN_REFERRER = SAFE_REFERRER | {"no-referrer-when-downgrade", "origin", "origin-when-cross-origin", "unsafe-url"}
NONCE_OR_HASH = ("'nonce-", "'sha256-", "'sha384-", "'sha512-")


def _hdr(resp, name):
    value = resp.get(name)
    return f"{name}: {value}" if value is not None else f"{name}: (not set)"


def parse_csp(value):
    """Return {directive: [sources]} for one CSP header value. The first occurrence of a directive wins."""
    out = {}
    for part in (value or "").split(";"):
        tokens = part.strip().split()
        if tokens and tokens[0].lower() not in out:
            out[tokens[0].lower()] = [t for t in tokens[1:]]
    return out


def _merged_csp(resp):
    """One dict per enforced CSP. Several headers (or one header with comma-separated policies) all apply: a load
    must pass every policy, so the strictest policy decides each question."""
    return [parse_csp(p) for v in resp.get_all("content-security-policy") for p in v.split(",") if p.strip()]


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
    resp = ctx.client.home()
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
        return failed("BROWSER-01", "HSTS has no includeSubDomains, so subdomains (and cookies scoped to the parent "
                      "domain) can still be reached over HTTP.", ev)
    return passed("BROWSER-01", f"HSTS is on with max-age {max_age} and includeSubDomains.", ev)


@auto("BROWSER-02")
def csp(ctx):
    resp = ctx.client.home()
    policies = _merged_csp(resp)
    ev = [_hdr(resp, "content-security-policy")]
    if not policies:
        ro = resp.get("content-security-policy-report-only")
        if ro:
            return warned("BROWSER-02", "CSP is report-only, so it blocks nothing yet.",
                          ev + [f"content-security-policy-report-only: {ro}"])
        return failed("BROWSER-02", "No Content-Security-Policy header; injected scripts would run.", ev)
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
    resp = ctx.client.home()
    value = (resp.get("x-content-type-options") or "").strip().lower()
    ev = [_hdr(resp, "x-content-type-options")]
    if value == "nosniff":
        return passed("BROWSER-03", "X-Content-Type-Options is nosniff.", ev)
    return failed("BROWSER-03", "X-Content-Type-Options: nosniff is missing, so browsers may guess content types.", ev)


@auto("BROWSER-04")
def framing(ctx):
    resp = ctx.client.home()
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
    resp = ctx.client.home()
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


def _looks_like_session(name):
    # __Host- and __Secure- are hardening prefixes, not a sign of a session; judge the name after them.
    low = name.lower().removeprefix("__host-").removeprefix("__secure-")
    return low.startswith("sb-") or any(h in low for h in SESSION_HINTS)


@auto("BROWSER-06")
def cookies(ctx):
    home = ctx.client.home()
    responses = [home] + [p for p in crawl(ctx).pages if p is not home]
    raw, where = [], {}
    for resp in responses:
        for value in resp.get_all("set-cookie"):
            if value not in where:
                raw.append(value)
                where[value] = urlsplit(resp.url).path or "/"
    if not raw:
        return skipped("BROWSER-06", f"None of the {len(responses)} crawled page(s) set a cookie. Log in with a test "
                       "account and re-check the session cookie (see the proof steps).")
    fails, warns, ev = [], [], []
    for value in raw:
        name, attrs = parse_set_cookie(value)
        flags = [k for k in ("secure", "httponly") if k in attrs]
        same = attrs.get("samesite", "")
        ev.append(f"{name} (set on {where[value]}): {', '.join(flags) or 'no flags'}"
                  + (f", SameSite={same}" if same else ", no SameSite"))
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
    return passed("BROWSER-06", f"All {len(raw)} cookie(s) set on {len(responses)} crawled page(s) have safe flags.", ev)


@auto("BROWSER-07")
def cors(ctx):
    findings, ev = [], []
    for origin in (PROBE_ORIGIN, "null"):
        resp = ctx.client.get("/", headers={"Origin": origin})
        acao = resp.get("access-control-allow-origin")
        acac = (resp.get("access-control-allow-credentials") or "").strip().lower() == "true"
        ev.append(f"Origin: {origin} -> access-control-allow-origin: {acao or '(not set)'}, "
                  f"allow-credentials: {'true' if acac else 'no'}")
        if acao and acao.strip() == origin:
            findings.append((acac, origin))
    if any(cred for cred, _ in findings):
        bad = ", ".join(o for c, o in findings if c)
        return failed("BROWSER-07", f"The site echoes untrusted origins ({bad}) with credentials allowed, so other sites "
                      "can read logged-in responses.", ev)
    if findings:
        return warned("BROWSER-07", "The site echoes any Origin without credentials; fine for public data only.", ev)
    return passed("BROWSER-07", "Untrusted origins are not allowed to read responses.", ev)


@auto("BROWSER-08")
def isolation(ctx):
    resp = ctx.client.home()
    pp = resp.get("permissions-policy")
    coop = (resp.get("cross-origin-opener-policy") or "").strip().lower()
    ev = [_hdr(resp, "permissions-policy"), _hdr(resp, "cross-origin-opener-policy")]
    missing = []
    if not pp:
        missing.append("Permissions-Policy (turn off camera, microphone, geolocation and other features you do not use)")
    if coop not in ("same-origin", "same-origin-allow-popups"):
        missing.append("Cross-Origin-Opener-Policy: same-origin")
    if missing:
        return warned("BROWSER-08", "Missing: " + "; ".join(missing) + ".", ev)
    return passed("BROWSER-08", "Permissions-Policy and Cross-Origin-Opener-Policy are set.", ev)
