"""Whole-site web-app checks that read the shared crawl: mixed content, Subresource Integrity, password forms,
known-vulnerable client libraries, open redirects, directory listings, debug endpoints, API docs, GraphQL
introspection and TRACE. Every probe is a single inert GET, POST of a read-only query, or TRACE; nothing is
submitted, nothing is followed off the target."""

from __future__ import annotations

import json
import re
import secrets
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from ..crawl import crawl
from ..model import failed, passed, skipped, warned
from ..scope import is_local_host, same_origin
from . import auto
from .browser import _merged_csp
from .exposure import scripts


def _path(url):
    parts = urlsplit(url)
    return (parts.path or "/") + (f"?{parts.query}" if parts.query else "")


def _where(ctx, url):
    """A short label for a URL: the path when it is on the target, host and path when it is not."""
    if same_origin(ctx.target, url):
        return _path(url)
    parts = urlsplit(url)
    return f"{parts.netloc}{parts.path}"


def _upgrades(resp):
    return any("upgrade-insecure-requests" in p for p in _merged_csp(resp))


# --- BROWSER-20 mixed content ---------------------------------------------------------------------------------------

@auto("BROWSER-20")
def mixed_content(ctx):
    if not ctx.https:
        return skipped("BROWSER-20", "Target is plain HTTP; mixed content only applies to HTTPS pages. Scan the "
                       "https:// URL.")
    site = crawl(ctx)
    upgraded = {p.url for p in site.pages if _upgrades(p)}
    active, passive, ev = [], [], []
    for r in site.resources:
        if urlsplit(r.url).scheme != "http" or not r.page.startswith("https://"):
            continue
        line = f"{_path(r.page)}: <{r.tag}> loads {_where(ctx, r.url)} over http"
        if r.page in upgraded:
            ev.append(line + " (upgraded by CSP upgrade-insecure-requests)")
            continue
        (active if r.active else passive).append(line)
    ev = active + passive + ev + [site.summary()]
    if active:
        return failed("BROWSER-20", f"{len(active)} script, style, frame or plugin load(s) use http:// on HTTPS "
                      "pages. Browsers block them (breaking the page) or, in old browsers, let a network attacker "
                      "replace them.", ev)
    if passive:
        return warned("BROWSER-20", f"{len(passive)} image or media load(s) use http:// on HTTPS pages; a network "
                      "attacker can see or swap them.", ev)
    return passed("BROWSER-20", f"No http:// subresources on {len(site.pages)} crawled HTTPS page(s).", ev)


# --- BROWSER-21 Subresource Integrity -------------------------------------------------------------------------------

# Vendor loaders that change on every release and are documented as not supporting SRI; CSP is the control for them.
NO_SRI_HOSTS = ("js.stripe.com", "www.googletagmanager.com", "www.google-analytics.com", "connect.facebook.net",
                "challenges.cloudflare.com", "www.google.com", "www.gstatic.com", "fonts.googleapis.com",
                "va.vercel-scripts.com", "static.cloudflareinsights.com", "plausible.io", "js.hs-scripts.com")


@auto("BROWSER-21")
def subresource_integrity(ctx):
    site = crawl(ctx)
    seen, missing, ok, exempt = set(), [], [], []
    for r in site.resources:
        if r.kind not in ("script", "style") or same_origin(ctx.target, r.url) or r.url in seen:
            continue
        seen.add(r.url)
        host = (urlsplit(r.url).hostname or "").lower()
        label = f"{_where(ctx, r.url)} ({r.kind}, first seen on {_path(r.page)})"
        if r.integrity:
            ok.append(label + ": integrity set")
        elif host in NO_SRI_HOSTS:
            exempt.append(label + ": versionless vendor loader, SRI not possible; restrict it with CSP")
        else:
            missing.append(label + ": no integrity attribute")
    if not seen:
        return skipped("BROWSER-21", f"No third-party scripts or stylesheets on {len(site.pages)} crawled page(s).")
    ev = missing + ok + exempt + [site.summary()]
    if missing:
        return warned("BROWSER-21", f"{len(missing)} third-party script(s) or stylesheet(s) load without "
                      "Subresource Integrity, so a compromised CDN could change what runs on the site.", ev)
    return passed("BROWSER-21", f"{len(ok)} third-party script(s) and stylesheet(s) carry an integrity hash"
                  + (f"; {len(exempt)} versionless vendor loader(s) cannot use one" if exempt else "") + ".", ev)


# --- BROWSER-22 password forms --------------------------------------------------------------------------------------

@auto("BROWSER-22")
def password_forms(ctx):
    site = crawl(ctx)
    forms = [f for f in site.forms if f.has_password]
    if not forms:
        return skipped("BROWSER-22", f"No password fields on {len(site.pages)} crawled page(s).")
    problems, ev = [], []
    for f in forms:
        page_http = urlsplit(f.page).scheme == "http" and not is_local_host(urlsplit(f.page).hostname or "")
        action_http = urlsplit(f.action).scheme == "http" and not (
            same_origin(f.page, f.action) and is_local_host(urlsplit(f.action).hostname or ""))
        line = f"{_path(f.page)}: form {f.method.upper()} -> {_where(ctx, f.action)}"
        ev.append(line)
        if page_http:
            problems.append(f"{_path(f.page)} shows a password field on a plain-HTTP page")
        if action_http:
            problems.append(f"{_path(f.page)} sends the password to an http:// URL ({_where(ctx, f.action)})")
        if f.method != "post":
            problems.append(f"{_path(f.page)} submits the password with GET, so it lands in the URL, history and "
                            "server logs")
    ev.append(site.summary())
    if problems:
        return failed("BROWSER-22", "Password forms are not safe in transit: " + "; ".join(problems) + ".", ev)
    return passed("BROWSER-22", f"{len(forms)} password form(s) are served and submitted over HTTPS (or a local "
                  "development host) with POST.", ev)


# --- BROWSER-23 known-vulnerable client libraries -------------------------------------------------------------------

def _v(text):
    return tuple(int(x) for x in text.split("."))


# key -> (name, is_affected(version), why). Keep this list small and exact; each entry cites its advisory.
LIBRARIES = {
    "jquery": ("jQuery", lambda v: v < (3, 5, 0),
               "XSS when passing HTML to DOM methods (CVE-2020-11022, CVE-2020-11023); fixed in 3.5.0"),
    "angularjs": ("AngularJS", lambda v: v[0] == 1,
                  "AngularJS 1.x support ended in January 2022; it gets no more security fixes"),
    "bootstrap": ("Bootstrap", lambda v: v < (3, 4, 1) or (4, 0, 0) <= v < (4, 3, 1),
                  "XSS in tooltip and popover data-template (CVE-2019-8331); fixed in 3.4.1 and 4.3.1"),
    "lodash": ("lodash", lambda v: v < (4, 17, 21),
               "command injection through template (CVE-2021-23337); fixed in 4.17.21"),
    "moment": ("Moment.js", lambda v: v < (2, 29, 4),
               "denial of service through RFC 2822 parsing (CVE-2022-31129); fixed in 2.29.4"),
}
BANNERS = [
    ("jquery", re.compile(r"\bjQuery(?: JavaScript Library)? v(\d+\.\d+\.\d+)\b")),
    ("angularjs", re.compile(r"@license AngularJS v(\d+\.\d+\.\d+)\b")),
    ("bootstrap", re.compile(r"\bBootstrap v(\d+\.\d+\.\d+) \(https?://getbootstrap\.com")),
    ("moment", re.compile(r"moment\.js\s*\n\s*//! version : (\d+\.\d+\.\d+)\b")),
]
LODASH_MARK = re.compile(r"lodash\.com/license|Lodash <https://lodash\.com/>")
LODASH_VERSION = re.compile(r"\bVERSION\s*=\s*['\"](\d+\.\d+\.\d+)['\"]|=\s*\"(4\.\d+\.\d+)\",\w+=200,")
URL_VERSION = re.compile(r"(?i)(?:^|/)(jquery|angularjs|angular(?:\.js)?|bootstrap|lodash(?:\.js)?|moment(?:\.js)?)"
                         r"[-@/]v?(\d+\.\d+\.\d+)(?![\w])")


def _key(name):
    name = name.lower().removesuffix(".js")
    return "angularjs" if name.startswith("angular") else name


def find_libraries(label, text=None, url=None):
    """[(key, version, where)] for listed libraries recognised from a banner comment or a versioned URL."""
    hits = []
    if url:
        m = URL_VERSION.search(urlsplit(url).path)
        if m:
            hits.append((_key(m.group(1)), m.group(2), f"{label} (version in URL)"))
    if text:
        for key, pattern in BANNERS:
            m = pattern.search(text)
            if m:
                hits.append((key, m.group(1), f"{label} (banner)"))
        if LODASH_MARK.search(text):
            m = LODASH_VERSION.search(text)
            if m:
                hits.append(("lodash", m.group(1) or m.group(2), f"{label} (banner)"))
    return hits


@auto("BROWSER-23")
def vulnerable_libraries(ctx):
    site = crawl(ctx)
    found = []
    for url in dict.fromkeys(r.url for r in site.resources if r.kind == "script"):
        found += find_libraries(_where(ctx, url), url=url)
    texts = scripts(ctx)
    for label, text in texts:
        found += find_libraries(label, text=text)
    if not found and not texts and not any(r.kind == "script" for r in site.resources):
        return skipped("BROWSER-23", f"No scripts on {len(site.pages)} crawled page(s).")
    bad, eol, ok, seen = [], [], [], set()
    for key, version, where in found:
        if (key, version) in seen:
            continue
        seen.add((key, version))
        name, affected, why = LIBRARIES[key]
        try:
            hit = affected(_v(version))
        except ValueError:
            continue
        if key == "angularjs" and _v(version)[0] != 1:
            continue
        line = f"{where}: {name} {version}"
        if not hit:
            ok.append(line)
        elif key == "angularjs":
            eol.append(f"{line}: {why}")
        else:
            bad.append(f"{line}: {why}")
    ev = bad + eol + ok + [site.summary()]
    if bad:
        return failed("BROWSER-23", f"{len(bad)} client library version(s) with published vulnerabilities are "
                      "served to visitors. Upgrade them.", ev)
    if eol:
        return warned("BROWSER-23", "An end-of-life client library is served to visitors; it gets no security "
                      "fixes. Plan the migration.", ev)
    return passed("BROWSER-23", f"No listed library at a vulnerable version in {len(texts)} script(s) and the script "
                  f"URLs of {len(site.pages)} crawled page(s).", ev)


# --- API-19 open redirect -------------------------------------------------------------------------------------------

REDIRECT_PARAM = re.compile(r"(?i)^(?:next|url|continue|goto|redir|redirect\w*|return\w*|dest\w*|callback_?url|"
                            r"target_?url)$")
REDIRECT_PROBE = "https://asa-redirect-probe.invalid/"
MAX_REDIRECT_PROBES = 8


@auto("API-19")
def open_redirect(ctx):
    site = crawl(ctx)
    candidates = [(path, name, url) for (path, name), url in site.params().items() if REDIRECT_PARAM.match(name)]
    if not candidates:
        return skipped("API-19", f"No redirect-style query parameters (next, url, return..., redirect..., "
                       f"continue, dest...) in links on {len(site.pages)} crawled page(s). Test login and logout "
                       "redirects by hand (see the proof steps).")
    open_, ev = [], []
    for path, name, url in candidates[:MAX_REDIRECT_PROBES]:
        parts = urlsplit(url)
        query = [(k, REDIRECT_PROBE if k == name else v) for k, v in parse_qsl(parts.query, keep_blank_values=True)]
        probe = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), ""))
        resp = ctx.client.get(probe)
        loc = resp.get("location") or ""
        dest = (urlsplit(urljoin(probe, loc)).hostname or "").lower() if loc else ""
        label = f"GET {path}?{name}=<probe> -> {resp.status}"
        if resp.is_redirect and dest == "asa-redirect-probe.invalid":
            open_.append(f"{path}?{name}=")
            ev.append(f"{label}, Location points to the probe host")
        else:
            ev.append(label + (f", Location stays on {dest or 'the site'}" if loc else ", no redirect"))
    if len(candidates) > MAX_REDIRECT_PROBES:
        ev.append(f"{len(candidates) - MAX_REDIRECT_PROBES} more parameter(s) not probed")
    if open_:
        return failed("API-19", f"Open redirect: {', '.join(open_)} sends visitors to any site named in the "
                      "parameter, which phishing links and OAuth token theft rely on.", ev)
    return passed("API-19", f"{min(len(candidates), MAX_REDIRECT_PROBES)} redirect parameter(s) refused an "
                  "off-site destination.", ev)


# --- API-20 directory listing ---------------------------------------------------------------------------------------

COMMON_DIRS = ("/uploads/", "/static/", "/assets/", "/images/", "/files/", "/backup/", "/public/")
LISTING = re.compile(r"(?i)<title>\s*(?:Index of /|Directory listing for /)|<h1>\s*Index of /")
MAX_DIRS = 10


@auto("API-20")
def directory_listing(ctx):
    site = crawl(ctx)
    dirs = list(COMMON_DIRS)
    for r in site.resources:
        if same_origin(ctx.target, r.url):
            path = urlsplit(r.url).path
            if "/" in path.strip("/"):
                dirs.append(path.rsplit("/", 1)[0] + "/")
    dirs = list(dict.fromkeys(dirs))[:MAX_DIRS]
    listed, ev = [], []
    for d in dirs:
        resp = ctx.client.get(d, cache=True)
        if resp.status == 200 and LISTING.search(resp.text[:5000]):
            listed.append(d)
            ev.append(f"GET {d} -> 200, server-generated file index (file names not shown)")
        else:
            ev.append(f"GET {d} -> {resp.status}")
    if listed:
        return failed("API-20", f"Directory listing is on for {', '.join(listed)}: anyone can browse every file "
                      "stored there, including ones never linked.", ev)
    return passed("API-20", f"None of {len(dirs)} common or discovered directories returns a file index.", ev)


# --- API-21 debug and status endpoints ------------------------------------------------------------------------------

def _actuator_env(resp):
    try:
        data = json.loads(resp.body[:2_000_000])
    except ValueError:
        return False
    return isinstance(data, dict) and "propertySources" in data and "activeProfiles" in data


PHPINFO = re.compile(r"(?i)<title>[^<]*phpinfo\(\)\s*</title>")
DEBUG_ENDPOINTS = {
    "/server-status": ("Apache server-status", lambda r: "Apache Server Status for" in r.text[:20000]),
    "/server-info": ("Apache server-info", lambda r: "Apache Server Information" in r.text[:20000]),
    "/phpinfo.php": ("phpinfo() page", lambda r: PHPINFO.search(r.text[:5000]) is not None),
    "/info.php": ("phpinfo() page", lambda r: PHPINFO.search(r.text[:5000]) is not None),
    "/actuator/env": ("Spring Boot actuator env (configuration and environment)", _actuator_env),
    "/debug/pprof/": ("Go pprof profiler", lambda r: "<title>/debug/pprof/</title>" in r.text[:5000]),
    "/elmah.axd": ("ELMAH error log", lambda r: "Error Log for" in r.text[:20000] and "ELMAH" in r.text),
    "/_profiler/": ("Symfony profiler", lambda r: "Symfony Profiler" in r.text[:20000]),
}


@auto("API-21")
def debug_endpoints(ctx):
    exposed, ev = [], []
    for path, (what, test) in DEBUG_ENDPOINTS.items():
        resp = ctx.client.get(path)
        if resp.status == 200 and resp.body and test(resp):
            exposed.append(f"{path} ({what})")
            ev.append(f"GET {path} -> 200, content matches a real {what} (contents not shown)")
        else:
            ev.append(f"GET {path} -> {resp.status}")
    if exposed:
        return failed("API-21", f"Debug or status pages are public: {', '.join(exposed)}. They reveal internal "
                      "configuration, environment values and request details.", ev)
    return passed("API-21", f"None of {len(DEBUG_ENDPOINTS)} well-known debug and status endpoints is served.", ev)


# --- API-22 API description exposure --------------------------------------------------------------------------------

API_DOCS = ("/openapi.json", "/swagger.json", "/v3/api-docs", "/api-docs", "/swagger/v1/swagger.json",
            "/api/openapi.json", "/swagger-ui.html")


def _api_doc(resp):
    if resp.status != 200 or not resp.body:
        return None
    try:
        data = json.loads(resp.body[:2_000_000])
    except ValueError:
        data = None
    if isinstance(data, dict) and ("openapi" in data or "swagger" in data) and isinstance(data.get("paths"), dict):
        return f"{'OpenAPI ' + str(data.get('openapi')) if 'openapi' in data else 'Swagger 2'} document, " \
               f"{len(data['paths'])} path(s)"
    text = resp.text[:20000]
    if 'id="swagger-ui"' in text and "swagger-ui-bundle" in text:
        return "Swagger UI page"
    return None


@auto("API-22")
def api_docs(ctx):
    found, ev = [], []
    for path in API_DOCS:
        resp = ctx.client.get(path)
        what = _api_doc(resp)
        if what:
            found.append(path)
            ev.append(f"GET {path} -> 200, {what} (contents not shown)")
        else:
            ev.append(f"GET {path} -> {resp.status}")
    if found:
        return warned("API-22", f"API description is public at {', '.join(found)}. That is fine for a public API; "
                      "for an internal one it hands out a map of every endpoint and parameter.", ev)
    return passed("API-22", f"No OpenAPI or Swagger description at {len(API_DOCS)} common paths.", ev)


# --- API-23 GraphQL introspection -----------------------------------------------------------------------------------

GRAPHQL_PATHS = ("/graphql", "/api/graphql")
# The smallest standard introspection query: it reads type names only and runs no resolvers.
INTROSPECTION = json.dumps({"query": "query AsaIntrospectionProbe { __schema { queryType { name } "
                                     "mutationType { name } types { name } } }"})


@auto("API-23")
def graphql_introspection(ctx):
    open_, closed, ev = [], [], []
    for path in GRAPHQL_PATHS:
        resp = ctx.client.request("POST", path, body=INTROSPECTION, headers={"Content-Type": "application/json"})
        try:
            data = json.loads(resp.body[:2_000_000]) if resp.body else None
        except ValueError:
            data = None
        schema = data.get("data", {}).get("__schema") if isinstance(data, dict) and isinstance(
            data.get("data"), dict) else None
        if isinstance(schema, dict) and schema.get("queryType"):
            types = len(schema.get("types") or [])
            mutations = "with mutations" if schema.get("mutationType") else "no mutations"
            open_.append(path)
            ev.append(f"POST {path} -> {resp.status}, introspection answered: {types} type(s), {mutations} "
                      "(names not shown)")
        elif isinstance(data, dict) and isinstance(data.get("errors"), list) and all(
                isinstance(e, dict) and "message" in e for e in data["errors"]) and data["errors"]:
            closed.append(path)
            ev.append(f"POST {path} -> {resp.status}, GraphQL error returned (introspection refused)")
        else:
            ev.append(f"POST {path} -> {resp.status}, not a GraphQL endpoint")
    if open_:
        return warned("API-23", f"GraphQL introspection is on at {', '.join(open_)}: anyone can download the full "
                      "schema, including admin and internal fields. Turn it off in production unless the API is "
                      "public by design, and make sure every resolver checks authorization.", ev)
    if not closed:
        return skipped("API-23", "No GraphQL endpoint at /graphql or /api/graphql.")
    return passed("API-23", f"GraphQL at {', '.join(closed)} refuses introspection.", ev)


# --- API-24 TRACE ---------------------------------------------------------------------------------------------------

@auto("API-24")
def trace_method(ctx):
    marker = secrets.token_hex(8)
    resp = ctx.client.request("TRACE", "/", headers={"X-Asa-Trace-Probe": marker})
    echoed = resp.status == 200 and marker.encode() in resp.body and b"TRACE" in resp.body[:200]
    ev = [f"TRACE / -> {resp.status}" + (" and echoes the request headers back" if echoed else "")]
    if echoed:
        return failed("API-24", "The server answers TRACE by echoing the request, headers included. Turn TRACE off.",
                      ev)
    return passed("API-24", "TRACE is not answered with an echo of the request.", ev)
