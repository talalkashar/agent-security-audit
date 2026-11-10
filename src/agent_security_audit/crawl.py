"""A bounded, same-origin crawl that the checks share, so a scan covers the whole site and not only the home page.

- Seeds: the home page, robots.txt (Sitemap, Allow and Disallow lines without wildcards) and sitemap.xml.
  On a site the user has not said they own, Disallow paths are honored instead: never requested.
- Only GET, only the target origin, only HTML pages are parsed. Forms are recorded, never submitted.
- Links that look like logout or other state changes (logout, sign-out, delete, unsubscribe...) are never requested.
- Limits: max_pages (default 25), max_depth (default 3), at most 3 query-string variants per path, and the crawl
  spends at most half of the request budget that is left when it starts, so the checks always keep room.
- The result is cached in ctx.cache["crawl"]; every check reads the same crawl.
"""

from __future__ import annotations

import html
import re
from collections import Counter, deque
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import parse_qsl, quote, urldefrag, urljoin, urlsplit

from .http import (
    NETWORK_ERRORS,
    TIME_BUDGET_MESSAGE,
    BudgetExceeded,
    Excluded,
    ResponseTooSlow,
    TimeBudgetExceeded,
    busy,
)
from .scope import same_origin

DEFAULT_MAX_PAGES = 25
DEFAULT_MAX_DEPTH = 3
MAX_VARIANTS = 3
MAX_SITEMAPS = 3
# Paths that change state when merely visited are never requested.
SKIP_LINK = re.compile(r"(?i)(?:log|sign)[-_ ]?(?:out|off)|(?:^|[/?&=_.-])(?:delete|destroy|remove|unsubscribe|"
                       r"deactivate|revoke|exit)(?=$|[/?&=_.-])")
NOT_PAGE = (".js", ".mjs", ".css", ".map", ".json", ".xml", ".txt", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp",
            ".avif", ".ico", ".bmp", ".pdf", ".zip", ".gz", ".tgz", ".tar", ".rar", ".7z", ".mp4", ".webm", ".mov",
            ".mp3", ".wav", ".ogg", ".woff", ".woff2", ".ttf", ".otf", ".eot", ".csv", ".doc", ".docx", ".xls",
            ".xlsx", ".ppt", ".pptx", ".exe", ".dmg", ".apk")
LOC = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.IGNORECASE)
# Characters a URL may carry as they are; anything else (spaces, non-ASCII) is percent-encoded, as a browser does.
URL_SAFE = "!#$%&'()*+,/:;=?@[]~"


@dataclass
class Form:
    page: str
    action: str
    method: str
    inputs: list = field(default_factory=list)  # [(name, type)]

    @property
    def has_password(self):
        return any(t == "password" for _, t in self.inputs)


@dataclass
class Resource:
    page: str
    tag: str
    kind: str  # script, style, frame, object, media
    url: str
    integrity: str = ""

    @property
    def active(self):
        """Active content can change the page (scripts, styles, frames, plugins); browsers block it when mixed."""
        return self.kind != "media"


@dataclass
class Site:
    pages: list = field(default_factory=list)       # Response objects for crawled HTML pages; pages[0] is home
    inline: list = field(default_factory=list)      # [(page_url, inline script text)]
    resources: list = field(default_factory=list)   # [Resource]
    forms: list = field(default_factory=list)       # [Form]
    links: list = field(default_factory=list)       # same-origin URLs seen (links, redirects, sitemap), in order
    skipped: list = field(default_factory=list)     # URLs not requested because they look state-changing
    notes: list = field(default_factory=list)       # limits reached, errors
    timed_out: bool = False                         # the scan's time budget cut the crawl short
    cut: str = ""  # why the crawl is incomplete (time or request budget, a page too slow to read or unreachable)
    excluded: int = 0  # URLs not requested because --exclude-path matches their path

    def params(self):
        """{(path, name): example_url} for query parameters on same-origin links."""
        out = {}
        for url in self.links:
            parts = urlsplit(url)
            for name, _ in parse_qsl(parts.query, keep_blank_values=True):
                out.setdefault((parts.path or "/", name), url)
        return out

    def summary(self):
        text = (f"crawl: {_count(len(self.pages), 'page')}, {_count(len(self.resources), 'subresource reference')}, "
                f"{_count(len(self.forms), 'form')}")
        return text + ("; " + "; ".join(self.notes) if self.notes else "")


def _join(base, value):
    """urljoin without a fragment and with spaces and non-ASCII percent-encoded (http.client refuses both), or None
    for a URL that does not parse (a bad port or IPv6 literal on a hostile page)."""
    try:
        url = quote(urldefrag(urljoin(base, value))[0], safe=URL_SAFE)
        urlsplit(url).port  # noqa: B018 - raises ValueError for a bad port
        return url
    except ValueError:
        return None


class _PageParser(HTMLParser):
    def __init__(self, url):
        super().__init__(convert_charrefs=True)
        self.page, self.base = url, url
        self.links, self.resources, self.forms, self.inline = [], [], [], []
        self._form, self._script, self._based = None, None, False

    def _abs(self, value):
        value = (value or "").strip()
        if not value:
            return None
        url = _join(self.base, value)
        return url if url and urlsplit(url).scheme in ("http", "https") else None

    def _res(self, tag, kind, value, integrity=""):
        url = self._abs(value)
        if url:
            self.resources.append(Resource(self.page, tag, kind, url, (integrity or "").strip()))

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "base" and a.get("href") and not self._based:
            self.base, self._based = _join(self.page, a["href"].strip()) or self.page, True
        elif tag in ("a", "area"):
            url = self._abs(a.get("href"))
            if url:
                self.links.append(url)
        elif tag == "script":
            if a.get("src"):
                self._res(tag, "script", a["src"], a.get("integrity"))
            else:
                self._script = []
        elif tag == "link":
            rel = set(a.get("rel", "").lower().split())
            href = a.get("href", "")
            if "stylesheet" in rel:
                self._res(tag, "style", href, a.get("integrity"))
            elif (rel & {"modulepreload", "preload"} and (a.get("as") or "script").lower() == "script"
                  and href.split("?")[0].endswith((".js", ".mjs"))):
                self._res(tag, "script", href, a.get("integrity"))
        elif tag in ("iframe", "frame") and a.get("src"):
            self._res(tag, "frame", a["src"])
        elif tag == "object" and a.get("data"):
            self._res(tag, "object", a["data"])
        elif tag == "embed" and a.get("src"):
            self._res(tag, "object", a["src"])
        elif tag in ("img", "audio", "video", "source", "track") and a.get("src"):
            self._res(tag, "media", a["src"])
        elif tag == "form":
            self._form = Form(self.page, self._abs(a.get("action")) or urldefrag(self.page)[0],
                              (a.get("method") or "get").strip().lower())
            self.forms.append(self._form)
        elif tag == "input" and self._form is not None:
            self._form.inputs.append((a.get("name", ""), (a.get("type") or "text").strip().lower()))

    def handle_endtag(self, tag):
        if tag == "script" and self._script is not None:
            text = "".join(self._script)
            if text.strip():
                self.inline.append(text)
            self._script = None
        elif tag == "form":
            self._form = None

    def handle_data(self, data):
        if self._script is not None:
            self._script.append(data)


def is_html(resp):
    """True when the media type is HTML. Parameters are ignored, so charset=html on text/plain is not a page."""
    ctype = (resp.get("content-type") or "").split(";", 1)[0].strip().lower()
    if ctype:
        return "html" in ctype
    return resp.body[:200].lstrip().lower().startswith((b"<!doctype html", b"<html"))


def _not_html(resp):
    return not is_html(resp) and not resp.body[:200].lstrip().lower().startswith((b"<!doctype", b"<html"))


def _int_opt(ctx, name, default, low, high):
    try:
        return max(low, min(high, int(ctx.opt(name, default))))
    except (TypeError, ValueError):
        return default


class _Crawler:
    def __init__(self, ctx):
        self.ctx, self.client, self.site = ctx, ctx.client, Site()
        self.max_pages = _int_opt(ctx, "max_pages", DEFAULT_MAX_PAGES, 1, 500)
        self.max_depth = _int_opt(ctx, "max_depth", DEFAULT_MAX_DEPTH, 0, 20)
        budget = getattr(self.client, "budget", None)
        self.start = getattr(self.client, "sent", 0)
        self.cap = None if budget is None else max(5, (budget - self.start) // 2)
        self.queue, self.seen, self.variants = deque(), set(), Counter()
        # On a site the user has not said they own, robots.txt Disallow paths are honored, not visited.
        self.honor_robots = not getattr(ctx, "owned", False)
        self.disallow = []

    def room(self):
        return self.cap is None or getattr(self.client, "sent", 0) - self.start < self.cap

    def note_link(self, url):
        url = _join(url, "") if url else None
        if url is None or not same_origin(self.ctx.target, url):
            return None
        parts = urlsplit(url)
        if SKIP_LINK.search(parts.path + "?" + parts.query):
            if url not in self.site.skipped:
                self.site.skipped.append(url)
            return None
        if url not in self.site.links:
            self.site.links.append(url)
        return url

    def disallowed(self, url):
        return self.honor_robots and any(urlsplit(url).path.startswith(d) for d in self.disallow)

    def enqueue(self, url, depth):
        url = self.note_link(url)
        if url is None or url in self.seen or depth > self.max_depth:
            return
        parts = urlsplit(url)
        if parts.path.lower().endswith(NOT_PAGE):
            return
        if self.disallowed(url):
            return
        if parts.query:
            if self.variants[parts.path] >= MAX_VARIANTS:
                return
            self.variants[parts.path] += 1
        self.seen.add(url)
        self.queue.append((url, depth))

    def add_page(self, resp, depth):
        parser = _PageParser(resp.url)
        try:
            parser.feed(resp.text)
            parser.close()
        except (AssertionError, ValueError):  # malformed markup; keep what was parsed
            pass
        self.site.pages.append(resp)
        self.site.inline += [(resp.url, t) for t in parser.inline]
        self.site.resources += parser.resources
        self.site.forms += parser.forms
        for link in parser.links:
            self.enqueue(link, depth + 1)

    def fetch(self, url):
        """GET a same-origin URL, or None when the budget, the crawl cap or the network stops it."""
        if not self.room():
            # The URL in hand (and any still queued) goes unvisited, so the crawl is incomplete: no per-page check
            # may pass on it.
            self.site.cut = self.site.cut or ("not run: the crawl stopped at its share of the request budget before "
                                              "every page was visited (raise --budget)")
            self.stop("stopped early to keep request budget for the checks")
            return None
        try:
            resp = self.client.get(url, cache=True)
            if busy(resp):  # still 429 after the client's retry: that page was never seen
                self.site.cut = self.site.cut or (f"{urlsplit(url).path or '/'} kept answering {resp.status} "
                                                  "(the target asked the scan to slow down)")
            return resp
        except Excluded:  # never sent and cost no budget; checks that read this crawl cannot pass (see crawl())
            self.site.excluded += 1
        except TimeBudgetExceeded:
            self.site.timed_out = True
            self.site.cut = self.site.cut or TIME_BUDGET_MESSAGE
            self.stop("time budget used up")
        except BudgetExceeded:
            self.site.cut = self.site.cut or "not run: request budget used up before the crawl finished"
            self.stop("request budget used up")
        except ResponseTooSlow as exc:  # the page answered but could not be read in full: coverage has a hole
            self.site.cut = self.site.cut or f"{urlsplit(url).path or '/'} answered too slowly to read ({exc})"
            self.site.notes.append(f"{urlsplit(url).path or '/'}: {type(exc).__name__}")
        except NETWORK_ERRORS as exc:  # a page the crawl could not read at all is a hole in coverage too
            self.site.cut = self.site.cut or f"{urlsplit(url).path or '/'} could not be read ({type(exc).__name__})"
            self.site.notes.append(f"{urlsplit(url).path or '/'}: {type(exc).__name__}")
        return None

    def stop(self, why):
        if why not in self.site.notes:
            self.site.notes.append(why)
        self.cap, self.start = 0, getattr(self.client, "sent", 0)

    def seeds(self):
        """URLs from robots.txt and the sitemap(s), depth 1."""
        target = self.ctx.target
        sitemaps, paths = [], []
        robots = self.fetch(target + "/robots.txt")
        if robots is not None and robots.status == 200 and _not_html(robots):
            for line in robots.text.splitlines()[:500]:
                key, sep, value = line.partition(":")
                key, value = key.strip().lower(), value.split("#", 1)[0].strip()
                if not sep or not value:
                    continue
                if key == "sitemap" and _join(target + "/", value):
                    sitemaps.append(_join(target + "/", value))
                elif key == "disallow" and value.startswith("/") and self.honor_robots:
                    self.disallow.append(value.split("*", 1)[0].split("$", 1)[0] or "/")
                elif key in ("allow", "disallow") and value.startswith("/") and not any(c in value for c in "*$"):
                    paths.append(target + value)
        sitemaps = [u for u in sitemaps if same_origin(target, u)] or [target + "/sitemap.xml"]
        out, done = [], 0
        while sitemaps and done < MAX_SITEMAPS:
            resp = self.fetch(sitemaps.pop(0))
            done += 1
            if resp is None or resp.status != 200 or not _not_html(resp):
                continue
            locs = [html.unescape(m) for m in LOC.findall(resp.text)]
            if "<sitemapindex" in resp.text[:2000].lower():
                sitemaps += [u for u in locs if same_origin(target, u)][:MAX_SITEMAPS]
            else:
                out += locs[: self.max_pages * 2]
        return paths + out

    def run(self):
        home = self.client.home()
        for url in (self.ctx.target + "/", urldefrag(home.url)[0]):
            self.seen.add(url)
        if home.status == 200 and is_html(home):
            self.add_page(home, 0)
        if self.max_depth >= 1:
            for url in self.seeds():
                self.enqueue(url, 1)
        while self.queue and len(self.site.pages) < self.max_pages:
            url, depth = self.queue.popleft()
            if self.disallowed(url):
                continue
            resp = self.fetch(url)
            if resp is None:
                if self.cap == 0:
                    break
                continue
            if resp.is_redirect and resp.get("location"):
                nxt = _join(resp.url, resp.get("location"))
                if nxt:
                    self.enqueue(nxt, depth)
            elif resp.status == 200 and is_html(resp):
                self.add_page(resp, depth)
        if self.queue and len(self.site.pages) >= self.max_pages:
            self.site.notes.append(f"page limit {self.max_pages} reached, {_count(len(self.queue), 'queued link')} "
                                   "not visited (raise it with --max-pages)")
        if self.site.skipped:
            self.site.notes.append(f"{_count(len(self.site.skipped), 'logout or state-changing link')} not requested")
        if self.site.excluded:
            self.site.notes.append(f"{_count(self.site.excluded, 'link')} not requested (--exclude-path)")
        return self.site


def crawl(ctx):
    """The shared Site for this run. Crawls on first use. A check that reads a crawl the time or request budget cut
    short (or with a page too slow or failing to read) is flagged (ctx.cache["data_cut"]) so the runner never reports
    a pass built on part of the site. One that skipped excluded links flags ctx.cache["excluded"] the same way."""
    if "crawl" not in ctx.cache:
        ctx.cache["crawl"] = _Crawler(ctx).run()
    if ctx.cache["crawl"].cut:
        ctx.cache["data_cut"] = ctx.cache["crawl"].cut
    if getattr(ctx.cache["crawl"], "excluded", 0):
        ctx.cache["excluded"] = f"the crawl left out {_count(ctx.cache['crawl'].excluded, 'link')}"
    return ctx.cache["crawl"]


def _count(n, one):
    return f"{n} {one if n == 1 else one + 's'}"


# Next.js lists route chunks in its build manifest and in the RSC payload of each page. The path after
# static/chunks/ is bounded (real chunk paths are far shorter), so a hostile script full of "static/chunks/" starts
# costs linear time, not quadratic.
NEXT_CHUNK = re.compile(r"(?<![\w/.-])(?:/_next/)?static/chunks/[\w\-.~%@\[\]/]{1,200}?\.js\b")
# Distinct chunk paths kept from one page or script. A real build manifest names a few hundred; a hostile 2 MB body
# can name a hundred thousand. Far above exposure.MAX_SCRIPTS, so reaching it is always reported as a cut there.
MAX_CHUNKS_PER_TEXT = 2000


def next_chunks(text):
    """Same-origin paths of Next.js chunks referenced in a page or script, each once, in order. The whole text is
    searched (the pattern is linear and bodies stop at http.MAX_BODY), so a chunk named late in a large bundle is
    still fetched; at most MAX_CHUNKS_PER_TEXT distinct paths are kept."""
    out = {}
    for m in NEXT_CHUNK.finditer(text):
        path = m.group(0)
        out[path if path.startswith("/_next/") else "/_next/" + path] = None
        if len(out) >= MAX_CHUNKS_PER_TEXT:
            break
    return list(out)
