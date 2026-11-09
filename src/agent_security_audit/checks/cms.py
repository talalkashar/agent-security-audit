"""Passive CMS hints from the shared crawl. Never request CMS endpoints or assets."""

from __future__ import annotations

import re
from datetime import date
from html.parser import HTMLParser
from urllib.parse import parse_qs, urljoin, urlsplit

from ..crawl import crawl
from ..model import Result, failed, passed, skipped, warned
from ..scope import same_origin
from . import auto, count

MAX_TEXT = 400_000
MAX_TAG = 4096
MAX_TAGS = 4000
SNIPPET = 120
SUPPORT_DATE = "2026-11-07"
# After this many days the support snapshot is too old to call a release line supported (only "ended" still counts).
SUPPORT_MAX_AGE_DAYS = 90
# Verified release listings: the newest patch of each line at SUPPORT_DATE. A higher patch is unknown; a lower one
# is behind the latest security release.
PATCH_LIMITS = {
    "WordPress": {(7, 0): 8, (7, 1): 4, (6, 9): 11},
    "Drupal": {(10, 6): 21, (11, 3): 21, (11, 4): 12},
    "Joomla": {(5, 4): 10, (6, 2): 0},
}
SELF_HOSTED = ("WordPress", "Drupal", "Joomla")
# Disjoint tag interiors prevent repeated scans of an unterminated tag. HTMLParser sees only
# complete, bounded tokens; it never accumulates an attacker-controlled unfinished document.
TOKENS = re.compile(r"<!--.*?(?:-->|$)|<[^<>]*>", re.DOTALL)
VERSION = re.compile(r"(?:0|[1-9][0-9]{0,2})(?:\.(?:0|[1-9][0-9]{0,2})){0,2}")
GENERATOR = re.compile(r"^(WordPress|Drupal|Joomla!?)(?=\s|$)", re.IGNORECASE)
MARKERS = (
    ("WordPress", re.compile(r"/wp-(?:content|includes)/", re.IGNORECASE)),
    ("Drupal", re.compile(r"Drupal\.settings|data-drupal-selector|drupalSettings", re.IGNORECASE)),
    ("Joomla", re.compile(r"/media/jui/|/media/system/js/core(?:\.min)?\.js", re.IGNORECASE)),
    ("Shopify", re.compile(r"cdn\.shopify\.com|Shopify\.theme\b", re.IGNORECASE)),
    ("Wix", re.compile(r"static\.wixstatic\.com|Wix\.com Website Builder", re.IGNORECASE)),
    ("Squarespace", re.compile(r"static1\.squarespace\.com|<!-- This is Squarespace\. -->", re.IGNORECASE)),
)
CORE_ASSETS = {"/wp-includes/js/wp-emoji-release.min.js", "/wp-includes/js/wp-embed.min.js",
               "/wp-includes/css/dist/block-library/style.min.css"}
LOGIN_PATH = re.compile(r"(?:^|/)(?:wp-login\.php|wp-admin|administrator|user/login)/?$", re.IGNORECASE)
# Explicit released minor ranges only. Future/unrecognized minors must not inherit support.
# (major, first minor, last minor, status, explanation); sources are in catalog/cms.toml.
SUPPORT = {
    "WordPress": [(7, 1, 1, "ok", "7.1 is the actively maintained release line")],
    "Drupal": [
        (7, 0, 103, "eol", "Drupal 7 reached end of life on 2025-01-05"),
        (8, 0, 9, "eol", "Drupal 8 reached end of life on 2021-11-17"),
        (9, 0, 5, "eol", "Drupal 9 reached end of life on 2023-11-01"),
        (10, 0, 5, "eol", "Drupal 10.5 and earlier minors no longer receive security fixes"),
        (10, 6, 6, "old", "Drupal 10.6 receives security fixes; Drupal 10 ends on 2026-12-09"),
        (11, 0, 2, "eol", "Drupal 11.2 and earlier minors no longer receive security fixes"),
        (11, 3, 4, "ok", "Drupal 11.3 and 11.4 receive security fixes"),
    ],
    "Joomla": [
        (3, 0, 10, "eol", "Joomla 3 is end of life"),
        (4, 0, 4, "eol", "Joomla 4 support ended in October 2025"),
        (5, 0, 3, "eol", "only the latest minor of a Joomla major series is supported"),
        (5, 4, 4, "old", "Joomla 5.4 receives security fixes until 2027-10-12"),
        (6, 0, 1, "eol", "only the latest minor of a Joomla major series is supported"),
        (6, 2, 2, "ok", "Joomla 6.2 is the current minor release"),
    ],
}


def _path(url):
    try:
        return (urlsplit(url).path or "/")[:SNIPPET]
    except ValueError:
        return "[malformed URL]"


def _snippet(text):
    return " ".join(text[:SNIPPET].split())


def pages(ctx):
    return list(crawl(ctx).pages)  # No fallback home request when the shared crawl is empty.


class _Tag(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.item = None
        self.declaration = False

    def handle_decl(self, decl):
        self.declaration = decl.lower().startswith("doctype ")

    def handle_starttag(self, tag, attrs):
        # Duplicate attributes are ambiguous and must not supply a version.
        names = [key for key, _ in attrs]
        if len(set(names)) == len(names):
            self.item = (tag, {key: value or "" for key, value in attrs})


def _tags(ctx, page):
    key = ("cms-tags", page.url)
    if key in ctx.cache:
        return ctx.cache[key]
    text = page.text[:MAX_TEXT]
    if len(page.text) > MAX_TEXT:
        ctx.cache["cms-limited"] = True
    result, raw, end = [], "", 0
    for number, match in enumerate(TOKENS.finditer(text)):
        if number >= MAX_TAGS:
            ctx.cache["cms-limited"] = True
            break
        malformed_gap = "<" in text[end:match.start()]
        end = match.end()
        token = match.group()
        if malformed_gap:
            ctx.cache["cms-limited"] = True
            continue
        if token.startswith("<!--"):
            continue
        if raw:
            if re.fullmatch(r"</" + raw + r"\s*>", token, re.IGNORECASE):
                raw = ""
            continue
        if len(token) > MAX_TAG:
            ctx.cache["cms-limited"] = True
            continue
        parser = _Tag()
        try:
            parser.feed(token)
        except (ValueError, AssertionError):
            ctx.cache["cms-limited"] = True
            continue
        if parser.item:
            tag, attrs = parser.item
            result.append((tag, attrs))
            if tag in ("script", "style", "textarea", "title", "xmp", "iframe"):
                raw = tag
        elif not token.startswith("</") and not parser.declaration:
            ctx.cache["cms-limited"] = True
    if "<" in text[end:]:
        ctx.cache["cms-limited"] = True
    ctx.cache[key] = result
    return result


def detect(ctx):
    """Collect CMS hints; only unambiguous generator versions establish a release line."""
    if "cms" in ctx.cache:
        return ctx.cache["cms"]
    found = {}

    def record(name, page, evidence, version="", ambiguous=False):
        info = found.setdefault(name, {"version": "", "versions": set(), "ambiguous": False,
                                      "where": f"{_path(page.url)}: {_snippet(evidence)}"})
        if version:
            info["versions"].add(version)
            info["where"] = f"{_path(page.url)}: {_snippet(evidence)}"
        info["ambiguous"] |= ambiguous

    for page in pages(ctx):
        for tag, attrs in _tags(ctx, page):
            if tag == "meta" and attrs.get("name", "").lower() == "generator":
                content = attrs.get("content", "").strip()
                match = GENERATOR.match(content)
                if match:
                    name = match[1].rstrip("!").capitalize()
                    name = "WordPress" if name == "Wordpress" else name
                    tail = content[match.end():].strip()
                    if name == "Drupal":
                        tail = re.sub(r"\s+\(https?://www\.drupal\.org\)\s*$", "", tail)
                    version = tail if VERSION.fullmatch(tail) else ""
                    record(name, page, "generator: " + content, version, bool(tail and not version))
            # Cache-busting parameters may be stale/custom: disclose them as hints only.
            for attr in ("src", "href"):
                value = attrs.get(attr, "")
                try:
                    parsed = urlsplit(value)
                except ValueError:
                    continue
                if any(parsed.path.endswith(path) for path in CORE_ASSETS):
                    versions = parse_qs(parsed.query).get("ver", [])
                    if versions:
                        record("WordPress", page, "core asset version hint: " + _snippet(versions[0]))
                        found["WordPress"]["asset_hint"] = True
        for name, rx in MARKERS:
            match = rx.search(page.text[:MAX_TEXT])
            if match:
                record(name, page, match.group())
    for info in found.values():
        if len(info["versions"]) == 1 and not info["ambiguous"]:
            info["version"] = next(iter(info["versions"]))
    ctx.cache["cms"] = found
    return found


def _no_cms(check_id, n):
    return skipped(check_id, f"No WordPress, Drupal or Joomla markers on {count(n, 'crawled page')}.")


@auto("CMS-01")
def version_disclosure(ctx):
    found = detect(ctx)
    n = len(pages(ctx))
    ev = [f"{name}: {info['where']}" for name, info in found.items()]
    disclosed = [f"{name} {v}" for name, info in found.items() for v in sorted(info["versions"]) if "." in v]
    if disclosed:
        return failed("CMS-01", "Generator tags disclose CMS version strings: " + ", ".join(disclosed[:10]) +
                      ". This establishes disclosure, not an exploitable vulnerability or the running version.", ev)
    if not found or ctx.cache.get("cms-limited") or any(i.get("asset_hint") or i["ambiguous"] for i in found.values()):
        return Result("CMS-01", "manual", "CMS version disclosure could not be fully assessed from the bounded "
                      "page sample. Review generator tags and core asset URLs.", ev)
    return passed("CMS-01", f"No numeric major.minor CMS version in generator tags on {count(n, 'crawled page')}.", ev)


def _judge(name, version):
    if not VERSION.fullmatch(version):
        return "unknown", "unrecognized or prerelease version"
    parts = tuple(int(x) for x in version.split("."))
    if len(parts) == 1:
        return "unknown", "a major version alone does not establish a supported minor release"
    major, minor = parts[:2]
    if len(parts) == 3 and parts[2] > PATCH_LIMITS[name].get((major, minor), 0):
        return "unknown", "patch version outside the verified release snapshot"
    for known_major, first, last, status, note in SUPPORT[name]:
        if major == known_major and first <= minor <= last:
            latest = PATCH_LIMITS[name].get((major, minor))
            patch = parts[2] if len(parts) == 3 else 0  # "7.1" is how a x.y.0 release reports itself
            if status == "ok" and latest is not None and patch < latest:
                return "old", f"supported line, but behind the latest known security release {major}.{minor}.{latest}"
            return status, note
    # WordPress publishes courtesy releases on older branches, without a general EOL declaration.
    if name == "WordPress" and ((major in (3, 4, 5, 6) and minor <= 9) or (major == 7 and minor == 0)):
        return "old", "behind the actively maintained WordPress 7.1 line"
    return "unknown", f"release line outside the verified {SUPPORT_DATE} snapshot"


def _today():
    return date.today()


def support_data_stale():
    """True once the support snapshot is older than SUPPORT_MAX_AGE_DAYS."""
    return (_today() - date.fromisoformat(SUPPORT_DATE)).days > SUPPORT_MAX_AGE_DAYS


@auto("CMS-02")
def outdated_core(ctx):
    found = detect(ctx)
    cms = {k: v for k, v in found.items() if k in SELF_HOSTED}
    if not cms and ctx.cache.get("cms-limited"):
        return Result("CMS-02", "manual", "CMS support could not be assessed because page parsing was limited.")
    if not cms:
        return _no_cms("CMS-02", len(pages(ctx)))
    ev, verdicts = [], []
    for name, info in cms.items():
        ev.append(f"{name}: {info['where']}")
        status, note = (_judge(name, info["version"]) if info["version"] else
                        ("unknown", "version absent, conflicting, or ambiguous"))
        verdicts.append((status, f"{name} {info['version']}: {note}"))
    statuses = {s for s, _ in verdicts}
    msgs = "; ".join(m for _, m in verdicts)
    scope = (f"Vendor release snapshot {SUPPORT_DATE} (release line and latest patch); the running installation "
             "is not verified. ")
    if "eol" in statuses:
        return failed("CMS-02", "A generator reports a vendor-ended release line. " + scope + msgs, ev)
    if support_data_stale():
        return Result("CMS-02", "manual", f"Support data stale: the release-line snapshot ({SUPPORT_DATE}) is older "
                      f"than {SUPPORT_MAX_AGE_DAYS} days, so newer releases may exist. Update asa, or compare the "
                      "version with the vendor's release page. " + msgs + ".", ev)
    if "unknown" in statuses or ctx.cache.get("cms-limited"):
        return Result("CMS-02", "manual", scope + msgs + ". Verify the installed version in the admin dashboard.", ev)
    if "old" in statuses:
        return warned("CMS-02", "A generator reports an older release line. " + scope + msgs, ev)
    return passed("CMS-02", "The reported minor release line was supported at the snapshot date. " + scope + msgs, ev)


@auto("CMS-03")
def wordpress_api(ctx):
    found = detect(ctx)
    if "WordPress" not in found:
        return skipped("CMS-03", f"WordPress not detected on {count(len(pages(ctx)), 'crawled page')}.")
    ev = []
    for page in pages(ctx):
        for tag, attrs in _tags(ctx, page):
            if tag == "link" and attrs.get("rel", "").lower() in ("https://api.w.org/", "pingback", "edituri"):
                ev.append(f"{_path(page.url)}: {attrs['rel'][:SNIPPET]} link")
        if page.get("x-pingback"):
            ev.append(f"{_path(page.url)}: X-Pingback header present")
    return Result("CMS-03", "manual", "WordPress API markers do not establish endpoint accessibility or a "
                  "vulnerability. Review which public author fields and XML-RPC methods are intended, and verify "
                  "authentication and abuse controls on a site you own. No API endpoints were requested.",
                  list(dict.fromkeys(ev))[:10] or [f"WordPress: {found['WordPress']['where']}"])


@auto("CMS-04")
def admin_login_linked(ctx):
    hits = []
    all_pages = pages(ctx)
    for page in all_pages:
        for tag, attrs in _tags(ctx, page):
            value = attrs.get("action" if tag == "form" else "href", "")
            if tag not in ("a", "area", "form") or not value:
                continue
            try:
                target = urljoin(page.url, value)
                if same_origin(target, ctx.target) and LOGIN_PATH.search(urlsplit(target).path):
                    hits.append(f"{_path(page.url)} links to {_path(target)}")
            except ValueError:
                continue
    if hits:
        return Result("CMS-04", "manual", "Public pages link to a possible CMS login. A link does not establish "
                      "weak authentication. Review MFA, rate limiting and access policy.", list(dict.fromkeys(hits))[:10])
    if detect(ctx) and not ctx.cache.get("cms-limited"):
        return passed("CMS-04", f"No same-origin CMS login link in {count(len(all_pages), 'crawled page')}.",
                      ["Login protection itself was not tested."])
    return Result("CMS-04", "manual", "No CMS login link identified in the bounded sample; login protection "
                  "requires review.")
