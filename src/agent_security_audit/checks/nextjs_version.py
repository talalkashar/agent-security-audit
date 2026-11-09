"""NEXT-04 from the running site: the Next.js version string in the client JavaScript, looked up in OSV.

Reads only the scripts exposure.scripts() already fetched; the one extra request goes to api.osv.dev, never to the
target. It never passes: NEXT-04 also covers React and sharp, and a bundle string cannot show those or the server
runtime. Only the code audit (lockfile) can pass NEXT-04.
"""

from __future__ import annotations

import re
import time
from datetime import UTC, datetime
from urllib.parse import urlsplit

from ..code_audit import deps
from ..http import TIME_BUDGET_MESSAGE
from ..model import Result, errored, failed, skipped
from ..report import _plain
from . import auto, count
from .exposure import scripts

# A release or prerelease version, ASCII digits only ("15.5.28", "15.0.0-canary.12").
VERSION = r"([0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}(?:-[0-9A-Za-z.]{1,40})?)"
VERSION_ONLY = re.compile(rf"^{VERSION}\Z")  # \Z: "$" would let a trailing newline through
# Every pattern starts with a literal and has only bounded repeats, so a scan of the text is linear.
# App Router (seen in built 15.5.28, 16.2.12, 16.4.2, 16.4.3 bundles): window.next={version:"16.4.2",appDir:!0}
APP_ROUTER = re.compile(r'window\.next\s{0,4}=\s{0,4}\{\s{0,4}version\s{0,4}:\s{0,4}"' + VERSION + '"')
# Pages Router main chunk: window.next={version:n.version,...}, the module exports version:function(){return H}
# and declares let H="15.5.28". The getter is only trusted in a script that also has the window.next line.
PAGES_WINDOW = re.compile(r"window\.next\s{0,4}=\s{0,4}\{\s{0,4}version\s{0,4}:\s{0,4}[A-Za-z_$]")
GETTER = re.compile(r"\bversion\s{0,2}:\s{0,2}(?:function\s{0,2}\(\)\s{0,2}\{\s{0,2}return\s{1,2}|\(\)\s{0,2}=>\s{0,2})"
                    r"([A-Za-z_$][\w$]{0,5})\b")
MARKERS = ("/_next/static/", "self.__next_f", "__NEXT_DATA__", "window.next=", "window.next =")
MAX_HITS = 20         # matches read per pattern per script
MAX_GETTERS = 3       # getter variables followed per script
OSV_TIMEOUT = 10.0
MAX_ADVISORIES = 200  # advisories read from one OSV answer
SHOWN = 8             # advisory ids named in the summary
ADVISORY_ID = re.compile(r"^[A-Za-z][A-Za-z0-9._:-]{2,63}\Z")
NOT_SEEN = ("React, react-dom, sharp and the server runtime are not visible from the live site: run asa code on "
            "the source")


def _limited(pattern, text):
    for i, m in enumerate(pattern.finditer(text)):
        if i >= MAX_HITS:
            return
        yield m


def bundle_versions(text):
    """The Next.js versions a script names, as a set of version strings."""
    found = {m.group(1) for m in _limited(APP_ROUTER, text)}
    if PAGES_WINDOW.search(text):
        names = list(dict.fromkeys(m.group(1) for m in _limited(GETTER, text)))[:MAX_GETTERS]
        for name in names:
            decl = re.compile(r"(?<![\w$.])" + re.escape(name) + r'\s{0,2}=\s{0,2}"' + VERSION + '"')
            found |= {m.group(1) for m in _limited(decl, text)}
    return found


def _has_marker(label, text):
    return label.startswith("/_next/") or any(m in text for m in MARKERS)


def _key(version):
    """Sort key for a version that matched VERSION_ONLY: a prerelease sorts before its release."""
    main, _, pre = version.partition("-")
    nums = tuple(int(x) for x in main.split("."))
    if not pre:
        return (*nums, 1, ())
    return (*nums, 0, tuple((0, int(p), "") if p.isdigit() else (1, 0, p) for p in pre.split(".")))


def _list(value, limit):
    return [v for v in value[:limit] if isinstance(v, dict)] if isinstance(value, list) else []


def _fixes(vuln, version):
    """The smallest fixed version OSV gives for this advisory that is above version on its major line, or None."""
    major, here, best = version.split(".")[0], _key(version), None
    for affected in _list(vuln.get("affected"), 50):
        pkg = affected.get("package")
        if not isinstance(pkg, dict) or pkg.get("name") != "next" or pkg.get("ecosystem") != "npm":
            continue
        for rng in _list(affected.get("ranges"), 50):
            for event in _list(rng.get("events"), 100):
                fixed = event.get("fixed")
                if (isinstance(fixed, str) and VERSION_ONLY.match(fixed) and fixed.split(".")[0] == major
                        and _key(fixed) > here and (best is None or _key(fixed) < _key(best))):
                    best = fixed
    return best


def _manual(summary, evidence=None):
    return Result("NEXT-04", "manual", summary, list(evidence or []))


@auto("NEXT-04")
def nextjs_version(ctx):
    found = scripts(ctx)
    cut = ctx.cache.get("scripts_cut")
    where = {}
    for label, text in found:
        for v in sorted(bundle_versions(text)):
            where.setdefault(v, label)
    if not where:
        if cut:
            return _manual(f"No Next.js version string in the JavaScript that was read, and not every script was read "
                           f"({cut}). Run asa code on the source to check the Next.js, React and sharp versions.")
        if not any(_has_marker(label, text) for label, text in found):
            return skipped("NEXT-04", "No Next.js markers in the crawled pages' JavaScript. If the site is built "
                                      "with Next.js, run asa code on the source.")
        return _manual("The site uses Next.js, but its JavaScript names no version this check recognizes. Run asa "
                       "code on the source to check the Next.js, React and sharp versions.",
                       [_plain(label, 200) for label, text in found if _has_marker(label, text)][:5])
    if len(where) > 1:
        return _manual(f"{count(len(where), 'different Next.js version')} named in the site's JavaScript, so the one "
                       "running cannot be told apart. Run asa code on the source.",
                       [f"{_plain(label, 200)}: next {v}" for v, label in sorted(where.items())][:10])
    version, label = next(iter(where.items()))
    evidence = [f"{_plain(label, 200)}: version string next {version}"]
    if not ctx.opt("osv"):
        return _manual(f"Next.js {version} found in the site's JavaScript; advisory lookup is off (--no-osv, MCP "
                       f"no_osv). {NOT_SEEN}.", evidence)
    # The lookup goes through urllib, not ctx.client, so it keeps to the scan's deadline itself.
    deadline = getattr(ctx.client, "deadline", None)
    if deadline is not None and time.monotonic() >= deadline:
        return errored("NEXT-04", TIME_BUDGET_MESSAGE)
    lookup = ctx.opt("osv_lookup") or deps.query_osv_vulns
    hosts = getattr(ctx.client, "hosts", None)
    if hosts is not None:  # the report's record of hosts contacted
        hosts.add(urlsplit(deps.OSV_QUERY_URL).hostname)
    day = datetime.now(UTC).date().isoformat()
    try:
        vulns = lookup("npm", "next", version, timeout=OSV_TIMEOUT, deadline=deadline)
    except deps.OsvError as exc:
        return errored("NEXT-04", f"Could not query the OSV vulnerability database for next {version} "
                                  f"({_plain(str(exc), 160)}).")
    if not isinstance(vulns, list):
        return errored("NEXT-04", f"Unexpected answer from OSV for next {version}.")
    vulns = [v for v in vulns[:MAX_ADVISORIES] if isinstance(v, dict)]
    ids = [v["id"] for v in vulns if isinstance(v.get("id"), str) and ADVISORY_ID.match(v["id"])]
    if len(ids) != len(vulns):
        return errored("NEXT-04", f"Unexpected answer from OSV for next {version}: an advisory without a valid id.")
    evidence.append(f"OSV (api.osv.dev) queried {day}")
    if not vulns:
        return _manual(f"OSV lists no advisory for next {version} (version string found in the site's JavaScript, "
                       f"queried {day}). {NOT_SEEN}.", evidence)
    fixes = [_fixes(v, version) for v in vulns]
    named = ", ".join(ids[:SHOWN]) + (f" and {len(ids) - SHOWN} more" if len(ids) > SHOWN else "")
    major = version.split(".")[0]
    known = [f for f in fixes if f]
    if known:
        target = max(known, key=_key)
        upgrade = (f"Upgrade next to {target} or later, the first release on the {major}.x line that fixes "
                   + ("them all" if len(known) == len(fixes) else "the ones OSV gives a fix for") + " per OSV.")
    else:
        upgrade = "Upgrade next to the latest release."
    if len(known) != len(fixes):
        upgrade += (f" OSV gives no fix on the {major}.x line for {len(fixes) - len(known)} of them: move to a newer "
                    "major release.")
    for v, fix in list(zip(vulns, fixes, strict=True))[:10]:
        text = v.get("summary") if isinstance(v.get("summary"), str) else ""
        evidence.append(_plain(f"{v['id']}: {text}".rstrip(": ") + (f" (fixed in {fix})" if fix else ""), 200))
    return failed("NEXT-04", f"The site's JavaScript names next {version}, and OSV lists "
                             f"{count(len(ids), 'advisory', 'advisories')} for it: {named}. {upgrade}", evidence)
