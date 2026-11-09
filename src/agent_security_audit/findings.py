"""Stable finding ids: the key `asa diff` matches findings on between two runs.

An id is "asa1-" plus 16 hex characters of a sha256. It is a public contract: stored reports and baselines match on
it, so the inputs below never change under the "asa1-" prefix (tests/test_findings.py pins ids for fixed inputs).

- A result: the check id and the target's origin (lowercase scheme://host[:port], default port dropped). One live
  check with several affected paths on the site is one finding. A code target (a project folder) adds no origin,
  because the folder's path differs from machine to machine.
- A code location: the check id, the file path (posix, relative to the project root), a hash of the matched token,
  and the occurrence index of that (check, path, token) in file order. The token is the snippet the analyzer matched
  (a masked secret or the redacted source line) when there is one, else the location's message. Digits and quoted
  literals in it are normalized, so a version bump or a changed string keeps the id. Line numbers are left out, so a
  finding that moves keeps its id; two identical findings in one file are told apart only by their order.
"""

from __future__ import annotations

import hashlib
import posixpath
import re
from collections import Counter
from urllib.parse import urlsplit

PREFIX = "asa1-"
ID_RE = re.compile(r"^asa1-[0-9a-f]{16}$")
DEFAULT_PORTS = {"http": 80, "https": 443}
MAX_TOKEN = 1000
MAX_EVIDENCE_SCAN = 60  # evidence lines searched for snippets; a report lists at most 25 code findings plus merge notes
# No nested quantifiers and no line breaks inside a literal, so the match is linear on any input.
QUOTED = re.compile(r""""[^"\n]*"|'[^'\n]*'|`[^`\n]*`""")
DIGITS = re.compile(r"[0-9]+")


def _hash(*parts):
    return hashlib.sha256("\x1f".join(parts).encode("utf-8", "replace")).hexdigest()[:16]


def origin(target):
    """lowercase scheme://host[:port] with the default port dropped, or "" when target is not an http(s) URL."""
    try:
        parts = urlsplit(str(target).strip())
        port = parts.port
    except ValueError:
        return ""
    scheme, host = parts.scheme.lower(), (parts.hostname or "").lower()
    if scheme not in DEFAULT_PORTS or not host:
        return ""
    netloc = f"[{host}]" if ":" in host else host
    if port and port != DEFAULT_PORTS[scheme]:
        netloc += f":{port}"
    return f"{scheme}://{netloc}"


def normalize_path(path):
    """A project-relative path in posix form: backslashes turned to slashes, ./ and duplicate slashes removed."""
    p = str(path or "").replace("\\", "/")
    p = posixpath.normpath(p) if p else ""
    return "" if p == "." else p.lstrip("/")


def normalize_token(text):
    """The matched token with whitespace collapsed, quoted literals emptied and every digit run turned into 0."""
    # Cut before splitting: a report file can hold a token of many megabytes.
    text = " ".join(str(text or "")[:MAX_TOKEN * 4].split())[:MAX_TOKEN]
    text = QUOTED.sub(lambda m: m.group(0)[0] * 2, text)
    return DIGITS.sub("0", text)


def finding_id(check_id, target="", *, path=None, token="", occurrence=0):
    """The id of a result (check_id and target) or, with path, of one code location."""
    cid = str(check_id).upper()
    if path is None:
        return PREFIX + _hash("result", cid, origin(target))
    return PREFIX + _hash("code", cid, normalize_path(path), _hash(normalize_token(token)), str(int(occurrence)))


def _line(loc):
    try:
        return max(0, min(int(loc.get("line") or 0), 10**9))
    except (TypeError, ValueError, OverflowError):
        return 0


def location_ids(check_id, locations, tokens):
    """Ids for a result's locations, in their order. tokens[i] is the token matched at locations[i]. The occurrence
    index counts identical (path, token) pairs in line order, so it does not depend on the order the analyzer used."""
    keys = [(normalize_path(loc.get("path")), normalize_token(tok)) for loc, tok in zip(locations, tokens)]
    occurrence, seen = [0] * len(keys), Counter()
    for i in sorted(range(len(keys)), key=lambda i: (_line(locations[i]), i)):
        occurrence[i] = seen[keys[i]]
        seen[keys[i]] += 1
    return [finding_id(check_id, path=path, token=tok, occurrence=n) for (path, tok), n in zip(keys, occurrence)]


def _tokens_from_evidence(locations, evidence):
    """The token for each location of a report written without finding ids. A code finding's evidence line is
    "path:line: message: snippet" (with a "code: " or "live: " prefix after a merge), so the snippet is recovered from
    it; a location with no matching line falls back to its message (None in the second list: that id cannot match
    one computed from the snippet)."""
    lines = []
    for e in (evidence if isinstance(evidence, list) else [])[:MAX_EVIDENCE_SCAN]:
        if isinstance(e, str):
            for prefix in ("code: ", "live: "):
                e = e.removeprefix(prefix)
            lines.append(e)
    out, matched = [], []
    for loc in locations:
        msg = str(loc.get("message") or "")[:MAX_TOKEN * 4]
        head = f"{str(loc.get('path'))[:MAX_TOKEN * 4]}:{loc.get('line')}: {msg}"
        token, found = msg, False
        for e in lines:
            if e.startswith(head + ": "):
                token, found = e[len(head) + 2:len(head) + 2 + MAX_TOKEN * 4], True
                break
        out.append(token)
        matched.append(found)
    return out, matched


def annotate(result, target):
    """(row, derived): a copy of a report result (Result.to_dict() or a row read from a report file) with finding_id
    on it and on each location. Well-formed ids already present are kept; derived is True when any id had to be
    computed for a location, and "message" when one of those could only be keyed on the location's message."""
    row = dict(result)
    cid = str(row.get("check_id", ""))
    if not ID_RE.match(str(row.get("finding_id", ""))):
        row["finding_id"] = finding_id(cid, target)
    locations = [dict(loc) for loc in row.get("locations") or [] if isinstance(loc, dict)]
    missing = [i for i, loc in enumerate(locations) if not ID_RE.match(str(loc.get("finding_id", "")))]
    derived = bool(missing)
    if missing:
        tokens, matched = _tokens_from_evidence(locations, row.get("evidence"))
        ids = location_ids(cid, locations, tokens)
        for i in missing:
            locations[i]["finding_id"] = ids[i]
        if not all(matched[i] for i in missing):
            derived = "message"
    if "locations" in row:
        row["locations"] = locations
    return row, derived
