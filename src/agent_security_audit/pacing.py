"""How fast a scan sends and which paths it leaves alone: --rate, --exclude-path and the Retry-After backoff.

- The rate sets the client's minimum delay between connections, so it paces HTTP requests, TLS handshakes and port
  probes alike.
- Exclusion patterns are matched against the URL path. The CLI takes regular expressions from the operator; the MCP
  server takes only literal paths with "*" wildcards (an agent a scanned page may have steered chooses them there), and
  they are matched without a regex engine, in time linear in the path and pattern.
- The home page can never be excluded: every check starts from it.
"""

from __future__ import annotations

import math
import re
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from urllib.parse import unquote, urlsplit

DEFAULT_RATE = 20.0  # requests per second; the client's long-standing 0.05 s minimum delay
MIN_RATE, MAX_RATE = 0.1, 20.0
MAX_PATTERNS, MAX_PATTERN_LEN = 20, 200
# A path longer than this is treated as excluded while exclusions are set, so an operator's regex never runs on a long,
# site-chosen path (a crawl link can be up to the page size). Regexes get the shorter limit: a pattern as ordinary as
# /.*/.*/.*\.php backtracks in time that grows with a power of the path length (seconds at 1024 characters).
MAX_MATCH_PATH = 2048
MAX_REGEX_PATH = 256
MAX_BACKOFF = 30.0  # the longest wait for one Retry-After
DEFAULT_BACKOFF = 1.0  # a 429 with no usable Retry-After
MAX_DELAY = 10.0  # halving the rate stops at one request every 10 s
EXCLUDED_REASON = "excluded by --exclude-path"
# Characters an MCP glob may hold: letters, digits, path punctuation, percent signs and "*". Regex syntax
# (parentheses, brackets, +, ?, $, backslash) is refused, so a regular expression fails loudly instead of matching nothing.
GLOB_CHARS = re.compile(r"[A-Za-z0-9/._~%!&',;=:@*-]+")


def parse_rate(value):
    """Requests per second from --rate or MCP rate, as a float in [MIN_RATE, MAX_RATE]. Raises ValueError."""
    try:
        rate = float(value)
    except (TypeError, ValueError):
        raise ValueError(f"rate must be a number of requests per second, {MIN_RATE:g} to {MAX_RATE:g}") from None
    if not math.isfinite(rate) or not MIN_RATE <= rate <= MAX_RATE:
        raise ValueError(f"rate must be between {MIN_RATE:g} and {MAX_RATE:g} requests per second")
    return rate


def _glob_match(pattern, text):
    """fnmatch-style match where only "*" is special (it matches any characters, "/" included). Greedy leftmost
    search for each literal piece: no backtracking, at most len(pattern) * len(text) steps."""
    parts = pattern.split("*")
    if len(parts) == 1:
        return text == pattern
    first, last = parts[0], parts[-1]
    if len(text) < len(first) + len(last) or not text.startswith(first) or not text.endswith(last):
        return False
    pos, end = len(first), len(text) - len(last)
    for piece in parts[1:-1]:
        i = text.find(piece, pos, end)
        if i < 0:
            return False
        pos = i + len(piece)
    return True


class Exclusions:
    """The --exclude-path patterns of one run. glob=True takes MCP's safe subset (literal paths and "*")."""

    def __init__(self, patterns=(), *, glob=False):
        patterns = list(patterns or ())
        if len(patterns) > MAX_PATTERNS:
            raise ValueError(f"at most {MAX_PATTERNS} exclude-path patterns, got {len(patterns)}")
        self.glob = glob
        self.max_path = MAX_MATCH_PATH if glob else MAX_REGEX_PATH
        flag = "exclude_path" if glob else "--exclude-path"
        self.texts, self._tests = [], []
        for p in patterns:
            if not isinstance(p, str) or not p:
                raise ValueError("an exclude-path pattern must be a non-empty string")
            if len(p) > MAX_PATTERN_LEN:
                raise ValueError(f"an exclude-path pattern may hold at most {MAX_PATTERN_LEN} characters")
            if glob:
                if not GLOB_CHARS.fullmatch(p) or not p.startswith(("/", "*")):
                    raise ValueError("exclude_path takes paths like /admin/* : a leading / or *, then letters, "
                                     "digits, path punctuation and * (no regular expressions)")
                self._tests.append(lambda path, p=p: _glob_match(p, path))
            else:
                try:
                    rx = re.compile(p)
                except re.error as exc:
                    raise ValueError(f"{flag} {p[:60]!r} is not a valid regular expression: {exc}") from None
                self._tests.append(rx.fullmatch)
            if self._tests[-1]("/") or self._tests[-1](""):
                raise ValueError(f"{flag} {p[:60]!r} matches the home page (/), which every check needs; "
                                 "it cannot be excluded")
            self.texts.append(p)

    def __bool__(self):
        return bool(self.texts)

    def match(self, url):
        """True when the URL's path is excluded. The path is tested as sent and percent-decoded, so /%61dmin cannot
        slip past a pattern for /admin."""
        if not self.texts:
            return False
        path = urlsplit(url).path or "/"
        if len(path) > self.max_path:
            return True
        decoded = unquote(path)
        return any(test(path) or (decoded != path and test(decoded)) for test in self._tests)


def retry_after(value, now=None):
    """Seconds to wait for a Retry-After header value (RFC 9110 10.2.3: delay-seconds or an HTTP date), always in
    [0, MAX_BACKOFF]. Missing, negative or garbled values wait DEFAULT_BACKOFF."""
    value = (value or "").strip()
    if value.isascii() and value.isdigit():
        return MAX_BACKOFF if len(value) > 6 else min(float(value), MAX_BACKOFF)
    if 0 < len(value) <= 64:
        try:
            when = parsedate_to_datetime(value)
        except (TypeError, ValueError, IndexError, OverflowError):
            return DEFAULT_BACKOFF
        if when.tzinfo is None:
            when = when.replace(tzinfo=UTC)
        delta = (when - (now or datetime.now(UTC))).total_seconds()
        return min(max(delta, 0.0), MAX_BACKOFF)
    return DEFAULT_BACKOFF
