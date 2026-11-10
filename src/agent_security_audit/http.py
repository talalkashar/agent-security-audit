"""A small, bounded HTTP client for proof tests.

- Every request stays on the target origin (see scope.same_origin); anything else raises.
- A per-run request budget and a minimum delay keep scans gentle.
- Redirects are never followed automatically, so checks can see them.
- Response bodies are capped, and the per-run response cache stops growing at MAX_CACHE_BYTES.
- The target's host is resolved once per run and every connection to it goes to those addresses, so a resolver
  that changes its answer mid-scan (DNS rebinding) cannot move the scan to another machine.
- Each response must arrive in full within the timeout (a watchdog cuts a server that trickles bytes), and an
  optional scan-level deadline stops new requests once the time budget is used up.
"""

from __future__ import annotations

import codecs
import contextlib
import errno
import http.client
import re
import socket
import ssl
import threading
import time
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

from . import __version__
from .pacing import EXCLUDED_REASON, MAX_DELAY, Exclusions, retry_after
from .scope import is_local_host, same_origin

USER_AGENT = f"agent-security-audit/{__version__} (+https://github.com/talalkashar/agent-security-audit)"
MAX_BODY = 2 * 1024 * 1024
# The response cache stops adding entries once it holds this many body bytes, so a run's memory stays bounded.
MAX_CACHE_BYTES = 50 * 1024 * 1024
# connect() errors that come from this machine or its network, not from the target: no route (IPv6 without a route),
# host unreachable, no usable source address, or a local firewall that forbids the connection.
UNREACHABLE = {errno.ENETUNREACH, errno.EHOSTUNREACH, errno.EADDRNOTAVAIL, errno.EACCES, errno.EPERM}
# Text codecs no browser offers for a page. A hostile Content-Type could name one: punycode decoding is quadratic
# (2 MB takes about a minute), and the others turn escape sequences in the body into characters.
NOT_WEB_CHARSETS = ("punycode", "idna", "unicode-escape", "raw-unicode-escape", "utf-7")


class BudgetExceeded(RuntimeError):
    pass


class TimeBudgetExceeded(BudgetExceeded):
    """The scan-level time budget (--max-time) ran out before this request."""


TIME_BUDGET_MESSAGE = "not run: time budget for the scan used up (raise --max-time to allow more)"


class Blocked(RuntimeError):
    """The target's firewall answered with a bot challenge, so responses no longer describe the real site."""


CHALLENGE_HEADERS = ("x-vercel-mitigated", "cf-mitigated")


def challenge_of(resp):
    for name in CHALLENGE_HEADERS:
        value = (resp.get(name) or "").strip().lower()
        if value and value != "none":
            return f"{name}: {value}"
    if resp.status in (403, 429, 503) and resp.get("x-vercel-challenge-token"):
        return "x-vercel-challenge-token present"
    return None


class OffTarget(RuntimeError):
    pass


MAX_EXCLUDED_PATHS = 10000  # distinct excluded paths remembered for the report


class Excluded(RuntimeError):
    """The path is excluded by --exclude-path: the request was not sent and cost no budget."""

    def __init__(self, path):
        super().__init__(f"{path} not requested: {EXCLUDED_REASON}")
        self.path = path


def _pause(seconds):
    """time.sleep, named so tests can count waits instead of waiting."""
    time.sleep(seconds)


def busy(resp):
    """The target asked the client to slow down: 429, or 503 with Retry-After (RFC 9110 15.6.4)."""
    return resp.status == 429 or (resp.status == 503 and resp.get("retry-after") is not None)


class ResponseTooSlow(OSError):
    """The watchdog cut an exchange that ran past the timeout. Bytes may already have arrived, so this never means
    "no answer" or "closed". It is deliberately not a TimeoutError, which checks may read as a silent drop."""


CONTROL = re.compile(r"[\x00-\x1f\x7f]+")


def clean_header(value):
    """Collapse control characters (including obs-fold line breaks) to one space, as RFC 9112 5.2 allows."""
    return CONTROL.sub(" ", value).strip()


@dataclass
class Response:
    url: str
    status: int
    reason: str
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: bytes = b""
    truncated: bool = False

    def get(self, name, default=None):
        name = name.lower()
        for k, v in self.headers:
            if k.lower() == name:
                return clean_header(v)
        return default

    def get_all(self, name):
        name = name.lower()
        return [clean_header(v) for k, v in self.headers if k.lower() == name]

    @property
    def text(self):
        ctype = self.get("content-type", "") or ""
        charset = "utf-8"
        for part in ctype.split(";")[1:]:
            k, _, v = part.strip().partition("=")
            if k.lower() == "charset" and v:
                charset = v.strip('"')
        try:
            if codecs.lookup(charset).name in NOT_WEB_CHARSETS:
                charset = "utf-8"
            return self.body.decode(charset, errors="replace")
        except (LookupError, UnicodeError):  # unknown charset, or one such as idna that cannot decode a body
            return self.body.decode("utf-8", errors="replace")

    @property
    def is_redirect(self):
        return self.status in (301, 302, 303, 307, 308)


class Client:
    def __init__(self, target, *, timeout=10.0, budget=300, delay=0.05, insecure=False, deadline=None, exclude=None):
        if insecure and not is_local_host(urlsplit(target).hostname or ""):
            raise ValueError("insecure TLS is only allowed for local development hosts")
        self.target = target
        self.timeout = timeout
        self.budget = budget
        self.delay = delay
        self.insecure = insecure
        self.deadline = deadline  # time.monotonic() value after which no new request starts; None: no limit
        self.sent = 0
        self.exclude = exclude or Exclusions()
        self.excluded = 0  # attempts to request an excluded path (none was sent)
        self.excluded_paths = set()  # the distinct excluded paths asked for, for the report (capped)
        self.slowed = 0  # times the target answered 429 (or 503 with Retry-After)
        self.throttled = 0  # answers still 429 (or 503 with Retry-After) after the one retry: nothing was seen
        self.halved = False
        self._last = 0.0
        self._cache = {}
        self._cache_bytes = 0

    def url(self, path):
        return urljoin(self.target + "/", path.lstrip("/")) if not path.startswith(("http://", "https://")) else path

    def _context(self):
        if self.insecure:  # local development hosts only, enforced in __init__
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            return ctx
        return ssl.create_default_context()

    def request(self, method, path="/", *, headers=None, body=None, cache=False, backoff=True):
        """Request a path on the target origin. Anything else raises OffTarget; an excluded path raises Excluded.
        backoff=False keeps a 429 as the answer (the rate-limit probe wants to see it)."""
        url = self.url(path)
        if not same_origin(self.target, url):
            raise OffTarget(f"refusing to request {url}: outside the target origin {self.target}")
        return self._polite(method, url, headers, body, cache, backoff)

    def same_host(self, method, url, *, headers=None, body=None):
        """Request the target's own hostname on another scheme or port (used for the HTTP->HTTPS check)."""
        if (urlsplit(url).hostname or "").lower() != (urlsplit(self.target).hostname or "").lower():
            raise OffTarget(f"refusing to request {url}: different host from {self.target}")
        return self._polite(method, url, headers, body, False, True)

    def _polite(self, method, url, headers, body, cache, backoff):
        """_send for the target, minus excluded paths, with one retry after a 429 or Retry-After."""
        if self.exclude.match(url):
            self.excluded += 1
            if len(self.excluded_paths) < MAX_EXCLUDED_PATHS:
                self.excluded_paths.add(urlsplit(url).path or "/")
            raise Excluded(urlsplit(url).path or "/")
        resp = self._send(method, url, headers, body, cache)
        if not backoff or not busy(resp):
            return resp
        wait = retry_after(resp.get("retry-after"))
        self.slowed += 1
        if not self.halved:  # once per run: a firewall that throttles every probe path must not compound it
            self.halved = True
            self.delay = max(self.delay, min(self.delay * 2, MAX_DELAY))
        if self.deadline is not None and time.monotonic() + wait >= self.deadline:
            raise TimeBudgetExceeded(TIME_BUDGET_MESSAGE)
        _pause(wait)
        resp = self._send(method, url, headers, body, cache)
        if busy(resp):  # still refused: this answer says nothing about the path (the runner keeps it from a pass)
            self.throttled += 1
        return resp

    def external(self, method, url, *, headers=None, body=None):
        """Request another https host. Only opt-in checks (DNS resolver, the site's own Supabase project) use this."""
        if urlsplit(url).scheme != "https":
            raise OffTarget(f"refusing to request {url}: external requests must use https")
        return self._send(method, url, headers, body, False, verify=True)

    def _spend(self):
        """Count one connection against the budget and keep the minimum delay between them."""
        if self.deadline is not None and time.monotonic() >= self.deadline:
            raise TimeBudgetExceeded(TIME_BUDGET_MESSAGE)
        if self.sent >= self.budget:
            raise BudgetExceeded(f"request budget of {self.budget} used up")
        wait = self.delay - (time.monotonic() - self._last)
        if wait > 0:
            _pause(wait)
        self.sent += 1
        self._last = time.monotonic()

    def open_tls(self, context):
        """Open a TLS connection to the target's own host and port (for certificate and TLS-version checks).
        Counts against the budget like a request. Use as a context manager; the caller closes it."""
        parts = urlsplit(self.target)
        if parts.scheme != "https":
            raise OffTarget(f"refusing a TLS connection to {self.target}: target is not https")
        self._spend()
        raw = self._connect((parts.hostname, parts.port or 443), self.timeout)
        try:
            return context.wrap_socket(raw, server_hostname=parts.hostname)
        except BaseException:
            raw.close()
            raise

    def _addresses(self):
        """Every address the target's host resolves to, in resolver order, looked up once per run.
        An empty answer is cached and raised as OSError, so a later call cannot connect to a new address."""
        if not hasattr(self, "_all_addresses"):
            host = urlsplit(self.target).hostname
            self._all_addresses = list(dict.fromkeys(a[4][0] for a in socket.getaddrinfo(host, None,
                                                                                         type=socket.SOCK_STREAM)))
        if not self._all_addresses:
            host = urlsplit(self.target).hostname
            raise OSError(f"{host} did not resolve to an address")
        return self._all_addresses

    def addresses(self):
        """Every address the target's host resolves to (looked up once per run). Every connection to the target goes
        to these, so the runner's scope check and the requests see the same answer. Raises OSError when the host
        does not resolve."""
        return self._addresses()

    def _connect(self, address, timeout, source_address=None):
        """socket.create_connection for the target's host, tried against its pinned addresses in turn (as
        create_connection tries each DNS answer) instead of resolving the name again."""
        error = None
        for ip in self._addresses():
            try:
                return socket.create_connection((ip, address[1]), timeout, source_address)
            except OSError as exc:
                error = exc
        # An empty address list leaves error as None; raise None is a TypeError, not a connection failure.
        raise error or OSError("the host did not resolve to an address")

    def target_address(self):
        """The address port checks use: the first one, until a probe finds it unreachable from this machine (an IPv6
        address without an IPv6 route) and moves on to the next, as an HTTPS connection would."""
        if not hasattr(self, "_address"):
            self._address = self._addresses()[0]
        return self._address

    def probe_port(self, port, timeout=2.0):
        """Open a TCP connection to the target's own address on `port` and close it at once, sending nothing.
        Counts against the budget like a request. Returns "open", "closed" (refused), "filtered" (no answer) or
        "unreachable" (this machine has no route to the address, or a local firewall refused the connection: that
        says nothing about the target)."""
        self.target_address()
        self._spend()
        while True:
            try:
                sock = socket.create_connection((self._address, port), timeout=min(timeout, self.timeout))
            except ConnectionRefusedError:
                return "closed"
            except OSError as exc:
                if exc.errno not in UNREACHABLE:  # timed out, or no answer at all
                    return "filtered"
                rest = self._addresses()[self._addresses().index(self._address) + 1:]
                if not rest:
                    return "unreachable"
                self._address = rest[0]  # the address this machine cannot reach; try the next one
                continue
            sock.close()
            return "open"

    def _send(self, method, url, headers, body, cache, verify=False):
        key = (method, url, tuple(sorted((headers or {}).items())), body)
        if cache and key in self._cache:
            return self._cache[key]
        self._spend()
        parts = urlsplit(url)
        port = parts.port or (443 if parts.scheme == "https" else 80)
        if parts.scheme == "https":
            context = ssl.create_default_context() if verify else self._context()
            conn = http.client.HTTPSConnection(parts.hostname, port, timeout=self.timeout, context=context)
        else:
            conn = http.client.HTTPConnection(parts.hostname, port, timeout=self.timeout)
        if (parts.hostname or "").lower() == (urlsplit(self.target).hostname or "").lower():
            conn._create_connection = self._connect  # pinned addresses; the Host header and TLS name stay the name
        target_path = parts.path or "/"
        if parts.query:
            target_path += "?" + parts.query
        hdrs = {"User-Agent": USER_AGENT, "Accept": "*/*"}
        hdrs.update(headers or {})
        if isinstance(body, str):
            body = body.encode()
        # The socket timeout only bounds each read, so a server that sends one byte at a time could hold the
        # request open for minutes. The watchdog shuts the socket once the whole exchange passes the timeout.
        watchdog = _Watchdog(conn, self.timeout)
        try:
            conn.connect()
            if watchdog.expired:  # it fired while the socket was still being opened, so it had nothing to cut
                raise ResponseTooSlow(watchdog.message)
            conn.request(method, target_path, body=body, headers=hdrs)
            raw = conn.getresponse()
            data = raw.read(MAX_BODY + 1)
            # Proof the body is whole even if the watchdog fires right after the read: Content-Length fully met
            # (length counts down to 0), chunked framing (a cut makes read raise), or the size cap reached.
            whole = raw.chunked or raw.length == 0 or len(data) > MAX_BODY
            resp = Response(url, raw.status, raw.reason, list(raw.getheaders()), data[:MAX_BODY], len(data) > MAX_BODY)
        except Exception as exc:
            if watchdog.finish():
                raise ResponseTooSlow(watchdog.message) from exc
            raise
        finally:
            watchdog.finish()
            conn.close()
        if watchdog.expired and not whole:  # a body read until close may have been cut short
            raise ResponseTooSlow(watchdog.message)
        if not verify:
            why = challenge_of(resp)
            if why:  # name the header only: its value is chosen by the server
                why = why.partition(":")[0]
                raise Blocked(f"{urlsplit(url).netloc} answered {resp.status} with a bot challenge ({why}). Its firewall "
                              "is blocking the scanner, so results would describe the challenge page, not the site. "
                              "Allow this machine's IP in the firewall (or pause challenge mode) and scan again.")
        if cache and not busy(resp) and self._cache_bytes + len(resp.body) <= MAX_CACHE_BYTES:
            self._cache[key] = resp
            self._cache_bytes += len(resp.body)
        return resp

    def get(self, path="/", **kw):
        return self.request("GET", path, **kw)

    def home(self):
        """The target's root page, fetched once per run and following same-origin redirects (max 5)."""
        resp = self.get("/", cache=True)
        hops = 0
        while resp.is_redirect and hops < 5:
            loc = resp.get("location")
            if not loc:
                break
            nxt = urljoin(resp.url, loc)
            if not same_origin(self.target, nxt):
                break
            resp = self.get(nxt, cache=True)
            hops += 1
        return resp


class _Watchdog:
    """Shut a connection's socket when one request-response exchange runs past `seconds` of wall-clock time."""

    def __init__(self, conn, seconds):
        self.conn = conn
        self.message = f"no complete response within {seconds:g} s"
        self.expired = False
        self._done = False
        self._lock = threading.Lock()
        self._timer = threading.Timer(seconds, self._cut)
        self._timer.daemon = True
        self._timer.start()

    def _cut(self):
        with self._lock:
            if self._done:
                return
            self.expired = True
        sock = self.conn.sock
        if sock is not None:
            with contextlib.suppress(OSError):
                # The plain socket method, so a TLS socket is cut at the TCP level without touching its TLS state.
                socket.socket.shutdown(sock, socket.SHUT_RDWR)

    def finish(self):
        """Stop the timer. Returns True when it had already cut the connection."""
        with self._lock:
            self._done = True
        self._timer.cancel()
        return self.expired


NETWORK_ERRORS = (OSError, socket.timeout, ssl.SSLError, http.client.HTTPException)
