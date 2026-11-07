"""A small, bounded HTTP client for proof tests.

- Every request stays on the target origin (see scope.same_origin); anything else raises.
- A per-run request budget and a minimum delay keep scans gentle.
- Redirects are never followed automatically, so checks can see them.
- Response bodies are capped.
- Each response must arrive in full within the timeout (a watchdog cuts a server that trickles bytes), and an
  optional scan-level deadline stops new requests once the time budget is used up.
"""

from __future__ import annotations

import contextlib
import http.client
import re
import socket
import ssl
import threading
import time
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

from . import __version__
from .scope import is_local_host, same_origin

USER_AGENT = f"agent-security-audit/{__version__} (+https://github.com/talalkashar/agent-security-audit)"
MAX_BODY = 2 * 1024 * 1024


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
            return self.body.decode(charset, errors="replace")
        except LookupError:
            return self.body.decode("utf-8", errors="replace")

    @property
    def is_redirect(self):
        return self.status in (301, 302, 303, 307, 308)


class Client:
    def __init__(self, target, *, timeout=10.0, budget=300, delay=0.05, insecure=False, deadline=None):
        if insecure and not is_local_host(urlsplit(target).hostname or ""):
            raise ValueError("insecure TLS is only allowed for local development hosts")
        self.target = target
        self.timeout = timeout
        self.budget = budget
        self.delay = delay
        self.insecure = insecure
        self.deadline = deadline  # time.monotonic() value after which no new request starts; None: no limit
        self.sent = 0
        self._last = 0.0
        self._cache = {}

    def url(self, path):
        return urljoin(self.target + "/", path.lstrip("/")) if not path.startswith(("http://", "https://")) else path

    def _context(self):
        if self.insecure:  # local development hosts only, enforced in __init__
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            return ctx
        return ssl.create_default_context()

    def request(self, method, path="/", *, headers=None, body=None, cache=False):
        """Request a path on the target origin. Anything else raises OffTarget."""
        url = self.url(path)
        if not same_origin(self.target, url):
            raise OffTarget(f"refusing to request {url}: outside the target origin {self.target}")
        return self._send(method, url, headers, body, cache)

    def same_host(self, method, url, *, headers=None, body=None):
        """Request the target's own hostname on another scheme or port (used for the HTTP->HTTPS check)."""
        if (urlsplit(url).hostname or "").lower() != (urlsplit(self.target).hostname or "").lower():
            raise OffTarget(f"refusing to request {url}: different host from {self.target}")
        return self._send(method, url, headers, body, False)

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
            time.sleep(wait)
        self.sent += 1
        self._last = time.monotonic()

    def open_tls(self, context):
        """Open a TLS connection to the target's own host and port (for certificate and TLS-version checks).
        Counts against the budget like a request. Use as a context manager; the caller closes it."""
        parts = urlsplit(self.target)
        if parts.scheme != "https":
            raise OffTarget(f"refusing a TLS connection to {self.target}: target is not https")
        self._spend()
        raw = socket.create_connection((parts.hostname, parts.port or 443), timeout=self.timeout)
        try:
            return context.wrap_socket(raw, server_hostname=parts.hostname)
        except BaseException:
            raw.close()
            raise

    def target_address(self):
        """The first address the target's host resolves to, looked up once per run (for port checks)."""
        if not hasattr(self, "_address"):
            host = urlsplit(self.target).hostname
            self._address = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)[0][4][0]
        return self._address

    def probe_port(self, port, timeout=2.0):
        """Open a TCP connection to the target's own address on `port` and close it at once, sending nothing.
        Counts against the budget like a request. Returns "open", "closed" (refused) or "filtered" (no answer)."""
        address = self.target_address()
        self._spend()
        try:
            sock = socket.create_connection((address, port), timeout=min(timeout, self.timeout))
        except ConnectionRefusedError:
            return "closed"
        except OSError:  # timed out, or a firewall answered host/port unreachable
            return "filtered"
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
                raise TimeoutError(watchdog.message)
            conn.request(method, target_path, body=body, headers=hdrs)
            raw = conn.getresponse()
            data = raw.read(MAX_BODY + 1)
            resp = Response(url, raw.status, raw.reason, list(raw.getheaders()), data[:MAX_BODY], len(data) > MAX_BODY)
        except Exception as exc:
            if watchdog.finish():
                raise TimeoutError(watchdog.message) from exc
            raise
        finally:
            watchdog.finish()
            conn.close()
        if watchdog.expired:
            raise TimeoutError(watchdog.message)
        if not verify:
            why = challenge_of(resp)
            if why:
                raise Blocked(f"{urlsplit(url).netloc} answered {resp.status} with a bot challenge ({why}). Its firewall "
                              "is blocking the scanner, so results would describe the challenge page, not the site. "
                              "Allow this machine's IP in the firewall (or pause challenge mode) and scan again.")
        if cache:
            self._cache[key] = resp
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
