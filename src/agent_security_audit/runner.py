"""Run checks against one target and collect results."""

from __future__ import annotations

import ipaddress
import time
from datetime import UTC, datetime
from urllib.parse import urljoin, urlsplit

from . import catalog, code_audit
from .checks import Context, load_all
from .code_audit import deps
from .http import NETWORK_ERRORS, Blocked, BudgetExceeded, Client, OffTarget
from .model import Result, errored, skipped
from .report import _plain
from .scope import ScopeError, check_target_allowed, normalize_target, owned, same_origin

DETAIL_MAX = 160  # most characters of an exception's text quoted in an error; the rest may be the target's words


def describe(exc, limit=DETAIL_MAX):
    """An exception for an error message: its class name plus its text with control characters removed and the
    length capped. Network exceptions can carry what the target sent (a raw status line, say), so the text is data
    from the target, not ours."""
    if isinstance(exc, NETWORK_ERRORS) and not isinstance(exc, OSError):  # BadStatusLine and its kin: the text is
        # the server's own bytes, so only the class is named. OS-level errors are worded locally.
        return type(exc).__name__
    detail = _plain(str(exc), limit)
    return f"{type(exc).__name__}: {detail}" if detail else type(exc).__name__


def utc_now():
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


class RecordingClient(Client):
    """A Client that notes every host it connects to, for the report's record of the run."""

    def __init__(self, *args, hosts=None, **kw):
        super().__init__(*args, **kw)
        self.hosts = hosts if hosts is not None else set()

    def _note(self, url):
        host = urlsplit(url).hostname
        if host:
            self.hosts.add(host.lower())

    def _send(self, method, url, headers, body, cache, verify=False):
        self._note(url)
        return super()._send(method, url, headers, body, cache, verify=verify)

    def open_tls(self, context):
        self._note(self.target)
        return super().open_tls(context)

    def probe_port(self, port, timeout=2.0):
        self._note(self.target)
        return super().probe_port(port, timeout=timeout)


def audit_code(path, *, osv=True, timeout=20.0, ids=None, areas=None, hosts=None):
    """code_audit.run, noting api.osv.dev in hosts when the dependency lookup actually goes out."""
    def query(packages, timeout=timeout):
        if hosts is not None:
            hosts.add(urlsplit(deps.OSV_URL).hostname)
        return deps.query_osv(packages, timeout=timeout)
    return code_audit.run(path, osv=osv, osv_query=query, timeout=timeout, ids=ids, areas=areas)


def _is_ip(host):
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def _twin(a, b):
    """True when hosts a and b differ only by a leading 'www.'. IP addresses have no www twin."""
    a, b = a.lower(), b.lower()
    if _is_ip(a) or _is_ip(b) or _is_ip(a.removeprefix("www.")) or _is_ip(b.removeprefix("www.")):
        return False
    return a != b and (a == "www." + b or b == "www." + a)


def canonical_target(target, client):
    """Follow the root redirect when it goes to the same site's www/apex twin over HTTPS. Anything else off-origin
    is refused, because headers on a redirect say nothing about the real pages."""
    resp = client.get("/", cache=True)
    if not resp.is_redirect:
        return target
    try:
        nxt = urlsplit(urljoin(target + "/", resp.get("location") or ""))
        nxt.port  # noqa: B018 - raises ValueError on a bad port
    except ValueError as exc:
        raise ScopeError(f"{target} redirects to an address that does not parse. Scan the site's real URL "
                         "directly.") from exc
    here = urlsplit(target)
    if same_origin(target, nxt.geturl()):  # https://host:443/ is the same origin as https://host
        return target
    if nxt.scheme == "https" and _twin(here.hostname or "", nxt.hostname or ""):
        return normalize_target(f"https://{nxt.netloc}")
    # The Location header is the target's text: quote it cleaned and short, never as-is.
    where = _plain(f"{nxt.scheme}://{nxt.netloc}", 100)
    raise ScopeError(f"{target} redirects to another site ({where!r}). Scan that URL directly "
                     "(with --authorized if you own it).")


def select(ids=None, areas=None, stacks=None, modes=None):
    chosen = []
    wanted = {i.upper() for i in ids} if ids else None
    for check in catalog.load():
        if wanted is not None and check.id not in wanted:
            continue
        if areas and check.area not in areas:
            continue
        if stacks and not ({"any", *stacks} & set(check.stacks)):
            continue
        if modes and check.mode not in modes:
            continue
        chosen.append(check)
    if wanted:
        unknown = wanted - {c.id for c in chosen} - set(catalog.by_id())
        if unknown:
            raise catalog.CatalogError(f"unknown check ids: {', '.join(sorted(unknown))}")
    return chosen


def check_ids_need_network(ids, areas, stacks):
    return any(c.mode == "auto" for c in select(ids, areas, stacks))


def manual_result(check):
    how = ("check the code first, then a logged-in test if the code does not settle it"
           if check.mode == "assisted" else "check the code and config")
    if check.id in code_audit.CHECKS:
        how += " (`asa code <path>` or `asa scan --code <path>` reads the code for it)"
    return Result(check.id, "manual", f"Not visible from outside: {how}. Proof steps: {check.id}.",
                  [check.proof])


ACTIVE_SKIP = "Active probe not run: "


def probe_skipped(check):
    return skipped(check.id, f"{ACTIVE_SKIP}it sends test requests only a site owner should approve. "
                             "Re-run with --authorized if you own this site or have written permission.")


def run(target, *, authorized=False, ids=None, areas=None, stacks=None, options=None, insecure=False,
        budget=300, delay=0.05, timeout=10.0, include_manual=True, progress=None, max_time=None, record=None):
    """Return (normalized_target, [Result]) for the selected checks. progress, when given, is called as
    progress(done, total, check_id, status) after each check. max_time, in seconds, is the scan's time budget:
    once it is used up no new request starts, and checks that still need one report an error. record, when given,
    is a dict filled with the run's started/finished times (UTC), the hosts contacted and the requests sent."""
    started = utc_now()
    hosts = set()
    target = normalize_target(target)
    registry = load_all()
    deadline = time.monotonic() + max_time if max_time else None
    client = RecordingClient(target, timeout=timeout, budget=budget, delay=delay, insecure=insecure,
                             deadline=deadline, hosts=hosts)
    sent = 0
    if check_ids_need_network(ids, areas, stacks):
        check_target_allowed(target)
        try:
            final = canonical_target(target, client)
        except Blocked as exc:
            raise ScopeError(_plain(str(exc), 300)) from exc
        except NETWORK_ERRORS as exc:
            raise ScopeError(f"could not reach {target}: {describe(exc)}") from exc
        if final != target:
            check_target_allowed(final)
            target = final
            sent = client.sent
            client = RecordingClient(target, timeout=timeout, budget=budget - client.sent, delay=delay,
                                     insecure=insecure, deadline=deadline, hosts=hosts)
    may_probe = owned(target, authorized)
    ctx = Context(target, client, dict(options or {}), authorized=authorized, owned=may_probe)
    results = []
    chosen = [c for c in select(ids, areas, stacks)
              if include_manual or (c.mode == "auto" and c.id in registry)]
    for done, check in enumerate(chosen, 1):
        fn = registry.get(check.id)
        if check.mode != "auto" or fn is None:
            results.append(manual_result(check))
            if progress:
                progress(done, len(chosen), check.id, "manual")
            continue
        if check.probe == "active" and not may_probe:
            results.append(probe_skipped(check))
            if progress:
                progress(done, len(chosen), check.id, "skip")
            continue
        ctx.cache.pop("data_cut", None)
        try:
            result = fn(ctx)
        except Blocked as exc:
            raise ScopeError(_plain(str(exc), 300)) from exc
        except BudgetExceeded as exc:
            result = errored(check.id, str(exc))
        except OffTarget as exc:
            result = errored(check.id, _plain(str(exc), 300))
        except NETWORK_ERRORS as exc:
            result = errored(check.id, f"could not reach the target: {describe(exc)}")
        except Exception as exc:  # noqa: BLE001 - one broken check must not stop the scan; report it instead
            result = errored(check.id, f"check failed to run: {describe(exc)}")
        cut = ctx.cache.pop("data_cut", None)
        if cut and result.status in ("pass", "skip"):
            # It read a crawl or script set a budget (or a page too slow to read) cut short: "nothing found" is not
            # proven.
            result = errored(check.id, f"{cut}; it saw only part of the site, so it cannot pass")
        if result.status in ("fail", "warn") and not result.fix:
            result.fix = check.build
        results.append(result)
        if progress:
            progress(done, len(chosen), check.id, result.status)
    if record is not None:
        record.update(started=started, finished=utc_now(), hosts_contacted=sorted(hosts),
                      requests_sent=sent + client.sent)
    return target, results
