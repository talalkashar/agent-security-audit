"""Run checks against one target and collect results."""

from __future__ import annotations

import ipaddress
from urllib.parse import urljoin, urlsplit

from . import catalog, code_audit
from .checks import Context, load_all
from .http import NETWORK_ERRORS, Blocked, BudgetExceeded, Client, OffTarget
from .model import Result, errored
from .scope import ScopeError, check_authorized, normalize_target


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
    nxt = urlsplit(urljoin(target + "/", resp.get("location") or ""))
    here = urlsplit(target)
    if (nxt.scheme, nxt.hostname, nxt.port) == (here.scheme, here.hostname, here.port):
        return target
    if nxt.scheme == "https" and _twin(here.hostname or "", nxt.hostname or ""):
        return f"https://{nxt.hostname}" + (f":{nxt.port}" if nxt.port else "")
    raise ScopeError(f"{target} redirects to {nxt.scheme}://{nxt.netloc}. Scan that URL directly "
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


def run(target, *, authorized=False, ids=None, areas=None, stacks=None, options=None, insecure=False,
        budget=300, delay=0.05, timeout=10.0, include_manual=True):
    """Return (normalized_target, [Result]) for the selected checks."""
    target = normalize_target(target)
    check_authorized(target, authorized)
    registry = load_all()
    client = Client(target, timeout=timeout, budget=budget, delay=delay, insecure=insecure)
    if check_ids_need_network(ids, areas, stacks):
        try:
            final = canonical_target(target, client)
        except Blocked as exc:
            raise ScopeError(str(exc)) from exc
        except NETWORK_ERRORS as exc:
            raise ScopeError(f"could not reach {target}: {type(exc).__name__}: {exc}") from exc
        if final != target:
            check_authorized(final, authorized)
            target = final
            client = Client(target, timeout=timeout, budget=budget - client.sent, delay=delay, insecure=insecure)
    ctx = Context(target, client, dict(options or {}), authorized=authorized)
    results = []
    for check in select(ids, areas, stacks):
        fn = registry.get(check.id)
        if check.mode != "auto" or fn is None:
            if include_manual:
                results.append(manual_result(check))
            continue
        try:
            result = fn(ctx)
        except Blocked as exc:
            raise ScopeError(str(exc)) from exc
        except BudgetExceeded as exc:
            result = errored(check.id, str(exc))
        except OffTarget as exc:
            result = errored(check.id, str(exc))
        except NETWORK_ERRORS as exc:
            result = errored(check.id, f"could not reach the target: {type(exc).__name__}: {exc}")
        except Exception as exc:  # noqa: BLE001 - one broken check must not stop the scan; report it instead
            result = errored(check.id, f"check failed to run: {type(exc).__name__}: {exc}")
        if result.status in ("fail", "warn") and not result.fix:
            result.fix = check.build
        results.append(result)
    return target, results
