"""Who may be tested.

Local development hosts are always in scope. Any other host is tested only when the caller states it is
authorized (the person owns the site or has written permission). Every request is held to the target's
own scheme, host and port; redirects to other hosts are reported, never followed.
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlsplit

LOCAL_SUFFIXES = (".localhost", ".test")


class ScopeError(ValueError):
    pass


def is_local_host(host: str) -> bool:
    host = host.strip("[]").lower()
    if host == "localhost" or host.endswith(LOCAL_SUFFIXES):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def normalize_target(url: str) -> str:
    """Return scheme://host[:port] for a target URL, or raise ScopeError."""
    if "://" not in url:
        # A bare host:port is usually a dev server, which speaks plain HTTP.
        url = ("http://" if is_local_host(urlsplit("//" + url).hostname or "") else "https://") + url
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise ScopeError(f"only http and https targets are supported, got {parts.scheme!r}")
    if not parts.hostname:
        raise ScopeError(f"no host in {url!r}")
    if parts.username or parts.password:
        raise ScopeError("credentials in the URL are not allowed; pass test accounts separately")
    host = parts.hostname
    netloc = f"[{host}]" if ":" in host else host
    if parts.port:
        netloc += f":{parts.port}"
    return f"{parts.scheme}://{netloc}"


def _resolves_off_machine(host: str) -> str | None:
    """For a *.test or *.localhost name, return the first resolved address that is not loopback or private.
    Those names are trusted by suffix, but /etc/hosts, DNS or a search domain can still point them anywhere.
    A name that does not resolve returns None (the scan will fail to connect). The check runs once, before the
    scan, so a resolver that changes its answer mid-scan is not covered."""
    if not host.lower().endswith(LOCAL_SUFFIXES):
        return None
    try:
        infos = socket.getaddrinfo(host, None)
    except (OSError, UnicodeError):
        return None
    for info in infos:
        addr = ipaddress.ip_address(info[4][0].split("%")[0])
        if not (addr.is_loopback or addr.is_private):
            return str(addr)
    return None


def check_authorized(target: str, authorized: bool) -> None:
    if authorized:
        return
    host = urlsplit(target).hostname or ""
    if not is_local_host(host):
        raise ScopeError(
            f"{host} is not a local development host. Test it only if you own it or have written "
            "permission, and say so with --authorized (CLI) or authorized=true (MCP)."
        )
    public = _resolves_off_machine(host)
    if public:
        raise ScopeError(
            f"{host} resolves to {public}, which is not a loopback or private address. Test it only if you own it "
            "or have written permission, and say so with --authorized (CLI) or authorized=true (MCP)."
        )


def same_origin(target: str, url: str) -> bool:
    a, b = urlsplit(target), urlsplit(url)
    return (a.scheme, a.hostname, a.port) == (b.scheme, b.hostname, b.port)
