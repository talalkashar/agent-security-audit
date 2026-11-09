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
DEFAULT_PORTS = {"http": 80, "https": 443}

# Cloud instance metadata services. A scan (even a passive one) must never be pointed at them: they hand out
# credentials and internal configuration, and a page the scan reads could talk an agent into trying.
METADATA_HOSTS = frozenset({
    "metadata", "metadata.google.internal", "metadata.goog", "instance-data", "instance-data.ec2.internal",
    "metadata.tencentyun.com", "metadata.platformequinix.com",
})
METADATA_ADDRESSES = frozenset(ipaddress.ip_address(a) for a in (
    "169.254.169.254",  # AWS, GCP, Azure, Oracle, DigitalOcean, OpenStack
    "169.254.170.2",    # AWS ECS task metadata
    "fd00:ec2::254",    # AWS IMDS over IPv6
    "100.100.100.200",  # Alibaba Cloud
))
# NAT64 prefixes (RFC 6052 well-known, RFC 8215 local use): the IPv4 address is the low 32 bits.
NAT64 = (ipaddress.ip_network("64:ff9b::/96"), ipaddress.ip_network("64:ff9b:1::/48"))


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
    try:
        port = parts.port
    except ValueError as exc:
        raise ScopeError(f"bad port in {url!r}") from exc
    host = parts.hostname
    netloc = f"[{host}]" if ":" in host else host
    if port and port != DEFAULT_PORTS[parts.scheme]:
        netloc += f":{port}"
    return f"{parts.scheme}://{netloc}"


def _ip(text):
    """An address as getaddrinfo or a URL gives it, zone dropped, with an IPv4 address carried inside an IPv6 one
    (IPv4-mapped, 6to4, Teredo client, NAT64) unwrapped, so 64:ff9b::a9fe:a9fe is judged as 169.254.169.254.
    Raises ValueError for text that is not an address."""
    addr = ipaddress.ip_address(str(text).split("%")[0])
    if addr.version == 6:
        if addr.ipv4_mapped or addr.sixtofour:
            return addr.ipv4_mapped or addr.sixtofour
        if addr.teredo:
            return addr.teredo[1]
        if any(addr in net for net in NAT64):
            return ipaddress.IPv4Address(int(addr) & 0xFFFFFFFF)
    return addr


def _resolve(host: str):
    """Every address host resolves to, or [] when it does not resolve (the scan will fail to connect)."""
    try:
        return [info[4][0] for info in socket.getaddrinfo(host, None)]
    except (OSError, UnicodeError):
        return []


def _resolves_off_machine(host: str, addresses=None) -> str | None:
    """For a *.test or *.localhost name, return the first resolved address that is not loopback or private.
    Those names are trusted by suffix, but /etc/hosts, DNS or a search domain can still point them anywhere.
    A name that does not resolve returns None (the scan will fail to connect). Pass the addresses the scan's client
    pinned (http.Client.addresses) so this check and every connection see the same answer."""
    if not host.lower().endswith(LOCAL_SUFFIXES):
        return None
    for text in _resolve(host) if addresses is None else addresses:
        addr = _ip(text)
        if not (addr.is_loopback or addr.is_private):
            return str(addr)
    return None


def _forbidden_address(addr) -> str | None:
    """Why a scan may not connect to this address, or None. Link-local covers 169.254.0.0/16 and fe80::/10."""
    addr = _ip(addr)
    if addr in METADATA_ADDRESSES:
        return "a cloud metadata service address"
    if addr.is_link_local:
        return "a link-local address"
    return None


def _refuse(host: str, why: str) -> ScopeError:
    return ScopeError(f"refusing to scan {host}: it is {why}. asa scans websites, never cloud metadata or "
                      "link-local services, with or without --authorized.")


def check_target_allowed(target: str, resolve: bool = True, addresses=None) -> None:
    """Raise ScopeError when the target is a cloud metadata service or a link-local address, by name, by literal
    address, or (with resolve) by any address its name resolves to. Loopback and private addresses stay allowed:
    local and LAN dev servers are normal targets. A name that does not resolve passes (the scan will fail to
    connect). Pass the addresses the scan's client pinned (http.Client.addresses): the client connects only to
    those, so a resolver that changes its answer later cannot move the scan."""
    host = urlsplit(target).hostname or ""
    name = host.strip("[]").lower().rstrip(".")
    if name in METADATA_HOSTS:
        raise _refuse(host, "a cloud metadata service name")
    try:
        addr = ipaddress.ip_address(name.split("%")[0])
    except ValueError:
        addr = None
    if addr is not None:
        why = _forbidden_address(addr)
        if why:
            raise _refuse(host, why)
        return
    if not resolve:
        return
    for text in _resolve(name) if addresses is None else addresses:
        try:
            resolved = _ip(text)
        except ValueError:
            continue
        why = _forbidden_address(resolved)
        if why:
            raise _refuse(host, f"a name that resolves to {resolved}, {why}")


def check_private_allowed(target: str, addresses, authorized: bool) -> None:
    """For callers a scanned page could steer (the MCP server): refuse a target on a private network (RFC 1918, ULA,
    CGNAT; anything neither public nor loopback) unless the caller says it is authorized. Local dev names
    (localhost, *.test, *.localhost) stay allowed; check_authorized still holds them to loopback or private."""
    host = urlsplit(target).hostname or ""
    if authorized or is_local_host(host):
        return
    for text in addresses:
        addr = _ip(text)
        if not addr.is_global and not addr.is_loopback:
            raise ScopeError(f"{host} resolves to {addr}, a private network address. Scan it only if you own it or "
                             "have written permission, and say so with authorized=true.")


def check_dns_resolver(url: str) -> str:
    """A DNS-over-HTTPS endpoint the DNS and email checks may send the target's names to: https, a host, no
    credentials, and not a metadata or link-local address. Returns the URL, or raises ScopeError."""
    try:
        parts = urlsplit(url)
        parts.port  # noqa: B018 - raises ValueError on a bad port
    except ValueError as exc:
        raise ScopeError("the DNS resolver must be an https:// URL") from exc
    if parts.scheme != "https" or not parts.hostname:
        raise ScopeError("the DNS resolver must be an https:// URL, e.g. https://cloudflare-dns.com/dns-query")
    if parts.username or parts.password:
        raise ScopeError("credentials in the DNS resolver URL are not allowed")
    check_target_allowed(url)
    return url


def owned(target: str, authorized: bool, addresses=None) -> bool:
    """True when active probes may run: the user said they own the site, or it is a local dev host."""
    try:
        check_authorized(target, authorized, addresses)
    except ScopeError:
        return False
    return True


def check_authorized(target: str, authorized: bool, addresses=None) -> None:
    if authorized:
        return
    host = urlsplit(target).hostname or ""
    if not is_local_host(host):
        raise ScopeError(
            f"{host} is not a local development host. Test it only if you own it or have written "
            "permission, and say so with --authorized (CLI) or authorized=true (MCP)."
        )
    public = _resolves_off_machine(host, addresses)
    if public:
        raise ScopeError(
            f"{host} resolves to {public}, which is not a loopback or private address. Test it only if you own it "
            "or have written permission, and say so with --authorized (CLI) or authorized=true (MCP)."
        )


def origin(url: str):
    """(scheme, host, port) with the scheme's default port filled in, so https://h and https://h:443 are equal.
    None for a URL that does not parse (a bad port or IPv6 literal from a hostile page or Location header)."""
    try:
        parts = urlsplit(url)
        scheme = parts.scheme.lower()
        return scheme, parts.hostname, parts.port or DEFAULT_PORTS.get(scheme)
    except ValueError:
        return None


def same_origin(target: str, url: str) -> bool:
    a = origin(target)
    return a is not None and a == origin(url)
