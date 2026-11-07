"""Transport checks: HTTPS redirect, certificate, legacy TLS (OSI layers 4-6)."""

from __future__ import annotations

import ssl
from datetime import UTC, datetime
from urllib.parse import urljoin, urlsplit

from ..model import errored, failed, passed, skipped, warned
from ..scope import is_local_host
from . import auto

EXPIRY_WARN_DAYS = 21


def _host_port(ctx):
    parts = urlsplit(ctx.target)
    return parts.hostname, parts.port or (443 if parts.scheme == "https" else 80)


def _local(ctx):
    return is_local_host(_host_port(ctx)[0] or "")


@auto("INFRA-01")
def https_redirect(ctx):
    host, _port = _host_port(ctx)
    if _local(ctx):
        return skipped("INFRA-01", "Local development host; HTTPS redirects are tested on the deployed site.")
    if not ctx.https:
        return failed("INFRA-01", "The site is served over plain HTTP. Serve it over HTTPS and redirect HTTP to it.",
                      [f"target: {ctx.target}"])
    plain = f"http://{host}/"
    try:
        resp = ctx.client.same_host("GET", plain)
    except (ConnectionRefusedError, TimeoutError):
        return passed("INFRA-01", "Port 80 does not answer, so nothing is served without TLS.", [f"{plain}: no answer"])
    loc = resp.get("location") or ""
    ev = [f"GET {plain} -> {resp.status} {('location: ' + loc) if loc else ''}".strip()]
    if resp.is_redirect:
        dest = urlsplit(urljoin(plain, loc))
        if dest.scheme == "https" and (dest.hostname or "").lower() == host.lower():
            if resp.status in (301, 308):
                return passed("INFRA-01", "HTTP permanently redirects to HTTPS on the same host.", ev)
            return warned("INFRA-01", f"HTTP redirects to HTTPS with a temporary {resp.status}; use 301 or 308.", ev)
        if dest.scheme == "https":
            return warned("INFRA-01", "HTTP redirects to HTTPS on a different host; redirect to the same host first so "
                          "HSTS applies.", ev)
        return failed("INFRA-01", "HTTP redirects somewhere that is not HTTPS.", ev)
    return failed("INFRA-01", f"HTTP answers with {resp.status} instead of redirecting to HTTPS.", ev)


@auto("INFRA-02")
def certificate(ctx):
    if not ctx.https:
        return skipped("INFRA-02", "Target is plain HTTP; there is no certificate to check.")
    if _local(ctx):
        return skipped("INFRA-02", "Local development host; certificates are tested on the deployed site.")
    context = ssl.create_default_context()
    try:
        with ctx.client.open_tls(context) as tls:
            cert = tls.getpeercert()
            version = tls.version()
    except ssl.SSLCertVerificationError as exc:
        return failed("INFRA-02", f"The certificate does not verify: {exc.verify_message}.", [str(exc)])
    not_after = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), tz=UTC)
    days = (not_after - datetime.now(UTC)).days
    issuer = dict(x[0] for x in cert.get("issuer", ()))
    ev = [f"expires {not_after.date().isoformat()} ({days} days)", f"issuer: {issuer.get('organizationName', '?')}",
          f"negotiated: {version}"]
    if days < EXPIRY_WARN_DAYS:
        return warned("INFRA-02", f"The certificate expires in {days} days; check that renewal is automatic.", ev)
    return passed("INFRA-02", f"The certificate is valid for {days} more days.", ev)


def _try_version(client, version):
    """Return the negotiated version string, None if the server refused, or 'client' if this machine cannot offer it."""
    context = ssl.create_default_context()
    try:
        context.minimum_version = version
        context.maximum_version = version
        context.set_ciphers("DEFAULT:@SECLEVEL=0")
    except (ValueError, ssl.SSLError):
        return "client"
    try:
        with client.open_tls(context) as tls:
            return tls.version()
    except ssl.SSLCertVerificationError:
        return "cert"
    except ssl.SSLError as exc:
        if "NO_PROTOCOLS_AVAILABLE" in str(exc).upper() or "no protocols available" in str(exc).lower():
            return "client"
        return None
    except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
        return None


@auto("INFRA-03")
def legacy_tls(ctx):
    if not ctx.https:
        return skipped("INFRA-03", "Target is plain HTTP; there is no TLS to check.")
    if _local(ctx):
        return skipped("INFRA-03", "Local development host; TLS versions are tested on the deployed site.")
    accepted, untested, ev = [], [], []
    for name, version in (("TLS 1.0", ssl.TLSVersion.TLSv1), ("TLS 1.1", ssl.TLSVersion.TLSv1_1)):
        got = _try_version(ctx.client, version)
        if got == "client":
            untested.append(name)
            ev.append(f"{name}: this machine's OpenSSL cannot offer it")
        elif got == "cert":
            return errored("INFRA-03", "The certificate did not verify; fix INFRA-02 first.")
        elif got:
            accepted.append(name)
            ev.append(f"{name}: accepted ({got})")
        else:
            ev.append(f"{name}: refused")
    if accepted:
        return failed("INFRA-03", f"The server still accepts {', '.join(accepted)}.", ev)
    if untested:
        return skipped("INFRA-03", f"Could not test {', '.join(untested)} from this machine (its TLS library has them "
                       "turned off). Run `testssl.sh` or an online TLS test instead.")
    return passed("INFRA-03", "TLS 1.0 and 1.1 are refused.", ev)
