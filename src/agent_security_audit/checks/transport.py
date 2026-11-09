"""Transport checks: HTTPS redirect, certificate, legacy TLS (OSI layers 4-6)."""

from __future__ import annotations

import ssl
from datetime import UTC, datetime
from urllib.parse import urljoin, urlsplit

from ..http import ResponseTooSlow
from ..model import Result, errored, failed, passed, skipped, warned
from ..scope import is_local_host
from . import auto

EXPIRY_FAIL_DAYS = 14
EXPIRY_WARN_DAYS = 30


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
    except ConnectionRefusedError:
        return passed("INFRA-01", "Port 80 refuses connections, so nothing is served without TLS.",
                      [f"{plain}: connection refused"])
    except ResponseTooSlow as exc:
        # The watchdog cut a reply that was still arriving: port 80 answered, so this is not a silent drop.
        return errored("INFRA-01", f"Port 80 answered too slowly to read in full ({exc}), so what it serves is not "
                       "known. Open http:// in a browser and confirm it redirects to HTTPS.")
    except TimeoutError:
        # A silent drop looks the same as a network problem between this machine and the site, so it proves nothing.
        return Result("INFRA-01", "manual", "Port 80 did not answer in time: a firewall drop or a network problem on "
                      "the way. Open http:// in a browser and confirm it redirects to HTTPS or does not load.",
                      [f"{plain}: timed out"])
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
    # Renewal normally happens with a third of the lifetime left, so short-lived certificates (6 or 47 days) get
    # proportionally shorter thresholds: 14/30 days for a 90-day certificate.
    lifetime = (not_after - datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notBefore"]), tz=UTC)).days
    fail_days, warn_days = min(EXPIRY_FAIL_DAYS, lifetime // 6), min(EXPIRY_WARN_DAYS, lifetime // 3)
    issuer = dict(x[0] for x in cert.get("issuer", ()))
    ev = [f"expires {not_after.date().isoformat()} ({days} days)", f"issuer: {issuer.get('organizationName', '?')}",
          f"negotiated: {version}"]
    if days <= fail_days:
        return failed("INFRA-02", f"The certificate expires in {days} days and has not been renewed; renewal is "
                      "probably failing.", ev)
    if days < warn_days:
        return warned("INFRA-02", f"The certificate expires in {days} days; check that renewal is automatic.", ev)
    return passed("INFRA-02", f"The certificate is valid for {days} more days.", ev)


# Only these mean the server refused the protocol version: its protocol_version alert, or a reply in a version this
# client did not offer. A handshake_failure (no shared cipher), a reset or a closed connection could have other causes.
VERSION_REFUSALS = ("TLSV1_ALERT_PROTOCOL_VERSION", "UNSUPPORTED_PROTOCOL", "WRONG_SSL_VERSION",
                    "ALERT PROTOCOL VERSION", "UNSUPPORTED PROTOCOL")


def _try_version(client, version):
    """Return the negotiated version string, None if the server refused the version, 'client' if this machine cannot
    offer it, 'cert' if the certificate did not verify, or ('inconclusive', reason) for any other handshake error."""
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
        text = f"{getattr(exc, 'reason', '') or ''} {exc}".upper()
        if "NO_PROTOCOLS_AVAILABLE" in text or "NO PROTOCOLS AVAILABLE" in text:
            return "client"
        if any(r in text for r in VERSION_REFUSALS):
            return None
        return ("inconclusive", getattr(exc, "reason", None) or type(exc).__name__)
    except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError) as exc:
        return ("inconclusive", type(exc).__name__)


@auto("INFRA-03")
def legacy_tls(ctx):
    if not ctx.https:
        return skipped("INFRA-03", "Target is plain HTTP; there is no TLS to check.")
    if _local(ctx):
        return skipped("INFRA-03", "Local development host; TLS versions are tested on the deployed site.")
    accepted, untested, unclear, ev = [], [], [], []
    for name, version in (("TLS 1.0", ssl.TLSVersion.TLSv1), ("TLS 1.1", ssl.TLSVersion.TLSv1_1)):
        got = _try_version(ctx.client, version)
        if isinstance(got, tuple):
            unclear.append(name)
            ev.append(f"{name}: handshake failed without a protocol-version refusal ({str(got[1])[:80]})")
        elif got == "client":
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
    if unclear:
        return Result("INFRA-03", "manual", f"The handshake for {', '.join(unclear)} failed for a reason other than a "
                      "protocol-version refusal (for example no shared cipher, or the connection was dropped), so it "
                      "is not proven that the server refuses the version. Run `testssl.sh` or an online TLS test.", ev)
    if untested:
        return skipped("INFRA-03", f"Could not test {', '.join(untested)} from this machine (its TLS library has them "
                       "turned off). Run `testssl.sh` or an online TLS test instead.")
    return passed("INFRA-03", "TLS 1.0 and 1.1 are refused.", ev)
