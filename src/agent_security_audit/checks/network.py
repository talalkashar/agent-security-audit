"""Network, TLS and DNS depth (OSI layers 4-7): exposed service ports, weak TLS 1.2 cipher suites, CAA, DNSSEC,
dangling CNAMEs and MTA-STS.

Port checks only open a TCP connection and close it; they send nothing, read nothing and never log in. DNS is read
over DNS-over-HTTPS through the same budgeted client as the SPF and DMARC checks.
"""

from __future__ import annotations

import ipaddress
import json
import ssl
from urllib.parse import quote, urlsplit

from ..http import NETWORK_ERRORS
from ..model import Result, errored, failed, passed, skipped, warned
from ..scope import is_local_host
from . import auto, count
from .dns_email import DEFAULT_RESOLVER, QUOTED, SHARED_PLATFORMS, mail_domain, organizational_domain

# --- exposed ports (layer 4) -------------------------------------------------------------------------------------

# Services that ship with no authentication or are never meant for the public internet.
DATA_PORTS = {1433: "Microsoft SQL Server", 2375: "Docker API (no TLS)", 3306: "MySQL", 5432: "PostgreSQL",
              6379: "Redis", 9200: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB"}
# Remote administration. Telnet and VNC send credentials in the clear; RDP is a common ransomware entry point.
ADMIN_PORTS = {23: "Telnet", 3389: "Remote Desktop (RDP)", 5900: "VNC"}
# SSH is often open on purpose with key-only logins, so it is a warning, not a failure.
SSH_PORT = 22
# tcpmux, obsolete and practically never served. If it answers too, the address accepts every port (a SYN proxy or
# tarpit), and an open port proves nothing.
CONTROL_PORT = 1
PORT_TIMEOUT = 2.0


def _port_skip(ctx):
    host = urlsplit(ctx.target).hostname or ""
    if ctx.opt("no_ports"):
        return "Port checks turned off (--no-ports)."
    if is_local_host(host):
        return "Local development host; a dev machine's database is expected to listen locally. Ports are tested on " \
               "the deployed server."
    return None


def _probe(ctx, ports):
    """{port: state}, cached per run so a port is never probed twice."""
    seen = ctx.cache.setdefault("ports", {})
    timeout = float(ctx.opt("port_timeout", PORT_TIMEOUT))
    for port in ports:
        if port not in seen:
            seen[port] = ctx.client.probe_port(port, timeout=timeout)
    return {p: seen[p] for p in ports}


def _accepts_everything(ctx):
    return _probe(ctx, [CONTROL_PORT])[CONTROL_PORT] == "open"


def _port_lines(address, states, names):
    return [f"{address}:{p} ({names[p]}): {s}" for p, s in states.items()]


NOTE_CDN = ("Probed from this machine only. If a CDN or proxy fronts the site, this tests the edge, not the origin "
            "server; test the origin's address too.")


def _ports_result(ctx, check_id, ports, names, warn_ports=()):
    why = _port_skip(ctx)
    if why:
        return skipped(check_id, why)
    address = ctx.client.target_address()
    states = _probe(ctx, ports)
    ev = _port_lines(address, states, names)
    opened = [p for p, s in states.items() if s == "open"]
    if opened and _accepts_everything(ctx):
        return Result(check_id, "manual", f"{address} accepts a connection on every port, including unused port "
                      f"{CONTROL_PORT}, so open ports cannot be told apart. Check the server's firewall rules.",
                      [*ev, f"{address}:{CONTROL_PORT} (control): open"])
    bad = [p for p in opened if p not in warn_ports]
    if bad:
        listed = ", ".join(f"{p} ({names[p]})" for p in bad)
        return failed(check_id, f"{address} accepts connections from the internet on {listed}.", ev)
    if opened:
        listed = ", ".join(f"{p} ({names[p]})" for p in opened)
        return warned(check_id, f"{address} accepts connections on {listed}. Limit it to known addresses or a VPN.",
                      ev)
    return passed(check_id, f"None of the {len(ports)} ports accept a connection from this machine. {NOTE_CDN}", ev)


@auto("INFRA-24")
def data_ports(ctx):
    return _ports_result(ctx, "INFRA-24", list(DATA_PORTS), DATA_PORTS)


@auto("INFRA-25")
def admin_ports(ctx):
    names = {SSH_PORT: "SSH", **ADMIN_PORTS}
    return _ports_result(ctx, "INFRA-25", list(names), names, warn_ports=(SSH_PORT,))


# --- TLS 1.2 cipher suites (layer 6) -----------------------------------------------------------------------------

# Broken: RC4 (RFC 7465), 3DES and DES (64-bit blocks), export grade and NULL encryption.
BROKEN_CIPHERS = "RC4:3DES:DES:EXPORT:eNULL:@SECLEVEL=0"
# Static RSA key exchange: works, but a later key leak decrypts every recorded session (no forward secrecy).
STATIC_RSA = "kRSA:!RC4:!3DES:!DES:!EXPORT:!eNULL:!aNULL:@SECLEVEL=0"


def _try_ciphers(client, ciphers):
    """Return the negotiated suite, None if the server refused, 'client' if this machine cannot offer any of them,
    or 'cert' if the certificate did not verify."""
    context = ssl.create_default_context()
    try:
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.maximum_version = ssl.TLSVersion.TLSv1_2
        context.set_ciphers(ciphers)
    except (ValueError, ssl.SSLError):
        return "client"
    if not [c for c in context.get_ciphers() if c.get("protocol") != "TLSv1.3"]:
        return "client"
    try:
        with client.open_tls(context) as tls:
            return tls.cipher()[0]
    except ssl.SSLCertVerificationError:
        return "cert"
    except (ssl.SSLError, ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
        return None


@auto("INFRA-26")
def weak_ciphers(ctx):
    if not ctx.https:
        return skipped("INFRA-26", "Target is plain HTTP; there is no TLS to check.")
    if is_local_host(urlsplit(ctx.target).hostname or ""):
        return skipped("INFRA-26", "Local development host; cipher suites are tested on the deployed site.")
    got = {}
    for label, ciphers in (("broken", BROKEN_CIPHERS), ("static RSA", STATIC_RSA)):
        got[label] = _try_ciphers(ctx.client, ciphers)
        if got[label] == "cert":
            return errored("INFRA-26", "The certificate did not verify; fix INFRA-02 first.")
    ev = []
    for label, what in (("broken", "RC4, 3DES, DES, export or NULL suites"), ("static RSA", "static RSA key exchange")):
        value = got[label]
        ev.append(f"TLS 1.2 offering only {what}: " + ("this machine's OpenSSL cannot offer them" if value == "client"
                                                       else f"accepted ({value})" if value else "refused"))
    if got["broken"] not in (None, "client"):
        return failed("INFRA-26", f"The server accepts a broken TLS 1.2 cipher suite ({got['broken']}).", ev)
    if got["static RSA"] not in (None, "client"):
        return warned("INFRA-26", f"The server accepts {got['static RSA']}, a suite without forward secrecy.", ev)
    if "client" in got.values():
        return skipped("INFRA-26", "This machine's TLS library cannot offer some of the weak suites, so they were not "
                       "all tested. Run `testssl.sh` or an online TLS test instead.")
    return passed("INFRA-26", "TLS 1.2 refuses broken and non-forward-secret cipher suites.", ev)


# --- DNS (layer 7) ------------------------------------------------------------------------------------------------

DNS_TYPES = {"A": 1, "CNAME": 5, "MX": 15, "TXT": 16, "DS": 43, "CAA": 257}


def _dns_skip(ctx, what):
    host = urlsplit(ctx.target).hostname or ""
    if ctx.opt("no_dns"):
        return "DNS checks turned off (--no-dns)."
    if is_local_host(host):
        return "Local development host has no public DNS."
    try:
        ipaddress.ip_address(host)
        return f"Target is an IP address; check {what} on your domain."
    except ValueError:
        return None


def _platform_host(host):
    return any(host == p or host.endswith("." + p) for p in SHARED_PLATFORMS)


def dns_query(ctx, name, rtype, *, cd=False):
    """One DNS-over-HTTPS JSON query. Returns the parsed response (Status, AD, Answer...)."""
    resolver = ctx.opt("dns_resolver", DEFAULT_RESOLVER)
    url = f"{resolver}?name={quote(name)}&type={rtype}" + ("&cd=1" if cd else "")
    resp = ctx.client.external("GET", url, headers={"Accept": "application/dns-json"})
    if resp.status != 200:
        raise OSError(f"DNS resolver answered {resp.status}")
    return json.loads(resp.text)


def answers(data, rtype):
    """(owner name, data) of every answer of rtype; quoted TXT strings are joined."""
    out = []
    for ans in data.get("Answer", []) or []:
        if ans.get("type") != DNS_TYPES[rtype]:
            continue
        raw = ans.get("data", "")
        if rtype == "TXT":
            parts = QUOTED.findall(raw)
            raw = "".join(parts) if parts else raw
        out.append((ans.get("name", "").rstrip("."), raw))
    return out


def parse_caa(data):
    """Return (tag, value) from a CAA answer in presentation form (0 issue "ca.example") or RFC 3597 hex form."""
    data = data.strip()
    if data.startswith("\\#"):
        raw = bytes.fromhex("".join(data.split()[2:]))
        n = raw[1]
        return raw[2:2 + n].decode("ascii", "replace").lower(), raw[2 + n:].decode("utf-8", "replace")
    parts = data.split(None, 2)
    if len(parts) < 3:
        return "", ""
    return parts[1].lower(), parts[2].strip().strip('"')


# CAA identifiers for the issuers seen most on web hosts (organizationName substring -> CAA issuer domains).
ISSUER_CAA = {
    "let's encrypt": {"letsencrypt.org"},
    "google trust services": {"pki.goog"},
    "digicert": {"digicert.com", "www.digicert.com"},
    "sectigo": {"sectigo.com", "comodoca.com", "comodo.com", "usertrust.com"},
    "zerossl": {"sectigo.com"},
    "amazon": {"amazon.com", "amazontrust.com", "awstrust.com", "amazonaws.com"},
    "globalsign": {"globalsign.com"},
    "ssl corporation": {"ssl.com"},
    "ssl.com": {"ssl.com"},
}


def _peer_cert(ctx):
    """The verified leaf certificate as getpeercert() returns it, fetched once per run; None if it does not verify."""
    if "peer_cert" not in ctx.cache:
        try:
            with ctx.client.open_tls(ssl.create_default_context()) as tls:
                ctx.cache["peer_cert"] = tls.getpeercert()
        except ssl.SSLCertVerificationError:
            ctx.cache["peer_cert"] = None
    return ctx.cache["peer_cert"]


def _caa_set(ctx, host):
    """RFC 8659 relevant record set: climb from host towards the registered domain, stop at the first CAA set."""
    org = organizational_domain(host)
    labels = host.split(".")
    for i in range(len(labels)):
        name = ".".join(labels[i:])
        found = [parse_caa(d) for _, d in answers(dns_query(ctx, name, "CAA"), "CAA")]
        if found:
            return name, found
        if name == org:
            break
    return None, []


@auto("INFRA-11")
def caa(ctx):
    why = _dns_skip(ctx, "CAA")
    if why:
        return skipped("INFRA-11", why)
    host = (urlsplit(ctx.target).hostname or "").lower()
    if _platform_host(host):
        return skipped("INFRA-11", "The site is on a shared platform domain; its CAA records belong to the platform.")
    name, records = _caa_set(ctx, host)
    if not records:
        return warned("INFRA-11", f"No CAA record for {host} or its parent domain, so any public CA may issue a "
                      "certificate for it.", [f"CAA {host} .. {organizational_domain(host)}: none"])
    ev = [f"CAA {name}: {tag} \"{value}\"" for tag, value in records]
    cert = _peer_cert(ctx) if ctx.https else None
    if not cert:
        why = "target is plain HTTP" if not ctx.https else "certificate did not verify (INFRA-02)"
        return passed("INFRA-11", f"CAA records limit which CAs may issue for {host} (issuer not compared: {why}).", ev)
    issuer = dict(x[0] for x in cert.get("issuer", ())).get("organizationName", "")
    sans = [v.lower() for k, v in cert.get("subjectAltName", ()) if k == "DNS"]
    wildcard = host not in sans
    # RFC 8659 4.3: for a wildcard certificate, issuewild records (when present) replace issue records.
    tag = "issuewild" if wildcard and any(t == "issuewild" for t, _ in records) else "issue"
    allowed = {v.split(";")[0].strip().lower() for t, v in records if t == tag}
    allowed.discard("")
    ev.append(f"current certificate issuer: {issuer or '?'}" + (" (wildcard)" if wildcard else ""))
    want = next((ids for key, ids in ISSUER_CAA.items() if key in issuer.lower()), None)
    if want is None:
        return Result("INFRA-11", "manual", f"CAA records exist, but the issuer {issuer or '?'} is not in this tool's "
                      "table. Confirm its CAA domain is listed, or renewal will fail.", ev)
    if allowed & want:
        return passed("INFRA-11", f"CAA limits issuance and allows the current CA ({issuer}).", ev)
    return failed("INFRA-11", f"CAA does not allow the current CA ({issuer}), so its next renewal will be refused.", ev)


@auto("INFRA-27")
def dnssec(ctx):
    why = _dns_skip(ctx, "DNSSEC")
    if why:
        return skipped("INFRA-27", why)
    host = (urlsplit(ctx.target).hostname or "").lower()
    if _platform_host(host):
        return skipped("INFRA-27", "The site is on a shared platform domain; DNSSEC is the platform's to set.")
    zone = organizational_domain(host)
    ds = answers(dns_query(ctx, zone, "DS"), "DS")
    if not ds:
        return warned("INFRA-27", f"{zone} is not signed with DNSSEC (no DS record at the parent), so resolvers "
                      "cannot detect forged answers. Enable it only with automatic key rollover.",
                      [f"DS {zone}: none"])
    ev = [f"DS {zone}: {count(len(ds), 'record')}"]
    checked = dns_query(ctx, host, "A")
    if checked.get("Status") == 2:
        unchecked = dns_query(ctx, host, "A", cd=True)
        ev.append(f"A {host}: SERVFAIL when validated")
        if unchecked.get("Status") == 0:
            ev.append(f"A {host}: answers with validation turned off (cd=1)")
            return failed("INFRA-27", f"DNSSEC validation fails for {host}: validating resolvers return SERVFAIL, so "
                          "the site is unreachable for their users. Fix the DS or DNSKEY records.", ev)
        return errored("INFRA-27", f"The resolver returned SERVFAIL for {host} even without validation.")
    if checked.get("AD"):
        ev.append(f"A {host}: validated (AD flag set)")
        return passed("INFRA-27", f"{zone} is signed and {host} validates.", ev)
    ev.append(f"A {host}: answered without the AD flag")
    return warned("INFRA-27", f"{zone} has a DS record, but {host} did not validate; part of the chain is unsigned.",
                  ev)


# Providers where a CNAME pointing at a name that no longer exists (NXDOMAIN) can be claimed by anyone who creates
# a resource with that name. From Microsoft's dangling-DNS guidance and the can-i-take-over-xyz list.
CLAIMABLE_NXDOMAIN = ("azurewebsites.net", "cloudapp.net", "cloudapp.azure.com", "trafficmanager.net",
                      "blob.core.windows.net", "azureedge.net", "azure-api.net", "azurefd.net", "elasticbeanstalk.com")
# Providers that answer for unclaimed names with a fixed page instead of NXDOMAIN: (CNAME suffix, page marker).
CLAIMABLE_PAGE = (("github.io", "There isn't a GitHub Pages site here."), ("amazonaws.com", "NoSuchBucket"))


def _twin(host):
    org = organizational_domain(host)
    if host == org:
        return "www." + host
    if host == "www." + org:
        return org
    return None


def _cname_chain(ctx, name):
    data = dns_query(ctx, name, "A")
    return data.get("Status"), [d.rstrip(".").lower() for _, d in answers(data, "CNAME")]


def _ends(name, suffix):
    return name == suffix or name.endswith("." + suffix)


@auto("INFRA-28")
def dangling_cname(ctx):
    why = _dns_skip(ctx, "CNAME records")
    if why:
        return skipped("INFRA-28", why)
    host = (urlsplit(ctx.target).hostname or "").lower()
    names = [host] + ([t] if (t := _twin(host)) and not _platform_host(host) else [])
    ev, fails, warns = [], [], []
    for name in names:
        status, chain = _cname_chain(ctx, name)
        if not chain:
            ev.append(f"{name}: no CNAME")
            continue
        last = chain[-1]
        ev.append(f"{name}: CNAME -> {' -> '.join(chain)}" + (" (NXDOMAIN)" if status == 3 else ""))
        if status == 3:
            claimable = any(_ends(last, s) for s in CLAIMABLE_NXDOMAIN)
            (fails if claimable else warns).append(f"{name} points at {last}, which does not exist")
            continue
        if name == host:
            for suffix, marker in CLAIMABLE_PAGE:
                if _ends(last, suffix):
                    body = ctx.client.home().text
                    if marker in body:
                        ev.append(f"{host} answers with the provider's unclaimed page ({marker!r})")
                        fails.append(f"{host} points at {last}, which the provider reports as unclaimed")
    if fails:
        return failed("INFRA-28", "Dangling DNS: " + "; ".join(fails) + ". Anyone can claim that name and serve "
                      "content on your domain.", ev)
    if warns:
        return warned("INFRA-28", "Dangling DNS: " + "; ".join(warns) + ". Remove the record.", ev)
    return passed("INFRA-28", "No dangling CNAME on the site's hostnames.", ev)


def _mx_match(mx, patterns):
    """RFC 8461 4.1: an exact name, or *.suffix matching exactly one more label."""
    for p in patterns:
        if p.startswith("*."):
            label, _, rest = mx.partition(".")
            if label and rest == p[2:]:
                return True
        elif mx == p:
            return True
    return False


def parse_sts_policy(text):
    policy = {"mx": []}
    for line in text.splitlines():
        key, _, value = line.partition(":")
        key, value = key.strip().lower(), value.strip()
        if key == "mx":
            policy["mx"].append(value.lower().rstrip("."))
        elif key:
            policy[key] = value.lower()
    return policy


@auto("INFRA-12")
def mta_sts(ctx):
    why = _dns_skip(ctx, "MTA-STS")
    if why:
        return skipped("INFRA-12", why)
    domain = mail_domain(ctx)
    mx = [d.split()[-1].rstrip(".").lower() for _, d in answers(dns_query(ctx, domain, "MX"), "MX") if d.split()]
    mx = [m for m in mx if m]  # a null MX ("0 .") leaves nothing
    if not mx:
        return skipped("INFRA-12", f"{domain} has no MX records, so it receives no mail.")
    ev = [f"MX {domain}: {', '.join(mx)}"]
    sts = [r for _, r in answers(dns_query(ctx, f"_mta-sts.{domain}", "TXT"), "TXT") if r.lower().startswith("v=stsv1")]
    rpt = [r for _, r in answers(dns_query(ctx, f"_smtp._tls.{domain}", "TXT"), "TXT")
           if r.lower().startswith("v=tlsrptv1") and "rua=" in r.lower()]
    ev.append(f"TXT _smtp._tls.{domain}: {rpt[0] if rpt else 'none'}")
    if not sts:
        ev.insert(1, f"TXT _mta-sts.{domain}: none")
        return warned("INFRA-12", f"{domain} receives mail but publishes no MTA-STS policy, so a network attacker can "
                      "strip STARTTLS from mail sent to it.", ev)
    ev.insert(1, f"TXT _mta-sts.{domain}: {sts[0]}")
    url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
    try:
        resp = ctx.client.external("GET", url)
    except ssl.SSLCertVerificationError as exc:
        return failed("INFRA-12", "The MTA-STS policy host's certificate does not verify, so senders ignore the "
                      "policy.", [*ev, f"GET {url}: {exc.verify_message}"])
    except NETWORK_ERRORS as exc:
        return errored("INFRA-12", f"Could not fetch {url}: {type(exc).__name__}: {exc}")
    if resp.status != 200:
        return failed("INFRA-12", f"The MTA-STS record exists but the policy file answers {resp.status}, so senders "
                      "have no policy.", [*ev, f"GET {url} -> {resp.status}"])
    policy = parse_sts_policy(resp.text)
    mode = policy.get("mode", "")
    ev.append(f"policy: version={policy.get('version', '?')} mode={mode or '?'} mx={', '.join(policy['mx'])} "
              f"max_age={policy.get('max_age', '?')}")
    if policy.get("version") != "stsv1" or mode not in ("enforce", "testing", "none"):
        return failed("INFRA-12", "The MTA-STS policy file is not a valid STSv1 policy.", ev)
    if mode != "enforce":
        return warned("INFRA-12", f"MTA-STS is in mode {mode}: senders report failures but still deliver over "
                      "plaintext. Move to enforce once TLS-RPT reports are clean.", ev)
    unlisted = [m for m in mx if not _mx_match(m, policy["mx"])]
    if unlisted:
        return failed("INFRA-12", f"MTA-STS enforces, but MX {', '.join(unlisted)} matches no mx: line, so senders "
                      "that honor the policy refuse to deliver to it.", ev)
    if not rpt:
        return warned("INFRA-12", "MTA-STS enforces, but there is no TLS-RPT record, so you never hear about failed "
                      "deliveries.", ev)
    return passed("INFRA-12", "MTA-STS enforces TLS for every MX, and TLS-RPT sends reports.", ev)
