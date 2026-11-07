"""INFRA-06/07: email spoofing protection via DNS (SPF, DMARC), read over DNS-over-HTTPS (OSI layer 7, DNS)."""

from __future__ import annotations

import ipaddress
import json
import re
from urllib.parse import quote, urlsplit

from ..model import failed, passed, skipped, warned
from ..scope import is_local_host
from . import auto

DEFAULT_RESOLVER = "https://cloudflare-dns.com/dns-query"
QUOTED = re.compile(r'"((?:[^"\\]|\\.)*)"')


def mail_domain(ctx):
    host = (urlsplit(ctx.target).hostname or "").lower()
    return host.removeprefix("www.")


# A small public-suffix heuristic: second-level suffixes under a two-letter country code (example.co.uk), and
# hosting platforms whose subdomains belong to different owners (app.vercel.app is its own organization).
SECOND_LEVEL = {"co", "com", "org", "net", "gov", "ac", "edu"}
SHARED_PLATFORMS = {"vercel.app", "netlify.app", "pages.dev", "github.io", "herokuapp.com", "web.app",
                    "firebaseapp.com", "onrender.com", "fly.dev", "workers.dev", "supabase.co"}


def organizational_domain(host):
    """Best guess at the RFC 7489 organizational domain of host (the registered name)."""
    labels = host.lower().rstrip(".").split(".")
    keep = 2
    if len(labels) >= 3 and (".".join(labels[-2:]) in SHARED_PLATFORMS
                             or (len(labels[-1]) == 2 and labels[-2] in SECOND_LEVEL)):
        keep = 3
    return ".".join(labels[-keep:])


def _why_skip(ctx):
    host = urlsplit(ctx.target).hostname or ""
    if ctx.opt("no_dns"):
        return "DNS checks turned off (--no-dns)."
    if is_local_host(host):
        return "Local development host has no public DNS."
    try:
        ipaddress.ip_address(host)
        return "Target is an IP address; check SPF and DMARC on your domain."
    except ValueError:
        return None


def txt_records(ctx, name):
    resolver = ctx.opt("dns_resolver", DEFAULT_RESOLVER)
    url = f"{resolver}?name={quote(name)}&type=TXT"
    resp = ctx.client.external("GET", url, headers={"Accept": "application/dns-json"})
    if resp.status != 200:
        raise OSError(f"DNS resolver answered {resp.status}")
    data = json.loads(resp.text)
    records = []
    for ans in data.get("Answer", []) or []:
        if ans.get("type") != 16:
            continue
        raw = ans.get("data", "")
        parts = QUOTED.findall(raw)
        records.append("".join(parts) if parts else raw)
    return records


@auto("INFRA-06")
def spf(ctx):
    why = _why_skip(ctx)
    if why:
        return skipped("INFRA-06", why)
    domain = mail_domain(ctx)
    found = [r for r in txt_records(ctx, domain) if r.lower().startswith("v=spf1")]
    if not found:
        return failed("INFRA-06", f"{domain} has no SPF record, so anyone can send mail that claims to be from it. "
                      "If the domain sends no mail, publish v=spf1 -all.", [f"TXT {domain}: no v=spf1 record"])
    if len(found) > 1:
        return failed("INFRA-06", f"{domain} has {len(found)} SPF records; receivers treat that as an error.",
                      [f"TXT {domain}: {r}" for r in found])
    record = found[0]
    ev = [f"TXT {domain}: {record}"]
    terms = record.lower().split()
    if "+all" in terms or "all" in terms:
        return failed("INFRA-06", "SPF ends in +all, which lets every server on the internet send as this domain.", ev)
    if "?all" in terms:
        return warned("INFRA-06", "SPF ends in ?all (neutral), which gives receivers no instruction.", ev)
    if not any(t.endswith("all") for t in terms) and not any(t.startswith("redirect=") for t in terms):
        return warned("INFRA-06", "SPF has no all mechanism; end it with -all or ~all.", ev)
    return passed("INFRA-06", "SPF names the allowed senders and rejects or flags the rest.", ev)


@auto("INFRA-07")
def dmarc(ctx):
    why = _why_skip(ctx)
    if why:
        return skipped("INFRA-07", why)
    domain = mail_domain(ctx)
    name = f"_dmarc.{domain}"
    found = [r for r in txt_records(ctx, name) if r.lower().startswith("v=dmarc1")]
    org = organizational_domain(domain)
    inherited = False
    if not found and org != domain:
        # RFC 7489 6.6.3: with no record at the host, receivers apply the organizational domain's record (sp=).
        org_name = f"_dmarc.{org}"
        found = [r for r in txt_records(ctx, org_name) if r.lower().startswith("v=dmarc1")]
        if found:
            name, inherited = org_name, True
    if not found:
        where = f"_dmarc.{domain}" + (f" or _dmarc.{org}" if org != domain else "")
        return failed("INFRA-07", f"{domain} has no DMARC record, so receivers have no policy for spoofed mail.",
                      [f"TXT {where}: none"])
    record = found[0]
    ev = [f"TXT {name}: {record}"]
    tags = {}
    for part in record.split(";"):
        k, _, v = part.strip().partition("=")
        if k:
            tags[k.strip().lower()] = v.strip().lower()
    if inherited:
        ev.append(f"no record at _dmarc.{domain}; the organizational domain's sp= (or p=) applies")
        tags["p"] = tags.get("sp") or tags.get("p", "")
    policy = tags.get("p", "")
    if policy not in ("quarantine", "reject"):
        return warned("INFRA-07", f"DMARC policy is p={policy or '(missing)'}: spoofed mail is still delivered. "
                      "Move to quarantine, then reject, once reports look clean.", ev)
    pct = tags.get("pct", "100")
    if pct != "100":
        return warned("INFRA-07", f"DMARC p={policy} applies to only {pct}% of mail.", ev)
    if "rua" not in tags:
        return warned("INFRA-07", f"DMARC enforces p={policy}, but has no rua= address, so you never see spoofing "
                      "attempts or broken senders.", ev)
    return passed("INFRA-07", f"DMARC enforces p={policy} and sends aggregate reports.", ev)
