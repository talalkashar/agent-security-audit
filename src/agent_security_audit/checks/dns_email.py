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


def _txt_lookup(ctx, name):
    """(DNS response code, TXT strings) for name through the configured DNS-over-HTTPS resolver."""
    resolver = ctx.opt("dns_resolver", DEFAULT_RESOLVER)
    url = f"{resolver}?name={quote(name)}&type=TXT"
    resp = ctx.client.external("GET", url, headers={"Accept": "application/dns-json"})
    if resp.status != 200:
        raise OSError(f"DNS resolver answered {resp.status}")
    try:
        data = json.loads(resp.text)
    except ValueError as exc:
        raise OSError("DNS resolver answered with something that is not JSON") from exc
    if not isinstance(data, dict):
        raise OSError("DNS resolver answered with unexpected JSON")
    records = []
    for ans in data.get("Answer", []) or []:
        if not isinstance(ans, dict) or ans.get("type") != 16:
            continue
        raw = str(ans.get("data", ""))
        parts = QUOTED.findall(raw)
        records.append("".join(parts) if parts else raw)
    rcode = data.get("Status", 0)
    return (rcode if isinstance(rcode, int) else 0), records


def txt_records(ctx, name):
    rcode, records = _txt_lookup(ctx, name)
    if rcode not in (0, NXDOMAIN):  # SERVFAIL or REFUSED: the record may exist, so absence is not proven
        raise OSError(f"DNS lookup for {name[:120]} failed (response code {rcode})")
    return records


def _spf_records(records):
    return [r for r in records if r.lower() == "v=spf1" or r.lower().startswith("v=spf1 ")]


# RFC 7208 4.6.4: include, a, mx, ptr and exists mechanisms and the redirect modifier each cost one DNS lookup, counted
# across every included record; more than 10 is a permerror, so receivers treat the SPF policy as broken.
MAX_LOOKUPS = 10
DNS_MECHANISM = re.compile(r"^(?:a|mx|ptr)(?:$|[:/])|^exists:")
NXDOMAIN = 3


def _all_of(terms):
    return next((t for t in terms if t.lstrip("+-~?") == "all"), None)


def _cidr0_before_all(record):
    """'+' or '?' when an ip4 or ip6 prefix of /0 appears before all, else None.

    RFC 7208 evaluates left to right and stops at the first match, so ip4:0.0.0.0/0 -all matches every
    IPv4 address and the trailing all never runs. A fail or softfail qualifier on that mechanism does not
    let mail pass. a/0 and mx/0 are not judged here: they match only when the name has an address.
    """
    for term in record.lower().split()[1:]:
        qual, mech = (term[0], term[1:]) if term[:1] in "+-~?" else ("+", term)
        if mech == "all":
            return None
        if qual not in "+?":
            continue
        if _ip_prefix_zero(mech):
            return qual
    return None


def _ip_prefix_zero(mech):
    found = re.fullmatch(r"ip4:(\d{1,3}(?:\.\d{1,3}){3})/0", mech) or re.fullmatch(r"ip6:([0-9a-f:]+)/0", mech)
    if not found:
        return False
    try:
        ipaddress.ip_address(found.group(1))
    except ValueError:
        return False
    return True


def _walk_spf(ctx, record):
    """Expand include: and redirect= through the same resolver. Returns (lookups, problems, evidence, effective record),
    where the effective record is the one whose all mechanism decides (the redirect target when there is no all).
    Stops once the lookup limit is passed, so it never sends more than MAX_LOOKUPS + 1 queries."""
    state = {"lookups": 0, "problems": [], "ev": []}

    def walk(rec, depth):
        terms = rec.lower().split()[1:]
        effective = rec
        has_all = _all_of(terms) is not None
        for term in terms:
            mech = term.lstrip("+-~?")
            if term.startswith("redirect="):
                if has_all:  # RFC 7208 6.1: redirect is ignored when the record has an all mechanism
                    continue
                kind, target = "redirect", term.removeprefix("redirect=")
            elif mech.startswith("include:"):
                kind, target = "include", mech.removeprefix("include:")
            elif DNS_MECHANISM.search(mech):
                state["lookups"] += 1
                continue
            else:
                continue
            state["lookups"] += 1
            if state["lookups"] > MAX_LOOKUPS:
                return effective
            if "%" in target or depth >= MAX_LOOKUPS:  # a macro is expanded per message; it cannot be resolved here
                continue
            rcode, records = _txt_lookup(ctx, target)
            found = _spf_records(records)
            if rcode == NXDOMAIN:
                state["problems"].append(f"{kind} {target} does not exist (NXDOMAIN)")
            elif rcode != 0:
                raise OSError(f"DNS resolver answered status {rcode} for {target}")
            elif not found:
                state["problems"].append(f"{kind} {target} has no SPF record")
            elif len(found) > 1:
                state["problems"].append(f"{kind} {target} has {len(found)} SPF records")
            else:
                state["ev"].append(f"TXT {target}: {found[0]}")
                inner = walk(found[0], depth + 1)
                # judge the record the include resolves to, after its own redirect (RFC 7208 5.2, 6.1)
                if kind == "include" and _all_of(inner.lower().split()[1:]) in ("all", "+all"):
                    state["problems"].append(f"include {target} ends in +all, so it matches every server")
                if kind == "include" and _cidr0_before_all(inner) == "+":
                    state["problems"].append(f"include {target} matches every address with an ip4 or ip6 prefix of /0 "
                                             "before all")
                if kind == "redirect":
                    effective = inner
            if state["lookups"] > MAX_LOOKUPS:
                return effective
        return effective

    effective = walk(record, 0)
    return state["lookups"], state["problems"], state["ev"], effective


@auto("INFRA-06")
def spf(ctx):
    why = _why_skip(ctx)
    if why:
        return skipped("INFRA-06", why)
    domain = mail_domain(ctx)
    found = _spf_records(txt_records(ctx, domain))
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
    lookups, problems, walked, effective = _walk_spf(ctx, record)
    ev += walked[:12]
    if lookups > MAX_LOOKUPS:
        return failed("INFRA-06", f"SPF needs more than {MAX_LOOKUPS} DNS lookups once includes and redirects are "
                      "expanded, so receivers return permerror and the policy protects nothing (RFC 7208 4.6.4). "
                      "Remove unused includes or flatten them.", ev + [f"DNS lookups counted: over {MAX_LOOKUPS}"])
    if problems:
        return failed("INFRA-06", "SPF points at records that do not resolve to one valid SPF policy ("
                      + "; ".join(problems) + "), so receivers return permerror or let every server pass.", ev)
    ev.append(f"DNS lookups counted: {lookups} of {MAX_LOOKUPS}")
    terms = effective.lower().split()
    if "+all" in terms or "all" in terms:
        return failed("INFRA-06", "SPF redirects to a record that ends in +all, which lets every server on the "
                      "internet send as this domain.", ev)
    hole = _cidr0_before_all(effective)
    if hole == "+":
        return failed("INFRA-06", "SPF matches every address with an ip4 or ip6 prefix of /0 before all, so the "
                      "trailing all never runs (RFC 7208 evaluates left to right).", ev)
    if "?all" in terms:
        return warned("INFRA-06", "SPF ends in ?all (neutral), which gives receivers no instruction.", ev)
    if hole == "?":
        return warned("INFRA-06", "SPF matches every address with ? on an ip4 or ip6 prefix of /0 before all, which "
                      "gives receivers no instruction.", ev)
    if _all_of(terms) is None:
        return warned("INFRA-06", "SPF has no all mechanism; end it with -all or ~all.", ev)
    return passed("INFRA-06", f"SPF names the allowed senders, rejects or flags the rest, and needs {lookups} of "
                  f"{MAX_LOOKUPS} DNS lookups.", ev)


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
    if len(found) > 1:  # RFC 7489 6.6.3: receivers discard every record and apply no policy
        return failed("INFRA-07", f"{name} has {len(found)} DMARC records, so receivers ignore all of them and apply "
                      "no policy. Keep one.", [f"TXT {name}: {r}" for r in found[:5]])
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
