"""The check catalog: one TOML file per area under catalog/, validated on load."""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from functools import lru_cache
from importlib import resources

SEVERITIES = ("critical", "high", "medium", "low")
MODES = ("auto", "assisted", "review")
ID_RE = re.compile(r"^[A-Z]+-\d{2}$")
CWE_RE = re.compile(r"^CWE-\d+$")
REQUIRED = ("id", "title", "severity", "layer", "cwe", "risk", "build", "proof", "mode", "stacks", "sources")
ALLOWED = (*REQUIRED, "asvs", "probe", "owasp")
PROBES = ("passive", "active")
STACKS = ("any", "nextjs", "supabase", "vercel", "node")

# OWASP categories a check may name in its optional `owasp` list, with their official titles.
OWASP_LISTS = {
    "2021": "OWASP Top 10:2021",
    "2025": "OWASP Top 10:2025",
    "API2023": "OWASP API Security Top 10:2023",
}
OWASP = {
    "A01:2021": "Broken Access Control",
    "A02:2021": "Cryptographic Failures",
    "A03:2021": "Injection",
    "A04:2021": "Insecure Design",
    "A05:2021": "Security Misconfiguration",
    "A06:2021": "Vulnerable and Outdated Components",
    "A07:2021": "Identification and Authentication Failures",
    "A08:2021": "Software and Data Integrity Failures",
    "A09:2021": "Security Logging and Monitoring Failures",
    "A10:2021": "Server-Side Request Forgery (SSRF)",
    "A01:2025": "Broken Access Control",
    "A02:2025": "Security Misconfiguration",
    "A03:2025": "Software Supply Chain Failures",
    "A04:2025": "Cryptographic Failures",
    "A05:2025": "Injection",
    "A06:2025": "Insecure Design",
    "A07:2025": "Authentication Failures",
    "A08:2025": "Software or Data Integrity Failures",
    "A09:2025": "Security Logging and Alerting Failures",
    "A10:2025": "Mishandling of Exceptional Conditions",
    "API1:2023": "Broken Object Level Authorization",
    "API2:2023": "Broken Authentication",
    "API3:2023": "Broken Object Property Level Authorization",
    "API4:2023": "Unrestricted Resource Consumption",
    "API5:2023": "Broken Function Level Authorization",
    "API6:2023": "Unrestricted Access to Sensitive Business Flows",
    "API7:2023": "Server Side Request Forgery",
    "API8:2023": "Security Misconfiguration",
    "API9:2023": "Improper Inventory Management",
    "API10:2023": "Unsafe Consumption of APIs",
}


def owasp_list(owasp_id):
    """Which list an OWASP id belongs to: '2021', '2025' or 'API2023'."""
    return "API2023" if owasp_id.startswith("API") else owasp_id.split(":")[1]


def owasp_match(check, query):
    """True when the check maps to the OWASP category `query`: a full id ('A03:2021', 'API1:2023') or a bare
    one ('A03', 'API1'), which matches that number in every list it appears in (A03 is Injection in 2021 and
    Software Supply Chain Failures in 2025)."""
    q = query.strip().upper()
    return any(o.upper() == q or o.split(":")[0].upper() == q for o in check.owasp)


def owasp_query_valid(query):
    q = query.strip().upper()
    return any(o.upper() == q or o.split(":")[0].upper() == q for o in OWASP)


class CatalogError(ValueError):
    pass


@dataclass(frozen=True)
class Source:
    title: str
    url: str


@dataclass(frozen=True)
class Check:
    id: str
    area: str
    title: str
    severity: str
    layer: int
    cwe: tuple[str, ...]
    risk: str
    build: str
    proof: str
    mode: str
    stacks: tuple[str, ...]
    sources: tuple[Source, ...]
    asvs: tuple[str, ...] = field(default=())
    probe: str = "passive"
    owasp: tuple[str, ...] = field(default=())

    def to_dict(self):
        return {
            "id": self.id, "area": self.area, "title": self.title, "severity": self.severity,
            "osi_layer": self.layer, "cwe": list(self.cwe), "asvs": list(self.asvs), "mode": self.mode,
            "stacks": list(self.stacks), "probe": self.probe, "owasp": list(self.owasp), "risk": self.risk, "build": self.build, "proof": self.proof,
            "sources": [{"title": s.title, "url": s.url} for s in self.sources],
        }


def _parse(area, raw):
    missing = [k for k in REQUIRED if k not in raw]
    where = f"{area}:{raw.get('id', '?')}"
    if missing:
        raise CatalogError(f"{where} is missing {', '.join(missing)}")
    extra = sorted(set(raw) - set(ALLOWED))
    if extra:
        raise CatalogError(f"{where}: unknown keys {', '.join(extra)}")
    if not raw["stacks"] or any(st not in STACKS for st in raw["stacks"]):
        raise CatalogError(f"{where}: stacks must be a non-empty list drawn from {STACKS}")
    if not ID_RE.match(raw["id"]):
        raise CatalogError(f"{where}: bad id")
    if raw["severity"] not in SEVERITIES:
        raise CatalogError(f"{where}: severity must be one of {SEVERITIES}")
    if raw.get("probe", "passive") not in PROBES:
        raise CatalogError(f"{where}: probe must be one of {PROBES}")
    if raw["mode"] not in MODES:
        raise CatalogError(f"{where}: mode must be one of {MODES}")
    if not isinstance(raw["layer"], int) or not 1 <= raw["layer"] <= 7:
        raise CatalogError(f"{where}: layer must be an OSI layer 1-7")
    # An empty list is allowed for process checks (security.txt, backups) that no CWE describes.
    if not isinstance(raw["cwe"], list) or not all(CWE_RE.match(c) for c in raw["cwe"]):
        raise CatalogError(f"{where}: cwe must be a list like ['CWE-79'] (empty when no CWE fits)")
    owasp = raw.get("owasp", [])
    if not isinstance(owasp, list) or any(o not in OWASP for o in owasp) or len(set(owasp)) != len(owasp):
        raise CatalogError(f"{where}: owasp must be a list of distinct ids from {', '.join(OWASP)}")
    for key in ("title", "risk", "build", "proof"):
        if not str(raw[key]).strip():
            raise CatalogError(f"{where}: {key} is empty")
    sources = raw["sources"]
    if not sources:
        raise CatalogError(f"{where}: at least one source is required")
    for s in sources:
        if not s.get("title") or not str(s.get("url", "")).startswith("https://"):
            raise CatalogError(f"{where}: every source needs a title and an https url")
    return Check(
        id=raw["id"], area=area, title=raw["title"].strip(), severity=raw["severity"], layer=raw["layer"],
        cwe=tuple(raw["cwe"]), risk=raw["risk"].strip(), build=raw["build"].strip(), proof=raw["proof"].strip(),
        mode=raw["mode"], stacks=tuple(raw["stacks"]), asvs=tuple(raw.get("asvs", ())), probe=raw.get("probe", "passive"),
        owasp=tuple(sorted(owasp, key=list(OWASP).index)), sources=tuple(Source(s["title"], s["url"]) for s in sources),
    )


@lru_cache(maxsize=1)
def load():
    """All checks, ordered by area file then by position. Raises CatalogError on any defect."""
    checks, seen = [], set()
    root = resources.files("agent_security_audit") / "catalog"
    for entry in sorted(root.iterdir(), key=lambda p: p.name):
        if not entry.name.endswith(".toml"):
            continue
        area = entry.name[:-5]
        data = tomllib.loads(entry.read_text(encoding="utf-8"))
        for raw in data.get("check", []):
            check = _parse(area, raw)
            if check.id in seen:
                raise CatalogError(f"duplicate id {check.id}")
            seen.add(check.id)
            checks.append(check)
    return tuple(checks)


def by_id():
    return {c.id: c for c in load()}


def find(check_id):
    try:
        return by_id()[check_id.upper()]
    except KeyError:
        raise CatalogError(f"no check {check_id!r}") from None
