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
ALLOWED = (*REQUIRED, "asvs", "probe")
PROBES = ("passive", "active")
STACKS = ("any", "nextjs", "supabase", "vercel", "node")


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

    def to_dict(self):
        return {
            "id": self.id, "area": self.area, "title": self.title, "severity": self.severity,
            "osi_layer": self.layer, "cwe": list(self.cwe), "asvs": list(self.asvs), "mode": self.mode,
            "stacks": list(self.stacks), "probe": self.probe, "risk": self.risk, "build": self.build, "proof": self.proof,
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
        sources=tuple(Source(s["title"], s["url"]) for s in sources),
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
