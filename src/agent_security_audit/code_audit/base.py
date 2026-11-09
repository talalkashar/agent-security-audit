"""Shared helpers for the code analyzers."""

from __future__ import annotations

from ..findings import location_ids
from ..model import Result

MAX_EVIDENCE = 25
MAX_LOCATIONS = 50
SUSPECTED = "Suspected, from a static read of the code: "


def make(check_id, status, summary, findings=(), evidence=(), fix=""):
    """A Result whose evidence lists each finding as path:line and whose locations feed SARIF."""
    findings = list(findings)
    ev = [f.evidence() for f in findings[:MAX_EVIDENCE]]
    if len(findings) > MAX_EVIDENCE:
        ev.append(f"... and {len(findings) - MAX_EVIDENCE} more")
    ev += list(evidence)
    kept = findings[:MAX_LOCATIONS]
    locations = [f.location() for f in kept]
    # The id hashes what was matched (the snippet), not the message, whose wording can change between versions.
    for loc, fid in zip(locations, location_ids(check_id, locations, [f.snippet or f.note for f in kept])):
        loc["finding_id"] = fid
    return Result(check_id, status, summary, ev, fix, locations)


def plural(n, word):
    if n == 1:
        return f"{n} {word}"
    if word.endswith("y") and word[-2:-1] not in "aeiou":
        return f"{n} {word[:-1]}ies"
    return f"{n} {word}s"
