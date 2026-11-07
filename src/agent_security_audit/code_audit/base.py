"""Shared helpers for the code analyzers."""

from __future__ import annotations

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
    return Result(check_id, status, summary, ev, fix, [f.location() for f in findings[:MAX_LOCATIONS]])


def plural(n, word):
    if n == 1:
        return f"{n} {word}"
    if word.endswith("y") and word[-2:-1] not in "aeiou":
        return f"{n} {word[:-1]}ies"
    return f"{n} {word}s"
