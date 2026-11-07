"""Result types shared by checks, reports, the CLI and the MCP server."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

# pass: the defense was observed working.  fail: the flaw was observed.
# warn: a weaker setting that is not a proven flaw.  manual: needs a person, test accounts or the code.
# skip: does not apply to this target.  error: the check could not run (network, timeout).
STATUSES = ("pass", "fail", "warn", "manual", "skip", "error")


@dataclass
class Result:
    check_id: str
    status: str
    summary: str
    evidence: list[str] = field(default_factory=list)
    fix: str = ""
    # Source locations from the code audit: [{"path": "app/x.ts", "line": 3, "message": "..."}]. Empty for live checks.
    locations: list[dict] = field(default_factory=list)

    def __post_init__(self):
        if self.status not in STATUSES:
            raise ValueError(f"unknown status {self.status!r}")

    def to_dict(self):
        out = asdict(self)
        if not out["locations"]:
            del out["locations"]
        return out


def passed(check_id, summary, evidence=None):
    return Result(check_id, "pass", summary, list(evidence or []))


def failed(check_id, summary, evidence=None, fix=""):
    return Result(check_id, "fail", summary, list(evidence or []), fix)


def warned(check_id, summary, evidence=None, fix=""):
    return Result(check_id, "warn", summary, list(evidence or []), fix)


def skipped(check_id, summary):
    return Result(check_id, "skip", summary)


def errored(check_id, summary):
    return Result(check_id, "error", summary)
