"""Reports: JSON for tools, Markdown for people, SARIF for code scanning."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from urllib.parse import quote

from . import __version__, catalog

ORDER = {"fail": 0, "error": 1, "warn": 2, "manual": 3, "pass": 4, "skip": 5}
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}


def _now():
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def counts(results):
    out = {s: 0 for s in ORDER}
    for r in results:
        out[r.status] += 1
    return out


def sort_results(results):
    checks = catalog.by_id()
    return sorted(results, key=lambda r: (ORDER[r.status], SEV_ORDER[checks[r.check_id].severity], r.check_id))


def to_json(target, results):
    checks = catalog.by_id()
    return json.dumps({
        "tool": "agent-security-audit", "version": __version__, "target": target, "generated": _now(),
        "counts": counts(results),
        "results": [
            {**r.to_dict(), "title": checks[r.check_id].title, "severity": checks[r.check_id].severity,
             "osi_layer": checks[r.check_id].layer, "cwe": list(checks[r.check_id].cwe)}
            for r in sort_results(results)
        ],
    }, indent=2)


CONTROL = re.compile(r"[\x00-\x1f\x7f]+")
MD_SPECIAL = re.compile(r"([\\`*_\[\]<>#|!])")
MAX_TEXT = 1000


def _clean(text, limit=MAX_TEXT):
    """Collapse control characters (line breaks included) to one space and cap the length. Summaries and evidence
    carry values the scanned site chose, so they must not be able to start new Markdown lines."""
    text = CONTROL.sub(" ", str(text)).strip()
    return text if len(text) <= limit else text[:limit] + "..."


def _md_escape(text):
    """Plain text for a Markdown line or table cell: no line breaks, links, HTML, code spans or emphasis."""
    return MD_SPECIAL.sub(r"\\\1", _clean(text))


def _md_code(text):
    """A code span whose fence is longer than any backtick run in the text, so the text cannot close it early."""
    text = _clean(text)
    runs = [len(m) for m in re.findall(r"`+", text)]
    fence = "`" * (max(runs, default=0) + 1)
    pad = " " if text.startswith("`") or text.endswith("`") or not text else ""
    return f"{fence}{pad}{text}{pad}{fence}"


def to_markdown(target, results):
    checks = catalog.by_id()
    c = counts(results)
    lines = [
        f"# Security proof report: {target}",
        "",
        f"Generated {_now()} by agent-security-audit {__version__}.",
        "",
        (f"**{c['fail']} failed · {c['warn']} warnings · {c['error']} could not run · {c['manual']} to check in code "
        f"· {c['pass']} passed · {c['skip']} not applicable**"),
        "",
        "| Status | Severity | Check | Result |",
        "|---|---|---|---|",
    ]
    for r in sort_results(results):
        chk = checks[r.check_id]
        lines.append(f"| {r.status} | {chk.severity} | {r.check_id} {_md_escape(chk.title)} | {_md_escape(r.summary)} |")
    details = [r for r in sort_results(results) if r.status in ("fail", "warn", "error")]
    if details:
        lines += ["", "## Details"]
        for r in details:
            chk = checks[r.check_id]
            lines += ["", f"### {r.check_id} {chk.title} ({r.status})", "", _md_escape(r.summary)]
            if r.evidence:
                lines += ["", "Evidence:", ""] + [f"- {_md_code(e)}" for e in r.evidence[:20]]
            fix = _md_escape(r.fix) if r.fix else chk.build
            lines += ["", f"Fix: {fix}"]
    lines += ["", ("A pass means the defense was observed working on this target at this time. It is not a guarantee "
              "that the site has no other flaws.")]
    return "\n".join(lines) + "\n"


def to_sarif(target, results):
    checks = catalog.by_id()
    used = sorted({r.check_id for r in results})
    rules = []
    for cid in used:
        chk = checks[cid]
        rules.append({
            "id": cid, "name": chk.title, "shortDescription": {"text": chk.title},
            "fullDescription": {"text": chk.risk}, "help": {"text": chk.build},
            "properties": {"tags": ["security", *chk.cwe], "security-severity": {
                "critical": "9.5", "high": "7.5", "medium": "5.0", "low": "3.0"}[chk.severity]},
            "defaultConfiguration": {"level": SARIF_LEVEL[chk.severity]},
        })
    sarif_results = []
    for r in sort_results(results):
        if r.status not in ("fail", "warn"):
            continue
        chk = checks[r.check_id]
        level = SARIF_LEVEL[chk.severity] if r.status == "fail" else "note"
        if not r.locations:
            sarif_results.append({"ruleId": r.check_id, "level": level, "message": {"text": r.summary},
                                  "locations": [{"physicalLocation": {"artifactLocation": {"uri": target}}}]})
        # Code audit results: one SARIF result per source location, relative to the project root.
        for loc in r.locations:
            sarif_results.append({
                "ruleId": r.check_id, "level": level,
                "message": {"text": _clean(f"{loc.get('message') or r.summary}. {r.summary}")},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": quote(str(loc["path"])), "uriBaseId": "%SRCROOT%"},
                    "region": {"startLine": max(1, int(loc.get("line") or 1))}}}],
            })
    return json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "agent-security-audit", "version": __version__,
                                      "informationUri": "https://github.com/talalkashar/agent-security-audit",
                                      "rules": rules}},
                  "results": sarif_results}],
    }, indent=2)
