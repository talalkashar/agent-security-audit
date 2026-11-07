"""Reports: JSON for tools, Markdown and HTML for people, SARIF for code scanning."""

from __future__ import annotations

import html
import json
import re
from datetime import UTC, datetime
from urllib.parse import quote

from . import __version__, catalog

ORDER = {"fail": 0, "error": 1, "warn": 2, "manual": 3, "pass": 4, "skip": 5}
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
LAYERS = {1: "Physical", 2: "Data link", 3: "Network", 4: "Transport", 5: "Session", 6: "Presentation",
          7: "Application"}
LAYER_COLUMNS = ("pass", "fail", "warn", "manual")
FIX_FIRST_MAX = 10
DISCLAIMER = ("A pass means the defense was observed working on this target at this time. It is not a guarantee "
              "that the site has no other flaws.")


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


def fix_first(results, limit=FIX_FIRST_MAX):
    """Failed checks, most severe first, each paired with its check and the fix to apply."""
    checks = catalog.by_id()
    fails = [r for r in sort_results(results) if r.status == "fail"][:limit]
    return [(r, checks[r.check_id], r.fix or checks[r.check_id].build) for r in fails]


def layer_coverage(results):
    """{layer: {status: count}} for OSI layers 1-7, layer taken from the catalog. Every layer is present, so a
    layer with no checks shows as zeros instead of disappearing."""
    checks = catalog.by_id()
    out = {n: dict.fromkeys(LAYER_COLUMNS, 0) for n in LAYERS}
    for r in results:
        row = out[checks[r.check_id].layer]
        if r.status in row:
            row[r.status] += 1
    return out


def to_json(target, results):
    checks = catalog.by_id()
    return json.dumps({
        "tool": "agent-security-audit", "version": __version__, "target": target, "generated": _now(),
        "counts": counts(results),
        "fix_first": [{"check_id": r.check_id, "severity": chk.severity, "title": chk.title, "fix": fix}
                      for r, chk, fix in fix_first(results)],
        "osi_layers": {str(n): row for n, row in layer_coverage(results).items()},
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
        "## Fix these first",
        "",
    ]
    first = fix_first(results)
    lines += [f"{i}. **{chk.severity}** {r.check_id} {_md_escape(chk.title)}. Fix: {_md_escape(fix)}"
              for i, (r, chk, fix) in enumerate(first, 1)] or ["Nothing failed."]
    lines += ["", "## Coverage by OSI layer", "", "| Layer | Pass | Fail | Warn | Manual |", "|---|---|---|---|---|"]
    for n, row in layer_coverage(results).items():
        lines.append(f"| {n} {LAYERS[n]} | " + " | ".join(str(row[k]) for k in LAYER_COLUMNS) + " |")
    lines += ["", "## All results", "", "| Status | Severity | Check | Result |", "|---|---|---|---|"]
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
    lines += ["", DISCLAIMER]
    return "\n".join(lines) + "\n"


C1_CONTROL = re.compile(r"[\x80-\x9f]+")


def _plain(text, limit=MAX_TEXT):
    """One line of terminal-safe text: C0 and C1 control characters (escape sequences included) removed."""
    return C1_CONTROL.sub(" ", _clean(text, limit))


def summary_text(target, results, hint=""):
    """A compact plain-text summary for a terminal or an agent: counts, then what to fix first."""
    c = counts(results)
    lines = [f"asa: {target}",
             (f"{c['fail']} failed · {c['warn']} warnings · {c['error']} could not run · {c['manual']} to check in "
              f"code · {c['pass']} passed · {c['skip']} not applicable"), ""]
    first = fix_first(results)
    if first:
        lines.append("Fix these first:")
        for i, (r, chk, fix) in enumerate(first, 1):
            lines += [f"{i:>2}. [{chk.severity}] {r.check_id} {_plain(chk.title)}: {_plain(r.summary, 160)}",
                      f"    Fix: {_plain(fix, 200)}"]
        more = c["fail"] - len(first)
        if more > 0:
            lines.append(f"    ...and {more} more failed checks in the full report.")
    else:
        lines.append("Nothing failed.")
    if hint:
        lines += ["", hint]
    return "\n".join(lines) + "\n"


HTML_CSS = """
:root{--bg:#fff;--fg:#1b1f24;--muted:#57606a;--line:#d0d7de;--card:#f6f8fa;--fail:#cf222e;--warn:#9a6700;
--pass:#1a7f37;--manual:#0969da;--other:#6e7781}
@media (prefers-color-scheme:dark){:root{--bg:#0d1117;--fg:#e6edf3;--muted:#8d96a0;--line:#30363d;--card:#161b22;
--fail:#ff7b72;--warn:#d29922;--pass:#3fb950;--manual:#58a6ff;--other:#8b949e}}
*{box-sizing:border-box}
body{margin:0 auto;max-width:72rem;padding:1.5rem 1rem 3rem;background:var(--bg);color:var(--fg);
font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
h1{font-size:1.5rem;margin:0 0 .25rem;overflow-wrap:anywhere}h2{font-size:1.15rem;margin:2rem 0 .5rem}
h3{font-size:1rem;margin:0 0 .25rem}.muted{color:var(--muted)}
.counts{display:flex;flex-wrap:wrap;gap:.5rem;padding:0;margin:1rem 0;list-style:none}
.counts li{background:var(--card);border:1px solid var(--line);border-radius:6px;padding:.4rem .75rem}
.counts b{font-size:1.2rem;margin-right:.25rem}
table{border-collapse:collapse;width:100%;font-size:.9rem}
th,td{border-bottom:1px solid var(--line);padding:.4rem .5rem;text-align:left;vertical-align:top}
th{background:var(--card)}td.n{text-align:right;font-variant-numeric:tabular-nums}
.wrap{overflow-x:auto}.cell{overflow-wrap:anywhere}
.s{font-weight:600;text-transform:uppercase;font-size:.75rem;letter-spacing:.03em}
.s-fail{color:var(--fail)}.s-warn{color:var(--warn)}.s-pass{color:var(--pass)}.s-manual{color:var(--manual)}
.s-error,.s-skip{color:var(--other)}
ol.first{padding-left:1.5rem}ol.first li{margin:.5rem 0}
.item{border:1px solid var(--line);border-left:4px solid var(--other);border-radius:6px;padding:.75rem 1rem;
margin:.75rem 0;break-inside:avoid}
.item.fail{border-left-color:var(--fail)}.item.warn{border-left-color:var(--warn)}
pre{background:var(--card);border-radius:4px;padding:.5rem;margin:.25rem 0;white-space:pre-wrap;
overflow-wrap:anywhere;font-size:.8rem}
footer{margin-top:2rem;border-top:1px solid var(--line);padding-top:1rem}
@media print{:root{--bg:#fff;--fg:#000;--muted:#444;--line:#bbb;--card:#f2f2f2}body{max-width:none;padding:0}
h2{break-after:avoid}tr{break-inside:avoid}}
"""


def _h(text, limit=MAX_TEXT):
    return html.escape(_clean(text, limit), quote=True)


def _status(status):
    return f'<span class="s s-{_h(status)}">{_h(status)}</span>'


def to_html(target, results):
    """One self-contained page: inline CSS, no scripts, no external requests. Every value from the target is
    escaped, and a Content-Security-Policy forbids loading anything even if escaping were ever missed."""
    checks = catalog.by_id()
    c = counts(results)
    ordered = sort_results(results)
    labels = (("fail", "failed"), ("warn", "warnings"), ("error", "could not run"), ("manual", "to check in code"),
              ("pass", "passed"), ("skip", "not applicable"))
    out = ["<!doctype html>", '<html lang="en">', "<head>", '<meta charset="utf-8">',
           '<meta name="viewport" content="width=device-width, initial-scale=1">',
           "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\">",
           '<meta name="referrer" content="no-referrer">',
           f"<title>Security proof report: {_h(target)}</title>", f"<style>{HTML_CSS}</style>", "</head>", "<body>",
           f"<h1>Security proof report: {_h(target)}</h1>",
           f'<p class="muted">Generated {_h(_now())} by agent-security-audit {_h(__version__)}.</p>',
           '<ul class="counts">']
    out += [f'<li class="s-{k}"><b>{c[k]}</b>{label}</li>' for k, label in labels]
    out += ["</ul>", "<h2>Fix these first</h2>"]
    first = fix_first(results)
    if first:
        out.append('<ol class="first">')
        for r, chk, fix in first:
            out.append(f"<li><b>{_h(chk.severity)}</b> {_h(r.check_id)} {_h(chk.title)}<br>"
                       f'<span class="muted">{_h(r.summary)}</span><br>Fix: {_h(fix)}</li>')
        out.append("</ol>")
    else:
        out.append("<p>Nothing failed.</p>")
    out += ["<h2>Coverage by OSI layer</h2>", '<div class="wrap"><table>',
            "<thead><tr><th>Layer</th><th>Pass</th><th>Fail</th><th>Warn</th><th>Manual</th></tr></thead><tbody>"]
    for n, row in layer_coverage(results).items():
        out.append(f"<tr><td>{n} {LAYERS[n]}</td>" + "".join(f'<td class="n">{row[k]}</td>' for k in LAYER_COLUMNS)
                   + "</tr>")
    out += ["</tbody></table></div>", "<h2>All results</h2>", '<div class="wrap"><table>',
            "<thead><tr><th>Status</th><th>Severity</th><th>Layer</th><th>Check</th><th>Result</th></tr></thead>",
            "<tbody>"]
    for r in ordered:
        chk = checks[r.check_id]
        out.append(f"<tr><td>{_status(r.status)}</td><td>{_h(chk.severity)}</td><td>{chk.layer}</td>"
                   f'<td>{_h(r.check_id)} {_h(chk.title)}</td><td class="cell">{_h(r.summary)}</td></tr>')
    out.append("</tbody></table></div>")
    details = [r for r in ordered if r.status in ("fail", "warn", "error")]
    if details:
        out.append("<h2>Details</h2>")
        for r in details:
            chk = checks[r.check_id]
            out += [f'<section class="item {_h(r.status)}">',
                    f"<h3>{_h(r.check_id)} {_h(chk.title)} ({_status(r.status)})</h3>", f"<p>{_h(r.summary)}</p>"]
            if r.evidence:
                out.append("<p>Evidence:</p>")
                out += [f"<pre>{_h(e)}</pre>" for e in r.evidence[:20]]
            out += [f"<p>Fix: {_h(r.fix or chk.build)}</p>", "</section>"]
    out += [f"<footer><p>{_h(DISCLAIMER)}</p></footer>", "</body>", "</html>"]
    return "\n".join(out) + "\n"


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
