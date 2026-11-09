"""Reports: JSON for tools, Markdown and HTML for people, SARIF for code scanning."""

from __future__ import annotations

import hashlib
import html
import json
import re
import textwrap
import unicodedata
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
# One word per status everywhere a person reads results, each with a short plain explanation.
STATUS_HELP = (
    ("fail", "a defense is missing; fix it"),
    ("warn", "weak or partial"),
    ("error", "the check could not run"),
    ("manual", "needs the code or a logged-in test"),
    ("pass", "observed working"),
    ("skip", "does not apply here, or an active probe was not allowed"),
)
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


def count_line(results):
    """'3 fail · 1 warn · 0 error · 12 manual · 20 pass · 4 skip': the status names, in report order."""
    c = counts(results)
    return " · ".join(f"{c[s]} {s}" for s, _ in STATUS_HELP)


def status_legend():
    return " · ".join(f"{s}: {why}" for s, why in STATUS_HELP)


def run_scope(*, interface, mode, flags, started=None, finished=None, hosts=(), requests_sent=None):
    """What a run did, for the report's audit trail: tool version, where it was started from (cli or mcp), mode
    (scan, code, or scan+code), the flags in effect, the hosts contacted, the requests sent and the start and end
    times (UTC)."""
    return {"tool": "agent-security-audit", "version": __version__, "interface": interface, "mode": mode,
            "flags": dict(flags), "hosts_contacted": sorted(set(hosts)), "requests_sent": requests_sent,
            "started": started, "finished": finished}


def _flag(value):
    if value is True:
        return "yes"
    if value is False:
        return "no"
    if value is None:
        return "-"
    if isinstance(value, (list, tuple)):
        return ",".join(map(str, value)) or "-"
    return str(value)


def scope_lines(scope):
    """(label, text) pairs describing a run's scope, shared by the Markdown and HTML reports."""
    flags = ", ".join(f"{k}={_flag(v)}" for k, v in scope.get("flags", {}).items())
    hosts = ", ".join(scope.get("hosts_contacted") or []) or "none"
    tool = (f"{scope.get('tool', 'agent-security-audit')} {scope.get('version', __version__)}, "
            f"run from {scope.get('interface', '-')}, mode {scope.get('mode', '-')}")
    lines = [("Tool", tool), ("Flags", flags or "-"), ("Hosts contacted", hosts)]
    if scope.get("requests_sent") is not None:
        lines.append(("Requests to the target", str(scope["requests_sent"])))
    lines.append(("Time (UTC)", f"started {scope.get('started') or '-'}, finished {scope.get('finished') or '-'}"))
    return lines


def to_json(target, results, scope=None):
    checks = catalog.by_id()
    extra = {"scope": scope} if scope else {}
    return json.dumps({
        "tool": "agent-security-audit", "version": __version__, "target": target, "generated": _now(), **extra,
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


BREAKS = ("Cc", "Zl", "Zp")       # control characters and Unicode line or paragraph separators: become one space
INVISIBLE = ("Cf", "Co", "Cs")    # format (zero-width, bidi overrides, tag characters), private use, surrogates


# Invisible code points outside those categories: variation selectors (Mn, the emoji smuggling channel), the
# combining grapheme joiner, Mongolian free variation selectors, and Hangul fillers (Lo) that render as blank.
HIDDEN = re.compile("[\u034f\u115f\u1160\u180b-\u180d\u180f\u3164\ufe00-\ufe0f\uffa0\U000e0100-\U000e01ef]")


def strip_invisible(text):
    """Text with every Cc, Zl and Zp character turned into a line break and every Cf, Co and Cs character (and the
    HIDDEN ones) dropped, so a value the target chose cannot hide or reorder text (bidi overrides, U+E0000 tags,
    zero-width, variation selectors, Hangul fillers)."""
    return "".join("\n" if cat in BREAKS else "" if cat in INVISIBLE else ch
                   for ch, cat in ((c, unicodedata.category(c)) for c in HIDDEN.sub("", str(text))))


def _clean(text, limit=MAX_TEXT):
    """Collapse control characters (line breaks included) to one space, drop invisible format characters, and cap
    the length. Summaries and evidence carry values the scanned site chose, so they must not be able to start new
    Markdown lines or hide text."""
    text = CONTROL.sub(" ", strip_invisible(text)).strip()
    return text if len(text) <= limit else text[:limit] + "..."


def _md_escape(text):
    """Plain text for a Markdown line or table cell: no line breaks, links, HTML, code spans or emphasis."""
    return MD_SPECIAL.sub(r"\\\1", _clean(text))


CODE_SPAN = re.compile(r"`([^`]+)`")


def _md_inline(text, table=False):
    """Like _md_escape, but a `backtick pair` becomes a Markdown code span. Text inside a span is literal in Markdown,
    so it needs no escaping. In a table cell a pipe ends the cell even inside a span, so a span holding a pipe or a
    backslash stays escaped plain text there."""
    text = _clean(text)
    out, pos = [], 0
    for m in CODE_SPAN.finditer(text):
        if table and ("|" in m.group(1) or "\\" in m.group(1)):
            continue
        out += [MD_SPECIAL.sub(r"\\\1", text[pos:m.start()]), m.group(0)]
        pos = m.end()
    out.append(MD_SPECIAL.sub(r"\\\1", text[pos:]))
    return "".join(out)


def _md_code(text):
    """A code span whose fence is longer than any backtick run in the text, so the text cannot close it early."""
    text = _clean(text)
    runs = [len(m) for m in re.findall(r"`+", text)]
    fence = "`" * (max(runs, default=0) + 1)
    pad = " " if text.startswith("`") or text.endswith("`") or not text else ""
    return f"{fence}{pad}{text}{pad}{fence}"


def to_markdown(target, results, scope=None):
    checks = catalog.by_id()
    lines = [
        f"# Security proof report: {target}",
        "",
        f"Generated {_now()} by agent-security-audit {__version__}.",
        "",
        f"**{count_line(results)}**",
        "",
        status_legend(),
        "",
        "## Fix these first",
        "",
    ]
    first = fix_first(results)
    lines += [f"{i}. **{chk.severity}** {r.check_id} {_md_escape(chk.title)}. Fix: {_md_inline(fix)}"
              for i, (r, chk, fix) in enumerate(first, 1)] or ["Nothing failed."]
    lines += ["", "## Coverage by OSI layer", "", "| Layer | Pass | Fail | Warn | Manual |", "|---|---|---|---|---|"]
    for n, row in layer_coverage(results).items():
        lines.append(f"| {n} {LAYERS[n]} | " + " | ".join(str(row[k]) for k in LAYER_COLUMNS) + " |")
    lines += ["", "## All results", "", "| Status | Severity | Check | Result |", "|---|---|---|---|"]
    for r in sort_results(results):
        chk = checks[r.check_id]
        lines.append(f"| {r.status} | {chk.severity} | {r.check_id} {_md_escape(chk.title)} | {_md_inline(r.summary, table=True)} |")
    details = [r for r in sort_results(results) if r.status in ("fail", "warn", "error")]
    if details:
        lines += ["", "## Details"]
        for r in details:
            chk = checks[r.check_id]
            lines += ["", f"### {r.check_id} {chk.title} ({r.status})", "", _md_inline(r.summary)]
            if r.evidence:
                lines += ["", "Evidence:", ""] + [f"- {_md_code(e)}" for e in r.evidence[:20]]
            fix = _md_inline(r.fix) if r.fix else chk.build
            lines += ["", f"Fix: {fix}"]
    if scope:
        lines += ["", "## Scope of this run", ""]
        lines += [f"- {label}: {_md_escape(text)}" for label, text in scope_lines(scope)]
    lines += ["", DISCLAIMER]
    return "\n".join(lines) + "\n"


C1_CONTROL = re.compile(r"[\x80-\x9f]+")


def _plain(text, limit=MAX_TEXT):
    """One line of terminal-safe text: C0 and C1 control characters (escape sequences included) removed."""
    return C1_CONTROL.sub(" ", _clean(text, limit))


def shorten(text, limit, more=""):
    """Plain text cut at a word boundary before limit characters, never mid-word, then ' ...' and `more` (say,
    where the rest is). Text that fits is returned whole."""
    text = _plain(text, max(limit * 4, MAX_TEXT))
    if len(text) <= limit:
        return text
    head = text[:limit + 1]
    cut = head[:head.rfind(" ")] if " " in head else text[:limit]
    return cut.rstrip(" ,;:") + " ..." + (f" {more}" if more else "")


def _wrap(text, width, indent):
    if not width:
        return [indent + text]
    return textwrap.wrap(text, width, initial_indent=indent, subsequent_indent=" " * len(indent),
                         break_long_words=False, break_on_hyphens=False) or [indent]


def _where(r):
    """'path:line' of a code finding's first location, plus how many more, or ''."""
    locs = [loc for loc in r.locations or [] if loc.get("path")]
    if not locs:
        return ""
    first = f"{_plain(str(locs[0]['path']), 200)}:{int(locs[0].get('line') or 1)}"
    return first + (f" (and {len(locs) - 1} more)" if len(locs) > 1 else "")


def summary_text(target, results, hint="", width=100, next_step=""):
    """A compact plain-text summary for a terminal or an agent: counts with what each status means, what to fix
    first (with file:line for code findings), the hint, then the next step for manual results. Lines wrap at word
    boundaries to width."""
    c = counts(results)
    lines = [f"asa: {_plain(target, 300)}", *_wrap(count_line(results), width, ""),
             *_wrap(status_legend(), width, "  "), ""]
    first = fix_first(results)
    if first:
        lines.append("Fix these first:")
        for i, (r, chk, fix) in enumerate(first, 1):
            lines += _wrap(f"[{chk.severity}] {r.check_id} {_plain(chk.title)}: {shorten(r.summary, 160)}", width,
                           f"{i:>2}. ")
            where = _where(r)
            if where:
                lines += _wrap(f"At: {where}", width, "    ")
            lines += _wrap(f"Fix: {shorten(fix, 200, f'(asa show {r.check_id})')}", width, "    ")
        more = c["fail"] - len(first)
        if more > 0:
            lines.append(f"    ...and {more} more failed checks in the full report.")
    else:
        lines.append("Nothing failed.")
    if hint:
        lines += ["", *_wrap(hint, width, "")]
    if next_step:  # last, so the next step is what the reader sees at the prompt
        lines += ["", *_wrap(next_step, width, "")]
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
code{background:var(--card);border-radius:4px;padding:0 .25rem;font-size:.85em;overflow-wrap:anywhere}
footer{margin-top:2rem;border-top:1px solid var(--line);padding-top:1rem}
@media print{:root{--bg:#fff;--fg:#000;--muted:#444;--line:#bbb;--card:#f2f2f2}body{max-width:none;padding:0}
h2{break-after:avoid}tr{break-inside:avoid}}
"""


def _h(text, limit=MAX_TEXT):
    return html.escape(_clean(text, limit), quote=True)


def _h_inline(text, limit=MAX_TEXT):
    """Escaped HTML in which a `backtick pair` becomes <code>. The span body is escaped before it is wrapped, and it
    cannot hold a backtick, so the markup it adds is always exactly <code> and </code>."""
    return CODE_SPAN.sub(r"<code>\1</code>", _h(text, limit))


def _status(status):
    return f'<span class="s s-{_h(status)}">{_h(status)}</span>'


def to_html(target, results, scope=None):
    """One self-contained page: inline CSS, no scripts, no external requests. Every value from the target is
    escaped, and a Content-Security-Policy forbids loading anything even if escaping were ever missed."""
    checks = catalog.by_id()
    c = counts(results)
    ordered = sort_results(results)
    out = ["<!doctype html>", '<html lang="en">', "<head>", '<meta charset="utf-8">',
           '<meta name="viewport" content="width=device-width, initial-scale=1">',
           "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\">",
           '<meta name="referrer" content="no-referrer">',
           f"<title>Security proof report: {_h(target)}</title>", f"<style>{HTML_CSS}</style>", "</head>", "<body>",
           f"<h1>Security proof report: {_h(target)}</h1>",
           f'<p class="muted">Generated {_h(_now())} by agent-security-audit {_h(__version__)}.</p>',
           '<ul class="counts">']
    out += [f'<li class="s-{k}" title="{_h(why)}"><b>{c[k]}</b>{k}</li>' for k, why in STATUS_HELP]
    out += ["</ul>", f'<p class="muted">{_h(status_legend())}</p>', "<h2>Fix these first</h2>"]
    first = fix_first(results)
    if first:
        out.append('<ol class="first">')
        for r, chk, fix in first:
            out.append(f"<li><b>{_h(chk.severity)}</b> {_h(r.check_id)} {_h(chk.title)}<br>"
                       f'<span class="muted">{_h_inline(r.summary)}</span><br>Fix: {_h_inline(fix)}</li>')
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
                   f'<td>{_h(r.check_id)} {_h(chk.title)}</td><td class="cell">{_h_inline(r.summary)}</td></tr>')
    out.append("</tbody></table></div>")
    details = [r for r in ordered if r.status in ("fail", "warn", "error")]
    if details:
        out.append("<h2>Details</h2>")
        for r in details:
            chk = checks[r.check_id]
            out += [f'<section class="item {_h(r.status)}">',
                    f"<h3>{_h(r.check_id)} {_h(chk.title)} ({_status(r.status)})</h3>", f"<p>{_h_inline(r.summary)}</p>"]
            if r.evidence:
                out.append("<p>Evidence:</p>")
                out += [f"<pre>{_h(e)}</pre>" for e in r.evidence[:20]]
            out += [f"<p>Fix: {_h_inline(r.fix or chk.build)}</p>", "</section>"]
    if scope:
        out += ["<h2>Scope of this run</h2>", "<ul>"]
        out += [f"<li><b>{_h(label)}:</b> {_h(text)}</li>" for label, text in scope_lines(scope)]
        out.append("</ul>")
    out += [f"<footer><p>{_h(DISCLAIMER)}</p></footer>", "</body>", "</html>"]
    return "\n".join(out) + "\n"


REPO = "https://github.com/talalkashar/agent-security-audit"
SECURITY_SEVERITY = {"critical": "9.5", "high": "7.5", "medium": "5.0", "low": "3.0"}


def _doc_anchor(chk):
    """The heading anchor GitHub gives "## <id> <title>" in docs/checks/<area>.md (same rule as scripts/gen_docs.py)."""
    text = f"{chk.id} {chk.title}".lower()
    return "".join(ch for ch in text if ch.isalnum() or ch in " -_").replace(" ", "-")


def _cwe_tags(cwe):
    """GitHub code scanning reads CWE ids from tags of the form external/cwe/cwe-079."""
    out = []
    for c in cwe:
        m = re.fullmatch(r"CWE-(\d+)", c)
        if m:
            out.append(f"external/cwe/cwe-{int(m.group(1)):03d}")
    return out


def _sarif_rule(chk):
    return {
        "id": chk.id, "name": chk.title, "shortDescription": {"text": _clean(chk.title)},
        "fullDescription": {"text": _clean(chk.risk)},
        "help": {"text": _clean(chk.build, 4000),
                 "markdown": f"**Fix:** {chk.build}\n\n**How it is proven:**\n\n{chk.proof}"},
        "helpUri": f"{REPO}/blob/main/docs/checks/{chk.area}.md#{_doc_anchor(chk)}",
        "properties": {"tags": ["security", *chk.cwe, *_cwe_tags(chk.cwe)], "precision": "high",
                       "security-severity": SECURITY_SEVERITY[chk.severity]},
        "defaultConfiguration": {"level": SARIF_LEVEL[chk.severity]},
    }


def _fingerprint(*parts):
    return {"asaFinding/v1": hashlib.sha256("|".join(map(str, parts)).encode()).hexdigest()[:32]}


def _sarif_time(value):
    return value.replace("+00:00", "Z") if isinstance(value, str) else None


def to_sarif(target, results, scope=None):
    """SARIF 2.1.0 for GitHub code scanning: one rule per check that ran, one result per failed or warned check
    (or per source location for the code audit). Valid against the OASIS schema; see tests/test_report.py."""
    checks = catalog.by_id()
    used = sorted({r.check_id for r in results})
    index = {cid: i for i, cid in enumerate(used)}
    rules = [_sarif_rule(checks[cid]) for cid in used]
    sarif_results = []
    for r in sort_results(results):
        if r.status not in ("fail", "warn"):
            continue
        chk = checks[r.check_id]
        level = SARIF_LEVEL[chk.severity] if r.status == "fail" else "note"
        base = {"ruleId": r.check_id, "ruleIndex": index[r.check_id], "level": level}
        if not r.locations:
            sarif_results.append({**base, "message": {"text": _clean(r.summary) or chk.title},
                                  "locations": [{"physicalLocation": {"artifactLocation": {"uri": target}}}],
                                  "partialFingerprints": _fingerprint(r.check_id, target)})
        # Code audit results: one SARIF result per source location, relative to the project root.
        for loc in r.locations:
            line = max(1, int(loc.get("line") or 1))
            uri = quote(str(loc["path"]))
            sarif_results.append({
                **base, "message": {"text": _clean(f"{loc.get('message') or r.summary}. {r.summary}")},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": uri, "uriBaseId": "%SRCROOT%"}, "region": {"startLine": line}}}],
                "partialFingerprints": _fingerprint(r.check_id, uri, line, _clean(loc.get("message") or "")),
            })
    run = {"tool": {"driver": {"name": "agent-security-audit", "version": __version__,
                               "semanticVersion": __version__, "informationUri": REPO, "rules": rules}},
           "results": sarif_results}
    if scope:
        invocation = {"executionSuccessful": True, "properties": {"scope": scope}}
        for key, field in (("startTimeUtc", "started"), ("endTimeUtc", "finished")):
            if _sarif_time(scope.get(field)):
                invocation[key] = _sarif_time(scope[field])
        run["invocations"] = [invocation]
    return json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0", "runs": [run],
    }, indent=2)
