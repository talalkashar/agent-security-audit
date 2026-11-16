"""Reports: JSON for tools, Markdown and HTML for people, SARIF for code scanning, JUnit XML for CI test screens and
JSON Lines for log pipelines."""

from __future__ import annotations

import hashlib
import html
import json
import re
import textwrap
import unicodedata
import xml.etree.ElementTree as ET
from datetime import UTC, datetime
from urllib.parse import quote, urlsplit

from . import __version__, catalog, findings

ORDER = {"fail": 0, "error": 1, "warn": 2, "manual": 3, "pass": 4, "skip": 5}
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
LAYERS = {1: "Physical", 2: "Data link", 3: "Network", 4: "Transport", 5: "Session", 6: "Presentation",
          7: "Application"}
LAYER_COLUMNS = ("pass", "fail", "warn", "manual")
FIX_FIRST_MAX = 10
# Major version of the JSON report layout. `asa diff` refuses a report with a major it does not know.
REPORT_SCHEMA = 1
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


def run_scope(*, interface, mode, flags, started=None, finished=None, hosts=(), requests_sent=None, pacing=None):
    """What a run did, for the report's audit trail: tool version, where it was started from (cli or mcp), mode
    (scan, code, or scan+code), the flags in effect, the hosts contacted, the requests sent and the start and end
    times (UTC). pacing, for a scan: the rate it started and ended at, how often the target slowed it (429 or
    Retry-After) and how many requests --exclude-path kept back."""
    out = {"tool": "agent-security-audit", "version": __version__, "interface": interface, "mode": mode,
           "flags": dict(flags), "hosts_contacted": sorted(set(hosts)), "requests_sent": requests_sent,
           "started": started, "finished": finished}
    if pacing:
        out["pacing"] = dict(pacing)
    return out


def _rate_text(value):
    return f"{value:g}" if isinstance(value, (int, float)) and not isinstance(value, bool) else _flag(value)


def _pacing_lines(scope):
    """The rate and the --exclude-path patterns, as scope lines. Patterns are shown cleaned and capped."""
    flags, pace = scope.get("flags", {}), scope.get("pacing") or {}
    lines = []
    if "rate" in flags or pace:
        text = f"{_rate_text(pace.get('rate') or flags.get('rate'))} requests/s"
        if pace.get("slowed"):
            text += (f"; the target asked to slow down {pace['slowed']} time{'s' if pace['slowed'] != 1 else ''} "
                     f"(429 or Retry-After), so it ended at {_rate_text(pace.get('final_rate'))} requests/s")
        lines.append(("Rate", text))
    if flags.get("exclude_path"):
        text = ", ".join(f'"{_plain(p, 200)}"' for p in flags["exclude_path"])  # as given: repr() doubles backslashes
        if pace.get("excluded_not_sent"):
            n = pace["excluded_not_sent"]
            text += f"; {n} path{'s' if n != 1 else ''} not requested"
        lines.append(("Excluded paths", text))
    return lines


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
    flags = ", ".join(f"{k}={_flag(v)}" for k, v in scope.get("flags", {}).items()
                      if k not in ("rate", "exclude_path"))  # each has its own line below
    hosts = ", ".join(scope.get("hosts_contacted") or []) or "none"
    tool = (f"{scope.get('tool', 'agent-security-audit')} {scope.get('version', __version__)}, "
            f"run from {scope.get('interface', '-')}, mode {scope.get('mode', '-')}")
    lines = [("Tool", tool), ("Flags", flags or "-"), ("Hosts contacted", hosts)]
    if scope.get("requests_sent") is not None:
        lines.append(("Requests to the target", str(scope["requests_sent"])))
    lines += _pacing_lines(scope)
    lines.append(("Time (UTC)", f"started {scope.get('started') or '-'}, finished {scope.get('finished') or '-'}"))
    return lines


def to_json(target, results, scope=None):
    checks = catalog.by_id()
    extra = {"scope": scope} if scope else {}
    return json.dumps({
        "tool": "agent-security-audit", "report_schema": REPORT_SCHEMA, "version": __version__, "target": target,
        "generated": _now(), **extra,
        "counts": counts(results),
        "fix_first": [{"check_id": r.check_id, "severity": chk.severity, "title": chk.title, "fix": fix}
                      for r, chk, fix in fix_first(results)],
        "osi_layers": {str(n): row for n, row in layer_coverage(results).items()},
        "results": [
            {**findings.annotate(r.to_dict(), target)[0], "title": checks[r.check_id].title,
             "severity": checks[r.check_id].severity, "osi_layer": checks[r.check_id].layer,
             "cwe": list(checks[r.check_id].cwe)}
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
        f"# Security proof report: {_md_escape(target)}",  # a code target is a folder name, which can hold Markdown
        "",
        f"Generated {_now()} by agent-security-audit {__version__}.",
        "",
        f"**{count_line(results)}**",
        "",
        "| Status | Meaning |",
        "|---|---|",
        *[f"| `{status}` | {why} |" for status, why in STATUS_HELP],
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
    # Both can name the target (a URL, or a folder name that can hold escape sequences): plain text only.
    if hint:
        lines += ["", *_wrap(_plain(hint, 600), width, "")]
    if next_step:  # last, so the next step is what the reader sees at the prompt
        lines += ["", *_wrap(_plain(next_step, 600), width, "")]
    return "\n".join(lines) + "\n"


HTML_CSS = """
:root{color-scheme:light dark;--bg:#f7f8fa;--fg:#17212f;--muted:#536171;--line:#d9dfe6;--card:#fff;
--subtle:#eef1f5;--fail:#b42332;--warn:#855600;--pass:#15733b;--manual:#145fc0;--other:#536171}
@media (prefers-color-scheme:dark){:root{--bg:#10151c;--fg:#edf2f7;--muted:#a6b3c3;--line:#343f4c;--card:#181f29;
--subtle:#232d3a;--fail:#ff989d;--warn:#e8bd65;--pass:#73d69b;--manual:#89b9ff;--other:#a6b3c3}}
*{box-sizing:border-box}
body{margin:0 auto;max-width:72rem;padding:2.5rem 2rem 3rem;background:var(--bg);color:var(--fg);
font:15px/1.6 system-ui,-apple-system,"Segoe UI",sans-serif;overflow-wrap:anywhere}
.masthead{display:flex;align-items:center;justify-content:space-between;gap:1rem;padding-bottom:1.25rem;
border-bottom:1px solid var(--line);font-size:.8rem;color:var(--muted)}
.brand{color:var(--fg);font-weight:650}.brand b{display:inline-block;background:var(--fg);color:var(--bg);
padding:.1rem .45rem;border-radius:4px;margin-right:.5rem;font:600 1rem/1.5 ui-monospace,monospace}
header{padding:2rem 0 .5rem}h1{font-size:2.5rem;line-height:1.15;letter-spacing:-.04em;margin:0 0 1rem}
.target{margin:0 0 .5rem;font-size:.95rem}.target code{background:var(--subtle);padding:.25rem .5rem}
header .muted{font-size:.8rem}h2{font-size:1.25rem;letter-spacing:-.02em;margin:2.5rem 0 .25rem}
h3{font-size:1rem;line-height:1.5;margin:.65rem 0 .35rem}p{margin:.5rem 0 1rem}.muted{color:var(--muted)}
.counts{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));padding:0;margin:1rem 0 0;list-style:none;
background:var(--card);border:1px solid var(--line);border-radius:8px;overflow:hidden}
.counts li{padding:1rem;border-right:1px solid var(--line)}.counts li:last-child{border:0}
.counts b{display:block;font-size:2rem;line-height:1.2;letter-spacing:-.04em;font-variant-numeric:tabular-nums}
.count-label{font-weight:600;font-size:.85rem}.count-help{display:block;color:var(--muted);font-size:.7rem;
line-height:1.5;margin-top:.4rem}
table{border-collapse:collapse;width:100%;font-size:.85rem}
th,td{border-bottom:1px solid var(--line);padding:.75rem;text-align:left;vertical-align:top}
th{background:var(--subtle);font-weight:600}tbody tr:last-child td{border-bottom:0}
td.n{text-align:right;font-variant-numeric:tabular-nums}
.wrap{overflow-x:auto;background:var(--card);border:1px solid var(--line);border-radius:8px;margin-top:1rem}
.wrap:focus-visible,summary:focus-visible{outline:3px solid var(--manual);outline-offset:3px}
.results td:nth-child(4){min-width:14rem}.results td:last-child{width:46%}.cell{overflow-wrap:anywhere}
.s{font-weight:650;font-size:.75rem}
.s-fail{color:var(--fail)}.s-warn{color:var(--warn)}.s-pass{color:var(--pass)}.s-manual{color:var(--manual)}
.s-error,.s-skip{color:var(--other)}
ol.first{list-style:none;padding:0;margin:1rem 0;display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:1rem;
counter-reset:finding}ol.first>li{background:var(--card);border:1px solid var(--line);border-radius:8px;
padding:1.25rem;counter-increment:finding}ol.first>li::before{content:counter(finding,decimal-leading-zero);
float:right;color:var(--muted);font:12px/1.8 ui-monospace,monospace}
.finding-meta{display:flex;align-items:center;gap:.5rem;font-size:.75rem}
.severity{font-size:.7rem;font-weight:650;border:1px solid currentColor;border-radius:4px;padding:0 .4rem}
.severity-critical,.severity-high{color:var(--fail)}.severity-medium{color:var(--warn)}
.first p{font-size:.85rem;margin:.5rem 0 .75rem}.first details{border-top:1px solid var(--line);padding-top:.6rem}
summary{cursor:pointer;font-size:.8rem;font-weight:600;padding:.35rem 0}details[open] summary{margin-bottom:.5rem}
.item{background:var(--card);border:1px solid var(--line);border-left:3px solid var(--other);border-radius:8px;
padding:1rem 1.25rem;margin:.75rem 0;break-inside:avoid}
.item.fail{border-left-color:var(--fail)}.item.warn{border-left-color:var(--warn)}
pre{background:var(--subtle);border:1px solid var(--line);border-radius:4px;padding:.75rem;margin:.25rem 0;
white-space:pre-wrap;overflow-wrap:anywhere;font-size:.8rem}
code{background:var(--subtle);border-radius:3px;padding:.1rem .25rem;font:.85em/1.6 ui-monospace,SFMono-Regular,
Consolas,monospace;overflow-wrap:anywhere}.scope{padding-left:1.25rem;font-size:.85rem}.scope li{margin:.5rem 0}
footer{margin-top:2.5rem;border-top:1px solid var(--line);padding-top:1rem;font-size:.8rem;color:var(--muted)}
@media(max-width:640px){body{padding:1.25rem 1rem 2rem}.masthead{font-size:.65rem}.brand b{font-size:.85rem}
header{padding:1.5rem 0 .5rem}h1{font-size:2rem}.counts{grid-template-columns:repeat(3,minmax(0,1fr))}
.counts li{padding:.75rem;border-bottom:1px solid var(--line)}.counts li:nth-child(3){border-right:0}
.counts li:nth-child(n+4){border-bottom:0}.counts b{font-size:1.75rem}.count-help{font-size:.65rem}
ol.first{grid-template-columns:1fr}.first>li{padding:1rem}h2{margin-top:2rem}
.results thead{position:absolute;width:1px;height:1px;overflow:hidden;clip-path:inset(50%)}
.results,.results tbody,.results tr,.results td{display:block}.results tr{padding:.75rem;border-bottom:1px solid var(--line)}
.results tr:last-child{border:0}.results td{display:grid;grid-template-columns:4.5rem minmax(0,1fr);gap:.5rem;
border:0;padding:.2rem 0}.results td::before{content:attr(data-label);color:var(--muted);font-size:.75rem}
.results td:nth-child(4){min-width:0}.results td:last-child{width:auto}}
@media print{:root{color-scheme:light;--bg:#fff;--fg:#000;--muted:#444;--line:#bbb;--card:#fff;--subtle:#f2f2f2;
--fail:#8e1620;--warn:#704900;--pass:#145c31;--manual:#164e94;--other:#444}body{max-width:none;padding:0;font-size:11px}
h2{break-after:avoid}tr,ol.first>li{break-inside:avoid}ol.first{grid-template-columns:1fr}
details>summary{display:none}details::details-content{content-visibility:visible}details>*{display:block!important}}
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
           ('<div class="masthead"><span class="brand"><b>asa</b> agent-security-audit</span>'
            f'<span>Report / v{_h(__version__)}</span></div>'),
           '<main><header><h1>Security proof report</h1>',
           f'<p class="target"><code>{_h(target)}</code></p>',
           f'<p class="muted">Generated {_h(_now())} · Evidence from this run.</p></header>',
           '<ul class="counts" aria-label="Results by status">']
    out += [f'<li class="s-{k}"><b>{c[k]}</b><span class="count-label">{k}</span>'
            f'<span class="count-help">{_h(why)}</span></li>' for k, why in STATUS_HELP]
    out += ["</ul>", "<h2>Fix these first</h2>"]
    first = fix_first(results)
    if first:
        out.append(f'<p class="muted">{len(first)} of {c["fail"]} failed checks · Most severe first. '
                   'Expand a fix for the build rule.</p>')
        out.append('<ol class="first">')
        for r, chk, fix in first:
            out.append(f'<li><div class="finding-meta"><span class="severity severity-{_h(chk.severity)}">'
                       f'{_h(chk.severity)}</span><code>{_h(r.check_id)}</code></div>'
                       f'<h3>{_h(chk.title)}</h3><p>{_h_inline(r.summary)}</p>'
                       f'<details><summary>How to fix {_h(r.check_id)}</summary>'
                       f'<p>Fix: {_h_inline(fix)}</p></details></li>')
        out.append("</ol>")
    else:
        out.append("<p>Nothing failed.</p>")
    out += ["<h2>Coverage by OSI layer</h2>",
            '<div class="wrap" role="region" aria-label="Coverage by OSI layer" tabindex="0"><table>',
            "<thead><tr><th>Layer</th><th>Pass</th><th>Fail</th><th>Warn</th><th>Manual</th></tr></thead><tbody>"]
    for n, row in layer_coverage(results).items():
        out.append(f"<tr><td>{n} {LAYERS[n]}</td>" + "".join(f'<td class="n">{row[k]}</td>' for k in LAYER_COLUMNS)
                   + "</tr>")
    out += ["</tbody></table></div>", "<h2>All results</h2>",
            '<div class="wrap"><table class="results">',
            "<thead><tr><th>Status</th><th>Severity</th><th>Layer</th><th>Check</th><th>Result</th></tr></thead>",
            "<tbody>"]
    for r in ordered:
        chk = checks[r.check_id]
        out.append(f'<tr><td data-label="Status">{_status(r.status)}</td>'
                   f'<td data-label="Severity">{_h(chk.severity)}</td><td data-label="Layer">{chk.layer}</td>'
                   f'<td data-label="Check">{_h(r.check_id)} {_h(chk.title)}</td>'
                   f'<td data-label="Result" class="cell"><span>{_h_inline(r.summary)}</span></td></tr>')
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
        out += ["<h2>Scope of this run</h2>", '<ul class="scope">']
        out += [f"<li><b>{_h(label)}:</b> {_h(text)}</li>" for label, text in scope_lines(scope)]
        out.append("</ul>")
    out += [f"<footer><p>{_h(DISCLAIMER)}</p></footer></main>", "</body>", "</html>"]
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
                                  "partialFingerprints": {**_fingerprint(r.check_id, target),
                                                          "asaFinding/v2": findings.finding_id(r.check_id, target)}})
        # Code audit results: one SARIF result per source location, relative to the project root.
        ids = [loc["finding_id"] for loc in findings.annotate(r.to_dict(), target)[0].get("locations", [])]
        for loc, fid in zip(r.locations, ids):
            line = max(1, int(loc.get("line") or 1))
            uri = quote(str(loc["path"]))
            sarif_results.append({
                **base, "message": {"text": _clean(f"{loc.get('message') or r.summary}. {r.summary}")},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": uri, "uriBaseId": "%SRCROOT%"}, "region": {"startLine": line}}}],
                "partialFingerprints": {**_fingerprint(r.check_id, uri, line, _clean(loc.get("message") or "")),
                                        "asaFinding/v2": fid},
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


# Code points XML 1.0 forbids even as character references. _plain already drops C0/C1 controls and surrogates; this
# also drops the noncharacters U+FFFE and U+FFFF, so a value the scanned site chose can never make the file unparsable.
XML_ILLEGAL = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\ud800-\udfff\ufffe\uffff]")
JUNIT_MAX_DETAIL = 25  # evidence lines and locations in one testcase body


def _x(text, limit=MAX_TEXT):
    return XML_ILLEGAL.sub("", _plain(text, limit))


def _seconds(scope):
    try:
        start, end = datetime.fromisoformat(scope["started"]), datetime.fromisoformat(scope["finished"])
        return f"{max(0.0, (end - start).total_seconds()):.3f}"
    except (KeyError, TypeError, ValueError):
        return "0"


def _junit_detail(r, chk):
    lines = [_x(r.summary)]
    lines += [f"{_x(loc.get('path'), 300)}:{findings._line(loc)}: {_x(loc.get('message') or '', 300)}"
              for loc in r.locations[:JUNIT_MAX_DETAIL]]
    lines += [f"evidence: {_x(e, 500)}" for e in r.evidence[:JUNIT_MAX_DETAIL]]
    lines.append(f"fix: {_x(r.fix or chk.build)}")
    return "\n".join(lines)


def to_junit(target, results, scope=None):
    """JUnit XML: one testsuite, one testcase per result. Only a pass is a bare (passing) testcase: fail and warn are
    <failure>, error is <error>, manual and skip are <skipped>. Uses only the elements and attributes Jenkins, GitLab
    and Azure DevOps all read. Built with ElementTree (no DTD, no entities) from cleaned text."""
    checks = catalog.by_id()
    c = counts(results)
    totals = {"tests": str(len(results)), "failures": str(c["fail"] + c["warn"]), "errors": str(c["error"]),
              "skipped": str(c["manual"] + c["skip"]), "time": _seconds(scope or {})}
    root = ET.Element("testsuites", {"name": "agent-security-audit", **totals})
    suite = ET.SubElement(root, "testsuite", {"name": f"asa {_x(target, 300)}", **totals})
    props = ET.SubElement(suite, "properties")
    pairs = [(f"asa.{k}", v) for k, v in (("target", target), ("version", __version__))]
    for key, value in (scope or {}).items():
        if key == "flags":
            pairs += [(f"asa.flag.{k}", _flag(v)) for k, v in value.items()]
        elif key not in ("tool", "version"):
            pairs.append((f"asa.{key}", _flag(value)))
    for name, value in pairs:
        ET.SubElement(props, "property", {"name": _x(name, 100), "value": _x(value)})
    for r in sort_results(results):
        chk = checks[r.check_id]
        case = ET.SubElement(suite, "testcase", {"classname": f"asa.{chk.area}", "name": f"{r.check_id} {_x(chk.title)}",
                                                 "time": "0"})
        message = _x(r.summary, 300)
        if r.status in ("fail", "warn"):
            kind = chk.severity if r.status == "fail" else "warn"
            ET.SubElement(case, "failure", {"type": kind, "message": message}).text = _junit_detail(r, chk)
        elif r.status == "error":
            ET.SubElement(case, "error", {"type": "error", "message": message}).text = _junit_detail(r, chk)
        elif r.status in ("manual", "skip"):
            ET.SubElement(case, "skipped", {"message": f"{r.status}: {message}"})
    ET.indent(root)
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(root, encoding="unicode") + "\n"


JSONL_SCHEMA = 1  # major version of the JSON Lines field names; a renamed or removed field bumps it
ECS_SEVERITY = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def _scope_data(value, depth=0):
    """A copy of a scope block with every string cleaned and capped, lists and nesting bounded, for the run event."""
    if isinstance(value, str):
        return _plain(value, 300)
    if isinstance(value, dict) and depth < 4:
        return {_plain(k, 100): _scope_data(v, depth + 1) for k, v in list(value.items())[:100]}
    if isinstance(value, (list, tuple)) and depth < 4:
        return [_scope_data(v, depth + 1) for v in value[:100]]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return _plain(_flag(value), 300)


def to_jsonl(target, results, scope=None, *, now=_now):
    """JSON Lines for log pipelines (Splunk, Elastic, Sentinel): one event per result per source location (a result
    with no locations is one event), then one event with event.kind "run" carrying the scope and counts. Fields are
    ECS-style and nested as ECS JSON is (event.kind is {"event": {"kind": ...}}). Every line carries asa.schema. The
    timestamp is the run's finish time from the scope, else now()."""
    checks = catalog.by_id()
    scope = _scope_data(scope or {})
    stamp = scope.get("finished") or scope.get("started") or now()
    site = findings.origin(target)
    url = {"original": _plain(target, 300), "domain": urlsplit(site).hostname} if site else None
    lines = []
    for r in sort_results(results):
        chk = checks[r.check_id]
        row, _ = findings.annotate(r.to_dict(), target)
        asa = {"schema": JSONL_SCHEMA, "target": _plain(target, 300), "status": r.status, "severity": chk.severity,
               "finding_id": row["finding_id"], "cwe": list(chk.cwe), "owasp": list(chk.owasp)}
        event = {"@timestamp": stamp,
                 "event": {"kind": "finding", "dataset": "asa", "severity": ECS_SEVERITY[chk.severity]},
                 "rule": {"id": r.check_id, "name": chk.title, "category": chk.area,
                          "reference": f"{REPO}/blob/main/docs/checks/{chk.area}.md#{_doc_anchor(chk)}"},
                 **({"url": url} if url else {})}
        locations = row.get("locations") or []
        if not locations:
            lines.append({**event, "asa": asa, "message": _plain(r.summary)})
        for loc in locations:
            lines.append({**event, "asa": {**asa, "finding_id": loc["finding_id"]},
                          "file": {"path": _plain(loc.get("path"), 300), "line": findings._line(loc)},
                          "message": _plain(f"{loc.get('message') or r.summary}. {r.summary}")})
    lines.append({"@timestamp": stamp, "event": {"kind": "run", "dataset": "asa"},
                  "asa": {"schema": JSONL_SCHEMA, "target": _plain(target, 300), "version": __version__,
                          "counts": counts(results), "scope": scope},
                  **({"url": url} if url else {})})
    return "".join(json.dumps(line) + "\n" for line in lines)
