"""`asa diff OLD.json NEW.json`: what changed between two asa JSON reports of the same target.

Each finding (a result, or one source location of a code result) lands in one bucket:
  REGRESSED     passed in the old run, fails or warns now
  NEW           fails or warns now; before it was absent, manual, skip or error
  STILL OPEN    fails or warns in both runs
  NOT PROVEN    failed or warned before; now error, manual, skip, or missing although the check was selected, or
                a location the new run could not read. Never counted as fixed: a pass needs observed evidence.
                Also a pass that is now error, manual or skip: proof the new run lost.
  FIXED         failed or warned before, observed passing now
  NOT COMPARED  the check ran in only one of the two runs (for example it was not selected)

Report files are untrusted input: size, nesting and counts are capped, and every string is cleaned before it is
printed.
"""

from __future__ import annotations

import json
import os
import re
from urllib.parse import urlsplit

from . import __version__, catalog, findings, report
from .code_audit import CHECKS as CODE_CHECKS
from .code_audit.base import MAX_LOCATIONS as CODE_LOCATION_CAP
from .model import STATUSES, UNLISTED

MAX_BYTES = 50 * 1024 * 1024
MAX_RESULTS = 2000
MAX_LOCATIONS = 200       # per result; the code audit keeps 50
MAX_TOTAL_LOCATIONS = 20000
MAX_SHOWN = 300           # characters of any one string from a report file
MAX_TARGET = 4096         # a URL or a folder path; longer is not a report asa wrote
MAX_UNREAD = 1000         # unread file names read from one result
CHECK_ID = re.compile(r"^[A-Z][A-Z0-9]{0,15}-[0-9]{1,4}$")
BAD = ("fail", "warn")
SEVERITIES = ("critical", "high", "medium", "low")
FAIL_RANK = {s: i for i, s in enumerate(SEVERITIES)}
BUCKETS = (
    ("regressed", "REGRESSED", "passed before, fails or warns now"),
    ("new", "NEW", "fails or warns now; not failing before"),
    ("still_open", "STILL OPEN", "fails or warns in both runs"),
    ("not_proven", "NOT PROVEN", "the new run did not prove it fixed, or lost a pass"),
    ("fixed", "FIXED", "failed before, observed passing now"),
    ("not_compared", "NOT COMPARED", "ran in only one of the two runs"),
)
# Flags whose difference changes which checks can run or what they may do.
COMPARED_FLAGS = ("authorized", "no_dns", "no_ports", "auto_only", "allow_supabase", "osv", "insecure")
SELECTION_FLAGS = ("checks", "areas", "stacks")


class DiffError(ValueError):
    """A report that cannot be compared: exit 2."""


def _s(value, limit=MAX_SHOWN):
    return report._plain(str(value)[:limit * 4], limit)  # cut first: cleaning a huge string is slow


def load(path, label):
    """The parsed report at path, checked to be asa JSON with a known report_schema, or DiffError."""
    name = _s(path, 200)
    try:
        if not os.path.isfile(path):
            raise DiffError(f"{label} report {name} is not a file")
        if os.path.getsize(path) > MAX_BYTES:
            raise DiffError(f"{label} report {name} is over {MAX_BYTES // (1024 * 1024)} MB")
        with open(path, "rb") as fh:
            raw = fh.read(MAX_BYTES + 1)
    except OSError as exc:
        raise DiffError(f"could not read {label} report {name}: {_s(exc.strerror or exc, 100)}") from exc
    if len(raw) > MAX_BYTES:
        raise DiffError(f"{label} report {name} is over {MAX_BYTES // (1024 * 1024)} MB")
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise DiffError(f"{label} report {name} is not valid JSON") from exc
    return _validate(data, f"{label} report {name}")


def _validate(data, where):
    if not isinstance(data, dict) or data.get("tool") != "agent-security-audit":
        raise DiffError(f"{where} is not an asa JSON report (no tool key); write one with --format json")
    schema = data.get("report_schema", 0)
    if type(schema) is not int or schema not in (0, report.REPORT_SCHEMA) or "report_schema" in data and schema == 0:
        raise DiffError(f"{where} has report_schema {_s(schema, 20)}, which this asa ({__version__}) does not know; "
                        "update asa")
    if not isinstance(data.get("target"), str) or len(data["target"]) > MAX_TARGET:
        raise DiffError(f"{where} has no target, or one over {MAX_TARGET} characters")
    rows = data.get("results")
    if not isinstance(rows, list) or len(rows) > MAX_RESULTS:
        raise DiffError(f"{where} has no results list, or more than {MAX_RESULTS} results")
    seen, total = set(), 0
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("check_id"), str) \
                or not CHECK_ID.match(row["check_id"]) or row.get("status") not in STATUSES:
            raise DiffError(f"{where} has a result without a valid check_id and status")
        if row["check_id"] in seen:
            raise DiffError(f"{where} lists {row['check_id']} twice")
        seen.add(row["check_id"])
        locs = row.get("locations", [])
        if not isinstance(locs, list) or len(locs) > MAX_LOCATIONS or not all(isinstance(x, dict) for x in locs):
            raise DiffError(f"{where} has a bad locations list in {row['check_id']}")
        total += len(locs)
        if total > MAX_TOTAL_LOCATIONS:
            raise DiffError(f"{where} has more than {MAX_TOTAL_LOCATIONS} locations")
    if not isinstance(data.get("scope"), dict):
        data.pop("scope", None)
    return data


def normalize_target(target):
    """The origin of a URL target, or a project folder as a posix path without a trailing slash."""
    return findings.origin(target) or findings.normalize_path(target).rstrip("/") or str(target)


def _severity(row):
    chk = catalog.by_id().get(row["check_id"])
    if chk:
        return chk.severity
    return row.get("severity") if row.get("severity") in SEVERITIES else "unknown"


def _title(row):
    chk = catalog.by_id().get(row["check_id"])
    return chk.title if chk else _s(row.get("title") or "", 120)


def _version(data):
    scope = data.get("scope") or {}
    return _s(scope.get("version") or data.get("version") or "unknown", 40)


def _not_selected(data, check_id):
    """True when the run's scope block shows the check was left out, None when the run has no scope block (its flags
    are unknown, never guessed), else False."""
    scope = data.get("scope")
    if not scope or not isinstance(scope.get("flags"), dict):
        return None
    flags, chk = scope["flags"], catalog.by_id().get(check_id)
    named = flags.get("checks")
    if isinstance(named, list) and named and check_id not in {str(c).upper() for c in named}:
        return True
    areas = flags.get("areas")
    if chk and isinstance(areas, list) and areas and chk.area not in areas:
        return True
    stacks = flags.get("stacks")
    if chk and isinstance(stacks, list) and stacks and not ({"any", *map(str, stacks)} & set(chk.stacks)):
        return True
    if chk and flags.get("auto_only") is True and chk.mode != "auto":
        return True
    return scope.get("mode") == "code" and check_id not in CODE_CHECKS


def _rows(data):
    """{check_id: annotated row} and whether any id had to be derived."""
    out, derived = {}, False
    for row in data["results"]:
        row, d = findings.annotate(row, data["target"])
        row["_by_message"] = d == "message"
        unread = row.get("unread") if isinstance(row.get("unread"), list) else []
        row["_unread"] = {findings.normalize_path(p[:MAX_TARGET]) for p in unread[:MAX_UNREAD] if isinstance(p, str)}
        if len(unread) > MAX_UNREAD:
            row["_unread"].add(UNLISTED)
        out[row["check_id"]] = row
        derived = "message" if "message" in (derived, d) else derived or d
    return out, derived


def _read_code(data):
    """Whether the run read source code: its scope's mode, or, in a report without one, a folder target."""
    mode = (data.get("scope") or {}).get("mode")
    return mode in ("code", "scan+code") if mode else not findings.origin(data["target"])


def _gone(fid, old, new, loc, new_data, fixed_note=""):
    """The entry for an old location missing from a new result that passes or still fails: FIXED only when the new
    run read the file it was in."""
    if loc is not None and not new.get("locations") and not _read_code(new_data):
        return _entry("not_proven", fid, old, new, loc, "the new run did not read the source code")
    if loc is not None and (UNLISTED in new["_unread"] or findings.normalize_path(loc.get("path")) in new["_unread"]):
        return _entry("not_proven", fid, old, new, loc, "the new run could not read this file")
    return _entry("fixed", fid, old, new, loc, fixed_note)


def _units(row):
    """[(finding_id, location or None)]: one per source location, or the result itself when it has none."""
    locs = row.get("locations") or []
    if locs:
        return [(loc["finding_id"], loc) for loc in locs]
    return [(row["finding_id"], None)]


def _where(loc):
    if not loc:
        return ""
    line = findings._line(loc)
    return _s(loc.get("path") or "", 200) + (f":{line}" if line else "")


def _entry(bucket, fid, old, new, loc=None, note=""):
    row = new or old
    return {"bucket": bucket, "finding_id": fid, "check_id": row["check_id"], "title": _title(row),
            "severity": _severity(row), "old_status": old["status"] if old else "missing",
            "new_status": new["status"] if new else "missing", "where": _where(loc), "note": note}


def _change_note(old, new):
    notes = []
    if old["status"] != new["status"]:
        notes.append(f"{old['status']} -> {new['status']}")
    sev = [r.get("severity") if r.get("severity") in SEVERITIES else None for r in (old, new)]
    if sev[0] and sev[1] and sev[0] != sev[1]:
        notes.append(f"severity {sev[0]} -> {sev[1]}")
    return "; ".join(notes)


def _compare_check(old, new, old_data, new_data):
    if old is None or new is None:
        side, other_data = (new, old_data) if old is None else (old, new_data)
        if side["status"] in BAD:
            left_out = _not_selected(other_data, side["check_id"])
            if left_out:
                return [_entry("not_compared", side["finding_id"], old, new,
                               note=f"not selected in the {'old' if old is None else 'new'} run")]
            unknown = " (flags unknown)" if left_out is None else ""
            if old is None:
                return [_entry("new", fid, None, new, loc, f"not in the old report{unknown}")
                        for fid, loc in _units(new)]
            return [_entry("not_proven", fid, old, None, loc, f"missing from the new report{unknown}")
                    for fid, loc in _units(old)]
        return [_entry("not_compared", side["finding_id"], old, new)]
    o, n = old["status"], new["status"]
    if o in BAD and n == "pass":
        return [_gone(fid, old, new, loc, new_data) for fid, loc in _units(old)]
    if o in BAD and n not in BAD:
        return [_entry("not_proven", fid, old, new, loc, f"now {n}") for fid, loc in _units(old)]
    if o == "pass" and n not in BAD:
        return [] if n == "pass" else [_entry("not_proven", new["finding_id"], old, new, None,
                                              f"passed before, now {n}")]
    if o == "pass" and n in BAD:
        return [_entry("regressed", fid, old, new, loc) for fid, loc in _units(new)]
    if n in BAD and o not in BAD:
        return [_entry("new", fid, old, new, loc) for fid, loc in _units(new)]
    if o not in BAD:
        return []
    note = _change_note(old, new)
    if bool(old.get("locations")) != bool(new.get("locations")) or old["_by_message"] or new["_by_message"]:
        # One run has source locations and the other does not (a scan with and without --code), or an old report's
        # location ids could only be keyed on messages, so they cannot match the other run's: compare the check.
        why = ("only one run has source locations" if bool(old.get("locations")) != bool(new.get("locations"))
               else "location ids in an old report could only be derived from messages")
        return [_entry("still_open", new["finding_id"], old, new, None,
                       "; ".join(filter(None, [note, f"compared by check: {why}"])))]
    before, after = dict(_units(old)), dict(_units(new))
    capped = len(new.get("locations") or []) >= CODE_LOCATION_CAP
    out = [_entry("still_open", fid, old, new, loc, note) for fid, loc in after.items() if fid in before]
    out += [_entry("new", fid, old, new, loc, "new location; the check failed before too")
            for fid, loc in after.items() if fid not in before]
    for fid, loc in before.items():
        if fid in after:
            continue
        if capped:
            out.append(_entry("not_proven", fid, old, new, loc,
                              f"the new run lists only its first {CODE_LOCATION_CAP} locations"))
        else:
            out.append(_gone(fid, old, new, loc, new_data, "no longer reported; the check still fails elsewhere"))
    return out


def _flag(value):
    return _s(report._flag(value), 120)


def warnings(old, new, derived, targets_differ):
    """Comparability warnings for the header, loudest first."""
    out = []
    if targets_differ:
        out.append(f"different targets: old {_s(old['target'], 200)}, new {_s(new['target'], 200)} "
                   "(--allow-different-target)")
    elif _url_path(old["target"]) != _url_path(new["target"]):
        out.append(f"same site, different paths: old {_s(old['target'], 200)}, new {_s(new['target'], 200)}; "
                   "findings match on the site, so make sure both runs scanned the same app")
    for label, data in (("old", old), ("new", new)):
        if not data.get("scope"):
            out.append(f"the {label} report has no scope block (written by asa {_version(data)}): its flags are "
                       "unknown, so a check missing from it is never treated as not selected")
    if _version(old) != _version(new):
        out.append(f"different asa versions: old {_version(old)}, new {_version(new)}; check wording and results "
                   "can differ between versions")
    if old.get("scope") and new.get("scope"):
        so, sn = old["scope"], new["scope"]
        if so.get("mode") != sn.get("mode"):
            out.append(f"different modes: old {_flag(so.get('mode'))}, new {_flag(sn.get('mode'))}")
        fo, fn = so.get("flags") or {}, sn.get("flags") or {}
        if not isinstance(fo, dict) or not isinstance(fn, dict):
            fo, fn = {}, {}
        for key in COMPARED_FLAGS:
            if key in fo and key in fn and fo[key] != fn[key]:
                out.append(f"flag {key} differs: old {_flag(fo[key])}, new {_flag(fn[key])}")
        for key in SELECTION_FLAGS:
            if (fo.get(key) or []) != (fn.get(key) or []):
                out.append(f"{key} selection differs: old {_flag(fo.get(key))}, new {_flag(fn.get(key))}")
    for label, d in (("old", derived[0]), ("new", derived[1])):
        if d:
            out.append(f"finding ids in the {label} report were derived from the fields present (it was written "
                       "without them)" + ("; some code locations (past the 25 the report lists in its evidence) "
                                          "cannot be matched, so their checks are compared as a whole"
                                          if d == "message" else ""))
    return out


def _url_path(target):
    """The path and query of a URL target without a trailing slash, or "" for a folder target."""
    if not findings.origin(target):
        return ""
    parts = urlsplit(str(target).strip())
    return parts.path.rstrip("/") + (f"?{parts.query}" if parts.query else "")


def compare(old, new, allow_different_target=False):
    """The diff of two loaded reports as a dict (the JSON output)."""
    targets_differ = normalize_target(old["target"]) != normalize_target(new["target"])
    if targets_differ and not allow_different_target:
        raise DiffError(f"the reports are for different targets ({_s(old['target'], 200)} and "
                        f"{_s(new['target'], 200)}); pass --allow-different-target to compare them anyway")
    before, d_old = _rows(old)
    after, d_new = _rows(new)
    entries = []
    for cid in sorted(set(before) | set(after)):
        entries += _compare_check(before.get(cid), after.get(cid), old, new)
    entries.sort(key=lambda e: (e["bucket"] != "not_compared" and "fail" not in (e["new_status"], e["old_status"]),
                                FAIL_RANK.get(e["severity"], 0), e["check_id"], e["where"]))
    buckets = {key: [e for e in entries if e["bucket"] == key] for key, _, _ in BUCKETS}
    return {
        "tool": "agent-security-audit", "version": __version__, "diff_schema": 1,
        "old": {"target": _s(old["target"]), "version": _version(old), "generated": _s(old.get("generated") or "-")},
        "new": {"target": _s(new["target"]), "version": _version(new), "generated": _s(new.get("generated") or "-")},
        "warnings": warnings(old, new, (d_old, d_new), targets_differ),
        "counts": {key: len(v) for key, v in buckets.items()},
        "buckets": buckets,
    }


def exit_code(result, fail_on_new):
    """1 when a NEW or REGRESSED fail is at or above fail_on_new (an unknown severity counts as critical), else 0."""
    if fail_on_new == "none":
        return 0
    limit = FAIL_RANK[fail_on_new]
    gating = result["buckets"]["new"] + result["buckets"]["regressed"]
    return int(any(e["new_status"] == "fail" and FAIL_RANK.get(e["severity"], 0) <= limit for e in gating))


def _count_line(result):
    return " · ".join(f"{result['counts'][key]} {name.lower()}" for key, name, _ in BUCKETS)


def _line_text(e):
    head = f"  {e['old_status'] + ' -> ' + e['new_status']:<17} {e['severity']:<8} {e['check_id']:<11} {e['title']}"
    sub = "  ".join(filter(None, [e["where"], e["note"], e["finding_id"]]))
    return [head, f"{'':<39}{sub}"]


def to_text(result, old_name, new_name):
    lines = [f"asa diff: {_s(old_name, 200)} -> {_s(new_name, 200)}",
             f"old: {result['old']['target']} (asa {result['old']['version']}, {result['old']['generated']})",
             f"new: {result['new']['target']} (asa {result['new']['version']}, {result['new']['generated']})"]
    lines += [f"WARNING: {w}" for w in result["warnings"]]
    for key, name, why in BUCKETS:
        rows = result["buckets"][key]
        if not rows:
            continue
        lines += ["", f"{name}: {len(rows)} ({why})"]
        if key == "not_compared":
            ids = sorted({e["check_id"] for e in rows})
            lines.append("  " + ", ".join(ids[:60]) + (f" and {len(ids) - 60} more" if len(ids) > 60 else ""))
            continue
        for e in rows:
            lines += _line_text(e)
    lines += ["", _count_line(result)]
    return "\n".join(lines) + "\n"


def to_markdown(result, old_name, new_name):
    esc, code = report._md_escape, report._md_code
    lines = ["# asa diff", "",
             f"- Old: {code(old_name)}, {esc(result['old']['target'])} (asa {esc(result['old']['version'])})",
             f"- New: {code(new_name)}, {esc(result['new']['target'])} (asa {esc(result['new']['version'])})", ""]
    lines += [f"> **Warning:** {esc(w)}" for w in result["warnings"]]
    for key, name, why in BUCKETS:
        rows = result["buckets"][key]
        if not rows:
            continue
        lines += ["", f"## {name} ({len(rows)})", "", esc(why), ""]
        if key == "not_compared":
            lines.append(", ".join(code(c) for c in sorted({e["check_id"] for e in rows})))
            continue
        for e in rows:
            extra = " · ".join(filter(None, [code(e["where"]) if e["where"] else "", esc(e["note"])]))
            lines.append(f"- **{esc(e['old_status'])} -> {esc(e['new_status'])}** "
                         f"{esc(e['severity'])} {code(e['check_id'])} {esc(e['title'])}"
                         + (f" · {extra}" if extra else "") + f" · {code(e['finding_id'])}")
    lines += ["", esc(_count_line(result))]
    return "\n".join(lines) + "\n"


def run(old_path, new_path, *, fmt="text", out=None, fail_on_new="high", allow_different_target=False, say=print):
    """The `asa diff` command: prints or writes the diff and returns the exit code (0, 1, or 2 on bad input)."""
    try:
        result = compare(load(old_path, "old"), load(new_path, "new"), allow_different_target)
    except DiffError as exc:
        say(exc)
        return 2
    if fmt == "json":
        text = json.dumps(result, indent=2) + "\n"
    else:
        text = (to_markdown if fmt == "md" else to_text)(result, str(old_path), str(new_path))
    if out:
        try:
            os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
            with open(out, "w", encoding="utf-8") as fh:
                fh.write(text)
        except OSError as exc:
            say(f"could not write {out}: {exc.strerror or exc}")
            return 2
    else:
        print(text, end="")
    return exit_code(result, fail_on_new)
