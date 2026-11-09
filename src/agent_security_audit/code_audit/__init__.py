"""Code audit: read a web project's files statically and settle catalog checks with file:line evidence.

    from agent_security_audit import code_audit
    target, results = code_audit.run("path/to/project")

Nothing in the project is executed: no package manager, no git, no build. Only files under the given path are read.
The one network call is the OSV vulnerability lookup for locked dependencies (turn it off with osv=False).
"""

from __future__ import annotations

from .. import catalog
from ..model import UNLISTED, Result, errored
from . import ci, deps, nextjs, patterns, request_input, secrets, sql
from .project import Project

MODULES = (secrets, sql, nextjs, patterns, request_input, ci)
# Every catalog check the code audit can settle. Docs and `asa scan` hints read this.
CHECKS = tuple(dict.fromkeys(cid for mod in (*MODULES, deps) for cid in mod.CHECKS))
# The only checks the code audit may pass: each pass rests on a literal setting, a header value on a route that
# matches every path or a locked version that the read sees in full. Every other check is at most manual from code:
# an auth call, an RLS statement in a migration or a search for known bad patterns (raw HTML sinks, eval) is not
# proof, since a missed sink or an obfuscated call reads clean. An allowlist, so a new check starts out unable to
# pass. run() and merge() enforce it; a test keeps it a subset of CHECKS.
STATIC_PROOF = frozenset({"NEXT-02", "NEXT-03", "NEXT-04", "NEXT-07", "NEXT-11", "BROWSER-01", "BROWSER-02",
                          "BROWSER-03", "BROWSER-04", "BROWSER-05", "BROWSER-08"})
NO_STATIC_PASS = frozenset(CHECKS) - STATIC_PROOF
MAX_UNREAD = 100  # unread files named on one result; past it the result says UNLISTED


def run(path=".", *, osv=True, osv_query=None, timeout=20.0, ids=None, areas=None):
    """Return (project_root, [Result]) for every check the code settles, filtered by ids/areas."""
    project = Project(path)
    results = []
    for mod in MODULES:
        for fn in mod.ANALYZERS:
            project.unread = []
            try:
                results += _unread(fn(project), project)
            except Exception as exc:  # noqa: BLE001 - one broken analyzer must not stop the audit
                cid = mod.CHECKS[0]
                results.append(errored(cid, f"code analyzer {fn.__name__} failed: {type(exc).__name__}: {exc}"))
    project.unread = []
    try:
        results += _unread(deps.dependencies(project, osv=osv, osv_query=osv_query, timeout=timeout), project)
    except Exception as exc:  # noqa: BLE001
        results.append(errored("INFRA-13", f"dependency analyzer failed: {type(exc).__name__}: {exc}"))
    results = _static_only(results)
    if gap := project.coverage_gap():
        results = _not_proven(results, f"The audit did not cover the whole project: {gap}.")
        for r in results:
            r.unread = [*r.unread, UNLISTED]
    known = catalog.by_id()
    wanted = {i.upper() for i in ids} if ids else None
    out = [r for r in results if r.check_id in known and (wanted is None or r.check_id in wanted)
           and (not areas or known[r.check_id].area in areas)]
    for r in out:
        if r.status in ("fail", "warn") and not r.fix:
            r.fix = known[r.check_id].build
    return str(project.root), out


def _static_only(results):
    guessed = [r for r in results if r.check_id not in STATIC_PROOF]
    return [r for r in results if r.check_id in STATIC_PROOF] + \
        _not_proven(guessed, "A static read cannot prove this check.")


def _not_proven(results, note):
    """A pass that needed every file is not proven when some were not read: it becomes manual, with the reason."""
    out = []
    for r in results:
        if r.status == "pass":
            r = Result(r.check_id, "manual", f"Not proven: {note} {r.summary}", r.evidence + [note], r.fix,
                       r.locations, r.unread)
        out.append(r)
    return out


def _unread(results, project):
    files = sorted(set(project.unread))
    if not files:
        return results
    shown = ", ".join(files[:5]) + (f" and {len(files) - 5} more" if len(files) > 5 else "")
    out = _not_proven(results, f"{len(files)} file{'' if len(files) == 1 else 's'} over the size cap "
                               f"{'was' if len(files) == 1 else 'were'} not read ({shown}).")
    for r in out:  # a fail keeps its status, but its locations in these files are unknown, not gone
        r.unread = files[:MAX_UNREAD] + ([UNLISTED] if len(files) > MAX_UNREAD else [])
    return out


# Lower is stronger evidence of a flaw when merging a code result with a live one.
_MERGE_RANK = {"fail": 0, "warn": 1, "pass": 2, "error": 3, "manual": 4, "skip": 5}


def merge(live, code):
    """Combine live scan results with code audit results for the same checks.

    A live fail always stands. A code fail beats a live pass or warn (the flaw is in the source). A code pass never
    replaces a live manual or error: a pass needs observed evidence, so the live status stands and the code result
    is kept as evidence. Otherwise a live pass/warn stands and a code result fills in where the scan could only say
    manual, skip or error. Evidence from both sides is kept, prefixed with where it came from.
    """
    by_id = {r.check_id: r for r in code}
    out = []
    for r in live:
        c = by_id.pop(r.check_id, None)
        if c is None:
            out.append(r)
            continue
        if r.status == "fail":
            keep, other = r, c
        elif c.status == "fail":
            keep, other = c, r
        elif r.status in ("pass", "warn") or (c.status == "pass" and r.status in ("manual", "error")):
            keep, other = r, c
        else:
            keep, other = _static_only([c])[0], r  # also for code results that did not come from run()
        src_keep, src_other = ("live", "code") if keep is r else ("code", "live")
        evidence = [f"{src_keep}: {e}" for e in keep.evidence]
        if other.status != "manual":
            evidence += [f"{src_other} ({other.status}): {other.summary}"] + [f"{src_other}: {e}" for e in
                                                                             other.evidence[:10]]
        out.append(Result(keep.check_id, keep.status, keep.summary, evidence, keep.fix,
                          keep.locations or other.locations, c.unread))
    out += sorted(_static_only(by_id.values()), key=lambda r: (_MERGE_RANK[r.status], r.check_id))
    return out
