"""Code audit: read a web project's files statically and settle catalog checks with file:line evidence.

    from agent_security_audit import code_audit
    target, results = code_audit.run("path/to/project")

Nothing in the project is executed: no package manager, no git, no build. Only files under the given path are read.
The one network call is the OSV vulnerability lookup for locked dependencies (turn it off with osv=False).
"""

from __future__ import annotations

from .. import catalog
from ..model import Result, errored
from . import ci, deps, nextjs, patterns, secrets, sql
from .project import Project

MODULES = (secrets, sql, nextjs, patterns, ci)
# Every catalog check the code audit can settle. Docs and `asa scan` hints read this.
CHECKS = tuple(dict.fromkeys(cid for mod in (*MODULES, deps) for cid in mod.CHECKS))


def run(path=".", *, osv=True, osv_query=None, timeout=20.0, ids=None, areas=None):
    """Return (project_root, [Result]) for every check the code settles, filtered by ids/areas."""
    project = Project(path)
    results = []
    for mod in MODULES:
        for fn in mod.ANALYZERS:
            try:
                results += fn(project)
            except Exception as exc:  # noqa: BLE001 - one broken analyzer must not stop the audit
                cid = mod.CHECKS[0]
                results.append(errored(cid, f"code analyzer {fn.__name__} failed: {type(exc).__name__}: {exc}"))
    try:
        results += deps.dependencies(project, osv=osv, osv_query=osv_query, timeout=timeout)
    except Exception as exc:  # noqa: BLE001
        results.append(errored("INFRA-13", f"dependency analyzer failed: {type(exc).__name__}: {exc}"))
    known = catalog.by_id()
    wanted = {i.upper() for i in ids} if ids else None
    out = [r for r in results if r.check_id in known and (wanted is None or r.check_id in wanted)
           and (not areas or known[r.check_id].area in areas)]
    for r in out:
        if r.status in ("fail", "warn") and not r.fix:
            r.fix = known[r.check_id].build
    return str(project.root), out


# Lower is stronger evidence of a flaw when merging a code result with a live one.
_MERGE_RANK = {"fail": 0, "warn": 1, "pass": 2, "error": 3, "manual": 4, "skip": 5}


def merge(live, code):
    """Combine live scan results with code audit results for the same checks.

    A live fail always stands. A code fail beats a live pass or warn (the flaw is in the source). Otherwise a live
    pass/warn stands and a code result fills in where the scan could only say manual, skip or error. Evidence from
    both sides is kept, prefixed with where it came from.
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
        elif r.status in ("pass", "warn"):
            keep, other = r, c
        else:
            keep, other = c, r
        src_keep, src_other = ("live", "code") if keep is r else ("code", "live")
        evidence = [f"{src_keep}: {e}" for e in keep.evidence]
        if other.status != "manual":
            evidence += [f"{src_other} ({other.status}): {other.summary}"] + [f"{src_other}: {e}" for e in
                                                                             other.evidence[:10]]
        out.append(Result(keep.check_id, keep.status, keep.summary, evidence, keep.fix,
                          keep.locations or other.locations))
    out += sorted(by_id.values(), key=lambda r: (_MERGE_RANK[r.status], r.check_id))
    return out
