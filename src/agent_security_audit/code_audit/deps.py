"""Dependencies: lockfiles parsed without running a package manager, known vulnerabilities from the OSV database
(INFRA-13 for all packages, NEXT-04 for Next.js, React and sharp)."""

from __future__ import annotations

import json
import posixpath
import re
import ssl
import tomllib
import urllib.request

from .. import __version__
from ..model import Result
from .base import make, plural
from .project import LOCKFILES, Finding, is_test_path

OSV_URL = "https://api.osv.dev/v1/querybatch"
OSV_BATCH = 500
MAX_RESPONSE = 20_000_000
FRAMEWORK = {"next", "react", "react-dom", "sharp"}
VERSION = re.compile(r"^\d+\.\d+[\w.+-]*$")
PNPM_KEY = re.compile(r"""^ {2}['"]?/?((?:@[^/@\s'"]+/)?[^/@\s('"]+)[@/](\d[^(:'"\s_]*)""")
REQUIREMENT = re.compile(r"^\s*([A-Za-z0-9][\w.-]*)(?:\[[^\]]*\])?\s*==\s*([\w.+!-]+)")


class OsvError(Exception):
    pass


def parse_package_lock(text):
    data = json.loads(text)
    out = set()
    for key, meta in (data.get("packages") or {}).items():
        if key and isinstance(meta, dict) and not meta.get("link") and "node_modules/" in key:
            out.add((key.rsplit("node_modules/", 1)[1], meta.get("version", "")))

    def walk(deps):
        for name, meta in (deps or {}).items():
            if isinstance(meta, dict):
                out.add((name, meta.get("version", "")))
                walk(meta.get("dependencies"))

    if not out:
        walk(data.get("dependencies"))
    return out


def parse_pnpm_lock(text):
    out, section = set(), None
    for line in text.splitlines():
        if line and not line.startswith(" "):
            section = line.rstrip(":").strip()
            continue
        if section in ("packages", "snapshots") and (m := PNPM_KEY.match(line)):
            out.add((m.group(1), m.group(2)))
    return out


def parse_yarn_lock(text):
    out, name = set(), None
    for line in text.splitlines():
        if line and not line.startswith((" ", "#")) and line.rstrip().endswith(":"):
            spec = line.rstrip(":").split(",")[0].strip().strip('"')
            at = spec.find("@", 1)
            name = spec[:at] if at > 0 and not spec.startswith("__") else None
            continue
        m = re.match(r"""^\s+version:?\s+"?([^"\s]+)"?""", line)
        if m and name:
            out.add((name, m.group(1)))
            name = None
    return out


def parse_requirements(text):
    return {(m.group(1).lower(), m.group(2)) for line in text.splitlines() if (m := REQUIREMENT.match(line))}


def parse_poetry_lock(text):
    return {(p["name"].lower(), p["version"]) for p in tomllib.loads(text).get("package", [])
            if isinstance(p, dict) and p.get("name") and p.get("version")}


PARSERS = {
    "package-lock.json": ("npm", parse_package_lock), "npm-shrinkwrap.json": ("npm", parse_package_lock),
    "pnpm-lock.yaml": ("npm", parse_pnpm_lock), "yarn.lock": ("npm", parse_yarn_lock),
    "requirements.txt": ("PyPI", parse_requirements), "poetry.lock": ("PyPI", parse_poetry_lock),
}


def query_osv(packages, timeout=20.0):
    """{(ecosystem, name, version): [vuln ids]} for every package. Raises OsvError when OSV cannot be reached."""
    context = ssl.create_default_context()
    found, packages = {}, sorted(packages)
    for i in range(0, len(packages), OSV_BATCH):
        chunk = packages[i:i + OSV_BATCH]
        body = json.dumps({"queries": [{"package": {"ecosystem": e, "name": n}, "version": v}
                                       for e, n, v in chunk]}).encode()
        req = urllib.request.Request(OSV_URL, data=body, method="POST", headers={
            "Content-Type": "application/json", "User-Agent": f"agent-security-audit/{__version__}"})
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=context) as resp:
                data = json.loads(resp.read(MAX_RESPONSE))
        except (OSError, ValueError) as exc:
            raise OsvError(f"{type(exc).__name__}: {exc}") from exc
        results = data.get("results") if isinstance(data, dict) else None
        if not isinstance(results, list) or len(results) != len(chunk):
            raise OsvError("unexpected response from OSV")
        for pkg, res in zip(chunk, results, strict=True):
            ids = [v.get("id") for v in (res or {}).get("vulns") or [] if isinstance(v, dict) and v.get("id")]
            if ids:
                found[pkg] = ids
    return found


def dependencies(project, osv=True, osv_query=None, timeout=20.0):
    files = [f for f in project.files if not is_test_path(f)]
    locks, manifests = {}, [f for f in files if posixpath.basename(f) == "package.json"]
    unchecked = []  # lockfiles present but not read: a format with no parser, or one that gave no packages
    for rel in files:
        base = posixpath.basename(rel)
        if base not in PARSERS:
            if base in LOCKFILES:
                unchecked.append(Finding(rel, 1, "lockfile format not supported, so its packages were not checked"))
            continue
        eco, parse = PARSERS[base]
        try:
            pkgs = {(eco, n, v) for n, v in parse(project.text(rel)) if n and VERSION.match(v or "")}
        except (ValueError, KeyError, TypeError, AttributeError, tomllib.TOMLDecodeError):
            pkgs = set()
        if pkgs:
            locks[rel] = pkgs
        elif base != "requirements.txt":
            unchecked.append(Finding(rel, 1, "no package versions could be read from this lockfile"))
    declares_next = any(re.search(r'"next"\s*:', project.text(m)) for m in manifests)
    npm_dirs = {posixpath.dirname(f) for f in files
                if posixpath.basename(f) in ("package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml",
                                             "yarn.lock", "bun.lockb", "bun.lock")}
    unlocked = [Finding(m, 1, "package.json with no lockfile in its folder or a parent folder") for m in manifests
                if m.endswith("package.json") and not any(_under(posixpath.dirname(m), d) for d in npm_dirs)]
    gap = (f"Not checked: {', '.join(f.path for f in unchecked[:5])}"
           + (f" and {len(unchecked) - 5} more" if len(unchecked) > 5 else "") + ".") if unchecked else ""
    if not locks:
        if unlocked:
            return [make("INFRA-13", "warn", "No lockfile, so every install can pull different (and newly "
                         "compromised) versions. Commit the lockfile and install with npm ci.", unlocked + unchecked)]
        if unchecked:
            out = [make("INFRA-13", "manual", "Dependencies were not checked for known vulnerabilities: no "
                        f"supported lockfile could be read. {gap} Run the package manager's audit (for example "
                        "bun audit, cargo audit or pip-audit) or export a supported lockfile.", unchecked)]
            if declares_next:
                out.append(make("NEXT-04", "manual", "The Next.js, React and sharp versions were not checked: the "
                                f"lockfile could not be read. {gap}", unchecked))
            return out
        return []
    all_pkgs = set().union(*locks.values())
    framework = {p for p in all_pkgs if p[0] == "npm" and p[1] in FRAMEWORK}
    has_next = any(p[1] == "next" for p in framework)
    # package.json declares next, but no lockfile that was read lists it: say the versions went unchecked.
    next_unread = [make("NEXT-04", "manual", "The Next.js, React and sharp versions were not checked: no lockfile "
                        "that was read lists next." + (f" {gap}" if gap else ""), unchecked + unlocked)] \
        if declares_next and not has_next else []
    note = f"Read {plural(len(all_pkgs), 'package version')} from {', '.join(sorted(locks))}."
    if not osv:
        out = [Result("INFRA-13", "manual", "Dependency vulnerability lookup skipped (--no-osv). " + note
                      + (" " + gap if gap else ""), [f.evidence() for f in unlocked + unchecked])]
        if has_next:
            out.append(Result("NEXT-04", "manual", "Vulnerability lookup skipped (--no-osv): "
                              + ", ".join(sorted(f"{n} {v}" for _, n, v in framework))))
        return out + next_unread
    try:
        vulns = (osv_query or query_osv)(all_pkgs, timeout=timeout)
    except OsvError as exc:
        msg = f"Could not query the OSV vulnerability database ({exc}); dependencies were not checked."
        return [Result("INFRA-13", "error", msg)] + ([Result("NEXT-04", "error", msg)] if has_next else next_unread)

    def finding(pkg, ids):
        _, name, version = pkg
        rel, line = next(((r, _line(project.text(r), name)) for r, p in locks.items() if pkg in p), ("", 1))
        shown = ", ".join(ids[:5]) + (f" and {len(ids) - 5} more" if len(ids) > 5 else "")
        return Finding(rel, line, f"{name} {version} has known vulnerabilities: {shown}")

    out = []
    general = [finding(p, ids) for p, ids in sorted(vulns.items()) if p not in framework]
    core = [finding(p, ids) for p, ids in sorted(vulns.items()) if p in framework]
    if general or core:
        n = len(general) + len(core)
        out.append(make("INFRA-13", "fail", f"{plural(n, 'locked package')} {'has' if n == 1 else 'have'} known "
                        "vulnerabilities in OSV. Upgrade to a fixed version.", core + general + unlocked + unchecked,
                        [note]))
    elif unlocked:
        out.append(make("INFRA-13", "warn", "Locked packages have no known vulnerabilities, but a package.json has no "
                        "lockfile.", unlocked + unchecked, [note]))
    elif unchecked:
        out.append(make("INFRA-13", "manual", f"No known vulnerabilities in OSV for "
                        f"{plural(len(all_pkgs), 'locked package version')}, but not every lockfile was read. {gap}",
                        unchecked, [note]))
    else:
        out.append(make("INFRA-13", "pass", f"No known vulnerabilities in OSV for "
                        f"{plural(len(all_pkgs), 'locked package version')}. Install-script and typosquat review still apply.", evidence=[note]))
    if has_next:
        versions = ", ".join(sorted(f"{n} {v}" for _, n, v in framework))
        if core:
            out.append(make("NEXT-04", "fail", "Next.js, React or sharp is on a release with known vulnerabilities. "
                            "Upgrade to the latest patch release.", core))
        elif unchecked or unlocked:  # another app in the repo may pin an older Next.js in a file not read
            out.append(make("NEXT-04", "manual", f"Not proven: no known vulnerabilities in OSV for {versions}, but not "
                            "every package.json has a lockfile that was read." + (f" {gap}" if gap else ""),
                            unchecked + unlocked))
        else:
            out.append(make("NEXT-04", "pass", f"No known vulnerabilities in OSV for {versions}."))
    return out + next_unread


def _under(path, folder):
    return not folder or path == folder or path.startswith(folder + "/")


def _line(text, name):
    for needle in (f'node_modules/{name}"', f"/{name}@", f"{name}@", f'"{name}"', name):
        i = text.find(needle)
        if i >= 0:
            return text.count("\n", 0, i) + 1
    return 1


CHECKS = ("INFRA-13", "NEXT-04")
