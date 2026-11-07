"""Secrets in the code: committed secret keys and .env files (INFRA-08), secret-looking public env vars (NEXT-01)."""

from __future__ import annotations

import posixpath
import re

from ..checks.exposure import JWT, SECRET_PATTERNS, _jwt_role, mask
from .base import SUSPECTED, make, plural
from .project import LOCKFILES, Finding, line_of

ENV_FILE = re.compile(r"^\.env(\.[\w.-]+)?$")
ENV_TEMPLATE = re.compile(r"(example|sample|template|dist|defaults?|schema)$", re.IGNORECASE)
LOCAL_ENV = (".env", ".env.local", ".env.development", ".env.development.local", ".env.production",
             ".env.production.local")
ENV_ASSIGN = re.compile(r"^[ \t]*(?:export[ \t]+)?([A-Za-z_][A-Za-z0-9_]*)[ \t]*=[ \t]*(.*)$", re.MULTILINE)
PUBLIC_VAR = re.compile(r"\b(NEXT_PUBLIC_|EXPO_PUBLIC_|NUXT_PUBLIC_|REACT_APP_|GATSBY_|VITE_|PUBLIC_)([A-Z0-9_]+)")
SECRET_NAME = re.compile(r"SERVICE_?ROLE|SECRET|PRIVATE|PASSWORD|PASSWD|DATABASE_URL|DB_URL|ADMIN_KEY|SIGNING_KEY")


def _placeholder(value):
    body = re.sub(r"^[a-z]+[_-](?:live|secret|ant|proj)?[_-]?", "", value, flags=re.IGNORECASE)
    return "EXAMPLE" in value.upper() or len(set(body.lower())) < 6


def secret_hits(text):
    """[(offset, kind, masked)] for secret formats in text, placeholders left out."""
    hits = []
    for kind, pattern in SECRET_PATTERNS:
        for m in pattern.finditer(text):
            if kind == "private key" or not _placeholder(m.group(0)):
                hits.append((m.start(), kind, mask(m.group(0))))
    for m in JWT.finditer(text):
        if _jwt_role(m.group(0)) == "service_role":
            hits.append((m.start(), "Supabase service_role JWT", mask(m.group(0))))
    return hits


def committed_secrets(project):
    findings, env_files, tracked_env = [], [], False
    for rel in project.files:
        base = posixpath.basename(rel)
        if base in LOCKFILES or rel.endswith(".map"):
            continue
        text = project.text(rel)
        if ENV_FILE.match(base) and not ENV_TEMPLATE.search(base):
            names = [m.group(1) for m in ENV_ASSIGN.finditer(text) if m.group(2).strip().strip("\"'")]
            is_tracked = rel in project.tracked
            tracked_env = tracked_env or is_tracked
            where = "tracked in git" if is_tracked else "not covered by .gitignore"
            env_files.append(Finding(rel, 1, f"environment file is {where} ({plural(len(names), 'variable')} with values: "
                                     + ", ".join(names[:8]) + (", ..." if len(names) > 8 else "") + "; values not shown)"))
        for offset, kind, masked in secret_hits(text):
            findings.append(Finding(rel, line_of(text, offset), kind, masked))
    note = f"Files read from the {project.source}; git history was not read."
    if findings:
        return [make("INFRA-08", "fail", f"{plural(len(findings), 'secret key')} in files git tracks or would commit. Treat "
                     "each one as leaked: rotate it, then move it to the host's environment settings.",
                     findings + env_files, [note])]
    if env_files:
        status = "fail" if tracked_env else "warn"
        return [make("INFRA-08", status, f"{plural(len(env_files), '.env file')} "
                     + ("tracked in git" if tracked_env else "not covered by .gitignore")
                     + ". Remove them from the repository, add .env* to .gitignore and rotate the values.",
                     env_files, [note])]
    # The check covers git history too, which a static read of the files cannot see: never a pass from here.
    return [make("INFRA-08", "manual", f"No secret key formats or .env files in {plural(len(project.files), 'file')} "
                 "of the working tree. Git history was not read, so a secret committed and later deleted would not "
                 "show; scan the history with a tool such as gitleaks or trufflehog.", evidence=[note])]


def public_env(project):
    fails, warns, seen, any_public = [], [], set(), False
    env_paths = [f for f in project.files if ENV_FILE.match(posixpath.basename(f))]
    dirs = {""} | {posixpath.dirname(f) for f in project.files if posixpath.basename(f) == "package.json"}
    for d in sorted(dirs):
        for name in LOCAL_ENV:
            rel = posixpath.join(d, name) if d else name
            if rel not in env_paths and project.extra_text(rel):
                env_paths.append(rel)
    for rel in env_paths:
        text = project.text(rel)
        for m in ENV_ASSIGN.finditer(text):
            pm = PUBLIC_VAR.fullmatch(m.group(1))
            if not pm:
                continue
            any_public = True
            line = line_of(text, m.start())
            hits = secret_hits(m.group(2))
            if hits:
                fails.append(Finding(rel, line, f"{m.group(1)} holds a {hits[0][1]}", hits[0][2]))
            elif _secret_name(pm.group(2)) and (rel, m.group(1)) not in seen:
                seen.add((rel, m.group(1)))
                warns.append(Finding(rel, line, f"{m.group(1)} has a secret-looking name (value not shown)"))
    for rel in project.code_files():
        text = project.text(rel)
        for m in PUBLIC_VAR.finditer(text):
            any_public = True
            if _secret_name(m.group(2)) and m.group(0) not in seen:
                seen.add(m.group(0))
                warns.append(Finding(rel, line_of(text, m.start()), f"code reads {m.group(0)}, a public variable "
                                     "with a secret-looking name"))
    if fails:
        return [make("NEXT-01", "fail", "A secret key is set in a public environment variable, which the build "
                     "copies into every visitor's JavaScript. Rotate it and move it to a server-only variable.",
                     fails + warns)]
    if warns:
        return [make("NEXT-01", "warn", SUSPECTED + f"{plural(len(warns), 'public environment variable')} "
                     f"with {'a secret-looking name' if len(warns) == 1 else 'secret-looking names'}. Anything with a public prefix ships to the browser.", warns)]
    if any_public or "package.json" in project.files:
        return [make("NEXT-01", "pass", "No public (NEXT_PUBLIC_, VITE_, PUBLIC_ ...) environment variable holds a "
                     "secret key or has a secret-looking name.")]
    return []


def _secret_name(name):
    return SECRET_NAME.search(name) is not None and "PUBLISHABLE" not in name


ANALYZERS = (committed_secrets, public_env)
CHECKS = ("INFRA-08", "NEXT-01")
