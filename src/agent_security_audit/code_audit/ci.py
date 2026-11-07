"""GitHub Actions workflows (INFRA-15): script injection, pull_request_target with PR code, unpinned actions,
missing permissions."""

from __future__ import annotations

import re

from .base import make, plural
from .project import Finding, line_of, line_text, redact

WORKFLOW = re.compile(r"^\.github/workflows/[^/]+\.ya?ml$")
UNTRUSTED = re.compile(r"\$\{\{\s*(?:github\.event\.(?:issue|pull_request|comment|review|review_comment|discussion|"
                       r"head_commit|commits|pages|workflow_run)\b[\w.\[\]*]*\.(?:title|body|message|name|email|"
                       r"label|ref|head_branch|page_name)|github\.head_ref)\s*\}\}")
USES = re.compile(r"^\s*-?\s*uses:\s*['\"]?([\w.-]+/[\w./-]+)@([\w.-]+)", re.MULTILINE)
PR_HEAD = re.compile(r"ref:\s*\$\{\{\s*github\.event\.pull_request\.head\.(?:sha|ref)|refs/pull/")
SHA = re.compile(r"^[0-9a-f]{40}$")
TRUSTED_OWNERS = ("actions/", "github/")


def _run_blocks(text):
    """(offset, body) of every run: step, including | and > block scalars."""
    out = []
    for m in re.finditer(r"^(\s*)-?\s*run:\s*([|>][-+]?)?(.*)$", text, re.MULTILINE):
        start = m.start()
        if m.group(2) is None:
            out.append((start, m.group(3)))
            continue
        indent, lines, pos = len(m.group(1)), [], m.end() + 1
        for line in text[pos:].splitlines():
            if line.strip() and len(line) - len(line.lstrip()) <= indent:
                break
            lines.append(line)
        out.append((start, "\n".join(lines)))
    return out


def workflows(project):
    files = [f for f in project.files if WORKFLOW.search(f)]
    if not files:
        return []
    bad, weak = [], []

    def at(rel, text, offset, note):
        line = line_of(text, offset)
        return Finding(rel, line, note, redact(line_text(text, line)))

    for rel in files:
        text = project.text(rel)
        for offset, body in _run_blocks(text):
            if m := UNTRUSTED.search(body):
                bad.append(at(rel, text, offset, f"run step expands {m.group(0)} straight into the shell"))
        if re.search(r"^\s*pull_request_target\s*:|^on:.*\bpull_request_target\b|^\s*-\s*pull_request_target\b",
                     text, re.MULTILINE) and (m := PR_HEAD.search(text)):
            bad.append(at(rel, text, m.start(), "pull_request_target checks out the pull request's own code"))
        for m in USES.finditer(text):
            if not m.group(1).startswith(TRUSTED_OWNERS) and not SHA.match(m.group(2)):
                weak.append(at(rel, text, m.start(), f"third-party action {m.group(1)} pinned to a tag, not a "
                               "commit SHA"))
        if not re.search(r"^\s*permissions\s*:", text, re.MULTILINE):
            weak.append(Finding(rel, 1, "no permissions: block, so the token gets the repository default"))
    if bad:
        return [make("INFRA-15", "fail", f"{plural(len(bad), 'workflow step')} let pull request or issue text run as "
                     "code in CI. Pass the value through env: and quote it, and never check out PR code under "
                     "pull_request_target.", bad + weak)]
    if weak:
        return [make("INFRA-15", "warn", f"{plural(len(weak), 'workflow setting')} weaker than least privilege: "
                     "unpinned third-party actions or no permissions block.", weak)]
    return [make("INFRA-15", "pass", f"{plural(len(files), 'workflow')}: no script injection, third-party actions "
                 "pinned to SHAs, permissions set.")]


ANALYZERS = (workflows,)
CHECKS = ("INFRA-15",)
