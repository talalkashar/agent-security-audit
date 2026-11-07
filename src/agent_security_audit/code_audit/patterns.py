"""Dangerous code patterns: raw HTML (BROWSER-09), dynamic code (API-30), shell commands (API-31), SQL built from
strings (API-32) and PostgREST filters built from strings (API-05)."""

from __future__ import annotations

import re

from .base import SUSPECTED, make, plural
from .project import Finding, is_test_path, line_of, line_text, redact, strip_js_comments

DSIH = re.compile(r"dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*")
INNER = re.compile(r"\.(?:innerHTML|outerHTML)\s*\+?=(?!=)\s*|\binsertAdjacentHTML\(\s*['\"]\w+['\"]\s*,\s*|"
                   r"\bdocument\.write(?:ln)?\(\s*")
LITERAL = re.compile(r"""^\s*(?:'(?:[^'\\\n]|\\.)*'|"(?:[^"\\\n]|\\.)*"|`(?:[^`\\$]|\\.|\$(?!\{))*`)\s*$""")
SAFE_HTML = re.compile(r"sanitiz|purify|\bxss\(|escapeHtml|JSON\.stringify|renderToStaticMarkup", re.IGNORECASE)
EVAL = re.compile(r"(?<![\w.$])eval\(|\bnew\s+Function\(|\bvm\.run\w*\(|\bvm\.Script\(|\bnew\s+vm\.Script\(")
CHILD = re.compile(r"""['"](?:node:)?child_process['"]|\bexeca\b|\bshelljs\b""")
SHELL_CALL = re.compile(r"(?<![\w.$])(?:exec|execSync|child_process\.exec|child_process\.execSync|cp\.exec|"
                        r"cp\.execSync)\(\s*")
SHELL_TRUE = re.compile(r"\bshell\s*:\s*true\b")
PY_SHELL = re.compile(r"\bos\.(?:system|popen)\(\s*(?:f['\"]|['\"][^'\"\n]*['\"]\s*(?:%|\+|\.format))|"
                      r"\bsubprocess\.\w+\((?:[^()]|\([^()]*\))*shell\s*=\s*True")
PY_EVAL = re.compile(r"(?<![\w.])(?:eval|exec)\(\s*(?!['\"])")
PY_SQL = re.compile(r"\.execute(?:many)?\(\s*(?:f['\"]|['\"][^'\"\n]*['\"]\s*(?:%|\+|\.format))")
SQL_SHAPE = re.compile(r"\b(?:select\b[\s\S]{1,300}?\bfrom|insert\s+into|update\s+[\w\".]+\s+set|delete\s+from)\b",
                       re.IGNORECASE)
TEMPLATE = re.compile(r"(?<![\w$.\])])`((?:[^`\\]|\\.)*)`")
CONCAT = re.compile(r"""(['"])((?:(?!\1)[^\\\n]|\\.)*)\1\s*\+\s*[\w$(]""")
QUERY_CALL = re.compile(r"(?:\.(?:query|execute|raw|unsafe|prepare|exec|run|all|get)|\$(?:query|execute)RawUnsafe|"
                        r"\braw)\(\s*$")
QUERY_ANY = re.compile(r"\.(?:query|execute|raw|unsafe|prepare)\(|\$(?:query|execute)RawUnsafe\(")
POSTGREST = re.compile(r"\.(?:or|filter|not|textSearch|match)\(\s*")
SUPABASE = re.compile(r"@supabase/|\bsupabase\b")


def _files(project, py=False):
    files = project.code_files()
    if py:
        files += [f for f in project.files if f.endswith(".py") and not is_test_path(f)]
    return files


def _arg(code, start, limit=400):
    """The first argument text starting at start, up to its closing bracket or a top-level comma."""
    depth, i, quote = 0, start, None
    while i < len(code) and i - start < limit:
        c = code[i]
        if quote:
            if c == "\\":
                i += 2
                continue
            if c == quote:
                quote = None
        elif c in "'\"`":
            quote = c
        elif c in "([{":
            depth += 1
        elif c in ")]}":
            if depth == 0:
                break
            depth -= 1
        elif c == "," and depth == 0:
            break
        i += 1
    return code[start:i]


def _at(project, rel, code, offset, note):
    line = line_of(code, offset)
    return Finding(rel, line, note, redact(line_text(project.text(rel), line)))


def _code(project, rel):
    return project.text(rel) if rel.endswith(".py") else strip_js_comments(project.text(rel))


def _constant(code, arg):
    """True for an UPPER_CASE module constant, or a name assigned a string literal in the same file."""
    name = arg.strip()
    if not re.fullmatch(r"[A-Za-z_$][\w$]*", name):
        return False
    if re.fullmatch(r"[A-Z][A-Z0-9_]*", name):
        return True
    m = re.search(r"\b(?:const|let|var)\s+" + re.escape(name) + r"\s*(?::\s*string\s*)?=\s*", code)
    return bool(m and LITERAL.match(_arg(code, m.end()).split(";")[0]))


def raw_html(project):
    risky, safe = [], 0
    files = _files(project)
    for rel in files:
        code = _code(project, rel)
        for rx, what in ((DSIH, "dangerouslySetInnerHTML"), (INNER, "raw HTML sink")):
            for m in rx.finditer(code):
                arg = _arg(code, m.end())
                if LITERAL.match(arg) or SAFE_HTML.search(arg) or _constant(code, arg):
                    safe += 1
                else:
                    risky.append(_at(project, rel, code, m.start(), f"{what} gets a dynamic value that is not "
                                     "visibly sanitized"))
    if risky:
        return [make("BROWSER-09", "warn", SUSPECTED + f"{plural(len(risky), 'place')} put dynamic HTML into the page "
                     "without a sanitizer call. If any of it can come from a user, it is stored XSS.", risky)]
    if files:
        return [make("BROWSER-09", "pass", "No dangerouslySetInnerHTML, innerHTML or document.write with an "
                     f"unsanitized dynamic value ({safe} literal or sanitized use(s)).")]
    return []


def dynamic_code(project):
    hits, files = [], _files(project, py=True)
    for rel in files:
        code = _code(project, rel)
        rx = PY_EVAL if rel.endswith(".py") else EVAL
        for m in rx.finditer(code):
            if rel.endswith(".py"):
                hits.append(_at(project, rel, code, m.start(), "eval/exec on a non-literal value"))
                continue
            arg = _arg(code, m.end())
            if not LITERAL.match(arg):
                hits.append(_at(project, rel, code, m.start(), "runs a string as code"))
    if hits:
        return [make("API-30", "fail", f"{plural(len(hits), 'place')} run strings as code (eval, new Function, vm). "
                     "If any part of the string comes from a request, it is remote code execution.", hits)]
    return [make("API-30", "pass", f"No eval, new Function or vm call on a dynamic string in "
                 f"{plural(len(files), 'file')}.")] if files else []


def shell_commands(project):
    hits, files = [], _files(project, py=True)
    for rel in files:
        code = _code(project, rel)
        if rel.endswith(".py"):
            for m in PY_SHELL.finditer(code):
                hits.append(_at(project, rel, code, m.start(), "shell command built from a string"))
            continue
        if not CHILD.search(code):
            continue
        for m in SHELL_CALL.finditer(code):
            arg = _arg(code, m.end())
            if ("${" in arg and arg.lstrip().startswith("`")) or CONCAT.search(arg + " ") or re.search(r"\+\s*[\w$]",
                                                                                                        arg):
                hits.append(_at(project, rel, code, m.start(), "shell command built with interpolation"))
        for m in SHELL_TRUE.finditer(code):
            hits.append(_at(project, rel, code, m.start(), "spawn/execFile with shell: true"))
    if hits:
        return [make("API-31", "fail", f"{plural(len(hits), 'shell command')} are built from strings. A value with ; "
                     "or $( ) in it runs its own command. Use execFile/spawn with an argument array and no shell.",
                     hits)]
    return [make("API-31", "pass", "No shell command built from interpolated strings.")] if files else []


def sql_strings(project):
    direct, loose, files = [], [], _files(project, py=True)
    for rel in files:
        code = _code(project, rel)
        if rel.endswith(".py"):
            for m in PY_SQL.finditer(code):
                direct.append(_at(project, rel, code, m.start(), "SQL built with an f-string, % or + in execute()"))
            continue
        queries = QUERY_ANY.search(code) is not None
        candidates = [(m.start(), m.group(1)) for m in TEMPLATE.finditer(code) if "${" in m.group(1)]
        candidates += [(m.start(), m.group(2)) for m in CONCAT.finditer(code)]
        for start, body in candidates:
            if not SQL_SHAPE.search(re.sub(r"\$\{[^}]*\}", "x", body)):
                continue
            before = code[max(0, start - 60):start]
            if QUERY_CALL.search(before):
                direct.append(_at(project, rel, code, start, "SQL string with interpolated values passed to a query"))
            elif queries:
                loose.append(_at(project, rel, code, start, "SQL string built with interpolated values"))
    if direct:
        return [make("API-32", "fail", f"{plural(len(direct), 'query')} are built by pasting values into SQL text. "
                     "Use parameters ($1, ?) or a tagged sql`` template instead.", direct + loose)]
    if loose:
        return [make("API-32", "warn", SUSPECTED + f"{plural(len(loose), 'SQL string')} are built with interpolated "
                     "values in files that run queries.", loose)]
    return [make("API-32", "pass", "No SQL text built from interpolated values or concatenation.")] if files else []


def postgrest_filters(project):
    hits, used = [], False
    for rel in _files(project):
        code = _code(project, rel)
        if not SUPABASE.search(code):
            continue
        used = True
        for m in POSTGREST.finditer(code):
            arg = _arg(code, m.end())
            if (arg.lstrip().startswith("`") and "${" in arg) or re.search(r"['\"]\s*\+|\+\s*['\"]", arg):
                hits.append(_at(project, rel, code, m.start(), "PostgREST filter string built from a variable"))
    if hits:
        return [make("API-05", "warn", SUSPECTED + f"{plural(len(hits), 'filter string')} for .or()/.filter() are "
                     "built from variables. A comma or parenthesis in user input adds its own conditions.", hits)]
    return [make("API-05", "pass", "Supabase filters are built with typed methods (.eq, .in), not from strings.")] \
        if used else []


ANALYZERS = (raw_html, dynamic_code, shell_commands, sql_strings, postgrest_filters)
CHECKS = ("BROWSER-09", "API-30", "API-31", "API-32", "API-05")
