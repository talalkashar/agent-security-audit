"""Supabase SQL in migrations: row-level security (ACCESS-01), permissive policies (ACCESS-02), views and
security definer functions (ACCESS-06)."""

from __future__ import annotations

import re
import tomllib

from .base import SUSPECTED, make, plural
from .project import Finding, is_test_path, line_of, line_text, redact

NAME = r'((?:"[^"]+"|[\w$]+)(?:\s*\.\s*(?:"[^"]+"|[\w$]+))?)'
NAMES = NAME[:-1] + r'(?:\s*,\s*' + NAME[1:-1] + r')*)'
FLAGS = re.IGNORECASE | re.DOTALL
CREATE_TABLE = re.compile(r"^create\s+(?:(?:global\s+|local\s+)?(temp|temporary)\s+|unlogged\s+)?table\s+"
                          r"(?:if\s+not\s+exists\s+)?" + NAME, FLAGS)
ALTER_RLS = re.compile(r"^alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?" + NAME
                       + r"\s+.*?\b(enable|disable)\s+row\s+level\s+security", FLAGS)
DROP_TABLE = re.compile(r"^drop\s+table\s+(?:if\s+exists\s+)?" + NAMES, FLAGS)
REVOKE = re.compile(r"^revoke\s+.+?\s+on\s+(?:table\s+)?" + NAMES + r"\s+from\s+(.+)$", FLAGS)
POLICY = re.compile(r'^create\s+policy\s+(?:"[^"]+"|[\w$]+)\s+on\s+' + NAME + r"(.*)$", FLAGS)
VIEW = re.compile(r"^create\s+(?:or\s+replace\s+)?(materialized\s+)?view\s+(?:if\s+not\s+exists\s+)?" + NAME
                  + r"(.*)$", FLAGS)
ALTER_VIEW_INVOKER = re.compile(r"^alter\s+view\s+(?:if\s+exists\s+)?" + NAME + r"\s+set\s*\(\s*security_invoker"
                                r"\s*=\s*(?:true|on|1)", FLAGS)
FUNCTION = re.compile(r"^create\s+(?:or\s+replace\s+)?function\s+" + NAME + r"\s*\(", FLAGS)
FUNC_PRIV = re.compile(r"^(revoke|grant)\s+(?:execute|all)\b.*?\bon\s+function\s+" + NAME
                       + r".*?\b(?:from|to)\s+([\w\s,\"]+)$", FLAGS)
SECURITY_DEFINER = re.compile(r"\bsecurity\s+definer\b", re.IGNORECASE)
SEARCH_PATH = re.compile(r"\bset\s+search_path\b", re.IGNORECASE)
INVOKER_OPTION = re.compile(r"security_invoker\s*=\s*(?:true|on|1)", re.IGNORECASE)
OWNER_COLUMN = re.compile(r"\b(user_id|owner_id|author_id|profile_id|created_by|account_id|member_id|customer_id|"
                          r"uid)\b|references\s+auth\s*\.\s*users", re.IGNORECASE)
USER_TABLES = {"profiles", "users", "accounts", "user_profiles", "customers", "orders", "messages", "payments",
               "subscriptions", "addresses"}
DOLLAR = re.compile(r"\$[A-Za-z_]*\$")
OPEN_EXPRESSIONS = {"true", "auth.role()='authenticated'", "'authenticated'=auth.role()", "auth.uid()isnotnull",
                    "auth.role()in('authenticated')", "auth.role()in('authenticated','anon')",
                    "auth.role()in('anon','authenticated')"}


def split_sql(text):
    """[(offset, statement)] with comments blanked; quotes and $tag$ bodies are kept whole."""
    buf, out, i, n, start = list(text), [], 0, len(text), 0

    def blank(a, b):
        for k in range(a, b):
            if buf[k] != "\n":
                buf[k] = " "

    while i < n:
        c = text[i]
        if text.startswith("--", i):
            j = text.find("\n", i)
            j = n if j == -1 else j
            blank(i, j)
            i = j
            continue
        if text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j == -1 else j + 2
            blank(i, j)
            i = j
            continue
        if c in "'\"":
            j = i + 1
            while j < n:
                if text[j] == c:
                    if j + 1 < n and text[j + 1] == c:
                        j += 2
                        continue
                    break
                j += 1
            i = j + 1
            continue
        if c == "$":
            m = DOLLAR.match(text, i)
            if m:
                j = text.find(m.group(0), m.end())
                i = n if j == -1 else j + len(m.group(0))
                continue
        if c == ";":
            out.append((start, "".join(buf[start:i])))
            start = i + 1
        i += 1
    out.append((start, "".join(buf[start:])))
    result = []
    for offset, stmt in out:
        lead = len(stmt) - len(stmt.lstrip())
        if stmt.strip():
            result.append((offset + lead, stmt.strip()))
    return result


def norm(name, default="public"):
    parts = [p.strip().strip('"').lower() for p in re.split(r"\s*\.\s*", name.strip(), maxsplit=1)]
    return ".".join(parts) if len(parts) == 2 else f"{default}.{parts[0]}"


def _names(text):
    return [norm(m.group(1)) for m in re.finditer(NAME, text)]


def _expr(rest, keyword):
    m = re.search(r"\b" + keyword + r"\s*\(", rest, re.IGNORECASE)
    if not m:
        return None
    depth, i = 1, m.end()
    while i < len(rest) and depth:
        depth += {"(": 1, ")": -1}.get(rest[i], 0)
        i += 1
    return rest[m.end():i - 1]


def _open(expr):
    if expr is None:
        return False
    e = re.sub(r"\s+", "", expr.lower())
    e = re.sub(r"\(select(auth\.\w+\(\))\)", r"\1", e)
    while e.startswith("(") and e.endswith(")"):
        e = e[1:-1]
    return e in OPEN_EXPRESSIONS


def exposed_schemas(project):
    text = project.text("supabase/config.toml")
    try:
        schemas = tomllib.loads(text).get("api", {}).get("schemas") if text else None
    except tomllib.TOMLDecodeError:
        schemas = None
    return {s.lower() for s in schemas} if schemas else {"public", "graphql_public"}


def parse(project):
    """Replay every .sql file in path order and return the final tables, policies, views and functions."""
    tables, policies, views, functions = {}, [], {}, {}
    sql_files = [f for f in project.files if f.endswith(".sql") and not is_test_path(f)]
    for rel in sql_files:
        text = project.text(rel)
        for offset, stmt in split_sql(text):
            line = line_of(text, offset)
            where = (rel, line, redact(line_text(text, line)))
            if m := CREATE_TABLE.match(stmt):
                if not m.group(1):
                    name = norm(m.group(2))
                    tables[name] = {"where": where, "rls": False, "revoked": set(),
                                    "owned": bool(OWNER_COLUMN.search(stmt)) or name.split(".")[1] in USER_TABLES}
            elif m := ALTER_RLS.match(stmt):
                if (t := tables.get(norm(m.group(1)))) is not None:
                    t["rls"] = m.group(2).lower() == "enable"
            elif m := DROP_TABLE.match(stmt):
                for name in _names(m.group(1)):
                    tables.pop(name, None)
            elif m := REVOKE.match(stmt):
                roles = {r.strip().strip('"').lower() for r in m.group(2).split(",")}
                for name in _names(m.group(1)):
                    if name in tables:
                        tables[name]["revoked"] |= roles
            elif m := POLICY.match(stmt):
                rest = m.group(2)
                cmd = re.search(r"\bfor\s+(all|select|insert|update|delete)\b", rest, re.IGNORECASE)
                roles = re.search(r"\bto\s+([\w\s,\"]+?)(?=\busing\b|\bwith\b|$)", rest, re.IGNORECASE)
                policies.append({"table": norm(m.group(1)), "where": where,
                                 "cmd": cmd.group(1).lower() if cmd else "all",
                                 "roles": roles.group(1).strip().lower() if roles else "public",
                                 "restrictive": re.search(r"\bas\s+restrictive\b", rest, re.IGNORECASE) is not None,
                                 "using": _expr(rest, "using"), "check": _expr(rest, r"with\s+check")})
            elif m := VIEW.match(stmt):
                options = re.split(r"\bas\b", m.group(3), maxsplit=1, flags=re.IGNORECASE)[0]
                views[norm(m.group(2))] = {"where": where, "materialized": bool(m.group(1)),
                                           "invoker": bool(INVOKER_OPTION.search(options))}
            elif m := ALTER_VIEW_INVOKER.match(stmt):
                if (v := views.get(norm(m.group(1)))) is not None:
                    v["invoker"] = True
            elif m := FUNCTION.match(stmt):
                head = DOLLAR.sub(" ", re.sub(r"\$([A-Za-z_]*)\$.*?\$\1\$", " ", stmt, flags=re.DOTALL))
                functions[norm(m.group(1))] = {"where": where, "definer": bool(SECURITY_DEFINER.search(head)),
                                               "search_path": bool(SEARCH_PATH.search(head)), "revoked": set()}
            elif (m := FUNC_PRIV.match(stmt)) and (fn := functions.get(norm(m.group(2)))) is not None:
                roles = {r.strip().strip('"').lower() for r in m.group(3).split(",")}
                if m.group(1).lower() == "revoke":
                    fn["revoked"] |= roles
                else:
                    fn["revoked"] -= roles
    return sql_files, tables, policies, views, functions


def _finding(where, note):
    rel, line, snippet = where
    return Finding(rel, line, note, snippet)


def supabase_sql(project):
    sql_files, tables, policies, views, functions = parse(project)
    if not sql_files:
        return []
    schemas = exposed_schemas(project)
    exposed = {k: v for k, v in tables.items() if k.split(".")[0] in schemas}
    results = []
    files_note = f"Read {plural(len(sql_files), 'SQL file')}; exposed schemas: {', '.join(sorted(schemas))}."

    no_rls = [_finding(t["where"], f"table {name} is created without enable row level security")
              for name, t in exposed.items()
              if not t["rls"] and not ({"anon", "authenticated"} <= t["revoked"] or "public" in t["revoked"])]
    if no_rls:
        results.append(make("ACCESS-01", "fail", f"{plural(len(no_rls), 'table')} in an exposed schema never enable "
                            "row-level security in the migrations, so the public anon key can read and write them.",
                            no_rls, [files_note]))
    elif exposed:
        results.append(make("ACCESS-01", "pass", "Every table created in an exposed schema "
                            f"({len(exposed)}) enables row-level security in the migrations (policies are judged under ACCESS-02).",
                            evidence=[files_note]))
    else:
        results.append(make("ACCESS-01", "skip", "The SQL files create no tables in an exposed schema.",
                            evidence=[files_note]))

    hard, soft = [], []
    for p in policies:
        if p["restrictive"] or p["table"].split(".")[0] not in schemas:
            continue
        if not (_open(p["using"]) or _open(p["check"])):
            continue
        who = "anyone, signed in or not" if p["roles"] in ("public", "anon") or "anon" in p["roles"] \
            else "any signed-in user"
        owned = tables.get(p["table"], {}).get("owned", p["table"].split(".")[1] in USER_TABLES)
        note = f"{p['cmd']} policy on {p['table']} lets {who} through (no owner check)"
        (hard if owned or p["cmd"] in ("update", "delete") else soft).append(_finding(p["where"], note))
    if hard:
        results.append(make("ACCESS-02", "fail", f"{plural(len(hard), 'policy')} on user-data tables allow every "
                            "row to any caller instead of the row's owner. Compare the owner column with "
                            "(select auth.uid()).", hard + soft))
    elif soft:
        results.append(make("ACCESS-02", "warn", SUSPECTED + f"{plural(len(soft), 'policy')} allow every row "
                            "(using (true) or any signed-in user). Fine only for public content tables.", soft))
    elif policies:
        results.append(make("ACCESS-02", "pass", f"None of {plural(len(policies), 'policy')} in the migrations is "
                            "open to every row or to any signed-in user.", evidence=[files_note]))

    risky = []
    for name, v in views.items():
        if name.split(".")[0] not in schemas:
            continue
        if v["materialized"]:
            risky.append(_finding(v["where"], f"materialized view {name} in an exposed schema has no row-level "
                                  "security"))
        elif not v["invoker"]:
            risky.append(_finding(v["where"], f"view {name} runs with its owner's rights and bypasses RLS "
                                  "(no security_invoker = true)"))
    for name, f in functions.items():
        if f["definer"] and name.split(".")[0] in schemas and not {"anon", "authenticated"} <= f["revoked"]:
            risky.append(_finding(f["where"], f"security definer function {name} is callable through the API"
                                  + ("" if f["search_path"] else " and has no fixed search_path")))
    if risky:
        results.append(make("ACCESS-06", "warn", SUSPECTED + f"{plural(len(risky), 'view or function')} in an "
                            "exposed schema can bypass row-level security. Use security_invoker views and move "
                            "security definer functions to a private schema.", risky))
    elif views or functions:
        results.append(make("ACCESS-06", "pass", f"{plural(len(views), 'view')} and {plural(len(functions), 'function')}"
                            " checked: views use security_invoker and no security definer function sits in an "
                            "exposed schema.", evidence=[files_note]))
    return results


ANALYZERS = (supabase_sql,)
CHECKS = ("ACCESS-01", "ACCESS-02", "ACCESS-06")
