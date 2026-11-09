"""ACCESS-01: Supabase tables must not be readable with the public key the site ships (OSI layer 7).

Read-only and row-free: one HEAD per table with `Prefer: count=exact`. PostgREST answers with headers only, and its
Content-Range header carries how many rows the public key can see, so readability is proven without downloading a row.
Only table names and row counts are reported, never row contents.
Tables come from --supabase-table, else from `.from("name")` calls in the site's JavaScript, else from the API
root. Supabase stopped serving the API root to anon keys in 2026, so the last source usually answers 401.
"""

from __future__ import annotations

import json
import re
from urllib.parse import quote, urlsplit

from ..model import Result, failed, passed, skipped, warned
from ..scope import is_local_host
from . import are, auto, count
from .exposure import JWT, _jwt_role, scripts

PROJECT_URL = re.compile(r"https://([a-z0-9]{20})\.supabase\.co")
PUBLISHABLE = re.compile(r"\bsb_publishable_[A-Za-z0-9_-]{20,}")
MAX_TABLES = 50
# supabase.from("profiles") / db.from('orders'); Array.from and Buffer.from take other arguments, and
# supabase.storage.from("avatars") names a storage bucket, not a table.
FROM_CALL = re.compile(r"(?<!Array)(?<!Buffer)(?<!storage)\.from\(\s*[\"'`]([A-Za-z_][A-Za-z0-9_]{0,62})[\"'`]\s*\)")
# Content-Range: 0-0/42 (rows visible) or */0 (none); the total is * when the server does not count.
CONTENT_RANGE = re.compile(r"^\s*(?:\d+-\d+|\*)\s*/\s*(\d+|\*)\s*$")


def find_project(ctx):
    """(project_url, public_key) from the site's own JavaScript, or (None, None)."""
    url = key = None
    for _, text in scripts(ctx):
        if url is None:
            m = PROJECT_URL.search(text)
            if m:
                url = f"https://{m.group(1)}.supabase.co"
        if key is None:
            m = PUBLISHABLE.search(text)
            if m:
                key = m.group(0)
            else:
                for jm in JWT.finditer(text):
                    if _jwt_role(jm.group(0)) == "anon":
                        key = jm.group(0)
                        break
    return url, key


def _headers(key):
    h = {"apikey": key, "Accept": "application/json"}
    if key.startswith("eyJ"):
        h["Authorization"] = f"Bearer {key}"
    return h


def bundle_tables(ctx):
    """Table names the site's own JavaScript queries with `.from("name")`."""
    names = []
    for _, text in scripts(ctx):
        for m in FROM_CALL.finditer(text):
            if m.group(1) not in names:
                names.append(m.group(1))
    return names


def list_tables(ctx, base, key):
    resp = ctx.client.external("GET", f"{base}/rest/v1/", headers=_headers(key))
    if resp.status != 200:
        return None, resp.status
    try:
        spec = json.loads(resp.text)
    except ValueError:
        return None, resp.status
    paths = spec.get("paths") if isinstance(spec, dict) else None
    if not isinstance(paths, dict):  # not an OpenAPI document
        return None, resp.status
    names = [p.strip("/") for p in paths if p not in ("/",) and not p.startswith("/rpc/")]
    return sorted(n for n in names if n and "/" not in n), resp.status


@auto("ACCESS-01")
def anon_tables(ctx):
    base, key = find_project(ctx)
    if not base:
        return skipped("ACCESS-01", "No Supabase project URL found in the site's JavaScript.")
    if not key:
        return Result("ACCESS-01", "manual", f"Found {base} but no public key in the JavaScript; run the RLS proof "
                      "steps with your anon key.", [f"project: {base}"])
    local = is_local_host(urlsplit(ctx.target).hostname or "")
    if local and not ctx.authorized:
        # A local site's code can name any Supabase project (a cloned repo, a sample), and supabase.co is not local.
        return Result("ACCESS-01", "manual", f"The local site's JavaScript names Supabase project {base}, which is "
                      "not on this machine. If you own that project, re-run with --allow-supabase --authorized (MCP: "
                      "allow_supabase and authorized) to test whether its tables are readable with the public key.",
                      [f"project: {base}"])
    if not ctx.opt("allow_supabase"):
        return Result("ACCESS-01", "manual", f"The site uses Supabase project {base}. Re-run with --allow-supabase "
                      "(MCP: allow_supabase) to test whether its tables are readable with the public key.",
                      [f"project: {base}"])
    tables = [t for t in (ctx.opt("supabase_tables") or []) if re.fullmatch(r"[A-Za-z0-9_]+", t)]
    source, status = "named with --supabase-table", None
    if not tables:
        tables, source = bundle_tables(ctx), "found in the site's JavaScript"
    if not tables:
        listed, status = list_tables(ctx, base, key)
        tables, source = listed or [], "listed by the API root"
    if not tables:
        return Result("ACCESS-01", "manual", f"No table names found in the site's JavaScript, and the API root answered "
                      f"{status} (Supabase no longer lists tables for the anon key). Name them with --supabase-table "
                      "(take them from your migrations) to test each one.", [f"project: {base}"])
    readable, empty, refused, unproven = [], [], [], []
    ev = [f"project: {base}", f"tables {source}"]
    headers = {**_headers(key), "Prefer": "count=exact"}
    for table in tables[:MAX_TABLES]:
        resp = ctx.client.external("HEAD", f"{base}/rest/v1/{quote(table)}?select=*&limit=1", headers=headers)
        if resp.status in (200, 206):
            m = CONTENT_RANGE.match(resp.get("content-range") or "")
            if not m or m.group(1) == "*":
                unproven.append(f"{table} ({resp.status}, no row count)")
            elif int(m.group(1)) > 0:
                readable.append(f"{table} ({count(int(m.group(1)), 'row')})")
            else:
                empty.append(table)
        elif resp.status in (401, 403):
            refused.append(table)
        else:  # 404: no such table in the exposed schema (a typo, a storage bucket); 5xx: the API failed
            unproven.append(f"{table} ({resp.status})")
    if readable:
        ev.append("readable with the public key (row count only, no rows fetched): " + ", ".join(readable))
    if empty:
        ev.append("0 rows visible (RLS filtering, or the table is empty): " + ", ".join(empty))
    if refused:
        ev.append("refused (401/403): " + ", ".join(refused))
    if unproven:
        ev.append("not found or unclear: " + ", ".join(unproven))
    if len(tables) > MAX_TABLES:
        ev.append(f"only the first {MAX_TABLES} of {len(tables)} tables were tested")
    if readable:
        return failed("ACCESS-01", f"{count(len(readable), 'table')} {'shows' if len(readable) == 1 else 'show'} rows "
                      "to anyone holding the public key. Enable RLS and add policies before anything else.", ev)
    if empty:
        return warned("ACCESS-01", "No rows are visible, but empty tables cannot prove RLS. Confirm RLS is enabled on "
                      "every table (ACCESS proof steps).", ev)
    if unproven:
        return Result("ACCESS-01", "manual", f"{count(len(unproven), 'table')} {are(len(unproven))} not found or gave "
                      "no answer that proves access is refused (a 404 means the name is not a table in the exposed "
                      "schema). Check the names with --supabase-table.", ev)
    if len(tables) > MAX_TABLES:
        return Result("ACCESS-01", "manual", f"The {count(MAX_TABLES, 'table')} tested refused the public key, but "
                      f"{len(tables) - MAX_TABLES} more were not tested. Name them with --supabase-table.", ev)
    if source == "found in the site's JavaScript":  # tables the pages never query were not tested
        return Result("ACCESS-01", "manual", f"{'The' if len(refused) == 1 else 'All'} {count(len(refused), 'table')} "
                      "the site's JavaScript queries refused the public key (401/403), but other tables were not "
                      "tested. Name every table from your migrations with --supabase-table.", ev)
    return passed("ACCESS-01", f"{'The' if len(refused) == 1 else 'All'} {count(len(refused), 'table')} {source} "
                  "refused the public key (401/403).", ev)
