"""ACCESS-01: Supabase tables must not be readable with the public key the site ships (OSI layer 7).

Read-only: one `limit=1` GET per table. Only table names are reported, never row contents.
Tables come from --supabase-table, else from `.from("name")` calls in the site's JavaScript, else from the API
root. Supabase stopped serving the API root to anon keys in 2026, so the last source usually answers 401.
"""

from __future__ import annotations

import json
import re
from urllib.parse import quote, urlsplit

from ..model import Result, failed, passed, skipped, warned
from ..scope import is_local_host
from . import auto
from .exposure import JWT, _jwt_role, scripts

PROJECT_URL = re.compile(r"https://([a-z0-9]{20})\.supabase\.co")
PUBLISHABLE = re.compile(r"\bsb_publishable_[A-Za-z0-9_-]{20,}")
MAX_TABLES = 50
# supabase.from("profiles") / db.from('orders'); Array.from and Buffer.from take other arguments.
FROM_CALL = re.compile(r"(?<!Array)(?<!Buffer)\.from\(\s*[\"'`]([A-Za-z_][A-Za-z0-9_]{0,62})[\"'`]\s*\)")


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
    names = [p.strip("/") for p in (spec.get("paths") or {}) if p not in ("/",) and not p.startswith("/rpc/")]
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
    readable, empty, blocked, ev = [], [], [], [f"project: {base}", f"tables {source}"]
    for table in tables[:MAX_TABLES]:
        resp = ctx.client.external("GET", f"{base}/rest/v1/{quote(table)}?select=*&limit=1", headers=_headers(key))
        if resp.status == 200:
            try:
                rows = json.loads(resp.text)
            except ValueError:
                rows = []
            (readable if rows else empty).append(table)
        else:
            blocked.append(table)
    if readable:
        ev.append("readable with the public key: " + ", ".join(readable))
    if empty:
        ev.append("returned no rows (RLS filtering, or the table is empty): " + ", ".join(empty))
    if blocked:
        ev.append("refused: " + ", ".join(blocked))
    if len(tables) > MAX_TABLES:
        ev.append(f"only the first {MAX_TABLES} of {len(tables)} tables were tested")
    if readable:
        return failed("ACCESS-01", f"{len(readable)} table(s) return rows to anyone holding the public key. Enable RLS "
                      "and add policies before anything else.", ev)
    if empty:
        return warned("ACCESS-01", "No rows came back, but empty tables cannot prove RLS. Confirm RLS is enabled on "
                      "every table (ACCESS proof steps).", ev)
    return passed("ACCESS-01", f"All {min(len(tables), MAX_TABLES)} tables refused the public key.", ev)
