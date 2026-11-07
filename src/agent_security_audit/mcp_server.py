"""MCP server over stdio: newline-delimited JSON-RPC 2.0, standard library only.

Run it as `asa-mcp` or `python -m agent_security_audit.mcp_server`. stdout carries protocol messages only;
anything else (logs, stray prints from checks) goes to stderr.
"""

from __future__ import annotations

import contextlib
import json
import sys

from . import __version__, catalog, report, runner
from .cli import rules_markdown, show_markdown
from .scope import ScopeError

PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")
LATEST = PROTOCOL_VERSIONS[0]

INSTRUCTIONS = (
    "agent-security-audit has two modes. BUILD mode: before writing a Next.js/Supabase/Vercel site, call "
    "build_rules (filter by stack/area) and follow every rule; get_check shows one control in full. VERIFY mode: "
    "once the site runs, call run_scan on it. Each control comes back pass (with evidence), fail (with the fix), "
    "or manual/skip (check in code, does not apply, or an active probe that was not run). Any URL gets the "
    "passive checks. Active probes run on local hosts, and on other hosts only with authorized=true, set only when "
    "the user owns the site or has written permission. The claim is that every listed check was built in and proven, not that the site has no flaws."
)

AREAS = sorted({c.area for c in catalog.load()})
_str_list = {"type": "array", "items": {"type": "string"}}


def _enum_list(values):
    return {"type": "array", "items": {"type": "string", "enum": list(values)}}


TOOLS = [
    {
        "name": "list_checks",
        "title": "List checks",
        "description": "List the security checks in the catalog (id, area, title, severity, OSI layer, mode, "
                       "stacks). Filter by area, stack or mode.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "area": {"type": "string", "enum": AREAS, "description": "only checks in this area"},
                "stack": {"type": "string", "enum": list(catalog.STACKS),
                          "description": "only checks that apply to this stack ('any' checks always included)"},
                "mode": {"type": "string", "enum": list(catalog.MODES),
                         "description": "auto: proven by the scanner; assisted: code check, then an "
                                        "optional logged-in test; review: code or config check"},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "get_check",
        "title": "Get one check",
        "description": "Full detail for one check: risk, build rule, proof test, CWE, sources.",
        "inputSchema": {
            "type": "object",
            "properties": {"id": {"type": "string", "description": "check id, e.g. BROWSER-03"}},
            "required": ["id"],
            "additionalProperties": False,
        },
    },
    {
        "name": "build_rules",
        "title": "Build rules",
        "description": "BUILD mode: the rules to follow while writing the code, as Markdown, grouped by area.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "stack": {**_enum_list(catalog.STACKS), "description": "e.g. [\"nextjs\", \"supabase\"]; default all"},
                "area": {**_enum_list(AREAS), "description": "only these areas; default all"},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "run_scan",
        "title": "Run proof tests",
        "description": "VERIFY mode: run the proof tests against a running site. Any URL gets the passive checks. Active "
                       "probes (sensitive files, login rate limit, malformed requests, Supabase reads) run on local "
                       "hosts, and on other hosts only when authorized is true, which you may set only when the "
                       "user owns the site or has written permission to test it.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "site URL, e.g. http://localhost:3000"},
                "authorized": {"type": "boolean", "default": False,
                               "description": "the user owns this site or has written permission: also run active probes"},
                "checks": {**_str_list, "description": "only these check ids"},
                "areas": {**_enum_list(AREAS), "description": "only these areas"},
                "stacks": {**_enum_list(catalog.STACKS), "description": "only checks for these stacks"},
                "auto_only": {"type": "boolean", "default": True,
                              "description": "leave out the code and logged-in checks (assisted/review)"},
                "rate_limit_path": {"type": "string", "description": "endpoint to prove rate limiting on, "
                                                                     "e.g. /api/auth/login"},
                "rate_limit_method": {"type": "string", "default": "POST"},
                "rate_limit_body": {"type": "string",
                                    "description": "request body for the rate-limit probe; use fake credentials"},
                "rate_limit_attempts": {"type": "integer", "minimum": 1, "maximum": 60, "default": 30},
                "allow_supabase": {"type": "boolean", "default": False,
                                   "description": "also test the Supabase project the site points to "
                                                  "(read-only, row counts only); on a local target this also "
                                                  "needs authorized=true, since the project is not local"},
                "supabase_tables": {**_str_list, "description": "tables to test (default: names from .from() calls "
                                                         "in the site's JavaScript)"},
                "no_dns": {"type": "boolean", "default": False,
                           "description": "skip DNS and email checks (they query a public resolver)"},
                "no_ports": {"type": "boolean", "default": False,
                             "description": "skip the TCP connect checks on database and admin ports"},
                "max_pages": {"type": "integer", "minimum": 1, "maximum": 200, "default": 25,
                              "description": "most same-origin pages the crawl visits"},
                "format": {"type": "string", "enum": ["json", "md", "html"], "default": "json",
                           "description": "the report format; a second text block always carries a short "
                                          "summary with the failed checks to fix first"},
            },
            "required": ["target"],
            "additionalProperties": False,
        },
    },
]
TOOLS_BY_NAME = {t["name"]: t for t in TOOLS}
_JSON_TYPES = {"string": str, "boolean": bool, "integer": int, "array": list, "object": dict}


class ToolError(Exception):
    """Reported to the client as a tool result with isError true."""


class RpcError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def log(msg):
    print(f"asa-mcp: {msg}", file=sys.stderr, flush=True)


def _validate(schema, args):
    if not isinstance(args, dict):
        raise ToolError("arguments must be an object")
    props = schema.get("properties", {})
    for key in schema.get("required", []):
        if key not in args:
            raise ToolError(f"missing required argument: {key}")
    for key, value in args.items():
        spec = props.get(key)
        if spec is None:
            raise ToolError(f"unknown argument: {key}")
        if value is None:
            continue
        typ = _JSON_TYPES[spec["type"]]
        if not isinstance(value, typ) or (typ is int and isinstance(value, bool)):
            raise ToolError(f"{key} must be {spec['type']}")
        if spec["type"] == "array":
            item = spec.get("items", {})
            if not all(isinstance(v, str) for v in value):
                raise ToolError(f"{key} must be a list of strings")
            bad = [v for v in value if "enum" in item and v not in item["enum"]]
            if bad:
                raise ToolError(f"{key}: unknown value(s) {', '.join(bad)}; allowed: {', '.join(item['enum'])}")
        if "enum" in spec and value not in spec["enum"]:
            raise ToolError(f"{key} must be one of {', '.join(spec['enum'])}")
        if spec["type"] == "integer" and not spec.get("minimum", value) <= value <= spec.get("maximum", value):
            raise ToolError(f"{key} must be between {spec['minimum']} and {spec['maximum']}")


def tool_list_checks(area=None, stack=None, mode=None):
    checks = runner.select(areas=[area] if area else None, stacks=[stack] if stack else None,
                           modes=[mode] if mode else None)
    rows = [{"id": c.id, "area": c.area, "title": c.title, "severity": c.severity, "osi_layer": c.layer,
             "mode": c.mode, "stacks": list(c.stacks)} for c in checks]
    return json.dumps({"count": len(rows), "checks": rows}, indent=2)


def tool_get_check(id):
    c = catalog.find(id)
    return json.dumps(c.to_dict(), indent=2) + "\n\n" + show_markdown(c)


def tool_build_rules(stack=None, area=None):
    return rules_markdown(runner.select(areas=area or None, stacks=stack or None))


def tool_run_scan(target, authorized=False, checks=None, areas=None, stacks=None, auto_only=True,
                  rate_limit_path=None, rate_limit_method=None, rate_limit_body=None, rate_limit_attempts=None,
                  allow_supabase=False, supabase_tables=None, no_dns=False, no_ports=False, max_pages=None,
                  format="json"):
    options = {
        "rate_limit_path": rate_limit_path, "rate_limit_method": rate_limit_method or "POST",
        "rate_limit_body": rate_limit_body, "rate_limit_content_type": "application/json",
        "rate_limit_attempts": 30 if rate_limit_attempts is None else rate_limit_attempts,
        "allow_supabase": bool(allow_supabase), "no_dns": bool(no_dns), "no_ports": bool(no_ports),
        "supabase_tables": supabase_tables or None,
        "dns_resolver": None, "max_pages": max_pages,
    }
    final, results = runner.run(target, authorized=bool(authorized), ids=checks or None, areas=areas or None,
                                stacks=stacks or None, options=options, include_manual=not auto_only)
    render = {"md": report.to_markdown, "html": report.to_html}.get(format, report.to_json)
    return [render(final, results), report.summary_text(final, results)]


HANDLERS = {
    "list_checks": tool_list_checks,
    "get_check": tool_get_check,
    "build_rules": tool_build_rules,
    "run_scan": tool_run_scan,
}


def call_tool(params):
    name = params.get("name")
    if name not in TOOLS_BY_NAME:
        raise RpcError(-32602, f"unknown tool: {name}")
    args = params.get("arguments") or {}
    try:
        _validate(TOOLS_BY_NAME[name]["inputSchema"], args)
        args = {k: v for k, v in args.items() if v is not None}
        # Checks must never write to stdout: it carries the protocol.
        with contextlib.redirect_stdout(sys.stderr):
            out = HANDLERS[name](**args)
    except (ToolError, ScopeError, catalog.CatalogError, ValueError) as exc:
        return {"content": [{"type": "text", "text": str(exc)}], "isError": True}
    except Exception as exc:  # noqa: BLE001 - a tool failure is a tool result, not a protocol error
        log(f"{name} failed: {type(exc).__name__}: {exc}")
        return {"content": [{"type": "text", "text": f"{name} failed: {type(exc).__name__}: {exc}"}],
                "isError": True}
    texts = out if isinstance(out, list) else [out]
    return {"content": [{"type": "text", "text": t} for t in texts], "isError": False}


def handle(msg):
    """Return the response dict for one message, or None when no reply is due."""
    if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0" or not isinstance(msg.get("method"), str):
        if isinstance(msg, dict) and "method" not in msg and ("result" in msg or "error" in msg):
            return None  # a response to a request we never send; ignore
        return {"jsonrpc": "2.0", "id": msg.get("id") if isinstance(msg, dict) else None,
                "error": {"code": -32600, "message": "invalid request"}}
    method, params = msg["method"], msg.get("params") or {}
    is_notification = "id" not in msg
    try:
        if not isinstance(params, dict):
            raise RpcError(-32602, "params must be an object")
        if method == "initialize":
            asked = params.get("protocolVersion")
            result = {
                "protocolVersion": asked if asked in PROTOCOL_VERSIONS else LATEST,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "agent-security-audit", "version": __version__},
                "instructions": INSTRUCTIONS,
            }
        elif method == "ping":
            result = {}
        elif method == "tools/list":
            result = {"tools": TOOLS}
        elif method == "tools/call":
            result = call_tool(params)
        elif method.startswith("notifications/"):
            return None
        else:
            raise RpcError(-32601, f"method not found: {method}")
    except RpcError as exc:
        if is_notification:
            return None
        return {"jsonrpc": "2.0", "id": msg["id"], "error": {"code": exc.code, "message": str(exc)}}
    except Exception as exc:  # noqa: BLE001 - report any failure as a JSON-RPC error, never crash the server
        log(f"internal error on {method}: {type(exc).__name__}: {exc}")
        if is_notification:
            return None
        return {"jsonrpc": "2.0", "id": msg["id"], "error": {"code": -32603, "message": "internal error"}}
    if is_notification:
        return None
    return {"jsonrpc": "2.0", "id": msg["id"], "result": result}


def serve(stdin=None, stdout=None):
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    log(f"agent-security-audit {__version__} MCP server on stdio")
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError as exc:
            reply = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": f"parse error: {exc}"}}
        else:
            reply = handle(msg)
        if reply is not None:
            stdout.write(json.dumps(reply, separators=(",", ":")) + "\n")
            stdout.flush()


def main():
    try:
        serve()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    main()
