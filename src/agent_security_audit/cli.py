"""Command line: asa list | show | rules | lab | scan | code | install, and `asa <url>` as a shortcut for `asa scan <url>`."""

from __future__ import annotations

import argparse
import json
import os
import shlex
import shutil
import sys
from urllib.parse import urlsplit

from . import __version__, catalog, code_audit, install, report, runner
from .checks.dns_email import DEFAULT_RESOLVER
from .checks.ratelimit import ALLOWED_METHODS as ALLOWED_RATE_LIMIT_METHODS
from .scope import ScopeError, check_dns_resolver, is_local_host

FAIL_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}
COMMANDS = ("list", "show", "rules", "lab", "scan", "code", "install")
FORMATS = ("md", "json", "sarif", "html")
MAX_TIME = 300.0
EXIT_NOT_RUN = 3
FAIL_ON_ERROR = ("all", "any", "none")
MAIN_EPILOG = """examples:
  asa lab &                                  start the practice site at http://127.0.0.1:8642
  asa scan http://127.0.0.1:8642            prove the defenses on a running site
  asa http://localhost:3000                  shortcut: a URL first is the same as `asa scan <url>`
  asa scan http://localhost:3000 --code .    scan and read the project's source in one run
  asa code .                                 audit the source only (nothing is executed)
  asa show AUTH-01                           one check in full: risk, build rule, proof steps

exit codes (scan and code):
  0  nothing at or above --fail-on failed
  1  a failed check at or above --fail-on (default high)
  2  usage or scope error (bad URL, refused target, unknown check id)
  3  checks could not run (see --fail-on-error)

Run `asa <command> --help` for each command's options."""
FAIL_ON_ERROR_HELP = ("when an error (a check that could not run) makes the run exit 3: 'all' (default) when every "
                      "check that tried to run errored, or a check named with --check errored; 'any' on any error; "
                      "'none' never. A failed check (exit 1) takes precedence. With --fail-on none the default is "
                      "'none', so --fail-on none still always exits 0")
EXTENSIONS = {".md": "md", ".json": "json", ".sarif": "sarif", ".html": "html", ".htm": "html"}
SCAN_EPILOG = """output:
  --out FILE        write the full report to FILE; the format comes from --format, else from the
                    extension (.md .json .sarif .html), else Markdown
  no --out          a terminal gets a short summary (counts and what to fix first); a pipe or file
                    gets the full Markdown report. --format always prints that full format.
  progress          one updating line on stderr while a terminal is attached; --quiet turns it off

ownership:
  Any URL gets every passive check (headers, TLS, DNS, cookies, public code). Active probes
  (sensitive-file fetches, login rate limit, malformed requests, Supabase reads) run on local hosts,
  and on other hosts only with --authorized: you own the site or have written permission.

exit codes:
  0 ok · 1 a failed check at or above --fail-on · 2 usage or scope error · 3 checks could not run
  (--fail-on-error; default: every check that tried errored, or a check named with --check errored)

`asa <url> ...` is the same as `asa scan <url> ...`."""


def scan_flags(*, authorized, allow_supabase, auto_only, no_dns, dns_resolver, no_ports, rate_limit_path,
               rate_limit_method, budget, max_time, max_pages, code, osv, insecure=False, checks=None):
    """The settings of a scan, as recorded in the report's scope block (CLI and MCP alike)."""
    return {"authorized": bool(authorized), "allow_supabase": bool(allow_supabase), "auto_only": bool(auto_only),
            "insecure": bool(insecure), "no_dns": bool(no_dns),
            "dns_resolver": None if no_dns else (dns_resolver or DEFAULT_RESOLVER), "no_ports": bool(no_ports),
            "rate_limit_path": rate_limit_path, "rate_limit_method": rate_limit_method, "budget": budget,
            "max_time": max_time, "max_pages": max_pages, "checks": list(checks or []), "code": code,
            "osv": bool(osv)}


def rate_limit_method(value):
    """The rate-limit probe's HTTP method, upper-cased; only ALLOWED_RATE_LIMIT_METHODS (POST), so the probe can
    never send DELETE, PUT or another method that changes data."""
    method = str(value or "POST").strip().upper()
    if method not in ALLOWED_RATE_LIMIT_METHODS:
        raise ValueError(f"rate-limit method must be {' or '.join(sorted(ALLOWED_RATE_LIMIT_METHODS))}, "
                         f"got {report.shorten(str(value), 20)!r}")
    return method


def rules_markdown(checks):
    lines = ["# Build rules", "", ("Follow every rule while writing the code. Each one has a proof test in "
             "`asa show <ID>`."), ""]
    area = None
    for c in checks:
        if c.area != area:
            area = c.area
            lines += ([""] if lines[-1] else []) + [f"## {area}", ""]  # a heading needs a blank line before it
        lines.append(f"- **{c.id} {c.title}** ({c.severity}): {c.build}")
    return "\n".join(lines) + "\n"


def show_markdown(c):
    lines = [f"# {c.id} {c.title}", "",
             f"Severity: {c.severity} · OSI layer {c.layer} · {', '.join(c.cwe) or 'no CWE'}"
             + (f" · ASVS {', '.join(c.asvs)}" if c.asvs else "")
             + (f" · OWASP {', '.join(c.owasp)}" if c.owasp else "") + f" · mode: {c.mode}"
             + f" · stacks: {', '.join(c.stacks)}", "",
             "## Risk", "", c.risk, "", "## Build rule", "", c.build, "", "## Proof test", "", c.proof, "",
             "## Sources", ""]
    lines += [f"- [{s.title}]({s.url})" for s in c.sources]
    return "\n".join(lines) + "\n"


def _owasp(values):
    """--owasp values, checked against the OWASP ids so a typo is an error, not an empty list."""
    queries = _csv(values)
    if values and not queries:
        raise ValueError("--owasp needs a category such as A01, API1 or A03:2021")
    bad = [q for q in queries or [] if not catalog.owasp_query_valid(q)]
    if bad:
        raise ValueError(f"unknown OWASP category {', '.join(bad)}; use A01 to A10, API1 to API10, or a full id "
                         "such as A03:2021, A03:2025 or API1:2023")
    return queries


def _csv(values):
    out = []
    for v in values or []:
        out += [x.strip() for x in v.split(",") if x.strip()]
    return out or None


def _stacks(values):
    """--stack values, checked against the catalog's stacks so a typo is an error, not an unfiltered list."""
    stacks = _csv(values)
    bad = [s for s in stacks or [] if s not in catalog.STACKS]
    if bad:
        raise ValueError(f"unknown stack {', '.join(bad)}; valid values: {', '.join(catalog.STACKS)}")
    return stacks


def _code_hint(args):
    """One line suggesting --code . when a local site is scanned from what looks like its project folder."""
    host = urlsplit(args.target if "://" in args.target else "http://" + args.target).hostname or ""
    if args.code or not is_local_host(host) or not os.path.isfile("package.json"):
        return None
    return "asa: tip: this folder has a package.json; add --code . to settle code checks from the source"


def _say(msg):
    """An error line for the terminal. Messages can quote the target (a redirect host, a status line), so control
    characters and escape sequences are removed and the length is capped."""
    print(f"asa: {report._plain(str(msg), 600)}", file=sys.stderr)


def run_lab(mode, port):
    import time

    from . import lab

    try:
        server, url = lab.serve(mode, port)
    except OSError as exc:
        _say(f"could not listen on port {port} ({exc.strerror or exc}); pass another --port")
        return 2
    print(f"asa lab ({mode}) at {url}  -  try: asa scan {url} --rate-limit-path /api/login  (Ctrl-C to stop)",
          file=sys.stderr)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        server.shutdown()
    return 0


def build_parser():
    p = argparse.ArgumentParser(prog="asa", description="Security checks you build in, then prove on the running site.",
                                epilog=MAIN_EPILOG, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="version", version=f"agent-security-audit {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    ls = sub.add_parser("list", help="list checks")
    ls.add_argument("--area", action="append")
    ls.add_argument("--stack", action="append", help=f"only checks for these stacks: {', '.join(catalog.STACKS)}")
    ls.add_argument("--owasp", action="append",
                    help="only checks mapped to these OWASP categories: A03 (every list), A03:2021, API1:2023")
    ls.add_argument("--json", action="store_true")

    sh = sub.add_parser("show", help="show one check in full")
    sh.add_argument("id")
    sh.add_argument("--json", action="store_true")

    ru = sub.add_parser("rules", help="build rules for a stack, as Markdown")
    ru.add_argument("--stack", action="append",
                    help=f"comma-separated, from: {', '.join(catalog.STACKS)} (default: all)")
    ru.add_argument("--area", action="append")

    lb = sub.add_parser("lab", help="run the local practice site (vulnerable or fixed) to try the scanner on",
                        description="Serve a practice site on 127.0.0.1 only, to try the scanner on. Stop it with "
                                    "Ctrl-C.", epilog="example: asa lab --mode fixed --port 8643",
                        formatter_class=argparse.RawDescriptionHelpFormatter)
    lb.add_argument("--mode", choices=("vulnerable", "fixed"), default="vulnerable",
                    help="vulnerable (default): the controls are missing, so checks fail; fixed: the same site with "
                         "the controls in place, so they pass")
    lb.add_argument("--port", type=int, default=8642,
                    help="port on 127.0.0.1 to listen on (default 8642; 0 picks a free port)")

    sc = sub.add_parser("scan", help="run the proof tests against a running site", epilog=SCAN_EPILOG,
                        formatter_class=argparse.RawDescriptionHelpFormatter)
    sc.add_argument("target", help="URL of the site to check")
    sc.add_argument("--authorized", action="store_true",
                    help="you own this site or have written permission: also run the active probes")
    sc.add_argument("--check", action="append", help="only these check ids (repeat or comma-separate)")
    sc.add_argument("--area", action="append")
    sc.add_argument("--stack", action="append", help=f"only checks for these stacks: {', '.join(catalog.STACKS)}")
    sc.add_argument("--format", choices=FORMATS, help="md, json, sarif or html (see output below)")
    sc.add_argument("--out", help="write the report here instead of stdout")
    sc.add_argument("-q", "--quiet", action="store_true", help="no progress line on stderr")
    sc.add_argument("--auto-only", action="store_true", help="only the scanner checks; leave out code and logged-in checks")
    sc.add_argument("--fail-on", choices=("critical", "high", "medium", "low", "none"), default="high",
                    help="exit 1 when a failed check is at least this severe (default: high)")
    sc.add_argument("--fail-on-error", choices=FAIL_ON_ERROR, help=FAIL_ON_ERROR_HELP)
    sc.add_argument("--rate-limit-path", help="endpoint to prove rate limiting on, e.g. /api/auth/login")
    sc.add_argument("--rate-limit-method", default="POST", type=str.upper, choices=sorted(ALLOWED_RATE_LIMIT_METHODS),
                    help="HTTP method of the rate-limit probe: POST only, so it never sends a method that changes "
                         "data")
    sc.add_argument("--rate-limit-body", help="request body for the rate-limit probe (use fake credentials)")
    sc.add_argument("--rate-limit-content-type", default="application/json")
    sc.add_argument("--rate-limit-attempts", type=int, default=30, help="max requests for the probe (max 60)")
    sc.add_argument("--allow-supabase", action="store_true",
                    help="also test the Supabase project the site's code points to (read-only, row counts only; "
                         "on a local target this also needs --authorized)")
    sc.add_argument("--supabase-table", action="append",
                    help="Supabase table to test (default: names from .from() calls in the site's JavaScript)")
    sc.add_argument("--dns-resolver", help=f"DNS-over-HTTPS JSON endpoint, https only (default {DEFAULT_RESOLVER}); "
                                           "the DNS and email checks send it the target's DNS names")
    sc.add_argument("--no-dns", action="store_true", help="skip DNS and email checks (they query a public resolver)")
    sc.add_argument("--no-ports", action="store_true",
                    help="skip the TCP connect checks on database and admin ports (INFRA-24, INFRA-25)")
    sc.add_argument("--insecure", action="store_true", help="accept self-signed TLS (local hosts only)")
    sc.add_argument("--max-pages", type=int, default=25,
                    help="most same-origin pages the crawl visits (default 25); it never uses more than half the budget")
    sc.add_argument("--max-depth", type=int, default=3, help="most link hops from the home page the crawl follows")
    sc.add_argument("--budget", type=int, default=300, help="maximum requests to the target")
    sc.add_argument("--timeout", type=float, default=10.0,
                    help="seconds for one full response (default 10); a server that trickles bytes is cut off")
    sc.add_argument("--max-time", type=float, default=MAX_TIME,
                    help=f"time budget for the whole scan in seconds (default {MAX_TIME:g}; 0 = no limit). Checks "
                         "still waiting for a request when it runs out, or that would pass on a crawl it cut short, "
                         "report error \"not run: time budget\"")
    sc.add_argument("--code", metavar="PATH", help="also audit the site's source code at PATH and merge the results "
                    "(code evidence settles manual checks; a live fail always stands)")
    sc.add_argument("--no-osv", action="store_true", help="skip the OSV lookups (api.osv.dev): the Next.js version "
                    "found in the site's JavaScript (NEXT-04) and, with --code, the dependency lookup")

    co = sub.add_parser("code", help="audit a project's source code statically (nothing is executed)")
    co.add_argument("path", nargs="?", default=".", help="project folder (default: the current folder)")
    co.add_argument("--check", action="append", help="only these check ids (repeat or comma-separate)")
    co.add_argument("--area", action="append")
    co.add_argument("--format", choices=FORMATS, help="md, json, sarif or html (default as for scan)")
    co.add_argument("--out", help="write the report here instead of stdout")
    co.add_argument("-q", "--quiet", action="store_true", help="no progress output on stderr (as for scan)")
    co.add_argument("--fail-on", choices=("critical", "high", "medium", "low", "none"), default="high",
                    help="exit 1 when a failed check is at least this severe (default: high)")
    co.add_argument("--fail-on-error", choices=FAIL_ON_ERROR, help=FAIL_ON_ERROR_HELP)
    co.add_argument("--no-osv", action="store_true",
                    help="skip the dependency vulnerability lookup (the only network call, to api.osv.dev)")
    co.add_argument("--timeout", type=float, default=20.0, help="seconds to wait for OSV")

    ins = sub.add_parser("install", help="add the MCP server (and the skill, where supported) to an agent's config",
                         description="Adds the asa-mcp server to one agent's MCP config, plus the skill for "
                         "claude-code and codex. claude-code and vscode write to the current folder (.mcp.json, "
                         ".vscode/mcp.json); the others write to your home folder. Without --yes it only prints the "
                         "change. Existing servers are kept; a changed file is first copied to <file>.bak.")
    ins.add_argument("agent", choices=install.AGENTS)
    ins.add_argument("--yes", action="store_true", help="write the change (default: dry run that prints it)")
    ins.add_argument("--uvx", action="store_true",
                     help="run the server with `uvx --from agent-security-audit==<version> asa-mcp` (the pinned PyPI release) instead of the installed asa-mcp")
    return p


def _is_tty(stream):
    try:
        return bool(stream.isatty())
    except (AttributeError, ValueError):
        return False


def _output_format(args):
    if args.format:
        return args.format
    if args.out:
        return EXTENSIONS.get(os.path.splitext(args.out)[1].lower(), "md")
    return "summary" if _is_tty(sys.stdout) else "md"


def _progress(done, total, check_id, status):
    sys.stderr.write(f"\r\x1b[Kasa: [{done}/{total}] {check_id} {status}")
    sys.stderr.flush()


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] not in COMMANDS and not argv[0].startswith("-"):
        argv.insert(0, "scan")  # `asa <url>` is `asa scan <url>`
    try:
        return _main(argv)
    except BrokenPipeError:
        # The reader went away (for example `asa list | head`); stop quietly.
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
        return 1


def _main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        if args.cmd == "list":
            checks = runner.select(areas=_csv(args.area), stacks=_stacks(args.stack))
            if owasp := _owasp(args.owasp):
                checks = [c for c in checks if any(catalog.owasp_match(c, q) for q in owasp)]
            if args.json:
                print(json.dumps([c.to_dict() for c in checks], indent=2))
            else:
                for c in checks:
                    print(f"{c.id:<11} {c.severity:<8} L{c.layer} {c.mode:<8} {c.title}")
            return 0
        if args.cmd == "show":
            try:
                c = catalog.find(args.id)
            except catalog.CatalogError as exc:
                raise catalog.CatalogError(f"{exc}; run `asa list` to see the check ids") from exc
            print(json.dumps(c.to_dict(), indent=2) if args.json else show_markdown(c), end="")
            return 0
        if args.cmd == "rules":
            print(rules_markdown(runner.select(areas=_csv(args.area), stacks=_stacks(args.stack))), end="")
            return 0
        if args.cmd == "lab":
            return run_lab(args.mode, args.port)
        if args.cmd == "install":
            try:
                return install.run(args.agent, yes=args.yes, uvx=args.uvx)
            except install.InstallError as exc:
                _say(exc)
                return 2
        if args.cmd == "code":
            hosts, started = set(), runner.utc_now()
            target, results = runner.audit_code(args.path, osv=not args.no_osv, timeout=args.timeout,
                                                ids=_csv(args.check), areas=_csv(args.area), hosts=hosts)
            scope = report.run_scope(interface="cli", mode="code", started=started, finished=runner.utc_now(),
                                     hosts=hosts, flags={"osv": not args.no_osv, "checks": _csv(args.check) or [],
                                                         "areas": _csv(args.area) or []})
            return _emit(args, target, results, scope)
        if args.dns_resolver:
            check_dns_resolver(args.dns_resolver)
        options = {
            "rate_limit_path": args.rate_limit_path, "rate_limit_method": rate_limit_method(args.rate_limit_method),
            "rate_limit_body": args.rate_limit_body, "rate_limit_content_type": args.rate_limit_content_type,
            "rate_limit_attempts": args.rate_limit_attempts, "allow_supabase": args.allow_supabase,
            "no_dns": args.no_dns, "no_ports": args.no_ports, "supabase_tables": _csv(args.supabase_table),
            "dns_resolver": args.dns_resolver, "max_pages": args.max_pages, "max_depth": args.max_depth,
            "osv": not args.no_osv,
        }
        if args.max_time < 0:
            raise ValueError("--max-time must be 0 (no limit) or more seconds")
        stacks = _stacks(args.stack)
        hint = _code_hint(args)
        if hint:
            print(hint, file=sys.stderr)
        authorized = args.authorized
        show_progress = not args.quiet and _is_tty(sys.stderr)
        record, started = {}, runner.utc_now()
        try:
            target, results = runner.run(
                args.target, authorized=authorized, ids=_csv(args.check), areas=_csv(args.area),
                stacks=stacks, options=options, insecure=args.insecure, budget=args.budget,
                timeout=args.timeout, include_manual=not args.auto_only, max_time=args.max_time or None,
                progress=_progress if show_progress else None, record=record)
        finally:
            if show_progress:
                sys.stderr.write("\r\x1b[K")
                sys.stderr.flush()
        hosts = set(record.get("hosts_contacted", []))
        if args.code:
            selected = {c.id for c in runner.select(_csv(args.check), _csv(args.area), stacks)}
            _, code_results = runner.audit_code(args.code, osv=not args.no_osv, hosts=hosts)
            results = code_audit.merge(results, [r for r in code_results if r.check_id in selected])
        flags = scan_flags(authorized=authorized, allow_supabase=args.allow_supabase, auto_only=args.auto_only,
                           no_dns=args.no_dns, dns_resolver=args.dns_resolver, no_ports=args.no_ports,
                           rate_limit_path=args.rate_limit_path, rate_limit_method=options["rate_limit_method"],
                           budget=args.budget, max_time=args.max_time, max_pages=args.max_pages, code=args.code,
                           osv=not args.no_osv, insecure=args.insecure, checks=_csv(args.check))
        scope = report.run_scope(interface="cli", mode="scan+code" if args.code else "scan", flags=flags,
                                 started=record.get("started", started), finished=runner.utc_now(), hosts=hosts,
                                 requests_sent=record.get("requests_sent"))
    except (ScopeError, catalog.CatalogError, ValueError) as exc:
        _say(exc)
        return 2
    return _emit(args, target, results, scope)


def _width():
    return max(60, min(120, shutil.get_terminal_size((100, 24)).columns))


def _next_step(args, target, results):
    """The summary's last line: what to do about the manual results."""
    n = report.counts(results)["manual"]
    if not n:
        return ""
    checks = f"{n} manual check{'s' if n != 1 else ''}"
    if getattr(args, "cmd", "") == "code":
        return (f"Next: {checks} need the running site or a logged-in test: "
                f"asa scan <url> --code {shlex.quote(target)} (asa show <ID> gives each one's proof steps).")
    if getattr(args, "code", None):
        return (f"Next: {checks} need a logged-in test or a config review: asa show <ID> gives each one's proof "
                "steps.")
    return (f"Next: {checks} need the code or a logged-in test: asa scan {shlex.quote(target)} --code . "
            "(run it from the project folder; asa show <ID> gives each one's proof steps).")


def exit_code(args, results):
    """0, 1 (a failed check at or above --fail-on) or 3 (checks could not run, per --fail-on-error)."""
    checks = catalog.by_id()
    if args.fail_on != "none":
        limit = FAIL_RANK[args.fail_on]
        if any(r.status == "fail" and FAIL_RANK[checks[r.check_id].severity] <= limit for r in results):
            return 1
    policy = getattr(args, "fail_on_error", None) or ("none" if args.fail_on == "none" else "all")
    errors = [r for r in results if r.status == "error"]
    if policy == "none" or not errors:
        return 0
    if policy == "any":
        return EXIT_NOT_RUN
    tried = [r for r in results if r.status not in ("manual", "skip")]
    named = {c.upper() for c in _csv(getattr(args, "check", None)) or []}
    # A firewall challenge mid-scan stops every later check, so the report is cut short: never a clean exit.
    blocked = any(r.summary.startswith(runner.BLOCKED_PREFIX) for r in errors)
    if blocked or len(errors) == len(tried) or any(r.check_id in named for r in errors):
        return EXIT_NOT_RUN
    return 0


def _emit(args, target, results, scope=None):
    fmt = _output_format(args)
    if fmt == "summary":
        # Quoted, so a folder with spaces or shell characters gives a command that can be pasted as is.
        again = f"asa {'code' if getattr(args, 'cmd', '') == 'code' else 'scan'} {shlex.quote(target)}"
        hint = f"Full report with evidence: {again} --out asa-report.html"
        text = report.summary_text(target, results, hint, width=_width(),
                                   next_step=_next_step(args, target, results))
    else:
        render = {"md": report.to_markdown, "json": report.to_json, "sarif": report.to_sarif,
                  "html": report.to_html}[fmt]
        text = render(target, results, scope=scope)
    if args.out:
        try:
            os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
            with open(args.out, "w", encoding="utf-8") as fh:
                fh.write(text)
        except OSError as exc:
            _say(f"could not write {args.out}: {exc.strerror or exc}")
            return 2
        c = report.counts(results)
        print(f"asa: wrote {args.out} ({c['fail']} fail, {c['warn']} warn, {c['error']} error, {c['pass']} pass)",
              file=sys.stderr)
    else:
        print(text, end="")
    code = exit_code(args, results)
    if code == EXIT_NOT_RUN:
        n = report.counts(results)["error"]
        _say(f"exit {EXIT_NOT_RUN}: {n} check{'s' if n != 1 else ''} could not run (see the error rows; "
             "--fail-on-error none ignores this)")
    return code


if __name__ == "__main__":
    sys.exit(main())
