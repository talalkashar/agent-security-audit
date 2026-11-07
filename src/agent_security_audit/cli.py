"""Command line: asa list | show | rules | scan."""

from __future__ import annotations

import argparse
import json
import os
import sys

from . import __version__, catalog, report, runner
from .scope import ScopeError

FAIL_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def rules_markdown(checks):
    lines = ["# Build rules", "", ("Follow every rule while writing the code. Each one has a proof test in "
             "`asa show <ID>`."), ""]
    area = None
    for c in checks:
        if c.area != area:
            area = c.area
            lines += [f"## {area}", ""]
        lines.append(f"- **{c.id} {c.title}** ({c.severity}): {c.build}")
    return "\n".join(lines) + "\n"


def show_markdown(c):
    lines = [f"# {c.id} {c.title}", "",
             f"Severity: {c.severity} · OSI layer {c.layer} · {', '.join(c.cwe) or 'no CWE'}"
             + (f" · ASVS {', '.join(c.asvs)}" if c.asvs else "") + f" · mode: {c.mode}"
             + f" · stacks: {', '.join(c.stacks)}", "",
             "## Risk", "", c.risk, "", "## Build rule", "", c.build, "", "## Proof test", "", c.proof, "",
             "## Sources", ""]
    lines += [f"- [{s.title}]({s.url})" for s in c.sources]
    return "\n".join(lines) + "\n"


def _csv(values):
    out = []
    for v in values or []:
        out += [x.strip() for x in v.split(",") if x.strip()]
    return out or None


def run_lab(mode, port):
    import time

    from . import lab

    try:
        server, url = lab.serve(mode, port)
    except OSError as exc:
        print(f"asa: could not listen on port {port} ({exc.strerror or exc}); pass another --port", file=sys.stderr)
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
    p = argparse.ArgumentParser(prog="asa", description="Security checks you build in, then prove on the running site.")
    p.add_argument("--version", action="version", version=f"agent-security-audit {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    ls = sub.add_parser("list", help="list checks")
    ls.add_argument("--area", action="append")
    ls.add_argument("--stack", action="append")
    ls.add_argument("--json", action="store_true")

    sh = sub.add_parser("show", help="show one check in full")
    sh.add_argument("id")
    sh.add_argument("--json", action="store_true")

    ru = sub.add_parser("rules", help="build rules for a stack, as Markdown")
    ru.add_argument("--stack", action="append", help="e.g. nextjs,supabase,vercel (default: all)")
    ru.add_argument("--area", action="append")

    lb = sub.add_parser("lab", help="run the local practice site (vulnerable or fixed) to try the scanner on")
    lb.add_argument("--mode", choices=("vulnerable", "fixed"), default="vulnerable")
    lb.add_argument("--port", type=int, default=8642)

    sc = sub.add_parser("scan", help="run the proof tests against a running site")
    sc.add_argument("target", help="URL of a site you own or are authorized to test")
    sc.add_argument("--authorized", action="store_true",
                    help="confirm you own this non-local site or have written permission to test it")
    sc.add_argument("--check", action="append", help="only these check ids (repeat or comma-separate)")
    sc.add_argument("--area", action="append")
    sc.add_argument("--stack", action="append")
    sc.add_argument("--format", choices=("md", "json", "sarif"), default="md")
    sc.add_argument("--out", help="write the report here instead of stdout")
    sc.add_argument("--auto-only", action="store_true", help="only the scanner checks; leave out code and logged-in checks")
    sc.add_argument("--fail-on", choices=("critical", "high", "medium", "low", "none"), default="high",
                    help="exit 1 when a failed check is at least this severe (default: high)")
    sc.add_argument("--rate-limit-path", help="endpoint to prove rate limiting on, e.g. /api/auth/login")
    sc.add_argument("--rate-limit-method", default="POST")
    sc.add_argument("--rate-limit-body", help="request body for the rate-limit probe (use fake credentials)")
    sc.add_argument("--rate-limit-content-type", default="application/json")
    sc.add_argument("--rate-limit-attempts", type=int, default=30, help="max requests for the probe (max 60)")
    sc.add_argument("--allow-supabase", action="store_true",
                    help="also test the Supabase project the site's code points to (read-only, row counts only; "
                         "on a local target this also needs --authorized)")
    sc.add_argument("--supabase-table", action="append",
                    help="Supabase table to test (default: names from .from() calls in the site's JavaScript)")
    sc.add_argument("--dns-resolver", help="DNS-over-HTTPS JSON endpoint (default https://cloudflare-dns.com/dns-query)")
    sc.add_argument("--no-dns", action="store_true", help="skip DNS and email checks (they query a public resolver)")
    sc.add_argument("--no-ports", action="store_true",
                    help="skip the TCP connect checks on database and admin ports (INFRA-24, INFRA-25)")
    sc.add_argument("--insecure", action="store_true", help="accept self-signed TLS (local hosts only)")
    sc.add_argument("--budget", type=int, default=300, help="maximum requests to the target")
    sc.add_argument("--timeout", type=float, default=10.0)
    return p


def main(argv=None):
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
            checks = runner.select(areas=_csv(args.area), stacks=_csv(args.stack))
            if args.json:
                print(json.dumps([c.to_dict() for c in checks], indent=2))
            else:
                for c in checks:
                    print(f"{c.id:<11} {c.severity:<8} L{c.layer} {c.mode:<8} {c.title}")
            return 0
        if args.cmd == "show":
            c = catalog.find(args.id)
            print(json.dumps(c.to_dict(), indent=2) if args.json else show_markdown(c), end="")
            return 0
        if args.cmd == "rules":
            print(rules_markdown(runner.select(areas=_csv(args.area), stacks=_csv(args.stack))), end="")
            return 0
        if args.cmd == "lab":
            return run_lab(args.mode, args.port)
        options = {
            "rate_limit_path": args.rate_limit_path, "rate_limit_method": args.rate_limit_method,
            "rate_limit_body": args.rate_limit_body, "rate_limit_content_type": args.rate_limit_content_type,
            "rate_limit_attempts": args.rate_limit_attempts, "allow_supabase": args.allow_supabase,
            "no_dns": args.no_dns, "no_ports": args.no_ports, "supabase_tables": _csv(args.supabase_table), "dns_resolver": args.dns_resolver,
        }
        target, results = runner.run(
            args.target, authorized=args.authorized, ids=_csv(args.check), areas=_csv(args.area),
            stacks=_csv(args.stack), options=options, insecure=args.insecure, budget=args.budget,
            timeout=args.timeout, include_manual=not args.auto_only)
    except (ScopeError, catalog.CatalogError, ValueError) as exc:
        print(f"asa: {exc}", file=sys.stderr)
        return 2
    render = {"md": report.to_markdown, "json": report.to_json, "sarif": report.to_sarif}[args.format]
    text = render(target, results)
    if args.out:
        try:
            os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
            with open(args.out, "w", encoding="utf-8") as fh:
                fh.write(text)
        except OSError as exc:
            print(f"asa: could not write {args.out}: {exc.strerror or exc}", file=sys.stderr)
            return 2
        c = report.counts(results)
        print(f"asa: wrote {args.out} ({c['fail']} failed, {c['warn']} warnings, {c['pass']} passed)", file=sys.stderr)
    else:
        print(text, end="")
    if args.fail_on == "none":
        return 0
    checks = catalog.by_id()
    limit = FAIL_RANK[args.fail_on]
    return 1 if any(r.status == "fail" and FAIL_RANK[checks[r.check_id].severity] <= limit for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
