"""Every URL and hostname literal in the package source, held to an explicit allowlist.

docs/TRUST.md tells a reviewer which hosts this tool can contact. This test keeps that statement true: it parses every
.py file under src/agent_security_audit, collects the hosts named in URL literals (f-string parts become "{}") and the
bare hostname literals, and fails when the set differs from the lists below. A new host in the source must be added
here, with the reason it is there, and to docs/TRUST.md when the tool can contact it.

It also fails when a module other than the known ones imports a network or process module.

Not covered: catalog/*.toml. Its URLs are the `sources` links printed in reports (catalog.py loads them as text);
no code passes them to a network call.
"""

from __future__ import annotations

import ast
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = ROOT / "src" / "agent_security_audit"

# Hosts the tool connects to that are not the scanned target. Keep docs/TRUST.md in step with this list.
CONTACTED = {
    "cloudflare-dns.com": "default DNS-over-HTTPS resolver for the DNS and email checks (checks/dns_email.py "
                          "DEFAULT_RESOLVER); --dns-resolver replaces it, --no-dns turns it off",
    "api.osv.dev": "OSV vulnerability database, queried with package names and versions from lockfiles by "
                   "`asa code` and `asa scan --code` (code_audit/deps.py OSV_URL); --no-osv turns it off",
}

# Host part of every URL literal. "{}" stands for a value filled in at runtime.
URL_HOSTS = {
    # Contacted (see CONTACTED).
    "cloudflare-dns.com": "default DoH resolver",
    "api.osv.dev": "OSV querybatch endpoint",
    # Derived from the target and contacted.
    "{}": "the target's own host (transport.py plain-HTTP redirect check, runner.py www/apex twin, webapp.py), "
          "or the lab's own address in lab.py",
    "mta-sts.{}": "the target domain's MTA-STS policy host (RFC 8461), fetched by INFRA-12 (checks/network.py)",
    "{}.supabase.co": "the Supabase project the site's own JavaScript names; contacted only with --allow-supabase "
                      "(checks/supabase.py)",
    # Never contacted: header values, report metadata, examples.
    "github.com": "project homepage in the User-Agent string (http.py) and the SARIF tool URI (report.py)",
    "json.schemastore.org": "SARIF $schema value in report.py; never fetched",
    "asa-origin-probe.invalid": "Origin header value for the CORS check (checks/browser.py); .invalid never "
                                "resolves (RFC 6761)",
    "{}.asa-origin-probe.invalid": "Origin header value, suffix form (checks/browser.py)",
    "asa-origin-probe-{}": "Origin header value, prefix form (checks/browser.py); only a header, never contacted",
    "asa-origin-probe.{}": "Origin header value, subdomain form (checks/browser.py); only a header, never contacted",
    "{}{}": "lab sitemap entries built from the request's Host header (lab.py)",
    "code-audit.invalid": "placeholder URL for an in-memory Response in the static code audit (code_audit/nextjs.py)",
    "localhost:3000": "example value in an MCP tool description (mcp_server.py)",
    "cdn.asa-lab.invalid": "script URL inside a lab page (lab.py); the scanner never leaves the target origin",
    "login.asa-lab.invalid": "form action inside a lab page (lab.py)",
    "www.sitemaps.org": "XML namespace in the lab sitemap (lab.py); never fetched",
    "127.0.0.1:{}": "the lab's listen address (lab.py)",
    "h": "docstring example in scope.py",
    "h:443": "docstring example in scope.py",
}

# Bare hostname literals. Each is compared against data the tool already has (DNS answers, page HTML, the target's
# host name); none is passed to a network call.
HOST_LITERALS = {
    # Certificate authority domains matched against CAA records (checks/network.py).
    "amazon.com", "amazontrust.com", "awstrust.com", "comodo.com", "comodoca.com", "digicert.com",
    "www.digicert.com", "globalsign.com", "letsencrypt.org", "pki.goog", "sectigo.com", "ssl.com", "usertrust.com",
    # Cloud suffixes matched against CNAME targets for the dangling-DNS check (checks/network.py).
    "amazonaws.com", "azure-api.net", "azureedge.net", "azurefd.net", "azurewebsites.net", "blob.core.windows.net",
    "cloudapp.azure.com", "cloudapp.net", "elasticbeanstalk.com", "trafficmanager.net",
    # Shared hosting suffixes for the organizational-domain heuristic (checks/dns_email.py), also used by network.py.
    "vercel.app", "netlify.app", "pages.dev", "github.io", "herokuapp.com", "web.app", "firebaseapp.com",
    "onrender.com", "fly.dev", "workers.dev", "supabase.co",
    # Third-party script hosts recognized in the site's HTML for the subresource-integrity check (checks/webapp.py).
    "challenges.cloudflare.com", "connect.facebook.net", "fonts.googleapis.com", "js.hs-scripts.com", "js.stripe.com",
    "plausible.io", "static.cloudflareinsights.com", "va.vercel-scripts.com", "www.google-analytics.com",
    "www.google.com", "www.googletagmanager.com", "www.gstatic.com",
    # Open-redirect probe value placed in query parameters (checks/webapp.py REDIRECT_HOST); .invalid never
    # resolves (RFC 6761) and redirects are never followed.
    "asa-redirect-probe.invalid",
}

# Modules allowed to import network or process modules, and what each imports them for.
NETWORK_MODULES = {"socket", "ssl", "http.client", "http.server", "urllib.request", "subprocess", "smtplib",
                   "ftplib", "asyncio", "webbrowser", "requests", "httpx", "aiohttp", "xmlrpc", "telnetlib",
                   "imaplib", "poplib", "multiprocessing", "ctypes"}
NETWORK_IMPORTERS = {
    "http.py": {"socket", "ssl", "http.client"},   # the bounded client every scan request goes through
    "scope.py": {"socket"},                         # resolves *.test / *.localhost names before a scan
    "lab.py": {"http.server"},                      # the practice site, bound to 127.0.0.1
    "deps.py": {"ssl", "urllib.request"},           # the OSV query
    "transport.py": {"ssl"},                        # TLS contexts handed to http.Client.open_tls
    "network.py": {"ssl"},                          # TLS contexts handed to http.Client.open_tls
}

# Only http(s), ws(s) and f-string "{}" schemes: scheme-relative "//host" text in docstrings and regex sources is
# prose, not a URL.
URL = re.compile(r"(?i)(?:\b(?:https?|wss?)|\{\})://([^/\s\"'`<>()\\?#]+)")
LABEL = r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?"
HOSTNAME = re.compile(rf"(?i)^\.?{LABEL}(?:\.{LABEL})*\.[a-z][a-z0-9-]*[a-z0-9]\.?$")
# Bare names that look like hosts but are file names or library names.
NOT_A_HOST = re.compile(r"(?i)(^\.env\b|\.(json|lock|lockb|yaml|yml|txt|toml|js|ts|sum|md|py)$)")


def _strings(tree):
    """Every string in a module. An f-string is one string with "{}" for each value, and its parts are not
    yielded again on their own."""
    parts = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.JoinedStr):
            parts.update(id(v) for v in node.values)
    for node in ast.walk(tree):
        if isinstance(node, ast.JoinedStr):
            yield "".join(v.value if isinstance(v, ast.Constant) else "{}" for v in node.values)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in parts:
            yield node.value


def _modules():
    for path in sorted(PACKAGE.rglob("*.py")):
        yield path, ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def collect():
    urls, hosts = {}, {}
    for path, tree in _modules():
        rel = str(path.relative_to(ROOT))
        for s in _strings(tree):
            for m in URL.finditer(s):
                urls.setdefault(m.group(1).lower().rstrip("."), set()).add(rel)
            bare = s.strip()
            if HOSTNAME.match(bare) and not NOT_A_HOST.search(bare):
                hosts.setdefault(bare.lower().strip("."), set()).add(rel)
    return urls, hosts


class OutboundHostsTest(unittest.TestCase):
    def test_url_hosts_match_allowlist(self):
        urls, _ = collect()
        new = {h: sorted(f) for h, f in urls.items() if h not in URL_HOSTS}
        self.assertEqual(new, {}, "URL host not in tests/test_outbound_hosts.py URL_HOSTS; add it with the reason "
                                  "and update docs/TRUST.md if the tool contacts it")
        self.assertEqual(set(URL_HOSTS) - set(urls), set(), "allowlisted URL host no longer in the source; remove it")

    def test_hostname_literals_match_allowlist(self):
        _, hosts = collect()
        new = {h: sorted(f) for h, f in hosts.items() if h not in HOST_LITERALS}
        self.assertEqual(new, {}, "hostname literal not in HOST_LITERALS; add it with the reason")
        self.assertEqual(HOST_LITERALS - set(hosts), set(), "allowlisted hostname no longer in the source; remove it")

    def test_contacted_hosts_are_constants_and_documented(self):
        from agent_security_audit.checks.dns_email import DEFAULT_RESOLVER
        from agent_security_audit.code_audit.deps import OSV_URL
        self.assertEqual(DEFAULT_RESOLVER, "https://cloudflare-dns.com/dns-query")
        self.assertEqual(OSV_URL, "https://api.osv.dev/v1/querybatch")
        trust = (ROOT / "docs" / "TRUST.md").read_text(encoding="utf-8")
        for host in CONTACTED:
            self.assertIn(host, trust, f"docs/TRUST.md does not mention {host}")
            self.assertIn(host, URL_HOSTS)

    def test_network_imports_only_in_known_modules(self):
        found = {}
        for path, tree in _modules():
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    names = [a.name for a in node.names]
                elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                    names = [node.module]
                else:
                    continue
                for name in names:
                    if name in NETWORK_MODULES or name.split(".")[0] in NETWORK_MODULES - {"http", "urllib"}:
                        found.setdefault(path.name, set()).add(name)
        self.assertEqual(found, NETWORK_IMPORTERS)


if __name__ == "__main__":
    unittest.main()
