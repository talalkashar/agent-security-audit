# Trust and data handling

This page is for a security reviewer deciding whether developers may run `agent-security-audit` (`asa`, `asa-mcp`).
Each statement names the source file it comes from, so you can check it against the code. Paths are relative to
`src/agent_security_audit/` unless they start with `tests/`, `docs/` or `.github/`.

## Summary

- The scanner sends requests to the target you name. Without opt-out flags it also sends DNS-over-HTTPS queries to
  `cloudflare-dns.com`, and a code audit sends package names and versions to `api.osv.dev`. Nothing else is
  contacted unless you pass `--allow-supabase` (the site's own Supabase project) or the target publishes an MTA-STS
  record (its own `mta-sts.` host).
- No telemetry, analytics, crash reporting or update check. Only six modules import a network or process module, and
  `tests/test_outbound_hosts.py` fails if that list or the set of host names in the source changes.
- Scanning and the code audit write only the report you ask for with `--out`. `asa install <agent> --yes` (and only
  with `--yes`) also writes that agent's config file, a `.bak` copy of it and, for two agents, the skill (see
  [What is written to disk](#what-is-written-to-disk)).
- The package has no runtime dependencies (`dependencies = []` in `pyproject.toml`). Scanning and the code audit read
  no environment variables themselves; `asa install` reads the home folder
  (`HOME`; `USERPROFILE` on Windows), `PATH` (to find `asa-mcp` and `uvx`) and, on Windows, `APPDATA`.

## Network requests

All scan traffic goes through one client, `Client` in `http.py`. It counts every connection against a request budget
(`--budget`, default 300), waits a minimum delay between connections, never follows redirects on its own, caps each
response body at 2 MiB (`MAX_BODY`), and cuts any exchange that runs past `--timeout` (`_Watchdog`). Every request
carries `User-Agent: agent-security-audit/<version> (+https://github.com/talalkashar/agent-security-audit)`
(`USER_AGENT` in `http.py`). The URL in that header is text; it is never requested.

The client has four ways to open a connection:

| Method in `http.py` | Allowed destination | Used by |
| --- | --- | --- |
| `request` | the target's scheme, host and port only (`scope.same_origin`); anything else raises `OffTarget` | almost every check, the crawl (`crawl.py`) |
| `same_host` | the target's hostname on another scheme or port | the plain-HTTP-to-HTTPS check (`checks/transport.py`) |
| `open_tls`, `probe_port` | the target's host (TLS handshake) and the target's first resolved address (TCP connect) | TLS checks (`checks/transport.py`, `checks/network.py`), port checks INFRA-24/25 |
| `external` | any `https://` URL, with certificate verification always on | the DNS resolver, the MTA-STS policy host, Supabase (below) |

### Hosts contacted

| Host | When | What is sent | How to turn it off |
| --- | --- | --- | --- |
| The target | every `asa scan` | HTTP requests to paths on the target, TLS handshakes, TCP connects (see Active probes) | n/a |
| The target's `www.` or apex twin | only when the target's root page redirects there over HTTPS | the scan then continues against that origin (`canonical_target` in `runner.py`); a redirect to any other host stops the scan with an error | n/a |
| `cloudflare-dns.com` (default) or the URL given with `--dns-resolver` | DNS and email checks INFRA-06, 07, 11, 12, 27, 28 on a public hostname | `GET <resolver>?name=<name>&type=<TXT, MX, A, CAA or DS>[&cd=1]` with `Accept: application/dns-json` (`txt_records` in `checks/dns_email.py`, `dns_query` in `checks/network.py`). Names are the target host, its `www`/apex twin, `_dmarc.`, `_mta-sts.` and `_smtp._tls.` under the mail domain, and the names between the target host and its registered domain (CAA, DS). | `--no-dns` (MCP: `no_dns`). Skipped automatically for local hosts and IP-address targets (`_why_skip` in `checks/dns_email.py`). |
| `mta-sts.<target domain>` | INFRA-12, only when DNS shows MX records and a `v=STSv1` record | `GET /.well-known/mta-sts.txt` (`mta_sts` in `checks/network.py`) | `--no-dns` |
| `<project>.supabase.co` | ACCESS-01, only with `--allow-supabase`, and only if the site's own JavaScript names a project and a public (anon or publishable) key | `GET /rest/v1/` only when neither `--supabase-table` nor the site's JavaScript names a table, then one `HEAD /rest/v1/<table>?select=*&limit=1` per table (max 50) with `Prefer: count=exact` and the site's own public key (`checks/supabase.py`). Reports table names and row counts, not rows. | leave out `--allow-supabase`; for a local target it also needs `--authorized` |
| `api.osv.dev` | `asa code`, `asa scan --code`, MCP `run_code_audit`, MCP `run_scan` with `code_path` | `POST /v1/querybatch` with JSON `{"queries": [{"package": {"ecosystem", "name"}, "version"}]}` for each package read from lockfiles, up to 500 per request (`query_osv` in `code_audit/deps.py`). No file contents, paths or project names. | `--no-osv` (MCP: `no_osv`) |

The scanned site's content is not sent to any third party. Responses from the target are read and turned into
results in memory. What leaves the machine toward non-target hosts is: DNS names derived from the target's hostname
(to the resolver), the site's own public Supabase key and table names (to that Supabase project, opt-in), and package
names and versions (to OSV).

Name resolution for the target itself uses the operating system resolver (`socket.getaddrinfo` in `http.py` and
`http.client`), not DNS-over-HTTPS. `scope.py` also resolves `*.test` and `*.localhost` names once before a scan to
confirm they point at a loopback or private address (`_resolves_off_machine`).

`asa lab` starts a practice site bound to `127.0.0.1` only (`lab.py`). It makes no outbound requests.

### What "passive" sends

Passive checks run on any target, without `--authorized`. They send no payloads and no guessed paths for sensitive
files, but not all of their traffic is what a browser sends on its own:

- a crawl of same-origin links (`crawl.py`), seeded from `/robots.txt` and `/sitemap.xml`; links whose path looks
  like sign-out, delete, unsubscribe or a similar state change are skipped (`SKIP_LINK`), and on a host scanned
  without `--authorized` the `robots.txt` Disallow paths are not visited;
- `GET /.well-known/security.txt` (INFRA-05, `checks/exposure.py`) and a `.map` request next to each same-origin
  script (NEXT-02, `checks/exposure.py`);
- `GET /` with a made-up `Origin` header, including `null` (BROWSER-07, `checks/browser.py`);
- one plain-HTTP request to the same host (INFRA-01, `checks/transport.py`);
- TLS handshakes that offer only TLS 1.0, only TLS 1.1, or only weak cipher suites, to see whether the server refuses
  them (INFRA-03, INFRA-26, `checks/transport.py`, `checks/network.py`).

These are mild and common in scanners, but they are an automated scan. Organisations that forbid scanning third-party
hosts should treat a passive scan the same way.

## What is written to disk

- `asa scan` and `asa code` write the report, only when you pass `--out FILE`; the CLI creates the parent folder if
  needed (`_emit` in `cli.py`). Without `--out` the report goes to stdout. There is no cache, log file or state
  directory; the client's response cache is an in-memory dict per run (`Client._cache` in `http.py`).
- `asa install <agent>` writes nothing without `--yes`: it prints the change. With `--yes` (`apply` in `install.py`)
  it writes the files below, and nothing else:
  - the agent's MCP config, merged with one `agent-security-audit` entry: `.mcp.json` (claude-code) or
    `.vscode/mcp.json` (vscode) in the current folder; `~/.cursor/mcp.json`; `claude_desktop_config.json` in
    `~/Library/Application Support/Claude/` (macOS), `%APPDATA%\Claude\` (Windows) or `~/.config/Claude/` (Linux);
    `~/.config/devin/mcp_config.json`, plus `~/.codeium/windsurf/mcp_config.json` when that folder exists (windsurf);
    `~/.codex/config.toml`; `~/.gemini/settings.json`; `~/.gemini/config/mcp_config.json` (antigravity)
    (`mcp_targets` in `install.py`);
  - the skill, for `claude-code` (`~/.claude/skills/agent-security-audit/SKILL.md`) and `codex`
    (`~/.agents/skills/agent-security-audit/SKILL.md`) (`skill_targets`);
  - `<file>.bak`, a copy of each existing file before it changes, beside the real file; if a `.bak` already exists it
    stops instead of overwriting it;
  - a temporary `.<file>.<random>` in the same folder, renamed over the config (`_replace_config`), and any missing
    parent folder, created with mode `0700` (`_parent_directory`).

  Project configs are never written through a symlink, and a home config only when its real path stays inside your
  home folder. A file that is not plain JSON or valid TOML is left alone and the entry is printed instead. `--yes`
  refuses to write on platforms without directory-handle support (Windows).
- The MCP server writes nothing to disk. It returns reports over stdio and redirects anything a check prints to
  stderr, so stdout carries only protocol messages (`mcp_server.py`).
- Python itself may write `__pycache__` bytecode next to the installed package, as for any Python package.

The code audit only reads. It never runs project code, a package manager or git: tracked files come from parsing
`.git/index` directly (`code_audit/project.py`). It skips `node_modules`, `.git`, build output and similar folders,
reads at most 20,000 files of at most 2 MB each, and stops walking after 100,000 entries (`SKIP_DIRS`, `MAX_FILES`,
`MAX_BYTES`, `WALK_LIMIT` in `code_audit/project.py`).

## No telemetry, analytics or auto-update

The only modules that import `socket`, `ssl`, `http.client`, `http.server`, `urllib.request` or any other network or
process module are `http.py`, `scope.py`, `lab.py`, `code_audit/deps.py`, `checks/transport.py` and
`checks/network.py`, for the reasons listed in `NETWORK_IMPORTERS` in `tests/test_outbound_hosts.py`. No module
imports `subprocess`. The package never reports usage, never checks for a newer version and never downloads code or
rule updates; the check catalog ships inside the package (`catalog/*.toml`, loaded by `catalog.py`).

## Secrets and personal data in evidence

Reports quote what the checks observed. The code keeps secret values out of that text:

- Secret formats (API keys, private keys, Supabase `service_role` JWTs) found in served JavaScript are shown as their
  first 10 characters plus `...` (first 4 for values of 14 characters or fewer) (`mask` and `find_secrets` in `checks/exposure.py`).
- A sensitive file served by the site (`/.env`, `.git` files, backups; INFRA-04) is reported by path and status with
  "contents not shown" (`checks/exposure.py`).
- Source lines quoted by the code audit pass through `redact` in `code_audit/project.py`: secret formats and JWTs are
  masked, quoted values assigned to names like `secret`, `token`, `password`, `api_key` are masked, and the line is
  capped at 160 characters. `code_audit/secrets.py`, `ci.py`, `patterns.py`, `sql.py` and `nextjs.py` use it.
- Public env vars with a secret-looking name are reported by name with "value not shown" (`code_audit/secrets.py`).
- Cookie evidence lists cookie names and flags, not values (`cookies` in `checks/browser.py`).
- Supabase results report table names and row counts; the request is a `HEAD`, so no rows are downloaded
  (`checks/supabase.py`).
- Target URLs with a username or password are refused (`normalize_target` in `scope.py`).

## Active probes

Passive checks (headers, TLS, DNS, cookies, public pages and scripts) run on any target. Checks marked
`probe = "active"` in `catalog/*.toml` run only when the target is a local development host (`localhost`, a loopback
address, or a `*.localhost` / `*.test` name that resolves to a loopback or private address) or the user passes
`--authorized` (MCP: `authorized=true`) (`owned` and `check_authorized` in `scope.py`; the gate is in `run` in
`runner.py`). Without it they report "Active probe not run". All of them go through the same budgeted, same-origin
client.

| Check | What it sends (file) |
| --- | --- |
| INFRA-04 | `GET` for known sensitive paths such as `/.env`, `/.env.local`, `/.git/` files and backups (`checks/exposure.py`) |
| API-01 | up to `--rate-limit-attempts` requests (default 30, max 60), stopping at the first 429, to the path given with `--rate-limit-path` (POST by default, `--rate-limit-method`, `--rate-limit-body`); without that flag, to a same-origin POST login form the crawl found, never one whose page or action looks like sign-up or password reset, with the fake address `asa-rate-limit-probe@example.invalid` (`login_endpoint` in `checks/ratelimit.py`) |
| API-02 | `GET /asa-missing-<random>`, `POST /api/asa-missing-<random>` with body `{`, and the same malformed body to a login endpoint found on the site (`checks/exposure.py`) |
| API-19 | requests to the site's redirect parameters with `asa-redirect-probe.invalid` in several encodings; responses are read, redirects not followed (`checks/webapp.py`) |
| API-20, 21, 22 | `GET` for directory listings, debug and status endpoints, and API description files (`checks/webapp.py`) |
| API-23 | `POST` of a GraphQL introspection query to common GraphQL paths (`checks/webapp.py`) |
| API-24 | one `TRACE /` with an `X-Asa-Trace-Probe: <random>` header (`checks/webapp.py`) |
| INFRA-24, 25 | a TCP connect, closed at once with nothing sent, to database, cache, Docker API and remote-admin ports on the target's address (`DATA_PORTS`, `ADMIN_PORTS` in `checks/network.py`; `probe_port` in `http.py`). Turn off with `--no-ports`. |
| ACCESS-01 | the Supabase requests above; also needs `--allow-supabase` |

`--insecure` (accept a self-signed certificate) is refused for any non-local host (`Client.__init__` in `http.py`).

## MCP server and target-controlled text

`asa-mcp` speaks MCP over stdio (`mcp_server.py`). Report fields quote text the scanned site or project chose
(header values, cookie names, `security.txt` fields, paths, code). Before any of it reaches the agent:

- `mark_untrusted` and `_data` in `mcp_server.py` collapse C0/C1 control characters and line separators, drop
  invisible format and private-use characters (`strip_invisible` in `report.py`: bidi overrides, tag characters,
  zero-width characters, variation selectors), and cap lengths (summary 1,000 characters, evidence 1,000 characters
  per item and 20 items, paths 300).
- Every result carries an `untrusted_data` note saying that the quoted text is data, never instructions; the server's
  `instructions` say the same (`UNTRUSTED_NOTE`, `INSTRUCTIONS` in `mcp_server.py`).
- The Markdown, HTML and SARIF renderers escape the same fields for their format (`_clean`, `_md_escape`, HTML escaping
  in `report.py`), so a value cannot start a new Markdown line, inject a link or add HTML.
- Tool errors (for example a redirect host or a malformed status line the target sent) get the same control-character
  strip, length cap and untrusted-data note as a summary (`_tool_error` in `mcp_server.py`).
- The MCP `run_scan` tool takes the same `authorized`, `allow_supabase`, `no_dns`, `no_ports` and `no_osv` switches
  as the CLI.

These measures reduce, but cannot remove, the chance that an agent acts on text an attacker placed on a scanned site.

## Dependencies

- Runtime: none. `pyproject.toml` has `dependencies = []`; the package uses only the Python standard library
  (Python 3.11 or later).
- Development: `ruff==0.17.4`, pinned in `.github/workflows/ci.yml`; `build==1.6.1`, pinned in
  `.github/workflows/release.yml`. Tests use the standard library `unittest`.
- CI actions are pinned by commit SHA, and the workflow token is read-only (`permissions: contents: read` in
  `.github/workflows/ci.yml`).

## Release provenance

Releases are git tags (`v0.2.0` is the first public one); the install commands in the docs pin that tag. When the
owner publishes a GitHub release, `.github/workflows/release.yml` runs two jobs:

- `build`: checks out the release (`persist-credentials: false`), installs `build==1.6.1` and runs `python -m build`
  to make the sdist and wheel, then stores them as a workflow artifact.
- `publish`: downloads that artifact and uploads it to PyPI with `pypa/gh-action-pypi-publish` through Trusted
  Publishing (OIDC). Only this job has `id-token: write`, it runs in the `pypi` environment, and no PyPI token is
  stored in the repository.

The workflow token is otherwise read-only (`permissions: contents: read`) and every action is pinned by commit SHA.
`docs/CI.md` describes the workflows and `docs/INSTALL.md` the one-time PyPI setup. To check what you install, compare
the tag you pin with the release page, or read the source at that tag before installing it.

## Verify it yourself

Run these from a checkout.

```sh
# Hosts named anywhere in the source, held to an explicit allowlist, plus the list of network-importing modules
PYTHONPATH=src python3 -m unittest tests.test_outbound_hosts -v

# Every URL literal and every network, process, file-write and environment call
grep -rnoE "https?://[^\"' )]+" src/agent_security_audit --include='*.py' | sort -u
grep -rnE "import (socket|ssl|subprocess|urllib\.request|http\.client|http\.server)|from (socket|ssl|subprocess|urllib\.request|http)" src/agent_security_audit
grep -rnE "os\.environ|getenv|Path\.home|shutil\.which|subprocess|urlopen|create_connection|getaddrinfo" src/agent_security_audit
grep -rnE "open\([^)]*['\"]w|O_WRONLY|write_text|write_bytes|mkdir|makedirs|rename|tempfile" src/agent_security_audit

# Use your own DNS-over-HTTPS resolver (any endpoint that answers application/dns-json), or none at all
asa scan https://your-site.example --dns-resolver https://doh.internal.example/dns-query
asa scan https://your-site.example --no-dns --no-ports

# Watch the OSV lookup through a logging proxy: urllib honors HTTPS_PROXY (and NO_PROXY)
HTTPS_PROXY=http://127.0.0.1:8080 asa code . --format json --out /tmp/asa-code.json

# Scan traffic does not use HTTPS_PROXY (see limitations); capture it at the network layer instead
sudo tcpdump -n -i any 'tcp port 443 or tcp port 80' &
asa scan https://your-site.example --no-ports
```

## Known limitations

- Scan traffic ignores proxy environment variables. `http.py` connects directly with `http.client` and `socket`, so
  `HTTPS_PROXY` covers only the OSV request (made with `urllib.request` in `code_audit/deps.py`). Use a firewall rule
  or packet capture to observe or restrict scan traffic.
- The MCP `run_scan` tool has no resolver option: it always uses `cloudflare-dns.com` unless `no_dns` is set
  (`tool_run_scan` passes `"dns_resolver": None` in `mcp_server.py`).
- `--dns-resolver` must be an `https://` URL (`Client.external` refuses other schemes) and must speak the JSON DoH
  format.
- DNS names sent to the resolver reveal which domain you are scanning to the resolver's operator. This is on by default
  for public hosts; use `--no-dns` or your own resolver where that is not acceptable.
- `--authorized` (MCP: `authorized=true`) is a statement by whoever runs the tool, or by the agent calling it. The tool
  cannot check that the statement is true. The skill and the MCP instructions tell agents to set it only after the
  user says they own the site or have written permission.
- The local-host check in `scope.py` resolves `*.test` and `*.localhost` names once, before the scan; a resolver that
  changes its answer mid-scan is not covered.
- `tests/test_outbound_hosts.py` scans string literals in the Python source. A host assembled from pieces at run time,
  or one inside `catalog/*.toml`, is outside its reach; the catalog URLs are reference links printed in reports and are
  never requested.
- Secret masking matches known formats and secret-looking names. A secret in an unrecognized format inside a quoted
  source line or a target response can appear in a report.
- The Python standard library honors some environment variables the package does not read itself, such as
  `SSL_CERT_FILE` for the CA bundle used by `ssl.create_default_context`.
