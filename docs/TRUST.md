# Trust and data handling

This page is for a security reviewer deciding whether developers may run `agent-security-audit` (`asa`, `asa-mcp`).
Each statement names the source file it comes from, so you can check it against the code. Paths are relative to
`src/agent_security_audit/` unless they start with `tests/`, `docs/` or `.github/`.

## Summary

- The scanner sends requests to the target you name. Without opt-out flags it also sends DNS-over-HTTPS queries to
  `cloudflare-dns.com`, a scan of a Next.js site sends the Next.js version found in its JavaScript to
  `api.osv.dev`, and a code audit sends package names and versions to `api.osv.dev`. Nothing else is
  contacted unless you pass `--allow-supabase` (the site's own Supabase project) or the target publishes an MTA-STS
  record (its own `mta-sts.` host).
- No telemetry, analytics, crash reporting or update check. Only six modules import a network or process module, and
  `tests/test_outbound_hosts.py` fails if that list or the set of host names in the source changes.
- Scanning (`asa scan`, MCP `run_scan`) and the code audit (`asa code`, MCP `run_code_audit`) write only the report
  you ask for with `--out`. `asa install <agent> --yes` is the one command that writes anything else: the agent config
  files it lists in its dry run, a `<file>.bak` copy of each file it changes, and a copy of the skill for Claude Code
  and Codex (see [`asa install`](#asa-install-only-with---yes)). Without `--yes` it writes nothing.
- The package has no runtime dependencies (`dependencies = []` in `pyproject.toml`). The only environment variable it
  reads itself is `APPDATA`, in `asa install` on Windows (`_appdata` in `install.py`). Standard library calls read a
  few more on its behalf; they are listed in [Environment variables](#environment-variables).
- You are responsible for having authorization for what you scan; see [Acceptable use](#acceptable-use).

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
| `<project>.supabase.co` | ACCESS-01, only with `--allow-supabase`, and only if the site's own JavaScript names a project and a public (anon or publishable) key | `GET /rest/v1/` and one `HEAD /rest/v1/<table>?select=*&limit=1` per table (max 50) with `Prefer: count=exact` and the site's own public key (`checks/supabase.py`). Reports table names and row counts, not rows. | leave out `--allow-supabase`; for a local target it also needs `--authorized` |
| `api.osv.dev` | `asa code`, `asa scan --code`, MCP `run_code_audit`, MCP `run_scan` with `code_path` | `POST /v1/querybatch` with JSON `{"queries": [{"package": {"ecosystem", "name"}, "version"}]}` for each package read from lockfiles, up to 500 per request (`query_osv` in `code_audit/deps.py`). No file contents, paths or project names. | `--no-osv` (MCP: `no_osv`) |
| `api.osv.dev` | `asa scan` and MCP `run_scan` (NEXT-04), only when exactly one Next.js version string is found in the JavaScript the scan already read | `POST /v1/query` with JSON `{"package": {"ecosystem": "npm", "name": "next"}, "version": "<version>"}`, at most 3 pages (`query_osv_vulns` in `code_audit/deps.py`, called from `checks/nextjs_version.py`). No URL, host name or other content of the target. | `--no-osv` (MCP: `no_osv`) |

The scanned site's content is not sent to any third party. Responses from the target are read and turned into
results in memory. What leaves the machine toward non-target hosts is: DNS names derived from the target's hostname
(to the resolver), the site's own public Supabase key and table names (to that Supabase project, opt-in), package
names and versions (to OSV), and the Next.js version string found in the site's JavaScript (to OSV, without the
site's address).

Name resolution for the target itself uses the operating system resolver (`socket.getaddrinfo` in `http.py` and
`http.client`), not DNS-over-HTTPS. `scope.py` also resolves `*.test` and `*.localhost` names once before a scan to
confirm they point at a loopback or private address (`_resolves_off_machine`).

`asa lab` starts a practice site bound to `127.0.0.1` only (`lab.py`). It makes no outbound requests.

### Scope record in every report

Each report (Markdown, HTML, JSON, MCP) has a `scope` section: tool version, interface (CLI or MCP), mode, the flags in
effect (`--authorized`, `--allow-supabase`, `--no-dns`, `--no-ports`, `--no-osv` and the rest), the hosts contacted
besides the target (the DNS resolver, the Supabase project and `api.osv.dev`, each listed only when it was
contacted), the number of requests sent, and the start and end time in UTC. SARIF carries the same data in
`invocations` (`run_scope` in `report.py`).

## What is written to disk

- The report, only when you pass `--out FILE`; the CLI creates the parent folder if needed (`_emit` in `cli.py`).
  Without `--out` the report goes to stdout.
- Nothing else during a scan or code audit. There is no cache, log file or state directory. The client's response
  cache is an in-memory dict per run (`Client._cache` in `http.py`).
- `asa install <agent> --yes` writes agent configuration (next section). It is the only other code that writes files.
- The search in [Verify it yourself](#verify-it-yourself) for `open(` with a write mode, `write_text`, `write_bytes`,
  `mkdir`, `makedirs` and `tempfile` finds `_emit` in `cli.py` (the report and its folder) and these lines in
  `install.py`: the `tempfile` import and `tempfile.gettempdir()` (used only to recognise an `asa-mcp` inside a temp
  folder; no temp file is created through `tempfile`), `os.mkdir` (a missing config folder, mode 0700), and the two
  `os.fdopen` writes in `_replace_config` (the `.bak` copy and the new file). The new file is first written under a
  random hidden name in the same folder with `os.open(..., O_CREAT | O_EXCL | O_NOFOLLOW)` and then renamed over the
  config, so a crash never leaves a half-written config.
- The MCP server writes nothing to disk. It returns reports over stdio and redirects anything a check prints to
  stderr, so stdout carries only protocol messages (`mcp_server.py`).
- Python itself may write `__pycache__` bytecode next to the installed package, as for any Python package.

### `asa install` (only with `--yes`)

`asa install <agent>` without `--yes` is a dry run: it prints the server command it chose (and why), every file it
would create or change, and the exact text it would add, and writes nothing. With `--yes` (`apply` in `install.py`) it
may write:

| Agent | Files |
| --- | --- |
| `claude-code` | `.mcp.json` in the current folder; the skill at `~/.claude/skills/agent-security-audit/SKILL.md` |
| `claude-desktop` | macOS `~/Library/Application Support/Claude/claude_desktop_config.json`; Windows `%APPDATA%\Claude\claude_desktop_config.json`; Linux `~/.config/Claude/claude_desktop_config.json` |
| `cursor` | `~/.cursor/mcp.json` |
| `vscode` | `.vscode/mcp.json` in the current folder |
| `windsurf` | `~/.config/devin/mcp_config.json` (Windows `%APPDATA%\devin\mcp_config.json`), and `~/.codeium/windsurf/mcp_config.json` when that folder already exists |
| `codex` | `~/.codex/config.toml` (one table appended); the skill at `~/.agents/skills/agent-security-audit/SKILL.md` |
| `gemini` | `~/.gemini/settings.json` |
| `antigravity` | `~/.gemini/config/mcp_config.json` |

How it writes (`mcp_targets`, `skill_targets`, `_replace_config` in `install.py`):

- It merges one `agent-security-audit` entry and never removes or rewrites another server. A file that is not plain
  JSON or valid TOML, or that already has an `agent-security-audit` entry with other settings, is left as is.
- Before changing an existing file it copies it to `<file>.bak` beside the real file (mode preserved). It refuses to
  overwrite an existing `.bak`.
- Missing parent folders are created with mode 0700. Project configs (`.mcp.json`, `.vscode/mcp.json`) are never
  written through a symlink; a home config may follow a symlink only when the real file stays inside the home folder.
- Writes go through directory file descriptors with no-follow opens. Where the platform lacks them (Windows), `--yes`
  refuses and the dry run shows the text to add by hand.
- The server command it writes is the installed `asa-mcp` by its path when that is a stable install, or
  `uvx --from agent-security-audit==<version> asa-mcp` (the pinned PyPI release; for this version
  `agent-security-audit==0.2.0`) when `asa-mcp` is missing or sits in a
  temporary folder, a uv cache or a project virtualenv (`server_choice`). When an agent later starts that `uvx`
  command, uv (not this package) downloads the pinned release from PyPI.
- `asa install` makes no network requests.

### Environment variables

| Variable | Read by | Why |
| --- | --- | --- |
| `APPDATA` | `_appdata` in `install.py` | Claude Desktop and Windsurf config folders on Windows (`asa install` only) |
| `PATH` (and `PATHEXT` on Windows) | `shutil.which` in `install.py` | find the installed `asa-mcp` (`asa install` only) |
| `HOME` (`USERPROFILE` on Windows) | `Path.home()` in `install.py` | the home folder for agent configs (`asa install` only) |
| `TMPDIR`, `TEMP`, `TMP` | `tempfile.gettempdir()` in `install.py` | recognise an `asa-mcp` inside a temp folder (`asa install` only) |
| `HTTPS_PROXY`, `NO_PROXY` and similar | `urllib.request` in `code_audit/deps.py` | the OSV lookup honours a proxy; scan traffic does not (see limitations) |
| `SSL_CERT_FILE`, `SSL_CERT_DIR` | `ssl.create_default_context` | the CA bundle for HTTPS connections |

A search for `os.environ` and `getenv` in the package finds only `_appdata` in `install.py`.

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
- Cloud metadata services (`169.254.169.254`, `metadata.google.internal` and the like) and link-local addresses are
  refused as targets, even with `--authorized`: by name, by address, and again after DNS resolution (`scope.py`).
- A custom DNS resolver must be an `https://` URL without a username or password (`check_dns_resolver` in
  `scope.py`).

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
| API-01 | up to `--rate-limit-attempts` requests (default 30, max 60) to a login endpoint, stopping at the first 429 (`checks/ratelimit.py`). The endpoint is `--rate-limit-path` (always `POST`: `--rate-limit-method` accepts only `POST`, and the MCP enum is `["POST"]`; with `--rate-limit-body`). A named path that looks like sign-up, registration, invitation or password reset is refused, or, without it, a same-origin `POST` login form the crawl found: a page or action that looks like a login and has exactly one password field, never one that looks like sign-up, registration, invitation or password reset (`login_endpoint`, `LOGIN_PATH`, `NOT_LOGIN_PATH`). The auto-detected form gets a fake email (`asa-rate-limit-probe@example.invalid`) and a fake password. |
| API-02 | `GET /asa-missing-<random>`, `POST /api/asa-missing-<random>` with body `{`, and the same malformed body to a login endpoint found on the site (`checks/exposure.py`) |
| API-19 | requests to the site's redirect parameters with `asa-redirect-probe.invalid` in several encodings; responses are read, redirects not followed (`checks/webapp.py`) |
| API-20, 21, 22 | `GET` for directory listings, debug and status endpoints, and API description files (`checks/webapp.py`) |
| API-23 | `POST` of a GraphQL introspection query to common GraphQL paths (`checks/webapp.py`) |
| API-24 | one `TRACE /` with an `X-Asa-Trace-Probe: <random>` header (`checks/webapp.py`) |
| INFRA-24, 25 | a TCP connect, closed at once with nothing sent, to database, cache, Docker API and remote-admin ports on the target's address (`DATA_PORTS`, `ADMIN_PORTS` in `checks/network.py`; `probe_port` in `http.py`). Turn off with `--no-ports`. |
| ACCESS-01 | the Supabase requests above; also needs `--allow-supabase` |

`--insecure` (accept a self-signed certificate) is refused for any non-local host (`Client.__init__` in `http.py`).

## Acceptable use

The tool runs where you point it; the scope gate limits what it sends, not whether you may send it.

- **The operator is responsible for authorization.** Whoever runs `asa`, or lets an agent run it, is responsible for
  having permission to test every target. Unauthorized testing can break computer-misuse laws (for example the CFAA in
  the US or the Computer Misuse Act in the UK) and a site's terms of service. The maintainer gives no authorization to
  test anyone's site.
- **Passive scans of third-party sites** still send traffic a browser never would. Within the request budget, on
  the same origin: page, script, `robots.txt`, `sitemap.xml` and `/.well-known/security.txt` GETs (`crawl.py`,
  `security_txt` in `checks/exposure.py`); up to three guessed `<script>.map` paths for scripts that do not name a
  source map (`source_maps` in `checks/exposure.py`); one plain-HTTP request to the same host
  (`checks/transport.py`); TLS handshakes including legacy-version and weak-cipher attempts (`checks/transport.py`,
  `checks/network.py`); CORS requests with a test `Origin` and with `Origin: null` (`checks/browser.py`); and DNS
  lookups. No attack payloads and no form submissions, and robots.txt `Disallow` paths are not visited unless the
  target is local or you passed `--authorized` (`honor_robots` in `crawl.py`). Your organisation's policy may still forbid automated scans
  of sites you do not own; follow it.
- **Active probes only with ownership or written permission.** `--authorized` (MCP: `authorized: true`) states that
  you own the site or have written permission to test it. `asa` cannot verify that statement; it records it in the
  report as the run's scope and relies on whoever passed it. `--allow-supabase` additionally requires that permission
  for the Supabase project the site uses; row counts can themselves be sensitive.
- **Agents never self-authorize.** The skill and `AGENTS.md` tell an agent to add `--authorized` only after the user
  says, in the conversation, that they own the site or have written permission. The agent must not infer it from
  context, and a pasted link is not permission. An agent may run the passive scan on a URL the user named, or on the
  user's own site or project when asked for an audit; before scanning a non-local host the user did not name, it asks
  first.
- **No warranty.** The MIT license's no-warranty clause applies to results. A pass means the defense was observed on
  that target at that time; it is not a certification that the site is free of flaws.

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
- The MCP `run_scan` tool takes the same `authorized`, `allow_supabase`, `no_dns`, `dns_resolver`, `no_ports` and
  `no_osv` switches as the CLI, with the same refusals.
- Tool errors can quote target text too (a redirect address, a server's status line), so they are cleaned, capped at
  600 characters and labelled as untrusted in the same way (`_error_text` in `mcp_server.py`).
- `authorized: true` is a statement by the caller. The server cannot check it; the tool description, the server
  instructions and the skill say it must come from the user, never from the agent's own judgment.

These measures reduce, but cannot remove, the chance that an agent acts on text an attacker placed on a scanned site.

## Dependencies

- Runtime: none. `pyproject.toml` has `dependencies = []`; the package uses only the Python standard library
  (Python 3.11 or later).
- Development and release: `ruff==0.17.4`, `build==1.6.1` and `twine==7.0.0`, pinned by version in the workflows. Tests
  use the standard library `unittest`.
- CI actions are pinned by commit SHA, and the workflow token is read-only (`permissions: contents: read` in
  `.github/workflows/ci.yml`).

## Release provenance

Releases come from `.github/workflows/release.yml` on `main`, which runs only when the maintainer publishes a GitHub
release for a `vX.Y.Z` tag. Every action is pinned by commit SHA and the workflow token is read-only except where a job
needs more:

1. `verify`: checks that the tag equals `v` + the `version` in `pyproject.toml`, runs `ruff check .` and the full unit
   test suite on the tagged commit (the suite also checks that the version in `pyproject.toml`, `__init__.py`,
   `.claude-plugin/plugin.json` and `CITATION.cff` agree, and that every pinned install command uses it).
2. `build`: builds the sdist and wheel with `SOURCE_DATE_EPOCH` set to the commit time, runs `twine check --strict`,
   installs the wheel into a clean virtualenv and smoke-tests it against the local lab, then writes a CycloneDX SBOM
   (`agent-security-audit.cdx.json`, from `scripts/make_sbom.py`; it lists no components because there are no runtime
   dependencies) and `SHA256SUMS` for the sdist, wheel and SBOM.
3. `attest`: SLSA build provenance attestations for every file, through `actions/attest-build-provenance`
   (`id-token: write`, `attestations: write` on this job only).
4. `publish`: uploads the sdist and wheel to PyPI with Trusted Publishing (OIDC from the `pypi` environment; no PyPI
   token is stored). `pypa/gh-action-pypi-publish` also uploads PEP 740 attestations to PyPI.
5. `release-assets`: attaches the sdist, wheel, `SHA256SUMS` and SBOM to the GitHub release (`contents: write` on this
   job only).

Verify a download:

```sh
gh release download v0.2.0 -R talalkashar/agent-security-audit
sha256sum -c SHA256SUMS
gh attestation verify agent_security_audit-0.2.0-py3-none-any.whl -R talalkashar/agent-security-audit
```

For the copy on PyPI, compare the file's SHA-256 on the PyPI "Download files" page with `SHA256SUMS`, and check the
"Provenance" panel there, which names this repository and `release.yml`.

## Verify it yourself

Run these from a checkout.

```sh
# Hosts named anywhere in the source, held to an explicit allowlist, plus the list of network-importing modules
PYTHONPATH=src python3 -m unittest tests.test_outbound_hosts -v

# Every URL literal and every network, process, file-write and environment call
grep -rnoE "https?://[^\"' )]+" src/agent_security_audit --include='*.py' | sort -u
grep -rnE "import (socket|ssl|subprocess|urllib\.request|http\.client|http\.server)|from (socket|ssl|subprocess|urllib\.request|http)" src/agent_security_audit
grep -rnE "os\.environ|getenv|subprocess|urlopen|create_connection|getaddrinfo" src/agent_security_audit
grep -rnE "open\([^)]*['\"]w|write_text|write_bytes|mkdir|makedirs|tempfile" src/agent_security_audit

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
  `HTTPS_PROXY` covers only the OSV requests (made with `urllib.request` in `code_audit/deps.py`). Use a firewall rule
  or packet capture to observe or restrict scan traffic.
- `--dns-resolver` (MCP `dns_resolver`) must be an `https://` URL without credentials (`check_dns_resolver` in
  `scope.py`) and must speak the JSON DoH format. Without it, DNS checks use `cloudflare-dns.com` unless `no_dns` is
  set.
- Inconclusive evidence is not a pass: INFRA-24/25 report `manual` when ports silently drop connections, INFRA-26
  often reports `skip` on OpenSSL 3 builds that cannot offer old TLS versions, BROWSER-06 reports `manual` when no
  session cookie was seen, and BROWSER-07 probes at most 3 API routes and reports `manual` if it finds none.
- Bounded reads: script and page scans read at most 500 KB per response, and the response cache holds at most 50 MB.
  CMS end-of-support data older than 90 days is treated as expired and the check reports `manual`.
- DNS names sent to the resolver reveal which domain you are scanning to the resolver's operator.
- The local-host check in `scope.py` resolves `*.test` and `*.localhost` names once, before the scan; a resolver that
  changes its answer mid-scan is not covered.
- `tests/test_outbound_hosts.py` scans string literals in the Python source. A host assembled from pieces at run time,
  or one inside `catalog/*.toml`, is outside its reach; the catalog URLs are reference links printed in reports and are
  never requested.
- Secret masking matches known formats and secret-looking names. A secret in an unrecognized format inside a quoted
  source line or a target response can appear in a report.
- The Python standard library honors some environment variables the package does not read itself, such as
  `SSL_CERT_FILE` for the CA bundle used by `ssl.create_default_context`.
