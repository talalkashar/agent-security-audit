# Changelog

All notable changes to this project are listed here. Versions follow [Semantic Versioning](https://semver.org/).

## Unreleased

- MCP `run_scan` takes `max_depth` (0–20, default 3), `budget` (1–2000, default 300), `timeout` (1–60 seconds, default 10), `insecure` (local hosts only) and `rate_limit_content_type` (at most 128 characters, default `application/json`). Reports record `max_depth`. The budget cap is MCP-only: a scanned page can steer the agent; the CLI stays uncapped.
- MCP tool `diff_reports` compares two in-memory asa JSON reports and does not read files. Different targets are refused unless `allow_different_target` is true. `gate.would_fail` follows `asa diff`'s exit rule. FIXED still needs an observed pass.
- MCP string arguments are length-capped and reject control characters. `rate_limit_body` may contain newlines.
- API-23 does not pass when one of `/graphql` and `/api/graphql` refuses introspection and the other is unproven (generic JSON errors, or an auth, throttle, gateway or firewall answer). A path that is not an endpoint still allows the pass.
- BROWSER-05 combines every `Referrer-Policy` field and uses the last recognised token. A later `unsafe-url` does not pass because an earlier field was strict.
- BROWSER-05 applies `<meta name="referrer">` after the header. The last single-keyword meta wins, so `unsafe-url` in the page does not pass behind a strict header.

## 0.2.0 - unreleased draft (set the date when the release is tagged)

The first release published to PyPI. 0.1.0 was never tagged or published; everything below is new since its changelog entry. Network behaviour that a reviewer should re-check is marked **(network)**.

### Checks

- The catalog grows from 102 to 126 checks in seven areas: the new `cms` area (CMS-01 to CMS-04: CMS version disclosure, supported core release line, WordPress REST and XML-RPC exposure, public CMS login links), plus API-19 to API-25, API-30 to API-33, BROWSER-20 to BROWSER-23 and INFRA-24 to INFRA-28.
- Automated live proof tests grow from 21 to 44 (32 passive, 12 active). The code audit reads 31 checks and can pass 11 of them from source; the rest are guided checks with written proof steps.
- **(network)** New active probes, only on local hosts or with `--authorized`: open redirects (API-19), directory listings (API-20), debug and status endpoints (API-21), API description files (API-22), GraphQL introspection (API-23), `TRACE` (API-24), and TCP connect probes (connect and close, nothing sent) to database, cache, container API and remote-admin ports (INFRA-24, INFRA-25; off with `--no-ports`).
- **(network)** New passive checks: legacy and weak TLS 1.2 cipher suites (INFRA-26), DNSSEC (INFRA-27), dangling CNAMEs (INFRA-28), mixed content, Subresource Integrity, password forms over HTTPS, known-vulnerable client libraries (BROWSER-20 to BROWSER-23), server banners (API-25) and the CMS checks. DNS and email checks query a DNS-over-HTTPS resolver (`cloudflare-dns.com` by default, `--dns-resolver` to change it, `--no-dns` to turn it off) and may fetch `mta-sts.<domain>`.
- **(network)** Checks read one shared, bounded crawl of the site (same-origin GET only, seeded from `/`, `robots.txt` and `sitemap.xml`; `--max-pages`, `--max-depth`) instead of the home page alone. API-01 can find a login form on the crawled pages by itself; sign-up and reset forms are never used.
- Every check is mapped to the OWASP Top 10 (2021 and 2025) and the OWASP API Security Top 10 (2023): `asa list --owasp <ID>`, the generated `docs/OWASP.md`, and coverage tables that name the thin categories.

### Code audit

- `asa code [path]`, `asa scan --code <path>` and the `run_code_audit` MCP tool: a static code audit with `file:line` evidence that never runs the project, git or a package manager. Heuristic findings are `warn` and say "Suspected".
- **(network)** Locked dependency versions are checked against the OSV database (`api.osv.dev`): package names and versions only; `--no-osv` turns it off, and an OSV outage is reported as `error`, never `pass`.
- New review checks API-30 (eval and dynamic code), API-31 (shell commands built from strings), API-32 (SQL built from strings) and API-33 (mass assignment).

### Reports and CLI

- HTML report (`--out asa-report.html`): one self-contained page, no scripts or external URLs, light and dark, prints cleanly.
- SARIF: code-audit results carry the file and line as their location, and every rule links to its check documentation.
- A short terminal summary that counts results by status name (`fail`, `warn`, `error`, `manual`, `pass`, `skip`) with a one-line legend, the failed checks to fix first, and a `Next:` line for the `manual` checks; code findings show `At: file:line`, and `asa code -q` turns off the progress line; "Fix these first" and an OSI layer coverage table in the Markdown, HTML and JSON reports.
- `asa <url>` as a shortcut for `asa scan <url>`; `--max-time` (default 300 s) with checks the time budget cut reported as `error`, never `pass`.
- Reports and MCP output strip control, bidi, zero-width and other invisible characters from target text and cap its length.

### Agent setup

- `asa install <agent>` for Claude Code, Claude Desktop, Cursor, VS Code, Windsurf (Devin Desktop), Codex, Gemini CLI and Antigravity. Dry run by default; with `--yes` it merges one entry into the agent's config, keeps a `<file>.bak` copy, never writes through a symlink that leaves the project or home folder, and copies the skill for Claude Code and Codex.
- The MCP config that `asa install`, the README one-liners and the Cursor install link write now runs the pinned PyPI release (`uvx --from agent-security-audit==0.2.0 asa-mcp`), not the moving `main` branch. `asa install` writes a stable installed `asa-mcp` by path when there is one, never one inside a temporary folder or a project virtualenv, and the dry run says which command it chose and why.
- The skill and `AGENTS.md` say that an agent adds `--authorized` only after the user states that they own the site or have written permission, never on its own judgment.

### Platforms

- CI runs the tests on Linux, macOS and Windows with Python 3.11 to 3.14, and smoke-tests the built wheel (not an editable install) on all three.
- On Windows the scanner, the lab and the MCP server work; `asa install --yes` refuses to write (the secure directory-handle writes it relies on are not available there), so run the dry run and add the printed configuration by hand.

### Release and project

- Releases are built from the tag after the tests and ruff pass and the tag matches the package version, checked with `twine check`, and published to PyPI through Trusted Publishing. The sdist, wheel, `SHA256SUMS` and a CycloneDX SBOM are attached to the GitHub release with build provenance attestations. See `docs/TRUST.md` for how to verify them.
- `docs/TRUST.md` corrected: it now lists what `asa install --yes` writes and reads, and adds an acceptable-use section. New `GOVERNANCE.md`, `SUPPORT.md` and `.github/CODEOWNERS`.
- `pyproject.toml`: build backend floor `setuptools>=77` (needed for the SPDX `license` field), classifiers and project URLs.

### Accuracy and hardening

- Code audit: AUTH-01, ACCESS-01, ACCESS-02, ACCESS-06, ACCESS-11, NEXT-05, NEXT-06 and NEXT-15 never pass from code alone. A guard found by pattern is reported as `manual` ("Not proven: ...") with its `file:line`; NEXT-15 needs a comparison that rejects a wrong `CRON_SECRET`. A code `pass` never overrides a live `manual` or `error`.
- Live checks no longer pass on partial or inconclusive evidence: INFRA-24/25 report `manual` when ports silently drop connections, INFRA-26 often reports `skip` on OpenSSL 3, BROWSER-06 reports `manual` when no session cookie was seen, BROWSER-07 probes up to 3 API routes and reports `manual` if it finds none, and a duplicated HSTS directive fails.
- ReDoS fix in the Next.js chunk pattern, and script scans read at most 500 KB per response, so a hostile page cannot stall the scanner or MCP server. The response cache is capped at 50 MB.
- CMS end-of-support data expires after 90 days; after that the check reports `manual` instead of trusting stale dates.
- The rate-limit probe (API-01) sends `POST` only (`--rate-limit-method` and the MCP enum accept only `POST`) and refuses a named path that looks like sign-up, registration, invitation or password reset.
- Cloud metadata services and link-local addresses are refused as targets, even with `--authorized`, by name, by address and after DNS resolution. A custom DNS resolver must be an `https://` URL without credentials.
- MCP `run_scan` takes `dns_resolver` (https only). MCP tool errors are cleaned, capped and labelled as untrusted before they reach the agent.
- Reports record the run's scope: tool version, interface, mode, flags (`--authorized`, `--allow-supabase`, `--no-dns`, `--no-ports`, `--no-osv` and the rest), hosts contacted besides the target, request count and UTC start and end times. SARIF carries it in `invocations`.
- Exit code 3 when checks could not run, set by `--fail-on-error {all,any,none}` (default `all`; `none` when `--fail-on none`), for `asa scan` and `asa code`.
- Earlier accuracy fixes in this release: a security header that middleware sets only on some requests is judged `manual`, not `pass`; script checks cannot pass when only the first 40 of more same-origin scripts were read; string and template literals are read in one linear pass so a hostile file cannot stall the code audit.

## 0.1.0 - 2026-11-07

First version (not tagged or published to PyPI).

- Check catalog of 102 checks in six areas (access, api, auth, browser, infra, nextjs), each with a risk, CWE, OSI layer, build rule, proof test, stacks and sources.
- 21 automated proof tests run by `asa scan`, with a scope gate (local hosts always, other hosts only with `--authorized`), a request budget, same-origin requests and a stop on firewall bot challenges.
- Reports in Markdown, JSON and SARIF 2.1.0.
- `asa lab`: a local practice site in vulnerable and fixed modes.
- Agent skill (`skills/agent-security-audit`), `AGENTS.md` guidance, a Claude Code plugin and marketplace manifest, and MCP configuration for `asa-mcp`.
- Generated check reference in `docs/checks/`.
