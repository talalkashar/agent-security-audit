# Changelog

All notable changes to this project are listed here. Versions follow [Semantic Versioning](https://semver.org/).

## Unreleased

Nothing yet.

## 0.2.0 - unreleased draft (set the date when the release is tagged)

The first release published to PyPI. 0.1.0 was never tagged or published; everything below is new since its changelog entry. Network behaviour that a reviewer should re-check is marked **(network)**.

### Checks

- The catalog grows from 102 to 126 checks in seven areas: the new `cms` area (CMS-01 to CMS-04: CMS version disclosure, supported core release line, WordPress REST and XML-RPC exposure, public CMS login links), plus API-19 to API-25, API-30 to API-33, BROWSER-20 to BROWSER-23 and INFRA-24 to INFRA-28.
- Automated live proof tests grow from 21 to 43 (31 passive, 12 active). 31 checks can be settled from source code, and the rest are guided checks with written proof steps.
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
- A short terminal summary with the failed checks to fix first; "Fix these first" and an OSI layer coverage table in the Markdown, HTML and JSON reports.
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

<!-- Integrator: replace these placeholders with one line each for the parallel fixes as they merge, then remove this comment. -->

- TODO: code-audit heuristics no longer report `pass` for checks they cannot prove (reported as `manual` with evidence).
- TODO: ReDoS fix in the Next.js chunk pattern (a hostile page can no longer stall the scanner or MCP server).
- TODO: MCP error messages are sanitized, capped and labelled as untrusted before they reach the agent.
- TODO: the rate-limit probe (API-01) sends `POST` only.
- TODO: link-local and cloud metadata addresses are refused as targets.
- TODO: reports record the scope and run configuration (`--authorized`, `--allow-supabase`, `--no-dns`, `--no-ports`, `--no-osv`).
- TODO: `--fail-on` also fails the run on `error` results.
- Earlier accuracy fixes in this release: a security header that middleware sets only on some requests is judged `manual`, not `pass`; script checks cannot pass when only the first 40 of more same-origin scripts were read; string and template literals are read in one linear pass so a hostile file cannot stall the code audit.

## 0.1.0 - 2026-11-07

First version (not tagged or published to PyPI).

- Check catalog of 102 checks in six areas (access, api, auth, browser, infra, nextjs), each with a risk, CWE, OSI layer, build rule, proof test, stacks and sources.
- 21 automated proof tests run by `asa scan`, with a scope gate (local hosts always, other hosts only with `--authorized`), a request budget, same-origin requests and a stop on firewall bot challenges.
- Reports in Markdown, JSON and SARIF 2.1.0.
- `asa lab`: a local practice site in vulnerable and fixed modes.
- Agent skill (`skills/agent-security-audit`), `AGENTS.md` guidance, a Claude Code plugin and marketplace manifest, and MCP configuration for `asa-mcp`.
- Generated check reference in `docs/checks/`.
