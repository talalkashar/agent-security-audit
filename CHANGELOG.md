# Changelog

All notable changes to this project are listed here. Versions follow [Semantic Versioning](https://semver.org/).

## Unreleased

- `asa code [path]`, `asa scan --code <path>` and the `run_code_audit` MCP tool: a static code audit that settles 29 checks with file:line evidence (SARIF locations included), with an OSV lookup for locked dependencies (`--no-osv` to skip).
- README: honest headline counts (live proof tests, checks settled from code, guided checks) and the OSI layer table are now generated from the catalog by `scripts/gen_docs.py` and checked by the docs-sync test; real terminal output from the practice site; a screenshot of the HTML report; every `asa` command in the README is checked against the CLI parser.
- Reports: text in backticks in summaries and fixes renders as code (`<code>` in HTML, a code span in Markdown) instead of literal backticks. Values from the scanned site stay escaped.
- New review checks API-30 (eval and dynamic code), API-31 (shell commands built from strings) and API-32 (SQL built from strings).
- Code audit: a security header that middleware sets only on some requests (inside an if, switch or loop, after an early return, or with a `matcher`) is judged manual, not pass. A headers list shared across several `source` routes (shorthand, variable, call or spread) is manual too.
- Code audit: string and template literals are read in one linear pass, so a hostile file cannot stall NEXT-05 or API-32; sanitizer imports are read once per file for BROWSER-09.
- NEXT-01 and other script checks cannot pass when the site has more than 40 same-origin script files and only the first 40 were read.
- Reports and MCP output also drop variation selectors and Hangul fillers from target text.

## 0.1.0 - 2026-11-07

First release.

- Check catalog of 102 checks in six areas (access, api, auth, browser, infra, nextjs), each with a risk, CWE, OSI layer, build rule, proof test, stacks and sources.
- 21 automated proof tests run by `asa scan`, with a scope gate (local hosts always, other hosts only with `--authorized`), a request budget, same-origin requests and a stop on firewall bot challenges.
- Reports in Markdown, JSON and SARIF 2.1.0.
- `asa lab`: a local practice site in vulnerable and fixed modes.
- Agent skill (`skills/agent-security-audit`), `AGENTS.md` guidance, a Claude Code plugin and marketplace manifest, and MCP configuration for `asa-mcp`.
- Generated check reference in `docs/checks/`.
