# Changelog

All notable changes to this project are listed here. Versions follow [Semantic Versioning](https://semver.org/).

## 0.1.0 - 2026-11-07

First release.

- Check catalog of 102 checks in six areas (access, api, auth, browser, infra, nextjs), each with a risk, CWE, OSI layer, build rule, proof test, stacks and sources.
- 21 automated proof tests run by `asa scan`, with a scope gate (local hosts always, other hosts only with `--authorized`), a request budget, same-origin requests and a stop on firewall bot challenges.
- Reports in Markdown, JSON and SARIF 2.1.0.
- `asa lab`: a local practice site in vulnerable and fixed modes.
- Agent skill (`skills/agent-security-audit`), `AGENTS.md` guidance, a Claude Code plugin and marketplace manifest, and MCP configuration for `asa-mcp`.
- Generated check reference in `docs/checks/`.
