# Documentation

Run an audit, understand the evidence, and work through what remains unproven.

[Project overview](../README.md) · [Quick start](../README.md#quick-start) · [Check catalog](checks/README.md)

## Start here

1. **[Install the CLI](INSTALL.md#1-the-cli).** Python 3.11+, with no runtime dependencies. Install from Git while the package is unavailable on PyPI.
2. **[Run the sample](../README.md#quick-start).** Check the bundled Next.js config, then [compare it with the corrected version](../examples/README.md).
3. **[Connect your agent](../README.md#agent-setup).** Preview the config with `asa install <agent>`, then add `--yes` to apply it.
4. **[Read the trust notes](TRUST.md).** See exactly which hosts can be contacted, what is written to disk, and how authorization works.

## Choose a workflow

| You want to… | Read |
|---|---|
| Add defenses while building | [Build mode](../README.md#build-mode) |
| Test the running site before launch | [Verify mode](../README.md#verify-mode) |
| Audit source without a running site | [Code audit](../README.md#code-audit) |
| Save HTML, Markdown, JSON, SARIF, JUnit, or JSON Lines | [Output formats](../README.md#output-formats) |
| Check whether a fix was observed working | [Compare two runs](../README.md#comparing-two-runs) |
| Add an audit to a pull request | [CI and GitHub code scanning](CI.md) |

## Read a report

The HTML report starts with six status totals and up to ten failed checks, most severe first. Expand **How to fix** for the build rule. Full results, evidence, and the scope of the run follow below. It is a self-contained file with no scripts, external fonts, or network requests; it also supports dark mode and printing. Markdown carries the same findings in a format you can keep alongside a pull request.

- **Fail:** a flaw was observed. Apply the fix and run the check again.
- **Warn:** a weaker setting or suspected finding needs confirmation.
- **Error:** the check could not run. Resolve the cause and retry.
- **Manual:** this run could not prove it. Read the code or follow the check's proof steps.
- **Pass:** the defense was observed working within the scope of the check.
- **Skip:** the check did not apply or an active probe was not allowed. Read its reason.

Use `asa show <ID>` for the risk, build rule, proof steps, and sources behind a check. [Reproduce the source finding and lab screenshots](assets/README.md).

## Look up a check

- [Check catalog](checks/README.md): every check, organized by area and OSI layer.
- [OWASP coverage](OWASP.md): mappings and explicit gaps for the Top 10 and API Security Top 10.
- [Scope and safety](../README.md#scope-and-safety): passive requests, active probes, request budgets, and authorization.

## Project and maintenance

[Contributing](../CONTRIBUTING.md) · [Changelog](../CHANGELOG.md) · [Security policy](../SECURITY.md) · [Support](../SUPPORT.md) · [Governance](../GOVERNANCE.md)

A pass means the defense was observed working on this target at this time. It is not a guarantee that the site has no other flaws.
