# agent-security-audit

[![CI](https://github.com/talalkashar/agent-security-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/talalkashar/agent-security-audit/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)
![Dependencies: none](https://img.shields.io/badge/dependencies-none-brightgreen.svg)

**Your coding agent builds the site. This makes it prove the site is secure before you ship.**

Point it at any website you own, local or live. It scans the running site, reads the code, and tells you every security flaw it finds, with the evidence and the fix. No accounts to create, no config, no setup.

It works as a skill and an MCP server for Claude Code, Codex, Cursor, Gemini CLI, Windsurf and any agent that reads `AGENTS.md`, and as a plain command line tool (`asa`). 102 checks, mapped to OSI layers 1 to 7. Python, no runtime dependencies.

```text
$ asa scan https://your-site.com --authorized

| fail | critical | INFRA-04  Sensitive files not served   | Sensitive files are downloadable: /.env, /.git/HEAD
| fail | critical | NEXT-01   No secret keys in client JS  | Secret keys are shipped to every visitor's browser. Rotate them now.
| fail | high     | API-01    Login endpoint rate limited  | 30 login attempts from one client were all processed.
| fail | high     | BROWSER-07 CORS reflects any origin    | The site echoes untrusted origins with credentials.
| fail | medium   | NEXT-02   No production source maps    | 1 source map is public: anyone can read your original source.
...
```

*Output from the built-in practice site (`asa lab`), trimmed. Every fail comes with its fix.*

### Start in three steps

```sh
pipx install git+https://github.com/talalkashar/agent-security-audit   # 1. install
```

2. Add the skill to your agent ([Claude Code](#claude-code), [Codex, Cursor and others](#codex-cursor-and-other-agents-that-read-agentsmd), [MCP](#install-as-an-mcp-server)).
3. Ask your agent: **"Run a security audit on my site."** It scans, checks the code, fixes what failed and re-scans until it passes.

## How it differs from code-only audit skills

Most security skills for coding agents read the source and list what looks risky. This tool also tests the running site:

- **Proof, not opinion.** Each check has a proof test. A check passes only when the defense was observed working on the target, and the report shows the evidence (the request sent, the status and headers that came back). A check that could not be proven is reported as `manual`, not as a pass.
- **Build and verify use the same catalog.** The rule the agent followed while coding is the rule the scan proves later, under the same ID.
- **Every check is mapped to an OSI layer**, from physical security of hosting and developer devices (layer 1) up to the application (layer 7), so the gaps are visible instead of implied.

Not every layer can be tested from outside the site. This table shows what the tool does at each layer today:

| OSI layer | What is checked | How |
|---|---|---|
| 7 Application | Access control and RLS, auth and sessions, API abuse, browser headers and cookies, Next.js and Vercel settings, DNS and email records | 18 automated, 50 assisted, 18 review |
| 6 Presentation | HTTPS redirect, certificate, legacy TLS refused, mail transport security | 3 automated, 1 review |
| 5 Session | Sessions ended on logout and password change, token storage | Assisted (test accounts and a headless browser) |
| 4 Transport | Admin and database ports closed to the internet | Review |
| 3 Network | Database reachable only from allowed networks, over SSL | Review |
| 2 Data link | Deploys and dashboards used only from trusted networks | Review |
| 1 Physical | Hosting attestations, encrypted and locked developer devices | Review |

- **auto**: `asa scan` runs the proof test and reports pass or fail with evidence.
- **assisted**: the agent checks the code first. If the code does not settle it, it runs a logged-in test itself in a headless browser, with two accounts it signs up on your site. Nothing for you to set up.
- **review**: the proof is in the code, the hosting dashboard or a policy, so the agent or a person reads it.

**What a pass means.** A pass means the defense was observed working on that target at that time. It does not mean the site has no flaws. The honest claim for a site that passes is: every listed check was built in and proven. Anything the catalog does not list was not tested.

## Quick start

Install the CLI (Python 3.11 or newer):

```sh
pipx install git+https://github.com/talalkashar/agent-security-audit
# or
uv tool install git+https://github.com/talalkashar/agent-security-audit
```

Try it on the built-in practice site, which runs only on your machine:

```sh
asa lab &                                            # vulnerable practice site on http://127.0.0.1:8642
asa scan http://127.0.0.1:8642 --rate-limit-path /api/login
asa lab --mode fixed --port 8643 &                   # the same site with the defenses in place
asa scan http://127.0.0.1:8643 --rate-limit-path /api/login
```

The first scan fails most checks; the second passes them. Stop the labs with `kill %1 %2`.

Other commands:

```sh
asa list --area auth                     # checks in one area
asa show AUTH-01                         # one check in full: risk, build rule, proof test, sources
asa rules --stack nextjs,supabase        # build rules for your stack, as Markdown
asa scan http://localhost:3000           # prove the automated checks on your dev server
asa https://your-site.com                # shortcut for `asa scan`; asks once whether you own the site
```

In a terminal, a scan shows a progress line and ends with a short summary: the counts and the failed checks to fix first, most severe first, each with its fix. Add `--out asa-report.html` for the full report with evidence.

## Build mode

Use it while the site is being written.

1. Run `asa rules --stack nextjs,supabase,vercel` (drop the parts of the stack you do not use) and give the output to the agent, or let the skill do it.
2. The agent follows every rule as it writes code: server-side identity checks, row-level security on every table, rate limits on login and signup, security headers, no secrets in client code, and the rest.
3. When a rule cannot be followed, the agent says so and records which check ID is affected.

## Verify mode

Use it before launch and after any change to auth, data access or hosting.

1. Start the site (`npm run dev`, a preview deployment, or production you own).
2. Run `asa scan <url>`. Automated checks report `pass`, `fail` or `warn` with evidence. Assisted and review checks come back as `manual` with their proof steps.
3. The agent works through each `manual` check without asking you for anything: it reads the code and config, and where the code does not settle it, signs up two accounts on your site and runs a logged-in test in a headless browser.
4. Every `fail` gets fixed using the build rule, then the scan runs again until it passes. A check that cannot be proven stays reported as unproven.

## Install as an agent skill

### Claude Code

As a plugin, from this repository's marketplace:

```text
/plugin marketplace add talalkashar/agent-security-audit
/plugin install agent-security-audit@agent-security-audit
```

The plugin adds the skill and declares the `asa-mcp` server (through the repository's [.mcp.json](.mcp.json)). The plugin does not install the Python package, so install it first (`pipx install` or `uv tool install`, see Quick start); otherwise the MCP server cannot start.

Or copy the skill by hand:

```sh
git clone https://github.com/talalkashar/agent-security-audit
cp -r agent-security-audit/skills/agent-security-audit ~/.claude/skills/
```

The skill calls the `asa` CLI, so install that too (see Quick start).

### Codex, Cursor and other agents that read AGENTS.md

Copy the guidance in [AGENTS.md](AGENTS.md) into your project's `AGENTS.md` (or reference it), and install the `asa` CLI. Cursor also reads `AGENTS.md` at the project root.

## Install as an MCP server

The package installs an `asa-mcp` command that speaks MCP over stdio. It offers four tools that match the CLI: `list_checks`, `get_check`, `build_rules` and `run_scan` (which takes `authorized: true` for non-local hosts). Install the package first (Quick start), then add the server to your agent. If your agent cannot find `asa-mcp`, use the full path from `which asa-mcp`.

**Claude Code**

```sh
claude mcp add agent-security-audit -- asa-mcp
# for every project: claude mcp add --scope user agent-security-audit -- asa-mcp
```

The Claude Code plugin above already declares this server through the repository's [.mcp.json](.mcp.json), so you do not need both.

**Claude Desktop** (`claude_desktop_config.json`), **Cursor** (`.cursor/mcp.json` in a project or `~/.cursor/mcp.json`), **Gemini CLI** (`~/.gemini/settings.json` or `.gemini/settings.json`) and **Windsurf** (`~/.codeium/windsurf/mcp_config.json`) all use this shape:

```json
{
  "mcpServers": {
    "agent-security-audit": {
      "command": "asa-mcp"
    }
  }
}
```

Claude Desktop does not inherit your shell's `PATH`, so give it the full path, for example `"/Users/you/.local/bin/asa-mcp"`.

**VS Code** (`.vscode/mcp.json`):

```json
{
  "servers": {
    "agent-security-audit": {
      "type": "stdio",
      "command": "asa-mcp"
    }
  }
}
```

**Codex** (`~/.codex/config.toml`):

```toml
[mcp_servers.agent-security-audit]
command = "asa-mcp"
```

More detail per agent is in [docs/INSTALL.md](docs/INSTALL.md).

## Scope and safety

This tool is for testing sites you own or have written permission to test. It is defensive: it contains no exploit payloads or bypass techniques, and its proof tests are built not to damage data or overload a service.

- **Own site or written permission.** `localhost`, loopback addresses, `*.localhost` and `*.test` are always allowed. Any other host is refused unless you pass `--authorized` (CLI) or `authorized: true` (MCP), which states that you own the site or have written permission.
- **Request budget.** A scan sends at most 300 requests by default (`--budget`), with a short delay between them. The rate-limit probe sends at most 60 (`--rate-limit-attempts`, default 30).
- **Same origin.** Requests stay on the target's scheme, host and port. Redirects to other hosts are reported, not followed. The only exceptions are the www/apex twin of the same site over HTTPS, the Supabase project the site itself points to when you pass `--allow-supabase` (read-only, row counts only; on a local target it also needs `--authorized`, because that project is not local), and DNS lookups through a public resolver (turn off with `--no-dns`).
- **Stops at a firewall challenge.** If the site's firewall answers with a bot challenge, the scan stops and says so. It does not try to get around it.
- **Runs on your real, live site.** Scans and proof tests work against production and its real data. That is the point: find the leak before your users or an attacker do.
- **No setup.** Logged-in tests use two accounts the agent signs up on your site itself, and it lists them at the end so you can delete them. It never signs in as one of your users or uses their credentials.
- **Exposed real data is a fail, not a copy.** If a test shows other people's real data, the check fails with where it leaked and how many records came back. The records themselves never go into the report. The scan keeps going, and the fix leads the report.
- **No destructive tests.** Proof tests read, or write only to your own accounts' rows. Nothing deletes data, floods a service or changes another user's account.

## Output formats

```sh
asa scan <url>                                  # terminal: short summary; pipe or file: Markdown report
asa scan <url> --out asa-report.html            # one self-contained HTML page (light/dark, prints cleanly)
asa scan <url> --format md                      # Markdown report for people
asa scan <url> --format json --out asa.json     # JSON for tools and agents
asa scan <url> --format sarif --out asa.sarif   # SARIF 2.1.0 for GitHub code scanning
```

With `--out`, the format comes from `--format`, else from the file extension (`.md`, `.json`, `.sarif`, `.html`), else Markdown. The Markdown and HTML reports open with "Fix these first" (up to 10 failed checks, most severe first, each with its fix) and a coverage table by OSI layer, then every result with its evidence. JSON adds the same as `fix_first` and `osi_layers`. The progress line goes to stderr only when it is a terminal; `--quiet` turns it off.

A non-local host needs `--authorized`. In an interactive terminal, `asa` asks once instead ("Do you own <host> or have written permission to test it? [y/N]") and scans only on `y` or `yes`. In scripts and CI there is no prompt: pass `--authorized`.

`asa scan` exits 1 when a failed check is at least as severe as `--fail-on` (default `high`), 2 on a usage or scope error, and 0 otherwise. Use `--fail-on none` to always exit 0, and `--auto-only` to leave out the `manual` rows.

### GitHub code scanning

This workflow starts the app in CI, scans it on localhost and uploads the SARIF file. Failed and warned checks appear under the repository's Security tab. Results point at the scanned URL, not at a line of source code.

```yaml
name: security-proof
on: [pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: 22 }
      - uses: actions/setup-python@v5
        with: { python-version: "3.13" }
      - run: npm ci && npm run build
      - run: npm start &
      - run: npx wait-on http://localhost:3000
      - run: pipx install git+https://github.com/talalkashar/agent-security-audit
      - run: asa scan http://localhost:3000 --auto-only --no-dns --format sarif --out asa.sarif --fail-on none
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: asa.sarif
```

Checks that only make sense on the deployed site (HTTPS redirect, certificate, HSTS) are reported as not applicable on localhost. Scan your preview or production URL with `--authorized` to cover them.

## Check catalog

Every check has a risk with a CWE ID, a build rule, a proof test, the stacks it applies to and at least one primary source. The full reference is in [docs/checks](docs/checks/README.md), or run `asa show <ID>`.

<!-- catalog:start (generated by scripts/gen_docs.py, do not edit by hand) -->

Checks by area:

| Area | What it covers | Checks | Auto | Assisted | Review | Critical | High | Medium | Low |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| [access](docs/checks/access.md) | Access control and Supabase row-level security | 15 | 1 | 10 | 4 | 5 | 9 | 1 | 0 |
| [api](docs/checks/api.md) | API abuse, input handling and rate limits | 18 | 2 | 12 | 4 | 1 | 11 | 6 | 0 |
| [auth](docs/checks/auth.md) | Authentication and sessions | 11 | 0 | 10 | 1 | 1 | 6 | 4 | 0 |
| [browser](docs/checks/browser.md) | Browser security headers, cookies and client code | 19 | 8 | 7 | 4 | 0 | 7 | 11 | 1 |
| [infra](docs/checks/infra.md) | Transport, DNS, email and hosting | 23 | 7 | 2 | 14 | 5 | 11 | 3 | 4 |
| [nextjs](docs/checks/nextjs.md) | Next.js and Vercel | 16 | 3 | 10 | 3 | 3 | 5 | 7 | 1 |
| **Total** | | **102** | **21** | **51** | **30** | **15** | **49** | **32** | **6** |

Checks by OSI layer:

| OSI layer | Checks | Auto | Assisted | Review |
|---|---:|---:|---:|---:|
| 1 Physical | 2 | 0 | 0 | 2 |
| 2 Data link | 1 | 0 | 0 | 1 |
| 3 Network | 1 | 0 | 0 | 1 |
| 4 Transport | 1 | 0 | 0 | 1 |
| 5 Session | 2 | 0 | 2 | 0 |
| 6 Presentation | 4 | 3 | 0 | 1 |
| 7 Application | 91 | 18 | 49 | 24 |

<!-- catalog:end -->

## How to read results

| Status | Meaning | What to do |
|---|---|---|
| `pass` | The defense was observed working. Evidence lists what was seen. | Keep it. Re-scan after related changes. |
| `fail` | The flaw was observed. | Fix it with the build rule shown under Fix, then scan again. |
| `warn` | A weaker setting that is not a proven flaw. | Fix it when you can. |
| `manual` | Not visible from outside the site. The proof steps are in the result. | The agent checks the code, or runs a logged-in test, and records pass or fail with evidence. |
| `skip` | Does not apply to this target, for example TLS checks on plain HTTP. | Scan the deployed HTTPS site to cover it. |
| `error` | The check could not run (network error, timeout, budget used up). | Fix the cause and scan again. It is not a pass. |

Treat anything not proven as suspected, not as fine.

## Contributing

New checks, better proof tests and fixes are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) first; it explains how to add a check and the defensive-only rule. Report security problems in this tool privately, as described in [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
