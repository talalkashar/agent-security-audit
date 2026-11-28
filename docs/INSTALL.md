# Install

agent-security-audit has three parts you can use alone or together:

- the `asa` CLI, which every other part relies on;
- the agent skill (`skills/agent-security-audit/SKILL.md`) or the `AGENTS.md` guidance, which tell the agent when and how to use it;
- the `asa-mcp` MCP server, for agents that prefer tools over shell commands.

Install from the public Git repository. The package is not currently available on PyPI, so the registry-based `uvx --from agent-security-audit==0.2.0` examples below need a published package before they can run. After the source install, use `asa install <agent>` or configure the installed `asa-mcp` executable by its full path.

Every path and command on this page comes from the agent's own documentation, linked in [Sources](#sources).

## 1. The CLI

Python 3.11 or newer. No dependencies.

```sh
pipx install git+https://github.com/talalkashar/agent-security-audit
# or
uv tool install git+https://github.com/talalkashar/agent-security-audit
# or, without uv or pipx
python3 -m pip install --user git+https://github.com/talalkashar/agent-security-audit
```

Append `@<commit-sha>` to the Git URL to pin a reviewed revision. Check it: `asa --version`. The install also adds `agent-security-audit` (same as `asa`) and `asa-mcp`.

On macOS, `asa` can resolve to a system utility. If `asa --version` reports an illegal option, use `agent-security-audit --version` and put your uv or pipx executable directory first on `PATH`. The longer CLI name accepts the same commands.

The registry-based one-off command, `uvx --from agent-security-audit==0.2.0 asa <command>`, is unavailable until the package is published. Use the installed CLI instead.

Upgrade with `uv tool upgrade agent-security-audit` or `pipx upgrade agent-security-audit`.

These commands install the latest source, which is not pinned. Use a reviewed commit for anything you rely on. How to verify a release file (checksums, provenance attestations, SBOM) is in [TRUST.md](TRUST.md#release-provenance).

## 2. The skill

The skill follows the [Agent Skills specification](https://agentskills.io/specification) (the test suite checks its frontmatter against it) and asks for no agent-specific tools: it runs the `asa` CLI through whatever shell tool the agent has, or the MCP tools when there is no shell.

| Agent | How |
|---|---|
| Any agent the `skills` installer supports (Claude Code, Codex, Cursor, Gemini CLI, GitHub Copilot, OpenCode, Windsurf, Cline, Goose, Amp and more) | `npx skills add talalkashar/agent-security-audit` (project) or with `-g` (every project); `-a <agent>` picks the agent. The installer finds it in the repository's `skills/` folder. |
| Claude Code, as a plugin | `/plugin marketplace add talalkashar/agent-security-audit`, then `/plugin install agent-security-audit@agent-security-audit`. Adds the skill and the server (step 3). |
| Claude Code, by hand | `asa install claude-code --yes`, or copy `skills/agent-security-audit` into `~/.claude/skills/` (all projects) or `.claude/skills/` (one project). |
| Codex | `asa install codex --yes` copies the skill to `~/.agents/skills/agent-security-audit/`; or put it in `.agents/skills/` in the repository. |
| Agents without skills | Add the first section of [AGENTS.md](../AGENTS.md) to your project's `AGENTS.md` (Codex and Cursor read it at the project root), or `GEMINI.md` for Gemini CLI. |

## 3. The MCP server

The server runs over stdio. The command is either `uvx --from agent-security-audit==0.2.0 asa-mcp` (needs [uv](https://docs.astral.sh/uv/), nothing else; uv downloads that exact release from PyPI) or `asa-mcp` once the CLI is installed (use the full path from `which asa-mcp` where the agent does not use your shell's `PATH`, such as Claude Desktop). Non-local targets still need `authorized: true` in the tool call for active probes, and only after the user states that they own the site or have written permission.

### `asa install <agent>`

Automatic configuration writes require directory-descriptor and no-follow support (macOS and Linux).
On Windows or another platform without those primitives, run without `--yes` and copy the printed configuration
using the agent-specific instructions below. `--yes` refuses to write there rather than risk following a directory
that changed during installation. The scanner and MCP server still run on Windows.


```sh
asa install cursor            # dry run: prints what it would add and where
asa install cursor --yes      # writes it; a changed file is copied to <file>.bak first
```

Agents: `claude-code`, `claude-desktop`, `cursor`, `vscode`, `windsurf`, `codex`, `gemini`, `antigravity`. It merges one `agent-security-audit` entry into the agent's config and keeps every other server. A file that is not plain JSON (for example with comments) is never rewritten; it prints the entry to add by hand. An existing `agent-security-audit` entry with other settings is left as is. For Codex it appends one table to the end of `config.toml` and never rewrites the rest. It writes the installed `asa-mcp` by full path when it is a stable install (pipx, `uv tool`, a system or user install). When `asa-mcp` is not found, or sits in a temporary folder, a uv cache or a project virtualenv that may be deleted, or with `--uvx`, it writes `uvx --from agent-security-audit==0.2.0 asa-mcp` instead. The dry run prints the command it chose and why, and what it would write to each file is listed in [TRUST.md](TRUST.md#asa-install-only-with---yes).

The `uvx` alternatives and the Cursor link in this table require a published PyPI release. For the current source install, use the configuration below.

| Agent | File `asa install` writes | Alternative after publication |
|---|---|---|
| Claude Code | `.mcp.json` in the current folder (project scope), plus the skill in `~/.claude/skills/` | `claude mcp add --scope user agent-security-audit -- uvx --from agent-security-audit==0.2.0 asa-mcp` |
| Claude Desktop | macOS `~/Library/Application Support/Claude/claude_desktop_config.json`; Windows `%APPDATA%\Claude\claude_desktop_config.json`; Linux `~/.config/Claude/claude_desktop_config.json` | none; restart Claude Desktop after the change |
| Cursor | `~/.cursor/mcp.json` (`.cursor/mcp.json` for one project) | the install link below |
| VS Code | `.vscode/mcp.json` in the current folder | `code --add-mcp '{"name":"agent-security-audit","type":"stdio","command":"uvx","args":["--from","agent-security-audit==0.2.0","asa-mcp"]}'` (user profile) |
| Windsurf (now Devin Desktop) | `~/.config/devin/mcp_config.json` (Windows `%APPDATA%\devin\mcp_config.json`), and `~/.codeium/windsurf/mcp_config.json` too when that folder exists (older Windsurf builds) | none |
| Codex | `~/.codex/config.toml`, plus the skill in `~/.agents/skills/` | `codex mcp add agent-security-audit -- uvx --from agent-security-audit==0.2.0 asa-mcp` |
| Gemini CLI | `~/.gemini/settings.json` (`.gemini/settings.json` for one project) | `gemini mcp add -s user ...` (see its docs) |
| Antigravity | `~/.gemini/config/mcp_config.json` (`.agents/mcp_config.json` for one workspace) | its MCP manager |

Cursor one-click install link (open it in a browser on a machine with Cursor; the `config` value is the base64 of `{"command":"uvx","args":["--from","agent-security-audit==0.2.0","asa-mcp"]}`):

```text
cursor://anysphere.cursor-deeplink/mcp/install?name=agent-security-audit&config=eyJjb21tYW5kIjoidXZ4IiwiYXJncyI6WyItLWZyb20iLCJhZ2VudC1zZWN1cml0eS1hdWRpdD09MC4yLjAiLCJhc2EtbWNwIl19
```

### Config shapes

After the persistent CLI install, run `asa-mcp` from the client's PATH, or use the full executable path in place of `asa-mcp`. With a uv tool install on macOS or Linux, `echo "$(uv tool dir --bin)/asa-mcp"` prints that path. Merge the entry with any existing servers.

Claude Code (`.mcp.json` in the project) and Cursor (`.cursor/mcp.json` in the project) use this JSON:

```json
{
  "mcpServers": {
    "agent-security-audit": { "command": "asa-mcp", "args": [] }
  }
}
```

Codex (`~/.codex/config.toml`) uses TOML:

```toml
[mcp_servers.agent-security-audit]
command = "asa-mcp"
args = []
```

VS Code uses the key `servers` and adds `"type": "stdio"` inside the server entry. Claude Desktop, Gemini CLI, Antigravity and Windsurf use the JSON shape above.

The Claude Code plugin declares the server through the repository's `.mcp.json`, which runs `asa-mcp` from your `PATH`, so install the CLI first (step 1) when you use the plugin.

### Tools

| Tool | What it does | Main arguments |
|---|---|---|
| `list_checks` | List checks (id, area, title, severity, OSI layer, mode, stacks) | `area`, `stack`, `mode` (all optional) |
| `get_check` | One check in full: risk, build rule, proof test, sources | `id` (required) |
| `build_rules` | Build-mode rules as Markdown | `stack`, `area` (lists, optional) |
| `run_scan` | Proof tests against a running site | `target` (required); `authorized`, `code_path`, `auto_only`, `max_time`, `checks`, `areas`, `stacks`, `rate_limit_path`, `rate_limit_method` (`POST` only), `rate_limit_body`, `rate_limit_content_type`, `rate_limit_attempts`, `allow_supabase`, `supabase_tables`, `no_dns`, `dns_resolver` (`https://` only), `no_ports`, `no_osv`, `max_pages`, `max_depth`, `budget` (1–2000), `timeout`, `insecure` (local hosts only), `format` |
| `run_code_audit` | Static audit of a project folder | `path` (required); `checks`, `areas`, `no_osv`, `format` |
| `diff_reports` | Compare two asa JSON reports already in hand (no file read) | `old`, `new` (required); `allow_different_target`, `fail_on_new`, `format` |

See [scope and safety](../README.md#scope-and-safety) for what the live scanner sends and the permissions its optional checks require.

## Publishing to PyPI (maintainer)

`.github/workflows/release.yml` tests, builds, attests and publishes the package with [PyPI Trusted Publishing](https://docs.pypi.org/trusted-publishers/) when a GitHub release is published. No token is stored in the repository. One-time setup:

1. On PyPI, open [Publishing](https://pypi.org/manage/account/publishing/) and add a pending trusted publisher: project `agent-security-audit`, owner `talalkashar`, repository `agent-security-audit`, workflow `release.yml`, environment `pypi`. Do not rename the workflow file or the environment; the publisher is bound to both.
2. In the GitHub repository settings, create an environment named `pypi` with the maintainer as a required reviewer, so every upload needs a manual approval.

For each release:

1. Set the new version in `pyproject.toml`, `src/agent_security_audit/__init__.py`, `.claude-plugin/plugin.json` and `CITATION.cff`, and in the pinned install commands (`agent-security-audit==X.Y.Z` in `README.md`, `AGENTS.md`, this file, `docs/TRUST.md` and the skill; regenerate the Cursor link's base64). Date the version's `CHANGELOG.md` entry. `tests/test_release.py` fails until all of them agree.
2. Merge to `main`, then create a signed tag `vX.Y.Z` on that commit and publish a GitHub release for it.
3. The workflow refuses a tag that does not match the version, runs the tests, builds, and waits for the `pypi` environment approval before uploading. The release then gets the sdist, wheel, `SHA256SUMS`, SBOM and provenance attestations.

## Uninstall

`uv tool uninstall agent-security-audit` (or `pipx uninstall agent-security-audit`), then remove the skill folder or plugin (`/plugin uninstall agent-security-audit@agent-security-audit`) and the `agent-security-audit` entries from the MCP configs. `asa install` leaves the previous version of each file it changed at `<file>.bak`.

## Sources

Checked on 2026-11-07.

- Agent Skills specification: https://agentskills.io/specification
- `skills` installer (`npx skills add`), discovery folders and supported agents: https://github.com/vercel-labs/skills (docs/creating-skills.md, docs/agents.md)
- Claude Code MCP (`claude mcp add`, scopes, `.mcp.json`): https://code.claude.com/docs/en/mcp
- Claude Code skills (`~/.claude/skills`, `.claude/skills`): https://code.claude.com/docs/en/skills
- Claude Code plugin marketplaces: https://code.claude.com/docs/en/plugin-marketplaces
- Claude Desktop config file: https://modelcontextprotocol.io/docs/develop/connect-local-servers
- Cursor MCP (`mcp.json` locations and format): https://cursor.com/docs/context/mcp
- Cursor install links: https://cursor.com/docs/context/mcp/install-links
- VS Code MCP configuration (`servers`, `code --add-mcp`): https://code.visualstudio.com/docs/agents/reference/mcp-configuration
- Codex MCP (`codex mcp add`, `[mcp_servers.<name>]`): https://learn.chatgpt.com/docs/extend/mcp?surface=cli
- Codex skills (`~/.agents/skills`, `.agents/skills`): https://learn.chatgpt.com/docs/build-skills
- Gemini CLI MCP (`settings.json`, `gemini mcp add`): https://geminicli.com/docs/tools/mcp-server/
- Antigravity MCP (`~/.gemini/config/mcp_config.json`): https://antigravity.google/docs/mcp
- Windsurf / Devin Desktop MCP (`~/.config/devin/mcp_config.json`): https://docs.devin.ai/desktop/cascade/mcp and https://docs.devin.ai/cli/extensibility/mcp/configuration.md
- PyPI Trusted Publishing and the publish action: https://docs.pypi.org/trusted-publishers/ and https://github.com/pypa/gh-action-pypi-publish
