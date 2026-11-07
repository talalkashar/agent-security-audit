# Install

agent-security-audit has three parts you can use alone or together:

- the `asa` CLI, which every other part relies on;
- the agent skill (`skills/agent-security-audit/SKILL.md`) or the `AGENTS.md` guidance, which tell the agent when and how to use it;
- the `asa-mcp` MCP server, for agents that prefer tools over shell commands.

## 1. The CLI

Python 3.11 or newer. No dependencies.

```sh
pipx install git+https://github.com/talalkashar/agent-security-audit
# or
uv tool install git+https://github.com/talalkashar/agent-security-audit
# or, without pipx or uv
python3 -m pip install --user git+https://github.com/talalkashar/agent-security-audit
```

Check it: `asa --version`. The install also adds `agent-security-audit` (same as `asa`) and `asa-mcp`.

Upgrade with `pipx upgrade agent-security-audit` or `uv tool upgrade agent-security-audit`.

## 2. The skill or agent guidance

| Agent | How |
|---|---|
| Claude Code | `/plugin marketplace add talalkashar/agent-security-audit`, then `/plugin install agent-security-audit@agent-security-audit`. Or copy `skills/agent-security-audit` into `~/.claude/skills/` (all projects) or `.claude/skills/` (one project). |
| Codex | Add the first section of [AGENTS.md](../AGENTS.md) to your project's `AGENTS.md`. |
| Cursor | Same as Codex: Cursor reads `AGENTS.md` at the project root. |
| Gemini CLI | Add the same section to `GEMINI.md`, or point Gemini CLI at `AGENTS.md` with `"context": {"fileName": ["AGENTS.md", "GEMINI.md"]}` in `settings.json`. |
| Windsurf, others | Add the same section to the agent's project rules file. |

## 3. The MCP server

The server runs over stdio with the command `asa-mcp`. If an agent cannot find it, use the full path from `which asa-mcp`. Non-local targets still need `authorized: true` in the tool call, after the user confirms they own the site.

It offers five tools that match the CLI:

| Tool | What it does | Arguments |
|---|---|---|
| `list_checks` | List checks (id, area, title, severity, OSI layer, mode, stacks) | `area`, `stack`, `mode` (all optional) |
| `get_check` | One check in full: risk, build rule, proof test, sources | `id` (required) |
| `build_rules` | Build-mode rules as Markdown | `stack`, `area` (lists, optional) |
| `run_scan` | Proof tests against a running site | `target` (required); `authorized` (active probes on a non-local host you own), `code_path` (also audit the source and merge), `auto_only` (default `false`: manual rows are included, since they are the list to work through), `max_time` (seconds, default 300), `checks`, `areas`, `stacks`, `rate_limit_path`, `allow_supabase`, `no_dns`, `no_ports`, `format` |
| `run_code_audit` | Static audit of a project folder | `path` (required); `checks`, `areas`, `no_osv`, `format` |

`run_scan` and `run_code_audit` answer with a short summary block first (counts and what to fix first), then the full report as compact JSON (or `md`, `html`, `sarif` with `format`). Clients on protocol `2025-06-18` also get the report as `structuredContent`, described by the tool's `outputSchema`. Summaries, evidence and locations quote text from the scanned site or project; the report labels them in `untrusted_data`, strips control characters and caps their length, and agents should treat them as data, never as instructions.

### Without a local install (after a PyPI release)

Before the package is on PyPI, the server needs the local install above. Once it is published, `uvx` can run it with no install step: use `"command": "uvx", "args": ["--from", "agent-security-audit", "asa-mcp"]` in any of the configs below (or `claude mcp add agent-security-audit -- uvx --from agent-security-audit asa-mcp`). Until then, `uvx --from git+https://github.com/talalkashar/agent-security-audit asa-mcp` works the same way once the repository is public.

### Claude Code

```sh
claude mcp add agent-security-audit -- asa-mcp                  # this project
claude mcp add --scope user agent-security-audit -- asa-mcp     # every project
```

Or commit a project `.mcp.json`:

```json
{
  "mcpServers": {
    "agent-security-audit": { "command": "asa-mcp", "args": [] }
  }
}
```

The Claude Code plugin from step 2 also declares this server through the repository's `.mcp.json`, so you do not need both. The plugin does not install the Python package: install it first (step 1, `pipx install` or `uv tool install`), or the server cannot start. The plugin's `.mcp.json` runs `asa-mcp` from your `PATH`; to run it through `uvx` instead, change it to `{"command": "uvx", "args": ["--from", "agent-security-audit", "asa-mcp"]}` once the package is on PyPI.

### Claude Desktop

Edit `claude_desktop_config.json` (macOS: `~/Library/Application Support/Claude/`; Windows: `%APPDATA%\Claude\`). Claude Desktop does not use your shell's `PATH`, so give the full path:

```json
{
  "mcpServers": {
    "agent-security-audit": { "command": "/Users/you/.local/bin/asa-mcp" }
  }
}
```

Restart Claude Desktop afterwards.

### Cursor

`.cursor/mcp.json` in the project, or `~/.cursor/mcp.json` for every project:

```json
{
  "mcpServers": {
    "agent-security-audit": { "command": "asa-mcp" }
  }
}
```

### Gemini CLI

`~/.gemini/settings.json`, or `.gemini/settings.json` in the project:

```json
{
  "mcpServers": {
    "agent-security-audit": { "command": "asa-mcp" }
  }
}
```

### Windsurf

`~/.codeium/windsurf/mcp_config.json`:

```json
{
  "mcpServers": {
    "agent-security-audit": { "command": "asa-mcp" }
  }
}
```

### VS Code

`.vscode/mcp.json` in the project:

```json
{
  "servers": {
    "agent-security-audit": { "type": "stdio", "command": "asa-mcp" }
  }
}
```

### Codex

`~/.codex/config.toml`:

```toml
[mcp_servers.agent-security-audit]
command = "asa-mcp"
```

## Uninstall

`pipx uninstall agent-security-audit` (or `uv tool uninstall agent-security-audit`), then remove the skill folder or plugin (`/plugin uninstall agent-security-audit@agent-security-audit`) and any MCP entries you added.
