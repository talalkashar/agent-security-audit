# Contributing

Thank you for helping. This project has one rule above the others: **defensive only**. It helps people build and prove defenses on sites they own. It must never contain exploit payloads, payload lists, bypass techniques, ways around rate limits or firewalls, or tests that could damage data, overload a service or touch an account the tester does not own. Pull requests that add any of these are closed.

## Set up

```sh
git clone https://github.com/talalkashar/agent-security-audit
cd agent-security-audit
PYTHONPATH=src python3 -m unittest discover -s tests   # Python 3.11+, no dependencies
PYTHONPATH=src python3 -m agent_security_audit list
```

Lint with ruff if you have it (`ruff check .`); the settings are in `ruff.toml`. Do not add runtime dependencies.

## Add a check

1. **Pick the area file** in `src/agent_security_audit/catalog/` (access, api, auth, browser, cms, infra, nextjs) and add a `[[check]]` entry with the next free ID for that area.
2. **Fill every field.** The loader rejects an entry with a missing or unknown field:
   - `id`, `title`, `severity` (critical, high, medium, low), `layer` (OSI 1-7), `cwe` (list like `["CWE-79"]`), optional `asvs`
   - `risk`: what goes wrong and why it matters, in plain words
   - `build`: what the agent must do while writing code so the flaw never appears; concrete and stack-aware
   - `proof`: a safe, non-destructive way to show the defense working on a running site the tester owns, with clear pass and fail conditions
   - `mode`: `auto` (the scanner runs it), `assisted` (an agent with a headless browser and test accounts) or `review` (code, dashboard or policy)
   - `stacks`: any of `any`, `nextjs`, `supabase`, `vercel`, `node`
   - `sources`: at least one, each with a `title` and an `https` URL. Use primary sources: OWASP (ASVS, Cheat Sheets, WSTG), CWE, NIST, vendor security docs and advisories, CVE entries. No invented incidents, CVE numbers or statistics.
3. **Regenerate the docs**: `python3 scripts/gen_docs.py`. The test suite fails if `docs/checks/` or the catalog table in `README.md` is out of date.

## Add an automated proof test (mode = auto)

An `auto` check also needs:

1. **Code** in `src/agent_security_audit/checks/`, registered with `@auto("<ID>")`. It takes a `Context`, sends requests only through `ctx.client` (which enforces the scope, the budget and same-origin), and returns a `Result` from `model.py`: `pass` only when the defense was observed, with evidence; `fail` with evidence and a fix; `skip` when it does not apply; `manual` when it needs a person. Never put secrets or personal data in evidence; write "contents not shown".
2. **Lab coverage** in `src/agent_security_audit/lab.py`: the `vulnerable` mode shows the flaw and the `fixed` mode shows the defense.
3. **Tests** in `tests/` that run the check against both lab modes and assert `fail` and `pass`. Tests never reach a non-local host.

## Pull requests

- One check or one fix per pull request.
- Plain, exact English in check text and docs. No hype.
- Run the tests before you open the pull request.
- Report security problems in the tool privately; see `SECURITY.md`.

## Branch protection and signed commits

`main` is protected. The rules, set in the repository settings (they are not visible from a clone):

- Changes land through a pull request; direct pushes, force pushes and branch deletion are blocked.
- The `ci` workflow must pass: lint, the test matrix and the wheel jobs. CodeQL runs on every pull request.
- [CODEOWNERS](.github/CODEOWNERS) review is required, so the maintainer approves every change.
- **Commits must be signed** (SSH, GPG or S/MIME) and show as "Verified" on GitHub. Set it up once with
  `git config commit.gpgsign true` and a signing key added to your GitHub account
  ([GitHub docs](https://docs.github.com/en/authentication/managing-commit-signature-verification)). An unsigned
  commit blocks the merge; re-sign it with `git rebase --exec 'git commit --amend --no-edit -S' main` on your branch.
- Release tags (`vX.Y.Z`) are signed and created by the maintainer only; see [GOVERNANCE.md](GOVERNANCE.md).

By opening a pull request you confirm that you wrote the change or have the right to submit it under the MIT license.
