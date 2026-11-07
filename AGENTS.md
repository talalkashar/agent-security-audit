# agent-security-audit: guidance for coding agents

Copy this section into your project's `AGENTS.md` (Codex, Cursor and other agents read it) to use agent-security-audit while building and before shipping a website.

## Security: build it in, then prove it

Tool: `asa` (install with `pipx install git+https://github.com/talalkashar/agent-security-audit` or `uv tool install git+https://github.com/talalkashar/agent-security-audit`; Python 3.11+, no dependencies). Check with `asa --version`.

**Build mode** (while writing code)
- Run `asa rules --stack <nextjs,supabase,vercel,node>` for the stacks the project uses and follow every rule that applies.
- Most often missed: server-side identity on every private route and Server Action (AUTH-01), RLS with owner-only policies on every table (ACCESS-01, ACCESS-02), rate limits on login/sign-up/reset (API-01), no secret keys in client code (NEXT-01), security headers (BROWSER-01 to BROWSER-08).
- If a rule cannot be followed, name the check ID and the reason. Nothing is proven in build mode.

**Verify mode** (before launch and after auth, data, API or hosting changes)
1. Any URL: run the scan right away; passive checks need no permission. Add `--authorized` (enables active probes) only when the site is the project you are building with the user or the user says they own it or have written permission. Local hosts always get active probes.
2. Run `asa scan <url> --format json --out .asa/report.json` (add `--rate-limit-path <login endpoint>`; add `--allow-supabase` only for the user's own Supabase project).
3. For each `manual` result, run `asa show <ID>` and settle it without asking the user for setup: read the code, migrations and config first (a route with no server-side auth check, a table with no RLS policy, is a fail with file and line). Only if the code does not settle an assisted check, sign up two accounts A and B through the site's own sign-up and test in headless Playwright (A must not read or change B's data through the page, the API or the Supabase REST endpoint). List those accounts at the end so the user can delete them. Use desktop computer use only as a fallback and with the user's go-ahead.
4. Fix each `fail` with its build rule, re-run `asa scan <url> --check <ID>`, repeat until it passes or the fix needs the user. Tell the user to rotate any exposed secret.

**Rules**
- Keep the default request budget. Stop on a firewall bot challenge; do not get around it.
- Runs on the real, live site and its real data. Sign in only as accounts you signed up for the test, never as one of the site's users. If a test shows other people's data, record a fail with the route or table and the record count (never the values), tell the user, and keep going.
- No destructive tests: nothing deleted, flooded or changed in another account.
- A pass needs observed evidence (request, status, header). Anything not proven is suspected, not passed. Never put secrets, tokens or personal data in evidence.
- Report: counts; failed checks by severity with the fix; manual/suspected checks with what is needed to prove them; passes with one line of evidence each. End with: "A pass means the defense was observed working on this target at this time. It is not a guarantee that the site has no other flaws." Never claim the site has zero flaws.

## Working on this repository

- Python 3.11+, standard library only at runtime. Run tests with `PYTHONPATH=src python3 -m unittest discover -s tests`.
- The catalog lives in `src/agent_security_audit/catalog/*.toml`. After changing it, run `python3 scripts/gen_docs.py` to regenerate `docs/checks/` and the catalog table in `README.md`.
- Defensive only: no exploit payloads, bypass techniques or tests that could damage data. See `CONTRIBUTING.md`.
- Never scan a host you do not own; the tests use the local lab (`asa lab`).
