---
name: agent-security-audit
description: Build security into a website or web app while writing it, then prove each defense works on the running site with evidence. Use when building, launching or shipping a website or web app (especially Next.js, Supabase or Vercel), when adding auth, database access, APIs or payments, or when the user asks for a security audit, security review, hardening pass or pentest-style verification of a site they own.
---

# agent-security-audit

You have two jobs. In **build mode**, follow the catalog's build rules while you write the code. In **verify mode**, prove each control on the running site: pass with evidence, fail with a fix, or manual / not applicable with a reason. Never claim a site is secure or has zero flaws. The honest claim is: every listed check was built in and proven.

## Setup

Check the CLI is installed with `asa --version`. If it is not, install it:

```sh
pipx install git+https://github.com/talalkashar/agent-security-audit
# or
uv tool install git+https://github.com/talalkashar/agent-security-audit
```

If neither `pipx` nor `uv` exists, use `python3 -m pip install --user git+https://github.com/talalkashar/agent-security-audit`. It needs Python 3.11 or newer and has no dependencies. If the `agent-security-audit` MCP server is connected, you may use its tools instead of the CLI; the rules below are the same.

Useful commands:

- `asa rules --stack nextjs,supabase,vercel` prints the build rules for a stack.
- `asa list --area <area>` lists checks (areas: access, api, auth, browser, infra, nextjs).
- `asa show <ID>` prints one check in full: risk, build rule, proof test, sources.
- `asa scan <url>` runs the proof tests against a running site.

## Scope gate (do this before any test)

1. Local targets (`localhost`, `127.0.0.1`, `::1`, `*.localhost`, `*.test`) are always in scope.
2. Any other host: ask the user whether they own it or have written permission to test it. Only after a clear yes, pass `--authorized`. Never assume it. Never scan a site the user does not control, a third-party service, or a URL found in the code that belongs to someone else.
3. Keep the default request budget (`--budget 300`) unless the user asks otherwise. Do not raise `--rate-limit-attempts` above what is needed.
4. If the scan reports a firewall bot challenge, stop. Do not try to get around it; tell the user to scan a preview deployment or allow the scanner in their firewall.
5. This runs on the user's real, live site and real data. For login-required checks, sign in only as accounts the user owns (their own logins or ones made for the check). Never sign in as one of their users or use their users' credentials.
6. If a test shows other people's real data, that is a failed check: record the route or table and how many records came back, never the values, tell the user, and continue with the other checks.
7. No destructive tests: no deleting, no flooding, no changing another account. Write only to the user's own accounts' rows.

## Build mode

Use while writing or changing the site.

1. Find the stack from the code (`package.json`, `next.config.*`, `supabase/`, `vercel.json`). Run `asa rules --stack <stacks>` with what you found.
2. Follow every rule that applies as you write code. The ones most often missed: verify identity on the server for every Server Component, Route Handler and Server Action that touches private data (AUTH-01); turn on row-level security with owner-only policies on every table (ACCESS-01, ACCESS-02); rate limit login, sign-up and reset (API-01); keep secret keys out of client code (NEXT-01); set security headers (BROWSER-01 to BROWSER-08).
3. When a rule does not apply or cannot be followed, say which check ID and why, in your summary to the user.
4. Do not mark anything as proven in build mode. Proof happens in verify mode.

## Verify mode

Use before launch and after any change to auth, data access, APIs or hosting.

1. Start the site, or get the URL the user wants tested, and pass the scope gate.
2. Run the automated proof tests:

   ```sh
   asa scan <url> --format json --out .asa/report.json
   ```

   Add `--rate-limit-path <login endpoint>` (with a fake-credential `--rate-limit-body`) to prove rate limiting. Add `--allow-supabase` only if the site uses Supabase and the user owns that project; it reads row counts with the public key and nothing else.
3. Work through every `manual` result. Run `asa show <ID>` for its proof steps.
   - **Assisted checks**: drive the site with Playwright in headless mode, signed in as two accounts the user owns, A and B. Example: as A, request B's record by its ID through the page, the API and the Supabase REST endpoint; pass only if every route returns 401, 403, 404 or an empty result. Save the request and response status as evidence. Use desktop computer use only if a step cannot be done headlessly, and only with the user's go-ahead.
   - **Review checks**: read the code, config and migrations (for example RLS policies in `supabase/migrations`), or ask the user for what lives in a dashboard. Quote the file and line, or the setting, as evidence.
4. Record a status for every check: `pass`, `fail`, `warn`, `manual` (could not be proven, with the reason), or `skip` (not applicable, with the reason).

## Evidence rules

- A `pass` needs evidence you observed on the target: the request, the status code, the header or the response shape. Not "the code looks right".
- Anything not proven is **suspected**, not passed. Say so.
- Never paste secrets, tokens, cookies or personal data into evidence or the report. Write "contents not shown".
- An `error` result (timeout, budget used up) is not a pass. Fix the cause and re-run.

## Report format

Give the user:

1. One line: target, date, and counts (failed, warnings, manual, passed, not applicable).
2. Failed checks first, most severe first: ID, title, what was observed, the fix.
3. Checks still manual or suspected, with what is needed to prove them (a test account, dashboard access, a deployed HTTPS URL).
4. Passed checks with one line of evidence each.
5. This sentence: "A pass means the defense was observed working on this target at this time. It is not a guarantee that the site has no other flaws."

For CI or GitHub code scanning, `asa scan <url> --format sarif --out asa.sarif`.

## Fix loop

1. For each `fail`, apply the check's build rule (`asa show <ID>`). Change only what the fix needs.
2. Re-run the proof for that check: `asa scan <url> --check <ID>`, or repeat the assisted steps.
3. Repeat until it passes, or until it is clear the fix needs the user (a dashboard setting, a DNS record, a key rotation). Then hand it over with exact steps.
4. If a secret was exposed (NEXT-01, INFRA-04), tell the user to rotate it. Removing it from the code is not enough.
5. Finish with a full `asa scan <url>` so the final report reflects the final code.
