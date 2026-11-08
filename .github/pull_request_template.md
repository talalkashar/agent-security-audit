## What this changes

<!-- One check or one fix per pull request. -->

## Checklist

- [ ] Defensive only: no exploit payloads, payload lists, bypass techniques or tests that could damage data (see `CONTRIBUTING.md`).
- [ ] Tests pass: `PYTHONPATH=src python3 -m unittest discover -s tests`
- [ ] Lint passes: `ruff check .`
- [ ] Docs regenerated if the catalog changed: `python3 scripts/gen_docs.py`
- [ ] No secrets, tokens, cookies or personal data in evidence, tests, fixtures or screenshots ("contents not shown").
- [ ] A check that sends requests a browser would not send on its own is marked `probe = "active"`, so it runs only on local hosts or with `--authorized`.
- [ ] A new `auto` check has lab coverage (`vulnerable` fails, `fixed` passes) and tests for both.
- [ ] Sources are primary and real: no invented incidents, CVE numbers or statistics.
