# Continuous integration

Four workflows live in `.github/workflows/`. Every third-party action is pinned to a full commit SHA, with the release tag in a trailing comment (`uses: owner/action@<sha> # vX.Y.Z`). Dependabot proposes SHA bumps. Every workflow starts with read-only `contents: read` permission, or with no permissions at all, and grants write scopes only to the job that needs them. Checkouts use `persist-credentials: false`.

## ci.yml: lint and tests

Runs on every push to `main` and on every pull request to `main`. A new push to the same PR cancels the run that is already going.

| Job | What it guards |
| --- | --- |
| `Lint (ruff)` | `ruff check .` with ruff pinned at 0.17.4, so a new ruff release cannot break CI by itself. |
| `Test (<os>, Python <ver>)` | 12 jobs: ubuntu-latest, macos-latest and windows-latest, each with Python 3.11, 3.12, 3.13 and 3.14. Each job runs `pip install -e .`, then `python -m unittest discover -s tests -v`, then smoke-tests the `asa` and `asa-mcp` entry points. |
| `Wheel (<os>)` | 3 jobs, one per OS, Python 3.13. Builds the sdist and wheel (`build==1.6.1`), runs `twine check --strict`, installs the **wheel** (not an editable install) into a clean virtualenv, and runs `scripts/smoke_wheel.py` from a temporary folder: `asa --version` must match `pyproject.toml`, `asa list`, `asa show AUTH-01` and `asa-mcp` must work, and a scan of `asa lab` on 127.0.0.1 must fail checks in the vulnerable mode and none in the fixed mode. This catches package data missing from the wheel. |

The test steps run in `bash` on all three operating systems (Git Bash on Windows), so the same commands work everywhere. `fail-fast` is off, so one failing combination does not cancel the others.

**Reading a failure**

- *Lint* failed: run `uvx ruff@0.17.4 check .` on your machine. The log shows the same file, line and rule code.
- *One OS fails and the others pass*: look for paths with a hard-coded `/`, line endings, file locking, or a shell feature that Windows lacks. *One Python version fails*: look for a deprecated or newly added stdlib API.
- *Every test job fails at "Editable install"*: `pyproject.toml` or the package layout is broken.
- *Tests pass but the smoke step fails*: an entry point in `[project.scripts]` no longer imports or exits cleanly.
- *Only the wheel job fails*: a file the code reads (`catalog/*.toml`, `skill/SKILL.md`) is missing from `[tool.setuptools.package-data]`, or the version fields disagree. Reproduce with `python -m build && python -m venv /tmp/w && /tmp/w/bin/pip install dist/*.whl && python scripts/smoke_wheel.py /tmp/w/bin`.
- To reproduce a run on your machine: `python -m pip install -e . && python -m unittest discover -s tests -v`. Without installing the package: `PYTHONPATH=src python3 -m unittest discover -s tests`.

## codeql.yml: static analysis

Runs CodeQL for Python on push and pull request to `main`, and once a week (Monday 06:23 UTC) so that new queries reach code nobody has changed. The workflow uses `build-mode: none` because the package is pure Python. Only this job holds `security-events: write`, which it needs to upload results to code scanning.

**Reading a failure**

- A failed *job* (red X) is usually a setup problem, such as the action not being able to download or code scanning being off for the repository. The step log shows the cause.
- *Findings* do not fail the job. They appear under **Security > Code scanning** and as annotations on the pull request. Open the alert to see the source-to-sink path, then fix the code or dismiss the alert with a written reason.

## scorecard.yml: OpenSSF Scorecard

Runs on push to `main`, once a week (Tuesday 07:41 UTC), and on manual dispatch. It grades supply-chain practices: pinned dependencies, token permissions, branch protection, code review, a security policy, and others. It uploads a SARIF file to code scanning and keeps it as a 5-day artifact. With `publish_results: true` (which needs `id-token: write`) it also publishes the score to the public Scorecard API and badge.

`publish_results` only accepts a minimal workflow: no top-level `env` or `defaults`, and only an allow-listed set of actions. That is why this file has no `concurrency` block. Keep it bare.

**Reading a failure**

- The job fails at the scorecard step with a publish or "workflow verification" error: someone added a non-allow-listed step, a top-level `env`/`defaults`, or a write permission at workflow level. Revert that change.
- A low score is not a failure. Each check shows up as a code-scanning alert that includes the remediation steps.

## release.yml: build, attest and publish

Runs only when the maintainer publishes a GitHub release. PyPI's trusted publisher is bound to this file name and to the `pypi` environment, so neither may be renamed. Jobs, in order:

| Job | Permissions | What it does |
| --- | --- | --- |
| `verify` | `contents: read` | Fails unless the release tag is `v` + the `version` in `pyproject.toml`; runs `ruff check .` and the full unit test suite on the tagged commit (`tests/test_release.py` checks that every version field and pinned install command agree). |
| `build` | `contents: read` | Builds the sdist and wheel with `SOURCE_DATE_EPOCH` set to the commit time, runs `twine check --strict`, smoke-tests the installed wheel (`scripts/smoke_wheel.py`), writes a CycloneDX SBOM (`scripts/make_sbom.py`) and `SHA256SUMS`. |
| `attest` | `id-token: write`, `attestations: write` | Build provenance attestations for the sdist, wheel, SBOM and `SHA256SUMS` (`actions/attest-build-provenance`). |
| `publish` | `id-token: write`; environment `pypi` | Uploads the sdist and wheel to PyPI with Trusted Publishing. The `pypi` environment's required reviewer must approve first. |
| `release-assets` | `contents: write` | Attaches the sdist, wheel, `SHA256SUMS` and SBOM to the GitHub release with `gh release upload`. |

**Reading a failure**

- *verify* fails at "Tag matches the package version": the tag and `pyproject.toml` disagree. Delete the release and tag, fix the version on `main`, and tag again. Never move a published tag.
- *publish* fails with an OIDC or "trusted publisher" error: the PyPI publisher settings (owner, repository, `release.yml`, `pypi`) no longer match the workflow.
- A PyPI upload cannot be replaced. If a bad build was published, yank it on PyPI and release a new patch version.

How to verify the published files is in [TRUST.md](TRUST.md#release-provenance).

## Changing a workflow

1. Pin any new action to a commit SHA. For annotated tags, take the `^{}` line: `git ls-remote https://github.com/<owner>/<repo> 'refs/tags/<tag>^{}'`. Put the tag in a comment.
2. Check the YAML parses: `uvx --from pyyaml python -c 'import yaml,sys; [yaml.safe_load(open(f)) for f in sys.argv[1:]]' .github/workflows/*.yml`
3. Audit it: `uvx zizmor .github/workflows`. The default persona must report no findings. `--persona pedantic` reports one known item, the missing `concurrency` block in `scorecard.yml`, which is left out on purpose (see above).

`tests/test_release.py` fails if any `uses:` line is not pinned to a 40-character SHA with a version comment. No repository visibility or billing settings are changed by these workflows. Branch protection for `main` is described in [CONTRIBUTING.md](../CONTRIBUTING.md#branch-protection-and-signed-commits).
