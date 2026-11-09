# Continuous integration

Four workflows live in `.github/workflows/`. Every third-party action is pinned to a full commit SHA, with the release tag in a trailing comment (`uses: owner/action@<sha> # vX.Y.Z`). Dependabot proposes SHA bumps. Every workflow starts with read-only `contents: read` permission, or with no permissions at all, and grants write scopes only to the job that needs them. Checkouts use `persist-credentials: false`.

## ci.yml: lint and tests

Runs on every push to `main` and on every pull request to `main`. A new push to the same PR cancels the run that is already going.

| Job | What it guards |
| --- | --- |
| `Lint (ruff)` | `ruff check .` with ruff pinned at 0.17.4, so a new ruff release cannot break CI by itself. |
| `Test (<os>, Python <ver>)` | 12 jobs: ubuntu-latest, macos-latest and windows-latest, each with Python 3.11, 3.12, 3.13 and 3.14. Each job runs `pip install -e .`, then `python -m unittest discover -s tests -v`, then smoke-tests the `asa` and `asa-mcp` entry points. |

The test steps run in `bash` on all three operating systems (Git Bash on Windows), so the same commands work everywhere. `fail-fast` is off, so one failing combination does not cancel the others.

**Reading a failure**

- *Lint* failed: run `uvx ruff@0.17.4 check .` on your machine. The log shows the same file, line and rule code.
- *One OS fails and the others pass*: look for paths with a hard-coded `/`, line endings, file locking, or a shell feature that Windows lacks. *One Python version fails*: look for a deprecated or newly added stdlib API.
- *Every test job fails at "Editable install"*: `pyproject.toml` or the package layout is broken.
- *Tests pass but the smoke step fails*: an entry point in `[project.scripts]` no longer imports or exits cleanly.
- To reproduce a run on your machine: `python -m pip install -e . && python -m unittest discover -s tests -v`. Without installing the package: `PYTHONPATH=src python3 -m unittest discover -s tests`.

## codeql.yml: static analysis

Runs CodeQL for Python on push and pull request to `main`, and once a week (Monday 06:23 UTC) so that new queries reach code nobody has changed. The workflow uses `build-mode: none` because the package is pure Python. Only its analysis job holds `security-events: write`, which it needs to upload results to code scanning.

**Reading a failure**

- A failed *job* (red X) is usually a setup problem, such as the action not being able to download or code scanning being off for the repository. The step log shows the cause.
- *Findings* do not fail the job. They appear under **Security > Code scanning** and as annotations on the pull request. Open the alert to see the source-to-sink path, then fix the code or dismiss the alert with a written reason.

## scorecard.yml: OpenSSF Scorecard

Runs on push to `main`, once a week (Tuesday 07:41 UTC), and on manual dispatch. It grades supply-chain practices: pinned dependencies, token permissions, branch protection, code review, a security policy, and others. It uploads a SARIF file to code scanning and keeps it as a 5-day artifact. With `publish_results: true` (which needs `id-token: write`) it also publishes the score to the public Scorecard API and badge.

`publish_results` only accepts a minimal workflow: no top-level `env` or `defaults`, and only an allow-listed set of actions. That is why this file has no `concurrency` block. Keep it bare.

**Reading a failure**

- The job fails at the scorecard step with a publish or "workflow verification" error: someone added a non-allow-listed step, a top-level `env`/`defaults`, or a write permission at workflow level. Revert that change.
- A low score is not a failure. Each check shows up as a code-scanning alert that includes the remediation steps.

## release.yml: build and publish

Runs only when the owner publishes a GitHub release. Two jobs:

| Job | What it does |
| --- | --- |
| `build` | Checks out the release, installs `build==1.6.1`, runs `python -m build` and stores `dist/` (sdist and wheel) as an artifact. |
| `publish` | Downloads `dist/` and uploads it to PyPI with `pypa/gh-action-pypi-publish` through [Trusted Publishing](https://docs.pypi.org/trusted-publishers/). It runs in the `pypi` environment and is the only job with `id-token: write`; no PyPI token is stored in the repository. |

The one-time PyPI and environment setup, and the release steps, are in [INSTALL.md](INSTALL.md#publishing-to-pypi-owner-once).

**Reading a failure**

- *build* fails: the package does not build from a clean checkout. Run `python -m pip install build==1.6.1 && python -m build` locally.
- *publish* fails with a trusted-publisher or OIDC error: the pending publisher on PyPI does not match the owner, repository, workflow file name or environment name. It fails with "file already exists" when that version was uploaded before; bump the version.

## Changing a workflow

1. Pin any new action to a commit SHA. For annotated tags, take the `^{}` line: `git ls-remote https://github.com/<owner>/<repo> 'refs/tags/<tag>^{}'`. Put the tag in a comment.
2. Check the YAML parses: `uvx --from pyyaml python -c 'import yaml,sys; [yaml.safe_load(open(f)) for f in sys.argv[1:]]' .github/workflows/*.yml`
3. Audit it: `uvx zizmor .github/workflows`. The default persona must report no findings. `--persona pedantic` reports one known item, the missing `concurrency` block in `scorecard.yml`, which is left out on purpose (see above).
