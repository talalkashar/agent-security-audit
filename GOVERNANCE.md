# Governance

## Maintainer

The project has a single maintainer, Talal Kashar ([@talalkashar](https://github.com/talalkashar)), who owns the
repository and the `agent-security-audit` project on PyPI. There is no company, foundation or second maintainer
behind it today. Organisations that depend on it should plan for that: the code is MIT-licensed, has no runtime
dependencies, and can be forked and kept as is.

## How decisions are made

- The maintainer decides what is merged and released, guided by the rules in [CONTRIBUTING.md](CONTRIBUTING.md). The
  defensive-only rule is not open to change: no exploit payloads, bypass techniques or tests that could damage data.
- Larger changes (new check areas, new network behaviour, changes to the scope gate or to what `--authorized`
  allows) are proposed in an issue first, so the reasoning is public before code is written.
- Any change that makes the tool contact a new host, write a new file or read a new environment variable must update
  [docs/TRUST.md](docs/TRUST.md) in the same pull request, and is called out in [CHANGELOG.md](CHANGELOG.md).

## Releases

- Versions follow [Semantic Versioning](https://semver.org/). While the version is 0.x, a minor release may change
  check IDs, statuses or report fields; the changelog says so when it does.
- Only the maintainer can publish. The maintainer tags a commit on `main` as `vX.Y.Z`, signs the tag, and publishes a
  GitHub release for it (the workflow checks neither the signature nor the branch); the `release.yml` workflow tests
  the tagged commit, builds, attests and publishes to PyPI after a manual approval on the
  `pypi` environment. The steps are in [docs/INSTALL.md](docs/INSTALL.md#publishing-to-pypi-maintainer) and how to
  verify a release is in [docs/TRUST.md](docs/TRUST.md#release-provenance).

## Security fixes

- Vulnerabilities in the tool are reported privately ([SECURITY.md](SECURITY.md)) and take priority over other work.
- A confirmed issue is fixed in a private fork or branch, released as a new patch version, and then disclosed in a
  GitHub security advisory with a CVE requested where it applies. The reporter is credited unless they ask not to be.
- Only the latest release receives fixes.

## Continuity

If the maintainer can no longer maintain the project, the intent is to say so in the README, archive the repository
so it stays readable, and leave the PyPI releases in place. Ownership is transferred only to someone with a public
record of contributions here, and the change is announced in the README and the changelog before any release from the
new owner.

## Conduct

Everyone in project spaces follows the [code of conduct](CODE_OF_CONDUCT.md).
