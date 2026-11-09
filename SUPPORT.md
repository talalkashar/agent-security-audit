# Support

agent-security-audit is maintained by one person in their own time. There is no paid support and no guaranteed
response time; the targets below are best effort.

## Where to ask

| You want to | Use | Expected first reply |
| --- | --- | --- |
| Report a vulnerability in this tool | Private report, as described in [SECURITY.md](SECURITY.md). Never a public issue. | within 7 days |
| Report a bug, or a result you think is wrong | A [GitHub issue](https://github.com/talalkashar/agent-security-audit/issues/new/choose) with the bug or "wrong result" form | within 14 days |
| Propose a check | The "check request" issue form | within 14 days |
| Ask how to use it | A GitHub issue; read [README.md](README.md), [docs/INSTALL.md](docs/INSTALL.md) and `asa show <ID>` first | best effort |

Do not paste secrets, tokens, cookies or other people's data into an issue. Reports quote what the scanned site
served; remove anything sensitive before you share one.

Flaws that `asa` finds in someone else's site are not handled here: contact that site's owner.

## What is supported

- The latest release on PyPI. Fixes go into a new release; older versions are not patched.
- Python 3.11, 3.12, 3.13 and 3.14 on Linux, macOS and Windows (the versions and systems CI tests).
- On Windows, `asa install --yes` refuses to write (see [docs/INSTALL.md](docs/INSTALL.md)); use the dry run and add
  the printed configuration by hand. Everything else is supported.
- Agent integrations follow each agent's documented config paths as of the date in docs/INSTALL.md. When an agent
  changes them, report it with the bug form.

Unreleased code from `main` (`pipx install git+https://github.com/talalkashar/agent-security-audit`) is not supported.
