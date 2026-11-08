# Security policy

## Reporting a vulnerability in this tool

Report it privately through GitHub's private vulnerability reporting: open the repository's **Security** tab and choose **Report a vulnerability** (https://github.com/talalkashar/agent-security-audit/security/advisories/new). Do not open a public issue.

Include what you found, how to reproduce it against the local lab (`asa lab`) or a site you own, and the version (`asa --version`). You should get a reply within 7 days.

Examples of what to report:

- The scope gate lets a scan reach a host it should refuse, or follows a redirect off the target.
- The request budget or the rate-limit cap can be exceeded.
- A report, log or evidence line includes a secret, token or personal data.
- A proof test can change or delete data, or a check reports `pass` without having observed the defense.

### Scope

In scope: the `asa` command line tool, the MCP server (`asa-mcp`), the local lab, the skills and agent guidance in this repository, and the reports they write.

Out of scope: findings `asa` reports about a site (report those to the site's owner), the intentional flaws in the `vulnerable` lab mode, and problems that need an attacker who already controls your machine or your agent's configuration.

### Safe harbor

Good-faith research on this tool is welcome. Test against the local lab or sites you own, do not access data that is not yours, and give a reasonable time to fix before you disclose. The maintainer will not pursue or support legal action against research that follows these rules.

## Reporting a flaw in someone else's site

This project does not handle those. Contact the site's owner, through its `/.well-known/security.txt` if it has one.

## Supported versions

Only the latest release gets fixes.
