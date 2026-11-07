# Security policy

## Reporting a vulnerability in this tool

Report it privately through GitHub's private vulnerability reporting: open the repository's **Security** tab and choose **Report a vulnerability** (https://github.com/talalkashar/agent-security-audit/security/advisories/new). Do not open a public issue.

Include what you found, how to reproduce it against the local lab (`asa lab`) or a site you own, and the version (`asa --version`). You should get a reply within 7 days.

Examples of what to report:

- The scope gate lets a scan reach a host it should refuse, or follows a redirect off the target.
- The request budget or the rate-limit cap can be exceeded.
- A report, log or evidence line includes a secret, token or personal data.
- A proof test can change or delete data, or a check reports `pass` without having observed the defense.

## Reporting a flaw in someone else's site

This project does not handle those. Contact the site's owner, through its `/.well-known/security.txt` if it has one.

## Supported versions

Only the latest release gets fixes.
