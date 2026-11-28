# Examples

Run these from the repository root with Git and uv installed. Each example uses the local checkout. The two Next.js fixtures are inputs to the test suite and can be audited without starting an application.

## Check a setting before and after a fix

A reviewer wants to know whether a build exposes browser source maps. Compare the [original config](../tests/fixtures/code_vuln/next.config.js) and the [corrected config](../tests/fixtures/code_fixed/next.config.js).

```sh
uv run --no-project --with . asa code tests/fixtures/code_vuln --check NEXT-02 --no-osv --out before.html
uv run --no-project --with . asa code tests/fixtures/code_fixed --check NEXT-02 --no-osv --out after.html
```

Open the two files. The first shows a medium-severity failure at `next.config.js:2`. The second passes the same check. This verifies the source configuration. Whether a deployed build serves any map files is a separate question.

## Save source evidence for a code review

```sh
uv run --no-project --with . asa code tests/fixtures/code_vuln --check NEXT-02 --no-osv --out review.sarif
```

In `review.sarif`, the result's `ruleId` is `NEXT-02`. Its physical location identifies `next.config.js` and line 2 so a review tool can annotate the relevant line. The default exit threshold is high, so this medium finding produces a report and exits 0. Add `--fail-on medium` if this should fail your build.

## Prepare a review of session handling

```sh
uv run --no-project --with . asa rules --stack nextjs,supabase --area auth
uv run --no-project --with . asa show AUTH-01
```

Use the first command for the checklist. The second gives the individual rule, the evidence to look for and its sources. Running either command only reads the catalog.
