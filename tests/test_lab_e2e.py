"""End to end: start the lab in both modes, run `asa scan --authorized` through the CLI, and check every auto check.

Each auto check is in exactly one bucket below. Vulnerable mode must give the listed status, fixed mode must pass,
and no check may error. A check that can only ever warn (a weaker setting, not a proven flaw) is in WARN_ONLY; the
lab cannot push it to fail without breaking the rule that fail needs observed evidence of a flaw.
"""

import contextlib
import io
import json
import os
import tempfile
import unittest

from agent_security_audit import catalog, cli, lab
from agent_security_audit.checks import load_all

# Observed flaw in vulnerable mode, observed defense in fixed mode.
FAIL = {
    "API-02",      # verbose errors: stack trace in 404/500 bodies
    "API-19",      # open redirect via /redirect?url=
    "API-20",      # directory listing at /uploads/
    "API-21",      # debug endpoint /actuator/env
    "API-24",      # TRACE echoes the request
    "API-25",      # Server header discloses the lab's software versions
    "BROWSER-02",  # no CSP
    "BROWSER-03",  # no nosniff
    "BROWSER-04",  # framable
    "BROWSER-05",  # Referrer-Policy: unsafe-url
    "BROWSER-06",  # session cookie without Secure/HttpOnly/SameSite
    "BROWSER-07",  # CORS reflects any origin with credentials
    "BROWSER-22",  # password form posts to plain http on another host
    "BROWSER-23",  # known-vulnerable jQuery 3.4.1
    "INFRA-04",    # /.env and /.git/HEAD served
    "NEXT-01",     # service_role key and live Stripe key in client JS
    "NEXT-02",     # public source map
    "NEXT-03",     # X-Powered-By: Next.js
}

# Highest status these checks give by design: the setting is weaker, not a proven flaw.
WARN_ONLY = {
    "API-01",      # no throttle seen: a limit may still exist elsewhere (another IP, a WAF)
    "API-22",      # public OpenAPI file is fine for a public API
    "API-23",      # GraphQL introspection on is fine for a public API
    "BROWSER-08",  # missing Permissions-Policy / COOP is hardening
    "BROWSER-21",  # third-party script without SRI is a risk, not an observed compromise
    "INFRA-05",    # missing security.txt
}

# The lab cannot exercise these over plain HTTP on 127.0.0.1: they skip in both modes.
GAPS = {
    "ACCESS-01": "needs a real Supabase project URL; the lab ships none so a scan never leaves the machine",
    "BROWSER-01": "HSTS needs HTTPS",
    "BROWSER-20": "mixed content needs an HTTPS page",
    "INFRA-01": "HTTP-to-HTTPS redirect is tested on the deployed site",
    "INFRA-02": "certificate needs HTTPS",
    "INFRA-03": "TLS versions need HTTPS",
    "INFRA-26": "TLS cipher/protocol details need HTTPS",
    "INFRA-06": "DNS (CAA/DNSSEC): a local host has no public DNS",
    "INFRA-07": "DNS: a local host has no public DNS",
    "INFRA-11": "email (SPF): a local host has no public DNS",
    "INFRA-12": "email (DMARC): a local host has no public DNS",
    "INFRA-27": "DNS/email: a local host has no public DNS",
    "INFRA-28": "DNS/email: a local host has no public DNS",
    "INFRA-24": "open database ports are expected on a dev machine, so local hosts skip",
    "INFRA-25": "open admin ports are expected on a dev machine, so local hosts skip",
    "CMS-02": "the lab is not a self-hosted CMS; version fixtures are in test_cms.py",
    "CMS-03": "the lab is not WordPress; API-marker fixtures are in test_cms.py",
}

# No CMS markers means these observations remain unproven, rather than passing or skipping.
MANUAL_GAPS = {"CMS-01", "CMS-04",
               "NEXT-04"}  # Next.js markers, no version string: the lab never sends a query to OSV

# These pass with the observation in the summary only ("No X-Powered-By header", "2 map URLs probed") and an empty
# evidence list. Owned by the check modules, not the lab; listed so a new empty-evidence pass is caught.
PASS_WITHOUT_EVIDENCE = {"NEXT-02", "NEXT-03"}

# Fake secret values the lab serves. Evidence must name them, never repeat them.
SECRETS = (lab.fake_jwt("service_role"), "sk_" + "live_" + "FAKE0000000000000000000000",
           "postgres://lab:lab@", "lab123", "not-a-secret")


def scan_cli(url):
    with tempfile.TemporaryDirectory() as tmp:
        out = os.path.join(tmp, "r.json")
        with contextlib.redirect_stderr(io.StringIO()):
            code = cli.main(["scan", url, "--authorized", "--auto-only", "--quiet", "--format", "json",
                             "--out", out, "--rate-limit-path", "/api/login", "--fail-on", "none"])
        if code != 0:
            raise AssertionError(f"asa scan exited {code}")
        with open(out, encoding="utf-8") as fh:
            return {r["check_id"]: r for r in json.load(fh)["results"]}


class LabEndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.results = {}
        for mode in lab.MODES:
            server, url = lab.serve(mode, 0)
            try:
                cls.results[mode] = scan_cli(url)
            finally:
                server.shutdown()
                server.server_close()

    def test_buckets_cover_every_auto_check_once(self):
        auto = {c.id for c in catalog.load() if c.mode == "auto" and c.id in load_all()}
        buckets = [FAIL, WARN_ONLY, set(GAPS), MANUAL_GAPS]
        covered = FAIL | WARN_ONLY | set(GAPS) | MANUAL_GAPS
        self.assertEqual(sum(len(b) for b in buckets), len(covered), "a check is in two buckets")
        self.assertEqual(covered, auto)
        for mode in lab.MODES:
            self.assertEqual(set(self.results[mode]), auto)

    def test_no_check_errors(self):
        for mode in lab.MODES:
            for cid, r in self.results[mode].items():
                with self.subTest(mode=mode, check=cid):
                    self.assertNotEqual(r["status"], "error", r["summary"])

    def test_vulnerable_mode(self):
        got = self.results["vulnerable"]
        for cid in FAIL:
            with self.subTest(check=cid):
                self.assertEqual(got[cid]["status"], "fail", got[cid]["summary"])
                self.assertTrue(got[cid]["evidence"], "a fail needs observed evidence")
        for cid in WARN_ONLY:
            with self.subTest(check=cid):
                self.assertEqual(got[cid]["status"], "warn", got[cid]["summary"])

    def test_fixed_mode_passes_with_evidence(self):
        got = self.results["fixed"]
        for cid in FAIL | WARN_ONLY:
            with self.subTest(check=cid):
                self.assertEqual(got[cid]["status"], "pass", got[cid]["summary"])
                if cid not in PASS_WITHOUT_EVIDENCE:
                    self.assertTrue(got[cid]["evidence"], "a pass needs observed evidence")

    def test_gaps_skip_in_both_modes(self):
        for mode in lab.MODES:
            for cid in GAPS:
                with self.subTest(mode=mode, check=cid):
                    self.assertEqual(self.results[mode][cid]["status"], "skip")

    def test_cms_absence_requires_manual_review_in_both_modes(self):
        for mode in lab.MODES:
            for cid in MANUAL_GAPS:
                with self.subTest(mode=mode, check=cid):
                    self.assertEqual(self.results[mode][cid]["status"], "manual")

    def test_evidence_has_no_secret_values(self):
        for mode in lab.MODES:
            for cid, r in self.results[mode].items():
                text = json.dumps(r)
                for value in SECRETS:
                    with self.subTest(mode=mode, check=cid, value=value[:12]):
                        self.assertNotIn(value, text)

    @classmethod
    def tearDownClass(cls):
        if os.environ.get("ASA_LAB_GAPS"):
            rows = "\n".join(f"  {cid:<11} {why}" for cid, why in sorted(GAPS.items()))
            print(f"\nAuto checks the lab does not exercise (expected: need HTTPS, public DNS or a real "
                  f"Supabase project):\n{rows}")


if __name__ == "__main__":
    os.environ.setdefault("ASA_LAB_GAPS", "1")
    unittest.main()
