"""Offline regression tests for passive CMS checks."""

import subprocess
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from agent_security_audit.checks import Context, cms


class Page:
    def __init__(self, text, url="https://example.test/"):
        self.text = text
        self.url = url
        self.headers = {}

    def get(self, name, default=None):
        return self.headers.get(name.lower(), default)


class Client:
    def __init__(self):
        self.calls = []


def context(*pages):
    client = Client()
    ctx = Context("https://example.test", client)
    ctx.cache["crawl"] = SimpleNamespace(pages=list(pages), cut=False)
    return ctx


class CmsChecksTest(unittest.TestCase):
    def test_html_doctype_does_not_make_a_complete_sample_limited(self):
        ctx = context(Page('<!DOCTYPE html><meta name=generator content=WordPress>'))
        self.assertEqual(cms.version_disclosure(ctx).status, "pass")
        self.assertEqual(cms.admin_login_linked(ctx).status, "pass")
        self.assertFalse(ctx.cache.get("cms-limited"))

    def test_detects_versioned_cms_and_hosted_platforms(self):
        ctx = context(Page('<meta name="generator" content="WordPress 7.1.4"> '
                           '<script src="/wp-includes/js/wp-embed.min.js?ver=7.1.4"></script> '
                           'cdn.shopify.com'))
        found = cms.detect(ctx)
        self.assertEqual(found["WordPress"]["version"], "7.1.4")
        self.assertIn("Shopify", found)
        self.assertIn("WordPress", cms.version_disclosure(ctx).evidence[0])

    def test_drupal_script_marker_does_not_establish_version(self):
        found = cms.detect(context(Page('jQuery.extend(Drupal.settings, {});')))
        self.assertEqual(found["Drupal"]["version"], "")
        result = cms.outdated_core(context(Page('jQuery.extend(Drupal.settings, {});')))
        self.assertEqual(result.status, "manual")

    def test_supported_and_ended_release_lines(self):
        cases = [("WordPress", "7.1", "ok"), ("WordPress", "7.0", "old"),
                 ("Drupal", "11.3", "ok"), ("Drupal", "11.2", "eol"),
                 ("Drupal", "10.6", "old"), ("Joomla", "5.4", "old"),
                 ("Joomla", "4.4", "eol"), ("Joomla", "6.2", "ok"), ("Joomla", "6.0", "eol")]
        for name, version, expected in cases:
            with self.subTest(name=name, version=version):
                self.assertEqual(cms._judge(name, version)[0], expected)

    def test_newer_version_is_unknown_and_reported_manual(self):
        for name, version, html in [
            ("WordPress", "7.2", '<meta name="generator" content="WordPress 7.2">'),
            ("Drupal", "12.0", '<meta name="generator" content="Drupal 12.0">'),
            ("Joomla", "7.0", '<meta name="generator" content="Joomla! 7.0">'),
        ]:
            with self.subTest(name=name):
                self.assertEqual(cms._judge(name, version)[0], "unknown")
                result = cms.outdated_core(context(Page(html)))
                self.assertEqual(result.status, "manual")

    def test_api_markers_are_manual_and_do_not_claim_vulnerability(self):
        ctx = context(Page('<meta name="generator" content="WordPress"> '
                           '<link rel="https://api.w.org/" href="/wp-json/"> '
                           '<link rel="pingback" href="/xmlrpc.php">'))
        result = cms.wordpress_api(ctx)
        self.assertEqual(result.status, "manual")
        self.assertIn("do not establish", result.summary)
        self.assertTrue(any("https://api.w.org/" in item for item in result.evidence))

    def test_all_checks_reuse_crawl_without_extra_requests(self):
        ctx = context(Page('<meta name="generator" content="WordPress 7.1"> '
                           '<a href="/wp-login.php">Login</a> '
                           '<link rel="https://api.w.org/">'))
        for check in (cms.version_disclosure, cms.outdated_core, cms.wordpress_api,
                      cms.admin_login_linked):
            check(ctx)
        self.assertEqual(ctx.client.calls, [])

    def test_pathological_html_is_bounded_and_late_marker_ignored(self):
        text = "x" * (cms.MAX_TEXT + 10_000) + '<meta name="generator" content="WordPress 7.1">'
        ctx = context(Page(text))
        self.assertEqual(cms.detect(ctx), {})
        result = cms.version_disclosure(ctx)
        self.assertEqual(result.status, "manual")
        self.assertLess(len(result.summary), 500)
        self.assertTrue(all(len(item) <= 500 for item in result.evidence))

    def test_generator_attribute_order_case_spacing_and_unquoted_values(self):
        for html, name, version in [
            ('<META CONTENT="Drupal 11.4.12 (https://www.drupal.org)" NAME = Generator>', "Drupal", "11.4.12"),
            ("<meta content='Joomla! 6.2.0' name=generator>", "Joomla", "6.2.0"),
            ('<meta content="WordPress 7.1.4" name="generator"/>', "WordPress", "7.1.4"),
        ]:
            with self.subTest(html=html):
                self.assertEqual(cms.detect(context(Page(html)))[name]["version"], version)

    def test_major_prerelease_invalid_and_future_versions_are_manual(self):
        for name, versions in {
            "WordPress": ["7", "7.2", "7.1.5", "7.1.4-beta1", "7.1.4.5", "0.0", "9" * 5000],
            "Drupal": ["10", "11", "10.7", "11.5", "11.99", "9.99", "11.4.13", "11.4.0-dev"],
            "Joomla": ["5", "6", "5.5", "6.3", "4.99", "6.2.1", "6.2.0-rc1"],
        }.items():
            for version in versions:
                with self.subTest(name=name, version=version[:20]):
                    self.assertEqual(cms._judge(name, version)[0], "unknown")
                    html = f'<meta name="generator" content="{name} {version}">'
                    self.assertEqual(cms.outdated_core(context(Page(html))).status, "manual")

    def test_status_classification_is_explicit(self):
        for name, version, status in [
            ("WordPress", "7.1.4", "pass"), ("WordPress", "7.0.8", "warn"),
            ("Drupal", "11.4.12", "pass"), ("Drupal", "10.6.21", "warn"),
            ("Drupal", "9.5", "fail"), ("Drupal", "11.2", "fail"),
            ("Joomla", "6.2.0", "pass"), ("Joomla", "5.4.10", "warn"),
            ("Joomla", "4.4", "fail"), ("Joomla", "5.3", "fail"),
        ]:
            with self.subTest(name=name, version=version):
                result = cms.outdated_core(context(Page(f'<meta name=generator content="{name} {version}">')))
                self.assertEqual(result.status, status)
                self.assertIn(cms.SUPPORT_DATE, result.summary)

    def test_conflicting_generators_never_claim_installation_status(self):
        for pages in [
            [Page('<meta name=generator content="Drupal 9.5"><meta name=generator content="Drupal 11.4">')],
            [Page('<meta name=generator content="Drupal 9.5">'),
             Page('<meta name=generator content="Drupal 11.4">', 'https://example.test/other')],
            [Page('<meta name=generator content="Drupal 9.5"><meta name=generator content="Drupal 11.4-rc1">')],
        ]:
            self.assertEqual(cms.outdated_core(context(*pages)).status, "manual")
            self.assertEqual(cms.version_disclosure(context(*pages)).status, "fail")

    def test_embedded_examples_and_duplicate_attributes_do_not_supply_versions(self):
        generator = '<meta name=generator content="Drupal 9.5">'
        for html in [f'<!-- {generator} -->', f'<script>{generator}</script>',
                     f'<style>{generator}</style>', f'<textarea>{generator}</textarea>',
                     '<meta name=generator name=description content="Drupal 9.5">',
                     '<meta name=generator><meta content="Drupal 9.5">',
                     '<a <meta name=generator content="Drupal 9.5">']:
            with self.subTest(html=html):
                found = cms.detect(context(Page(html)))
                self.assertFalse(any(info["version"] for info in found.values()))
                self.assertNotEqual(cms.outdated_core(context(Page(html))).status, "fail")

    def test_asset_versions_are_hints_and_jquery_is_not_core(self):
        ctx = context(Page('<script src="/wp-includes/js/wp-embed.min.js?ver=6.9.11"></script>'))
        self.assertEqual(cms.detect(ctx)["WordPress"]["version"], "")
        self.assertEqual(cms.version_disclosure(ctx).status, "manual")
        self.assertEqual(cms.outdated_core(ctx).status, "manual")
        ctx = context(Page('<script src="/wp-includes/js/jquery/jquery.min.js?ver=3.7.1"></script>'))
        self.assertEqual(cms.detect(ctx)["WordPress"]["version"], "")

    def test_empty_crawl_and_all_checks_never_request_pages(self):
        for ctx in [context(), context(Page('<meta name=generator content="WordPress 7.1.4">'))]:
            with patch.object(ctx.client, "home", create=True, side_effect=AssertionError("extra request")), \
                 patch.object(ctx.client, "get", create=True, side_effect=AssertionError("extra request")):
                for check in (cms.version_disclosure, cms.outdated_core, cms.wordpress_api, cms.admin_login_linked):
                    check(ctx)

    def test_login_links_are_manual_and_evidence_omits_queries(self):
        ctx = context(Page('<a href="/wp-admin/?token=secret#private">Admin</a>'))
        result = cms.admin_login_linked(ctx)
        self.assertEqual(result.status, "manual")
        self.assertNotIn("secret", str(result))
        self.assertNotIn("private", str(result))
        self.assertIn("does not establish", result.summary)

    def test_external_malformed_and_prefix_login_urls_are_not_local_findings(self):
        ctx = context(Page('<meta name=generator content=WordPress>'
                           '<a href="https://elsewhere.test/wp-admin/">External</a>'
                           '<a href="http://[invalid/wp-admin/">Malformed</a>'
                           '<a href="/wp-admin-tools/">Other</a>'))
        self.assertEqual(cms.admin_login_linked(ctx).status, "pass")

    def test_input_and_tag_limits_prevent_absence_passes(self):
        for html in [
            '<meta name=generator content=WordPress>' + 'x' * cms.MAX_TEXT,
            '<meta name=generator content=WordPress><a x="' + 'x' * cms.MAX_TAG + '">',
            '<meta name=generator content=WordPress>' + '<p>' * cms.MAX_TAGS,
        ]:
            ctx = context(Page(html))
            self.assertEqual(cms.version_disclosure(ctx).status, "manual")
            self.assertEqual(cms.admin_login_linked(ctx).status, "manual")

    def test_hosted_markers_and_absence_do_not_pass_core_support(self):
        for html in ['', 'cdn.shopify.com', 'static.wixstatic.com', 'static1.squarespace.com']:
            self.assertEqual(cms.outdated_core(context(Page(html))).status, "skip")

    def test_malformed_html_has_a_hard_runtime_regression_guard(self):
        # Separate process ensures a catastrophic regex regression cannot hang the suite.
        script = f"""
import sys
sys.path.insert(0, {str(Path(__file__).resolve().parent)!r})
from test_cms import context, Page
from agent_security_audit.checks import cms
for size in (50_000, 400_000):
    for text in ('<meta ' * (size // 6), '<meta ' + 'x ' * (size // 2),
                 '<a href="' + 'x' * size, '<!-- ' + '<meta ' * (size // 6),
                 '<meta ' + 'content="' * (size // 9)):
        ctx = context(Page(text))
        for check in (cms.version_disclosure, cms.outdated_core, cms.wordpress_api, cms.admin_login_linked):
            check(ctx)
"""
        result = subprocess.run([sys.executable, '-c', script], timeout=10, capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
