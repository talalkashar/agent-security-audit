"""Checks added to close OWASP gaps: API-25 (version banners, live), API-08 (SSRF, code) and API-33 (mass
assignment, code). Each has pass, fail or warn, and manual fixtures."""

import unittest

from agent_security_audit.checks import exposure
from tests.test_checks import ctx_for, home_with, resp
from tests.test_code_audit import audit_files

ROUTE = "app/api/x/route.ts"


class VersionBannerTest(unittest.TestCase):
    def test_versioned_server_fails(self):
        for value in ("nginx/1.18.0 (Ubuntu)", "Apache/2.4.41", "Microsoft-IIS/10.0", "BaseHTTP/0.6 Python/3.13.1"):
            with self.subTest(server=value):
                r = exposure.version_banners(home_with(("Server", value)))
                self.assertEqual(r.status, "fail")
                self.assertIn(f"server: {value}", r.evidence)

    def test_aspnet_version_fails(self):
        r = exposure.version_banners(home_with(("Server", "cloudflare"), ("X-AspNet-Version", "4.0.30319")))
        self.assertEqual(r.status, "fail")
        self.assertEqual(r.evidence, ["x-aspnet-version: 4.0.30319"])

    def test_bare_names_pass_with_evidence(self):
        for headers in ([("Server", "nginx")], [("Server", "Vercel")], []):
            with self.subTest(headers=headers):
                r = exposure.version_banners(home_with(*headers))
                self.assertEqual(r.status, "pass")
                self.assertTrue(r.evidence and r.evidence[0] == "GET / -> 200")

    def test_error_page_is_manual(self):
        r = exposure.version_banners(ctx_for(lambda m, u, h, b: resp(403, [("Server", "cloudflare")], "blocked")))
        self.assertEqual(r.status, "manual")

    def test_error_page_with_version_still_fails(self):
        r = exposure.version_banners(ctx_for(lambda m, u, h, b: resp(503, [("Server", "nginx/1.2")], "")))
        self.assertEqual(r.status, "fail")


class SsrfCodeTest(unittest.TestCase):
    def status(self, files):
        r = audit_files(files).get("API-08")
        return r.status if r else None

    def test_request_url_warns(self):
        r = audit_files({ROUTE: "export async function GET(req) {\n  const url = req.nextUrl.searchParams.get('u');\n"
                                "  const res = await fetch(url);\n  return res;\n}\n"})["API-08"]
        self.assertEqual(r.status, "warn")
        self.assertIn(f"{ROUTE}:3:", r.evidence[0])

    def test_destructured_body_url_warns(self):
        src = ("export async function POST(request) {\n  const { target } = await request.json();\n"
               "  return axios.get(`${target}/preview`);\n}\n")
        self.assertEqual(self.status({ROUTE: src}), "warn")

    def test_host_check_in_file_is_manual(self):
        src = ("const ALLOWED_HOSTS = ['a.example'];\nexport async function GET(req) {\n"
               "  const u = new URL(req.query.u);\n  if (!ALLOWED_HOSTS.includes(u.hostname)) return;\n"
               "  return fetch(u);\n}\n")
        self.assertEqual(self.status({"pages/api/p.ts": src}), "manual")

    def test_untraced_url_is_manual(self):
        src = "export async function GET(req) {\n  const row = await load();\n  return fetch(row.url);\n}\n"
        self.assertEqual(self.status({ROUTE: src}), "manual")

    def test_fixed_origins_pass(self):
        src = ("const BASE = 'https://api.example.com/v1';\nexport async function GET(req) {\n"
               "  const id = req.nextUrl.searchParams.get('id');\n"
               "  await fetch(`https://api.example.com/items/${id}`);\n  await fetch(BASE);\n"
               "  await fetch(process.env.UPSTREAM_URL);\n  return fetch('/api/health');\n}\n")
        self.assertEqual(self.status({ROUTE: src}), "pass")

    def test_origin_without_slash_is_not_fixed(self):
        # `https://api.example.com${x}` lets x add `@other.host`, so the host is not fixed.
        src = ("export async function GET(req) {\n  const x = req.query.x;\n"
               "  return fetch(`https://api.example.com${x}`);\n}\n")
        self.assertEqual(self.status({"pages/api/p.ts": src}), "warn")

    def test_reassigned_url_is_not_fixed(self):
        # The declaration is a literal, but a later assignment takes the request body.
        src = ("export async function POST(req) {\n  const body = await req.json();\n"
               "  let target = 'https://api.example.com/data';\n  if (body.url) target = body.url;\n"
               "  return fetch(target);\n}\n")
        self.assertEqual(self.status({ROUTE: src}), "warn")

    def test_upper_case_name_from_request_is_not_constant(self):
        src = ("export async function POST(request) {\n  const { url: TARGET_URL } = await request.json();\n"
               "  return fetch(TARGET_URL);\n}\n")
        self.assertEqual(self.status({ROUTE: src}), "warn")
        # An imported UPPER_CASE name is not traced in this file: not proven, so manual rather than pass.
        src = "import { API_URL } from './config';\nexport async function GET(req) {\n  return fetch(API_URL);\n}\n"
        self.assertEqual(self.status({ROUTE: src}), "manual")

    def test_env_or_constant_origin_with_request_path_passes(self):
        src = ("const BASE = 'https://api.example.com';\nconst { SEARCH_URL } = process.env;\n"
               "export async function GET(req) {\n  const q = req.nextUrl.searchParams.get('q');\n"
               "  await fetch(`${process.env.API_URL}/search?q=${q}`);\n  await fetch(`${BASE}/items/${q}`);\n"
               "  return fetch(SEARCH_URL);\n}\n")
        self.assertEqual(self.status({ROUTE: src}), "pass")
        # Request input in the origin slot is still a warning.
        src = ("export async function GET(req) {\n  const host = req.query.host;\n"
               "  return fetch(`${host}/search`);\n}\n")
        self.assertEqual(self.status({"pages/api/p.ts": src}), "warn")

    def test_component_with_client_hooks_is_browser_code(self):
        src = ("import { useEffect } from 'react';\nimport { useSearchParams } from 'next/navigation';\n"
               "export function Preview() {\n  const searchParams = useSearchParams();\n"
               "  useEffect(() => {\n    fetch(searchParams.get('src'));\n  }, []);\n  return null;\n}\n")
        self.assertIsNone(self.status({"components/preview.tsx": src}))
        # A page with getServerSideProps still runs server code even if its component uses hooks.
        src = ("import { useState } from 'react';\nexport async function getServerSideProps({ req, query }) {\n"
               "  const r = await fetch(req.query.src);\n  return { props: {} };\n}\n"
               "export default function P() { useState(0); return null; }\n")
        self.assertEqual(self.status({"pages/p.tsx": src}), "warn")

    def test_client_files_and_no_fetch_say_nothing(self):
        self.assertIsNone(self.status({"app/page.tsx": "'use client'\nfetch(location.search);\n"}))
        self.assertIsNone(self.status({ROUTE: "export function GET(req) { return req.query; }\n"}))


class MassAssignmentCodeTest(unittest.TestCase):
    def status(self, src, path=ROUTE):
        r = audit_files({path: src}).get("API-33")
        return r.status if r else None

    def test_direct_body_warns(self):
        r = audit_files({ROUTE: "export async function POST(req) {\n"
                                "  await supabase.from('profiles').update(await req.json()).eq('id', 1);\n}\n"})
        self.assertEqual(r["API-33"].status, "warn")
        self.assertIn(f"{ROUTE}:2:", r["API-33"].evidence[0])

    def test_body_variable_and_spread_warn(self):
        self.assertEqual(self.status("export async function POST(req) {\n  const body = await req.json();\n"
                                     "  await supabase.from('notes').insert({ ...body, user_id: u.id });\n}\n"), "warn")
        self.assertEqual(self.status("export async function POST(req) {\n  const body = req.body;\n"
                                     "  await prisma.user.update({ where: { id }, data: body });\n}\n",
                                     "pages/api/u.ts"), "warn")
        self.assertEqual(self.status("export async function POST(req) {\n"
                                     "  const { id, ...rest } = await req.json();\n"
                                     "  await db.update(users).set(rest);\n}\n"), "warn")

    def test_named_fields_and_schema_pass(self):
        src = ("export async function POST(req) {\n  const input = Schema.parse(await req.json());\n"
               "  const { title } = await req.json();\n"
               "  await supabase.from('notes').insert({ title, user_id: user.id });\n"
               "  await supabase.from('notes').update(input).eq('id', 1);\n"
               "  await prisma.note.create({ data: { title: input.title } });\n}\n")
        self.assertEqual(self.status(src), "pass")

    def test_json_parse_of_body_is_the_whole_body(self):
        # JSON.parse decodes text; it checks no fields, so it is not a schema.
        src = ("export default async function handler(req, res) {\n  const payload = JSON.parse(req.body);\n"
               "  await supabase.from('profiles').insert(payload);\n}\n")
        self.assertEqual(self.status(src, "pages/api/save.ts"), "warn")
        src = ("export default async function handler(req, res) {\n  const payload = qs.parse(await load(req));\n"
               "  await supabase.from('profiles').insert(payload);\n}\n")
        self.assertEqual(self.status(src, "pages/api/save.ts"), "manual")
        src = ("export default async function handler(req, res) {\n"
               "  const payload = Profile.parse(JSON.parse(req.body));\n"
               "  await supabase.from('profiles').insert(payload);\n}\n")
        self.assertEqual(self.status(src, "pages/api/save.ts"), "pass")

    def test_untraced_payload_is_manual(self):
        self.assertEqual(self.status("export async function POST(req) {\n"
                                     "  await supabase.from('notes').insert(buildRow(req));\n}\n"), "manual")

    def test_no_writes_says_nothing(self):
        self.assertIsNone(self.status("export async function GET(req) { return Response.json(req.query); }\n"))


if __name__ == "__main__":
    unittest.main()
