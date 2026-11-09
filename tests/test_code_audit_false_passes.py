"""False-pass regressions for the code audit: a guard or an RLS statement found by a static read is evidence, not
proof, so these checks must never come out `pass`, and a code pass must never replace a live manual or error.
Each case here used to pass."""

import contextlib
import io
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from agent_security_audit import cli, code_audit, lab
from agent_security_audit.code_audit import nextjs, sql
from agent_security_audit.code_audit.base import make
from agent_security_audit.model import Result

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def audit(files):
    with tempfile.TemporaryDirectory() as tmp:
        for rel, text in files.items():
            (Path(tmp) / rel).parent.mkdir(parents=True, exist_ok=True)
            (Path(tmp) / rel).write_text(text)
        return {r.check_id: r for r in code_audit.run(tmp, osv=False)[1]}


def route(body):
    return audit({"app/api/notes/route.ts": "import { db, prisma } from '@/db';\n"
                  f"export async function GET(req, {{ params }}) {{\n{body}\n}}\n"})["NEXT-05"]


def action(body):
    return audit({"app/actions.ts": f"'use server';\nexport async function save(id) {{\n{body}\n}}\n"})


def migration(sql_text):
    return audit({"supabase/migrations/0001.sql": sql_text})


NOTES = ("create table public.notes (id bigint primary key, user_id uuid references auth.users);\n"
         "alter table public.notes enable row level security;\n")


class AuthPatternTest(unittest.TestCase):
    def test_user_lookup_is_not_authentication(self):
        r = route("  const user = await getUserById(params.id);\n  if (!user) return deny();\n"
                  "  return Response.json(await db.select().from(notes));")
        self.assertEqual(r.status, "warn", r.summary)

    def test_lookup_helpers_named_like_auth_do_not_count(self):
        for call in ("getUsers()", "getTokenPrice()", "getSessionCount(id)"):
            with self.subTest(call=call):
                r = route(f"  const x = await {call};\n  if (!x) return deny();\n"
                          "  return Response.json(await db.select().from(notes));")
                self.assertEqual(r.status, "warn", r.summary)

    def test_unchecked_auth_result_is_not_a_guard(self):
        r = route("  const session = await auth();\n  await prisma.post.deleteMany({});\n"
                  "  return Response.json({ ok: true });")
        self.assertEqual(r.status, "warn", r.summary)
        r = route("  await supabase.auth.getUser();\n  return Response.json(await db.select().from(notes));")
        self.assertEqual(r.status, "warn", r.summary)
        r = route("  const user = await getUser();\n  return Response.json(await db.select().from(notes));")
        self.assertEqual(r.status, "warn", r.summary)

    def test_checked_auth_counts_but_never_passes(self):
        for guard in ("  const session = await auth();\n  if (!session?.user) return deny();",
                      "  const { data: { user } } = await supabase.auth.getUser();\n  if (!user) return deny();",
                      "  if (!(await getServerSession(options))) return deny();",
                      "  const user = (await currentUser()) ?? redirect('/login');",
                      "  await requireUser();"):
            with self.subTest(guard=guard):
                r = route(guard + "\n  return Response.json(await db.select().from(notes));")
                self.assertEqual(r.status, "manual", r.summary)
                self.assertTrue(r.summary.startswith("Not proven:"))
                self.assertTrue(any(e.startswith("app/api/notes/route.ts:3:") for e in r.evidence), r.evidence)

    def test_declaring_a_gate_is_not_calling_it(self):
        # A pages/api handler is judged as one file, so the declaration used to count as the guard.
        code = ("import { db } from '@/db';\nasync function requireUser() { return 1; }\n"
                "export default async function handler(req, res) {\n  res.json(await db.select().from(notes));\n}\n")
        self.assertEqual(audit({"pages/api/notes.ts": code})["NEXT-05"].status, "warn")


class ServerActionTest(unittest.TestCase):
    def test_unchecked_auth_in_action_is_not_a_guard(self):
        r = action("  const session = await auth();\n  await prisma.note.delete({ where: { id } });")
        for cid in ("NEXT-06", "ACCESS-11"):
            self.assertEqual(r[cid].status, "warn", r[cid].summary)

    def test_guarded_action_is_manual_not_pass(self):
        r = action("  const session = await auth();\n  if (!session) throw new Error('no');\n"
                   "  await prisma.note.delete({ where: { id, ownerId: session.user.id } });")
        for cid in ("NEXT-06", "ACCESS-11"):
            self.assertEqual(r[cid].status, "manual", r[cid].summary)
            self.assertIn("app/actions.ts:3:", r[cid].evidence[0])


class SessionTrustTest(unittest.TestCase):
    def test_verified_user_call_is_manual_not_pass(self):
        r = audit({"middleware.ts": "export async function middleware() {\n"
                   "  const { data } = await supabase.auth.getClaims();\n}\n"})["AUTH-01"]
        self.assertEqual(r.status, "manual", r.summary)
        self.assertIn("middleware.ts:2:", r.evidence[0])


class SqlTest(unittest.TestCase):
    def test_rls_on_every_migration_table_is_manual(self):
        r = migration(NOTES)["ACCESS-01"]
        self.assertEqual(r.status, "manual", r.summary)
        self.assertIn("dashboard", r.summary)

    def test_tautologies_fail(self):
        for expr in ("1 = 1", "user_id = user_id", "auth.uid() = auth.uid()", "(select auth.uid()) = user_id or true"):
            with self.subTest(expr=expr):
                r = migration(NOTES + f"create policy p on public.notes for select using ({expr});\n")["ACCESS-02"]
                self.assertEqual(r.status, "fail", r.summary)

    def test_unknown_expression_is_manual(self):
        for expr in ("is_member(team_id)", "auth.uid() = user_id or is_public",
                     "auth.uid() in (select member_id from members)"):
            with self.subTest(expr=expr):
                r = migration(NOTES + f"create policy p on public.notes for select using ({expr});\n")["ACCESS-02"]
                self.assertEqual(r.status, "manual", r.summary)
                self.assertTrue(r.locations)

    def test_owner_checks_only_are_manual_not_pass(self):
        r = migration(NOTES + "create policy p on public.notes for select using ((select auth.uid()) = user_id);\n"
                      "create policy q on public.notes for insert with check (auth.uid() = user_id);\n")["ACCESS-02"]
        self.assertEqual(r.status, "manual", r.summary)
        self.assertTrue(r.summary.startswith("Not proven:"))

    def test_classify(self):
        cases = {
            "auth.uid() = user_id": "owner", "user_id = ( select auth.uid() )": "owner",
            "auth.uid()::text = owner_id::text": "owner", "(auth.jwt()->>'sub')::uuid = user_id": "owner",
            "auth.uid() = notes.user_id and not archived": "owner",
            "(auth.uid() = user_id) and (deleted_at is null)": "owner",
            "auth.uid() = user_id or auth.uid() = owner_id": "owner",
            "true": "open", "1=1": "open", "user_id = user_id": "open", "auth.role() = 'authenticated'": "open",
            "auth.uid() is not null": "open", "auth.uid() = user_id or true": "open",
            "published = true": "unknown", "auth.uid() = user_id or is_public": "unknown",
            "user_id = owner_id": "unknown", "exists (select 1 from members m where m.user_id = auth.uid())": "unknown",
        }
        for expr, kind in cases.items():
            with self.subTest(expr=expr):
                self.assertEqual(sql.classify(expr), kind)

    def test_invoker_view_is_manual_not_pass(self):
        r = migration(NOTES + "create view public.v with (security_invoker = true) as select 1;\n")["ACCESS-06"]
        self.assertEqual(r.status, "manual", r.summary)


def cron(body):
    return audit({"vercel.json": json.dumps({"crons": [{"path": "/api/cron/job"}]}),
                  "app/api/cron/job/route.ts": f"export async function GET(req) {{\n{body}\n"
                                               "  return Response.json({ ok: true });\n}\n"})["NEXT-15"]


class CronSecretTest(unittest.TestCase):
    def test_mere_mention_of_cron_secret_is_not_a_check(self):
        for body in ("  console.log(Boolean(process.env.CRON_SECRET));",
                     "  const secret = process.env.CRON_SECRET;\n  await run(secret);",
                     "  // TODO: check CRON_SECRET\n  const s = 'CRON_SECRET';",
                     # compared, but the mismatch is not rejected
                     ("  if (req.headers.get('authorization') !== `Bearer ${process.env.CRON_SECRET}`) {\n"
                     "    console.warn('bad secret');\n  }"),
                     # compared with a constant, not the request
                     "  if (process.env.CRON_SECRET !== 'x') return new Response(null, { status: 401 });"):
            with self.subTest(body=body):
                r = cron(body)
                self.assertNotEqual(r.status, "pass", r.summary)
                self.assertIn(r.status, ("manual", "fail"), r.summary)

    def test_comment_only_mention_fails(self):
        r = cron("  // TODO: check CRON_SECRET")
        self.assertEqual(r.status, "fail", r.summary)

    def test_real_check_is_manual_with_location(self):
        for body in (("  if (req.headers.get('authorization') !== `Bearer ${process.env.CRON_SECRET}`) {\n"
                     "    return new Response('Unauthorized', { status: 401 });\n  }"),
                     ("  const auth = req.headers.get('authorization');\n  const secret = process.env.CRON_SECRET;\n"
                     "  if (!secret || auth !== `Bearer ${secret}`) return new Response(null, { status: 401 });"),
                     ("  const token = req.headers.get('authorization') ?? '';\n"
                     "  if (!timingSafeEqual(Buffer.from(token), Buffer.from(`Bearer ${process.env.CRON_SECRET}`)))"
                     " throw new Error('unauthorized');")):
            with self.subTest(body=body):
                r = cron(body)
                self.assertEqual(r.status, "manual", r.summary)
                self.assertTrue(r.summary.startswith("Not proven:"))
                self.assertTrue(r.evidence[0].startswith("app/api/cron/job/route.ts:"), r.evidence)
                self.assertIn("rejects a mismatch here", r.evidence[0])


class StructuralTest(unittest.TestCase):
    def test_run_downgrades_a_static_pass_on_heuristic_checks(self):
        def guess(project):
            return [make("NEXT-05", "pass", "guessed"), make("NEXT-03", "pass", "poweredByHeader: false")]
        with mock.patch.object(nextjs, "ANALYZERS", (guess,)):
            r = audit({"package.json": "{}"})
        self.assertEqual(r["NEXT-05"].status, "manual")
        self.assertEqual(r["NEXT-03"].status, "pass")

    def test_pattern_searches_never_pass(self):
        # A clean read for raw HTML sinks or eval used to pass: a missed sink or an obfuscated eval also reads clean.
        self.assertTrue({"BROWSER-09", "API-30"} <= code_audit.NO_STATIC_PASS)
        r = audit({"app/page.tsx": "export default function P() { return <p>{'hi'}</p>; }\n"})
        for cid in ("BROWSER-09", "API-30"):
            self.assertEqual(r[cid].status, "manual", r[cid].summary)
            self.assertTrue(r[cid].summary.startswith("Not proven:"), r[cid].summary)
        self.assertEqual(code_audit.merge([], [make("API-30", "pass", "no eval")])[0].status, "manual")
        # Findings are unchanged: a dynamic sink still warns and eval on a dynamic string still fails.
        r = audit({"app/page.tsx": "export const P = (p) => <div dangerouslySetInnerHTML={{ __html: p.x }} />;\n",
                   "lib/run.js": "export const run = (s) => eval(s);\n"})
        self.assertEqual(r["BROWSER-09"].status, "warn")
        self.assertEqual(r["API-30"].status, "fail")

    def test_readme_lists_the_checks_that_can_pass(self):
        readme = (Path(__file__).resolve().parent.parent / "README.md").read_text()
        ids = sorted(code_audit.STATIC_PROOF)
        self.assertIn(f"Only {', '.join(ids[:-1])} and {ids[-1]} can pass from code", readme)

    def test_no_static_pass_covers_the_heuristic_checks(self):
        self.assertTrue({"NEXT-05", "NEXT-06", "ACCESS-11", "AUTH-01", "ACCESS-01", "ACCESS-02", "ACCESS-06",
                         "NEXT-15"} <= code_audit.NO_STATIC_PASS)

    def test_merge_keeps_live_manual_and_error_over_code_pass(self):
        for live in ("manual", "error"):
            with self.subTest(live=live):
                merged = code_audit.merge([Result("NEXT-05", live, "live")], [Result("NEXT-05", "pass", "code")])
                self.assertEqual(merged[0].status, live)

    def test_scan_with_code_never_passes_auth_from_source(self):
        # The confirmed bug: `asa scan --code` printed pass for AUTH-01 and NEXT-05 on the fixed project.
        tmp = tempfile.mkdtemp()
        try:
            proj = Path(tmp) / "code_fixed"
            shutil.copytree(FIXTURES / "code_fixed", proj)
            for p in list(proj.rglob("*.fixture")):
                p.rename(p.with_suffix(""))
            server, url = lab.serve("fixed", 0)
            out = io.StringIO()
            try:
                with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                    cli.main(["scan", url, "--code", str(proj), "--no-osv", "--no-dns", "--format", "json",
                              "--check", "AUTH-01,NEXT-05,NEXT-06,ACCESS-01,ACCESS-02", "--fail-on", "none"])
            finally:
                server.shutdown()
                server.server_close()
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        results = {r["check_id"]: r["status"] for r in json.loads(out.getvalue())["results"]}
        self.assertEqual(set(results), {"AUTH-01", "NEXT-05", "NEXT-06", "ACCESS-01", "ACCESS-02"})
        self.assertNotIn("pass", results.values(), results)


if __name__ == "__main__":
    unittest.main()
