import { supabaseAdmin } from "../../../../lib/supabase-admin";

export async function GET(req: Request) {
  if (req.headers.get("authorization") !== `Bearer ${process.env.CRON_SECRET}`) {
    return new Response("Unauthorized", { status: 401 });
  }
  await supabaseAdmin.from("notes").delete().lt("created_at", "2020-01-01");
  return Response.json({ ok: true });
}
