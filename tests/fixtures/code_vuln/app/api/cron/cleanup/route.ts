import { supabaseAdmin } from "../../../../lib/supabase-admin";

export async function GET() {
  await supabaseAdmin.from("notes").delete().lt("created_at", "2020-01-01");
  return Response.json({ ok: true });
}
