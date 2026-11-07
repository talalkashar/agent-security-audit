import { createClient } from "../../../lib/server";
import { pool } from "../../../lib/db";

export async function GET(req: Request) {
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return new Response("Unauthorized", { status: 401 });
  const id = new URL(req.url).searchParams.get("id");
  const { data } = await supabase.from("notes").select("*").eq("user_id", user.id);
  const rows = await pool.query("SELECT * FROM notes WHERE id = $1 AND user_id = $2", [id, user.id]);
  return Response.json({ data, rows });
}
