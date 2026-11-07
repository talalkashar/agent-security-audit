import { createClient } from "@supabase/supabase-js";
import { pool } from "../../../lib/db";

const supabase = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!);

export async function GET(req: Request) {
  const id = new URL(req.url).searchParams.get("id");
  const { data } = await supabase.from("notes").select("*");
  const rows = await pool.query(`SELECT * FROM notes WHERE id = ${id}`);
  return Response.json({ data, rows });
}
