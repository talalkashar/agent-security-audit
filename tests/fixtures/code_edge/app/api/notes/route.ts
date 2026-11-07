import { createClient } from "@/lib/server";

// POST checks the user; GET does not. The auth call in POST must not cover GET.
export async function GET() {
  const supabase = await createClient();
  const { data } = await supabase.from("notes").select("*");
  return Response.json(data);
}

export async function POST(req: Request) {
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return new Response("Unauthorized", { status: 401 });
  const { data } = await supabase.from("notes").insert({ user_id: user.id, body: await req.text() });
  return Response.json(data);
}
