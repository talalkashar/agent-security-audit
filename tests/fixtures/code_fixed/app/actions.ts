"use server";

import { createClient } from "../lib/server";

export async function deleteNote(id: string) {
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) throw new Error("Unauthorized");
  await supabase.from("notes").delete().eq("id", id).eq("user_id", user.id);
}
