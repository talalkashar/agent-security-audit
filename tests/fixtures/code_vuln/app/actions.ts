"use server";

import { supabaseAdmin } from "../lib/supabase-admin";

export async function deleteNote(id: string) {
  await supabaseAdmin.from("notes").delete().eq("id", id);
}
