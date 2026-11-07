import { supabase } from "./client";

export function search(q: string) {
  return supabase.from("notes").select("*").ilike("title", `%${q}%`);
}
