import { supabase } from "./client";

export function search(q: string) {
  return supabase.from("notes").select("*").or(`title.ilike.%${q}%,body.ilike.%${q}%`);
}
