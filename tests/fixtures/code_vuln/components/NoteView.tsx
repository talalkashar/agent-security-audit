"use client";

import { supabaseAdmin } from "../lib/supabase-admin";

export function NoteView({ note, formula }: { note: { body: string }; formula: string }) {
  const total = eval(formula);
  console.log(supabaseAdmin, process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY);
  return <div data-total={total} dangerouslySetInnerHTML={{ __html: note.body }} />;
}
