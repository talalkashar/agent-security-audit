import { NextResponse } from "next/server";
import { createServerClient } from "@supabase/ssr";

export async function middleware() {
  const nonce = crypto.randomUUID();
  const res = NextResponse.next();
  res.headers.set("Content-Security-Policy", `default-src 'self'; script-src 'self' 'nonce-${nonce}' 'strict-dynamic'`);
  const supabase = createServerClient("url", "key", { cookies: {} as never });
  await supabase.auth.getClaims();
  return res;
}
