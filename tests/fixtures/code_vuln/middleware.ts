import { createServerClient } from "@supabase/ssr";

export async function middleware(req: Request) {
  const supabase = createServerClient("url", "key", { cookies: {} as never });
  const { data } = await supabase.auth.getSession();
  if (!data.session) return Response.redirect(new URL("/login", req.url));
}
