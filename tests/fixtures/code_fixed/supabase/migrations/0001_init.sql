create table public.notes (
  id bigint generated always as identity primary key,
  user_id uuid references auth.users not null,
  body text
);
alter table public.notes enable row level security;

create policy "owner reads notes" on public.notes
  for select to authenticated using ((select auth.uid()) = user_id);
create policy "owner writes notes" on public.notes
  for insert to authenticated with check ((select auth.uid()) = user_id);

create view public.note_summary with (security_invoker = true) as
  select user_id, count(*) from public.notes group by user_id;

create schema if not exists private;
create function private.reset_notes() returns void
language plpgsql security definer set search_path = '' as $$
begin
  delete from public.notes;
end;
$$;

create function public.note_count() returns bigint
language sql security definer set search_path = '' as $$ select count(*) from public.notes $$;
revoke execute on function public.note_count() from public, anon, authenticated;
