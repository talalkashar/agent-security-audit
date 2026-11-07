-- Notes belong to a user; profiles are public. Both are wrong on purpose.
create table public.notes (
  id bigint generated always as identity primary key,
  user_id uuid references auth.users not null,
  body text
);

create table if not exists public.profiles (
  id uuid primary key references auth.users,
  display_name text
);
alter table public.profiles enable row level security;

create policy "anyone signed in" on public.profiles
  for update to authenticated using (auth.role() = 'authenticated');

create table public.posts (id bigint primary key, title text);
alter table public.posts enable row level security;
create policy "public posts" on public.posts for select using (true);

create view public.note_summary as select user_id, count(*) from public.notes group by user_id;

create function public.reset_notes() returns void
language plpgsql security definer as $$
begin
  delete from public.notes; -- a ; inside the body must not split the statement
end;
$$;
