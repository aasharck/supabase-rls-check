-- A small "vibe-coded app" database with the usual mistakes, for the demo and tests.
-- Mimics Supabase's API roles so the checks behave as they would on a real project.

do $$ begin
  if not exists (select 1 from pg_roles where rolname = 'anon') then create role anon nologin; end if;
  if not exists (select 1 from pg_roles where rolname = 'authenticated') then create role authenticated nologin; end if;
end $$;

-- Supabase grants the API roles broad table access by default; RLS is what limits rows.
grant usage on schema public to anon, authenticated;
alter default privileges in schema public grant all on tables to anon, authenticated;

-- ✅ Done right: RLS on, owner-only policy.
create table public.profiles (id serial primary key, owner text not null default current_user, bio text);
alter table public.profiles enable row level security;
create policy "owner reads own profile" on public.profiles for select to authenticated using (owner = current_user);

-- 🔴 RLS never turned on: anyone with the anon key can read and write every note.
create table public.notes (id serial primary key, body text);

-- 🔴 RLS on, but the policy lets everyone do everything.
create table public.orders (id serial primary key, total numeric, customer_email text);
alter table public.orders enable row level security;
create policy "allow all" on public.orders for all to public using (true) with check (true);

-- 🟠 Read-only, but still every row for everyone.
create table public.products (id serial primary key, name text);
alter table public.products enable row level security;
create policy "public read" on public.products for select to anon using (true);

-- ⚪ Server-only table: RLS on, no policies (intended).
create table public.audit_log (id serial primary key, event text);
alter table public.audit_log enable row level security;

-- 🔴 SECURITY DEFINER function anyone can call through /rpc, no fixed search_path.
create function public.reset_orders() returns void language sql security definer as $$ delete from public.orders $$;

-- 🟠 View owned by the table owner: bypasses the RLS on orders.
create view public.order_summary as select customer_email, sum(total) as spent from public.orders group by 1;
grant select on public.order_summary to anon, authenticated;
