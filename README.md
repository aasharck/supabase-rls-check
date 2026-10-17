# supabase-rls-check

A read-only CLI that finds the Supabase mistakes that leak data: tables any visitor can read or write, policies that allow every row, and functions or views that skip row-level security.

Apps built fast, especially with Lovable, Bolt or Cursor, often ship with at least one of these. With Supabase, the `anon` key is public by design, so **row-level security (RLS) is the only thing between your data and the internet.**

## What it checks
| Severity | Check | Why it matters |
|---|---|---|
| 🔴 High / 🟠 Medium | **RLS disabled** on a table | High if `anon` or `authenticated` can reach it: every row is readable or writable through the API |
| 🔴 High / 🟠 Medium | **Policy allows every row** (`USING (true)` / `WITH CHECK (true)`) | The policy exists but restricts nothing. High when everyone can write. |
| 🔴 High / 🟠 Medium | **`SECURITY DEFINER` function** callable by API roles | Runs with the owner's rights via `/rest/v1/rpc`. High without a fixed `search_path`. |
| 🟠 Medium | **View bypasses RLS** (not `security_invoker`) | Views run as their owner, so the RLS on the tables underneath doesn't apply |
| ⚪ Info | **RLS on, no policies** | API roles see nothing. Usually intended for server-only tables. |

Each finding comes with the exact SQL to fix it.

## Usage
```bash
npm install
DATABASE_URL="postgresql://postgres:[password]@db.[project].supabase.co:5432/postgres" npm run check
```
Options: `--schema public,storage` (default `public`) · `--json`.
Exit code is `1` when there's a high finding, so it can run in CI.

**Read-only by design.** Every query runs inside `BEGIN TRANSACTION READ ONLY` with a 15 s statement timeout, and it only reads Postgres's catalogs (`pg_class`, `pg_policies`, `pg_proc`). It never reads your rows. Use a connection string you're allowed to use, and never commit it.

## Try it without a Supabase project
Needs Postgres 15+ installed locally (`brew install postgresql@16`). Docker isn't required.
```bash
npm install
npm run demo   # starts a throwaway Postgres, loads demo/seed.sql, prints the report
npm test       # 8 tests against the same throwaway database
```
`demo/seed.sql` is a small app with the usual mistakes, plus one table done right that the checker leaves alone.

### Example output (from the demo database)
```
# Supabase RLS check

Schemas: public · High: 3 · Medium: 2 · Info: 1

## 1. 🔴 High · RLS disabled · `public.notes`
Row-level security is off and the table can be read by anon, authenticated; written by anon, authenticated through the API.
**Fix:** `alter table public.notes enable row level security;` then add policies for the rows each role may see.

## 2. 🔴 High · Policy allows every row · `public.orders → policy "allow all" (ALL)`
...
```

## Limits
- It checks configuration, not logic. A policy like `using (user_id = auth.uid())` passes even if your app sets `user_id` wrongly.
- Storage buckets, Edge Functions and API keys in client code are out of scope.
- It's a starting point for a review, not a replacement for one.

## Stack
TypeScript on Node 23.6+ (native type stripping, no build step) · [node-postgres](https://node-postgres.com) · `node:test`.

MIT licence.
