// Runs against the throwaway database from scripts/with-local-pg.sh (npm test).
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import pg from "pg";
import { runChecks, type Finding } from "../src/checks.ts";

const client = new pg.Client({ connectionString: process.env.DATABASE_URL });
let findings: Finding[] = [];
const find = (check: string, object: string) => findings.find((f) => f.check === check && f.object.startsWith(object));

before(async () => {
  assert.ok(process.env.DATABASE_URL, "run through `npm test` so a local database is started");
  await client.connect();
  ({ findings } = await runChecks(client, ["public"]));
});
after(() => client.end());

test("flags a table with RLS off that anon can write as high", () => {
  const f = find("RLS disabled", "public.notes");
  assert.equal(f?.severity, "high");
  assert.match(f!.detail, /written by anon/);
});

test("flags an allow-all write policy for everyone as high", () => {
  assert.equal(find("Policy allows every row", 'public.orders → policy "allow all"')?.severity, "high");
});

test("flags a read-only USING (true) policy as medium", () => {
  assert.equal(find("Policy allows every row", 'public.products → policy "public read"')?.severity, "medium");
});

test("flags an API-callable SECURITY DEFINER function without search_path as high", () => {
  const f = find("SECURITY DEFINER function exposed", "reset_orders()");
  assert.equal(f?.severity, "high");
  assert.match(f!.detail, /no fixed search_path/);
});

test("flags a view that bypasses RLS", () => {
  assert.equal(find("View bypasses RLS", "public.order_summary")?.severity, "medium");
});

test("reports RLS-on-no-policies as info only", () => {
  assert.equal(find("RLS on, no policies", "public.audit_log")?.severity, "info");
});

test("leaves the correctly secured table alone", () => {
  assert.equal(findings.filter((f) => f.object.startsWith("public.profiles")).length, 0);
});

test("CLI exits 1 on high findings and never writes", async () => {
  const before = await client.query("select count(*)::int as n from pg_class where relnamespace = 'public'::regnamespace");
  await assert.rejects(promisify(execFile)("node", ["src/cli.ts"], { env: process.env }), (err: { code?: number; stdout?: string }) => {
    assert.equal(err.code, 1);
    assert.match(err.stdout ?? "", /# Supabase RLS check/);
    return true;
  });
  const afterRun = await client.query("select count(*)::int as n from pg_class where relnamespace = 'public'::regnamespace");
  assert.equal(afterRun.rows[0].n, before.rows[0].n);
});
