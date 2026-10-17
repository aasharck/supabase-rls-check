import type pg from "pg";

export type Severity = "high" | "medium" | "info";

export interface Finding {
  severity: Severity;
  check: string;
  object: string;
  detail: string;
  fix: string;
}

// Supabase's API roles. "public" in pg_policies means every role.
const API_ROLES = ["anon", "authenticated"] as const;

type Queryable = Pick<pg.ClientBase, "query">;

async function existingApiRoles(db: Queryable): Promise<string[]> {
  const { rows } = await db.query<{ rolname: string }>(
    "select rolname from pg_roles where rolname = any($1)",
    [API_ROLES],
  );
  return rows.map((r) => r.rolname);
}

async function tablesWithoutRls(db: Queryable, schemas: string[], roles: string[]): Promise<Finding[]> {
  const { rows } = await db.query<{ schema: string; table: string; readers: string[]; writers: string[] }>(
    `select n.nspname as schema, c.relname as table,
            array(select r from unnest($2::text[]) r
                  where has_table_privilege(r, c.oid, 'SELECT')) as readers,
            array(select r from unnest($2::text[]) r
                  where has_table_privilege(r, c.oid, 'INSERT')
                     or has_table_privilege(r, c.oid, 'UPDATE')
                     or has_table_privilege(r, c.oid, 'DELETE')) as writers
       from pg_class c
       join pg_namespace n on n.oid = c.relnamespace
      where c.relkind in ('r', 'p')
        and n.nspname = any($1)
        and not c.relrowsecurity
      order by 1, 2`,
    [schemas, roles],
  );
  return rows.map((r) => {
    const exposed = r.readers.length > 0 || r.writers.length > 0;
    const who = [
      r.readers.length ? `read by ${r.readers.join(", ")}` : "",
      r.writers.length ? `written by ${r.writers.join(", ")}` : "",
    ].filter(Boolean).join("; ");
    return {
      severity: exposed ? "high" : "medium",
      check: "RLS disabled",
      object: `${r.schema}.${r.table}`,
      detail: exposed
        ? `Row-level security is off and the table can be ${who} through the API.`
        : "Row-level security is off. No API role has access today, but one GRANT would expose every row.",
      fix: `\`alter table ${r.schema}.${r.table} enable row level security;\` then add policies for the rows each role may see.`,
    } satisfies Finding;
  });
}

async function permissivePolicies(db: Queryable, schemas: string[]): Promise<Finding[]> {
  const { rows } = await db.query<{
    schemaname: string; tablename: string; policyname: string; cmd: string;
    roles: string[]; qual: string | null; with_check: string | null;
  }>(
    `select schemaname, tablename, policyname, cmd, roles::text[] as roles, qual, with_check
       from pg_policies
      where schemaname = any($1)
        and permissive = 'PERMISSIVE'
        and (coalesce(qual, '') = 'true' or coalesce(with_check, '') = 'true')
      order by 1, 2, 3`,
    [schemas],
  );
  return rows
    .filter((p) => p.roles.some((r) => r === "public" || r === "anon" || r === "authenticated"))
    .map((p) => {
      const writes = p.cmd !== "SELECT";
      const everyone = p.roles.includes("public") || p.roles.includes("anon");
      return {
        severity: writes && everyone ? "high" : "medium",
        check: "Policy allows every row",
        object: `${p.schemaname}.${p.tablename} → policy "${p.policyname}" (${p.cmd})`,
        detail: `Policy for ${p.roles.join(", ")} uses ${p.qual === "true" ? "USING (true)" : "WITH CHECK (true)"}, so it doesn't restrict rows at all.`,
        fix: writes
          ? "Replace `true` with a real condition, e.g. `using (auth.uid() = user_id)`."
          : "Fine for truly public data (a product catalog). Otherwise replace `true` with a real condition, e.g. `using (auth.uid() = user_id)`.",
      } satisfies Finding;
    });
}

async function rlsWithoutPolicies(db: Queryable, schemas: string[]): Promise<Finding[]> {
  const { rows } = await db.query<{ schema: string; table: string }>(
    `select n.nspname as schema, c.relname as table
       from pg_class c
       join pg_namespace n on n.oid = c.relnamespace
      where c.relkind in ('r', 'p')
        and n.nspname = any($1)
        and c.relrowsecurity
        and not exists (select 1 from pg_policy p where p.polrelid = c.oid)
      order by 1, 2`,
    [schemas],
  );
  return rows.map((r) => ({
    severity: "info",
    check: "RLS on, no policies",
    object: `${r.schema}.${r.table}`,
    detail: "Row-level security is on with no policies, so API roles see nothing. Fine if intended (server-only table).",
    fix: "If the app should read it, add a SELECT policy; otherwise leave it.",
  }));
}

async function exposedSecurityDefiner(db: Queryable, schemas: string[], roles: string[]): Promise<Finding[]> {
  const { rows } = await db.query<{ schema: string; fn: string; callers: string[]; pinned: boolean }>(
    `select n.nspname as schema, p.oid::regprocedure::text as fn,
            array(select r from unnest($2::text[]) r
                  where has_function_privilege(r, p.oid, 'EXECUTE')) as callers,
            exists (select 1 from unnest(coalesce(p.proconfig, '{}')) c
                    where c like 'search_path=%') as pinned
       from pg_proc p
       join pg_namespace n on n.oid = p.pronamespace
      where p.prosecdef
        and n.nspname = any($1)
      order by 1, 2`,
    [schemas, roles],
  );
  return rows
    .filter((f) => f.callers.length > 0)
    .map((f) => ({
      severity: f.pinned ? "medium" : "high",
      check: "SECURITY DEFINER function exposed",
      object: f.fn,
      detail: `Runs with its owner's rights and can be called by ${f.callers.join(", ")} (Supabase exposes it at /rest/v1/rpc).${f.pinned ? "" : " It also has no fixed search_path."}`,
      fix: `\`revoke execute on function ${f.fn} from public, ${f.callers.join(", ")};\` or make it SECURITY INVOKER${f.pinned ? "" : ", and add \`set search_path = ''\`"}.`,
    } satisfies Finding));
}

async function rlsBypassingViews(db: Queryable, schemas: string[], roles: string[]): Promise<Finding[]> {
  const { rows } = await db.query<{ schema: string; view: string; readers: string[] }>(
    `select n.nspname as schema, c.relname as view,
            array(select r from unnest($2::text[]) r
                  where has_table_privilege(r, c.oid, 'SELECT')) as readers
       from pg_class c
       join pg_namespace n on n.oid = c.relnamespace
      where c.relkind = 'v'
        and n.nspname = any($1)
        and not coalesce('security_invoker=true' = any(c.reloptions)
                      or 'security_invoker=on' = any(c.reloptions), false)
      order by 1, 2`,
    [schemas, roles],
  );
  return rows
    .filter((v) => v.readers.length > 0)
    .map((v) => ({
      severity: "medium",
      check: "View bypasses RLS",
      object: `${v.schema}.${v.view}`,
      detail: `The view runs as its owner, so RLS on the tables underneath doesn't apply. Readable by ${v.readers.join(", ")}.`,
      fix: `\`alter view ${v.schema}.${v.view} set (security_invoker = true);\` (Postgres 15+)`,
    } satisfies Finding));
}

export async function runChecks(db: Queryable, schemas: string[]): Promise<{ findings: Finding[]; notes: string[] }> {
  const notes: string[] = [];
  const roles = await existingApiRoles(db);
  const missing = API_ROLES.filter((r) => !roles.includes(r));
  if (missing.length) notes.push(`Role(s) ${missing.join(", ")} not found, so this may not be a Supabase database. Exposure checks for them were skipped.`);

  const findings = [
    ...(await tablesWithoutRls(db, schemas, roles)),
    ...(await permissivePolicies(db, schemas)),
    ...(await exposedSecurityDefiner(db, schemas, roles)),
    ...(await rlsBypassingViews(db, schemas, roles)),
    ...(await rlsWithoutPolicies(db, schemas)),
  ];
  const order: Record<Severity, number> = { high: 0, medium: 1, info: 2 };
  findings.sort((a, b) => order[a.severity] - order[b.severity] || a.object.localeCompare(b.object));
  return { findings, notes };
}
