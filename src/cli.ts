#!/usr/bin/env node
import pg from "pg";
import { runChecks } from "./checks.ts";
import { toMarkdown } from "./report.ts";

const HELP = `Usage: supabase-rls-check [--schema public,storage] [--json]

Connects with DATABASE_URL (read-only transaction) and reports:
  • tables with row-level security off that API roles can reach
  • policies with USING (true) / WITH CHECK (true)
  • SECURITY DEFINER functions callable through the API
  • views that bypass RLS
  • tables with RLS on but no policies (info)

Exit code: 1 if any high-severity finding, else 0.`;

function parseArgs(argv: string[]) {
  const args = { schemas: ["public"], json: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--help" || a === "-h") { console.log(HELP); process.exit(0); }
    else if (a === "--json") args.json = true;
    else if (a === "--schema") args.schemas = (argv[++i] ?? "").split(",").map((s) => s.trim()).filter(Boolean);
    else { console.error(`Unknown option: ${a}\n\n${HELP}`); process.exit(2); }
  }
  return args;
}

async function main() {
  const { schemas, json } = parseArgs(process.argv.slice(2));
  const url = process.env.DATABASE_URL;
  if (!url) { console.error("Set DATABASE_URL (a Postgres connection string)."); process.exit(2); }

  const client = new pg.Client({ connectionString: url, statement_timeout: 15_000 });
  await client.connect();
  try {
    // Never change anything: every query runs inside a read-only transaction.
    await client.query("begin transaction read only");
    const { findings, notes } = await runChecks(client, schemas);
    await client.query("rollback");

    console.log(json ? JSON.stringify({ schemas, notes, findings }, null, 2) : toMarkdown(findings, notes, schemas));
    process.exitCode = findings.some((f) => f.severity === "high") ? 1 : 0;
  } finally {
    await client.end();
  }
}

main().catch((err) => { console.error(err instanceof Error ? err.message : err); process.exit(2); });
