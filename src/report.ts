import type { Finding } from "./checks.ts";

const LABEL = { high: "🔴 High", medium: "🟠 Medium", info: "⚪ Info" } as const;

export function toMarkdown(findings: Finding[], notes: string[], schemas: string[]): string {
  const count = (s: Finding["severity"]) => findings.filter((f) => f.severity === s).length;
  const lines = [
    "# Supabase RLS check",
    "",
    `Schemas: ${schemas.join(", ")} · High: ${count("high")} · Medium: ${count("medium")} · Info: ${count("info")}`,
    "",
  ];
  for (const n of notes) lines.push(`> Note: ${n}`, "");
  if (findings.length === 0) {
    lines.push("No findings. 🎉");
    return lines.join("\n");
  }
  findings.forEach((f, i) => {
    lines.push(
      `## ${i + 1}. ${LABEL[f.severity]} · ${f.check} · \`${f.object}\``,
      "",
      f.detail,
      "",
      `**Fix:** ${f.fix}`,
      "",
    );
  });
  return lines.join("\n");
}
