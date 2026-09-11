#!/usr/bin/env node
/**
 * CI guard: the three editor plugins (Cursor, Claude Code, Kiro) must expose
 * the same commands/agents/skills, doc'd MCP tool counts must match the code,
 * and plugin manifest versions must match package.json.
 *
 *   node scripts/check-plugin-parity.mjs
 *
 * Exits 1 with a list of mismatches. Run `pnpm run plugin:gen-skills` and
 * `pnpm run sync-versions` to fix generated-content failures.
 */
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const errors = [];

const stems = (dir, { strip = "", ext = ".md" } = {}) =>
  readdirSync(join(root, dir))
    .filter((f) => f.endsWith(ext) && f.startsWith(strip))
    .map((f) => f.slice(strip.length, -ext.length))
    .sort();

const dirs = (dir) =>
  readdirSync(join(root, dir), { withFileTypes: true })
    .filter((d) => d.isDirectory())
    .map((d) => d.name)
    .sort();

function expectEqual(label, a, b) {
  if (JSON.stringify(a) !== JSON.stringify(b)) {
    errors.push(`${label}: mismatch\n    left:  ${a.join(", ")}\n    right: ${b.join(", ")}`);
  }
}

// ── Commands ──────────────────────────────────────────────────────────────
const cursorCmds = stems("cursor-plugin/commands");
const claudeCmds = stems("claude-code-plugin/commands", { strip: "qring-" });
const kiroCmds = stems("kiro-plugin/steering", { strip: "qring-cmd-" });
expectEqual("commands (cursor vs claude)", cursorCmds, claudeCmds);
expectEqual("commands (cursor vs kiro)", cursorCmds, kiroCmds);

// ── Agents ────────────────────────────────────────────────────────────────
expectEqual(
  "agents (cursor vs claude)",
  stems("cursor-plugin/agents"),
  stems("claude-code-plugin/agents"),
);

// ── Skills ────────────────────────────────────────────────────────────────
const cursorSkills = dirs("cursor-plugin/skills");
// `secret-hygiene-rules` is generated from cursor-plugin/rules/*.mdc and exists
// only for Claude Code (Cursor/Kiro ship the same content as rules/steering).
expectEqual(
  "skills (cursor vs claude)",
  cursorSkills,
  dirs("claude-code-plugin/skills").filter((s) => s !== "secret-hygiene-rules"),
);
const kiroSkillFiles = stems("kiro-plugin/steering", { strip: "qring-" }).filter((s) =>
  cursorSkills.includes(s),
);
expectEqual("skills (cursor vs kiro steering)", cursorSkills, kiroSkillFiles);

// ── MCP tool count: code vs docs ──────────────────────────────────────────
let actualTools = 0;
for (const f of readdirSync(join(root, "src", "mcp", "tools"))) {
  if (!f.endsWith(".ts")) continue;
  actualTools += (
    readFileSync(join(root, "src", "mcp", "tools", f), "utf8").match(/server\.tool\(/g) ?? []
  ).length;
}

const TOOL_COUNT_PATTERNS = [
  /MCP_tools-(\d+)-/g, // README badge
  /(\d+)\s+(?:q-ring\s+)?(?:built-in\s+)?MCP tools/g,
  /MCP server with (\d+) tools/g,
  /all (\d+) tools\b/g,
];
const DOC_FILES = [
  "README.md",
  "cursor-plugin/README.md",
  "kiro-plugin/README.md",
  "kiro-plugin/POWER.md",
  "claude-code-plugin/README.md",
  "docs/quickstart-claude-code.md",
  "docs/quickstart-cursor.md",
  "docs/quickstart-kiro.md",
];
for (const file of DOC_FILES) {
  const text = readFileSync(join(root, file), "utf8");
  for (const pattern of TOOL_COUNT_PATTERNS) {
    for (const m of text.matchAll(pattern)) {
      const claimed = Number(m[1]);
      if (claimed !== actualTools) {
        errors.push(
          `${file}: claims ${claimed} MCP tools but src/mcp/tools registers ${actualTools} ("${m[0]}")`,
        );
      }
    }
  }
}

// ── Versions: manifests vs package.json ───────────────────────────────────
const pkgVersion = JSON.parse(readFileSync(join(root, "package.json"), "utf8")).version;
const VERSIONED = [
  ["cursor-plugin/.cursor-plugin/plugin.json", (j) => j.version],
  [".cursor-plugin/marketplace.json", (j) => j.plugins?.[0]?.version],
  ["claude-code-plugin/.claude-plugin/plugin.json", (j) => j.version],
  [".claude-plugin/marketplace.json", (j) => j.plugins?.[0]?.version],
  ["server.json", (j) => j.version],
];
for (const [file, pick] of VERSIONED) {
  const v = pick(JSON.parse(readFileSync(join(root, file), "utf8")));
  if (v !== pkgVersion) {
    errors.push(
      `${file}: version ${v} != package.json ${pkgVersion} (run: pnpm run sync-versions)`,
    );
  }
}

if (errors.length > 0) {
  console.error(`check-plugin-parity: ${errors.length} problem(s):\n`);
  for (const e of errors) console.error(`  ✗ ${e}\n`);
  process.exit(1);
}
console.log(
  `check-plugin-parity: OK — ${cursorCmds.length} commands, ${stems("cursor-plugin/agents").length} agents, ${cursorSkills.length} skills in sync across plugins; ${actualTools} MCP tools match docs; versions ${pkgVersion} in lockstep`,
);
