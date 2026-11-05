#!/usr/bin/env node
/**
 * Generate the Claude Code and Kiro skill files from the Cursor plugin's
 * skills — `cursor-plugin/skills/<slug>/SKILL.md` is the single source of
 * truth. Skills are platform-agnostic content; hand-copying them caused
 * silent drift (heading case, arrows) across the three plugins.
 *
 *   node scripts/plugin-generate-skills.mjs           # regenerate
 *   node scripts/plugin-generate-skills.mjs --check   # exit 1 if out of date (CI)
 *
 * Outputs:
 *   claude-code-plugin/skills/<slug>/SKILL.md   — verbatim copy
 *   kiro-plugin/steering/qring-<slug>.md        — Kiro steering transform
 *                                                 (manual inclusion, #qring-<slug> chat tag)
 *
 * Also generates, from cursor-plugin/rules/*.mdc (the Cursor rules):
 *   claude-code-plugin/skills/secret-hygiene-rules/SKILL.md — all rules as one
 *       on-demand skill. Claude Code plugins cannot ship a loaded CLAUDE.md
 *       (`claude plugin validate` warns that a plugin-root CLAUDE.md is
 *       ignored). Cursor and Kiro already carry the rules as rules/steering,
 *       so this skill is Claude-only and check-plugin-parity.mjs excludes it
 *       from the cross-plugin skill set.
 *   claude-code-plugin/hooks/qring-session-rules.md — the `alwaysApply` rules
 *       only, injected into every session by hooks/scripts/qring-session-start.sh
 *       (SessionStart is the one always-on channel a plugin has). Path-scoped
 *       rules (Cursor `globs`) are left out: a session hook cannot scope by path.
 *   claude-code-plugin/rules/<name>.md — ready-made Claude Code rule files
 *       (`paths:` frontmatter where the Cursor rule had `globs`) for users who
 *       copy them into ~/.claude/rules/. Claude Code does not load rules from a
 *       plugin, so these are not active until copied.
 */
import { readFileSync, writeFileSync, readdirSync, mkdirSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const srcDir = join(root, "cursor-plugin", "skills");
const checkMode = process.argv.includes("--check");

// Kiro steering titles are curated per skill (not derivable from the slug).
const KIRO_TITLES = {
  "secret-management": "Secret Management",
  "secret-scanning": "Secret Scanning",
  "secret-rotation": "Secret Rotation & Validation",
  "project-onboarding": "Project Onboarding",
  "exec-with-secrets": "Exec with Secrets",
};

function parseFrontmatter(md) {
  const m = md.match(/^---\n([\s\S]*?)\n---\n/);
  if (!m) throw new Error("SKILL.md missing frontmatter");
  const desc = m[1].match(/^description:\s*(.*)$/m)?.[1] ?? "";
  return { description: desc, body: md.slice(m[0].length) };
}

function kiroSteering(slug, skillMd) {
  const { description, body } = parseFrontmatter(skillMd);
  const title = KIRO_TITLES[slug] ?? slug;
  // Short description: everything before the "Use when …" trigger sentence.
  const shortDesc = description.split(/\s+Use when/)[0].trim();
  // Body: everything after the top-level `# Title` heading line.
  const afterTitle = body.replace(/^\s*# .*\n/, "");
  return [
    "---",
    "inclusion: manual",
    "---",
    "",
    `# q-ring · ${title} (skill)`,
    "",
    `> Activate by typing \`#qring-${slug}\` in chat.`,
    "",
    shortDesc,
    "",
    afterTitle.replace(/^\n+/, ""),
  ].join("\n");
}

// Cursor rules. Order is deliberate: hygiene first, then workflow, then the
// .env-specific guidance. Every .mdc must be listed so a new rule cannot be
// silently left out of the Claude Code outputs.
const rulesDir = join(root, "cursor-plugin", "rules");
const RULE_FILES = ["secret-hygiene", "qring-workflow", "env-file-safety"];
{
  const onDisk = readdirSync(rulesDir)
    .filter((f) => f.endsWith(".mdc"))
    .map((f) => f.slice(0, -4))
    .sort();
  const listed = [...RULE_FILES].sort();
  if (JSON.stringify(onDisk) !== JSON.stringify(listed)) {
    throw new Error(
      `cursor-plugin/rules has [${onDisk.join(", ")}] but RULE_FILES lists [${listed.join(", ")}] — update RULE_FILES`,
    );
  }
}

function readRule(name) {
  const md = readFileSync(join(rulesDir, `${name}.mdc`), "utf8");
  const m = md.match(/^---\n([\s\S]*?)\n---\n/);
  if (!m) throw new Error(`${name}.mdc missing frontmatter`);
  const fm = m[1];
  const alwaysApply = /^alwaysApply:\s*true\s*$/m.test(fm);
  const globsRaw = fm.match(/^globs:\s*(.*)$/m)?.[1]?.trim() ?? "";
  const globs = globsRaw
    .replace(/^["']|["']$/g, "")
    .split(",")
    .map((g) => g.trim().replace(/^["']|["']$/g, ""))
    .filter(Boolean);
  return { name, alwaysApply, globs, body: md.slice(m[0].length).trim() };
}
const RULES = RULE_FILES.map(readRule);

// Demote a rule's H1 to H2 so the containing document has one top-level heading.
const demote = (body) => body.replace(/^# /, "## ");

// All rules → one Claude skill.
const RULES_SKILL = "secret-hygiene-rules";
function rulesSkill() {
  return [
    "---",
    `name: ${RULES_SKILL}`,
    "description: Always-on q-ring rules — never hardcode credentials, route every secret operation through the q-ring MCP tools, and handle .env files safely. Use when writing or reviewing code that touches API keys, tokens, passwords, connection strings, or .env files, and before any shell command that would carry a secret.",
    "---",
    "",
    "# q-ring secret hygiene rules",
    "",
    "These rules apply to every task in a project that uses q-ring. They are generated from the Cursor plugin's always-on rules so all three editor plugins enforce the same policy.",
    "",
    ...RULES.flatMap((r) => [demote(r.body), ""]),
  ].join("\n");
}

// `alwaysApply` rules → the text the SessionStart hook injects. Injected into
// every session, so it must stay compact: the rules are short bullet lists
// today; if they grow past the budget, condense the Cursor rules (the source)
// rather than letting the session preamble bloat.
const SESSION_RULES_WORD_BUDGET = 450;
function sessionRules() {
  const always = RULES.filter((r) => r.alwaysApply);
  if (always.length === 0) throw new Error("no alwaysApply rules in cursor-plugin/rules");
  const text = [
    "# q-ring always-on rules",
    "",
    "These rules apply to every task in this session.",
    "",
    ...always.flatMap((r) => [demote(r.body), ""]),
  ].join("\n");
  const words = text.split(/\s+/).filter(Boolean).length;
  if (words > SESSION_RULES_WORD_BUDGET) {
    throw new Error(
      `session rules are ${words} words (budget ${SESSION_RULES_WORD_BUDGET}) — condense the alwaysApply rules in cursor-plugin/rules`,
    );
  }
  return text;
}

// Each rule → a Claude Code rule file for ~/.claude/rules/. Claude Code rules
// take only a `paths:` frontmatter; without it a rule loads in every session.
function claudeRuleFile(rule) {
  const head =
    rule.globs.length > 0
      ? ["---", "paths:", ...rule.globs.map((g) => `  - "${g}"`), "---", ""]
      : [];
  return [...head, rule.body, ""].join("\n");
}

const slugs = readdirSync(srcDir).filter((d) => existsSync(join(srcDir, d, "SKILL.md")));
if (slugs.length === 0) throw new Error(`No skills found in ${srcDir}`);

let stale = [];

function emit(path, content) {
  if (checkMode) {
    const current = existsSync(path) ? readFileSync(path, "utf8") : null;
    if (current !== content) stale.push(path);
    return;
  }
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, content, "utf8");
}

for (const slug of slugs) {
  const skillMd = readFileSync(join(srcDir, slug, "SKILL.md"), "utf8");
  emit(join(root, "claude-code-plugin", "skills", slug, "SKILL.md"), skillMd);
  emit(join(root, "kiro-plugin", "steering", `qring-${slug}.md`), kiroSteering(slug, skillMd));
}
emit(join(root, "claude-code-plugin", "skills", RULES_SKILL, "SKILL.md"), rulesSkill());
emit(join(root, "claude-code-plugin", "hooks", "qring-session-rules.md"), sessionRules());
for (const rule of RULES) {
  emit(join(root, "claude-code-plugin", "rules", `${rule.name}.md`), claudeRuleFile(rule));
}
const generatedCount = slugs.length * 2 + 2 + RULES.length;

if (checkMode) {
  if (stale.length > 0) {
    console.error(
      "plugin-generate-skills: OUT OF DATE — regenerate with `pnpm run plugin:gen-skills` and commit:",
    );
    for (const p of stale) console.error(`  ${p}`);
    process.exit(1);
  }
  console.log(`plugin-generate-skills: ${generatedCount} generated files are up to date`);
} else {
  console.log(
    `plugin-generate-skills: wrote ${slugs.length + 1} Claude skills, ${slugs.length} Kiro steering files, the Claude session rules and ${RULES.length} Claude rule files from cursor-plugin/skills and rules`,
  );
}
