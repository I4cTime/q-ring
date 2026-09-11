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
 * Also generates claude-code-plugin/skills/secret-hygiene-rules/SKILL.md from
 * cursor-plugin/rules/*.mdc — the always-on rules. Claude Code plugins cannot
 * ship a loaded CLAUDE.md (`claude plugin validate` warns that a plugin-root
 * CLAUDE.md is ignored), so the rules travel as a skill instead. Cursor and
 * Kiro already carry them as rules/steering, so this skill is Claude-only
 * and check-plugin-parity.mjs excludes it from the cross-plugin skill set.
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

// Always-on rules → one Claude skill. Order is deliberate: hygiene first,
// then workflow, then the .env-specific guidance.
const RULES_SKILL = "secret-hygiene-rules";
const RULE_FILES = ["secret-hygiene", "qring-workflow", "env-file-safety"];
function rulesSkill() {
  const sections = RULE_FILES.map((name) => {
    const md = readFileSync(join(root, "cursor-plugin", "rules", `${name}.mdc`), "utf8");
    const m = md.match(/^---\n[\s\S]*?\n---\n/);
    if (!m) throw new Error(`${name}.mdc missing frontmatter`);
    // Demote the rule's H1 to H2 so the skill has a single top-level heading.
    return md.slice(m[0].length).trim().replace(/^# /, "## ");
  });
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
    ...sections.flatMap((s) => [s, ""]),
  ].join("\n");
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

if (checkMode) {
  if (stale.length > 0) {
    console.error(
      "plugin-generate-skills: OUT OF DATE — regenerate with `pnpm run plugin:gen-skills` and commit:",
    );
    for (const p of stale) console.error(`  ${p}`);
    process.exit(1);
  }
  console.log(`plugin-generate-skills: ${slugs.length * 2 + 1} generated files are up to date`);
} else {
  console.log(
    `plugin-generate-skills: wrote ${slugs.length + 1} Claude skills + ${slugs.length} Kiro steering files from cursor-plugin/skills and rules`,
  );
}
