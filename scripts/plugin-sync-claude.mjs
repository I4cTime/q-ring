#!/usr/bin/env node
/**
 * Copy `claude-code-plugin/` into a Claude Code project (or ~/.claude for the
 * user-level extensions).
 *
 *   # Default — install into $PWD as a project-scoped plugin
 *   node scripts/plugin-sync-claude.mjs
 *
 *   # Install into a specific project
 *   node scripts/plugin-sync-claude.mjs /path/to/your/project
 *
 *   # Install agents/commands/skills/hooks at user scope
 *   #   (CLAUDE.md and .mcp.json are NOT copied to the home dir)
 *   node scripts/plugin-sync-claude.mjs --user
 *
 *   # Force overwrite of existing settings.json, .mcp.json, CLAUDE.md
 *   node scripts/plugin-sync-claude.mjs --force
 *
 * NOTE: this script is the manual, project-scoped install path. If you just
 * want the plugin, install it through Claude Code's plugin system instead:
 *   /plugin marketplace add I4cTime/q-ring
 *   /plugin install qring@q-ring
 *
 * Project-scoped layout (source dirs live at the plugin root, matching the
 * Claude Code plugin format; they are copied under .claude/ for project use):
 *   claude-code-plugin/memory/CLAUDE.md     -> $DEST/CLAUDE.md
 *   claude-code-plugin/.mcp.json            -> $DEST/.mcp.json
 *   claude-code-plugin/agents/*             -> $DEST/.claude/agents/
 *   claude-code-plugin/commands/*           -> $DEST/.claude/commands/
 *   claude-code-plugin/skills/*             -> $DEST/.claude/skills/
 *   claude-code-plugin/hooks/*              -> $DEST/.claude/hooks/  (except hooks.json, plugin-only)
 *   claude-code-plugin/.claude/settings.json -> $DEST/.claude/settings.json
 *
 * Files inside agents/, commands/, skills/, and hooks/ are namespaced (qring-*,
 * secret-ops, etc.) so they do not collide with user files. They are always
 * overwritten.
 *
 * `settings.json`, `.mcp.json`, and `CLAUDE.md` may already be customized by
 * the user. By default, when one of those files already exists at the
 * destination, this script writes `<filename>.qring-template` next to it and
 * leaves the original alone. Pass `--force` to overwrite anyway.
 */
import { cpSync, mkdirSync, existsSync, readdirSync, statSync, copyFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { homedir } from "node:os";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const src = join(root, "claude-code-plugin");

if (!existsSync(src)) {
  console.error(`plugin-sync-claude: missing source directory ${src}`);
  process.exit(1);
}

const args = process.argv.slice(2);
const userScope = args.includes("--user");
const force = args.includes("--force");
const positional = args.filter((a) => !a.startsWith("--"));
const projectDest = positional[0] ?? process.cwd();
const dest = userScope ? homedir() : projectDest;

const claudeSrc = join(src, ".claude");
const claudeDest = join(dest, ".claude");

let copiedFiles = 0;
const skipped = [];

const writeOrTemplate = (from, to) => {
  if (existsSync(to) && !force) {
    const tpl = `${to}.qring-template`;
    copyFileSync(from, tpl);
    skipped.push({ to, tpl });
    copiedFiles += 1;
    return;
  }
  mkdirSync(dirname(to), { recursive: true });
  copyFileSync(from, to);
  copiedFiles += 1;
};

const subdirs = ["agents", "commands", "skills", "hooks"];
for (const sub of subdirs) {
  const srcDir = join(src, sub);
  if (!existsSync(srcDir) || !statSync(srcDir).isDirectory()) continue;
  const destDir = join(claudeDest, sub);
  mkdirSync(destDir, { recursive: true });
  for (const entry of readdirSync(srcDir)) {
    if (entry.startsWith(".")) continue;
    // hooks.json is the plugin-format manifest (uses ${CLAUDE_PLUGIN_ROOT});
    // project installs wire hooks via .claude/settings.json instead.
    if (sub === "hooks" && entry === "hooks.json") continue;
    const from = join(srcDir, entry);
    const to = join(destDir, entry);
    cpSync(from, to, { recursive: true });
    copiedFiles += 1;
  }
}

const settingsSrc = join(claudeSrc, "settings.json");
if (existsSync(settingsSrc)) {
  writeOrTemplate(settingsSrc, join(claudeDest, "settings.json"));
}

if (!userScope) {
  const claudeMd = join(src, "memory", "CLAUDE.md");
  const mcpJson = join(src, ".mcp.json");
  if (existsSync(claudeMd)) writeOrTemplate(claudeMd, join(dest, "CLAUDE.md"));
  if (existsSync(mcpJson)) writeOrTemplate(mcpJson, join(dest, ".mcp.json"));
}

const scope = userScope ? "user (~/.claude)" : `project (${projectDest})`;
console.log(
  `plugin-sync-claude: copied ${copiedFiles} entr${copiedFiles === 1 ? "y" : "ies"} into ${scope}`,
);

if (skipped.length > 0) {
  console.log("");
  console.log(
    "The following files already existed and were NOT overwritten. Saved a side-by-side template instead — review and merge by hand, or rerun with --force to overwrite:",
  );
  for (const { to, tpl } of skipped) {
    console.log(`  ${to}`);
    console.log(`    -> template: ${tpl}`);
  }
}

if (!userScope) {
  console.log("");
  console.log(
    "First time you run `claude` in this project, approve the project-scoped MCP server defined in `.mcp.json`.",
  );
}
