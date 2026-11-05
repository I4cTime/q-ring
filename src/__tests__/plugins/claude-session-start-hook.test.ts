/**
 * The Claude Code plugin's SessionStart hook is the plugin's one always-on
 * channel: it injects the generated always-on rules
 * (claude-code-plugin/hooks/qring-session-rules.md) through
 * hookSpecificOutput.additionalContext. Run it the way Claude Code does
 * (SessionStart JSON on stdin) and check the output is valid JSON carrying
 * the rules, that path-scoped rules stay out, and that the rules are skipped
 * when they already load from a copied rules file or the project CLAUDE.md.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { spawnSync } from "node:child_process";
import { cpSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const pluginHooks = join(repoRoot, "claude-code-plugin", "hooks");
const hookScript = join(pluginHooks, "scripts", "qring-session-start.sh");
const sessionRules = readFileSync(join(pluginHooks, "qring-session-rules.md"), "utf8").trim();

const hasJq = process.platform !== "win32" && spawnSync("jq", ["--version"]).status === 0;

let home: string;
let project: string;

function runHook(script = hookScript) {
  const input = JSON.stringify({
    session_id: "test",
    transcript_path: join(project, "transcript.jsonl"),
    cwd: project,
    hook_event_name: "SessionStart",
    source: "startup",
  });
  const res = spawnSync("bash", [script], {
    input,
    encoding: "utf8",
    env: { PATH: process.env.PATH ?? "", HOME: home, CLAUDE_PROJECT_DIR: project },
  });
  expect(res.status).toBe(0);
  const out = JSON.parse(res.stdout) as {
    hookSpecificOutput: { hookEventName: string; additionalContext: string };
  };
  expect(out.hookSpecificOutput.hookEventName).toBe("SessionStart");
  return out.hookSpecificOutput.additionalContext;
}

describe.skipIf(!hasJq)("claude-code-plugin SessionStart hook", () => {
  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), "qring-hook-home-"));
    project = mkdtempSync(join(tmpdir(), "qring-hook-project-"));
  });
  afterEach(() => {
    rmSync(home, { recursive: true, force: true });
    rmSync(project, { recursive: true, force: true });
  });

  it("injects the get_project_context note and the always-on rules", () => {
    const ctx = runHook();
    expect(ctx).toContain("get_project_context");
    expect(ctx).toContain("/qring-scan-secrets");
    expect(ctx).toContain(sessionRules);
    expect(ctx).toContain("## Secret Hygiene");
    expect(ctx).toContain("## q-ring Workflow");
    // Path-scoped in Cursor (globs), so it is not injected session-wide.
    expect(ctx).not.toContain(".env File Safety");
    expect(ctx).not.toContain("check_project");
  });

  it("adds the check_project nudge when .q-ring.json exists", () => {
    writeFileSync(join(project, ".q-ring.json"), "{}");
    const ctx = runHook();
    expect(ctx).toContain("check_project");
    expect(ctx).toContain(sessionRules);
  });

  it("skips the rules when they are copied into ~/.claude/rules/qring", () => {
    mkdirSync(join(home, ".claude", "rules", "qring"), { recursive: true });
    writeFileSync(
      join(home, ".claude", "rules", "qring", "secret-hygiene.md"),
      "# Secret Hygiene\n",
    );
    const ctx = runHook();
    expect(ctx).toContain("get_project_context");
    expect(ctx).not.toContain("## Secret Hygiene");
  });

  it("skips the rules when the project-copy CLAUDE.md already carries them", () => {
    cpSync(join(repoRoot, "claude-code-plugin", "memory", "CLAUDE.md"), join(project, "CLAUDE.md"));
    const ctx = runHook();
    expect(ctx).toContain("get_project_context");
    expect(ctx).not.toContain("## q-ring Workflow");
  });

  it("escapes quotes, backslashes and newlines in the rules text", () => {
    const pluginCopy = mkdtempSync(join(tmpdir(), "qring-hook-plugin-"));
    try {
      cpSync(join(pluginHooks, "scripts"), join(pluginCopy, "scripts"), { recursive: true });
      const tricky = 'Line "one" with \\n a backslash \\ and `ticks`\n\n\tTabbed $HOME $(id) line';
      writeFileSync(join(pluginCopy, "qring-session-rules.md"), `${tricky}\n`);
      const ctx = runHook(join(pluginCopy, "scripts", "qring-session-start.sh"));
      expect(ctx.endsWith(tricky)).toBe(true);
    } finally {
      rmSync(pluginCopy, { recursive: true, force: true });
    }
  });
});
