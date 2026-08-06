/**
 * `qring setup <editor>` — wire the q-ring MCP server into an editor's
 * MCP config with one command, instead of hand-editing JSON.
 *
 * Writes the same server entry the bundled plugins ship (cursor-plugin/,
 * kiro-plugin/, claude-code-plugin/), merged non-destructively into the
 * editor's existing config: other servers are preserved, and an existing
 * q-ring entry is only replaced with --force.
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";

export type Editor = "cursor" | "kiro" | "claude";

export const EDITORS: Editor[] = ["cursor", "kiro", "claude"];

/** MCP tools that are safe to auto-approve (read-only) — mirrors kiro-plugin/mcp.json. */
const READ_ONLY_TOOLS = [
  "list_secrets",
  "has_secret",
  "inspect_secret",
  "detect_environment",
  "get_project_context",
  "list_providers",
  "list_hooks",
  "get_policy_summary",
  "audit_log",
  "verify_audit_chain",
  "health_check",
  "analyze_secrets",
];

export interface SetupOptions {
  editor: Editor;
  /** Write the per-user config instead of the per-project one. */
  global?: boolean;
  projectPath?: string;
  /** Replace an existing q-ring entry that differs from ours. */
  force?: boolean;
  dryRun?: boolean;
}

export interface SetupResult {
  editor: Editor;
  configPath: string;
  serverName: string;
  action: "created" | "updated" | "unchanged";
  dryRun: boolean;
  warnings: string[];
}

const SERVER_NAME = "q-ring";

function serverEntry(editor: Editor): Record<string, unknown> {
  switch (editor) {
    case "cursor":
      return { command: "qring-mcp", args: [], env: {} };
    case "kiro":
      return {
        command: "qring-mcp",
        args: [],
        env: {},
        disabled: false,
        autoApprove: READ_ONLY_TOOLS,
      };
    case "claude":
      return { type: "stdio", command: "qring-mcp", args: [], env: {} };
  }
}

export function configPathFor(
  editor: Editor,
  global: boolean,
  projectPath: string,
): string {
  const home = homedir();
  switch (editor) {
    case "cursor":
      return global
        ? join(home, ".cursor", "mcp.json")
        : join(projectPath, ".cursor", "mcp.json");
    case "kiro":
      return global
        ? join(home, ".kiro", "settings", "mcp.json")
        : join(projectPath, ".kiro", "settings", "mcp.json");
    case "claude":
      if (global) {
        // ~/.claude.json is harness-managed state, not a config file we
        // should merge into. User-scoped registration goes through the CLI.
        throw new Error(
          "Claude Code user-scoped MCP servers are registered via the claude CLI, not a config file.\n" +
            "Run: claude mcp add --scope user q-ring qring-mcp\n" +
            "Or install the plugin: /plugin marketplace add I4cTime/q-ring && /plugin install qring@q-ring",
        );
      }
      return join(projectPath, ".mcp.json");
  }
}

export function setupEditor(opts: SetupOptions): SetupResult {
  const projectPath = opts.projectPath ?? process.cwd();
  const configPath = configPathFor(opts.editor, opts.global ?? false, projectPath);
  const warnings: string[] = [];

  let config: Record<string, unknown> = {};
  if (existsSync(configPath)) {
    const raw = readFileSync(configPath, "utf8");
    try {
      config = JSON.parse(raw) as Record<string, unknown>;
    } catch {
      throw new Error(
        `${configPath} exists but is not valid JSON — fix or remove it, then re-run.`,
      );
    }
  }

  const servers = (config.mcpServers ?? {}) as Record<string, unknown>;
  const desired = serverEntry(opts.editor);
  const existing = servers[SERVER_NAME];

  let action: SetupResult["action"];
  if (existing === undefined) {
    action = existsSync(configPath) ? "updated" : "created";
    servers[SERVER_NAME] = desired;
  } else if (JSON.stringify(existing) === JSON.stringify(desired)) {
    action = "unchanged";
  } else if (opts.force) {
    action = "updated";
    servers[SERVER_NAME] = desired;
  } else {
    action = "unchanged";
    warnings.push(
      `A different "${SERVER_NAME}" entry already exists in ${configPath} — left as-is (use --force to replace it).`,
    );
  }

  config.mcpServers = servers;

  if (action !== "unchanged" && !opts.dryRun) {
    mkdirSync(dirname(configPath), { recursive: true });
    writeFileSync(configPath, JSON.stringify(config, null, 2) + "\n");
  }

  return {
    editor: opts.editor,
    configPath,
    serverName: SERVER_NAME,
    action,
    dryRun: opts.dryRun ?? false,
    warnings,
  };
}
