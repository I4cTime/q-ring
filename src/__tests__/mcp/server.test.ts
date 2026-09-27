import { describe, it, expect } from "vitest";
import { createMcpServer } from "../../mcp/server.js";

const EXPECTED_TOOLS = [
  "get_secret",
  "list_secrets",
  "set_secret",
  "promote_secret",
  "diff_environments",
  "delete_secret",
  "has_secret",
  "export_secrets",
  "import_dotenv",
  "check_project",
  "env_generate",
  "inspect_secret",
  "detect_environment",
  "generate_secret",
  "entangle_secrets",
  "disentangle_secrets",
  "tunnel_create",
  "tunnel_read",
  "tunnel_list",
  "tunnel_destroy",
  "teleport_pack",
  "teleport_unpack",
  "audit_log",
  "detect_anomalies",
  "health_check",
  "validate_secret",
  "list_providers",
  "register_hook",
  "list_hooks",
  "remove_hook",
  "exec_with_secrets",
  "scan_codebase_for_secrets",
  "get_project_context",
  "agent_remember",
  "agent_recall",
  "agent_forget",
  "lint_files",
  "analyze_secrets",
  "status_dashboard",
  "agent_scan",
  "verify_audit_chain",
  "export_audit",
  "rotate_secret",
  "ci_validate_secrets",
  "check_policy",
  "get_policy_summary",
] as const;

function getRegisteredToolNames(server: any): string[] {
  for (const key of Object.getOwnPropertyNames(server)) {
    const val = server[key];
    if (val instanceof Map) {
      const firstEntry = val.values().next().value;
      if (firstEntry && typeof firstEntry === "object" && "description" in firstEntry) {
        return [...val.keys()];
      }
    }
    if (val && typeof val === "object" && !(val instanceof Map) && !Array.isArray(val)) {
      const subKeys = Object.keys(val);
      if (subKeys.length > 10 && subKeys.includes("get_secret")) {
        return subKeys;
      }
    }
  }
  return [];
}

describe("createMcpServer", () => {
  it("returns an McpServer instance", () => {
    const server = createMcpServer();
    expect(server).toBeDefined();
  });

  it(`registers all ${EXPECTED_TOOLS.length} expected tools`, () => {
    const server = createMcpServer();
    const names = getRegisteredToolNames(server);
    const allKeys = Object.getOwnPropertyNames(server);
    expect(
      names.length,
      `Could not find tools registry on McpServer. Server keys: ${allKeys.join(", ")}`,
    ).toBeGreaterThan(0);

    expect(names.length).toBe(EXPECTED_TOOLS.length);

    for (const name of EXPECTED_TOOLS) {
      expect(names, `Missing tool: ${name}`).toContain(name);
    }
  });

  it("has no unexpected tools registered", () => {
    const server = createMcpServer();
    const names = getRegisteredToolNames(server);
    expect(names.length).toBeGreaterThan(0);

    for (const name of names) {
      expect(
        (EXPECTED_TOOLS as readonly string[]).includes(name),
        `Unexpected tool: ${name}`,
      ).toBe(true);
    }
  });
});
