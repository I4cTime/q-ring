import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { toolAnnotations } from "../tool-annotations.js";
import { z } from "zod";
import {
  checkToolPolicy,
  checkKeyReadPolicy,
  checkExecPolicy,
  getPolicySummary,
} from "../../core/policy.js";
import { text, enforceToolPolicy, commonSchemas } from "./_shared.js";

const { projectPath } = commonSchemas;

export function registerPolicyTools(server: McpServer): void {
  server.tool(
    "check_policy",
    [
      "[policy] Ask whether a single intended action would be allowed by the project's `.q-ring.json` policy without actually performing it.",
      "Use as a dry-run before calling a potentially-blocked tool, attempting to read a sensitive key, or invoking `exec_with_secrets` with a non-trivial command; prefer `get_policy_summary` for a one-shot overview of the entire policy.",
      "Read-only. Returns JSON `{ allowed, reason?, policySource }` describing the decision. Returns an error 'Missing required parameter for the selected action type' if the matching argument for the chosen `action` is not supplied.",
    ].join(" "),
    {
      action: z
        .enum(["tool", "key_read", "exec"])
        .describe(
          "Which policy surface to query. 'tool' = MCP tool gate (needs `toolName`); 'key_read' = secret read gate (needs `key`); 'exec' = exec_with_secrets command gate (needs `command`).",
        ),
      toolName: z
        .string()
        .optional()
        .describe("Tool id to evaluate, e.g. 'rotate_secret'. Required when `action` is 'tool'."),
      key: z
        .string()
        .optional()
        .describe("Secret key name to evaluate. Required when `action` is 'key_read'."),
      command: z
        .string()
        .optional()
        .describe(
          "Command to evaluate against the exec allowlist/denylist. Required when `action` is 'exec'.",
        ),
      projectPath,
    },
    toolAnnotations("check_policy"),
    async (params) => {
      if (params.action === "tool" && params.toolName) {
        const d = checkToolPolicy(params.toolName, params.projectPath);
        return text(JSON.stringify(d, null, 2));
      }
      if (params.action === "key_read" && params.key) {
        const d = checkKeyReadPolicy(params.key, undefined, params.projectPath);
        return text(JSON.stringify(d, null, 2));
      }
      if (params.action === "exec" && params.command) {
        const d = checkExecPolicy(params.command, params.projectPath);
        return text(JSON.stringify(d, null, 2));
      }
      return text("Missing required parameter for the selected action type", true);
    },
  );

  server.tool(
    "get_policy_summary",
    [
      "[policy] Return a high-level summary of the project's `.q-ring.json` governance policy — counts of allow/deny rules for tools, key reads, exec commands, plus approval and rotation requirements.",
      "Use to orient an agent (or the user) on what guardrails are active before attempting policy-restricted actions; prefer `check_policy` for a precise per-action verdict.",
      "Read-only. Returns pretty-printed JSON; missing policy file returns an empty/default summary rather than an error so callers can branch on the counts.",
    ].join(" "),
    {
      projectPath,
    },
    toolAnnotations("get_policy_summary"),
    async (params) => {
      const toolBlock = enforceToolPolicy("get_policy_summary", params.projectPath);
      if (toolBlock) return toolBlock;
      const summary = getPolicySummary(params.projectPath);
      return text(JSON.stringify(summary, null, 2));
    },
  );
}
