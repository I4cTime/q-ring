import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { toolAnnotations } from "../tool-annotations.js";
import { z } from "zod";
import { remember, recall, listMemory, forget } from "../../core/memory.js";
import { text, enforceToolPolicy } from "./_shared.js";

export function registerAgentTools(server: McpServer): void {
  server.tool(
    "agent_remember",
    [
      "[agent] Persist a non-secret key/value note in encrypted, on-disk agent memory that survives across MCP sessions.",
      "Use to record stable agent context — last rotation date for a key, the user's deployment preferences, decisions taken in earlier sessions; do NOT use this to store secrets (use `set_secret` instead) and prefer chat scratchpad for purely transient state.",
      "Mutates the encrypted memory store. Idempotent: rewriting the same key with a new value simply overwrites. Returns 'Remembered \"KEY\"' on success.",
    ].join(" "),
    {
      key: z
        .string()
        .describe(
          "Memory key (free-form string). Convention: lowercase dotted namespaces, e.g. 'project.lastDeploy'.",
        ),
      value: z
        .string()
        .describe(
          "Plain-string value to store. JSON-stringify structured data on the caller side if needed.",
        ),
    },
    toolAnnotations("agent_remember"),
    async (params) => {
      const toolBlock = enforceToolPolicy("agent_remember");
      if (toolBlock) return toolBlock;

      remember(params.key, params.value);
      return text(`Remembered "${params.key}"`);
    },
  );

  server.tool(
    "agent_recall",
    [
      "[agent] Read a value from encrypted agent memory, or list every stored key when no specific key is supplied.",
      "Use at the start of an agent loop to rehydrate prior context, or to look up a single remembered fact; prefer `get_project_context` for a redacted overview of secrets and `get_secret` for actual credential values.",
      "Read-only. With a `key` argument: returns JSON `{ ok, data: { key, value } }` or a not-found error. Without `key`: returns a JSON listing of every stored key (no values), or 'Agent memory is empty'.",
    ].join(" "),
    {
      key: z
        .string()
        .optional()
        .describe("Memory key to read. Omit to list every stored key (without values)."),
    },
    toolAnnotations("agent_recall"),
    async (params) => {
      const toolBlock = enforceToolPolicy("agent_recall");
      if (toolBlock) return toolBlock;

      if (!params.key) {
        const entries = listMemory();
        if (entries.length === 0) return text("Agent memory is empty");
        return text(JSON.stringify(entries, null, 2));
      }
      const value = recall(params.key);
      if (value === null) return text(`No memory found for "${params.key}"`, true);
      return text(JSON.stringify({ ok: true, data: { key: params.key, value } }, null, 2));
    },
  );

  server.tool(
    "agent_forget",
    [
      "[agent] Permanently delete a single key from encrypted agent memory.",
      "Use to retract obsolete or misremembered context; prefer overwriting via `agent_remember` when you just want to update the value, and use `delete_secret` for actual credentials (which never live in agent memory).",
      "Destructive: there is no recycle bin. Returns 'Forgot \"KEY\"' on success or a not-found error if the key was already absent.",
    ].join(" "),
    {
      key: z.string().describe("Memory key to delete."),
    },
    toolAnnotations("agent_forget"),
    async (params) => {
      const toolBlock = enforceToolPolicy("agent_forget");
      if (toolBlock) return toolBlock;

      const removed = forget(params.key);
      return text(
        removed ? `Forgot "${params.key}"` : `No memory found for "${params.key}"`,
        !removed,
      );
    },
  );
}
