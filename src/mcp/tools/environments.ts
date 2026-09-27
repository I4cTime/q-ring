import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { toolAnnotations } from "../tool-annotations.js";
import { diffEnvironments, promoteSecret, PromoteConflictError } from "../../core/promote.js";
import { commonSchemas, enforceToolPolicy, opts, text } from "./_shared.js";

const { teamId, orgId, scope, projectPath } = commonSchemas;

export function registerEnvironmentTools(server: McpServer): void {
  server.tool(
    "promote_secret",
    [
      "[secrets] Copy one secret's value from a source environment to a target environment (superposition states), e.g. staging → prod, without the value ever leaving the keyring.",
      "Use when an environment must match another for a single key; use `diff_environments` first to see what differs. Refuses to overwrite a differing target unless `force` is true; a target that already matches is a no-op.",
      "Mutates the keyring (one 'write' audit event, hooks fire) only when the target changes. Returns { key, scope, from, to, previous: 'absent'|'same'|'different', changed }. Never returns the value.",
    ].join(" "),
    {
      key: z.string().describe("Secret key name. Example: 'DATABASE_URL'."),
      from: z.string().describe("Source environment state. Example: 'staging'."),
      to: z.string().describe("Target environment state. Example: 'prod'."),
      force: z
        .boolean()
        .default(false)
        .describe("Overwrite a differing target value. Default false → the call fails with ERR_PROMOTE_CONFLICT instead."),
      scope: scope.default("global"),
      projectPath,
      teamId,
      orgId,
    },
    toolAnnotations("promote_secret"),
    async (params) => {
      const toolBlock = enforceToolPolicy("promote_secret", params.projectPath);
      if (toolBlock) return toolBlock;
      try {
        const result = promoteSecret(params.key, {
          ...opts(params),
          from: params.from,
          to: params.to,
          force: params.force,
        });
        return text(JSON.stringify({ ok: true, data: result }, null, 2));
      } catch (err) {
        const code = err instanceof PromoteConflictError ? err.code : "ERR_PROMOTE";
        const message = err instanceof Error ? err.message : String(err);
        return text(JSON.stringify({ ok: false, code, error: message }), true);
      }
    },
  );

  server.tool(
    "diff_environments",
    [
      "[secrets] Compare two environments across the visible secrets and report, per key, whether the values are the same, different, or present on only one side — statuses only, never values.",
      "Use before a deploy or promotion to see environment drift; follow up with `promote_secret` per key. A single-value (collapsed) secret applies to every environment and is reported as 'collapsed'.",
      "Read-only apart from a 'list' audit event. Returns { a, b, entries: [{ key, scope, status }], summary, drift }.",
    ].join(" "),
    {
      envA: z.string().describe("First environment. Example: 'staging'."),
      envB: z.string().describe("Second environment. Example: 'prod'."),
      keys: z.array(z.string()).optional().describe("Restrict the comparison to these keys."),
      scope: scope.optional(),
      projectPath,
      teamId,
      orgId,
    },
    toolAnnotations("diff_environments"),
    async (params) => {
      const toolBlock = enforceToolPolicy("diff_environments", params.projectPath);
      if (toolBlock) return toolBlock;
      try {
        const result = diffEnvironments({
          ...opts(params),
          a: params.envA,
          b: params.envB,
          keys: params.keys,
        });
        return text(JSON.stringify({ ok: true, data: result }, null, 2));
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        return text(JSON.stringify({ ok: false, error: message }), true);
      }
    },
  );
}
