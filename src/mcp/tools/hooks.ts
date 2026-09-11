import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { toolAnnotations } from "../tool-annotations.js";
import { z } from "zod";
import {
  registerHook,
  removeHook,
  listHooks as listAllHooks,
  type HookType,
  type HookAction,
} from "../../core/hooks.js";
import { text, enforceToolPolicy } from "./_shared.js";

export function registerHookTools(server: McpServer): void {
  server.tool(
    "register_hook",
    [
      "[hooks] Register a side-effect (shell command, HTTP webhook, or process signal) that fires automatically when a matching secret is written, deleted, or rotated.",
      "Use to keep external systems in sync (restart a service after rotation, post to Slack on delete, kick a build); prefer `agent_remember` for storing facts an agent should recall later, and `register_hook` is not the right tool for time-based scheduled rotation (use `agent_scan` for that).",
      "Mutates the hook registry on disk. At least one match criterion (`key`, `keyPattern`, or `tag`) is required — calls without any return an error. Returns JSON of the registered hook entry including its assigned `id` (use that `id` with `remove_hook`).",
    ].join(" "),
    {
      type: z
        .enum(["shell", "http", "signal"])
        .describe(
          "Hook delivery mechanism. 'shell' runs a local command, 'http' POSTs JSON to a URL, 'signal' sends an OS signal to a named process.",
        ),
      key: z
        .string()
        .optional()
        .describe(
          "Trigger only on this exact key name. Pick at most one of `key` / `keyPattern` / `tag` (or combine for stricter matching).",
        ),
      keyPattern: z
        .string()
        .optional()
        .describe("Trigger on any key matching this glob pattern. Examples: 'DB_*', 'STRIPE_*'."),
      tag: z
        .string()
        .optional()
        .describe(
          "Trigger on any secret carrying this exact tag. Combinable with key/keyPattern as an AND filter.",
        ),
      scope: z
        .enum(["global", "project"])
        .optional()
        .describe(
          "Restrict the hook to secrets in this scope. Omit to fire across both global and project secrets.",
        ),
      actions: z
        .array(z.enum(["write", "delete", "rotate"]))
        .optional()
        .default(["write", "delete", "rotate"])
        .describe("Which lifecycle actions trigger this hook. Defaults to all three."),
      command: z
        .string()
        .optional()
        .describe(
          "Required when type='shell'. The literal shell command to run; q-ring exposes the matching key as $QRING_HOOK_KEY and action as $QRING_HOOK_ACTION.",
        ),
      url: z
        .string()
        .optional()
        .describe(
          "Required when type='http'. Full URL to POST a JSON body `{ id, key, scope, action, timestamp }` to (the value itself is never sent).",
        ),
      signalTarget: z
        .string()
        .optional()
        .describe(
          "Required when type='signal'. Either a numeric PID or a process name resolvable via `ps`.",
        ),
      signalName: z
        .string()
        .optional()
        .default("SIGHUP")
        .describe(
          "Signal name to send (e.g. 'SIGHUP', 'SIGUSR1'). Defaults to SIGHUP, which most daemons treat as 'reload config'.",
        ),
      description: z
        .string()
        .optional()
        .describe(
          "Free-text human-readable description, surfaced by `list_hooks` and the dashboard.",
        ),
    },
    toolAnnotations("register_hook"),
    async (params) => {
      const toolBlock = enforceToolPolicy("register_hook");
      if (toolBlock) return toolBlock;

      if (!params.key && !params.keyPattern && !params.tag) {
        return text("At least one match criterion required: key, keyPattern, or tag", true);
      }

      const entry = registerHook({
        type: params.type as HookType,
        match: {
          key: params.key,
          keyPattern: params.keyPattern,
          tag: params.tag,
          scope: params.scope as "global" | "project" | undefined,
          action: params.actions as HookAction[],
        },
        command: params.command,
        url: params.url,
        signal: params.signalTarget
          ? { target: params.signalTarget, signal: params.signalName }
          : undefined,
        description: params.description,
        enabled: true,
      });

      return text(JSON.stringify(entry, null, 2));
    },
  );

  server.tool(
    "list_hooks",
    [
      "[hooks] Enumerate every registered lifecycle hook with its match criteria, delivery type, enabled flag, and description.",
      "Use to find a hook's `id` before calling `remove_hook`, audit what side effects are wired up, or diagnose why a hook did not fire.",
      "Read-only. Returns pretty-printed JSON array of hook entries, or 'No hooks registered' when the registry is empty.",
    ].join(" "),
    {},
    toolAnnotations("list_hooks"),
    async () => {
      const toolBlock = enforceToolPolicy("list_hooks");
      if (toolBlock) return toolBlock;

      const hooks = listAllHooks();
      if (hooks.length === 0) return text("No hooks registered");
      return text(JSON.stringify(hooks, null, 2));
    },
  );

  server.tool(
    "remove_hook",
    [
      "[hooks] Detach a single lifecycle hook by its registry id so it stops firing.",
      "Use to retire a specific webhook/command without touching any secrets; prefer `delete_secret` to remove a credential and `tunnel_destroy` for ephemeral tunnels.",
      "Mutates the hook registry only — does not touch secret values, audit log, or env states. Idempotent in spirit: removing an already-absent id returns a not-found error rather than partial work. Returns 'Removed hook ID' on success.",
    ].join(" "),
    {
      id: z
        .string()
        .describe(
          "Hook id returned by `register_hook` or visible in `list_hooks` (opaque string).",
        ),
    },
    toolAnnotations("remove_hook"),
    async (params) => {
      const toolBlock = enforceToolPolicy("remove_hook");
      if (toolBlock) return toolBlock;

      const removed = removeHook(params.id);
      return text(
        removed ? `Removed hook ${params.id}` : `Hook "${params.id}" not found`,
        !removed,
      );
    },
  );
}
