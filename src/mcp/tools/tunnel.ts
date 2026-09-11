import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { toolAnnotations } from "../tool-annotations.js";
import { z } from "zod";
import { tunnelCreate, tunnelRead, tunnelDestroy, tunnelList } from "../../core/tunnel.js";
import { text, enforceToolPolicy } from "./_shared.js";

export function registerTunnelTools(server: McpServer): void {
  server.tool(
    "tunnel_create",
    [
      "[tunnel] Stash a one-shot or short-lived secret in the q-ring server's process memory and return an ID that can be used to read it back.",
      "Use for handing a one-time value to another tool/process without persisting it (npm OTP codes, magic-link tokens, copy/paste between machines via a relay); prefer `set_secret` with `ttlSeconds` when you actually want a tracked, auditable secret.",
      "Mutates only in-memory state — the value never touches disk and is lost on server restart. Subject to tool policy. Returns JSON `{ ok, data: { id } }` where `id` is an opaque string to pass to `tunnel_read`/`tunnel_destroy`.",
    ].join(" "),
    {
      value: z
        .string()
        .describe("The plaintext value to tunnel. Held only in process memory; never logged."),
      ttlSeconds: z
        .number()
        .optional()
        .describe(
          "Auto-destroy the tunnel after this many seconds. Omit for no time limit (then a `maxReads` is highly recommended).",
        ),
      maxReads: z
        .number()
        .optional()
        .describe(
          "Self-destruct after this many successful `tunnel_read` calls. Use 1 for true one-shot delivery.",
        ),
    },
    toolAnnotations("tunnel_create"),
    async (params) => {
      const toolBlock = enforceToolPolicy("tunnel_create");
      if (toolBlock) return toolBlock;

      const id = tunnelCreate(params.value, {
        ttlSeconds: params.ttlSeconds,
        maxReads: params.maxReads,
      });
      return text(JSON.stringify({ ok: true, data: { id } }, null, 2));
    },
  );

  server.tool(
    "tunnel_read",
    [
      "[tunnel] Fetch the value stashed by a prior `tunnel_create` call by its ID.",
      "Use exactly once per intended consumer; the value is destructive-by-design and may self-delete after this call.",
      "Increments the read counter and may auto-destroy the tunnel if `maxReads` was set. Returns JSON `{ ok, data: { id, value } }` on success, or an error 'Tunnel \"...\" not found or expired' if the tunnel has been destroyed, hit its TTL, or never existed.",
    ].join(" "),
    {
      id: z.string().describe("The opaque tunnel ID returned by `tunnel_create`. Case-sensitive."),
    },
    toolAnnotations("tunnel_read"),
    async (params) => {
      const toolBlock = enforceToolPolicy("tunnel_read");
      if (toolBlock) return toolBlock;

      const value = tunnelRead(params.id);
      if (value === null) {
        return text(`Tunnel "${params.id}" not found or expired`, true);
      }
      return text(JSON.stringify({ ok: true, data: { id: params.id, value } }, null, 2));
    },
  );

  server.tool(
    "tunnel_list",
    [
      "[tunnel] Enumerate all currently-active tunnels in the q-ring server with their remaining read budget and time-to-live.",
      "Use to audit what is still in memory or to look up an ID you forgot; values are never included in the output.",
      "Read-only. Returns one line per tunnel formatted as `id | reads:N | max:N | expires:Ns`, or the literal text 'No active tunnels' when the list is empty.",
    ].join(" "),
    {},
    toolAnnotations("tunnel_list"),
    async () => {
      const toolBlock = enforceToolPolicy("tunnel_list");
      if (toolBlock) return toolBlock;

      const tunnels = tunnelList();
      if (tunnels.length === 0) return text("No active tunnels");

      const lines = tunnels.map((t) => {
        const parts = [t.id];
        parts.push(`reads:${t.accessCount}`);
        if (t.maxReads) parts.push(`max:${t.maxReads}`);
        if (t.expiresAt) {
          const rem = Math.max(0, Math.floor((t.expiresAt - Date.now()) / 1000));
          parts.push(`expires:${rem}s`);
        }
        return parts.join(" | ");
      });

      return text(lines.join("\n"));
    },
  );

  server.tool(
    "tunnel_destroy",
    [
      "[tunnel] Immediately remove a tunnel from memory, regardless of remaining reads or TTL.",
      "Use when a tunneled value should be cancelled before delivery (e.g. wrong recipient, secret already rotated); prefer letting `maxReads`/TTL handle cleanup for normal flows.",
      "Mutates in-memory state only. Returns 'Destroyed ID' on success or a not-found error if the ID is unknown or already gone.",
    ].join(" "),
    {
      id: z.string().describe("The opaque tunnel ID to destroy."),
    },
    toolAnnotations("tunnel_destroy"),
    async (params) => {
      const toolBlock = enforceToolPolicy("tunnel_destroy");
      if (toolBlock) return toolBlock;

      const destroyed = tunnelDestroy(params.id);
      return text(
        destroyed ? `Destroyed ${params.id}` : `Tunnel "${params.id}" not found`,
        !destroyed,
      );
    },
  );
}
