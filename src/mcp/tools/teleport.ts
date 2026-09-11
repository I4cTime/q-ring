import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { toolAnnotations } from "../tool-annotations.js";
import { z } from "zod";
import { getSecret, setSecret, listSecrets } from "../../core/keyring.js";
import { teleportPack, teleportUnpack } from "../../core/teleport.js";
import { text, opts, enforceToolPolicy, commonSchemas } from "./_shared.js";

const { teamId, orgId, scope, projectPath } = commonSchemas;

export function registerTeleportTools(server: McpServer): void {
  server.tool(
    "teleport_pack",
    [
      "[teleport] Encrypt one or more secrets into a single AES-256-GCM bundle string that can be safely transferred between machines.",
      "Use to hand off a curated set of credentials to another developer or environment; prefer `export_secrets` for plaintext .env output (single machine, trusted) and `tunnel_create` for ephemeral one-shot delivery on the same machine.",
      "Reads each secret value (records 'export' audit events) and produces a base64-encoded ciphertext. The bundle is unreadable without the same passphrase via `teleport_unpack`. Returns the bundle string directly. Errors with 'No secrets to pack' if the filter matched zero secrets.",
    ].join(" "),
    {
      keys: z
        .array(z.string())
        .optional()
        .describe(
          "Whitelist of exact key names to include. Omit to pack every secret in the requested scope.",
        ),
      passphrase: z
        .string()
        .describe(
          "Symmetric passphrase used to derive the AES-256-GCM key. The receiver must supply the same string to `teleport_unpack`. Pick something high-entropy and share it out-of-band.",
        ),
      scope,
      projectPath,
      teamId,
      orgId,
    },
    toolAnnotations("teleport_pack"),
    async (params) => {
      const toolBlock = enforceToolPolicy("teleport_pack", params.projectPath);
      if (toolBlock) return toolBlock;

      const o = opts(params);
      const entries = listSecrets(o);

      const secrets: { key: string; value: string; scope?: string }[] = [];
      for (const entry of entries) {
        if (params.keys && !params.keys.includes(entry.key)) continue;
        const value = getSecret(entry.key, { ...o, scope: entry.scope });
        if (value !== null) {
          secrets.push({ key: entry.key, value, scope: entry.scope });
        }
      }

      if (secrets.length === 0) return text("No secrets to pack", true);

      const bundle = teleportPack(secrets, params.passphrase);
      return text(bundle);
    },
  );

  server.tool(
    "teleport_unpack",
    [
      "[teleport] Decrypt a bundle produced by `teleport_pack` and import each contained secret into the local keyring.",
      "Use on the receiving machine after a packer hands you the bundle and passphrase out-of-band; prefer `dryRun=true` first to preview what will be written.",
      "When dryRun is false this mutates the keyring (one 'write' event per imported secret) at the requested scope. Bad passphrase or tampered bundle returns JSON `{ ok: false, error: { message } }` with `isError: true`. On success returns 'Imported N secret(s) from teleport bundle'; in dryRun mode returns 'Would import N secrets:' followed by a `KEY [scope]` listing.",
    ].join(" "),
    {
      bundle: z
        .string()
        .describe(
          "Base64-encoded ciphertext returned by `teleport_pack`. Pass through whitespace untouched if possible.",
        ),
      passphrase: z
        .string()
        .describe(
          "The same passphrase that was used to pack this bundle. Bad passphrases return an authentication error rather than wrong plaintext.",
        ),
      scope: scope.default("global"),
      projectPath,
      teamId,
      orgId,
      dryRun: z
        .boolean()
        .optional()
        .default(false)
        .describe(
          "If true, decrypt and report what would be written but do not mutate the keyring. Useful for verifying bundle contents before commit.",
        ),
    },
    toolAnnotations("teleport_unpack"),
    async (params) => {
      const toolBlock = enforceToolPolicy("teleport_unpack", params.projectPath);
      if (toolBlock) return toolBlock;

      try {
        const payload = teleportUnpack(params.bundle, params.passphrase);

        if (params.dryRun) {
          const preview = payload.secrets
            .map((s) => `${s.key} [${s.scope ?? "global"}]`)
            .join("\n");
          return text(`Would import ${payload.secrets.length} secrets:\n${preview}`);
        }

        const o = opts(params);
        for (const s of payload.secrets) {
          setSecret(s.key, s.value, o);
        }

        return text(`Imported ${payload.secrets.length} secret(s) from teleport bundle`);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        return text(JSON.stringify({ ok: false, error: { message: msg } }), true);
      }
    },
  );
}
