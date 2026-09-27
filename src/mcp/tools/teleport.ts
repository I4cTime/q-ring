import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { toolAnnotations } from "../tool-annotations.js";
import { z } from "zod";
import { getSecret, setSecret, listSecrets } from "../../core/keyring.js";
import {
  teleportPack,
  teleportPackFor,
  teleportUnpackAuto,
  inspectTeleportBundle,
  loadTeleportIdentity,
  parseRecipient,
} from "../../core/teleport.js";
import { text, opts, enforceToolPolicy, commonSchemas } from "./_shared.js";

const { teamId, orgId, scope, projectPath } = commonSchemas;

export function registerTeleportTools(server: McpServer): void {
  server.tool(
    "teleport_pack",
    [
      "[teleport] Encrypt one or more secrets into a single AES-256-GCM bundle string that can be safely transferred between machines.",
      "Use to hand off a curated set of credentials to another developer or environment; prefer `export_secrets` for plaintext .env output (single machine, trusted) and `tunnel_create` for ephemeral one-shot delivery on the same machine.",
      "Two modes, exactly one required: `passphrase` (v1, symmetric — receiver needs the same string) or `recipients` (v2, public-key — each receiver's `qring1...` string from `qring teleport identity`; no shared secret, only the listed identities can open it).",
      "Reads each secret value (records 'export' audit events) and produces a base64-encoded ciphertext. Returns the bundle string directly. Errors with 'No secrets to pack' if the filter matched zero secrets.",
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
        .optional()
        .describe(
          "Symmetric passphrase used to derive the AES-256-GCM key (v1 bundle). The receiver must supply the same string to `teleport_unpack`. Pick something high-entropy and share it out-of-band. Mutually exclusive with `recipients`.",
        ),
      recipients: z
        .array(z.string())
        .optional()
        .describe(
          "Recipient public keys (`qring1...` strings, one per teammate) for a v2 recipient pack. The bundle can only be opened by the matching private keys, which each receiver created with `qring teleport keygen`. Mutually exclusive with `passphrase`.",
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

      const recipients = (params.recipients ?? [])
        .flatMap((r) => r.split(","))
        .map((r) => r.trim())
        .filter((r) => r.length > 0);
      const hasPassphrase =
        typeof params.passphrase === "string" && params.passphrase.length > 0;

      if (hasPassphrase === (recipients.length > 0)) {
        return text(
          "teleport_pack needs exactly one of `passphrase` (v1) or `recipients` (v2)",
          true,
        );
      }
      for (const r of recipients) {
        try {
          parseRecipient(r);
        } catch (err) {
          const msg = err instanceof Error ? err.message : String(err);
          return text(`Bad recipient "${r}": ${msg}`, true);
        }
      }

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

      const bundle =
        recipients.length > 0
          ? teleportPackFor(secrets, recipients)
          : teleportPack(secrets, params.passphrase as string);
      return text(bundle);
    },
  );

  server.tool(
    "teleport_unpack",
    [
      "[teleport] Decrypt a bundle produced by `teleport_pack` and import each contained secret into the local keyring.",
      "Use on the receiving machine after a packer hands you the bundle; prefer `dryRun=true` first to preview what will be written.",
      "Passphrase (v1) bundles need `passphrase`. Recipient (v2) bundles need no input: this machine's teleport identity is read from the OS keyring (create one with `qring teleport keygen`; the private key is never returned).",
      "When dryRun is false this mutates the keyring (one 'write' event per imported secret) at the requested scope. Bad passphrase, missing identity, not-a-recipient or tampered bundle returns JSON `{ ok: false, error: { message } }` with `isError: true`. On success returns 'Imported N secret(s) from teleport bundle'; in dryRun mode returns 'Would import N secrets:' followed by a `KEY [scope]` listing (v2 also lists the recipient ids the bundle is addressed to).",
    ].join(" "),
    {
      bundle: z
        .string()
        .describe(
          "Base64-encoded ciphertext returned by `teleport_pack`. Pass through whitespace untouched if possible.",
        ),
      passphrase: z
        .string()
        .optional()
        .describe(
          "The passphrase used to pack a v1 bundle. Omit for v2 recipient bundles (decrypted with this machine's keyring identity). Bad passphrases return an authentication error rather than wrong plaintext.",
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
        const info = inspectTeleportBundle(params.bundle);

        let header = "";
        let identity: ReturnType<typeof loadTeleportIdentity> = null;
        if (info.v === 2) {
          identity = loadTeleportIdentity();
          if (!identity) {
            throw new Error(
              "ERR_TELEPORT_NO_IDENTITY: this bundle is addressed to recipient keys and this machine has no teleport identity — run `qring teleport keygen` first",
            );
          }
          const ids = info.recipients
            .map((id) => (id === identity!.id ? `${id} (you)` : id))
            .join(", ");
          header = `Addressed to recipient id(s): ${ids}\n`;
        } else if (params.passphrase === undefined) {
          throw new Error(
            "ERR_TELEPORT_PASSPHRASE_REQUIRED: this is a passphrase (v1) bundle — pass `passphrase`",
          );
        }

        const payload = teleportUnpackAuto(params.bundle, {
          passphrase: params.passphrase,
          identity: identity?.privateKey,
        });

        if (params.dryRun) {
          const preview = payload.secrets
            .map((s) => `${s.key} [${s.scope ?? "global"}]`)
            .join("\n");
          return text(
            `${header}Would import ${payload.secrets.length} secrets:\n${preview}`,
          );
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
