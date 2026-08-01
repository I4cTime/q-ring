import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { filterSecretsByKeyGlob } from "../../services/list-secrets-filter.js";
import {
  getSecret,
  setSecret,
  deleteSecret,
  hasSecret,
  listSecrets,
  getEnvelope,
  entangleSecrets,
  disentangleSecrets,
  exportSecrets,
} from "../../core/keyring.js";
import { checkDecay } from "../../core/envelope.js";
import type { Scope } from "../../core/scope.js";
import {
  generateSecret,
  estimateEntropy,
  type NoiseFormat,
} from "../../core/noise.js";
import { importDotenv } from "../../core/import.js";
import { checkKeyReadPolicy } from "../../core/policy.js";
import { text, opts, enforceToolPolicy, commonSchemas } from "./_shared.js";

const { teamId, orgId, scope, projectPath, env } = commonSchemas;

export function registerSecretTools(server: McpServer): void {
  server.tool(
    "get_secret",
    [
      "[secrets] Read the plaintext value of a single secret from the q-ring keyring.",
      "Use when an agent needs the actual credential to call an external API or inject into a runtime; prefer `inspect_secret` to see metadata only, `has_secret` for presence-only checks, and `exec_with_secrets` to run a command without exposing the value to chat.",
      "Side effects: collapses superposition (selects the per-env state) and writes a 'read' event to the audit log (observer effect). Subject to project tool/key policy and may be denied with a 'Policy Denied' message. Returns JSON `{ ok, data: { key, value } }` on success or an error message if missing/blocked.",
    ].join(" "),
    {
      key: z
        .string()
        .describe(
          "Exact secret key name as stored in the keyring (case-sensitive). Example: 'OPENAI_API_KEY'.",
        ),
      scope,
      projectPath,
      env,
      teamId,
      orgId,
    },
    async (params) => {
      const toolBlock = enforceToolPolicy("get_secret", params.projectPath);
      if (toolBlock) return toolBlock;

      try {
        const keyBlock = checkKeyReadPolicy(
          params.key,
          undefined,
          params.projectPath,
        );
        if (!keyBlock.allowed) {
          return text(`Policy Denied: ${keyBlock.reason}`, true);
        }

        const value = getSecret(params.key, opts(params));
        if (value === null) return text(`Secret "${params.key}" not found`, true);
        return text(
          JSON.stringify({ ok: true, data: { key: params.key, value } }, null, 2),
        );
      } catch (err) {
        return text(err instanceof Error ? err.message : String(err), true);
      }
    },
  );

  server.tool(
    "list_secrets",
    [
      "[secrets] List secret keys and quantum metadata in the requested scope, never the values.",
      "Use to discover what secrets exist before reading or writing; pair with `inspect_secret` for full metadata on one key, `analyze_secrets` for usage trends, or `health_check` for decay/anomaly summaries.",
      "Read-only; safe to call repeatedly. Returns JSON `{ ok, data: { entries: [...] } }` where each entry has scope, key, stateKeys (env names if superposed), expired, stale, lifetimePercent, timeRemaining, entangledCount, accessCount.",
    ].join(" "),
    {
      scope,
      projectPath,
      tag: z
        .string()
        .optional()
        .describe(
          "Return only secrets that include this exact tag (case-sensitive). Example: 'production'.",
        ),
      expired: z
        .boolean()
        .optional()
        .describe(
          "If true, return only secrets whose decay TTL has elapsed (lifetimePercent >= 100).",
        ),
      stale: z
        .boolean()
        .optional()
        .describe(
          "If true, return only secrets in the stale window (lifetimePercent >= 75 and not yet expired).",
        ),
      filter: z
        .string()
        .optional()
        .describe(
          "Glob pattern matched against the key name. Supports `*` and `?`. Examples: 'API_*', 'STRIPE_?_KEY'.",
        ),
      teamId,
      orgId,
    },
    async (params) => {
      const toolBlock = enforceToolPolicy("list_secrets", params.projectPath);
      if (toolBlock) return toolBlock;

      let entries = listSecrets(opts(params));

      if (params.tag) {
        entries = entries.filter((e) =>
          e.envelope?.meta.tags?.includes(params.tag!),
        );
      }
      if (params.expired) {
        entries = entries.filter((e) => e.decay?.isExpired);
      }
      if (params.stale) {
        entries = entries.filter(
          (e) => e.decay?.isStale && !e.decay?.isExpired,
        );
      }
      if (params.filter) {
        entries = filterSecretsByKeyGlob(entries, params.filter);
      }
      const rows = entries.map((e) => ({
        scope: e.scope,
        key: e.key,
        stateKeys: e.envelope?.states
          ? Object.keys(e.envelope.states)
          : undefined,
        expired: !!e.decay?.isExpired,
        stale: !!e.decay?.isStale && !e.decay?.isExpired,
        lifetimePercent: e.decay?.lifetimePercent,
        timeRemaining: e.decay?.timeRemaining ?? null,
        entangledCount: e.envelope?.meta.entangled?.length ?? 0,
        accessCount: e.envelope?.meta.accessCount ?? 0,
      }));

      return text(JSON.stringify({ ok: true, data: { entries: rows } }, null, 2));
    },
  );

  server.tool(
    "set_secret",
    [
      "[secrets] Create or overwrite a single secret value, optionally with TTL/decay, per-env superposition, description, tags, and rotation hints.",
      "Use to add or update one key at a time; prefer `import_dotenv` for bulk .env ingest, `generate_secret` (with saveAs) to generate-and-store in one step, and `entangle_secrets` instead of duplicating the same value under two keys.",
      "Mutates the keyring (overwrites any existing value at the same key/scope), writes a 'write' event to the audit log, and triggers any matching hooks. Subject to tool policy. Returns a short confirmation text like '[scope] KEY saved' (or '[scope] KEY set for env:NAME' when `env` is provided).",
    ].join(" "),
    {
      key: z
        .string()
        .describe(
          "Secret key name (UPPER_SNAKE_CASE recommended). Example: 'STRIPE_SECRET_KEY'.",
        ),
      value: z
        .string()
        .describe(
          "The secret value to store. Stored as-is; never logged or echoed. May be empty only when `env` is provided to register a new env without a default.",
        ),
      scope: scope.default("global"),
      projectPath,
      env: z
        .string()
        .optional()
        .describe(
          "If set, writes this value to the named per-env state (superposition) instead of the default slot. Existing default value is preserved as state 'default'. Example: 'prod'.",
        ),
      ttlSeconds: z
        .number()
        .optional()
        .describe(
          "Quantum decay window in seconds. After this many seconds the secret is marked expired (still readable, but `has_secret` returns false and `health_check` flags it). Omit for no decay.",
        ),
      description: z
        .string()
        .optional()
        .describe(
          "Free-text human-readable description shown in `inspect_secret` and the dashboard.",
        ),
      tags: z
        .array(z.string())
        .optional()
        .describe(
          "Tag list for filtering and hook matching. Example: ['production', 'payments'].",
        ),
      rotationFormat: z
        .enum([
          "hex",
          "base64",
          "alphanumeric",
          "uuid",
          "api-key",
          "token",
          "password",
        ])
        .optional()
        .describe(
          "Format used by `agent_scan --autoRotate` and `rotate_secret` when this secret expires. Pick the format that matches the upstream service's accepted shape.",
        ),
      rotationPrefix: z
        .string()
        .optional()
        .describe(
          "Literal prefix prepended on auto-rotation (only used with rotationFormat 'api-key' or 'token'). Example: 'sk-'.",
        ),
      teamId,
      orgId,
    },
    async (params) => {
      const toolBlock = enforceToolPolicy("set_secret", params.projectPath);
      if (toolBlock) return toolBlock;

      const o = opts(params);

      if (params.env) {
        const existing = getEnvelope(params.key, o);
        const states = existing?.envelope?.states ?? {};
        states[params.env] = params.value;

        if (existing?.envelope?.value && !states["default"]) {
          states["default"] = existing.envelope.value;
        }

        setSecret(params.key, "", {
          ...o,
          states,
          defaultEnv: existing?.envelope?.defaultEnv ?? params.env,
          ttlSeconds: params.ttlSeconds,
          description: params.description,
          tags: params.tags,
          rotationFormat: params.rotationFormat,
          rotationPrefix: params.rotationPrefix,
        });

        return text(
          `[${params.scope ?? "global"}] ${params.key} set for env:${params.env}`,
        );
      }

      setSecret(params.key, params.value, {
        ...o,
        ttlSeconds: params.ttlSeconds,
        description: params.description,
        tags: params.tags,
        rotationFormat: params.rotationFormat,
        rotationPrefix: params.rotationPrefix,
      });

      return text(`[${params.scope ?? "global"}] ${params.key} saved`);
    },
  );

  server.tool(
    "delete_secret",
    [
      "[secrets] Permanently remove a secret value (and all its env states) from the keyring for the given scope.",
      "Use when a credential is being retired or was created in error; prefer `disentangle_secrets` to break a sync link without erasing values, `remove_hook` to detach lifecycle callbacks, and `tunnel_destroy` for ephemeral tunnels.",
      "Destructive and not undoable from q-ring (no built-in trash). Writes a 'delete' event to the audit log and fires matching hooks. Returns 'Deleted \"KEY\"' on success or a not-found error if the key did not exist in the requested scope. Subject to tool policy.",
    ].join(" "),
    {
      key: z
        .string()
        .describe("Exact secret key name to delete. Example: 'OLD_API_KEY'."),
      scope,
      projectPath,
      teamId,
      orgId,
    },
    async (params) => {
      const toolBlock = enforceToolPolicy("delete_secret", params.projectPath);
      if (toolBlock) return toolBlock;

      const deleted = deleteSecret(params.key, opts(params));
      return text(
        deleted ? `Deleted "${params.key}"` : `Secret "${params.key}" not found`,
        !deleted,
      );
    },
  );

  server.tool(
    "has_secret",
    [
      "[secrets] Check whether a secret exists in the requested scope without reading the value.",
      "Use as a cheap precondition before reading or writing — for example, to skip prompting the user for a key that is already configured. Prefer `inspect_secret` when you also need metadata.",
      "Read-only; does not record a 'read' in the audit log. Decay-aware: returns 'false' for expired secrets even though the value is still in the store. Returns the literal text 'true' or 'false'.",
    ].join(" "),
    {
      key: z
        .string()
        .describe("Exact secret key name. Example: 'GITHUB_TOKEN'."),
      scope,
      projectPath,
      teamId,
      orgId,
    },
    async (params) => {
      const toolBlock = enforceToolPolicy("has_secret", params.projectPath);
      if (toolBlock) return toolBlock;

      return text(hasSecret(params.key, opts(params)) ? "true" : "false");
    },
  );

  server.tool(
    "export_secrets",
    [
      "[secrets] Render multiple secrets as a single .env or JSON document for piping into another tool or file.",
      "Use to materialize secrets for a one-off export or copy; prefer `env_generate` when you want output driven by the project's `.q-ring.json` manifest, and `teleport_pack` for an encrypted bundle to share between machines.",
      "Reads values (collapses superposition for the requested env) and writes one 'export' event per included secret to the audit log. Returns the rendered text directly (no JSON wrapper). Returns an error if no secrets matched the filters. Values are surfaced in plaintext — handle with care.",
    ].join(" "),
    {
      format: z
        .enum(["env", "json"])
        .optional()
        .default("env")
        .describe(
          "'env' renders KEY=\"value\" lines suitable for a .env file; 'json' renders an object keyed by secret name. Defaults to 'env'.",
        ),
      keys: z
        .array(z.string())
        .optional()
        .describe(
          "Whitelist of exact key names to include. If omitted, every key in scope is considered (subject to `tags`).",
        ),
      tags: z
        .array(z.string())
        .optional()
        .describe(
          "Include only secrets tagged with at least one of these tags. Combined with `keys` as an AND filter when both are supplied.",
        ),
      scope,
      projectPath,
      env,
      teamId,
      orgId,
    },
    async (params) => {
      const toolBlock = enforceToolPolicy("export_secrets", params.projectPath);
      if (toolBlock) return toolBlock;

      const output = exportSecrets({
        ...opts(params),
        format: params.format as "env" | "json",
        keys: params.keys,
        tags: params.tags,
      });

      if (!output.trim()) return text("No secrets matched the filters", true);
      return text(output);
    },
  );

  server.tool(
    "import_dotenv",
    [
      "[secrets] Parse standard dotenv-formatted text and store each key/value pair into the keyring in one batch.",
      "Use when migrating an existing `.env` file into q-ring or onboarding a new project; prefer `set_secret` for a single key, and `teleport_unpack` to import an encrypted bundle.",
      "Mutates the keyring (one write per parsed key) and emits a 'write' audit event for each. Supports comments, single/double quotes, and `\\n` escapes. Returns a multiline summary listing imported keys and any skipped (existing) keys; in dryRun mode no writes happen and the same summary is produced for review.",
    ].join(" "),
    {
      content: z
        .string()
        .describe(
          "Raw .env file content as a single string (newline-separated KEY=VALUE lines, comments allowed).",
        ),
      scope: scope.default("global"),
      projectPath,
      skipExisting: z
        .boolean()
        .optional()
        .default(false)
        .describe(
          "If true, leave already-present keys untouched and add them to the 'skipped' list instead of overwriting.",
        ),
      dryRun: z
        .boolean()
        .optional()
        .default(false)
        .describe(
          "If true, parse and report what would happen but do not write to the keyring. Useful for previewing imports before committing.",
        ),
    },
    async (params) => {
      const toolBlock = enforceToolPolicy("import_dotenv", params.projectPath);
      if (toolBlock) return toolBlock;

      const result = importDotenv(params.content, {
        scope: params.scope as "global" | "project",
        projectPath: params.projectPath ?? process.cwd(),
        source: "mcp",
        skipExisting: params.skipExisting,
        dryRun: params.dryRun,
      });

      const lines = [
        params.dryRun
          ? "Dry run — no changes made"
          : `Imported ${result.imported.length} secret(s)`,
      ];

      if (result.imported.length > 0) {
        lines.push(`Keys: ${result.imported.join(", ")}`);
      }
      if (result.skipped.length > 0) {
        lines.push(`Skipped (existing): ${result.skipped.join(", ")}`);
      }

      return text(lines.join("\n"));
    },
  );

  server.tool(
    "inspect_secret",
    [
      "[secrets] Show full metadata for a single secret — env states, decay window, entanglement links, access counters — without ever revealing the value.",
      "Use when you need to understand the shape of a key before reading it or to debug 'why is this expired/stale'; prefer `get_secret` for the actual value, `list_secrets` for a many-key overview, and `audit_log` for the full access timeline.",
      "Read-only; does not write a 'read' event since the value is not exposed. Returns pretty-printed JSON with fields: key, scope, type ('superposition'|'collapsed'), created, updated, accessCount, lastAccessed, environments, defaultEnv, decay { expired, stale, lifetimePercent, timeRemaining }, entangled, description, tags. Errors with not-found if the key is absent.",
    ].join(" "),
    {
      key: z
        .string()
        .describe("Exact secret key name to inspect. Example: 'OPENAI_API_KEY'."),
      scope,
      projectPath,
      teamId,
      orgId,
    },
    async (params) => {
      const toolBlock = enforceToolPolicy("inspect_secret", params.projectPath);
      if (toolBlock) return toolBlock;

      const result = getEnvelope(params.key, opts(params));
      if (!result) return text(`Secret "${params.key}" not found`, true);

      const { envelope, scope: entryScope } = result;
      const decay = checkDecay(envelope);

      const info: Record<string, unknown> = {
        key: params.key,
        scope: entryScope,
        type: envelope.states ? "superposition" : "collapsed",
        created: envelope.meta.createdAt,
        updated: envelope.meta.updatedAt,
        accessCount: envelope.meta.accessCount,
        lastAccessed: envelope.meta.lastAccessedAt ?? "never",
      };

      if (envelope.states) {
        info.environments = Object.keys(envelope.states);
        info.defaultEnv = envelope.defaultEnv;
      }

      if (decay.timeRemaining) {
        info.decay = {
          expired: decay.isExpired,
          stale: decay.isStale,
          lifetimePercent: decay.lifetimePercent,
          timeRemaining: decay.timeRemaining,
        };
      }

      if (envelope.meta.entangled?.length) {
        info.entangled = envelope.meta.entangled;
      }

      if (envelope.meta.description)
        info.description = envelope.meta.description;
      if (envelope.meta.tags?.length) info.tags = envelope.meta.tags;

      return text(JSON.stringify(info, null, 2));
    },
  );

  server.tool(
    "generate_secret",
    [
      "[secrets] Generate a cryptographically random secret using Node's CSPRNG and optionally store it in the keyring in one step.",
      "Use to create new credentials that you control (signing keys, internal tokens, passwords); for issuer-issued credentials (Stripe/OpenAI etc.) use `rotate_secret` to ask the upstream provider for a fresh key, and use `set_secret` for values you already have in hand.",
      "If `saveAs` is provided this mutates the keyring (one 'write' event) and returns a summary like 'Generated and saved as \"KEY\" (FORMAT, ~N bits entropy)'. Without `saveAs` the call is read-only and returns JSON `{ ok, data: { value } }` containing the freshly generated string.",
    ].join(" "),
    {
      format: z
        .enum([
          "hex",
          "base64",
          "alphanumeric",
          "uuid",
          "api-key",
          "token",
          "password",
        ])
        .optional()
        .default("api-key")
        .describe(
          "Output shape. 'hex' / 'base64' / 'alphanumeric' = raw random string of `length` characters; 'uuid' = RFC4122 v4; 'api-key' / 'token' = random alphanumeric with optional `prefix`; 'password' = mixed-case alphanumeric with symbols. Defaults to 'api-key'.",
        ),
      length: z
        .number()
        .optional()
        .describe(
          "Number of characters (or bytes for hex/base64) to generate. Ignored for 'uuid'. Defaults to a sensible per-format value (e.g. 32 for api-key).",
        ),
      prefix: z
        .string()
        .optional()
        .describe(
          "Literal prefix prepended to the random portion. Only meaningful for 'api-key' and 'token'. Example: 'sk-' or 'svc_'.",
        ),
      saveAs: z
        .string()
        .optional()
        .describe(
          "If provided, store the generated value at this key name in the keyring (one mutation). Omit to just return the value without persisting.",
        ),
      scope: scope.default("global"),
      projectPath,
      teamId,
      orgId,
    },
    async (params) => {
      const toolBlock = enforceToolPolicy("generate_secret", params.projectPath);
      if (toolBlock) return toolBlock;

      const secret = generateSecret({
        format: params.format as NoiseFormat,
        length: params.length,
        prefix: params.prefix,
      });

      if (params.saveAs) {
        setSecret(params.saveAs, secret, {
          ...opts(params),
          description: `Generated ${params.format} secret`,
        });
        const entropy = estimateEntropy(secret);
        return text(
          `Generated and saved as "${params.saveAs}" (${params.format}, ~${entropy} bits entropy)`,
        );
      }

      return text(JSON.stringify({ ok: true, data: { value: secret } }, null, 2));
    },
  );

  server.tool(
    "entangle_secrets",
    [
      "[secrets] Link two keys (across the same or different scopes) so future writes/rotations of either propagate the same value to the other.",
      "Use when one logical credential lives under multiple names (e.g. `STRIPE_SECRET_KEY` global and project) and should never drift; prefer `set_secret` for unrelated values, and reverse the link with `disentangle_secrets` (does not delete values).",
      "Mutates only the metadata of both envelopes — the values themselves are not changed by this call. Idempotent: re-running on an already-entangled pair is a no-op. Subject to tool policy. Returns a short confirmation: 'Entangled: SOURCE <-> TARGET'.",
    ].join(" "),
    {
      sourceKey: z
        .string()
        .describe("First secret key in the pair. Example: 'STRIPE_SECRET_KEY'."),
      targetKey: z
        .string()
        .describe("Second secret key to keep in lockstep with the source."),
      sourceScope: scope.default("global"),
      targetScope: scope.default("global"),
      sourceProjectPath: z
        .string()
        .optional()
        .describe(
          "Project root for sourceKey when sourceScope='project'. Defaults to the server cwd.",
        ),
      targetProjectPath: z
        .string()
        .optional()
        .describe(
          "Project root for targetKey when targetScope='project'. Defaults to the server cwd.",
        ),
    },
    async (params) => {
      const toolBlock = enforceToolPolicy(
        "entangle_secrets",
        params.sourceProjectPath,
      );
      if (toolBlock) return toolBlock;

      // Entangling links two keys so a write to one propagates to the other —
      // i.e. it grants write access to targetKey. Gate BOTH keys with the same
      // key-level policy a direct read/write would face, so an agent can't link
      // a scratch key to a denied one and overwrite it via propagation (A2).
      for (const key of [params.sourceKey, params.targetKey]) {
        const decision = checkKeyReadPolicy(key, undefined, params.sourceProjectPath);
        if (!decision.allowed) {
          return text(
            `Policy Denied: ${decision.reason} (source: ${decision.policySource})`,
            true,
          );
        }
      }

      entangleSecrets(
        params.sourceKey,
        {
          scope: params.sourceScope as Scope,
          projectPath: params.sourceProjectPath ?? process.cwd(),
          source: "mcp",
        },
        params.targetKey,
        {
          scope: params.targetScope as Scope,
          projectPath: params.targetProjectPath ?? process.cwd(),
          source: "mcp",
        },
      );

      return text(`Entangled: ${params.sourceKey} <-> ${params.targetKey}`);
    },
  );

  server.tool(
    "disentangle_secrets",
    [
      "[secrets] Break the sync link between two previously entangled keys so future rotations no longer propagate.",
      "Use when one of the keys is being retired or should diverge intentionally; pair with `delete_secret` if you also want to erase one of the values, and use `entangle_secrets` to recreate the link.",
      "Mutates only metadata; the current values remain untouched. Safe and idempotent — running on a pair that was never linked returns success without effect. Subject to tool policy. Returns 'Disentangled: SOURCE </> TARGET'.",
    ].join(" "),
    {
      sourceKey: z.string().describe("First key in the previously linked pair."),
      targetKey: z.string().describe("Second key in the previously linked pair."),
      sourceScope: scope.default("global"),
      targetScope: scope.default("global"),
      sourceProjectPath: z
        .string()
        .optional()
        .describe("Project root for sourceKey when sourceScope='project'."),
      targetProjectPath: z
        .string()
        .optional()
        .describe("Project root for targetKey when targetScope='project'."),
    },
    async (params) => {
      const toolBlock = enforceToolPolicy(
        "disentangle_secrets",
        params.sourceProjectPath,
      );
      if (toolBlock) return toolBlock;

      disentangleSecrets(
        params.sourceKey,
        {
          scope: params.sourceScope as Scope,
          projectPath: params.sourceProjectPath ?? process.cwd(),
          source: "mcp",
        },
        params.targetKey,
        {
          scope: params.targetScope as Scope,
          projectPath: params.targetProjectPath ?? process.cwd(),
          source: "mcp",
        },
      );

      return text(`Disentangled: ${params.sourceKey} </> ${params.targetKey}`);
    },
  );
}
