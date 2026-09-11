import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { toolAnnotations } from "../tool-annotations.js";
import { z } from "zod";
import { getSecret, setSecret, getEnvelope, listSecrets } from "../../core/keyring.js";
import type { Scope } from "../../core/scope.js";
import {
  validateSecret,
  rotateWithProvider,
  ciValidateBatch,
  registry as providerRegistry,
} from "../../core/validate.js";
import { text, opts, enforceToolPolicy, commonSchemas } from "./_shared.js";

const { teamId, orgId, scope, projectPath } = commonSchemas;

export function registerValidationTools(server: McpServer): void {
  server.tool(
    "validate_secret",
    [
      "[validation] Test whether a stored secret is still accepted by its upstream service (OpenAI, Stripe, GitHub, AWS, generic HTTP, etc.) by making a minimal authenticated request.",
      "Use to confirm liveness before relying on a credential or as the verification step after `rotate_secret`; prefer `ci_validate_secrets` for a batch run across every key in scope.",
      "Side effects: makes one outbound network request per call (may incur tiny provider-side rate-limit cost). Records 'read' for the underlying secret value in the audit log; the value itself is never logged. Returns JSON `{ valid, provider, status?, message?, rateLimit?, ... }` (provider-specific shape).",
    ].join(" "),
    {
      key: z
        .string()
        .describe(
          "The exact key whose value should be tested upstream. Example: 'OPENAI_API_KEY'.",
        ),
      provider: z
        .string()
        .optional()
        .describe(
          "Force a specific provider id. Built-ins include 'openai', 'stripe', 'github', 'aws', 'http'. Omit to auto-detect from the value's prefix or the secret's stored provider hint.",
        ),
      scope,
      projectPath,
      teamId,
      orgId,
    },
    toolAnnotations("validate_secret"),
    async (params) => {
      const toolBlock = enforceToolPolicy("validate_secret", params.projectPath);
      if (toolBlock) return toolBlock;

      const value = getSecret(params.key, opts(params));
      if (value === null) return text(`Secret "${params.key}" not found`, true);

      const envelope = getEnvelope(params.key, opts(params));
      const provHint = params.provider ?? envelope?.envelope.meta.provider;

      const result = await validateSecret(value, { provider: provHint });
      return text(JSON.stringify(result, null, 2));
    },
  );

  server.tool(
    "list_providers",
    [
      "[validation] Enumerate the secret-validation providers q-ring knows how to call (OpenAI, Stripe, GitHub, …) along with their auto-detect prefixes.",
      "Use to discover what `provider` string to pass to `validate_secret`/`rotate_secret`, or to check whether your custom provider is registered.",
      "Read-only. Returns JSON array of `{ name, description, prefixes }` objects. `prefixes` are the literal key-value prefixes (e.g. 'sk-' for OpenAI) used for auto-detection.",
    ].join(" "),
    {},
    toolAnnotations("list_providers"),
    async () => {
      const toolBlock = enforceToolPolicy("list_providers");
      if (toolBlock) return toolBlock;

      const providers = providerRegistry.listProviders().map((p) => ({
        name: p.name,
        description: p.description,
        prefixes: p.prefixes ?? [],
      }));
      return text(JSON.stringify(providers, null, 2));
    },
  );

  server.tool(
    "rotate_secret",
    [
      "[validation] Ask the upstream provider to issue a fresh credential for this secret and store the new value back into the keyring.",
      "Use when a secret is expiring, leaked, or part of a scheduled rotation; prefer `generate_secret` for self-managed values you fully control, and `agent_scan --autoRotate` for sweep-style rotation across multiple expired keys.",
      "Mutates the keyring with the newly-issued value if rotation succeeds (one 'write' audit event), and makes outbound network requests against the provider's rotation API. Returns JSON `{ rotated, newValue?, message?, ... }`. If `rotated` is false, the existing value is left untouched.",
    ].join(" "),
    {
      key: z.string().describe("Exact key to rotate. Must already exist in the keyring."),
      provider: z
        .string()
        .optional()
        .describe(
          "Force a specific provider id (see `list_providers`). Omit to auto-detect from the current value or the secret's stored provider hint.",
        ),
      scope,
      projectPath,
      teamId,
      orgId,
    },
    toolAnnotations("rotate_secret"),
    async (params) => {
      const toolBlock = enforceToolPolicy("rotate_secret", params.projectPath);
      if (toolBlock) return toolBlock;

      const value = getSecret(params.key, opts(params));
      if (!value) return text(`Secret "${params.key}" not found`, true);

      const result = await rotateWithProvider(value, params.provider);
      if (result.rotated && result.newValue) {
        setSecret(params.key, result.newValue, {
          scope: (params.scope as Scope) ?? "global",
          projectPath: params.projectPath,
          source: "mcp",
        });
      }
      return text(JSON.stringify(result, null, 2));
    },
  );

  server.tool(
    "ci_validate_secrets",
    [
      "[validation] Validate every accessible secret in the requested scope against its detected provider in a single batch and return a structured pass/fail report.",
      "Use as a CI gate ('do all our credentials still work before deploy?') or as a pre-rotation health pass; prefer `validate_secret` for a single key.",
      "Side effects: one outbound request per validatable secret (cost scales with N). Reads each secret value (records 'read' audit events). Returns JSON `{ total, valid, invalid, results: [...] }` listing per-key status, provider, and error messages where applicable. Returns 'No secrets to validate' if nothing in scope has a provider mapping.",
    ].join(" "),
    {
      scope,
      projectPath,
      teamId,
      orgId,
    },
    toolAnnotations("ci_validate_secrets"),
    async (params) => {
      const toolBlock = enforceToolPolicy("ci_validate_secrets", params.projectPath);
      if (toolBlock) return toolBlock;

      const entries = listSecrets(opts(params));
      const secrets = entries
        .map((e) => {
          const val = getSecret(e.key, {
            ...opts(params),
            scope: e.scope,
            silent: true,
          });
          if (!val) return null;
          return {
            key: e.key,
            value: val,
            provider: e.envelope?.meta.provider,
            validationUrl: e.envelope?.meta.validationUrl,
          };
        })
        .filter((s): s is NonNullable<typeof s> => s !== null);

      if (secrets.length === 0) return text("No secrets to validate");

      const report = await ciValidateBatch(secrets);
      return text(JSON.stringify(report, null, 2));
    },
  );
}
