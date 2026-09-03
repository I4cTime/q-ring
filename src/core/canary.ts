/**
 * Canary honeytokens.
 *
 * A canary is a fake credential planted in the ring. It stores and reads like
 * any other secret — that is the point: an agent, a compromised MCP server, or
 * exfiltrated tooling that sweeps the ring cannot tell it apart. The moment
 * anything reads it, the trip hook in keyring.ts fires a "canary" audit event
 * and a loud desktop alert (see canary-alert.ts).
 *
 * Values imitate real provider token shapes so they survive casual inspection
 * and secret-scanners' entropy heuristics. They are pure CSPRNG noise — never
 * valid credentials.
 */

import { generateSecret } from "./noise.js";
import {
  setSecret,
  listSecrets,
  getEnvelope,
  disarmCanary as clearCanaryFlag,
  type KeyringOptions,
} from "./keyring.js";
import type { Scope } from "./scope.js";

export interface CanaryFormat {
  /** Provider name shown in `canary list` */
  name: string;
  description: string;
  generate(): string;
}

const ALPHA_UPPER_NUM = () =>
  generateSecret({ format: "alphanumeric", length: 16 }).toUpperCase();

/**
 * Token shapes per provider. Prefixes match the liveness-provider registry in
 * validate.ts; body length/charset approximates the real issuer closely
 * enough to pass shape checks (the AWS body satisfies validate.ts's
 * /^(AKIA|ASIA)[A-Z0-9]{16}$/).
 */
export const CANARY_FORMATS: Record<string, CanaryFormat> = {
  aws: {
    name: "aws",
    description: "AWS access key id (AKIA…)",
    generate: () => `AKIA${ALPHA_UPPER_NUM()}`,
  },
  github: {
    name: "github",
    description: "GitHub personal access token (ghp_…)",
    generate: () => generateSecret({ format: "api-key", prefix: "ghp_", length: 36 }),
  },
  openai: {
    name: "openai",
    description: "OpenAI API key (sk-…)",
    generate: () => generateSecret({ format: "api-key", prefix: "sk-", length: 48 }),
  },
  anthropic: {
    name: "anthropic",
    description: "Anthropic API key (sk-ant-…)",
    generate: () => generateSecret({ format: "api-key", prefix: "sk-ant-api03-", length: 80 }),
  },
  stripe: {
    name: "stripe",
    description: "Stripe live secret key (sk_live_…)",
    generate: () => generateSecret({ format: "api-key", prefix: "sk_live_", length: 24 }),
  },
  generic: {
    name: "generic",
    description: "Generic high-entropy API key",
    generate: () => generateSecret({ format: "api-key", prefix: "qk_", length: 40 }),
  },
};

export const DEFAULT_CANARY_FORMAT = "generic";

export interface PlantResult {
  key: string;
  value: string;
  format: string;
  scope: Scope;
}

export interface PlantOptions extends KeyringOptions {
  /** Which provider's token shape to imitate (default "generic") */
  format?: string;
  /** Use this exact value instead of generating one */
  value?: string;
  /**
   * Optional cover description. Deliberately NOT auto-filled: a description
   * like "Canary honeytoken" is readable via inspect_secret and would let an
   * attacker enumerate the tripwires without touching them. No description
   * (or an operator-chosen innocuous one) leaves no tell.
   */
  description?: string;
  /** Allow replacing an existing NON-canary secret at this key */
  force?: boolean;
}

/**
 * Plant a canary honeytoken under `key`. Refuses to overwrite an existing
 * real (non-canary) secret in the target scope unless `force` is set — the
 * guard lives here, not in the CLI, so no programmatic caller can clobber a
 * real credential by accident. Replanting over an existing canary is always
 * allowed.
 */
export function plantCanary(key: string, opts: PlantOptions = {}): PlantResult {
  const formatName = opts.format ?? DEFAULT_CANARY_FORMAT;
  const format = CANARY_FORMATS[formatName];
  if (!format) {
    throw new Error(
      `Unknown canary format "${formatName}". Available: ${Object.keys(CANARY_FORMATS).join(", ")}`,
    );
  }

  const value = opts.value ?? format.generate();
  const scope = opts.scope ?? "global";

  // Check the exact scope this plant will write to (not the whole resolution
  // chain — a project-scope real secret must not block a global plant).
  const existing = getEnvelope(key, { ...opts, scope });
  if (existing && !existing.envelope.meta.canary && !opts.force) {
    throw new Error(
      `"${key}" already holds a real secret in ${scope} scope. Use --force to replace it with a canary.`,
    );
  }
  setSecret(key, value, {
    ...opts,
    scope,
    canary: true,
    canaryFormat: formatName,
    description: opts.description,
  });

  return { key, value, format: formatName, scope };
}

export interface CanaryStatus {
  key: string;
  scope: Scope;
  format?: string;
  plantedAt: string;
  /** Reads recorded on the envelope — every one of these was an alert */
  tripCount: number;
  lastTrippedAt?: string;
}

/**
 * Disarm a canary: clears the flag so reads stop alarming. The stored value
 * stays fake until overwritten. Returns false if the key exists but is not
 * a canary; throws if the key doesn't exist at all.
 */
export function disarmCanary(key: string, opts: KeyringOptions = {}): boolean {
  const found = getEnvelope(key, opts);
  if (!found) {
    throw new Error(`"${key}" not found in any applicable scope`);
  }
  return clearCanaryFlag(key, { ...opts, scope: found.scope });
}

/** List all planted canaries across resolvable scopes, with trip stats. */
export function listCanaries(opts: KeyringOptions = {}): CanaryStatus[] {
  const out: CanaryStatus[] = [];
  for (const entry of listSecrets({ ...opts, silent: true })) {
    const meta = entry.envelope?.meta;
    if (!meta?.canary) continue;
    out.push({
      key: entry.key,
      scope: entry.scope,
      format: meta.canaryFormat,
      plantedAt: meta.createdAt,
      tripCount: meta.accessCount,
      lastTrippedAt: meta.lastAccessedAt,
    });
  }
  return out;
}
