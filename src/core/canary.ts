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

import { randomInt } from "node:crypto";
import { generateSecret } from "./noise.js";
import {
  setSecret,
  listSecrets,
  getEnvelope,
  disarmCanary as clearCanaryFlag,
  type KeyringOptions,
} from "./keyring.js";
import type { Scope } from "./scope.js";
import { isPlaceholderValue } from "./secrets-detect.js";

export interface CanaryFormat {
  /** Provider name shown in `canary list` */
  name: string;
  description: string;
  generate(): string;
}

const ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const UPPER_NUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const BASE64 = ALNUM + "+/";
const URLSAFE = ALNUM + "_-";
const DIGITS = "0123456789";

function pick(charset: string, length: number): string {
  let out = "";
  for (let i = 0; i < length; i++) out += charset[randomInt(charset.length)];
  return out;
}

/**
 * CSPRNG noise occasionally spells a placeholder marker ("xxx" turns up in a
 * 74-char body roughly once every few hundred draws), and `scan` would then
 * report the planted canary as a placeholder instead of a secret. Regenerate
 * until the value reads as a real token to the same heuristic scan uses.
 */
function dodgingPlaceholders(generate: () => string): () => string {
  return () => {
    for (let attempt = 0; attempt < 32; attempt++) {
      const value = generate();
      if (!isPlaceholderValue(value)) return value;
    }
    throw new Error("canary generator kept producing placeholder-like values");
  };
}

/**
 * Token shapes per provider. Prefixes match the liveness-provider registry in
 * validate.ts so a canary auto-detects like the real thing; body length and
 * charset track each issuer's current format closely enough to pass shape
 * checks and secret-scanner heuristics (the AWS body satisfies validate.ts's
 * /^(AKIA|ASIA)[A-Z0-9]{16}$/). Every value is CSPRNG noise — never valid.
 */
export const CANARY_FORMATS: Record<string, CanaryFormat> = {
  aws: {
    name: "aws",
    description: "AWS access key id (AKIA…)",
    generate: dodgingPlaceholders(() => `AKIA${pick(UPPER_NUM, 16)}`),
  },
  "aws-secret": {
    name: "aws-secret",
    description: "AWS secret access key (40-char base64)",
    generate: dodgingPlaceholders(() => pick(BASE64, 40)),
  },
  github: {
    name: "github",
    description: "GitHub classic personal access token (ghp_…)",
    generate: dodgingPlaceholders(() => `ghp_${pick(ALNUM, 36)}`),
  },
  "github-pat": {
    name: "github-pat",
    description: "GitHub fine-grained personal access token (github_pat_…)",
    generate: dodgingPlaceholders(() => `github_pat_${pick(ALNUM, 22)}_${pick(ALNUM, 59)}`),
  },
  openai: {
    name: "openai",
    description: "OpenAI API key (sk-…)",
    generate: dodgingPlaceholders(() => `sk-${pick(ALNUM, 48)}`),
  },
  "openai-project": {
    name: "openai-project",
    description: "OpenAI project API key (sk-proj-…)",
    generate: dodgingPlaceholders(() => `sk-proj-${pick(URLSAFE, 74)}T3BlbkFJ${pick(URLSAFE, 74)}`),
  },
  anthropic: {
    name: "anthropic",
    description: "Anthropic API key (sk-ant-api03-…)",
    generate: dodgingPlaceholders(() => `sk-ant-api03-${pick(URLSAFE, 91)}AA`),
  },
  stripe: {
    name: "stripe",
    description: "Stripe live secret key (sk_live_…)",
    generate: dodgingPlaceholders(() => `sk_live_${pick(ALNUM, 24)}`),
  },
  gitlab: {
    name: "gitlab",
    description: "GitLab personal access token (glpat-…)",
    generate: dodgingPlaceholders(() => `glpat-${pick(URLSAFE, 20)}`),
  },
  slack: {
    name: "slack",
    description: "Slack bot token (xoxb-…)",
    generate: dodgingPlaceholders(() => `xoxb-${pick(DIGITS, 12)}-${pick(DIGITS, 13)}-${pick(ALNUM, 24)}`),
  },
  google: {
    name: "google",
    description: "Google API key (AIza…)",
    generate: dodgingPlaceholders(() => `AIza${pick(URLSAFE, 35)}`),
  },
  npm: {
    name: "npm",
    description: "npm access token (npm_…)",
    generate: dodgingPlaceholders(() => `npm_${pick(ALNUM, 36)}`),
  },
  generic: {
    name: "generic",
    description: "Generic high-entropy API key",
    generate: dodgingPlaceholders(() => generateSecret({ format: "api-key", prefix: "qk_", length: 40 })),
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
