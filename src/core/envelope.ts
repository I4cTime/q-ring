/**
 * Quantum Envelope: the storage format for all q-ring secrets.
 *
 * Instead of storing raw strings, every secret is wrapped in an envelope
 * that carries quantum metadata: environment states (superposition),
 * TTL/expiry (decay), entanglement links, and access tracking (observer).
 */

import { z } from "zod";

export type Environment = string; // "dev" | "staging" | "prod" | custom

export interface EntanglementLink {
  /** Service name of the entangled scope */
  service: string;
  /** Key name in the entangled scope */
  key: string;
}

export interface SecretMetadata {
  createdAt: string;
  updatedAt: string;
  /** ISO timestamp when this secret expires (quantum decay) */
  expiresAt?: string;
  /** TTL in seconds from creation/update */
  ttlSeconds?: number;
  /** Human-readable description */
  description?: string;
  /** Tags for organization */
  tags?: string[];
  /** Entanglement links to other secrets */
  entangled?: EntanglementLink[];
  /** Total number of times this secret has been read */
  accessCount: number;
  /** ISO timestamp of last read */
  lastAccessedAt?: string;
  /** Whether this secret is ephemeral (tunneling - not persisted to keyring) */
  ephemeral?: boolean;
  /** Format to use when auto-rotating (e.g. "api-key", "password", "uuid") */
  rotationFormat?: string;
  /** Prefix to use when auto-rotating api-key/token formats */
  rotationPrefix?: string;
  /** Provider name for liveness validation (e.g. "openai", "stripe", "github") */
  provider?: string;
  /** Custom validation URL for generic HTTP provider */
  validationUrl?: string;
  /** Whether reading this secret via MCP requires explicit user approval */
  requiresApproval?: boolean;
  /** Just-In-Time (JIT) provisioning provider name (e.g. "aws-sts") */
  jitProvider?: string;
  /** Expiration timestamp for the cached JIT credential */
  jitExpiresAt?: string;
  /** Honeytoken: the value is fake and any read fires a loud alert */
  canary?: boolean;
  /** Format the canary value imitates (e.g. "aws", "github", "openai") */
  canaryFormat?: string;
}

export interface QuantumEnvelope {
  /** Schema version for forward compatibility */
  v: 1;
  /** Simple value (when not in superposition) */
  value?: string;
  /** Superposition: environment-keyed values */
  states?: Record<Environment, string>;
  /** Default environment to collapse to when no context is available */
  defaultEnv?: Environment;
  /** Quantum metadata */
  meta: SecretMetadata;
}

const EntanglementLinkSchema = z.object({
  service: z.string(),
  key: z.string(),
});

const SecretMetadataSchema = z.object({
  createdAt: z.string(),
  updatedAt: z.string(),
  expiresAt: z.string().optional(),
  ttlSeconds: z.number().optional(),
  description: z.string().optional(),
  tags: z.array(z.string()).optional(),
  entangled: z.array(EntanglementLinkSchema).optional(),
  accessCount: z.number(),
  lastAccessedAt: z.string().optional(),
  ephemeral: z.boolean().optional(),
  rotationFormat: z.string().optional(),
  rotationPrefix: z.string().optional(),
  provider: z.string().optional(),
  validationUrl: z.string().optional(),
  requiresApproval: z.boolean().optional(),
  jitProvider: z.string().optional(),
  jitExpiresAt: z.string().optional(),
  canary: z.boolean().optional(),
  canaryFormat: z.string().optional(),
});

/** Runtime validation for persisted envelopes (forward-compatible unknown meta fields stripped). */
export const QuantumEnvelopeSchema = z.object({
  v: z.literal(1),
  value: z.string().optional(),
  states: z.record(z.string(), z.string()).optional(),
  defaultEnv: z.string().optional(),
  meta: SecretMetadataSchema,
});

export function createEnvelope(
  value: string,
  opts?: Partial<Pick<QuantumEnvelope, "states" | "defaultEnv">> & {
    description?: string;
    tags?: string[];
    ttlSeconds?: number;
    expiresAt?: string;
    entangled?: EntanglementLink[];
    rotationFormat?: string;
    rotationPrefix?: string;
    provider?: string;
    requiresApproval?: boolean;
    jitProvider?: string;
    canary?: boolean;
    canaryFormat?: string;
  },
): QuantumEnvelope {
  const now = new Date().toISOString();

  let expiresAt = opts?.expiresAt;
  if (!expiresAt && opts?.ttlSeconds) {
    expiresAt = new Date(Date.now() + opts.ttlSeconds * 1000).toISOString();
  }

  return {
    v: 1,
    value: opts?.states ? undefined : value,
    states: opts?.states,
    defaultEnv: opts?.defaultEnv,
    meta: {
      createdAt: now,
      updatedAt: now,
      expiresAt,
      ttlSeconds: opts?.ttlSeconds,
      description: opts?.description,
      tags: opts?.tags,
      entangled: opts?.entangled,
      accessCount: 0,
      rotationFormat: opts?.rotationFormat,
      rotationPrefix: opts?.rotationPrefix,
      provider: opts?.provider,
      requiresApproval: opts?.requiresApproval,
      jitProvider: opts?.jitProvider,
      canary: opts?.canary,
      canaryFormat: opts?.canaryFormat,
    },
  };
}

export function parseEnvelope(raw: string): QuantumEnvelope | null {
  try {
    const parsed: unknown = JSON.parse(raw);
    const r = QuantumEnvelopeSchema.safeParse(parsed);
    if (r.success) {
      return r.data as QuantumEnvelope;
    }
  } catch {
    // Not a quantum envelope - legacy raw string
  }
  return null;
}

/**
 * Wrap a legacy raw string value into a quantum envelope.
 * Used for backward compatibility with secrets stored before the envelope format.
 */
export function wrapLegacy(rawValue: string): QuantumEnvelope {
  const now = new Date().toISOString();
  return {
    v: 1,
    value: rawValue,
    meta: {
      createdAt: now,
      updatedAt: now,
      accessCount: 0,
    },
  };
}

export function serializeEnvelope(envelope: QuantumEnvelope): string {
  return JSON.stringify(envelope);
}

/**
 * Resolve the concrete value from a quantum envelope.
 * If in superposition, collapses based on the provided environment.
 */
export function collapseValue(
  envelope: QuantumEnvelope,
  env?: Environment,
): string | null {
  if (envelope.states) {
    const targetEnv = env ?? envelope.defaultEnv;
    if (targetEnv && envelope.states[targetEnv]) {
      return envelope.states[targetEnv];
    }
    // If no env match, try default, then return null
    if (envelope.defaultEnv && envelope.states[envelope.defaultEnv]) {
      return envelope.states[envelope.defaultEnv];
    }
    // Last resort: return the first state
    const keys = Object.keys(envelope.states);
    if (keys.length > 0) {
      return envelope.states[keys[0]];
    }
    return null;
  }

  return envelope.value ?? null;
}

export interface DecayStatus {
  isExpired: boolean;
  isStale: boolean;
  /** Percentage of lifetime elapsed (0-100+) */
  lifetimePercent: number;
  /** Seconds remaining until expiry, or negative if expired */
  secondsRemaining: number | null;
  /** Human-readable time remaining */
  timeRemaining: string | null;
}

export function checkDecay(envelope: QuantumEnvelope): DecayStatus {
  if (!envelope.meta.expiresAt) {
    return {
      isExpired: false,
      isStale: false,
      lifetimePercent: 0,
      secondsRemaining: null,
      timeRemaining: null,
    };
  }

  const now = Date.now();
  const expires = new Date(envelope.meta.expiresAt).getTime();
  const created = new Date(envelope.meta.createdAt).getTime();

  if (!Number.isFinite(expires) || !Number.isFinite(created)) {
    return {
      isExpired: true,
      isStale: true,
      lifetimePercent: 100,
      secondsRemaining: null,
      timeRemaining: "invalid date",
    };
  }

  const totalLifetime = expires - created;
  const elapsed = now - created;
  const remaining = expires - now;

  const lifetimePercent =
    totalLifetime > 0 ? Math.round((elapsed / totalLifetime) * 100) : 100;

  const secondsRemaining = Math.floor(remaining / 1000);

  let timeRemaining = "expired";
  if (remaining > 0) {
    const days = Math.floor(remaining / 86400000);
    const hours = Math.floor((remaining % 86400000) / 3600000);
    const minutes = Math.floor((remaining % 3600000) / 60000);

    if (days > 0) timeRemaining = `${days}d ${hours}h`;
    else if (hours > 0) timeRemaining = `${hours}h ${minutes}m`;
    else timeRemaining = `${minutes}m`;
  }

  return {
    isExpired: remaining <= 0,
    isStale: lifetimePercent >= 75,
    lifetimePercent,
    secondsRemaining,
    timeRemaining,
  };
}

/**
 * Record an access event on the envelope (observer effect).
 * Returns a new envelope with updated access metadata.
 */
export function recordAccess(envelope: QuantumEnvelope): QuantumEnvelope {
  return {
    ...envelope,
    meta: {
      ...envelope.meta,
      accessCount: envelope.meta.accessCount + 1,
      lastAccessedAt: new Date().toISOString(),
    },
  };
}
