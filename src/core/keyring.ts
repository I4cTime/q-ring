import { withFileLock } from "../utils/file-lock.js";
import { Entry, findCredentials } from "./backend.js";
import {
  resolveScope,
  serviceForScope,
  globalService,
  projectService,
  teamService,
  orgService,
  type Scope,
} from "./scope.js";
import {
  type QuantumEnvelope,
  type Environment,
  createEnvelope,
  parseEnvelope,
  wrapLegacy,
  serializeEnvelope,
  collapseValue,
  checkDecay,
  recordAccess,
  type DecayStatus,
} from "./envelope.js";
import { collapseEnvironment } from "./collapse.js";
import { logAudit } from "./observer.js";
import { findEntangled, entangle as entangleLink, disentangle as disentangleLink } from "./entanglement.js";
import { fireHooks } from "./hooks.js";
import { hasApproval } from "./approval.js";
import { notifyApprovalRequested } from "./notify.js";
import { recordCanaryTrip } from "./canary-alert.js";
import { registry as jitRegistry } from "./provision.js";
import { checkKeyReadPolicy, checkSecretLifecyclePolicy, getPolicyRoot } from "./policy.js";

function withJitEnvelopeLock<T>(service: string, key: string, fn: () => T): T {
  return withFileLock(`${service}\0${key}`, fn, { dir: "jit-locks" });
}

export interface SecretEntry {
  key: string;
  scope: Scope;
  value?: string;
  envelope?: QuantumEnvelope;
  decay?: DecayStatus;
}

export interface KeyringOptions {
  scope?: Scope;
  projectPath?: string;
  /** Team identifier for team-scoped secrets */
  teamId?: string;
  /** Org identifier for org-scoped secrets */
  orgId?: string;
  /** Environment for superposition collapse */
  env?: Environment;
  /** Audit source */
  source?: "cli" | "mcp" | "agent" | "api" | "hook" | "ci";
  /** Skip audit logging (for internal polling like the dashboard) */
  silent?: boolean;
}

export interface SetSecretOptions extends KeyringOptions {
  /** Environment states for superposition */
  states?: Record<Environment, string>;
  /** Default environment */
  defaultEnv?: Environment;
  /** TTL in seconds (quantum decay) */
  ttlSeconds?: number;
  /** Expiry timestamp */
  expiresAt?: string;
  /** Description */
  description?: string;
  /** Tags */
  tags?: string[];
  /** Format for auto-rotation (e.g. "api-key", "password", "uuid") */
  rotationFormat?: string;
  /** Prefix for auto-rotation (e.g. "sk-") */
  rotationPrefix?: string;
  /** Provider for liveness validation (e.g. "openai", "stripe") */
  provider?: string;
  /** Whether reading this secret via MCP requires explicit user approval */
  requiresApproval?: boolean;
  /** Just-In-Time (JIT) provisioning provider name (e.g. "aws-sts") */
  jitProvider?: string;
  /** Honeytoken: any read fires a loud canary alert */
  canary?: boolean;
  /** Provider token shape the canary value imitates */
  canaryFormat?: string;
}

function readEnvelope(service: string, key: string): QuantumEnvelope | null {
  const entry = new Entry(service, key);
  const raw = entry.getPassword();
  if (raw === null) return null;

  const envelope = parseEnvelope(raw);
  return envelope ?? wrapLegacy(raw);
}

function writeEnvelope(
  service: string,
  key: string,
  envelope: QuantumEnvelope,
): void {
  const entry = new Entry(service, key);
  entry.setPassword(serializeEnvelope(envelope));
}

function resolveEnv(opts: KeyringOptions): Environment | undefined {
  if (opts.env) return opts.env;
  const result = collapseEnvironment({ projectPath: opts.projectPath });
  return result?.env;
}

function resolveTemplates(value: string, opts: KeyringOptions & { _seen?: Set<string> }, seen: Set<string>): string {
  if (!value.includes("{{") || !value.includes("}}")) return value;
  
  return value.replace(/\{\{([^}]+)\}\}/g, (_match, refKeyRaw) => {
    const refKey = refKeyRaw.trim();
    const refValue = getSecret(refKey, { ...opts, _seen: seen });
    if (refValue === null) {
      throw new Error(`Template resolution failed: referenced secret "${refKey}" not found`);
    }
    return refValue;
  });
}

export function resolveTemplatesOffline(value: string, rawValues: Map<string, string>, seen: Set<string>): string {
  if (!value.includes("{{") || !value.includes("}}")) return value;
  
  return value.replace(/\{\{([^}]+)\}\}/g, (_match, refKeyRaw) => {
    const refKey = refKeyRaw.trim();
    if (seen.has(refKey)) {
      throw new Error(`Circular dependency detected: ${[...seen].join(" -> ")} -> ${refKey}`);
    }
    const rawRef = rawValues.get(refKey);
    if (rawRef === undefined) {
      throw new Error(`Template resolution failed: referenced secret "${refKey}" not found`);
    }
    const nextSeen = new Set(seen);
    nextSeen.add(refKey);
    return resolveTemplatesOffline(rawRef, rawValues, nextSeen);
  });
}

/**
 * Retrieve a secret by key, with scope resolution and superposition collapse.
 * Records the access in the audit log (observer effect).
 */
export function getSecret(
  key: string,
  opts: KeyringOptions & { _seen?: Set<string> } = {},
): string | null {
  const scopes = resolveScope(opts);
  const env = resolveEnv(opts);
  const source = opts.source ?? "cli";
  const seen = opts._seen ?? new Set<string>();

  if (source === "mcp") {
    const policyDecision = checkKeyReadPolicy(key, undefined, opts.projectPath);
    if (!policyDecision.allowed) {
      throw new Error(`Policy Denied: ${policyDecision.reason}`);
    }
  }

  if (seen.has(key)) {
    throw new Error(`Circular dependency detected: ${[...seen].join(" -> ")} -> ${key}`);
  }
  const nextSeen = new Set(seen);
  nextSeen.add(key);

  for (const { service, scope } of scopes) {
    const envelope = readEnvelope(service, key);
    if (!envelope) continue;

    // Check decay
    const decay = checkDecay(envelope);
    if (decay.isExpired) {
      if (!opts.silent) {
        logAudit({
          action: "read",
          key,
          scope,
          source,
          detail: "blocked: secret expired (quantum decay)",
        });
      }
      continue;
    }

    // Check approvals for MCP
    if (envelope.meta.requiresApproval && source === "mcp") {
      if (!hasApproval(key, scope, service)) {
        if (!opts.silent) {
          logAudit({
            action: "read",
            key,
            scope,
            source,
            detail: "blocked: requires user approval",
          });
          notifyApprovalRequested(key, source);
        }
        throw new Error(`Access Denied: This secret requires user approval. Please ask the user to run 'qring approve ${key}'`);
      }
    }

    // Collapse superposition
    let value = collapseValue(envelope, env);
    if (value === null) continue;

    // Just-In-Time Provisioning
    if (envelope.meta.jitProvider) {
      const provider = jitRegistry.get(envelope.meta.jitProvider);
      if (provider) {
        let isExpired = true;
        if (envelope.states && envelope.states["jit"] && envelope.meta.jitExpiresAt) {
          isExpired = new Date(envelope.meta.jitExpiresAt).getTime() <= Date.now();
        }

        if (isExpired) {
          const jitConfigSource = value;
          withJitEnvelopeLock(service, key, () => {
            const latest = readEnvelope(service, key);
            if (!latest?.meta.jitProvider) return;
            let innerExpired = true;
            if (
              latest.states &&
              latest.states["jit"] &&
              latest.meta.jitExpiresAt
            ) {
              innerExpired =
                new Date(latest.meta.jitExpiresAt).getTime() <= Date.now();
            }
            if (!innerExpired) {
              envelope.states = latest.states;
              envelope.meta.jitExpiresAt = latest.meta.jitExpiresAt;
              return;
            }
            const result = provider.provision(jitConfigSource);
            latest.states = latest.states ?? {};
            latest.states["jit"] = result.value;
            latest.meta.jitExpiresAt = result.expiresAt;
            writeEnvelope(service, key, latest);
            envelope.states = latest.states;
            envelope.meta.jitExpiresAt = latest.meta.jitExpiresAt;
          });
        }
        value = envelope.states!["jit"];
      }
    }

    // Resolve templates
    value = resolveTemplates(value, { ...opts, _seen: nextSeen }, nextSeen);

    // Observer effect: record access and persist. Re-read the current envelope
    // first so a value written concurrently between our read above and this
    // write-back is preserved — the access counter is deliberately
    // last-write-wins, but the secret value must never be clobbered (B4).
    if (!opts.silent) {
      const latest = readEnvelope(service, key) ?? envelope;
      writeEnvelope(service, key, recordAccess(latest));
      logAudit({ action: "read", key, scope, env, source });
      // Honeytoken trip: still return the (fake) value so the reader has no
      // tell — the alarm is the side effect, not a denial. Silent reads
      // (dashboard polling) deliberately don't trip.
      if (envelope.meta.canary) {
        recordCanaryTrip({ key, scope, env, source });
      }
    }

    return value;
  }

  return null;
}

/**
 * Get the full envelope for a secret (for inspection, no value extraction).
 */
export function getEnvelope(
  key: string,
  opts: KeyringOptions = {},
): { envelope: QuantumEnvelope; scope: Scope } | null {
  const source = opts.source ?? "cli";

  if (source === "mcp") {
    const policyDecision = checkKeyReadPolicy(key, undefined, opts.projectPath);
    if (!policyDecision.allowed) {
      throw new Error(`Policy Denied: ${policyDecision.reason}`);
    }
  }

  const scopes = resolveScope(opts);

  for (const { service, scope } of scopes) {
    const envelope = readEnvelope(service, key);
    if (envelope) return { envelope, scope };
  }

  return null;
}

/**
 * Store a secret with quantum metadata.
 */
export function setSecret(
  key: string,
  value: string,
  opts: SetSecretOptions = {},
): void {
  const scope = opts.scope ?? "global";
  const scopes = resolveScope({ ...opts, scope });
  const { service } = scopes[0];
  const source = opts.source ?? "cli";

  // Check if there's an existing envelope to preserve metadata
  const existing = readEnvelope(service, key);

  let envelope: QuantumEnvelope;

  const rotFmt = opts.rotationFormat ?? existing?.meta.rotationFormat;
  const rotPfx = opts.rotationPrefix ?? existing?.meta.rotationPrefix;
  const prov = opts.provider ?? existing?.meta.provider;
  const reqApp = opts.requiresApproval ?? existing?.meta.requiresApproval;
  const jitProv = opts.jitProvider ?? existing?.meta.jitProvider;
  const canaryFlag = opts.canary ?? existing?.meta.canary;
  const canaryFmt = opts.canaryFormat ?? existing?.meta.canaryFormat;

  const mergedTags = opts.tags ?? existing?.meta.tags;
  const ttlForPolicy = opts.ttlSeconds ?? existing?.meta.ttlSeconds;
  const life = checkSecretLifecyclePolicy(
    {
      tags: mergedTags,
      ttlSeconds: ttlForPolicy,
      rotationFormat: rotFmt,
      requiresApproval: !!reqApp,
    },
    opts.projectPath,
  );
  if (!life.allowed) {
    throw new Error(life.reason ?? "Secret lifecycle policy denied");
  }

  if (opts.states) {
    envelope = createEnvelope("", {
      states: opts.states,
      defaultEnv: opts.defaultEnv,
      description: opts.description,
      tags: opts.tags,
      ttlSeconds: opts.ttlSeconds,
      expiresAt: opts.expiresAt,
      entangled: existing?.meta.entangled,
      rotationFormat: rotFmt,
      rotationPrefix: rotPfx,
      provider: prov,
      requiresApproval: reqApp,
      jitProvider: jitProv,
      canary: canaryFlag,
      canaryFormat: canaryFmt,
    });
  } else {
    envelope = createEnvelope(value, {
      description: opts.description,
      tags: opts.tags,
      ttlSeconds: opts.ttlSeconds,
      expiresAt: opts.expiresAt,
      entangled: existing?.meta.entangled,
      rotationFormat: rotFmt,
      rotationPrefix: rotPfx,
      provider: prov,
      requiresApproval: reqApp,
      jitProvider: jitProv,
      canary: canaryFlag,
      canaryFormat: canaryFmt,
    });
  }

  // Preserve access count from existing
  if (existing) {
    envelope.meta.createdAt = existing.meta.createdAt;
    envelope.meta.accessCount = existing.meta.accessCount;
  }

  writeEnvelope(service, key, envelope);
  logAudit({ action: "write", key, scope, source });

  // Propagate to entangled secrets
  const entangled = findEntangled({ service, key });
  for (const target of entangled) {
    try {
      // An MCP-sourced write must not silently propagate into a key the
      // caller's policy forbids — otherwise entanglement is a write primitive
      // that bypasses deniedKeys/deniedTags (A2). CLI writes are unrestricted
      // by design (the local operator already has full access).
      if (source === "mcp") {
        const decision = checkKeyReadPolicy(target.key, undefined, opts.projectPath);
        if (!decision.allowed) {
          logAudit({
            action: "entangle",
            key: target.key,
            scope: "global",
            source,
            detail: `blocked propagation from ${key}: ${decision.reason}`,
          });
          continue;
        }
      }
      const targetEnvelope = readEnvelope(target.service, target.key);
      if (targetEnvelope) {
        if (opts.states) {
          targetEnvelope.states = opts.states;
        } else {
          targetEnvelope.value = value;
        }
        targetEnvelope.meta.updatedAt = new Date().toISOString();
        writeEnvelope(target.service, target.key, targetEnvelope);
        logAudit({
          action: "entangle",
          key: target.key,
          scope: "global",
          source,
          detail: `propagated from ${key}`,
        });
      }
    } catch {
      // entangled target may not exist
    }
  }

  fireHooks({
    action: "write",
    key,
    scope,
    timestamp: new Date().toISOString(),
    source,
  }, envelope.meta.tags).catch(() => {});
}

/**
 * Delete a secret from the specified scope (or both if unscoped).
 */
export function deleteSecret(
  key: string,
  opts: KeyringOptions = {},
): boolean {
  const scopes = resolveScope(opts);
  const source = opts.source ?? "cli";

  if (source === "mcp") {
    const policyDecision = checkKeyReadPolicy(key, undefined, opts.projectPath);
    if (!policyDecision.allowed) {
      throw new Error(`Policy Denied: ${policyDecision.reason}`);
    }
  }

  let deleted = false;

  for (const { service, scope } of scopes) {
    const entry = new Entry(service, key);
    try {
      if (entry.deleteCredential()) {
        deleted = true;
        logAudit({ action: "delete", key, scope, source });
        fireHooks({
          action: "delete",
          key,
          scope,
          timestamp: new Date().toISOString(),
          source,
        }).catch(() => {});
      }
    } catch {
      // not found
    }
  }

  return deleted;
}

/**
 * Check whether a secret exists in any applicable scope.
 */
export function hasSecret(
  key: string,
  opts: KeyringOptions = {},
): boolean {
  const source = opts.source ?? "cli";

  if (source === "mcp") {
    const policyDecision = checkKeyReadPolicy(key, undefined, opts.projectPath);
    if (!policyDecision.allowed) return false;
  }

  const scopes = resolveScope(opts);

  for (const { service } of scopes) {
    const envelope = readEnvelope(service, key);
    if (envelope) {
      const decay = checkDecay(envelope);
      if (!decay.isExpired) return true;
    }
  }

  return false;
}

/**
 * List all secrets across applicable scopes with quantum metadata.
 */
export function listSecrets(opts: KeyringOptions = {}): SecretEntry[] {
  const source = opts.source ?? "cli";
  const services: { service: string; scope: Scope }[] = [];

  if (!opts.scope || opts.scope === "global") {
    services.push({ service: globalService(), scope: "global" });
  }

  if ((!opts.scope || opts.scope === "project") && opts.projectPath) {
    services.push({
      service: projectService(opts.projectPath),
      scope: "project",
    });
  }

  if ((!opts.scope || opts.scope === "team") && opts.teamId) {
    services.push({ service: teamService(opts.teamId), scope: "team" });
  }

  if ((!opts.scope || opts.scope === "org") && opts.orgId) {
    services.push({ service: orgService(opts.orgId), scope: "org" });
  }

  const results: SecretEntry[] = [];
  const seen = new Set<string>();

  for (const { service, scope } of services) {
    try {
      const credentials = findCredentials(service);
      for (const cred of credentials) {
        const id = `${scope}:${cred.account}`;
        if (seen.has(id)) continue;
        seen.add(id);

        const envelope = parseEnvelope(cred.password) ?? wrapLegacy(cred.password);
        const decay = checkDecay(envelope);

        results.push({
          key: cred.account,
          scope,
          envelope,
          decay,
        });
      }
    } catch {
      // keyring unavailable
    }
  }

  if (!opts.silent) {
    logAudit({ action: "list", source });
  }

  const sorted = results.sort((a, b) => a.key.localeCompare(b.key));

  if (source === "mcp") {
    return sorted.filter((e) => {
      const decision = checkKeyReadPolicy(e.key, undefined, opts.projectPath);
      return decision.allowed;
    });
  }

  return sorted;
}

/**
 * Export all secrets with their values (for .env or JSON export).
 * Collapses superposition based on detected environment.
 */
export function exportSecrets(
  opts: KeyringOptions & { format?: "env" | "json"; keys?: string[]; tags?: string[] } = {},
): string {
  const format = opts.format ?? "env";
  const env = resolveEnv(opts);
  let entries = listSecrets(opts);
  const source = opts.source ?? "cli";

  if (opts.keys?.length) {
    const keySet = new Set(opts.keys);
    entries = entries.filter((e) => keySet.has(e.key));
  }

  if (opts.tags?.length) {
    entries = entries.filter((e) =>
      opts.tags!.some((t) => e.envelope?.meta.tags?.includes(t)),
    );
  }

  const rawValues = new Map<string, string>();

  // Process in precedence order: global < org < team < project
  const globalEntries = entries.filter((e) => e.scope === "global");
  const orgEntries = entries.filter((e) => e.scope === "org");
  const teamEntries = entries.filter((e) => e.scope === "team");
  const projectEntries = entries.filter((e) => e.scope === "project");

  for (const entry of [...globalEntries, ...orgEntries, ...teamEntries, ...projectEntries]) {
    if (entry.envelope) {
      const decay = checkDecay(entry.envelope);
      if (decay.isExpired) continue;

      // Honor the approval gate on bulk reads too — otherwise export_secrets
      // would surface approval-protected values to an MCP agent that getSecret
      // would have denied. Silently skip (consistent with policy filtering).
      if (
        source === "mcp" &&
        entry.envelope.meta.requiresApproval &&
        !hasApproval(entry.key, entry.scope, serviceForScope(entry.scope, opts))
      ) {
        logAudit({
          action: "read",
          key: entry.key,
          scope: entry.scope,
          source,
          detail: "blocked: requires user approval (export)",
        });
        continue;
      }

      const value = collapseValue(entry.envelope, env);
      if (value !== null) {
        rawValues.set(entry.key, value);
      }
    }
  }

  const merged = new Map<string, string>();
  for (const [key, value] of rawValues) {
    try {
      const resolved = resolveTemplatesOffline(value, rawValues, new Set([key]));
      merged.set(key, resolved);
    } catch (err) {
      // In export, if a template fails, we just don't export it
      console.warn(`Warning: skipped exporting ${key} due to template error: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  logAudit({ action: "export", source, detail: `format=${format}` });

  if (format === "json") {
    const obj: Record<string, string> = {};
    for (const [key, value] of merged) {
      obj[key] = value;
    }
    return JSON.stringify(obj, null, 2);
  }

  const lines: string[] = [];
  for (const [key, value] of merged) {
    const escaped = value
      .replace(/\\/g, "\\\\")
      .replace(/"/g, '\\"')
      .replace(/\n/g, "\\n");
    lines.push(`${key}="${escaped}"`);
  }
  return lines.join("\n");
}

/**
 * Create an entanglement between two secrets.
 */
export function entangleSecrets(
  sourceKey: string,
  sourceOpts: KeyringOptions,
  targetKey: string,
  targetOpts: KeyringOptions,
): void {
  const sourceScopes = resolveScope({ ...sourceOpts, scope: sourceOpts.scope ?? "global" });
  const targetScopes = resolveScope({ ...targetOpts, scope: targetOpts.scope ?? "global" });

  const source = { service: sourceScopes[0].service, key: sourceKey };
  const target = { service: targetScopes[0].service, key: targetKey };

  entangleLink(source, target, {
    source: sourceOpts.source ?? "cli",
    policyRoot: getPolicyRoot(),
  });
  logAudit({
    action: "entangle",
    key: sourceKey,
    source: sourceOpts.source ?? "cli",
    detail: `entangled with ${targetKey}`,
  });
}

/**
 * Remove an entanglement between two secrets.
 */
export function disentangleSecrets(
  sourceKey: string,
  sourceOpts: KeyringOptions,
  targetKey: string,
  targetOpts: KeyringOptions,
): void {
  const sourceScopes = resolveScope({ ...sourceOpts, scope: sourceOpts.scope ?? "global" });
  const targetScopes = resolveScope({ ...targetOpts, scope: targetOpts.scope ?? "global" });

  const source = { service: sourceScopes[0].service, key: sourceKey };
  const target = { service: targetScopes[0].service, key: targetKey };

  disentangleLink(source, target);
  logAudit({
    action: "entangle",
    key: sourceKey,
    source: sourceOpts.source ?? "cli",
    detail: `disentangled from ${targetKey}`,
  });
}
