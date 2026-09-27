/**
 * Environment promotion (0.18 "garrison"): move a secret's value from one
 * superposition state to another, and diff two environments — without ever
 * printing a value.
 *
 * `qring set KEY --env dev` writes states one at a time; promotion is the
 * "now make prod match staging" step that used to mean copy-paste. Both
 * operations go through the normal keyring API so scope resolution, policy
 * checks, audit and hooks all apply.
 */
import { getEnvelope, listSecrets, setSecret, type KeyringOptions } from "./keyring.js";
import type { Environment } from "./envelope.js";
import type { Scope } from "./scope.js";

export interface PromoteOptions extends KeyringOptions {
  from: Environment;
  to: Environment;
  /** Overwrite a differing value in `to` without asking. */
  force?: boolean;
}

export type PromotePrevious = "absent" | "same" | "different";

export interface PromoteResult {
  key: string;
  scope: Scope;
  from: Environment;
  to: Environment;
  /** What `to` held before: nothing, the same value, or a different one. */
  previous: PromotePrevious;
  /** False when `to` already matched (no write, no audit event). */
  changed: boolean;
}

export class PromoteConflictError extends Error {
  readonly code = "ERR_PROMOTE_CONFLICT";
  constructor(key: string, to: Environment) {
    super(
      `"${key}" already has a different value for env "${to}" — pass force to overwrite it`,
    );
  }
}

function assertEnvName(env: string, label: string): void {
  if (!/^[A-Za-z0-9_.-]{1,64}$/.test(env)) {
    throw new Error(`${label} environment name "${env}" is invalid (letters, digits, _ . - only)`);
  }
}

/**
 * Copy the `from` state of `key` into its `to` state. A secret with a single
 * (collapsed) value has no states to promote from.
 */
export function promoteSecret(key: string, opts: PromoteOptions): PromoteResult {
  assertEnvName(opts.from, "source");
  assertEnvName(opts.to, "target");
  if (opts.from === opts.to) {
    throw new Error(`source and target environment are both "${opts.from}"`);
  }
  const found = getEnvelope(key, opts);
  if (!found) throw new Error(`Secret "${key}" not found`);
  const { envelope, scope } = found;
  const states = envelope.states;
  if (!states) {
    throw new Error(
      `"${key}" has a single value, not per-environment states — set one with: qring set ${key} --env ${opts.from}`,
    );
  }
  const source = states[opts.from];
  if (source === undefined) {
    const available = Object.keys(states).join(", ") || "none";
    throw new Error(`"${key}" has no value for env "${opts.from}" (available: ${available})`);
  }
  const current = states[opts.to];
  const previous: PromotePrevious =
    current === undefined ? "absent" : current === source ? "same" : "different";
  if (previous === "same") {
    return { key, scope, from: opts.from, to: opts.to, previous, changed: false };
  }
  if (previous === "different" && !opts.force) {
    throw new PromoteConflictError(key, opts.to);
  }
  const nextStates = { ...states, [opts.to]: source };
  setSecret(key, "", {
    ...opts,
    scope,
    states: nextStates,
    defaultEnv: envelope.defaultEnv,
  });
  return { key, scope, from: opts.from, to: opts.to, previous, changed: true };
}

export type DiffStatus = "same" | "different" | "only-a" | "only-b" | "collapsed";

export interface DiffEntry {
  key: string;
  scope: Scope;
  status: DiffStatus;
}

export interface DiffOptions extends KeyringOptions {
  a: Environment;
  b: Environment;
  /** Restrict to these keys (exact names). */
  keys?: string[];
}

export interface DiffResult {
  a: Environment;
  b: Environment;
  entries: DiffEntry[];
  summary: Record<DiffStatus, number>;
  /** True when anything differs or is missing on one side. */
  drift: boolean;
}

/**
 * Compare two environments across the visible secrets. Values are compared
 * for equality but never returned. A collapsed secret (single value) is the
 * same in every environment by definition and is reported as "collapsed".
 */
export function diffEnvironments(opts: DiffOptions): DiffResult {
  assertEnvName(opts.a, "first");
  assertEnvName(opts.b, "second");
  const wanted = opts.keys ? new Set(opts.keys) : null;
  const entries: DiffEntry[] = [];
  for (const entry of listSecrets(opts)) {
    if (wanted && !wanted.has(entry.key)) continue;
    const states = entry.envelope?.states;
    let status: DiffStatus;
    if (!states) {
      status = "collapsed";
    } else {
      const va = states[opts.a];
      const vb = states[opts.b];
      if (va === undefined && vb === undefined) continue; // in neither env
      if (va === undefined) status = "only-b";
      else if (vb === undefined) status = "only-a";
      else status = va === vb ? "same" : "different";
    }
    entries.push({ key: entry.key, scope: entry.scope, status });
  }
  const summary: Record<DiffStatus, number> = {
    same: 0,
    different: 0,
    "only-a": 0,
    "only-b": 0,
    collapsed: 0,
  };
  for (const e of entries) summary[e.status] += 1;
  const drift = summary.different + summary["only-a"] + summary["only-b"] > 0;
  return { a: opts.a, b: opts.b, entries, summary, drift };
}
