/**
 * Airlock result redaction.
 *
 * A wrapped MCP server can return anything in a tool result, resource read,
 * or prompt — including the operator's own secrets if it has them (from its
 * environment, a config file, a scraped page). Those results flow straight
 * into the agent transcript, which is the obvious exfiltration hole in the
 * airlock. This module builds the set of known secret VALUES and scrubs every
 * verbatim occurrence out of results before they leave the airlock.
 *
 * Values are read silently (no audit "read", no access counter, no canary
 * trip) with CLI-source semantics, exactly like `qring exec`'s redaction set.
 * The set is rebuilt lazily every REFRESH_MS so rotated secrets are picked up
 * by a long-lived airlock. Same replacement token as exec so redacted output
 * is recognisable everywhere.
 */

import { listSecrets, getSecret, type KeyringOptions } from "./keyring.js";
import { checkDecay } from "./envelope.js";

export const REDACTED = "[QRING:REDACTED]";
const REFRESH_MS = 60 * 1000;
const MIN_LENGTH = 6; // shorter values would shred ordinary text

export interface Redactor {
  text(input: string): string;
  /** Scrub a CallToolResult / ReadResourceResult / GetPromptResult in place. */
  result<T>(payload: T): T;
  /** Force the value set to rebuild on next use (tests, rotations). */
  invalidate(): void;
}

/** Gather every non-expired secret value in the resolvable scopes. */
export function collectSecretValues(opts: KeyringOptions = {}): string[] {
  const values = new Set<string>();
  for (const entry of listSecrets({ ...opts, source: "cli", silent: true })) {
    if (entry.envelope && checkDecay(entry.envelope).isExpired) continue;
    const value = getSecret(entry.key, {
      scope: entry.scope,
      projectPath: opts.projectPath,
      env: opts.env,
      source: "cli",
      silent: true,
    });
    if (value && value.length >= MIN_LENGTH) values.add(value);
  }
  // Longest first so a value that contains another is scrubbed whole.
  return [...values].sort((a, b) => b.length - a.length);
}

function scrubUnknown(node: unknown, scrub: (s: string) => string): unknown {
  if (typeof node === "string") return scrub(node);
  if (Array.isArray(node)) return node.map((n) => scrubUnknown(n, scrub));
  if (node && typeof node === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(node as Record<string, unknown>)) {
      // Binary payloads (base64 `blob`/`data`) are not text; leave them alone.
      out[k] = k === "blob" || k === "data" ? v : scrubUnknown(v, scrub);
    }
    return out;
  }
  return node;
}

export function createRedactor(opts: KeyringOptions = {}): Redactor {
  let values: string[] = [];
  let builtAt = 0;

  const ensure = () => {
    const now = Date.now();
    if (now - builtAt < REFRESH_MS) return;
    try {
      values = collectSecretValues(opts);
    } catch {
      // Keyring unavailable — keep whatever set we had; never block a result.
    }
    builtAt = now;
  };

  const text = (input: string): string => {
    ensure();
    let out = input;
    for (const v of values) {
      if (out.includes(v)) out = out.split(v).join(REDACTED);
    }
    return out;
  };

  return {
    text,
    result: <T>(payload: T): T => scrubUnknown(payload, text) as T,
    invalidate: () => {
      builtAt = 0;
    },
  };
}

/** A redactor that changes nothing — for `--no-redact` / policy opt-out. */
export const NOOP_REDACTOR: Redactor = {
  text: (s) => s,
  result: (p) => p,
  invalidate: () => {},
};
