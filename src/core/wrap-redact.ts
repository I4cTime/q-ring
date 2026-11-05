/**
 * Airlock result redaction.
 *
 * A wrapped MCP server can return anything in a tool result, resource read,
 * or prompt — including the operator's own secrets if it has them (from its
 * environment, a config file, a scraped page). Those results flow straight
 * into the agent transcript, which is the obvious exfiltration hole in the
 * airlock. This module builds the set of known secret VALUES (with the key
 * each came from) and scrubs them out of results before they leave the
 * airlock, using the same engine as `qring exec` (redaction.ts): verbatim,
 * base64/hex/URL/JSON-encoded, and 16+ char slices, each replaced with
 * `[QRING:REDACTED:<KEY>]`.
 *
 * Values are read silently (no audit "read", no access counter, no canary
 * trip) with CLI-source semantics, exactly like `qring exec`'s redaction set.
 * The set is rebuilt lazily every REFRESH_MS so rotated secrets are picked up
 * by a long-lived airlock.
 */

import { listSecrets, getSecret, type KeyringOptions } from "./keyring.js";
import { checkDecay } from "./envelope.js";
import {
  RedactionSet,
  MIN_REDACT_LENGTH,
  REDACTED,
  redactionToken,
  type RedactionEntry,
} from "./redaction.js";

export { REDACTED, redactionToken };

const REFRESH_MS = 60 * 1000;

export interface Redactor {
  text(input: string): string;
  /** Scrub a CallToolResult / ReadResourceResult / GetPromptResult in place. */
  result<T>(payload: T): T;
  /** Force the value set to rebuild on next use (tests, rotations). */
  invalidate(): void;
}

/** Gather every non-expired secret value in the resolvable scopes, with its key. */
export function collectSecretValues(opts: KeyringOptions = {}): RedactionEntry[] {
  const values = new Map<string, string>();
  for (const entry of listSecrets({ ...opts, source: "cli", silent: true })) {
    if (entry.envelope && checkDecay(entry.envelope).isExpired) continue;
    const value = getSecret(entry.key, {
      scope: entry.scope,
      projectPath: opts.projectPath,
      env: opts.env,
      source: "cli",
      silent: true,
    });
    // The first key that supplies a value names it.
    if (value && value.length >= MIN_REDACT_LENGTH && !values.has(value)) {
      values.set(value, entry.key);
    }
  }
  // Longest first so a value that contains another is scrubbed whole.
  return [...values]
    .map(([value, name]) => ({ name, value }))
    .sort((a, b) => b.value.length - a.value.length);
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

/**
 * Thrown by a redactor whose redaction set could not be built at all. The
 * airlock turns it into a tool error: a result is withheld, never passed
 * through unredacted. The message carries no values or key names.
 */
export class RedactionUnavailableError extends Error {
  constructor() {
    super("airlock: result withheld: secret redaction is unavailable");
    this.name = "RedactionUnavailableError";
  }
}

export function createRedactor(opts: KeyringOptions = {}): Redactor {
  // null until the first successful build (no known values yet).
  let set: RedactionSet | null = null;
  let failed = false;
  let builtAt = 0;

  const ensure = () => {
    const now = Date.now();
    if (!failed && now - builtAt < REFRESH_MS) return;
    let entries: RedactionEntry[];
    try {
      entries = collectSecretValues(opts);
    } catch {
      // Keyring unavailable — keep whatever set we had.
      builtAt = now;
      return;
    }
    try {
      set = new RedactionSet(entries);
      failed = false;
    } catch {
      // A full build should never fail on one bad value, but if it does, fall
      // back to verbatim-only matching of the same values — never to nothing.
      try {
        set = new RedactionSet(entries, { verbatimOnly: true });
        failed = false;
      } catch {
        // Fail closed; retried on the next result.
        failed = true;
        return;
      }
    }
    builtAt = now;
  };

  const text = (input: string): string => {
    ensure();
    if (failed) throw new RedactionUnavailableError();
    return set ? set.redact(input) : input;
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
