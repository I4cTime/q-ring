/**
 * Airlock result redaction.
 *
 * A wrapped MCP server can return anything in a tool result, resource read,
 * or prompt — including the operator's own secrets if it has them (from its
 * environment, a config file, a scraped page). Those results flow straight
 * into the agent transcript, which is the obvious exfiltration hole in the
 * airlock. This module builds the set of known secret VALUES (with the key
 * each came from) and scrubs them out of results before they leave the
 * airlock, using the same engine as `qring exec` (redaction.ts): whole values
 * and their base64/hex/URL/JSON-encoded forms, each replaced with
 * `[QRING:REDACTED:<KEY>]`.
 *
 * No slice matching here, deliberately. The agent on the other side chooses
 * the text it sends to a wrapped tool, and many tools echo their input (echo,
 * write-then-read, a search repeating the query). Slice extension stops at
 * the first char that no longer follows the secret, so lines of the form
 * "known 16-char prefix + candidate char" would come back redacted for the
 * right candidate and untouched for the rest: a per-char oracle that
 * recovers an unknown secret one call per char. Whole-value and encoded
 * matching answer only "is this the entire secret?", which leaks nothing an
 * attacker can build on.
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

export interface CollectStats {
  /** Entries whose value could not be read (and so are not in the set). */
  skipped: number;
  /** When present, filled with the id (scope + key) of each entry that could not be read. */
  failed?: string[];
  /** When present, filled with id -> { key, value } for each entry that was read. */
  read?: Map<string, { key: string; value: string }>;
}

/** Stable id of a keyring entry across rebuilds: scope plus key name. */
const entryId = (scope: string, key: string) => `${scope}\u0000${key}`;

/**
 * Gather every non-expired secret value in the resolvable scopes, with its
 * key. One entry that cannot be read (a template naming a missing or circular
 * key, a failing JIT provider) is skipped and counted in `stats`, never allowed
 * to fail the whole collection. Listing itself can still throw.
 */
export function collectSecretValues(
  opts: KeyringOptions = {},
  stats: CollectStats = { skipped: 0 },
): RedactionEntry[] {
  const values = new Map<string, string>();
  for (const entry of listSecrets({ ...opts, source: "cli", silent: true })) {
    let value: string | null;
    try {
      if (entry.envelope && checkDecay(entry.envelope).isExpired) continue;
      value = getSecret(entry.key, {
        scope: entry.scope,
        projectPath: opts.projectPath,
        env: opts.env,
        source: "cli",
        silent: true,
      });
    } catch {
      stats.skipped++;
      stats.failed?.push(entryId(entry.scope, entry.key));
      continue;
    }
    if (value && value.length >= MIN_REDACT_LENGTH) {
      stats.read?.set(entryId(entry.scope, entry.key), { key: entry.key, value });
    }
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
  let skipNoted = false;
  // Last value read for each entry (scope + key). A key whose read fails on a
  // refresh (D-Bus timeout, JIT provider error, template dependency) keeps
  // its last good value in the set rather than silently leaving it.
  let lastGood = new Map<string, { key: string; value: string }>();

  const ensure = () => {
    const now = Date.now();
    if (!failed && now - builtAt < REFRESH_MS) return;
    let entries: RedactionEntry[];
    const stats: CollectStats = { skipped: 0, failed: [], read: new Map() };
    try {
      entries = collectSecretValues(opts, stats);
    } catch {
      if (set) {
        // Keep the last good set; try again at the next refresh.
        builtAt = now;
      } else {
        // Never built: there is nothing to redact with, so fail closed and
        // retry on the next result.
        failed = true;
      }
      return;
    }
    // Keep the previous value of every entry that failed to read this time.
    // An entry that has never been read has nothing to keep and is skipped.
    const nextGood = new Map(stats.read);
    for (const id of stats.failed ?? []) {
      const prev = lastGood.get(id);
      if (!prev) continue;
      nextGood.set(id, prev);
      entries.push({ name: prev.key, value: prev.value });
    }
    lastGood = nextGood;
    if (stats.skipped > 0 && !skipNoted) {
      skipNoted = true;
      // Counts only: never a value or a key name.
      process.stderr.write(
        `[QRING] airlock redaction: ${stats.skipped} secret(s) could not be read ` +
          `(their last read values stay redacted; one never read is not)\n`,
      );
    }
    try {
      set = new RedactionSet(entries, { slices: false });
      failed = false;
    } catch {
      // A full build should never fail on one bad value, but if it does, fall
      // back to verbatim-only matching of the same values — never to nothing.
      try {
        set = new RedactionSet(entries, { verbatimOnly: true, slices: false });
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
