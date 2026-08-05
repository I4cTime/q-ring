/**
 * qring:// Secret References
 *
 * A secret reference is a stable, committable pointer to a secret in the
 * keyring — the value that goes in a .env file or CI config instead of the
 * secret itself:
 *
 *   qring://project/DATABASE_URL          project-scoped key
 *   qring://global/OPENAI_API_KEY         global-scoped key
 *   qring:///STRIPE_KEY                   auto scope (project, then global)
 *   qring://project/DATABASE_URL?env=prod pin the superposition environment
 *
 * The KEY always lives in the PATH component, never the host: URL hosts are
 * case-insensitive and WHATWG parsers lowercase them, which would silently
 * corrupt `qring://DATABASE_URL` into `database_url`. Refs are parsed with a
 * grammar of our own (not `new URL`) so that footgun cannot exist, and the
 * key-in-host form is rejected with a corrective error.
 */

import { getSecret, type KeyringOptions } from "./keyring.js";
import type { Environment } from "./envelope.js";

export const REF_PREFIX = "qring://";

/** Scopes addressable by a ref. Team/org need out-of-band ids and are not addressable. */
export type RefScope = "global" | "project";

export interface SecretRef {
  /** Undefined = auto: resolve project scope first, then global. */
  scope?: RefScope;
  key: string;
  /** Environment pin from `?env=`; undefined = collapse from context. */
  env?: Environment;
  /** The original ref string, for error messages and round-tripping. */
  raw: string;
}

const KEY_PATTERN = /^[A-Za-z_][A-Za-z0-9_]*$/;
const REF_PATTERN = /^qring:\/\/(global|project|)\/([^/?#]+)(?:\?([^#]*))?$/;

/** True if a string is even shaped like a ref (cheap pre-filter for env maps). */
export function isRef(value: string): boolean {
  return value.startsWith(REF_PREFIX);
}

/**
 * Parse a qring:// reference. Throws on malformed refs — a ref that made it
 * into a .env file is config, and config errors should be loud, not silently
 * passed through to the child process as a literal `qring://...` string.
 */
export function parseRef(raw: string): SecretRef {
  if (!isRef(raw)) {
    throw new Error(`Not a qring:// reference: "${raw}"`);
  }

  const match = REF_PATTERN.exec(raw);
  if (!match) {
    // The one mistake everyone will make: qring://DATABASE_URL (key in the
    // host slot). Catch it specifically and say what the correct form is.
    const hostOnly = /^qring:\/\/([^/?#]+)\/?$/.exec(raw);
    if (hostOnly && KEY_PATTERN.test(hostOnly[1]) && !["global", "project"].includes(hostOnly[1])) {
      throw new Error(
        `Invalid ref "${raw}": the key belongs in the path, not the host ` +
          `(URL hosts are lowercased by parsers). ` +
          `Use "qring:///${hostOnly[1]}" (auto scope) or "qring://project/${hostOnly[1]}".`,
      );
    }
    throw new Error(
      `Invalid ref "${raw}": expected qring://<global|project|>/KEY[?env=<env>]`,
    );
  }

  const [, scopeRaw, key, query] = match;

  if (!KEY_PATTERN.test(key)) {
    throw new Error(
      `Invalid ref "${raw}": "${key}" is not a valid secret key (expected [A-Za-z_][A-Za-z0-9_]*)`,
    );
  }

  let env: Environment | undefined;
  if (query) {
    for (const part of query.split("&")) {
      if (!part) continue;
      const eq = part.indexOf("=");
      const name = eq === -1 ? part : part.slice(0, eq);
      const value = eq === -1 ? "" : decodeURIComponent(part.slice(eq + 1));
      if (name === "env") {
        env = value as Environment;
      } else {
        throw new Error(`Invalid ref "${raw}": unknown query parameter "${name}"`);
      }
    }
  }

  return {
    scope: scopeRaw === "" ? undefined : (scopeRaw as RefScope),
    key,
    env,
    raw,
  };
}

export type ResolveRefOptions = KeyringOptions;

/**
 * Resolve a parsed ref to its secret value. Auto-scope refs try project
 * first, then global. Returns null when the key is absent (callers decide
 * whether missing is fatal); scope/env options from the ref override the
 * caller's context.
 */
export function resolveRef(ref: SecretRef, opts: ResolveRefOptions = {}): string | null {
  const scopes: RefScope[] = ref.scope ? [ref.scope] : ["project", "global"];

  for (const scope of scopes) {
    const value = getSecret(ref.key, {
      ...opts,
      scope,
      env: ref.env ?? opts.env,
    });
    if (value !== null) return value;
  }
  return null;
}

export interface ResolvedRefMap {
  /** Env map with every qring:// value replaced by its resolved secret. */
  resolved: Record<string, string>;
  /** Values that resolved from the keyring (for redaction). */
  secretValues: string[];
  /** Refs whose key was not found in any addressed scope. */
  missing: { name: string; ref: SecretRef }[];
}

/**
 * Resolve every qring:// value in an env map. Non-ref values pass through
 * untouched; malformed refs throw (see parseRef).
 */
export function resolveRefsInMap(
  map: Record<string, string>,
  opts: ResolveRefOptions = {},
): ResolvedRefMap {
  const resolved: Record<string, string> = {};
  const secretValues: string[] = [];
  const missing: { name: string; ref: SecretRef }[] = [];

  for (const [name, value] of Object.entries(map)) {
    if (!isRef(value)) {
      resolved[name] = value;
      continue;
    }
    const ref = parseRef(value);
    const secret = resolveRef(ref, opts);
    if (secret === null) {
      missing.push({ name, ref });
      continue;
    }
    resolved[name] = secret;
    secretValues.push(secret);
  }

  return { resolved, secretValues, missing };
}
