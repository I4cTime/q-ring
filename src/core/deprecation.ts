/**
 * Deprecation warnings.
 *
 * Every path deprecated ahead of 1.0 (see docs/stability.md, "Deprecated in
 * 0.19") calls `warnDeprecated` when it is used. The contract:
 *
 * - one line, prefixed `q-ring: deprecated:`, naming the replacement and the
 *   removal version;
 * - stderr only — never stdout, so `--json` consumers and MCP stdio framing
 *   are unaffected;
 * - at most once per id per process;
 * - silent when `QRING_SILENCE_DEPRECATIONS=1`;
 * - never contains a secret value (callers pass fixed text).
 */

export const SILENCE_DEPRECATIONS_ENV = "QRING_SILENCE_DEPRECATIONS";

const PREFIX = "q-ring: deprecated:";

const warned = new Set<string>();

/**
 * Print `q-ring: deprecated: <message>` to stderr the first time `id` is seen
 * in this process. Returns true when a line was written.
 */
export function warnDeprecated(id: string, message: string): boolean {
  if (process.env[SILENCE_DEPRECATIONS_ENV] === "1") return false;
  if (warned.has(id)) return false;
  warned.add(id);
  try {
    process.stderr.write(`${PREFIX} ${message}\n`);
  } catch {
    // A closed stderr must never turn a deprecation notice into a failure.
  }
  return true;
}

/** Test hook: forget which ids have already warned. */
export function resetDeprecationWarnings(): void {
  warned.clear();
}
