/**
 * Environment hygiene for child processes q-ring starts.
 *
 * `QRING_FILE_PASSPHRASE` unlocks the whole file backend and
 * `QRING_MEMORY_PASSPHRASE` the agent memory store. They are q-ring's own
 * master keys, never something a child needs: a command run through
 * `qring exec --keys ONE_KEY` that inherited the file passphrase could
 * decrypt every secret in the store, which defeats the point of injecting
 * one. They are removed from every child environment q-ring composes for
 * code it does not control (exec/run children, a wrapped MCP server under
 * --inherit-env, platform CLIs under `qring push`).
 */

export const QRING_CREDENTIAL_ENV_VARS = ["QRING_FILE_PASSPHRASE", "QRING_MEMORY_PASSPHRASE"];

/** A copy of `env` without q-ring's master-key variables (and without undefined values). */
export function withoutQringCredentials(
  env: Record<string, string | undefined>,
): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [name, value] of Object.entries(env)) {
    if (value === undefined) continue;
    if (QRING_CREDENTIAL_ENV_VARS.includes(name)) continue;
    out[name] = value;
  }
  return out;
}
