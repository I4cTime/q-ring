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

/**
 * Variables that change what a process loads or runs before its own code:
 * dynamic-linker preloads, interpreter start-up hooks, the command search
 * path, shell start-up files, git's ssh command, npm's script shell. A
 * secret with one of these names is not a credential; injected into a
 * child, it is code execution inside an allowlisted command.
 */
const PROCESS_CONTROL_NAMES = new Set([
  "PATH",
  "NODE_OPTIONS",
  "NODE_PATH",
  "BASH_ENV",
  "ENV",
  "SHELLOPTS",
  "BASHOPTS",
  "PS4",
  "PROMPT_COMMAND",
  "IFS",
  "PYTHONSTARTUP",
  "PYTHONPATH",
  "PYTHONHOME",
  "PYTHONINSPECT",
  "PERL5OPT",
  "PERL5LIB",
  "PERLLIB",
  "RUBYOPT",
  "RUBYLIB",
  "JAVA_TOOL_OPTIONS",
  "_JAVA_OPTIONS",
  "JDK_JAVA_OPTIONS",
  "GIT_SSH",
  "GIT_SSH_COMMAND",
  "GIT_EXEC_PATH",
  "GIT_CONFIG_GLOBAL",
  "GCONV_PATH",
]);
const PROCESS_CONTROL_PREFIXES = ["LD_", "DYLD_", "NPM_CONFIG_", "GIT_CONFIG_"];

/** True for an env var name that steers process start-up rather than holding a value. */
export function isProcessControlEnvName(name: string): boolean {
  const upper = name.toUpperCase();
  return (
    PROCESS_CONTROL_NAMES.has(upper) || PROCESS_CONTROL_PREFIXES.some((p) => upper.startsWith(p))
  );
}
