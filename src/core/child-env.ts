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
 * Variables that make a program run something other than what was asked
 * for: dynamic-linker preloads, interpreter and toolchain start-up hooks,
 * the command search path, shell start-up files, the helpers git, ssh,
 * make, cargo and pagers spawn (GIT_EXTERNAL_DIFF, GIT_ASKPASS,
 * SSH_ASKPASS, MAKEFLAGS, RUSTC_WRAPPER, PAGER, EDITOR, ...), and the
 * config files and homes those tools read. A secret with one of these
 * names is not a credential: injected into a child it is code execution
 * inside whatever command was allowed. Whole families are denied by
 * prefix, because a family keeps growing new hooks.
 *
 * This closes the environment-variable class only. It is not a sandbox: a
 * caller who controls the arguments of an allowed binary can still run
 * code through the binary itself (`git -c core.pager=...`, `make -f`).
 */
const PROCESS_CONTROL_NAMES = new Set([
  // Shells and the command search path.
  "PATH",
  "PATHEXT",
  "COMSPEC",
  "IFS",
  "CDPATH",
  "ZDOTDIR",
  "ENV",
  "BASH_ENV",
  "SHELLOPTS",
  "BASHOPTS",
  "PS4",
  "PROMPT_COMMAND",
  "SHELL",
  // Homes, config and temp directories tools load code or config from.
  "HOME",
  "XDG_CONFIG_HOME",
  "XDG_DATA_HOME",
  "TMPDIR",
  "DOCKER_HOST",
  "DOCKER_CONFIG",
  "KUBECONFIG",
  "AWS_CONFIG_FILE",
  "AWS_SHARED_CREDENTIALS_FILE",
  // Helpers other programs spawn.
  "PAGER",
  "MANPAGER",
  "EDITOR",
  "VISUAL",
  "BROWSER",
  "LESSOPEN",
  "LESSCLOSE",
  "SUDO_ASKPASS",
  // Compilers make and build scripts invoke by variable.
  "CC",
  "CXX",
  "CPP",
  "LD",
  "AR",
  // Go toolchain (exact names: a GO prefix would catch GOOGLE_API_KEY).
  "GOFLAGS",
  "GOPATH",
  "GOROOT",
  "GOTOOLCHAIN",
  "GOENV",
  "GOPROXY",
]);

const PROCESS_CONTROL_PREFIXES = [
  "LD_",
  "DYLD_",
  "GCONV_",
  "GLIBC_",
  "GIT_",
  "SSH_",
  "CARGO_",
  "RUSTC",
  "RUSTFLAGS",
  "RUSTDOCFLAGS",
  "MAKE",
  "PYTHON",
  "PERL",
  "RUBY",
  "JAVA",
  "_JAVA_",
  "JDK_",
  "NODE_",
  "NPM_",
  "YARN_",
  "PNPM_",
  "BUN_",
  "DENO_",
];

/**
 * Credentials that live inside a denied family. Their value is a token, not
 * a program or a path, so injecting one cannot run code, and denying them
 * would break `npm publish`, `cargo publish` and CI deploy keys. Matched on
 * the last `_` segment; GIT_CONFIG_* is never exempt (GIT_CONFIG_KEY_<n> /
 * GIT_CONFIG_VALUE_<n> set arbitrary git config, core.sshCommand included).
 */
const CREDENTIAL_SUFFIXES = new Set(["TOKEN", "KEY", "SECRET", "PASSWORD", "PAT"]);
const ALLOWED_IN_FAMILY = new Set(["NODE_ENV"]);

/** True for an env var name that steers what a process runs rather than holding a value. */
export function isProcessControlEnvName(name: string): boolean {
  const upper = name.toUpperCase();
  if (PROCESS_CONTROL_NAMES.has(upper)) return true;
  if (!PROCESS_CONTROL_PREFIXES.some((p) => upper.startsWith(p))) return false;
  if (ALLOWED_IN_FAMILY.has(upper)) return false;
  const last = upper.split("_").pop() ?? "";
  if (CREDENTIAL_SUFFIXES.has(last) && !upper.startsWith("GIT_CONFIG_")) return false;
  return true;
}
