/**
 * Secure Execution & Auto-Redaction
 *
 * Runs child processes with project secrets injected into the environment.
 * Captures stdout/stderr and redacts any known secret values before they
 * are printed to the terminal or returned to the MCP agent.
 *
 * Exec profiles restrict which commands may be run, with optional
 * network and timeout controls.
 */

import { spawn } from "node:child_process";
import {
  withoutQringCredentials,
  isProcessControlEnvName,
  hasEnvNameShape,
  isCredentialShapedName,
} from "./child-env.js";
import { StringDecoder } from "node:string_decoder";
import { Transform } from "node:stream";
import { listSecrets, getSecret, type KeyringOptions } from "./keyring.js";
import { checkDecay } from "./envelope.js";
import { checkExecPolicy, getExecMaxRuntime, getPolicyRoot } from "./policy.js";
import { readProjectConfig } from "./collapse.js";
import {
  RedactionSet,
  RedactionStream,
  MIN_REDACT_LENGTH,
  type RedactionEntry,
} from "./redaction.js";

export type { RedactionEntry } from "./redaction.js";

export interface ExecProfile {
  name: string;
  allowCommands?: string[];
  denyCommands?: string[];
  maxRuntimeSeconds?: number;
  allowNetwork?: boolean;
  stripEnvVars?: string[];
}

const BUILTIN_PROFILES: Record<string, ExecProfile> = {
  unrestricted: { name: "unrestricted" },
  restricted: {
    name: "restricted",
    denyCommands: [
      // Network tools.
      "curl", "wget", "ssh", "scp", "nc", "netcat", "ncat",
      // Interpreters and shells: given the secret env vars, `python -c`,
      // `node -e`, `bash -c`, etc. can perform arbitrary network I/O and
      // exfiltrate them, defeating allowNetwork. Denied by default in
      // `restricted`; to run them with secrets use a custom profile in
      // .q-ring.json, or the `ci` / `unrestricted` profile.
      "python", "python2", "python3", "node", "deno", "bun",
      "perl", "ruby", "php", "sh", "bash", "zsh",
    ],
    maxRuntimeSeconds: 30,
    allowNetwork: false,
    stripEnvVars: ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"],
  },
  ci: {
    name: "ci",
    maxRuntimeSeconds: 300,
    allowNetwork: true,
    denyCommands: ["rm -rf /", "mkfs", "dd if="],
  },
};

/**
 * Resolve an exec profile by name. An unknown name is an error: falling back
 * to an empty profile would silently run a typo (`--profile restriced`) with
 * no restrictions at all. Own-property lookup so `constructor`/`__proto__`
 * cannot resolve to an Object.prototype member.
 */
export function getProfile(name?: string): ExecProfile {
  if (!name) return BUILTIN_PROFILES.unrestricted;
  if (!Object.hasOwn(BUILTIN_PROFILES, name)) {
    throw new Error(
      `Unknown exec profile "${name}". Known profiles: ${Object.keys(BUILTIN_PROFILES).join(", ")}`,
    );
  }
  return BUILTIN_PROFILES[name];
}

export function listProfiles(): ExecProfile[] {
  return Object.values(BUILTIN_PROFILES);
}

export interface ExecOptions extends KeyringOptions {
  tags?: string[];
  keys?: string[];
  command: string;
  args: string[];
  /** If true, return output as string instead of piping to process.stdout */
  captureOutput?: boolean;
  /** Exec profile name (unrestricted, restricted, ci) */
  profile?: string;
}

export interface ExecResult {
  code: number;
  stdout: string;
  stderr: string;
  /** A note for the caller about what was injected (MCP exec without a manifest). */
  note?: string;
}

/**
 * Shown to an MCP caller when no manifest limits what exec injects. Names
 * the keys the credential-shape rule skipped (names only, never values).
 */
export function noManifestNote(skipped: string[]): string {
  return (
    "no manifest in .q-ring.json: only credential-shaped secret names (…_KEY, …_TOKEN, …_SECRET, …_URL, …_DSN, …) were injected" +
    (skipped.length ? `; skipped: ${skipped.join(", ")}` : "") +
    "; declare secrets there to lift this rule and choose exactly what exec_with_secrets injects"
  );
}

/**
 * Best-effort output redaction over a child process's stdout/stderr. Matching
 * lives in redaction.ts (shared with the MCP airlock): verbatim values longer
 * than 5 chars, their base64/hex/URL/JSON-encoded forms (values up to 256
 * chars), and any run of 16+ consecutive characters of a value's
 * credential-bearing parts (parts up to 1024 chars). Hits become
 * `[QRING:REDACTED:<KEY>]` (`[QRING:REDACTED]` when the key is unknown). This
 * is a safety net, NOT a guarantee: a child that transforms a secret in other
 * ways (encrypts, compresses, prints under 16 chars of it) gets through.
 *
 * Streaming (RedactionStream): only the shortest tail that could still grow
 * into a hit is held back raw and re-examined with the next chunk, so a value
 * split across writes is still matched whole while ordinary output flushes at
 * once; the held tail is bounded.
 */
export class RedactionTransform extends Transform {
  private readonly stream: RedactionStream | null;
  // Decodes UTF-8 across chunk boundaries: a multi-byte character split between
  // two Buffer chunks would otherwise be corrupted to U+FFFD by chunk.toString()
  // BEFORE matching runs, letting a multi-byte secret slip through unredacted.
  // StringDecoder buffers the incomplete trailing bytes until the rest arrives.
  private decoder = new StringDecoder("utf8");

  /** Takes `{ name, value }` entries, or a prebuilt set shared between streams. */
  constructor(secretsToRedact: readonly RedactionEntry[] | RedactionSet) {
    super();
    const set =
      secretsToRedact instanceof RedactionSet ? secretsToRedact : new RedactionSet(secretsToRedact);
    this.stream = set.empty ? null : new RedactionStream(set);
  }

  _transform(chunk: Buffer | string, _encoding: string, callback: () => void) {
    if (!this.stream) {
      this.push(chunk);
      return callback();
    }

    const decoded = typeof chunk === "string" ? chunk : this.decoder.write(chunk);
    const out = this.stream.write(decoded);
    if (out) this.push(out);
    callback();
  }

  _flush(callback: () => void) {
    // Flush any bytes the decoder is still holding (an incomplete sequence at
    // end-of-stream) along with the held-back raw tail, then redact once more.
    if (this.stream) {
      const out = this.stream.end(this.decoder.end());
      if (out) this.push(out);
    }
    callback();
  }
}

/**
 * Build the redaction set for a spawn. A full build never fails on one bad
 * value (derivation is per value), but if it does throw anyway, fall back to
 * verbatim-only matching rather than running unredacted. Throws only when
 * even that fails; callers must not spawn then.
 */
export function buildRedactionSet(entries: readonly RedactionEntry[]): RedactionSet {
  try {
    return new RedactionSet(entries);
  } catch {
    return new RedactionSet(entries, { verbatimOnly: true });
  }
}

/**
 * Enforce the exec policy and profile allow/deny lists for a command.
 * Shared by `qring exec` (scope-wide injection) and `qring run` (declared-only
 * injection). Throws on denial.
 */
export function enforceExecPolicy(
  profile: ExecProfile,
  command: string,
  args: string[],
  projectPath?: string,
): void {
  const fullCommand = [command, ...args].join(" ");

  const policyDecision = checkExecPolicy(fullCommand, projectPath);
  if (!policyDecision.allowed) {
    throw new Error(`Policy Denied: ${policyDecision.reason}`);
  }

  if (profile.denyCommands) {
    const denied = profile.denyCommands.find((d) => {
      const pattern = new RegExp(`(^|[\\s/])${d.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(\\s|$)`, "i");
      return pattern.test(fullCommand);
    });
    if (denied) {
      throw new Error(`Exec profile "${profile.name}" denies command containing "${denied}"`);
    }
  }
  if (profile.allowCommands) {
    const allowed = profile.allowCommands.some((a) => fullCommand.startsWith(a));
    if (!allowed) {
      throw new Error(`Exec profile "${profile.name}" does not allow command "${command}"`);
    }
  }
}

export async function execCommand(opts: ExecOptions): Promise<ExecResult> {
  const profile = getProfile(opts.profile);
  enforceExecPolicy(profile, opts.command, opts.args, opts.projectPath);

  const envMap: Record<string, string> = {};
  for (const [k, v] of Object.entries(process.env)) {
    if (v !== undefined) envMap[k] = v;
  }

  if (profile.stripEnvVars) {
    for (const key of profile.stripEnvVars) {
      delete envMap[key];
    }
  }

  // value -> key name; the first key that supplies a value names it.
  const secretsToRedact = new Map<string, string>();

  let entries = listSecrets({
    scope: opts.scope,
    projectPath: opts.projectPath,
    source: opts.source ?? "cli",
    silent: true, // list silently
  });

  // The boundary for an MCP caller is the operator's manifest: when the
  // project declares its secrets, exec_with_secrets injects only those (the
  // same least-privilege set `qring run` uses), intersected with `keys`. A
  // key an agent planted with set_secret is inert unless the operator
  // declared it. Read from the pinned policy root, not a caller-chosen path.
  // Without a manifest only credential-shaped names are injected (below,
  // after the shape rule and denylist), and the result says which were
  // skipped.
  let note: string | undefined;
  let credentialShapedOnly = false;
  if ((opts.source ?? "cli") === "mcp") {
    const root = getPolicyRoot() ?? opts.projectPath ?? process.cwd();
    const declared = Object.keys(readProjectConfig(root)?.secrets ?? {});
    if (declared.length > 0) {
      const allowed = new Set(declared);
      entries = entries.filter((e) => allowed.has(e.key));
    } else {
      credentialShapedOnly = true;
    }
  }

  if (opts.keys?.length) {
    const keySet = new Set(opts.keys);
    entries = entries.filter((e) => keySet.has(e.key));
  }

  if (opts.tags?.length) {
    entries = entries.filter((e) =>
      opts.tags!.some((t) => e.envelope?.meta.tags?.includes(t)),
    );
  }

  // A secret named NODE_OPTIONS, LD_PRELOAD, PATH, BASH_ENV, ... is code
  // that runs inside whatever command is allowed (`--import=data:...` needs
  // no file). Anyone who can write a key (an MCP agent, a teleport bundle)
  // could otherwise turn policy.exec.allowCommands into arbitrary
  // execution. Only the local operator may inject one, by naming it in --keys.
  entries = entries.filter((e) => {
    // Shape first, never overridable: `BASH_FUNC_ls%%` is a bash function
    // definition, not a variable.
    if (!hasEnvNameShape(e.key)) {
      if ((opts.source ?? "cli") !== "mcp") {
        process.stderr.write(
          `[QRING] not injecting "${e.key}": not a plain environment variable name\n`,
        );
      }
      return false;
    }
    if (!isProcessControlEnvName(e.key)) return true;
    if ((opts.source ?? "cli") !== "mcp" && opts.keys?.includes(e.key)) return true;
    if ((opts.source ?? "cli") !== "mcp") {
      process.stderr.write(
        `[QRING] not injecting "${e.key}": it controls process start-up; pass --keys ${e.key} to inject it deliberately\n`,
      );
    }
    return false;
  });

  // Third tier, MCP without a manifest: a denylist of hook variables cannot
  // be finished (GOAUTH, CGO_*, MAVEN_OPTS, ... keep appearing), so only
  // names that read as credentials are injected.
  if (credentialShapedOnly) {
    const skipped = entries.filter((e) => !isCredentialShapedName(e.key)).map((e) => e.key);
    entries = entries.filter((e) => isCredentialShapedName(e.key));
    note = noManifestNote(skipped);
  }

  for (const entry of entries) {
    if (entry.envelope) {
      const decay = checkDecay(entry.envelope);
      if (decay.isExpired) continue;
    }

    const val = getSecret(entry.key, {
      scope: entry.scope,
      projectPath: opts.projectPath,
      env: opts.env,
      source: opts.source ?? "cli",
      silent: false, // Log access for execution
    });

    if (val !== null) {
      envMap[entry.key] = val;
      if (val.length >= MIN_REDACT_LENGTH && !secretsToRedact.has(val)) {
        secretsToRedact.set(val, entry.key);
      }
    }
  }

  const result = await spawnRedacted({
    profile,
    command: opts.command,
    args: opts.args,
    envMap,
    secretsToRedact: [...secretsToRedact].map(([value, name]) => ({ name, value })),
    captureOutput: opts.captureOutput,
    projectPath: opts.projectPath,
  });
  return note ? { ...result, note } : result;
}

export interface SpawnRedactedOptions {
  profile: ExecProfile;
  command: string;
  args: string[];
  /** Complete child environment (caller composes inheritance + injection). */
  envMap: Record<string, string>;
  /** Values to redact from the child's stdout/stderr, with the key each came from. */
  secretsToRedact: RedactionEntry[];
  captureOutput?: boolean;
  /** Used only to resolve the policy-configured max runtime. */
  projectPath?: string;
}

/**
 * Spawn a child process with a fully-composed environment, enforcing the
 * profile's network restriction and runtime limit, and redacting known
 * secret values from its output.
 */
export function spawnRedacted(opts: SpawnRedactedOptions): Promise<ExecResult> {
  const { profile, secretsToRedact } = opts;
  // q-ring's own master keys never reach a child (see child-env.ts).
  const envMap = withoutQringCredentials(opts.envMap);
  const maxRuntime = profile.maxRuntimeSeconds ?? getExecMaxRuntime(opts.projectPath);

  return new Promise((resolve, reject) => {
    // Enforce network restrictions for profiles that disallow network access.
    const networkTools = new Set([
      "curl", "wget", "ping", "nc", "netcat", "ssh", "telnet", "ftp", "dig", "nslookup",
    ]);

    // Compare on the command basename so absolute paths like /usr/bin/curl are
    // still caught. (Interpreter-based egress — python -c, node -e — is out of
    // scope here; this is best-effort, not a hard sandbox.)
    const commandBase = opts.command.split(/[\\/]/).pop() ?? opts.command;

    if (profile.allowNetwork === false && networkTools.has(commandBase)) {
      const msg = `[QRING] Execution blocked: network access is disabled for profile "${profile.name}", command "${opts.command}" is considered network-related`;
      if (opts.captureOutput) {
        return resolve({ code: 126, stdout: "", stderr: msg });
      }
      process.stderr.write(msg + "\n");
      return resolve({ code: 126, stdout: "", stderr: "" });
    }

    // Build the redaction set BEFORE spawning: if it cannot be built, the
    // child must never run with secrets in its environment and unredacted
    // output.
    let redactionSet: RedactionSet;
    try {
      redactionSet = buildRedactionSet(secretsToRedact);
    } catch (err) {
      reject(
        new Error(
          `[QRING] Execution blocked: output redaction could not be set up (${err instanceof Error ? err.name : "error"})`,
        ),
      );
      return;
    }

    const child = spawn(opts.command, opts.args, {
      env: envMap,
      stdio: ["inherit", "pipe", "pipe"],
      shell: false,
    });

    let timedOut = false;
    let timer: ReturnType<typeof setTimeout> | undefined;

    if (maxRuntime) {
      timer = setTimeout(() => {
        timedOut = true;
        child.kill("SIGKILL");
      }, maxRuntime * 1000);
    }

    const stdoutRedact = new RedactionTransform(redactionSet);
    const stderrRedact = new RedactionTransform(redactionSet);

    if (child.stdout) child.stdout.pipe(stdoutRedact);
    if (child.stderr) child.stderr.pipe(stderrRedact);

    let stdoutStr = "";
    let stderrStr = "";

    if (opts.captureOutput) {
      stdoutRedact.on("data", (d) => (stdoutStr += d.toString()));
      stderrRedact.on("data", (d) => (stderrStr += d.toString()));
    } else {
      stdoutRedact.pipe(process.stdout);
      stderrRedact.pipe(process.stderr);
    }

    child.on("close", (code) => {
      if (timer) clearTimeout(timer);
      if (timedOut) {
        resolve({ code: 124, stdout: stdoutStr, stderr: stderrStr + `\n[QRING] Process killed: exceeded ${maxRuntime}s runtime limit` });
      } else {
        resolve({ code: code ?? 0, stdout: stdoutStr, stderr: stderrStr });
      }
    });

    child.on("error", (err) => {
      if (timer) clearTimeout(timer);
      reject(err);
    });
  });
}
