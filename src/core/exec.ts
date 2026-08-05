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
import { StringDecoder } from "node:string_decoder";
import { Transform } from "node:stream";
import { listSecrets, getSecret, type KeyringOptions } from "./keyring.js";
import { checkDecay } from "./envelope.js";
import { checkExecPolicy, getExecMaxRuntime } from "./policy.js";

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

export function getProfile(name?: string): ExecProfile {
  if (!name) return BUILTIN_PROFILES.unrestricted;
  return BUILTIN_PROFILES[name] ?? { name };
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
}

/**
 * Best-effort output redaction: replaces verbatim occurrences of known secret
 * values (>5 chars) in a child process's stdout/stderr. This is a safety net,
 * NOT a guarantee — it cannot catch secrets that the child has transformed
 * (base64/hex/URL-encoded, split across writes beyond the tail window, etc.).
 */
export class RedactionTransform extends Transform {
  private patterns: { value: string; replacement: string }[] = [];
  private tail: string = "";
  private maxLen: number = 0;
  // Decodes UTF-8 across chunk boundaries: a multi-byte character split between
  // two Buffer chunks would otherwise be corrupted to U+FFFD by chunk.toString()
  // BEFORE matching runs, letting a multi-byte secret slip through unredacted.
  // StringDecoder buffers the incomplete trailing bytes until the rest arrives.
  private decoder = new StringDecoder("utf8");

  constructor(secretsToRedact: string[]) {
    super();
    // Only redact secrets > 5 chars to avoid destroying output
    const validSecrets = secretsToRedact.filter((s) => s.length > 5);
    // Sort by length descending to match longest first
    validSecrets.sort((a, b) => b.length - a.length);

    this.patterns = validSecrets.map((s) => ({
      value: s,
      replacement: "[QRING:REDACTED]",
    }));

    if (validSecrets.length > 0) {
      this.maxLen = validSecrets[0].length;
    }
  }

  _transform(chunk: Buffer | string, _encoding: string, callback: () => void) {
    if (this.patterns.length === 0) {
      this.push(chunk);
      return callback();
    }

    const decoded =
      typeof chunk === "string" ? chunk : this.decoder.write(chunk);
    const text = this.tail + decoded;
    let redacted = text;

    for (const { value, replacement } of this.patterns) {
      redacted = redacted.split(value).join(replacement);
    }

    if (redacted.length < this.maxLen) {
      this.tail = redacted;
      return callback();
    }

    const outputLen = redacted.length - this.maxLen + 1;
    const output = redacted.slice(0, outputLen);
    this.tail = redacted.slice(outputLen);

    this.push(output);
    callback();
  }

  _flush(callback: () => void) {
    // Flush any bytes the decoder is still holding (an incomplete sequence at
    // end-of-stream) along with the retained tail, then redact once more.
    let final = this.tail + this.decoder.end();
    if (final) {
      for (const { value, replacement } of this.patterns) {
        final = final.split(value).join(replacement);
      }
      this.push(final);
    }
    callback();
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

  const secretsToRedact = new Set<string>();

  let entries = listSecrets({
    scope: opts.scope,
    projectPath: opts.projectPath,
    source: opts.source ?? "cli",
    silent: true, // list silently
  });

  if (opts.keys?.length) {
    const keySet = new Set(opts.keys);
    entries = entries.filter((e) => keySet.has(e.key));
  }

  if (opts.tags?.length) {
    entries = entries.filter((e) =>
      opts.tags!.some((t) => e.envelope?.meta.tags?.includes(t)),
    );
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
      if (val.length > 5) {
        secretsToRedact.add(val);
      }
    }
  }

  return spawnRedacted({
    profile,
    command: opts.command,
    args: opts.args,
    envMap,
    secretsToRedact: [...secretsToRedact],
    captureOutput: opts.captureOutput,
    projectPath: opts.projectPath,
  });
}

export interface SpawnRedactedOptions {
  profile: ExecProfile;
  command: string;
  args: string[];
  /** Complete child environment (caller composes inheritance + injection). */
  envMap: Record<string, string>;
  /** Values to redact from the child's stdout/stderr. */
  secretsToRedact: string[];
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
  const { profile, secretsToRedact, envMap } = opts;
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

    const stdoutRedact = new RedactionTransform([...secretsToRedact]);
    const stderrRedact = new RedactionTransform([...secretsToRedact]);

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
