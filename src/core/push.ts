/**
 * `qring push` — bridge secrets out to deployment platforms.
 *
 * Pushes keyring secrets to GitHub Actions, Vercel, Cloudflare Workers,
 * fly.io, Railway, or Netlify through each platform's OWN authenticated CLI
 * (gh / vercel / wrangler / flyctl / railway / netlify). q-ring never holds
 * platform tokens, and secret values travel over the child's stdin — never
 * argv, which is world-readable via /proc — or, for CLIs that can only read
 * a file, through a 0600 temp file under a 0700 mkdtemp dir that is removed
 * the moment the CLI exits.
 *
 * Which keys move is the project's declared contract: the .q-ring.json
 * secrets manifest by default, or an explicit --keys list. Every pushed key
 * is written to the audit chain as a "push" event (deliberate egress is
 * exactly what an audit log is for).
 */

import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { resolveRef } from "./refs.js";
import { readProjectConfig } from "./collapse.js";
import { logAudit } from "./observer.js";
import type { KeyringOptions } from "./keyring.js";

export type PushTarget = "github" | "vercel" | "cloudflare" | "fly" | "railway" | "netlify";

export const PUSH_TARGETS: PushTarget[] = [
  "github",
  "vercel",
  "cloudflare",
  "fly",
  "railway",
  "netlify",
];

export interface PushOptions extends KeyringOptions {
  target: PushTarget;
  /** Explicit keys; default is every key in the .q-ring.json manifest. */
  keys?: string[];
  /** GitHub repo (owner/name); default is the repo of the current directory. */
  repo?: string;
  /** Vercel environments to push to (production, preview, development). */
  vercelEnvs?: string[];
  /** fly.io app name; default is the app in ./fly.toml. */
  app?: string;
  /** Railway service (name or ID); default is the linked service. */
  service?: string;
  /** Railway environment (name or ID); default is the linked environment. */
  railwayEnv?: string;
  /** Netlify site (name or ID); default is the linked site. */
  site?: string;
  dryRun?: boolean;
  /**
   * Values to push for specific keys WITHOUT reading them from the keyring.
   * Used by `qring canary plant --push`: reading a freshly planted canary
   * would trip it. Internal to the CLI — never reachable over MCP.
   */
  presetValues?: Record<string, string>;
  /** Audit these keys as canaries (detail text only). */
  canaryKeys?: string[];
}

export interface PushResult {
  target: PushTarget;
  /** Keys that were (or with dryRun, would be) pushed. */
  pushed: string[];
  /** Keys the platform CLI rejected, with its stderr. */
  failed: { key: string; error: string }[];
  /** Keys not found in the keyring — skipped, reported, non-fatal. */
  missing: string[];
}

interface TargetCommand {
  binary: string;
  /**
   * argv for pushing one key. The value is never in it: it arrives on stdin
   * (see `stdin`), or — for CLIs that only read files — via `file`, whose
   * 0600 temp path is passed here as `secretFile`.
   */
  args(key: string, opts: PushOptions, secretFile?: string): string[][];
  /** What the child reads on stdin. Default: the raw value. */
  stdin?(key: string, value: string): string;
  /**
   * Content of a 0600 temp file the CLI consumes (a dotenv line). Set only
   * for CLIs with no stdin path at all; the file is removed in a `finally`.
   */
  file?(key: string, value: string): string;
  installHint: string;
}

/**
 * fly's `secrets import` parser (internal/command/secrets/parser.go) cuts an
 * unquoted value at the first `#` and strips surrounding quotes; a
 * triple-quoted value is taken verbatim, newlines included. Random secrets
 * contain `#` often enough that quoting is not optional.
 */
function flyImportLine(key: string, value: string): string {
  return `${key}="""${value}"""\n`;
}

/**
 * One line the `dotenv` parser (which `netlify env:import` uses) reads back
 * exactly. Single quotes are literal in dotenv, so they are the default; a
 * value that itself contains `'` falls back to double quotes (where only the
 * escapes `\n`/`\r` expand), and only a value that has both quote kinds or a
 * newline goes out raw (where `#` starts a comment).
 */
function dotenvLine(key: string, value: string): string {
  if (!/['\r\n]/.test(value)) return `${key}='${value}'\n`;
  if (!/["\r\n]/.test(value) && !/\\[nr]/.test(value)) return `${key}="${value}"\n`;
  return `${key}=${value}\n`;
}

const TARGETS: Record<PushTarget, TargetCommand> = {
  github: {
    binary: "gh",
    args: (key, opts) => [["secret", "set", key, ...(opts.repo ? ["--repo", opts.repo] : [])]],
    installHint: "install the GitHub CLI: https://cli.github.com (then `gh auth login`)",
  },
  vercel: {
    binary: "vercel",
    // One invocation per environment — `vercel env add` takes a single target.
    args: (key, opts) =>
      (opts.vercelEnvs ?? ["production"]).map((env) => ["env", "add", key, env, "--force"]),
    installHint: "install the Vercel CLI: npm i -g vercel (then `vercel link` in the project)",
  },
  cloudflare: {
    binary: "wrangler",
    args: (key) => [["secret", "put", key]],
    installHint: "install Wrangler: npm i -g wrangler (then `wrangler login`)",
  },
  fly: {
    binary: "flyctl",
    // `flyctl secrets set KEY=VALUE` is argv-only; `secrets import` reads
    // NAME=VALUE lines from stdin instead, so the key travels there too.
    args: (_key, opts) => [["secrets", "import", ...(opts.app ? ["--app", opts.app] : [])]],
    stdin: flyImportLine,
    installHint: "install flyctl: https://fly.io/docs/flyctl/install/ (then `flyctl auth login`)",
  },
  railway: {
    binary: "railway",
    // Railway CLI >= 4 reads the value from stdin with `variable set KEY --stdin`
    // (trailing newline trimmed); `--set KEY=VALUE` is the argv-only legacy form.
    args: (key, opts) => [
      [
        "variable",
        "set",
        key,
        "--stdin",
        ...(opts.service ? ["--service", opts.service] : []),
        ...(opts.railwayEnv ? ["--environment", opts.railwayEnv] : []),
      ],
    ],
    installHint: "install the Railway CLI: https://docs.railway.com/guides/cli (then `railway login`)",
  },
  netlify: {
    binary: "netlify",
    // `netlify env:set KEY VALUE` is argv-only and the CLI reads nothing from
    // stdin, so the value goes through a 0600 dotenv temp file consumed by
    // `env:import <file>` (which merges into the site's existing variables,
    // in every deploy context — env:import has no --context flag).
    args: (_key, opts, secretFile) => [
      ["env:import", secretFile ?? "", ...(opts.site ? ["--site", opts.site] : [])],
    ],
    file: dotenvLine,
    installHint:
      "install the Netlify CLI: https://docs.netlify.com/cli/get-started/ (then `netlify login` and `netlify link`)",
  },
};

function binaryAvailable(binary: string): boolean {
  const probe = spawnSync(binary, ["--version"], { stdio: "ignore", shell: false });
  return !probe.error;
}

/**
 * Run `fn` with a 0600 file holding `content`, inside a fresh 0700 mkdtemp
 * dir under os.tmpdir(); the whole dir is removed afterwards, success or not.
 */
function withSecretFile<T>(content: string, fn: (path: string) => T): T {
  const dir = mkdtempSync(join(tmpdir(), "qring-push-"));
  try {
    const file = join(dir, "secret.env");
    writeFileSync(file, content, { mode: 0o600, flag: "wx" });
    return fn(file);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/** Where the push landed, for the audit detail text. */
function destination(opts: PushOptions): string {
  const where = opts.repo ?? opts.app ?? opts.site ?? opts.service;
  return where ? ` (${where})` : "";
}

/** Resolve which keys a push covers: explicit list, else the manifest. */
export function resolvePushKeys(opts: PushOptions): string[] {
  if (opts.keys?.length) return opts.keys;
  const config = readProjectConfig(opts.projectPath);
  const manifestKeys = Object.keys(config?.secrets ?? {});
  if (manifestKeys.length === 0) {
    throw new Error(
      "Nothing to push: no --keys given and no secrets manifest in .q-ring.json. " +
        "Declare the project's secrets there or pass --keys KEY1,KEY2.",
    );
  }
  return manifestKeys;
}

export function pushSecrets(opts: PushOptions): PushResult {
  const target = TARGETS[opts.target];
  const keys = resolvePushKeys(opts);

  if (!opts.dryRun && !binaryAvailable(target.binary)) {
    throw new Error(`"${target.binary}" CLI not found — ${target.installHint}`);
  }

  const result: PushResult = { target: opts.target, pushed: [], failed: [], missing: [] };

  for (const key of keys) {
    const preset = opts.presetValues?.[key];
    const value =
      preset !== undefined
        ? preset
        : resolveRef(
            { key, raw: `push:${key}` },
            {
              projectPath: opts.projectPath,
              env: opts.env,
              source: opts.source ?? "cli",
              silent: opts.silent,
            },
          );
    if (value === null) {
      result.missing.push(key);
      continue;
    }

    if (opts.dryRun) {
      result.pushed.push(key);
      continue;
    }

    // File-fed CLIs get nothing on stdin; the value lives only in the temp file.
    const input = target.file ? "" : (target.stdin?.(key, value) ?? value);
    const invoke = (secretFile?: string): string | null => {
      for (const args of target.args(key, opts, secretFile)) {
        const child = spawnSync(target.binary, args, {
          input,
          cwd: opts.projectPath,
          encoding: "utf8",
          shell: false,
        });
        if (child.status !== 0) {
          return child.stderr?.trim() || child.error?.message || `exit ${child.status}`;
        }
      }
      return null;
    };
    const failedInvocation = target.file
      ? withSecretFile(target.file(key, value), invoke)
      : invoke();

    if (failedInvocation) {
      result.failed.push({ key, error: failedInvocation });
      continue;
    }

    result.pushed.push(key);
    if (!opts.silent) {
      logAudit({
        action: "push",
        key,
        env: opts.env,
        source: opts.source ?? "cli",
        detail: `${opts.canaryKeys?.includes(key) ? "canary honeytoken " : ""}pushed to ${opts.target}${destination(opts)}`,
      });
    }
  }

  return result;
}
