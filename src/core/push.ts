/**
 * `qring push` — bridge secrets out to deployment platforms.
 *
 * Pushes keyring secrets to GitHub Actions, Vercel, or Cloudflare Workers
 * through each platform's OWN authenticated CLI (gh / vercel / wrangler).
 * q-ring never holds platform tokens, and secret values travel over the
 * child's stdin — never argv, which is world-readable via /proc.
 *
 * Which keys move is the project's declared contract: the .q-ring.json
 * secrets manifest by default, or an explicit --keys list. Every pushed key
 * is written to the audit chain as a "push" event (deliberate egress is
 * exactly what an audit log is for).
 */

import { spawnSync } from "node:child_process";
import { resolveRef } from "./refs.js";
import { readProjectConfig } from "./collapse.js";
import { logAudit } from "./observer.js";
import type { KeyringOptions } from "./keyring.js";

export type PushTarget = "github" | "vercel" | "cloudflare";

export const PUSH_TARGETS: PushTarget[] = ["github", "vercel", "cloudflare"];

export interface PushOptions extends KeyringOptions {
  target: PushTarget;
  /** Explicit keys; default is every key in the .q-ring.json manifest. */
  keys?: string[];
  /** GitHub repo (owner/name); default is the repo of the current directory. */
  repo?: string;
  /** Vercel environments to push to (production, preview, development). */
  vercelEnvs?: string[];
  dryRun?: boolean;
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
  /** argv for pushing one key; the value is always piped via stdin. */
  args(key: string, opts: PushOptions): string[][];
  installHint: string;
}

const TARGETS: Record<PushTarget, TargetCommand> = {
  github: {
    binary: "gh",
    args: (key, opts) => [
      ["secret", "set", key, ...(opts.repo ? ["--repo", opts.repo] : [])],
    ],
    installHint: "install the GitHub CLI: https://cli.github.com (then `gh auth login`)",
  },
  vercel: {
    binary: "vercel",
    // One invocation per environment — `vercel env add` takes a single target.
    args: (key, opts) =>
      (opts.vercelEnvs ?? ["production"]).map((env) => [
        "env", "add", key, env, "--force",
      ]),
    installHint: "install the Vercel CLI: npm i -g vercel (then `vercel link` in the project)",
  },
  cloudflare: {
    binary: "wrangler",
    args: (key) => [["secret", "put", key]],
    installHint: "install Wrangler: npm i -g wrangler (then `wrangler login`)",
  },
};

function binaryAvailable(binary: string): boolean {
  const probe = spawnSync(binary, ["--version"], { stdio: "ignore", shell: false });
  return !probe.error;
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
    const value = resolveRef(
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

    let failedInvocation: string | null = null;
    for (const args of target.args(key, opts)) {
      const child = spawnSync(target.binary, args, {
        input: value,
        cwd: opts.projectPath,
        encoding: "utf8",
        shell: false,
      });
      if (child.status !== 0) {
        failedInvocation =
          child.stderr?.trim() || child.error?.message || `exit ${child.status}`;
        break;
      }
    }

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
        detail: `pushed to ${opts.target}${opts.repo ? ` (${opts.repo})` : ""}`,
      });
    }
  }

  return result;
}
