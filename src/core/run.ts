/**
 * `qring run` — least-privilege command runner.
 *
 * Where `qring exec` injects every secret in scope, `run` injects only what
 * the project declares: qring:// references found in .env files, plus the
 * keys listed in the .q-ring.json secrets manifest. This is the bridge that
 * lets a .env file be committed (it holds references, not values) while the
 * real secrets stay in the keyring.
 *
 * Environment composition, later sources win:
 *   process.env  <  manifest keys  <  .env files (plain values and resolved refs)
 */

import { existsSync, readFileSync } from "node:fs";
import { join, resolve as resolvePath } from "node:path";
import {
  getProfile,
  enforceExecPolicy,
  spawnRedacted,
  type ExecResult,
} from "./exec.js";
import { parseDotenv } from "./import.js";
import { resolveRef, resolveRefsInMap, isRef } from "./refs.js";
import { readProjectConfig } from "./collapse.js";
import type { KeyringOptions } from "./keyring.js";

export interface RunOptions extends KeyringOptions {
  command: string;
  args: string[];
  /** Explicit .env files; default is ./.env when it exists. */
  envFiles?: string[];
  /** Resolve .q-ring.json manifest keys (default true). */
  useManifest?: boolean;
  /** Exec profile name (unrestricted, restricted, ci). */
  profile?: string;
  captureOutput?: boolean;
  /** Treat missing optional manifest keys as fatal too. */
  strict?: boolean;
}

export interface InjectedVar {
  name: string;
  source: "manifest" | "env-file" | "env-file-ref";
}

export interface RunPlan {
  envFiles: string[];
  injected: InjectedVar[];
  /** Missing required keys (fatal) — manifest required:true or explicit refs. */
  missingRequired: string[];
  /** Missing optional manifest keys (warned, not fatal). */
  missingOptional: string[];
  envMap: Record<string, string>;
  secretsToRedact: string[];
}

/**
 * Compose the child environment for a run without spawning anything.
 * Exposed separately so `qring run --dry-run` and tests can inspect the plan.
 */
export function buildRunPlan(opts: RunOptions): RunPlan {
  const projectPath = opts.projectPath ?? process.cwd();
  const keyringOpts: KeyringOptions = {
    projectPath,
    env: opts.env,
    source: opts.source ?? "cli",
    silent: opts.silent,
  };

  const envMap: Record<string, string> = {};
  for (const [k, v] of Object.entries(process.env)) {
    if (v !== undefined) envMap[k] = v;
  }

  const injected: InjectedVar[] = [];
  const missingRequired: string[] = [];
  const missingOptional: string[] = [];
  const secretsToRedact = new Set<string>();

  // 1. Manifest keys (project scope first, then global — same as auto refs).
  if (opts.useManifest !== false) {
    const config = readProjectConfig(projectPath);
    for (const [key, entry] of Object.entries(config?.secrets ?? {})) {
      const value = resolveRef(
        { key, raw: `manifest:${key}` },
        keyringOpts,
      );
      if (value === null) {
        if (entry.required !== false) missingRequired.push(key);
        else if (opts.strict) missingRequired.push(key);
        else missingOptional.push(key);
        continue;
      }
      envMap[key] = value;
      injected.push({ name: key, source: "manifest" });
      if (value.length > 5) secretsToRedact.add(value);
    }
  }

  // 2. .env files: plain values pass through, qring:// refs resolve.
  const envFiles =
    opts.envFiles ??
    (existsSync(join(projectPath, ".env")) ? [join(projectPath, ".env")] : []);

  for (const file of envFiles) {
    const path = resolvePath(projectPath, file);
    if (!existsSync(path)) {
      throw new Error(`Env file not found: ${path}`);
    }
    const parsed = Object.fromEntries(parseDotenv(readFileSync(path, "utf8")));
    const { resolved, secretValues, missing } = resolveRefsInMap(parsed, keyringOpts);

    for (const [name, value] of Object.entries(resolved)) {
      envMap[name] = value;
      injected.push({
        name,
        source: isRef(parsed[name]) ? "env-file-ref" : "env-file",
      });
    }
    for (const value of secretValues) {
      if (value.length > 5) secretsToRedact.add(value);
    }
    // A ref written into a .env file is an explicit demand — missing is fatal.
    for (const m of missing) missingRequired.push(m.name);
  }

  return {
    envFiles: envFiles.map((f) => resolvePath(projectPath, f)),
    injected,
    missingRequired,
    missingOptional,
    envMap,
    secretsToRedact: [...secretsToRedact],
  };
}

export interface RunResult extends ExecResult {
  plan: RunPlan;
}

export async function runCommand(opts: RunOptions): Promise<RunResult> {
  const profile = getProfile(opts.profile);
  enforceExecPolicy(profile, opts.command, opts.args, opts.projectPath);

  const plan = buildRunPlan(opts);

  if (plan.missingRequired.length > 0) {
    throw new Error(
      `Missing required secrets: ${plan.missingRequired.join(", ")}. ` +
        `Store them with \`qring set <KEY>\` or drop them from the manifest/.env refs.`,
    );
  }

  if (profile.stripEnvVars) {
    for (const key of profile.stripEnvVars) {
      delete plan.envMap[key];
    }
  }

  const result = await spawnRedacted({
    profile,
    command: opts.command,
    args: opts.args,
    envMap: plan.envMap,
    secretsToRedact: plan.secretsToRedact,
    captureOutput: opts.captureOutput,
    projectPath: opts.projectPath,
  });

  return { ...result, plan };
}
