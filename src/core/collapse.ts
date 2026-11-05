/**
 * Wavefunction Collapse: auto-detect the current environment context.
 *
 * Resolution order (first match wins):
 * 1. Explicit --env flag
 * 2. QRING_ENV environment variable
 * 3. NODE_ENV environment variable
 * 4. Git branch heuristics (main/master → prod, develop → dev, staging → staging)
 * 5. .q-ring.json project config
 * 6. Default environment from the envelope
 */

import { execSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { Environment } from "./envelope.js";

const BRANCH_ENV_MAP: Record<string, Environment> = {
  main: "prod",
  master: "prod",
  production: "prod",
  develop: "dev",
  development: "dev",
  dev: "dev",
  staging: "staging",
  stage: "staging",
  test: "test",
  testing: "test",
};

// getSecret/exportSecrets call collapseEnvironment on every read that omits an
// explicit env; without caching that shelled out `git rev-parse` (sync, up to a
// 3s timeout) and re-read .q-ring.json on every call, blocking the MCP event
// loop. Git branch is cached per-cwd for a short window (a branch switch is
// picked up within the TTL); the config is cached by its exact text (always
// current, see readProjectConfig).
const BRANCH_CACHE_TTL_MS = 2000;
let branchCache: { cwd: string; at: number; branch: string | null } | null = null;

function detectGitBranch(cwd?: string): string | null {
  const dir = cwd ?? process.cwd();
  const now = Date.now();
  if (branchCache && branchCache.cwd === dir && now - branchCache.at < BRANCH_CACHE_TTL_MS) {
    return branchCache.branch;
  }
  let branch: string | null = null;
  try {
    const out = execSync("git rev-parse --abbrev-ref HEAD", {
      cwd: dir,
      stdio: ["pipe", "pipe", "pipe"],
      encoding: "utf8",
      timeout: 3000,
    }).trim();
    branch = out || null;
  } catch {
    // not a git repo / git absent — branch stays null
  }
  branchCache = { cwd: dir, at: now, branch };
  return branch;
}

/** Reset the collapse caches (config + git branch). Primarily for tests. */
export function clearCollapseCache(): void {
  branchCache = null;
  clearConfigCache();
}

/** Reset only the `.q-ring.json` cache (clearPolicyCache calls this too). */
export function clearConfigCache(): void {
  configCache = null;
}

export interface ManifestEntry {
  required?: boolean;
  description?: string;
  /** Expected format for auto-rotation (e.g. "api-key", "password", "uuid") */
  format?: string;
  /** Expected prefix (e.g. "sk-") */
  prefix?: string;
  /** Provider name for liveness validation (e.g. "openai", "stripe", "github") */
  provider?: string;
  /** Custom validation URL for generic HTTP provider */
  validationUrl?: string;
}

export interface ProjectConfig {
  env?: Environment;
  defaultEnv?: Environment;
  branchMap?: Record<string, Environment>;
  /** Secrets manifest — declares required/expected secrets for this project */
  secrets?: Record<string, ManifestEntry>;
  /** Governance policy for MCP, exec, and secret lifecycle */
  policy?: import("./policy.js").PolicyConfig;
}

// Keyed on the file's exact text, not on stat fields. An mtime-only key served
// the previous policy when two writes landed in the same millisecond (Windows
// CI, #132), and mtime + size + inode is not enough either: an in-place rewrite
// of equal length keeps the inode and size, and mtime resolution can be coarse.
// The file is a few hundred bytes, so reading it and comparing strings is cheap;
// what the cache saves is the JSON parse and, in loadPolicy, the schema check.
// Callers get the same object back while the text is unchanged, which is what
// loadPolicy keys its own cache on.
const ABSENT = Symbol("absent");
let configCache: {
  path: string;
  raw: string | typeof ABSENT;
  config: ProjectConfig | null;
} | null = null;

export function readProjectConfig(projectPath?: string): ProjectConfig | null {
  const configPath = join(projectPath ?? process.cwd(), ".q-ring.json");
  let raw: string | typeof ABSENT = ABSENT;
  try {
    raw = readFileSync(configPath, "utf8");
  } catch {
    // absent or unreadable: ABSENT is a stable sentinel
  }
  if (configCache && configCache.path === configPath && configCache.raw === raw) {
    return configCache.config;
  }
  let config: ProjectConfig | null = null;
  if (raw !== ABSENT) {
    try {
      config = JSON.parse(raw) as ProjectConfig;
    } catch {
      config = null; // invalid config
    }
  }
  configCache = { path: configPath, raw, config };
  return config;
}

export interface CollapseContext {
  /** Explicitly provided environment */
  explicit?: Environment;
  /** Project path for git/config detection */
  projectPath?: string;
}

export interface CollapseResult {
  env: Environment;
  source:
    | "explicit"
    | "QRING_ENV"
    | "NODE_ENV"
    | "git-branch"
    | "project-config"
    | "default";
}

export function collapseEnvironment(ctx: CollapseContext = {}): CollapseResult | null {
  if (ctx.explicit) {
    return { env: ctx.explicit, source: "explicit" };
  }

  const qringEnv = process.env.QRING_ENV;
  if (qringEnv) {
    return { env: qringEnv, source: "QRING_ENV" };
  }

  const nodeEnv = process.env.NODE_ENV;
  if (nodeEnv) {
    const mapped = mapEnvName(nodeEnv);
    return { env: mapped, source: "NODE_ENV" };
  }

  const config = readProjectConfig(ctx.projectPath);
  if (config?.env) {
    return { env: config.env, source: "project-config" };
  }

  const branch = detectGitBranch(ctx.projectPath);
  if (branch) {
    const branchMap = { ...BRANCH_ENV_MAP, ...config?.branchMap };
    const mapped = branchMap[branch] ?? matchGlob(branchMap, branch);
    if (mapped) {
      return { env: mapped, source: "git-branch" };
    }
  }

  if (config?.defaultEnv) {
    return { env: config.defaultEnv, source: "project-config" };
  }

  return null;
}

/**
 * Match a branch name against glob-style patterns in the branchMap.
 * Supports `*` as a wildcard (e.g., `release/*`, `feature/*`).
 */
const MAX_BRANCH_GLOB_PATTERN_LEN = 200;
const MAX_BRANCH_GLOB_REGEX_SOURCE = 400;

function matchGlob(
  branchMap: Record<string, Environment>,
  branch: string,
): Environment | undefined {
  for (const [pattern, env] of Object.entries(branchMap)) {
    if (!pattern.includes("*")) continue;
    if (pattern.length > MAX_BRANCH_GLOB_PATTERN_LEN) continue;
    const source = "^" + pattern.replace(/\*/g, ".*") + "$";
    if (source.length > MAX_BRANCH_GLOB_REGEX_SOURCE) continue;
    const regex = new RegExp(source);
    if (regex.test(branch)) return env;
  }
  return undefined;
}

function mapEnvName(raw: string): Environment {
  const lower = raw.toLowerCase();
  if (lower === "production") return "prod";
  if (lower === "development") return "dev";
  return lower;
}
