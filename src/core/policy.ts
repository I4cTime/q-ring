/**
 * Governance-As-Code Policy Engine
 *
 * Evaluates project-level policies declared in `.q-ring.json` under the
 * `policy` key. Enforces MCP tool gating, key/tag access restrictions,
 * exec allowlists, and mandatory metadata requirements.
 */

import { statSync } from "node:fs";
import { join } from "node:path";
import { z } from "zod";
import { readProjectConfig } from "./collapse.js";

/**
 * Strict schema for the `.q-ring.json` `policy` object. `.strict()` at every
 * level is the point of B3: an unknown key (a typo like `denytools` for
 * `denyTools`) is a hard error rather than a silently-ignored no-op. Because
 * this object is a deny-by-default security control, a misspelled deny rule that
 * is silently dropped fails *open* — the tool/key the user meant to block stays
 * allowed. Validating strictly and failing closed (see loadPolicy) closes that.
 */
const stringArray = z.array(z.string());
const mcpPolicySchema = z
  .object({
    allowTools: stringArray.optional(),
    denyTools: stringArray.optional(),
    readableKeys: stringArray.optional(),
    deniedKeys: stringArray.optional(),
    deniedTags: stringArray.optional(),
  })
  .strict();
const execPolicySchema = z
  .object({
    allowCommands: stringArray.optional(),
    denyCommands: stringArray.optional(),
    maxRuntimeSeconds: z.number().optional(),
    allowNetwork: z.boolean().optional(),
  })
  .strict();
const secretsPolicySchema = z
  .object({
    requireApprovalForTags: stringArray.optional(),
    requireRotationFormatForTags: stringArray.optional(),
    maxTtlSeconds: z.number().optional(),
  })
  .strict();
const policySchema = z
  .object({
    mcp: mcpPolicySchema.optional(),
    exec: execPolicySchema.optional(),
    secrets: secretsPolicySchema.optional(),
  })
  .strict();

export type PolicyConfig = z.infer<typeof policySchema>;

/** Thrown when `.q-ring.json` has a `policy` object that fails validation. */
export class PolicyConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PolicyConfigError";
  }
}

export interface PolicyDecision {
  allowed: boolean;
  reason?: string;
  policySource: string;
}

let cachedPolicy:
  | { path: string; mtimeMs: number; policy: PolicyConfig; error?: undefined }
  | { path: string; mtimeMs: number; error: PolicyConfigError; policy?: undefined }
  | null = null;

/**
 * Trusted policy root. When set (by the MCP server at startup), all policy
 * resolution is anchored here and ignores caller-supplied projectPath. This
 * prevents an MCP agent from escaping project governance by pointing
 * projectPath at a directory that has no (or a weaker) `.q-ring.json`.
 */
let policyRoot: string | null = null;

export function setPolicyRoot(root: string): void {
  policyRoot = root;
  cachedPolicy = null;
}

function resolvePolicyPath(projectPath?: string): string {
  return policyRoot ?? projectPath ?? process.cwd();
}

function configMtime(pp: string): number {
  try {
    return statSync(join(pp, ".q-ring.json")).mtimeMs;
  } catch {
    return 0; // file absent — stable sentinel
  }
}

export function loadPolicy(projectPath?: string): PolicyConfig {
  const pp = resolvePolicyPath(projectPath);
  const mtimeMs = configMtime(pp);
  if (cachedPolicy && cachedPolicy.path === pp && cachedPolicy.mtimeMs === mtimeMs) {
    if (cachedPolicy.error) throw cachedPolicy.error;
    return cachedPolicy.policy;
  }

  const config = readProjectConfig(pp) as { policy?: unknown } | null;
  const rawPolicy = config?.policy;

  if (rawPolicy === undefined || rawPolicy === null) {
    const policy: PolicyConfig = {};
    cachedPolicy = { path: pp, mtimeMs, policy };
    return policy;
  }

  const parsed = policySchema.safeParse(rawPolicy);
  if (!parsed.success) {
    const issues = parsed.error.issues
      .map((i) => `policy${i.path.length ? "." + i.path.join(".") : ""}: ${i.message}`)
      .join("; ");
    const error = new PolicyConfigError(
      `Invalid policy in ${join(pp, ".q-ring.json")} — refusing to run under an ` +
        `unparseable security policy (fail closed). Fix these and retry: ${issues}`,
    );
    // Loud, and cached by mtime so it surfaces on every call until the file is
    // corrected (a dropped deny rule must never silently allow access).
    console.error(`q-ring: ${error.message}`);
    cachedPolicy = { path: pp, mtimeMs, error };
    throw error;
  }

  cachedPolicy = { path: pp, mtimeMs, policy: parsed.data };
  return parsed.data;
}

export function clearPolicyCache(): void {
  cachedPolicy = null;
}

export function checkToolPolicy(toolName: string, projectPath?: string): PolicyDecision {
  const policy = loadPolicy(projectPath);
  if (!policy.mcp) return { allowed: true, policySource: "no-policy" };

  if (policy.mcp.denyTools?.includes(toolName)) {
    return {
      allowed: false,
      reason: `Tool "${toolName}" is denied by project policy`,
      policySource: ".q-ring.json policy.mcp.denyTools",
    };
  }

  if (policy.mcp.allowTools && !policy.mcp.allowTools.includes(toolName)) {
    return {
      allowed: false,
      reason: `Tool "${toolName}" is not in the allowlist`,
      policySource: ".q-ring.json policy.mcp.allowTools",
    };
  }

  return { allowed: true, policySource: ".q-ring.json" };
}

/** Enforce `policy.secrets` from `.q-ring.json` on writes. */
export function checkSecretLifecyclePolicy(
  input: {
    tags?: string[];
    ttlSeconds?: number;
    rotationFormat?: string;
    requiresApproval?: boolean;
  },
  projectPath?: string,
): PolicyDecision {
  const policy = loadPolicy(projectPath);
  if (!policy.secrets) return { allowed: true, policySource: "no-policy" };
  const s = policy.secrets;

  if (s.maxTtlSeconds != null && input.ttlSeconds != null && input.ttlSeconds > s.maxTtlSeconds) {
    return {
      allowed: false,
      reason: `TTL ${input.ttlSeconds}s exceeds policy maximum ${s.maxTtlSeconds}s`,
      policySource: ".q-ring.json policy.secrets.maxTtlSeconds",
    };
  }

  if (s.requireApprovalForTags?.length && input.tags?.length) {
    const hit = input.tags.find((t) => s.requireApprovalForTags!.includes(t));
    if (hit && !input.requiresApproval) {
      return {
        allowed: false,
        reason: `Tag "${hit}" requires explicit approval metadata (set requiresApproval / --requires-approval)`,
        policySource: ".q-ring.json policy.secrets.requireApprovalForTags",
      };
    }
  }

  if (s.requireRotationFormatForTags?.length && input.tags?.length) {
    const hit = input.tags.find((t) => s.requireRotationFormatForTags!.includes(t));
    if (hit && !input.rotationFormat) {
      return {
        allowed: false,
        reason: `Tag "${hit}" requires a rotationFormat to be set`,
        policySource: ".q-ring.json policy.secrets.requireRotationFormatForTags",
      };
    }
  }

  return { allowed: true, policySource: ".q-ring.json" };
}

export function checkKeyReadPolicy(key: string, tags: string[] | undefined, projectPath?: string): PolicyDecision {
  const policy = loadPolicy(projectPath);
  if (!policy.mcp) return { allowed: true, policySource: "no-policy" };

  if (policy.mcp.deniedKeys?.includes(key)) {
    return {
      allowed: false,
      reason: `Key "${key}" is denied by project policy`,
      policySource: ".q-ring.json policy.mcp.deniedKeys",
    };
  }

  if (policy.mcp.readableKeys && !policy.mcp.readableKeys.includes(key)) {
    return {
      allowed: false,
      reason: `Key "${key}" is not in the readable keys allowlist`,
      policySource: ".q-ring.json policy.mcp.readableKeys",
    };
  }

  if (tags && policy.mcp.deniedTags) {
    const blocked = tags.find((t) => policy.mcp!.deniedTags!.includes(t));
    if (blocked) {
      return {
        allowed: false,
        reason: `Tag "${blocked}" is denied by project policy`,
        policySource: ".q-ring.json policy.mcp.deniedTags",
      };
    }
  }

  return { allowed: true, policySource: ".q-ring.json" };
}

export function checkExecPolicy(command: string, projectPath?: string): PolicyDecision {
  const policy = loadPolicy(projectPath);
  if (!policy.exec) return { allowed: true, policySource: "no-policy" };

  if (policy.exec.denyCommands) {
    // Match on token/path boundaries so denying "rm" does not also block
    // "charm" or "npm", while still catching "/usr/bin/rm" and "rm -rf".
    const denied = policy.exec.denyCommands.find((d) => {
      const pattern = new RegExp(
        `(^|[\\s/])${d.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(\\s|$)`,
        "i",
      );
      return pattern.test(command);
    });
    if (denied) {
      return {
        allowed: false,
        reason: `Command containing "${denied}" is denied by project policy`,
        policySource: ".q-ring.json policy.exec.denyCommands",
      };
    }
  }

  if (policy.exec.allowCommands) {
    const normalized = command.trimStart();
    const allowed = policy.exec.allowCommands.some((a) => normalized.startsWith(a));
    if (!allowed) {
      return {
        allowed: false,
        reason: `Command "${command}" is not in the exec allowlist`,
        policySource: ".q-ring.json policy.exec.allowCommands",
      };
    }
  }

  return { allowed: true, policySource: ".q-ring.json" };
}

export function getExecMaxRuntime(projectPath?: string): number | undefined {
  return loadPolicy(projectPath).exec?.maxRuntimeSeconds;
}

export function getPolicySummary(projectPath?: string): {
  hasMcpPolicy: boolean;
  hasExecPolicy: boolean;
  hasSecretPolicy: boolean;
  details: PolicyConfig;
} {
  const policy = loadPolicy(projectPath);
  return {
    hasMcpPolicy: !!policy.mcp,
    hasExecPolicy: !!policy.exec,
    hasSecretPolicy: !!policy.secrets,
    details: policy,
  };
}
