/**
 * Stronger Approval Workflows (Zero-Trust Agent)
 *
 * Manages scoped, reasoned, time-limited approval tokens for accessing
 * protected secrets via MCP. Each token carries:
 * - Reason: why the approval was granted
 * - Workspace / session binding
 * - HMAC verification to prevent tampering
 * - Expiry enforcement
 *
 * Approvals are stored in a file so the CLI can grant them and the MCP
 * server can read and verify them.
 */

import { existsSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { loadJsonRegistry } from "../utils/registry.js";

export interface ApprovalEntry {
  id: string;
  key: string;
  scope: string;
  /**
   * The resolved service identity the approval is bound to (e.g.
   * `q-ring:project:<hashProjectPath>`), not the coarse `scope` label. This is
   * what actually isolates one project from another — the `scope` string is
   * `"project"` for *every* project. Absent on pre-v0.14 entries; a check that
   * requires a service will not match those (fail closed) — they must be
   * re-granted.
   */
  service?: string;
  reason: string;
  grantedBy: string;
  grantedAt: string;
  expiresAt: string;
  workspace?: string;
  sessionId?: string;
  hmac: string;
}

interface ApprovalRegistry {
  approvals: ApprovalEntry[];
}

function getHmacSecret(): string {
  const dir = join(homedir(), ".config", "q-ring");
  const secretPath = join(dir, ".approval-key");
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true, mode: 0o700 });

  if (existsSync(secretPath)) {
    return readFileSync(secretPath, "utf8").trim();
  }
  const secret = randomBytes(32).toString("hex");
  writeFileSync(secretPath, secret, { mode: 0o600 });
  return secret;
}

function computeHmac(entry: Omit<ApprovalEntry, "hmac">): string {
  // Include every persisted field so workspace/sessionId bindings stay
  // tamper-evident even if they are only surfaced informationally today.
  const payload = [
    entry.id,
    entry.key,
    entry.scope,
    entry.service ?? "",
    entry.reason,
    entry.grantedBy,
    entry.grantedAt,
    entry.expiresAt,
    entry.workspace ?? "",
    entry.sessionId ?? "",
  ].join("|");
  return createHmac("sha256", getHmacSecret()).update(payload).digest("hex");
}

function verifyHmac(entry: ApprovalEntry): boolean {
  const expected = computeHmac(entry);
  const a = Buffer.from(expected, "utf8");
  const b = Buffer.from(entry.hmac, "utf8");
  if (a.length !== b.length) return false;
  try {
    return timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

function getRegistryPath(): string {
  const dir = join(homedir(), ".config", "q-ring");
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
  }
  return join(dir, "approvals.json");
}

function loadRegistry(): ApprovalRegistry {
  return loadJsonRegistry<ApprovalRegistry>(getRegistryPath(), { approvals: [] });
}

function saveRegistry(registry: ApprovalRegistry): void {
  writeFileSync(getRegistryPath(), JSON.stringify(registry, null, 2), { mode: 0o600 });
}

function cleanup(registry: ApprovalRegistry): void {
  const now = Date.now();
  registry.approvals = registry.approvals.filter(
    (a) => new Date(a.expiresAt).getTime() > now,
  );
}

export interface GrantOptions {
  reason?: string;
  grantedBy?: string;
  workspace?: string;
  sessionId?: string;
}

export function grantApproval(
  key: string,
  scope: string,
  service: string,
  ttlSeconds: number = 3600,
  grantOpts: GrantOptions = {},
): ApprovalEntry {
  const registry = loadRegistry();
  cleanup(registry);

  const id = randomBytes(8).toString("hex");
  const grantedAt = new Date().toISOString();
  const expiresAt = new Date(Date.now() + ttlSeconds * 1000).toISOString();

  const partial: Omit<ApprovalEntry, "hmac"> = {
    id,
    key,
    scope,
    service,
    reason: grantOpts.reason ?? "no reason provided",
    grantedBy: grantOpts.grantedBy ?? "cli-user",
    grantedAt,
    expiresAt,
    workspace: grantOpts.workspace,
    sessionId: grantOpts.sessionId,
  };

  const entry: ApprovalEntry = { ...partial, hmac: computeHmac(partial) };

  const existingIdx = registry.approvals.findIndex(
    (a) => a.key === key && a.scope === scope && a.service === service,
  );
  if (existingIdx >= 0) {
    registry.approvals[existingIdx] = entry;
  } else {
    registry.approvals.push(entry);
  }

  saveRegistry(registry);
  return entry;
}

export function revokeApproval(key: string, scope: string, service: string): boolean {
  const registry = loadRegistry();
  const before = registry.approvals.length;
  registry.approvals = registry.approvals.filter(
    (a) => !(a.key === key && a.scope === scope && a.service === service),
  );
  saveRegistry(registry);
  return registry.approvals.length < before;
}

export function hasApproval(key: string, scope: string, service: string): boolean {
  const registry = loadRegistry();
  const entry = registry.approvals.find(
    (a) => a.key === key && a.scope === scope && a.service === service,
  );
  if (!entry) return false;
  if (new Date(entry.expiresAt).getTime() < Date.now()) return false;
  if (!verifyHmac(entry)) return false;
  return true;
}

export function getApprovalDetail(
  key: string,
  scope: string,
  service: string,
): ApprovalEntry | null {
  const registry = loadRegistry();
  const entry = registry.approvals.find(
    (a) => a.key === key && a.scope === scope && a.service === service,
  );
  if (!entry) return null;
  if (new Date(entry.expiresAt).getTime() < Date.now()) return null;
  return entry;
}

/** Count approvals with no service binding (pre-v0.14) — used by `qring doctor`. */
export function countLegacyApprovals(): number {
  return loadRegistry().approvals.filter((a) => a.service === undefined).length;
}

export function listApprovals(): (ApprovalEntry & { valid: boolean; tampered: boolean })[] {
  const registry = loadRegistry();
  const now = Date.now();
  return registry.approvals.map((a) => ({
    ...a,
    valid: new Date(a.expiresAt).getTime() > now,
    tampered: !verifyHmac(a),
  }));
}
