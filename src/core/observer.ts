/**
 * Observer Effect: every secret read/write/delete is logged.
 * Audit trail stored at ~/.config/q-ring/audit.jsonl
 *
 * The act of observation changes the state — each access increments
 * the envelope's access counter and records a timestamp.
 *
 * Hash-chain integrity: each event includes a SHA-256 hash of the
 * previous event, creating a tamper-evident chain. If any event is
 * modified or deleted, the chain breaks and `audit:verify` reports it.
 */

import {
  existsSync,
  mkdirSync,
  appendFileSync,
  chmodSync,
  readFileSync,
  openSync,
  fstatSync,
  readSync,
  closeSync,
  statSync,
} from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import { createHash, createHmac, randomBytes } from "node:crypto";
import { Entry } from "@napi-rs/keyring";
import { withFileLock } from "../utils/file-lock.js";

// The audit chain's tamper-evidence root is a keyed anchor — the HMAC of the
// head line — stored in the OS keyring, OUTSIDE the log file. The per-line
// SHA-256 chain (below) stays for cheap in-file consistency and backward
// compatibility, but it's forgeable on its own (no secret). The keyed anchor is
// what defeats tail-truncation and full-file rewrite: an attacker who can write
// audit.jsonl still can't produce a head line whose HMAC matches the anchor, nor
// update the anchor, without OS-keyring access. Fixed key, never rotated.
const AUDIT_KEYRING_SERVICE = "qring-audit-chain";
const AUDIT_KEY_ACCOUNT = "hmac-key";
const AUDIT_ANCHOR_ACCOUNT = "chain-head";

let warnedNoKeyring = false;

/** Random HMAC key from the OS keyring, or null (with a one-time warning). */
function getAuditKey(): Buffer | null {
  try {
    const entry = new Entry(AUDIT_KEYRING_SERVICE, AUDIT_KEY_ACCOUNT);
    const stored = entry.getPassword();
    if (stored) return Buffer.from(stored, "base64");
    const key = randomBytes(32);
    entry.setPassword(key.toString("base64"));
    return key;
  } catch {
    if (!warnedNoKeyring) {
      console.error(
        "q-ring: WARNING — OS keyring unavailable; the audit chain has no keyed " +
          "anchor on this host and is NOT tamper-evident against truncation or " +
          "full-file rewrite. (In-file SHA-256 chaining still detects edits.)",
      );
      warnedNoKeyring = true;
    }
    return null;
  }
}

function headAnchor(line: string, key: Buffer): string {
  return createHmac("sha256", key).update(line).digest("hex");
}

function readStoredAnchor(): string | null {
  try {
    return new Entry(AUDIT_KEYRING_SERVICE, AUDIT_ANCHOR_ACCOUNT).getPassword() ?? null;
  } catch {
    return null;
  }
}

function writeStoredAnchor(hash: string): void {
  try {
    new Entry(AUDIT_KEYRING_SERVICE, AUDIT_ANCHOR_ACCOUNT).setPassword(hash);
  } catch {
    /* ignore — anchor is best-effort when the keyring is unavailable */
  }
}

export type AuditAction =
  | "read"
  | "write"
  | "delete"
  | "list"
  | "export"
  | "generate"
  | "entangle"
  | "tunnel"
  | "teleport"
  | "collapse"
  | "approve"
  | "revoke"
  | "policy_deny"
  | "rotate";

export interface AuditEvent {
  timestamp: string;
  action: AuditAction;
  key?: string;
  scope?: string;
  env?: string;
  source: "cli" | "mcp" | "agent" | "api" | "hook" | "ci";
  detail?: string;
  pid: number;
  /** SHA-256 hash of the previous event line for chain integrity */
  prevHash?: string;
  /** Correlation ID to group related events across a single operation */
  correlationId?: string;
}

function getAuditDir(): string {
  if (process.env.QRING_AUDIT_DIR) {
    if (!existsSync(process.env.QRING_AUDIT_DIR)) {
      mkdirSync(process.env.QRING_AUDIT_DIR, { recursive: true, mode: 0o700 });
    }
    return process.env.QRING_AUDIT_DIR;
  }
  const dir = join(homedir(), ".config", "q-ring");
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
  }
  return dir;
}

function getAuditPath(): string {
  return join(getAuditDir(), "audit.jsonl");
}

function getLastLineHash(): string | undefined {
  const path = getAuditPath();
  if (!existsSync(path)) return undefined;

  try {
    const fd = openSync(path, "r");
    const stat = fstatSync(fd);
    if (stat.size === 0) {
      closeSync(fd);
      return undefined;
    }

    // Read up to the last 8KB to find the last line
    const tailSize = Math.min(stat.size, 8192);
    const buf = Buffer.alloc(tailSize);
    readSync(fd, buf, 0, tailSize, stat.size - tailSize);
    closeSync(fd);

    const tail = buf.toString("utf8");
    const lines = tail.split("\n").filter((l) => l.trim());
    if (lines.length === 0) return undefined;

    const lastLine = lines[lines.length - 1];
    return createHash("sha256").update(lastLine).digest("hex");
  } catch {
    return undefined;
  }
}

export function logAudit(
  event: Omit<AuditEvent, "timestamp" | "pid" | "prevHash">,
): void {
  try {
    // Reading the previous head, appending, and updating the keyed anchor must
    // be one atomic critical section — otherwise two concurrent writers (MCP +
    // CLI + dashboard) can compute the same prevHash/anchor and branch the chain.
    // Reuses the same on-disk lock as the JIT path (B1).
    withFileLock(
      "audit-chain",
      () => {
        const prevHash = getLastLineHash();
        const full: AuditEvent = {
          ...event,
          timestamp: new Date().toISOString(),
          pid: process.pid,
          prevHash,
        };
        const line = JSON.stringify(full);
        const path = getAuditPath();
        appendFileSync(path, line + "\n", { mode: 0o600 });
        // `mode` only applies when appendFileSync creates the file; chmod fixes
        // the perms of a log created by an older (world-readable) version.
        try {
          chmodSync(path, 0o600);
        } catch {
          /* ignore */
        }
        // Advance the keyed anchor to the HMAC of the new head line.
        const key = getAuditKey();
        if (key) writeStoredAnchor(headAnchor(line, key));
      },
      { timeoutMs: 5000 },
    );
  } catch {
    // audit logging (incl. a lock timeout) must never crash the app
  }
}

export interface AuditQuery {
  key?: string;
  action?: AuditAction;
  since?: string;
  limit?: number;
  source?: AuditEvent["source"];
  correlationId?: string;
}

/** Cap bytes read from audit log to avoid loading multi-GB files into memory. */
const MAX_AUDIT_BYTES = 12 * 1024 * 1024;

export function queryAudit(query: AuditQuery = {}): AuditEvent[] {
  const path = getAuditPath();
  if (!existsSync(path)) return [];

  try {
    const st = statSync(path);
    const readStart = st.size > MAX_AUDIT_BYTES ? st.size - MAX_AUDIT_BYTES : 0;
    const readLen = st.size > MAX_AUDIT_BYTES ? MAX_AUDIT_BYTES : st.size;
    const buf = Buffer.alloc(readLen);
    const fd = openSync(path, "r");
    readSync(fd, buf, 0, readLen, readStart);
    closeSync(fd);
    let text = buf.toString("utf8");
    if (readStart > 0) {
      const firstNl = text.indexOf("\n");
      if (firstNl !== -1) text = text.slice(firstNl + 1);
    }
    const lines = text.split("\n").filter((l) => l.trim());

    let events: AuditEvent[] = lines
      .map((line) => {
        try {
          return JSON.parse(line) as AuditEvent;
        } catch {
          return null;
        }
      })
      .filter((e): e is AuditEvent => e !== null);

    if (query.key) events = events.filter((e) => e.key === query.key);
    if (query.action) events = events.filter((e) => e.action === query.action);
    if (query.source) events = events.filter((e) => e.source === query.source);
    if (query.correlationId) events = events.filter((e) => e.correlationId === query.correlationId);
    if (query.since) {
      const since = new Date(query.since).getTime();
      events = events.filter((e) => new Date(e.timestamp).getTime() >= since);
    }

    events.sort(
      (a, b) =>
        new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime(),
    );

    if (query.limit) events = events.slice(0, query.limit);

    return events;
  } catch {
    return [];
  }
}

export interface VerifyResult {
  totalEvents: number;
  validEvents: number;
  brokenAt?: number;
  brokenEvent?: AuditEvent;
  intact: boolean;
  /** Set when the break is explained by something other than a per-line hash. */
  reason?: string;
}

/**
 * Verify the hash-chain integrity of the entire audit log.
 * Returns the first break point if the chain has been tampered with.
 */
export function verifyAuditChain(): VerifyResult {
  const path = getAuditPath();
  if (!existsSync(path)) {
    return { totalEvents: 0, validEvents: 0, intact: true };
  }

  const lines = readFileSync(path, "utf8")
    .split("\n")
    .filter((l) => l.trim());

  if (lines.length === 0) {
    return { totalEvents: 0, validEvents: 0, intact: true };
  }

  let validEvents = 0;

  for (let i = 0; i < lines.length; i++) {
    let event: AuditEvent;
    try {
      event = JSON.parse(lines[i]);
    } catch {
      return {
        totalEvents: lines.length,
        validEvents,
        brokenAt: i,
        intact: false,
      };
    }

    if (i === 0) {
      validEvents++;
      continue;
    }

    const expectedHash = createHash("sha256")
      .update(lines[i - 1])
      .digest("hex");

    if (event.prevHash !== expectedHash) {
      return {
        totalEvents: lines.length,
        validEvents,
        brokenAt: i,
        brokenEvent: event,
        intact: false,
      };
    }

    validEvents++;
  }

  // Keyed-anchor check: the head line's HMAC must match the anchor stored in the
  // keyring. This is what catches tail truncation (the head line changed) and a
  // full self-consistent rewrite (the attacker can't recompute a matching HMAC
  // without the key). Only enforced when both a key and a stored anchor exist —
  // a keyless host, or a log predating the anchor, degrades to per-line checks.
  const key = getAuditKey();
  const anchor = key ? readStoredAnchor() : null;
  if (key && anchor !== null) {
    const head = headAnchor(lines[lines.length - 1], key);
    if (head !== anchor) {
      return {
        totalEvents: lines.length,
        validEvents,
        brokenAt: lines.length - 1,
        intact: false,
        reason:
          "audit head does not match the keyed anchor in the OS keyring — the " +
          "log was truncated or rewritten",
      };
    }
  }

  return { totalEvents: lines.length, validEvents, intact: true };
}

export interface ExportOptions {
  since?: string;
  until?: string;
  format?: "jsonl" | "json" | "csv";
}

/**
 * Export audit events in a portable format, optionally filtered by time range.
 */
export function exportAudit(opts: ExportOptions = {}): string {
  const path = getAuditPath();
  if (!existsSync(path)) return opts.format === "json" ? "[]" : "";

  const lines = readFileSync(path, "utf8")
    .split("\n")
    .filter((l) => l.trim());

  let events: AuditEvent[] = lines
    .map((l) => {
      try {
        return JSON.parse(l) as AuditEvent;
      } catch {
        return null;
      }
    })
    .filter((e): e is AuditEvent => e !== null);

  if (opts.since) {
    const since = new Date(opts.since).getTime();
    events = events.filter((e) => new Date(e.timestamp).getTime() >= since);
  }
  if (opts.until) {
    const until = new Date(opts.until).getTime();
    events = events.filter((e) => new Date(e.timestamp).getTime() <= until);
  }

  if (opts.format === "json") {
    return JSON.stringify(events, null, 2);
  }

  if (opts.format === "csv") {
    const header = "timestamp,action,key,scope,env,source,pid,correlationId,detail";
    const rows = events.map(
      (e) =>
        `${e.timestamp},${e.action},${e.key ?? ""},${e.scope ?? ""},${e.env ?? ""},${e.source},${e.pid},${e.correlationId ?? ""},${(e.detail ?? "").replace(/,/g, ";")}`,
    );
    return [header, ...rows].join("\n");
  }

  return events.map((e) => JSON.stringify(e)).join("\n");
}

export interface AccessAnomaly {
  type: "burst" | "unusual-hour" | "new-source" | "tampered";
  description: string;
  events: AuditEvent[];
}

export function detectAnomalies(key?: string): AccessAnomaly[] {
  const recent = queryAudit({
    key,
    action: "read",
    since: new Date(Date.now() - 3600000).toISOString(),
  });

  const anomalies: AccessAnomaly[] = [];

  if (key && recent.length > 50) {
    anomalies.push({
      type: "burst",
      description: `${recent.length} reads of "${key}" in the last hour`,
      events: recent.slice(0, 10),
    });
  }

  const nightAccess = recent.filter((e) => {
    const hour = new Date(e.timestamp).getHours();
    return hour >= 1 && hour < 5;
  });

  if (nightAccess.length > 0) {
    anomalies.push({
      type: "unusual-hour",
      description: `${nightAccess.length} access(es) during unusual hours (1am-5am)`,
      events: nightAccess,
    });
  }

  const verification = verifyAuditChain();
  if (!verification.intact) {
    anomalies.push({
      type: "tampered",
      description: `Audit chain broken at event #${verification.brokenAt}`,
      events: verification.brokenEvent ? [verification.brokenEvent] : [],
    });
  }

  return anomalies;
}
