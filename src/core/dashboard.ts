/**
 * Quantum Status Dashboard: local HTTP server with SSE live updates.
 *
 * Collects a full snapshot of all quantum state every few seconds and
 * pushes it to connected browsers. Never exposes secret values.
 */

import { createServer, type IncomingMessage, type ServerResponse, type Server } from "node:http";
import { randomBytes, timingSafeEqual } from "node:crypto";
import { listSecrets } from "./keyring.js";
import { checkDecay, type DecayStatus, type QuantumEnvelope } from "./envelope.js";
import { listEntanglements, type EntanglementPair } from "./entanglement.js";
import { tunnelList } from "./tunnel.js";
import {
  queryAudit,
  detectAnomalies,
  verifyAuditChain,
  type AuditEvent,
  type AccessAnomaly,
  type AuditAction,
} from "./observer.js";
import { collapseEnvironment, readProjectConfig, type CollapseResult } from "./collapse.js";
import { listHooks, type HookEntry, type HookType } from "./hooks.js";
import { listApprovals } from "./approval.js";
import { listMemory } from "./memory.js";
import { getPolicySummary } from "./policy.js";
import { buildSessions, type AgentSession } from "./sessions.js";
import { getDashboardHtml } from "./dashboard-html.js";
import { PACKAGE_VERSION } from "../version.js";

export interface SecretSnapshot {
  key: string;
  scope: string;
  type: "collapsed" | "superposition";
  environments?: string[];
  defaultEnv?: string;
  decay: DecayStatus;
  accessCount: number;
  lastAccessedAt?: string;
  createdAt: string;
  updatedAt: string;
  description?: string;
  tags?: string[];
  entangled?: { service: string; key: string }[];
  /** Validation provider name (e.g. "openai", "stripe") */
  provider?: string;
  /** Whether reads require explicit approval via MCP */
  requiresApproval?: boolean;
  /** Just-In-Time provisioner name, if any */
  jitProvider?: string;
  /** Whether the rotation format is declared on this envelope */
  hasRotationFormat: boolean;
}

export interface TunnelSnapshot {
  id: string;
  createdAt: number;
  expiresAt?: number;
  accessCount: number;
  maxReads?: number;
}

export interface ApprovalSnapshot {
  id: string;
  key: string;
  scope: string;
  reason: string;
  grantedBy: string;
  grantedAt: string;
  expiresAt: string;
  /** Seconds remaining until expiry; negative if expired */
  secondsRemaining: number;
  /** True if HMAC verifies and not expired */
  valid: boolean;
  /** True if HMAC failed (forged/tampered) */
  tampered: boolean;
}

export interface HookSnapshot {
  id: string;
  type: HookType;
  description?: string;
  enabled: boolean;
  match: HookEntry["match"];
  /** A short, human-readable summary of the match criteria */
  matchSummary: string;
}

export interface ManifestSnapshot {
  /** Total declared keys in `.q-ring.json` `secrets` */
  declared: number;
  /** Number marked `required: true` */
  required: number;
  /** Required keys that are missing from project scope */
  missing: string[];
  /** Required keys that are present but expired */
  expired: string[];
  /** Required keys that are present but stale */
  stale: string[];
}

export interface PolicySnapshot {
  hasMcpPolicy: boolean;
  hasExecPolicy: boolean;
  hasSecretPolicy: boolean;
  /** Counts per restriction so the UI can render at-a-glance dots */
  counts: {
    allowTools: number;
    denyTools: number;
    deniedKeys: number;
    deniedTags: number;
    allowCommands: number;
    denyCommands: number;
    requireApprovalForTags: number;
    requireRotationFormatForTags: number;
  };
  maxTtlSeconds?: number;
  maxRuntimeSeconds?: number;
}

export interface AuditMetrics {
  /** Counts grouped by action over the audited window */
  byAction: Record<AuditAction, number>;
  /** Counts by source (cli, mcp, agent, etc.) */
  bySource: Record<string, number>;
  /** Top accessed keys (read action) over the window */
  topRead: Array<{ key: string; reads: number }>;
  /** Total events read for the metrics window */
  total: number;
  /** Window covered by the metrics, in seconds */
  windowSeconds: number;
}

export interface ScopeBreakdown {
  global: number;
  project: number;
  team: number;
  org: number;
}

/**
 * One agent session for the dashboard: the summary plus a short tail of
 * recent event lines. Key NAMES only — the dashboard never renders values.
 */
export interface AgentSessionSnapshot extends Omit<AgentSession, "events"> {
  /** Last few events, most recent first */
  recent: Pick<AuditEvent, "timestamp" | "action" | "key" | "detail">[];
}

const SESSION_RECENT_EVENTS = 10;

export interface DashboardSnapshot {
  /** Snapshot generation timestamp (ISO) */
  timestamp: string;
  /** q-ring version that produced the snapshot */
  version: string;
  /** Project path in use (for manifest/policy resolution) */
  projectPath: string;
  /** All visible secrets (no values) */
  secrets: SecretSnapshot[];
  /** Headline counts of secret health */
  health: { healthy: number; stale: number; expired: number; noDecay: number; total: number };
  /** Counts per scope */
  scopes: ScopeBreakdown;
  /** Secrets that require approval before MCP read */
  protectedCount: number;
  /** Active entanglement links */
  entanglements: EntanglementPair[];
  /** In-memory tunnels */
  tunnels: TunnelSnapshot[];
  /** Recent audit events (most recent first; "list" filtered out) */
  audit: AuditEvent[];
  /** Aggregate audit metrics (read counts, top keys, source breakdown) */
  auditMetrics: AuditMetrics;
  /** Detected access anomalies */
  anomalies: AccessAnomaly[];
  /** Agent sessions in the audit window (per-agent timelines, canary trips included — operator surface) */
  sessions: AgentSessionSnapshot[];
  /** Auto-detected environment & detection source */
  environment: CollapseResult | null;
  /** `.q-ring.json` manifest analysis (declared vs missing) */
  manifest: ManifestSnapshot | null;
  /** Governance policy summary */
  policy: PolicySnapshot;
  /** Active approval tokens (HMAC-verified) */
  approvals: ApprovalSnapshot[];
  /** Registered hooks (shell/http/signal) */
  hooks: HookSnapshot[];
  /** Agent memory key count */
  memoryKeys: number;
  /** Audit hash-chain integrity (same data as `qring audit:verify`) */
  auditChain: {
    intact: boolean;
    totalEvents: number;
    validEvents: number;
    brokenAt?: number;
  };
}

const AUDIT_WINDOW_SECONDS = 24 * 60 * 60; // 24h

function toSecretSnapshot(entry: {
  key: string;
  scope: string;
  envelope?: QuantumEnvelope;
  decay?: DecayStatus;
}): SecretSnapshot {
  const envelope = entry.envelope;
  const decay = envelope
    ? checkDecay(envelope)
    : {
        isExpired: false,
        isStale: false,
        lifetimePercent: 0,
        secondsRemaining: null,
        timeRemaining: null,
      };

  return {
    key: entry.key,
    scope: entry.scope,
    type: envelope?.states ? "superposition" : "collapsed",
    environments: envelope?.states ? Object.keys(envelope.states) : undefined,
    defaultEnv: envelope?.defaultEnv,
    decay,
    accessCount: envelope?.meta.accessCount ?? 0,
    lastAccessedAt: envelope?.meta.lastAccessedAt,
    createdAt: envelope?.meta.createdAt ?? "",
    updatedAt: envelope?.meta.updatedAt ?? "",
    description: envelope?.meta.description,
    tags: envelope?.meta.tags,
    entangled: envelope?.meta.entangled,
    provider: envelope?.meta.provider,
    requiresApproval: envelope?.meta.requiresApproval,
    jitProvider: envelope?.meta.jitProvider,
    hasRotationFormat: !!envelope?.meta.rotationFormat,
  };
}

function summariseHookMatch(match: HookEntry["match"]): string {
  const parts: string[] = [];
  if (match.key) parts.push(`key=${match.key}`);
  if (match.keyPattern) parts.push(`pattern=${match.keyPattern}`);
  if (match.tag) parts.push(`tag=${match.tag}`);
  if (match.scope) parts.push(`scope=${match.scope}`);
  if (match.action?.length) parts.push(`on=${match.action.join("|")}`);
  return parts.length ? parts.join(" · ") : "any change";
}

function buildManifest(projectPath: string, secrets: SecretSnapshot[]): ManifestSnapshot | null {
  const config = readProjectConfig(projectPath);
  if (!config?.secrets) return null;
  const declared = Object.keys(config.secrets);
  const projectSecrets = new Map(
    secrets.filter((s) => s.scope === "project").map((s) => [s.key, s]),
  );

  const required: string[] = [];
  const missing: string[] = [];
  const expired: string[] = [];
  const stale: string[] = [];

  for (const key of declared) {
    const entry = config.secrets[key];
    if (entry.required) required.push(key);
    const present = projectSecrets.get(key);
    if (!present) {
      if (entry.required) missing.push(key);
      continue;
    }
    if (present.decay.isExpired) expired.push(key);
    else if (present.decay.isStale) stale.push(key);
  }

  return {
    declared: declared.length,
    required: required.length,
    missing,
    expired,
    stale,
  };
}

function buildPolicySnapshot(projectPath: string): PolicySnapshot {
  const summary = getPolicySummary(projectPath);
  const mcp = summary.details.mcp ?? {};
  const exec = summary.details.exec ?? {};
  const sec = summary.details.secrets ?? {};
  return {
    hasMcpPolicy: summary.hasMcpPolicy,
    hasExecPolicy: summary.hasExecPolicy,
    hasSecretPolicy: summary.hasSecretPolicy,
    counts: {
      allowTools: mcp.allowTools?.length ?? 0,
      denyTools: mcp.denyTools?.length ?? 0,
      deniedKeys: mcp.deniedKeys?.length ?? 0,
      deniedTags: mcp.deniedTags?.length ?? 0,
      allowCommands: exec.allowCommands?.length ?? 0,
      denyCommands: exec.denyCommands?.length ?? 0,
      requireApprovalForTags: sec.requireApprovalForTags?.length ?? 0,
      requireRotationFormatForTags: sec.requireRotationFormatForTags?.length ?? 0,
    },
    maxTtlSeconds: sec.maxTtlSeconds,
    maxRuntimeSeconds: exec.maxRuntimeSeconds,
  };
}

function buildAuditMetrics(events: AuditEvent[]): AuditMetrics {
  const byAction = {} as Record<AuditAction, number>;
  const bySource: Record<string, number> = {};
  const readCounts = new Map<string, number>();

  for (const e of events) {
    byAction[e.action] = (byAction[e.action] ?? 0) + 1;
    bySource[e.source] = (bySource[e.source] ?? 0) + 1;
    if (e.action === "read" && e.key) {
      readCounts.set(e.key, (readCounts.get(e.key) ?? 0) + 1);
    }
  }

  const topRead = [...readCounts.entries()]
    .map(([key, reads]) => ({ key, reads }))
    .sort((a, b) => b.reads - a.reads)
    .slice(0, 10);

  return {
    byAction,
    bySource,
    topRead,
    total: events.length,
    windowSeconds: AUDIT_WINDOW_SECONDS,
  };
}

export function collectSnapshot(): DashboardSnapshot {
  const projectPath = process.cwd();
  const entries = listSecrets({ source: "api", silent: true, projectPath });

  const secrets = entries.map(toSecretSnapshot);

  let healthy = 0;
  let stale = 0;
  let expired = 0;
  let noDecay = 0;
  let protectedCount = 0;
  const scopes: ScopeBreakdown = { global: 0, project: 0, team: 0, org: 0 };

  for (const s of secrets) {
    if (!s.decay.timeRemaining) noDecay++;
    else if (s.decay.isExpired) expired++;
    else if (s.decay.isStale) stale++;
    else healthy++;
    if (s.requiresApproval) protectedCount++;
    if (s.scope === "global") scopes.global++;
    else if (s.scope === "project") scopes.project++;
    else if (s.scope === "team") scopes.team++;
    else if (s.scope === "org") scopes.org++;
  }

  const auditWindow = queryAudit({
    since: new Date(Date.now() - AUDIT_WINDOW_SECONDS * 1000).toISOString(),
  }).filter((e) => e.action !== "list");

  const recent = auditWindow.slice(0, 80);

  const sessions = buildSessions(auditWindow, SESSION_RECENT_EVENTS).map<AgentSessionSnapshot>(
    ({ events, ...summary }) => ({
      ...summary,
      recent: events.map((e) => ({
        timestamp: e.timestamp,
        action: e.action,
        ...(e.key ? { key: e.key } : {}),
        ...(e.detail ? { detail: e.detail } : {}),
      })),
    }),
  );

  const approvals = listApprovals().map<ApprovalSnapshot>((a) => ({
    id: a.id,
    key: a.key,
    scope: a.scope,
    reason: a.reason,
    grantedBy: a.grantedBy,
    grantedAt: a.grantedAt,
    expiresAt: a.expiresAt,
    secondsRemaining: Math.floor((new Date(a.expiresAt).getTime() - Date.now()) / 1000),
    valid: a.valid && !a.tampered,
    tampered: a.tampered,
  }));

  const hookEntries = listHooks().map<HookSnapshot>((h) => ({
    id: h.id,
    type: h.type,
    description: h.description,
    enabled: h.enabled,
    match: h.match,
    matchSummary: summariseHookMatch(h.match),
  }));

  return {
    timestamp: new Date().toISOString(),
    version: PACKAGE_VERSION,
    projectPath,
    secrets,
    health: { healthy, stale, expired, noDecay, total: secrets.length },
    scopes,
    protectedCount,
    entanglements: listEntanglements(),
    tunnels: tunnelList(),
    audit: recent,
    auditMetrics: buildAuditMetrics(auditWindow),
    anomalies: detectAnomalies(),
    sessions,
    environment: collapseEnvironment({ projectPath }),
    manifest: buildManifest(projectPath, secrets),
    policy: buildPolicySnapshot(projectPath),
    approvals,
    hooks: hookEntries,
    memoryKeys: listMemory().length,
    auditChain: (() => {
      const chain = verifyAuditChain();
      return {
        intact: chain.intact,
        totalEvents: chain.totalEvents,
        validEvents: chain.validEvents,
        ...(chain.brokenAt != null ? { brokenAt: chain.brokenAt } : {}),
      };
    })(),
  };
}

export interface DashboardServerOptions {
  port?: number;
}

// Enforced on every response. The page is fully self-contained (inline
// CSS/JS, no external fetches), so the CSP can deny everything except inline
// code and same-origin SSE. `no-referrer` keeps the ?token= URL out of any
// outbound Referer header; `no-store` keeps the token-bearing HTML out of
// shared caches.
const SECURITY_HEADERS: Record<string, string> = {
  "Content-Security-Policy":
    "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
  "X-Frame-Options": "DENY",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  "Cache-Control": "no-store",
};

function timingSafeStringEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a, "utf8");
  const bb = Buffer.from(b, "utf8");
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

export function startDashboardServer(options: DashboardServerOptions = {}): {
  port: number;
  token: string;
  url: string;
  close: () => void;
  server: Server;
} {
  const port = options.port ?? 9876;
  const clients = new Set<ServerResponse>();
  let intervalHandle: ReturnType<typeof setInterval> | null = null;

  // Per-launch bearer token. The dashboard binds to 127.0.0.1, but on a shared
  // host any local user/process could otherwise read key names, the audit log,
  // and approvals. Every route requires this token (passed as ?token=).
  const token = randomBytes(24).toString("base64url");
  const html = getDashboardHtml(token);

  function broadcast() {
    const snapshot = collectSnapshot();
    const data = `data: ${JSON.stringify(snapshot)}\n\n`;
    for (const res of clients) {
      if (res.writableEnded || res.destroyed) {
        clients.delete(res);
        continue;
      }
      try {
        const ok = res.write(data);
        if (!ok) {
          clients.delete(res);
          try {
            res.end();
          } catch {
            try {
              res.destroy();
            } catch {
              /* noop */
            }
          }
        }
      } catch {
        clients.delete(res);
        try {
          res.end();
        } catch {
          try {
            res.destroy();
          } catch {
            /* noop */
          }
        }
      }
    }
  }

  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    let pathname: string;
    let query: URLSearchParams;
    try {
      const parsed = new URL(req.url ?? "/", "http://127.0.0.1");
      pathname = parsed.pathname;
      query = parsed.searchParams;
    } catch {
      res.writeHead(400, { ...SECURITY_HEADERS, "Content-Type": "text/plain; charset=utf-8" });
      res.end("Bad Request: invalid URL");
      return;
    }

    const provided = query.get("token") ?? "";
    if (!timingSafeStringEqual(provided, token)) {
      res.writeHead(403, { ...SECURITY_HEADERS, "Content-Type": "text/plain; charset=utf-8" });
      res.end("Forbidden: missing or invalid token");
      return;
    }

    if (pathname === "/events") {
      res.writeHead(200, {
        ...SECURITY_HEADERS,
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache",
        Connection: "keep-alive",
      });

      const snapshot = collectSnapshot();
      res.write(`data: ${JSON.stringify(snapshot)}\n\n`);

      clients.add(res);
      req.on("close", () => clients.delete(res));
      return;
    }

    if (pathname === "/api/status") {
      const snapshot = collectSnapshot();
      res.writeHead(200, {
        ...SECURITY_HEADERS,
        "Content-Type": "application/json",
      });
      res.end(JSON.stringify(snapshot, null, 2));
      return;
    }

    res.writeHead(200, { ...SECURITY_HEADERS, "Content-Type": "text/html; charset=utf-8" });
    res.end(html);
  });

  server.listen(port, "127.0.0.1", () => {
    intervalHandle = setInterval(broadcast, 5000);
    if (intervalHandle && typeof intervalHandle === "object" && "unref" in intervalHandle) {
      intervalHandle.unref();
    }
  });

  return {
    port,
    token,
    url: `http://127.0.0.1:${port}/?token=${token}`,
    close: () => {
      if (intervalHandle) clearInterval(intervalHandle);
      for (const res of clients) {
        try {
          res.end();
        } catch {
          /* noop */
        }
      }
      clients.clear();
      server.close();
    },
    server,
  };
}
