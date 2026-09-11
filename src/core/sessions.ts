/**
 * Agent session timeline.
 *
 * v0.16 stamped every audit event with the connecting MCP client's identity
 * label (`agent`, from the initialize handshake) and airlock events with a
 * per-session `correlationId`. This module folds those events back into
 * sessions — one timeline per agent process — so an operator can answer
 * "what did Cursor do in that session?" instead of scanning a flat feed.
 *
 * Grouping rules:
 * - Airlock ("wrap") events group by their correlationId: one wrapped-server
 *   session is one timeline, whatever the host pid.
 * - Every other event groups by `pid` + `agent` label. MCP-sourced events
 *   without a label form an "unlabeled" session per pid.
 * - Plain CLI events carry no agent identity and are not sessions.
 *
 * Two audiences, two views. Operators (dashboard, `qring audit:sessions`)
 * see everything. Agents (the `qring://sessions` MCP resources) must never
 * see canary trips — a honeytoken's whole value is that nothing reading the
 * ring can tell it apart — so `agentVisibleEvents` strips them BEFORE any
 * summary is computed, and the summary never leaks a canary key name.
 */

import { queryAudit, type AuditEvent, type AuditAction } from "./observer.js";

export interface AgentSession {
  /** Stable id: the airlock correlationId, or `${pid}-${agent slug}` */
  id: string;
  /** Agent label (clientInfo name@version) or "unlabeled" */
  agent: string;
  /** Dominant event source in the session */
  source: AuditEvent["source"];
  pid: number;
  startedAt: string;
  endedAt: string;
  eventCount: number;
  countsByAction: Partial<Record<AuditAction, number>>;
  /** Unique key names touched (never values) */
  keys: string[];
  /** policy_deny events */
  denials: number;
  /** Set when the session is an MCP airlock: the wrapped command label */
  wrapLabel?: string;
  /** Events, most recent first, capped by `maxEvents` */
  events: AuditEvent[];
}

export interface SessionQuery {
  since?: string;
  /** Max sessions returned (most recent first) */
  limit?: number;
  /** Exact agent label filter */
  agent?: string;
  /** Cap on events kept per session (default 200) */
  maxEvents?: number;
}

const DEFAULT_MAX_EVENTS = 200;
const UNLABELED = "unlabeled";

function slug(label: string): string {
  return (
    label
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "")
      .slice(0, 48) || UNLABELED
  );
}

/** Which session an event belongs to, or null when it is not agent activity. */
export function sessionKeyFor(event: AuditEvent): string | null {
  if (event.action === "wrap" && event.correlationId) return `wrap:${event.correlationId}`;
  if (event.agent) return `pid:${event.pid}:${slug(event.agent)}`;
  if (event.source === "mcp" || event.source === "agent") return `pid:${event.pid}:${UNLABELED}`;
  return null;
}

function wrapLabelFrom(detail: string | undefined): string | undefined {
  const m = detail?.match(/^airlock session started: (.+?)(?: \(env (?:inherited|stripped)\))?$/);
  return m?.[1];
}

/**
 * Fold a flat event list into sessions. Pure: takes events in any order,
 * returns sessions most-recently-active first.
 */
export function buildSessions(
  events: AuditEvent[],
  maxEvents = DEFAULT_MAX_EVENTS,
): AgentSession[] {
  const byKey = new Map<string, AuditEvent[]>();
  for (const e of events) {
    const key = sessionKeyFor(e);
    if (!key) continue;
    const bucket = byKey.get(key);
    if (bucket) bucket.push(e);
    else byKey.set(key, [e]);
  }

  const sessions: AgentSession[] = [];
  for (const [key, bucket] of byKey) {
    bucket.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
    const first = bucket[0];
    const last = bucket[bucket.length - 1];

    const countsByAction: Partial<Record<AuditAction, number>> = {};
    const sources = new Map<AuditEvent["source"], number>();
    const keys = new Set<string>();
    let denials = 0;
    let wrapLabel: string | undefined;
    for (const e of bucket) {
      countsByAction[e.action] = (countsByAction[e.action] ?? 0) + 1;
      sources.set(e.source, (sources.get(e.source) ?? 0) + 1);
      if (e.key) keys.add(e.key);
      if (e.action === "policy_deny") denials++;
      if (!wrapLabel && e.action === "wrap") wrapLabel = wrapLabelFrom(e.detail);
    }
    const source = [...sources.entries()].sort((a, b) => b[1] - a[1])[0][0];
    const agent = bucket.find((e) => e.agent)?.agent ?? UNLABELED;
    const isWrap = key.startsWith("wrap:");

    sessions.push({
      id: isWrap ? key.slice("wrap:".length) : `${first.pid}-${slug(agent)}`,
      agent,
      source,
      pid: first.pid,
      startedAt: first.timestamp,
      endedAt: last.timestamp,
      eventCount: bucket.length,
      countsByAction,
      keys: [...keys].sort(),
      denials,
      ...(isWrap ? { wrapLabel: wrapLabel ?? "(unknown command)" } : {}),
      events: bucket.slice(-maxEvents).reverse(),
    });
  }

  sessions.sort((a, b) => new Date(b.endedAt).getTime() - new Date(a.endedAt).getTime());
  return sessions;
}

/**
 * Operator-only: canary trips stay in. Drop them with `agentVisibleEvents`
 * before handing anything to an agent surface.
 */
export function agentVisibleEvents(events: AuditEvent[]): AuditEvent[] {
  return events.filter((e) => e.action !== "canary");
}

function loadEvents(query: SessionQuery): AuditEvent[] {
  return queryAudit({ since: query.since, agent: query.agent }).filter((e) => e.action !== "list");
}

/** Operator view: every event, canary trips included. */
export function listAgentSessions(query: SessionQuery = {}): AgentSession[] {
  const sessions = buildSessions(loadEvents(query), query.maxEvents);
  return query.limit ? sessions.slice(0, query.limit) : sessions;
}

/** Agent view (MCP resources): canary trips removed before summarising. */
export function listAgentSessionsForAgents(query: SessionQuery = {}): AgentSession[] {
  const sessions = buildSessions(agentVisibleEvents(loadEvents(query)), query.maxEvents);
  return query.limit ? sessions.slice(0, query.limit) : sessions;
}

/** Strip the per-event timeline, leaving the summary. */
export function summariseSession(session: AgentSession): Omit<AgentSession, "events"> {
  const { events: _events, ...summary } = session;
  return summary;
}
