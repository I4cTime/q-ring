import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

vi.mock("@napi-rs/keyring", async () => {
  const fake = await import("../helpers/fake-keyring.js");
  return { Entry: fake.FakeEntry, findCredentials: fake.findCredentials };
});

import { logAudit, setAuditAgentLabel, type AuditEvent } from "../../core/observer.js";
import {
  buildSessions,
  sessionKeyFor,
  agentVisibleEvents,
  listAgentSessions,
  listAgentSessionsForAgents,
  summariseSession,
} from "../../core/sessions.js";
import { resetFakeKeyring } from "../helpers/fake-keyring.js";

let auditDir: string;

beforeEach(() => {
  resetFakeKeyring();
  setAuditAgentLabel(null);
  auditDir = mkdtempSync(join(tmpdir(), "qring-sessions-"));
  process.env.QRING_AUDIT_DIR = auditDir;
});
afterEach(() => {
  setAuditAgentLabel(null);
  delete process.env.QRING_AUDIT_DIR;
  rmSync(auditDir, { recursive: true, force: true });
});

const at = (offsetSeconds: number) =>
  new Date(1_700_000_000_000 + offsetSeconds * 1000).toISOString();

function ev(partial: Partial<AuditEvent> & Pick<AuditEvent, "action" | "source">): AuditEvent {
  return { timestamp: at(0), pid: 100, ...partial };
}

describe("sessionKeyFor", () => {
  it("groups airlock events by correlationId regardless of pid", () => {
    const a = ev({ action: "wrap", source: "mcp", correlationId: "abc", pid: 1 });
    const b = ev({ action: "wrap", source: "cli", correlationId: "abc", pid: 2 });
    expect(sessionKeyFor(a)).toBe("wrap:abc");
    expect(sessionKeyFor(b)).toBe("wrap:abc");
  });

  it("groups labelled events by pid + agent slug", () => {
    const e = ev({ action: "read", source: "mcp", agent: "Cursor@1.2.3", pid: 42 });
    expect(sessionKeyFor(e)).toBe("pid:42:cursor-1-2-3");
  });

  it("puts unlabelled MCP events in an unlabeled session per pid", () => {
    expect(sessionKeyFor(ev({ action: "read", source: "mcp", pid: 7 }))).toBe("pid:7:unlabeled");
  });

  it("does not treat plain CLI events as sessions", () => {
    expect(sessionKeyFor(ev({ action: "read", source: "cli" }))).toBeNull();
  });
});

describe("buildSessions", () => {
  it("folds events into sessions with counts, keys, denials, and ordering", () => {
    const events: AuditEvent[] = [
      ev({ action: "read", source: "mcp", agent: "cursor@1", pid: 1, key: "B", timestamp: at(10) }),
      ev({ action: "read", source: "mcp", agent: "cursor@1", pid: 1, key: "A", timestamp: at(5) }),
      ev({
        action: "policy_deny",
        source: "mcp",
        agent: "cursor@1",
        pid: 1,
        key: "A",
        timestamp: at(20),
      }),
      ev({ action: "write", source: "mcp", agent: "kiro@2", pid: 2, key: "C", timestamp: at(100) }),
    ];
    const sessions = buildSessions(events);
    expect(sessions.map((s) => s.agent)).toEqual(["kiro@2", "cursor@1"]); // most recent first

    const cursor = sessions[1];
    expect(cursor.id).toBe("1-cursor-1");
    expect(cursor.startedAt).toBe(at(5));
    expect(cursor.endedAt).toBe(at(20));
    expect(cursor.eventCount).toBe(3);
    expect(cursor.countsByAction).toEqual({ read: 2, policy_deny: 1 });
    expect(cursor.keys).toEqual(["A", "B"]);
    expect(cursor.denials).toBe(1);
    expect(cursor.wrapLabel).toBeUndefined();
    expect(cursor.events.map((e) => e.timestamp)).toEqual([at(20), at(10), at(5)]);
  });

  it("makes an airlock session one timeline with its wrap label", () => {
    const events: AuditEvent[] = [
      ev({
        action: "wrap",
        source: "cli",
        correlationId: "sess-1",
        pid: 9,
        detail: "airlock session started: npx some-server (env stripped)",
        timestamp: at(0),
      }),
      ev({
        action: "wrap",
        source: "mcp",
        correlationId: "sess-1",
        pid: 9,
        agent: "claude-code@1",
        detail: 'tool call "search" → npx some-server',
        timestamp: at(3),
      }),
    ];
    const [session] = buildSessions(events);
    expect(session.id).toBe("sess-1");
    expect(session.wrapLabel).toBe("npx some-server");
    expect(session.agent).toBe("claude-code@1");
    expect(session.source).toBe("cli"); // tie → first seen wins, both present
    expect(session.eventCount).toBe(2);
  });

  it("caps the events kept per session", () => {
    const events = Array.from({ length: 30 }, (_, i) =>
      ev({ action: "read", source: "mcp", agent: "a@1", key: `K${i}`, timestamp: at(i) }),
    );
    const [session] = buildSessions(events, 5);
    expect(session.eventCount).toBe(30);
    expect(session.events).toHaveLength(5);
    expect(session.events[0].timestamp).toBe(at(29));
  });
});

describe("canary visibility", () => {
  it("agentVisibleEvents strips canary trips and nothing else", () => {
    const events: AuditEvent[] = [
      ev({ action: "canary", source: "mcp", agent: "a@1", key: "AWS_TRAP" }),
      ev({ action: "read", source: "mcp", agent: "a@1", key: "REAL" }),
    ];
    expect(agentVisibleEvents(events).map((e) => e.action)).toEqual(["read"]);
  });

  it("the agent view never leaks a canary key name, the operator view keeps it", () => {
    setAuditAgentLabel("cursor@9");
    logAudit({ action: "read", key: "OPENAI_API_KEY", scope: "q-ring:global", source: "mcp" });
    logAudit({
      action: "canary",
      key: "AWS_TRAP",
      scope: "q-ring:global",
      source: "mcp",
      detail: "CANARY TRIPPED",
    });

    const operator = listAgentSessions();
    expect(operator).toHaveLength(1);
    expect(operator[0].keys).toContain("AWS_TRAP");
    expect(operator[0].countsByAction.canary).toBe(1);

    const agentView = listAgentSessionsForAgents();
    expect(agentView).toHaveLength(1);
    expect(agentView[0].keys).toEqual(["OPENAI_API_KEY"]);
    expect(agentView[0].countsByAction.canary).toBeUndefined();
    expect(agentView[0].eventCount).toBe(1);
    expect(JSON.stringify(agentView)).not.toContain("AWS_TRAP");
  });
});

describe("listAgentSessions", () => {
  it("applies agent filter and limit, and ignores list events", () => {
    setAuditAgentLabel("cursor@1");
    logAudit({ action: "list", scope: "q-ring:global", source: "mcp" });
    logAudit({ action: "read", key: "A", scope: "q-ring:global", source: "mcp" });
    setAuditAgentLabel("kiro@1");
    logAudit({ action: "read", key: "B", scope: "q-ring:global", source: "mcp" });

    expect(listAgentSessions()).toHaveLength(2);
    expect(listAgentSessions({ limit: 1 })).toHaveLength(1);
    const only = listAgentSessions({ agent: "cursor@1" });
    expect(only).toHaveLength(1);
    expect(only[0].eventCount).toBe(1);
    expect(only[0].countsByAction.list).toBeUndefined();
  });

  it("summariseSession drops the events array", () => {
    setAuditAgentLabel("cursor@1");
    logAudit({ action: "read", key: "A", scope: "q-ring:global", source: "mcp" });
    const summary = summariseSession(listAgentSessions()[0]);
    expect("events" in summary).toBe(false);
    expect(summary.eventCount).toBe(1);
  });
});
