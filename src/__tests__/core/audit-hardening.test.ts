import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";

vi.mock("@napi-rs/keyring", async () => {
  const fake = await import("../helpers/fake-keyring.js");
  return { Entry: fake.FakeEntry, findCredentials: fake.findCredentials };
});

vi.mock("../../core/notify.js", () => ({
  notificationsEnabled: vi.fn(() => false),
  notifyUser: vi.fn(() => true),
  notifyApprovalRequested: vi.fn(),
}));

import {
  logAudit,
  queryAudit,
  exportAudit,
  setAuditAgentLabel,
} from "../../core/observer.js";
import { setSecret, getSecret } from "../../core/keyring.js";
import { plantCanary } from "../../core/canary.js";
import { resetCanaryAlertThrottle } from "../../core/canary-alert.js";
import { createMcpServer } from "../../mcp/server.js";
import { resetFakeKeyring } from "../helpers/fake-keyring.js";

let auditDir: string;

beforeEach(() => {
  resetFakeKeyring();
  resetCanaryAlertThrottle();
  setAuditAgentLabel(null);
  auditDir = mkdtempSync(join(tmpdir(), "qring-audit-hard-"));
  process.env.QRING_AUDIT_DIR = auditDir;
});
afterEach(() => {
  setAuditAgentLabel(null);
  delete process.env.QRING_AUDIT_DIR;
  rmSync(auditDir, { recursive: true, force: true });
});

describe("audit write-time sanitization", () => {
  it("strips control characters from key and detail at write", () => {
    logAudit({
      action: "wrap",
      key: "TOOL\x1b[2K\x1b[1Aname",
      scope: "q-ring:global",
      source: "mcp",
      detail: "failed: \x1b[31mboom\x07\r\n end",
    });
    const [event] = queryAudit({ action: "wrap" });
    expect(event.key).toBe("TOOL[2K[1Aname");
    expect(event.detail).not.toContain("\r");
    expect(event.detail).not.toContain("\n");
    expect(event.detail).not.toContain("\x07");
    expect(event.detail).toContain("boom");
  });

  it("caps oversized detail", () => {
    logAudit({
      action: "wrap",
      scope: "q-ring:global",
      source: "mcp",
      detail: "x".repeat(2000),
    });
    const [event] = queryAudit({ action: "wrap" });
    expect(event.detail!.length).toBeLessThanOrEqual(601);
  });
});

describe("CSV export hardening", () => {
  it("quotes fields RFC-4180 style and defuses formula prefixes", () => {
    logAudit({
      action: "read",
      key: '=cmd|"/c calc"!A1',
      scope: "q-ring:global",
      source: "mcp",
      detail: 'a,b "quoted", c',
    });
    const csv = exportAudit({ format: "csv" });
    const dataRow = csv.split("\n")[1];
    expect(dataRow).toContain('"\'=cmd|""/c calc""!A1"');
    expect(dataRow).toContain('"a,b ""quoted"", c"');
    // Row count intact: injected commas must not create phantom columns.
    expect(dataRow.match(/","/g)!.length).toBe(9);
  });

  it("honors excludeActions", () => {
    logAudit({ action: "canary", key: "C", scope: "q-ring:global", source: "mcp" });
    logAudit({ action: "read", key: "R", scope: "q-ring:global", source: "mcp" });
    const out = exportAudit({ format: "jsonl", excludeActions: ["canary"] });
    expect(out).toContain('"R"');
    expect(out).not.toContain('"canary"');
  });
});

describe("MCP audit surface", () => {
  async function connectHost() {
    const server = createMcpServer();
    const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
    await server.connect(serverSide);
    const host = new Client({ name: "test-host", version: "1.2.3" });
    await host.connect(clientSide);
    return host;
  }

  it("stamps audit events with the client identity from a real initialize", async () => {
    setSecret("STAMPED", "v", { scope: "global", source: "cli" });
    const host = await connectHost();
    await host.callTool({ name: "get_secret", arguments: { key: "STAMPED" } });
    const [read] = queryAudit({ key: "STAMPED", action: "read" });
    expect(read.agent).toBe("test-host@1.2.3");
  });

  it("audit_log hides canary trips from agents and supports the agent filter", async () => {
    plantCanary("HIDDEN_TRIP", { format: "aws" });
    getSecret("HIDDEN_TRIP", { scope: "global", source: "cli" }); // trip it
    expect(queryAudit({ action: "canary" }).length).toBe(1); // operator sees it

    const host = await connectHost();
    const result = await host.callTool({
      name: "audit_log",
      arguments: { limit: 100 },
    });
    const textOut = (result.content as Array<{ text: string }>)[0].text;
    expect(textOut).not.toContain("CANARY TRIPPED");

    const filtered = await host.callTool({
      name: "audit_log",
      arguments: { agent: "nobody@0.0.0", limit: 100 },
    });
    expect((filtered.content as Array<{ text: string }>)[0].text).toContain(
      "No audit events found",
    );
  });

  it("export_audit omits canary events for MCP callers", async () => {
    plantCanary("EXPORT_HIDDEN", { format: "generic" });
    getSecret("EXPORT_HIDDEN", { scope: "global", source: "cli" });

    const host = await connectHost();
    const result = await host.callTool({
      name: "export_audit",
      arguments: { format: "jsonl" },
    });
    const textOut = (result.content as Array<{ text: string }>)[0].text;
    expect(textOut).not.toContain('"canary"');
    expect(textOut).toContain('"read"');
  });

  it("export_audit carries no hash chain that would point at a removed trip", async () => {
    setSecret("REAL_ONE", "real-value-1", { scope: "global", source: "cli" });
    plantCanary("CHAIN_TRAP", { format: "github" });
    getSecret("REAL_ONE", { scope: "global", source: "cli" });
    getSecret("CHAIN_TRAP", { scope: "global", source: "cli" }); // trips: read + canary lines
    getSecret("REAL_ONE", { scope: "global", source: "cli" });

    const host = await connectHost();
    const result = await host.callTool({ name: "export_audit", arguments: { format: "jsonl" } });
    const lines = (result.content as Array<{ text: string }>)[0].text.split("\n").filter(Boolean);
    const events = lines.map((l) => JSON.parse(l) as { prevHash?: string; key?: string });

    // The attack: hash each exported line and look for an event whose
    // prevHash names no exported line; the read just before it tripped.
    const hashes = new Set(lines.map((l) => createHash("sha256").update(l).digest("hex")));
    const orphans = events.filter((e, i) => i > 0 && e.prevHash && !hashes.has(e.prevHash));
    expect(orphans).toEqual([]);
    expect(events.every((e) => e.prevHash === undefined)).toBe(true);

    // The operator's unfiltered export keeps the chain.
    const full = exportAudit({ format: "jsonl" }).split("\n").filter(Boolean);
    const chained = full.slice(1).map((l) => (JSON.parse(l) as { prevHash?: string }).prevHash);
    expect(chained.every(Boolean)).toBe(true);
  });
});
