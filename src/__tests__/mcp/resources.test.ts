import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";

vi.mock("@napi-rs/keyring", async () => {
  const fake = await import("../helpers/fake-keyring.js");
  return { Entry: fake.FakeEntry, findCredentials: fake.findCredentials };
});

import { createMcpServer } from "../../mcp/server.js";
import { logAudit, setAuditAgentLabel } from "../../core/observer.js";
import { clearPolicyCache, setPolicyRoot } from "../../core/policy.js";
import { resetFakeKeyring } from "../helpers/fake-keyring.js";

let auditDir: string;
let projectDir: string;
const originalCwd = process.cwd();

beforeEach(() => {
  resetFakeKeyring();
  setAuditAgentLabel(null);
  auditDir = mkdtempSync(join(tmpdir(), "qring-resources-audit-"));
  projectDir = mkdtempSync(join(tmpdir(), "qring-resources-project-"));
  process.env.QRING_AUDIT_DIR = auditDir;
  process.chdir(projectDir);
  clearPolicyCache();
});
afterEach(() => {
  setAuditAgentLabel(null);
  process.chdir(originalCwd);
  setPolicyRoot(originalCwd);
  clearPolicyCache();
  delete process.env.QRING_AUDIT_DIR;
  rmSync(auditDir, { recursive: true, force: true });
  rmSync(projectDir, { recursive: true, force: true });
});

/** Resource contents are a text|blob union; every resource here is JSON text. */
function textOf(result: { contents: ({ text?: string } | { blob?: string })[] }): string {
  const first = result.contents[0];
  if (!("text" in first) || typeof first.text !== "string")
    throw new Error("expected text contents");
  return first.text;
}

async function connect() {
  const server = createMcpServer();
  const client = new Client({ name: "resources-test", version: "1.0" });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  await client.connect(clientTransport);
  return {
    client,
    close: async () => {
      await client.close();
      await server.close();
    },
  };
}

function seedSession() {
  setAuditAgentLabel("cursor@1.0.0");
  logAudit({ action: "read", key: "OPENAI_API_KEY", scope: "q-ring:global", source: "mcp" });
  logAudit({
    action: "canary",
    key: "AWS_TRAP",
    scope: "q-ring:global",
    source: "mcp",
    detail: "CANARY TRIPPED: honeytoken read via mcp",
  });
  logAudit({ action: "policy_deny", key: "PROD_DB", scope: "q-ring:global", source: "mcp" });
  setAuditAgentLabel(null);
}

describe("MCP resources: agent sessions", () => {
  it("advertises the sessions resource and the per-session template", async () => {
    const { client, close } = await connect();
    try {
      const { resources } = await client.listResources();
      expect(resources.map((r) => r.uri)).toContain("qring://sessions");
      const { resourceTemplates } = await client.listResourceTemplates();
      expect(resourceTemplates.map((t) => t.uriTemplate)).toContain("qring://sessions/{id}");
    } finally {
      await close();
    }
  });

  it("lists session summaries (no events) and reads one session's timeline", async () => {
    seedSession();
    const { client, close } = await connect();
    try {
      const list = await client.readResource({ uri: "qring://sessions" });
      const listed = JSON.parse(textOf(list)) as {
        sessions: { id: string; agent: string; eventCount: number; events?: unknown }[];
      };
      expect(listed.sessions).toHaveLength(1);
      const [summary] = listed.sessions;
      expect(summary.agent).toBe("cursor@1.0.0");
      expect(summary.events).toBeUndefined();

      // The template's list callback enumerates concrete session URIs.
      const { resources } = await client.listResources();
      expect(resources.map((r) => r.uri)).toContain(`qring://sessions/${summary.id}`);

      const one = await client.readResource({ uri: `qring://sessions/${summary.id}` });
      const session = JSON.parse(textOf(one)) as {
        id: string;
        denials: number;
        events: { action: string; key?: string }[];
      };
      expect(session.id).toBe(summary.id);
      expect(session.denials).toBe(1);
      expect(session.events.map((e) => e.action).sort()).toEqual(["policy_deny", "read"]);
    } finally {
      await close();
    }
  });

  it("never exposes a canary trip or its key name to the agent", async () => {
    seedSession();
    const { client, close } = await connect();
    try {
      const list = await client.readResource({ uri: "qring://sessions" });
      const listText = textOf(list);
      expect(listText).not.toContain("canary");
      expect(listText).not.toContain("AWS_TRAP");
      const { sessions } = JSON.parse(listText) as {
        sessions: { id: string; eventCount: number }[];
      };
      expect(sessions[0].eventCount).toBe(2); // read + policy_deny, canary excluded

      const one = await client.readResource({ uri: `qring://sessions/${sessions[0].id}` });
      const text = textOf(one);
      expect(text).not.toContain("canary");
      expect(text).not.toContain("AWS_TRAP");
    } finally {
      await close();
    }
  });

  it("errors on an unknown session id", async () => {
    const { client, close } = await connect();
    try {
      await expect(client.readResource({ uri: "qring://sessions/nope" })).rejects.toThrow(
        /Session not found/,
      );
    } finally {
      await close();
    }
  });

  it("goes dark when policy denies the audit_log tool", async () => {
    writeFileSync(
      join(projectDir, ".q-ring.json"),
      JSON.stringify({ policy: { mcp: { denyTools: ["audit_log"] } } }),
    );
    clearPolicyCache();
    seedSession();
    const { client, close } = await connect();
    try {
      const list = await client.readResource({ uri: "qring://sessions" });
      expect(JSON.parse(textOf(list))).toEqual({ sessions: [] });
      const { resources } = await client.listResources();
      expect(resources.filter((r) => r.uri.startsWith("qring://sessions/"))).toHaveLength(0);
    } finally {
      await close();
    }
  });
});
