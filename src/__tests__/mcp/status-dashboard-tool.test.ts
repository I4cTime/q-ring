import { describe, it, expect, vi, beforeAll, afterAll } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer } from "node:net";
import { join } from "node:path";
import { tmpdir } from "node:os";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

vi.mock("@napi-rs/keyring", async () => {
  const fake = await import("../helpers/fake-keyring.js");
  return { Entry: fake.FakeEntry, findCredentials: fake.findCredentials };
});

vi.mock("../../core/notify.js", () => ({
  notificationsEnabled: vi.fn(() => false),
  notifyUser: vi.fn(() => true),
  notifyApprovalRequested: vi.fn(),
}));

// Pass-through spy: records the options the tool starts the dashboard with
// and keeps the instance so the test can close it.
const started = vi.hoisted(
  () => [] as { options: Record<string, unknown>; instance: { close: () => void } }[],
);
vi.mock("../../core/dashboard.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../core/dashboard.js")>();
  return {
    ...actual,
    startDashboardServer: (options: Parameters<typeof actual.startDashboardServer>[0]) => {
      const instance = actual.startDashboardServer(options);
      started.push({ options: { ...options }, instance });
      return instance;
    },
  };
});

import { setSecret, getSecret } from "../../core/keyring.js";
import { plantCanary } from "../../core/canary.js";
import { registerToolingTools } from "../../mcp/tools/tooling.js";
import { resetFakeKeyring } from "../helpers/fake-keyring.js";

type Snapshot = {
  audit: Record<string, unknown>[];
  anomalies: { events: Record<string, unknown>[] }[];
};

let auditDir: string;
let url: URL;

function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = createServer();
    srv.once("error", reject);
    srv.listen(0, "127.0.0.1", () => {
      const addr = srv.address();
      const port = typeof addr === "object" && addr ? addr.port : 0;
      srv.close(() => resolve(port));
    });
  });
}

beforeAll(async () => {
  resetFakeKeyring();
  auditDir = mkdtempSync(join(tmpdir(), "qring-status-tool-"));
  process.env.QRING_AUDIT_DIR = auditDir;
  setSecret("REAL_KEY", "real-value-1", { scope: "global", source: "cli" });
  plantCanary("TRAP_KEY", { format: "github" });
  getSecret("REAL_KEY", { scope: "global", source: "mcp" });
  getSecret("TRAP_KEY", { scope: "global", source: "mcp" }); // hidden trip
  getSecret("REAL_KEY", { scope: "global", source: "mcp" });

  let tool: ((p: Record<string, unknown>) => Promise<{ content: { text: string }[] }>) | undefined;
  const stub = {
    tool: (n: string, ...rest: unknown[]) => {
      if (n === "status_dashboard") tool = rest[rest.length - 1] as typeof tool;
    },
  };
  registerToolingTools(stub as unknown as McpServer);
  const res = await tool!({ port: await freePort() });
  const match = /http:\/\/127\.0\.0\.1:\d+\/\?token=[\w-]+/.exec(res.content[0].text);
  if (!match) throw new Error(`no dashboard URL in: ${res.content[0].text}`);
  url = new URL(match[0]);
  // Wait until it accepts connections.
  for (let i = 0; i < 50; i++) {
    try {
      await fetch(`${url.origin}/api/status${url.search}`);
      break;
    } catch {
      await new Promise((r) => setTimeout(r, 20));
    }
  }
});

afterAll(() => {
  for (const s of started) s.instance.close();
  delete process.env.QRING_AUDIT_DIR;
  rmSync(auditDir, { recursive: true, force: true });
});

function assertAgentSafe(snap: Snapshot): void {
  const events = [...snap.audit, ...snap.anomalies.flatMap((a) => a.events)];
  expect(events.length).toBeGreaterThan(0);
  for (const e of events) {
    for (const field of ["prevHash", "pid", "correlationId"])
      expect(e[field], field).toBeUndefined();
    expect(["canary", "canary_alert"]).not.toContain(e.action);
  }
  expect(JSON.stringify(snap.audit)).not.toContain("CANARY TRIPPED");
}

describe("status_dashboard (MCP tool) serves the agent view", () => {
  it("starts the dashboard with agentView: true", () => {
    expect(started).toHaveLength(1);
    expect(started[0].options.agentView).toBe(true);
  });

  it("/api/status at the returned URL carries no canary records or chain fields", async () => {
    const res = await fetch(`${url.origin}/api/status${url.search}`);
    expect(res.status).toBe(200);
    assertAgentSafe((await res.json()) as Snapshot);
  });

  it("nor does the first SSE frame", async () => {
    const controller = new AbortController();
    const res = await fetch(`${url.origin}/events${url.search}`, { signal: controller.signal });
    const reader = res.body!.getReader();
    let buffer = "";
    while (!buffer.includes("\n\n")) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += new TextDecoder().decode(value);
    }
    controller.abort();
    assertAgentSafe(JSON.parse(buffer.split("\n\n")[0].replace(/^data: /, "")) as Snapshot);
  });
});
