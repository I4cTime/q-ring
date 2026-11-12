import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

vi.mock("@napi-rs/keyring", async () => {
  const fake = await import("../helpers/fake-keyring.js");
  return { Entry: fake.FakeEntry, findCredentials: fake.findCredentials };
});

vi.mock("../../core/notify.js", () => ({
  notificationsEnabled: vi.fn(() => false),
  notifyUser: vi.fn(() => true),
  notifyApprovalRequested: vi.fn(),
}));

import { setSecret, getSecret } from "../../core/keyring.js";
import { plantCanary } from "../../core/canary.js";
import { resetCanaryAlertThrottle } from "../../core/canary-alert.js";
import { startDashboardServer } from "../../core/dashboard.js";
import { resetFakeKeyring } from "../helpers/fake-keyring.js";

type Snapshot = {
  audit: Record<string, unknown>[];
  anomalies: { events: Record<string, unknown>[] }[];
  canaries: {
    key: string;
    scope: string;
    plantedAt?: string;
    trips: number;
    lastTripAt?: string;
    lastTripBy?: string;
  }[];
};

let auditDir: string;
let dash: ReturnType<typeof startDashboardServer>;
let base: string;

beforeEach(async () => {
  resetFakeKeyring();
  resetCanaryAlertThrottle();
  auditDir = mkdtempSync(join(tmpdir(), "qring-dash-agent-"));
  process.env.QRING_AUDIT_DIR = auditDir;
  setSecret("REAL_KEY", "real-value-1", { scope: "global", source: "cli" });
  plantCanary("TRAP_KEY", { format: "github" });
  getSecret("REAL_KEY", { scope: "global", source: "mcp" });
  getSecret("TRAP_KEY", { scope: "global", source: "mcp" }); // read + hidden trip
  getSecret("REAL_KEY", { scope: "global", source: "mcp" });

  // The dashboard the status_dashboard MCP tool starts.
  await startDashboard(true);
});

async function startDashboard(agentView: boolean): Promise<void> {
  dash = startDashboardServer({ port: 0, agentView });
  await new Promise<void>((resolve) => dash.server.once("listening", resolve));
  const addr = dash.server.address();
  if (addr === null || typeof addr === "string") throw new Error("no address");
  base = `http://127.0.0.1:${addr.port}`;
}

afterEach(() => {
  dash.close();
  delete process.env.QRING_AUDIT_DIR;
  rmSync(auditDir, { recursive: true, force: true });
});

const CHAIN_FIELDS = ["prevHash", "pid", "correlationId"];

function assertNoChain(snap: Snapshot): void {
  const events = [...snap.audit, ...snap.anomalies.flatMap((a) => a.events)];
  expect(events.length).toBeGreaterThan(0);
  for (const e of events) {
    for (const field of CHAIN_FIELDS) expect(e[field], field).toBeUndefined();
    expect(["canary", "canary_alert"]).not.toContain(e.action);
  }
  const json = JSON.stringify(snap.audit);
  expect(json).not.toContain("CANARY TRIPPED");
  expect(json).not.toContain("canary");
  // The canaries list is the other way a tripwire could be read off the page.
  expect(snap.canaries).toEqual([]);
}

describe("an agent-view dashboard ships no hash-chain links", () => {
  it("in /api/status", async () => {
    const res = await fetch(`${base}/api/status?token=${dash.token}`);
    assertNoChain((await res.json()) as Snapshot);
  });

  it("in the first SSE frame", async () => {
    const controller = new AbortController();
    const res = await fetch(`${base}/events?token=${dash.token}`, { signal: controller.signal });
    const reader = res.body!.getReader();
    let buffer = "";
    while (!buffer.includes("\n\n")) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += new TextDecoder().decode(value);
    }
    controller.abort();
    const frame = buffer.split("\n\n")[0].replace(/^data: /, "");
    assertNoChain(JSON.parse(frame) as Snapshot);
  });
});

describe("an agent-view dashboard hides the Canary card", () => {
  it("tells the client it is an agent view", async () => {
    const res = await fetch(`${base}/?token=${dash.token}`);
    expect(await res.text()).toContain("agentView:true");
  });
});

describe("the operator's dashboard lists canaries with their trips", () => {
  it("reports the planted canary, its trip count and who tripped it", async () => {
    // Same vault and audit as above, served as the operator's `qring status`.
    dash.close();
    await startDashboard(false);

    const res = await fetch(`${base}/api/status?token=${dash.token}`);
    const snap = (await res.json()) as Snapshot;
    expect(snap.canaries).toHaveLength(1);
    const [canary] = snap.canaries;
    expect(canary.key).toBe("TRAP_KEY");
    expect(canary.scope).toBe("global");
    expect(typeof canary.plantedAt).toBe("string");
    expect(canary.trips).toBe(1);
    expect(typeof canary.lastTripAt).toBe("string");
    expect(canary.lastTripBy).toMatch(/^mcp/);
    // The real key is not a canary.
    expect(snap.canaries.map((c) => c.key)).not.toContain("REAL_KEY");

    const page = await fetch(`${base}/?token=${dash.token}`);
    expect(await page.text()).toContain("agentView:false");
  });
});
