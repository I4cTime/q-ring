import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { startDashboardServer } from "../../core/dashboard.js";

describe("dashboard server auth + security headers", () => {
  let dash: ReturnType<typeof startDashboardServer>;
  let base: string;

  beforeAll(async () => {
    // Port 0 = ephemeral port from the OS; read the real one off the server.
    dash = startDashboardServer({ port: 0 });
    await new Promise<void>((resolve) => dash.server.once("listening", resolve));
    const addr = dash.server.address();
    if (addr === null || typeof addr === "string") throw new Error("no address");
    base = `http://127.0.0.1:${addr.port}`;
  });

  afterAll(() => {
    dash.close();
  });

  it("rejects requests without a token", async () => {
    const res = await fetch(`${base}/`);
    expect(res.status).toBe(403);
  });

  it("rejects requests with a wrong token", async () => {
    const res = await fetch(`${base}/?token=not-the-token`);
    expect(res.status).toBe(403);
  });

  it("serves the dashboard with the launch token", async () => {
    const res = await fetch(`${base}/?token=${dash.token}`);
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("text/html");
  });

  it("includes audit-chain integrity in the snapshot", async () => {
    const res = await fetch(`${base}/api/status?token=${dash.token}`);
    expect(res.status).toBe(200);
    const snap = (await res.json()) as {
      auditChain: { intact: boolean; totalEvents: number; validEvents: number };
    };
    expect(snap.auditChain).toBeDefined();
    expect(typeof snap.auditChain.intact).toBe("boolean");
    expect(snap.auditChain.totalEvents).toBeGreaterThanOrEqual(0);
  });

  it("includes agent sessions in the snapshot, summaries with a short event tail", async () => {
    const res = await fetch(`${base}/api/status?token=${dash.token}`);
    const snap = (await res.json()) as {
      sessions: {
        id: string;
        agent: string;
        eventCount: number;
        recent: unknown[];
        events?: unknown;
      }[];
    };
    expect(Array.isArray(snap.sessions)).toBe(true);
    for (const s of snap.sessions) {
      expect(typeof s.id).toBe("string");
      expect(typeof s.agent).toBe("string");
      expect(s.events).toBeUndefined();
      expect(s.recent.length).toBeLessThanOrEqual(10);
    }
  });

  it("ships the sessions card in the client bundle and its styles", async () => {
    const res = await fetch(`${base}/?token=${dash.token}`);
    const html = await res.text();
    expect(html).toContain(".sessions-list");
    expect(html).toContain("Agent Sessions (24h)");
  });

  it("serves the entanglement graph and chain badge styles", async () => {
    const res = await fetch(`${base}/?token=${dash.token}`);
    const html = await res.text();
    expect(html).toContain(".entangle-graph");
    expect(html).toContain(".chain-badge");
    expect(html).toContain("chain intact"); // client bundle renders the badge
  });

  it("sends security headers on every response", async () => {
    for (const url of [`${base}/`, `${base}/?token=${dash.token}`]) {
      const res = await fetch(url);
      expect(res.headers.get("content-security-policy")).toContain("default-src 'none'");
      expect(res.headers.get("x-frame-options")).toBe("DENY");
      expect(res.headers.get("x-content-type-options")).toBe("nosniff");
      expect(res.headers.get("referrer-policy")).toBe("no-referrer");
      expect(res.headers.get("cache-control")).toBe("no-store");
    }
  });
});
