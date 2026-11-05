import { describe, it, expect, beforeAll, afterAll, vi } from "vitest";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

vi.mock("@napi-rs/keyring", async () => {
  const fake = await import("../helpers/fake-keyring.js");
  return { Entry: fake.FakeEntry, findCredentials: fake.findCredentials };
});

import { collectSnapshot, startDashboardServer } from "../../core/dashboard.js";
import { clearPolicyCache } from "../../core/policy.js";
import { getProjectContext } from "../../core/context.js";

// The dashboard (`qring status`) is long-running and reads the policy of its
// cwd on every request and every 5s SSE tick: a corrupt .q-ring.json must be
// reported in the snapshot, not crash the request, the stream or the process.
describe("dashboard under a .q-ring.json that is not valid JSON", () => {
  const originalCwd = process.cwd();
  let dir: string;
  let dash: ReturnType<typeof startDashboardServer>;
  let base: string;

  beforeAll(async () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    dir = mkdtempSync(join(tmpdir(), "qring-dash-corrupt-"));
    writeFileSync(join(dir, ".q-ring.json"), "{ not json");
    process.chdir(dir);
    clearPolicyCache();
    dash = startDashboardServer({ port: 0 });
    await new Promise<void>((resolve) => dash.server.once("listening", resolve));
    const addr = dash.server.address();
    if (addr === null || typeof addr === "string") throw new Error("no address");
    base = `http://127.0.0.1:${addr.port}`;
  });

  afterAll(() => {
    dash.close();
    process.chdir(originalCwd);
    clearPolicyCache();
    rmSync(dir, { recursive: true, force: true });
    vi.restoreAllMocks();
  });

  it("collectSnapshot reports the error with no policy counts", () => {
    const snap = collectSnapshot();
    expect(snap.policy.policyError).toMatch(/not valid JSON/);
    expect(snap.policy.hasMcpPolicy).toBe(false);
    expect(snap.policy.counts.denyTools).toBe(0);
  });

  it("/api/status answers 200 with policyError", async () => {
    const res = await fetch(`${base}/api/status?token=${dash.token}`);
    expect(res.status).toBe(200);
    const snap = (await res.json()) as { policy: { policyError?: string } };
    expect(snap.policy.policyError).toMatch(/not valid JSON/);
  });

  it("the SSE stream sends its first frame with policyError", async () => {
    const ac = new AbortController();
    const res = await fetch(`${base}/events?token=${dash.token}`, { signal: ac.signal });
    expect(res.status).toBe(200);
    const reader = res.body!.getReader();
    let text = "";
    while (!text.includes("\n\n")) {
      const { value, done } = await reader.read();
      if (done) break;
      text += new TextDecoder().decode(value);
    }
    ac.abort();
    const frame = JSON.parse(text.slice("data: ".length, text.indexOf("\n\n"))) as {
      policy: { policyError?: string };
    };
    expect(frame.policy.policyError).toMatch(/not valid JSON/);
  });

  it("qring context (CLI source) still answers: it never consults the policy", () => {
    const ctx = getProjectContext({ projectPath: dir, source: "cli" });
    expect(ctx.projectPath).toBe(dir);
    expect(Array.isArray(ctx.secrets)).toBe(true);
  });

  it("ships the policy-error card in the client bundle", async () => {
    const res = await fetch(`${base}/?token=${dash.token}`);
    expect(await res.text()).toContain("every policy gate refuses until then");
  });
});
