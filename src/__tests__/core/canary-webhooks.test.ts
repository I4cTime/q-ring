import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtempSync, rmSync, statSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

vi.mock("@napi-rs/keyring", async () => {
  const fake = await import("../helpers/fake-keyring.js");
  return { Entry: fake.FakeEntry, findCredentials: fake.findCredentials };
});

vi.mock("../../core/notify.js", () => ({
  notificationsEnabled: vi.fn(() => false),
  notifyUser: vi.fn(() => true),
}));

const httpRequestMock = vi.hoisted(() => vi.fn());
vi.mock("../../utils/http-request.js", () => ({ httpRequest: httpRequestMock }));

const checkSSRFMock = vi.hoisted(() => vi.fn());
vi.mock("../../core/ssrf.js", () => ({
  checkSSRF: checkSSRFMock,
  checkSSRFSync: vi.fn(() => null),
  guardedLookup: vi.fn(),
}));

import {
  addCanaryAlert,
  listCanaryAlerts,
  removeCanaryAlert,
  setCanaryAlertEnabled,
  sendCanaryAlerts,
  buildAlertPayload,
  describeAlertUrl,
  type CanaryAlertEvent,
} from "../../core/canary-webhooks.js";
import { plantCanary } from "../../core/canary.js";
import { resetCanaryAlertThrottle } from "../../core/canary-alert.js";
import { getSecret } from "../../core/keyring.js";
import { queryAudit } from "../../core/observer.js";
import { resetFakeKeyring } from "../helpers/fake-keyring.js";

let dir: string;

const EVENT: CanaryAlertEvent = {
  key: "AWS_SECRET_ACCESS_KEY",
  scope: "global",
  env: "prod",
  source: "mcp",
  agent: "cursor@1.2.3",
  detail: "honeytoken read via mcp",
  timestamp: "2026-09-11T00:00:00.000Z",
};

beforeEach(() => {
  resetFakeKeyring();
  resetCanaryAlertThrottle();
  dir = mkdtempSync(join(tmpdir(), "qring-canary-alerts-"));
  process.env.QRING_CANARY_ALERTS_PATH = join(dir, "canary-alerts.json");
  process.env.QRING_AUDIT_DIR = dir;
  httpRequestMock.mockReset();
  httpRequestMock.mockResolvedValue({ statusCode: 204, body: "", truncated: false });
  checkSSRFMock.mockReset();
  checkSSRFMock.mockResolvedValue(null);
});

afterEach(() => {
  delete process.env.QRING_CANARY_ALERTS_PATH;
  delete process.env.QRING_AUDIT_DIR;
  rmSync(dir, { recursive: true, force: true });
});

describe("canary alert registry", () => {
  it("adds, lists, toggles and removes channels in a 0600 file", () => {
    const ch = addCanaryAlert({ type: "discord", url: "https://discord.com/api/webhooks/1/abc" });
    expect(ch.id).toHaveLength(8);
    expect(ch.enabled).toBe(true);
    expect(listCanaryAlerts().map((c) => c.id)).toEqual([ch.id]);
    expect(statSync(process.env.QRING_CANARY_ALERTS_PATH!).mode & 0o777).toBe(0o600);

    expect(setCanaryAlertEnabled(ch.id, false)).toBe(true);
    expect(listCanaryAlerts()[0].enabled).toBe(false);
    expect(setCanaryAlertEnabled("nope", true)).toBe(false);

    expect(removeCanaryAlert(ch.id)).toBe(true);
    expect(removeCanaryAlert(ch.id)).toBe(false);
    expect(listCanaryAlerts()).toEqual([]);
  });

  it("rejects unknown types and non-http URLs", () => {
    expect(() => addCanaryAlert({ type: "pager" as never, url: "https://x.example" })).toThrow(
      /Unknown alert type/,
    );
    expect(() => addCanaryAlert({ type: "generic", url: "ftp://x.example/hook" })).toThrow(
      /must be http/,
    );
    expect(() => addCanaryAlert({ type: "generic", url: "not a url" })).toThrow(/Invalid/);
  });

  it("redacts webhook paths for display", () => {
    expect(describeAlertUrl("https://discord.com/api/webhooks/123456/verylongsecrettoken")).toBe(
      "https://discord.com/api/web…oken",
    );
  });
});

describe("alert payloads", () => {
  it("shape Discord, Slack, ntfy and generic bodies correctly", () => {
    const discord = JSON.parse(buildAlertPayload("discord", EVENT).body);
    expect(discord.content).toContain("CANARY TRIPPED");
    expect(discord.content).toContain("AWS_SECRET_ACCESS_KEY");

    const slack = JSON.parse(buildAlertPayload("slack", EVENT).body);
    expect(slack.text).toContain("cursor@1.2.3");

    const ntfy = buildAlertPayload("ntfy", EVENT);
    expect(ntfy.headers.Title).toBe("q-ring: CANARY TRIPPED");
    expect(ntfy.headers.Priority).toBe("5");
    expect(ntfy.headers["Content-Type"]).toBe("text/plain");
    expect(ntfy.body).toContain("global/prod");

    const generic = JSON.parse(buildAlertPayload("generic", EVENT).body);
    expect(generic).toMatchObject({
      event: "canary",
      test: false,
      key: "AWS_SECRET_ACCESS_KEY",
      scope: "global",
      env: "prod",
      source: "mcp",
      agent: "cursor@1.2.3",
    });
  });

  it("labels drills as tests", () => {
    const body = buildAlertPayload("ntfy", { ...EVENT, test: true });
    expect(body.headers.Title).toContain("test");
    expect(body.headers.Priority).toBe("3");
  });
});

describe("sendCanaryAlerts", () => {
  it("posts to every enabled channel and skips disabled ones", async () => {
    const a = addCanaryAlert({ type: "discord", url: "https://discord.com/api/webhooks/1/a" });
    const b = addCanaryAlert({ type: "generic", url: "https://hooks.example.com/canary" });
    const off = addCanaryAlert({ type: "slack", url: "https://hooks.slack.com/services/x" });
    setCanaryAlertEnabled(off.id, false);

    const results = await sendCanaryAlerts(EVENT);
    expect(results.map((r) => r.channelId).sort()).toEqual([a.id, b.id].sort());
    expect(results.every((r) => r.success)).toBe(true);
    expect(httpRequestMock).toHaveBeenCalledTimes(2);
    const calls = httpRequestMock.mock.calls.map((c) => c[0]);
    expect(calls.every((c) => c.method === "POST" && c.timeoutMs === 10_000)).toBe(true);
  });

  it("targets a single channel by id, including disabled ones for drills", async () => {
    const off = addCanaryAlert({ type: "ntfy", url: "https://ntfy.sh/topic" });
    setCanaryAlertEnabled(off.id, false);
    const results = await sendCanaryAlerts({ ...EVENT, test: true }, off.id);
    expect(results).toHaveLength(1);
    expect(results[0].channelId).toBe(off.id);
  });

  it("reports failures without throwing", async () => {
    addCanaryAlert({ type: "generic", url: "https://hooks.example.com/canary" });
    httpRequestMock.mockRejectedValueOnce(new Error("ECONNRESET"));
    const results = await sendCanaryAlerts(EVENT);
    expect(results[0].success).toBe(false);
    expect(results[0].message).toBe("ECONNRESET");

    httpRequestMock.mockResolvedValueOnce({ statusCode: 500, body: "", truncated: false });
    const again = await sendCanaryAlerts(EVENT);
    expect(again[0].success).toBe(false);
    expect(again[0].message).toBe("HTTP 500");
  });

  it("refuses SSRF-flagged URLs and audits the block", async () => {
    addCanaryAlert({ type: "generic", url: "https://internal.example/hook" });
    checkSSRFMock.mockResolvedValueOnce("blocked: private address");
    const results = await sendCanaryAlerts(EVENT);
    expect(results[0].success).toBe(false);
    expect(httpRequestMock).not.toHaveBeenCalled();
    const denies = queryAudit({ action: "policy_deny" });
    expect(denies.some((e) => e.detail?.includes("canary alert SSRF blocked"))).toBe(true);
  });

  it("never sends the canary value", async () => {
    addCanaryAlert({ type: "generic", url: "https://hooks.example.com/canary" });
    addCanaryAlert({ type: "discord", url: "https://discord.com/api/webhooks/1/a" });
    const planted = plantCanary("LEAKY", { format: "github" });
    getSecret("LEAKY", { source: "mcp" });
    await vi.waitFor(() => expect(httpRequestMock).toHaveBeenCalledTimes(2));
    for (const [call] of httpRequestMock.mock.calls) {
      expect(call.body).not.toContain(planted.value);
      expect(call.body).toContain("LEAKY");
    }
  });
});

describe("trip wiring", () => {
  it("fires webhooks on a trip even with desktop notifications off, once per throttle window", async () => {
    addCanaryAlert({ type: "generic", url: "https://hooks.example.com/canary" });
    plantCanary("TRIPWIRE", { format: "aws" });
    getSecret("TRIPWIRE", { source: "mcp" });
    getSecret("TRIPWIRE", { source: "mcp" });
    await vi.waitFor(() => expect(httpRequestMock).toHaveBeenCalledTimes(1));
    // Both reads are audited even though only one alert went out.
    expect(queryAudit({ action: "canary", key: "TRIPWIRE" })).toHaveLength(2);
  });
});
