import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

vi.mock("@napi-rs/keyring", async () => {
  const fake = await import("../helpers/fake-keyring.js");
  return { Entry: fake.FakeEntry, findCredentials: fake.findCredentials };
});

vi.mock("../../core/notify.js", () => ({
  notificationsEnabled: vi.fn(() => true),
  notifyUser: vi.fn(() => true),
}));

import {
  plantCanary,
  disarmCanary,
  listCanaries,
  CANARY_FORMATS,
} from "../../core/canary.js";
import { resetCanaryAlertThrottle } from "../../core/canary-alert.js";
import {
  setSecret,
  getSecret,
  getEnvelope,
  deleteSecret,
  exportSecrets,
} from "../../core/keyring.js";
import { queryAudit } from "../../core/observer.js";
import { notifyUser, notificationsEnabled } from "../../core/notify.js";
import { resetFakeKeyring } from "../helpers/fake-keyring.js";

let auditDir: string;

beforeEach(() => {
  resetFakeKeyring();
  resetCanaryAlertThrottle();
  vi.mocked(notifyUser).mockClear();
  vi.mocked(notificationsEnabled).mockReturnValue(true);
  auditDir = mkdtempSync(join(tmpdir(), "qring-canary-"));
  process.env.QRING_AUDIT_DIR = auditDir;
});
afterEach(() => {
  delete process.env.QRING_AUDIT_DIR;
  rmSync(auditDir, { recursive: true, force: true });
});

describe("plantCanary", () => {
  it("generates provider-shaped values", () => {
    const aws = plantCanary("AWS_ACCESS_KEY_ID", { format: "aws" });
    expect(aws.value).toMatch(/^AKIA[A-Z0-9]{16}$/);

    const gh = plantCanary("GH_TOKEN", { format: "github" });
    expect(gh.value).toMatch(/^ghp_[A-Za-z0-9]{36}$/);

    const anthropic = plantCanary("ANTHROPIC_API_KEY", { format: "anthropic" });
    expect(anthropic.value.startsWith("sk-ant-api03-")).toBe(true);
  });

  it("stores canary metadata on the envelope", () => {
    plantCanary("CANARY_KEY", { format: "github" });
    const env = getEnvelope("CANARY_KEY", { scope: "global" });
    expect(env?.envelope.meta.canary).toBe(true);
    expect(env?.envelope.meta.canaryFormat).toBe("github");
  });

  it("accepts a custom value and rejects unknown formats", () => {
    const custom = plantCanary("CUSTOM", { value: "totally-real-key-123" });
    expect(custom.value).toBe("totally-real-key-123");
    expect(() => plantCanary("X", { format: "nope" })).toThrow(/Unknown canary format/);
  });

  it("leaves no description tell for inspect_secret to leak", () => {
    plantCanary("STEALTHY", { format: "aws" });
    const env = getEnvelope("STEALTHY", { scope: "global" });
    expect(env?.envelope.meta.description).toBeUndefined();

    plantCanary("COVERED", { format: "aws", description: "prod db key" });
    expect(
      getEnvelope("COVERED", { scope: "global" })?.envelope.meta.description,
    ).toBe("prod db key");
  });

  it("refuses to overwrite a real secret unless forced (core-level guard)", () => {
    setSecret("REAL_KEY", "real-value", { scope: "global", source: "cli" });
    expect(() => plantCanary("REAL_KEY")).toThrow(/already holds a real secret/);
    expect(getSecret("REAL_KEY", { scope: "global", silent: true })).toBe("real-value");

    const forced = plantCanary("REAL_KEY", { force: true });
    expect(getEnvelope("REAL_KEY", { scope: "global" })?.envelope.meta.canary).toBe(true);
    expect(forced.value).not.toBe("real-value");

    // Replanting over an existing canary never needs force.
    expect(() => plantCanary("REAL_KEY", { format: "github" })).not.toThrow();
  });

  it("a real secret in another scope does not block the plant", () => {
    setSecret("SCOPED", "project-value", {
      scope: "project",
      projectPath: "/tmp/qring-canary-scope-test",
      source: "cli",
    });
    expect(() =>
      plantCanary("SCOPED", {
        scope: "global",
        projectPath: "/tmp/qring-canary-scope-test",
      }),
    ).not.toThrow();
  });

  it("canary values dodge the placeholder heuristic in scan", () => {
    for (const format of Object.values(CANARY_FORMATS)) {
      const v = format.generate().toLowerCase();
      for (const marker of ["example", "your_", "placeholder", "replace_me", "xxx"]) {
        expect(v.includes(marker)).toBe(false);
      }
    }
  });
});

describe("canary trip", () => {
  it("read returns the fake value, logs a canary audit event, and alerts", () => {
    const planted = plantCanary("TRIP_ME", { format: "aws" });

    const value = getSecret("TRIP_ME", { scope: "global", source: "mcp" });
    expect(value).toBe(planted.value); // no tell for the reader

    const trips = queryAudit({ action: "canary", key: "TRIP_ME" });
    expect(trips.length).toBe(1);
    expect(trips[0].source).toBe("mcp");
    expect(vi.mocked(notifyUser)).toHaveBeenCalledTimes(1);
    expect(vi.mocked(notifyUser).mock.calls[0][0]).toContain("CANARY");
  });

  it("throttles desktop alerts but never audit events", () => {
    plantCanary("BURST", { format: "generic" });
    getSecret("BURST", { scope: "global", source: "mcp" });
    getSecret("BURST", { scope: "global", source: "mcp" });
    getSecret("BURST", { scope: "global", source: "mcp" });

    expect(queryAudit({ action: "canary", key: "BURST" }).length).toBe(3);
    expect(vi.mocked(notifyUser)).toHaveBeenCalledTimes(1);
  });

  it("silent reads (dashboard polling) do not trip", () => {
    plantCanary("QUIET", { format: "generic" });
    getSecret("QUIET", { scope: "global", source: "cli", silent: true });
    expect(queryAudit({ action: "canary", key: "QUIET" }).length).toBe(0);
    expect(vi.mocked(notifyUser)).not.toHaveBeenCalled();
  });

  it("respects the notification kill switch but still audits", () => {
    vi.mocked(notificationsEnabled).mockReturnValue(false);
    plantCanary("NO_TOAST", { format: "generic" });
    getSecret("NO_TOAST", { scope: "global", source: "cli" });
    expect(queryAudit({ action: "canary", key: "NO_TOAST" }).length).toBe(1);
    expect(vi.mocked(notifyUser)).not.toHaveBeenCalled();
  });

  it("normal secrets do not trip", () => {
    setSecret("REAL", "value", { scope: "global", source: "cli" });
    getSecret("REAL", { scope: "global", source: "cli" });
    expect(queryAudit({ action: "canary", key: "REAL" }).length).toBe(0);
  });

  it("bulk export trips every included canary and names exported keys", () => {
    setSecret("NORMAL", "v", { scope: "global", source: "cli" });
    plantCanary("SWEPT", { format: "aws" });

    exportSecrets({ scope: "global", source: "mcp" });

    const trips = queryAudit({ action: "canary", key: "SWEPT" });
    expect(trips.length).toBe(1);
    expect(trips[0].source).toBe("mcp");

    const exportEvents = queryAudit({ action: "export" });
    expect(exportEvents[0].detail).toContain("SWEPT");
    expect(exportEvents[0].detail).toContain("NORMAL");
  });

  it("deleting a canary is a trip, not a routine delete", () => {
    plantCanary("TRIPWIRE", { format: "github" });
    deleteSecret("TRIPWIRE", { scope: "global", source: "mcp" });

    const trips = queryAudit({ action: "canary", key: "TRIPWIRE" });
    expect(trips.length).toBe(1);
    expect(trips[0].detail).toContain("deleted");
    expect(vi.mocked(notifyUser)).toHaveBeenCalledTimes(1);
  });
});

describe("disarmCanary", () => {
  it("clears the flag so reads stop alarming", () => {
    plantCanary("DISARM_ME", { format: "generic" });
    expect(disarmCanary("DISARM_ME", { scope: "global" })).toBe(true);

    const env = getEnvelope("DISARM_ME", { scope: "global" });
    expect(env?.envelope.meta.canary).toBeUndefined();
    expect(env?.envelope.meta.canaryFormat).toBeUndefined();

    getSecret("DISARM_ME", { scope: "global", source: "cli" });
    expect(queryAudit({ action: "canary", key: "DISARM_ME" }).length).toBe(0);
    expect(listCanaries({ scope: "global" }).map((c) => c.key)).not.toContain("DISARM_ME");
  });

  it("returns false for a non-canary and throws for a missing key", () => {
    setSecret("PLAIN", "v", { scope: "global", source: "cli" });
    expect(disarmCanary("PLAIN", { scope: "global" })).toBe(false);
    expect(() => disarmCanary("NO_SUCH_KEY", { scope: "global" })).toThrow(/not found/);
  });
});

describe("listCanaries", () => {
  it("lists only canaries with trip stats", () => {
    setSecret("REAL", "value", { scope: "global", source: "cli" });
    plantCanary("C1", { format: "aws" });
    plantCanary("C2", { format: "github" });
    getSecret("C1", { scope: "global", source: "mcp" });
    getSecret("C1", { scope: "global", source: "mcp" });

    const list = listCanaries({ scope: "global" });
    expect(list.map((c) => c.key).sort()).toEqual(["C1", "C2"]);
    const c1 = list.find((c) => c.key === "C1")!;
    expect(c1.tripCount).toBe(2);
    expect(c1.format).toBe("aws");
    expect(c1.lastTrippedAt).toBeDefined();
    expect(list.find((c) => c.key === "C2")!.tripCount).toBe(0);
  });
});
