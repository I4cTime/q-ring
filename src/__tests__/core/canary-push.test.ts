import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

vi.mock("@napi-rs/keyring", async () => {
  const fake = await import("../helpers/fake-keyring.js");
  return { Entry: fake.FakeEntry, findCredentials: fake.findCredentials };
});

vi.mock("../../core/notify.js", () => ({
  notificationsEnabled: vi.fn(() => false),
  notifyUser: vi.fn(() => true),
}));

const spawnSyncMock = vi.hoisted(() => vi.fn());
vi.mock("node:child_process", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:child_process")>();
  return { ...actual, spawnSync: spawnSyncMock };
});

import { resetFakeKeyring } from "../helpers/fake-keyring.js";
import { plantCanary } from "../../core/canary.js";
import { pushSecrets } from "../../core/push.js";
import { queryAudit } from "../../core/observer.js";

let dir: string;

beforeEach(() => {
  resetFakeKeyring();
  spawnSyncMock.mockReset();
  spawnSyncMock.mockReturnValue({ status: 0, stdout: "", stderr: "", error: undefined });
  dir = mkdtempSync(join(tmpdir(), "qring-canary-push-"));
  process.env.QRING_AUDIT_DIR = dir;
});

afterEach(() => {
  delete process.env.QRING_AUDIT_DIR;
  rmSync(dir, { recursive: true, force: true });
});

describe("plant --push", () => {
  it("pushes the generated value over stdin without tripping the canary", () => {
    const planted = plantCanary("AWS_SECRET_ACCESS_KEY", { format: "aws-secret" });
    const result = pushSecrets({
      target: "github",
      keys: ["AWS_SECRET_ACCESS_KEY"],
      presetValues: { AWS_SECRET_ACCESS_KEY: planted.value },
      canaryKeys: ["AWS_SECRET_ACCESS_KEY"],
      repo: "acme/app",
      projectPath: dir,
      source: "cli",
    });
    expect(result.pushed).toEqual(["AWS_SECRET_ACCESS_KEY"]);
    expect(result.failed).toEqual([]);

    // probe + one push invocation, value on stdin, never in argv
    const pushCall = spawnSyncMock.mock.calls.find((c) => c[1]?.[0] === "secret");
    expect(pushCall?.[2]?.input).toBe(planted.value);
    expect(JSON.stringify(pushCall?.[1])).not.toContain(planted.value);

    expect(queryAudit({ action: "canary" })).toHaveLength(0);
    const push = queryAudit({ action: "push", key: "AWS_SECRET_ACCESS_KEY" });
    expect(push).toHaveLength(1);
    expect(push[0].detail).toContain("canary honeytoken pushed to github (acme/app)");
  });

  it("still resolves ordinary keys from the keyring when no preset value is given", () => {
    plantCanary("TRIP_ME", { format: "github" });
    const result = pushSecrets({
      target: "cloudflare",
      keys: ["TRIP_ME"],
      projectPath: dir,
      source: "cli",
    });
    expect(result.pushed).toEqual(["TRIP_ME"]);
    // A plain `qring push` of a canary key is a real read — and trips it.
    expect(queryAudit({ action: "canary", key: "TRIP_ME" })).toHaveLength(1);
  });
});
