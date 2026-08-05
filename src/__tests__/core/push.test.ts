import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

vi.mock("@napi-rs/keyring", async () => {
  const fake = await import("../helpers/fake-keyring.js");
  return { Entry: fake.FakeEntry, findCredentials: fake.findCredentials };
});

const spawnSyncMock = vi.hoisted(() => vi.fn());
vi.mock("node:child_process", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:child_process")>();
  return { ...actual, spawnSync: spawnSyncMock };
});

import { resetFakeKeyring } from "../helpers/fake-keyring.js";
import { setSecret } from "../../core/keyring.js";
import { clearCollapseCache } from "../../core/collapse.js";
import { pushSecrets, resolvePushKeys } from "../../core/push.js";

let project: string;

beforeEach(() => {
  resetFakeKeyring();
  clearCollapseCache();
  spawnSyncMock.mockReset();
  // Default: every CLI invocation (probe + push) succeeds.
  spawnSyncMock.mockReturnValue({ status: 0, stdout: "", stderr: "", error: undefined });
  project = mkdtempSync(join(tmpdir(), "qring-push-test-"));
});

afterEach(() => {
  rmSync(project, { recursive: true, force: true });
});

function writeManifest(secrets: Record<string, object>): void {
  writeFileSync(join(project, ".q-ring.json"), JSON.stringify({ secrets }));
  clearCollapseCache();
}

describe("resolvePushKeys", () => {
  it("prefers explicit keys over the manifest", () => {
    writeManifest({ FROM_MANIFEST: {} });
    expect(resolvePushKeys({ target: "github", keys: ["A", "B"], projectPath: project })).toEqual(["A", "B"]);
  });

  it("falls back to manifest keys", () => {
    writeManifest({ ONE: {}, TWO: {} });
    expect(resolvePushKeys({ target: "github", projectPath: project })).toEqual(["ONE", "TWO"]);
  });

  it("throws when there is nothing to push", () => {
    expect(() => resolvePushKeys({ target: "github", projectPath: project })).toThrow(/Nothing to push/);
  });
});

describe("pushSecrets", () => {
  it("pushes manifest keys via gh with the value on stdin, never argv", () => {
    writeManifest({ API_KEY: {} });
    setSecret("API_KEY", "secret-value-1", { scope: "project", projectPath: project, silent: true });

    const result = pushSecrets({ target: "github", projectPath: project, silent: true });

    expect(result.pushed).toEqual(["API_KEY"]);
    const pushCall = spawnSyncMock.mock.calls.find((c) => c[1]?.includes("set"));
    expect(pushCall![0]).toBe("gh");
    expect(pushCall![1]).toEqual(["secret", "set", "API_KEY"]);
    expect(pushCall![2].input).toBe("secret-value-1");
    expect(pushCall![1]).not.toContain("secret-value-1");
  });

  it("passes --repo to gh when given", () => {
    setSecret("K", "value-long", { scope: "project", projectPath: project, silent: true });
    pushSecrets({ target: "github", keys: ["K"], repo: "I4cTime/q-ring", projectPath: project, silent: true });
    const pushCall = spawnSyncMock.mock.calls.find((c) => c[1]?.includes("set"));
    expect(pushCall![1]).toEqual(["secret", "set", "K", "--repo", "I4cTime/q-ring"]);
  });

  it("vercel pushes once per environment with --force", () => {
    setSecret("K", "value-long", { scope: "project", projectPath: project, silent: true });
    pushSecrets({
      target: "vercel", keys: ["K"], vercelEnvs: ["production", "preview"],
      projectPath: project, silent: true,
    });
    const envCalls = spawnSyncMock.mock.calls.filter((c) => c[1]?.[0] === "env");
    expect(envCalls.map((c) => c[1])).toEqual([
      ["env", "add", "K", "production", "--force"],
      ["env", "add", "K", "preview", "--force"],
    ]);
  });

  it("reports missing keys without failing the push", () => {
    writeManifest({ PRESENT: {}, ABSENT: {} });
    setSecret("PRESENT", "value-long", { scope: "project", projectPath: project, silent: true });

    const result = pushSecrets({ target: "cloudflare", projectPath: project, silent: true });

    expect(result.pushed).toEqual(["PRESENT"]);
    expect(result.missing).toEqual(["ABSENT"]);
  });

  it("captures per-key CLI failures", () => {
    setSecret("BAD", "value-long", { scope: "project", projectPath: project, silent: true });
    spawnSyncMock.mockImplementation((_bin: string, args: string[]) =>
      args.includes("--version")
        ? { status: 0, stdout: "", stderr: "" }
        : { status: 1, stdout: "", stderr: "not logged in" },
    );

    const result = pushSecrets({ target: "github", keys: ["BAD"], projectPath: project, silent: true });

    expect(result.pushed).toEqual([]);
    expect(result.failed).toEqual([{ key: "BAD", error: "not logged in" }]);
  });

  it("dry run resolves keys but never invokes the platform CLI", () => {
    writeManifest({ K: {} });
    setSecret("K", "value-long", { scope: "project", projectPath: project, silent: true });

    const result = pushSecrets({ target: "github", projectPath: project, dryRun: true, silent: true });

    expect(result.pushed).toEqual(["K"]);
    expect(spawnSyncMock).not.toHaveBeenCalled();
  });

  it("errors up front when the platform CLI is absent", () => {
    setSecret("K", "value-long", { scope: "project", projectPath: project, silent: true });
    spawnSyncMock.mockReturnValue({ status: null, stdout: "", stderr: "", error: new Error("ENOENT") });

    expect(() =>
      pushSecrets({ target: "github", keys: ["K"], projectPath: project, silent: true }),
    ).toThrow(/gh.*not found/);
  });
});
