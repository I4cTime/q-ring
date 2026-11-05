import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
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

import { setSecret, getSecret, deleteSecret } from "../../core/keyring.js";
import { plantCanary } from "../../core/canary.js";
import { queryAudit } from "../../core/observer.js";
import { setPolicyRoot, clearPolicyCache } from "../../core/policy.js";
import { FakeEntry, resetFakeKeyring } from "../helpers/fake-keyring.js";

let dir: string;

beforeEach(() => {
  resetFakeKeyring();
  clearPolicyCache();
  dir = mkdtempSync(join(tmpdir(), "qring-delete-"));
  setPolicyRoot(dir);
});

afterEach(() => {
  vi.restoreAllMocks();
  setPolicyRoot(process.cwd());
  clearPolicyCache();
  rmSync(dir, { recursive: true, force: true });
});

describe("deleteSecret", () => {
  it("reads each scope's envelope once: the policy check and the canary check see the same copy", () => {
    plantCanary("TRAP", { format: "github" });
    const reads = vi.spyOn(FakeEntry.prototype, "getPassword");

    expect(deleteSecret("TRAP", { scope: "global", source: "cli" })).toBe(true);

    // Count reads of TRAP's entry only (audit logging reads its own key).
    const trapReads = reads.mock.contexts.filter(
      (ctx) => (ctx as unknown as { account: string }).account === "TRAP",
    );
    expect(trapReads).toHaveLength(1);
    expect(queryAudit({ action: "canary", key: "TRAP" })).toHaveLength(1);
  });

  it("checks policy on every scope's copy before deleting any of them", () => {
    writeFileSync(
      join(dir, ".q-ring.json"),
      JSON.stringify({ policy: { mcp: { deniedTags: ["prod"] } } }),
    );
    clearPolicyCache();
    setSecret("SHARED_KEY", "project-copy", { scope: "project", projectPath: dir, source: "cli" });
    setSecret("SHARED_KEY", "global-copy", { scope: "global", source: "cli", tags: ["prod"] });

    // No scope: resolves to the project copy (allowed) and the global copy
    // (tag-denied). The denial must leave both in place.
    expect(() => deleteSecret("SHARED_KEY", { projectPath: dir, source: "mcp" })).toThrow(
      /Policy Denied: Tag "prod"/,
    );
    expect(getSecret("SHARED_KEY", { scope: "project", projectPath: dir, silent: true })).toBe(
      "project-copy",
    );
    expect(getSecret("SHARED_KEY", { scope: "global", silent: true })).toBe("global-copy");
  });
});
