import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

vi.mock("@napi-rs/keyring", async () => {
  const fake = await import("../helpers/fake-keyring.js");
  return { Entry: fake.FakeEntry, findCredentials: fake.findCredentials };
});

import { setSecret, hasSecret, secretExists } from "../../core/keyring.js";
import { setPolicyRoot, clearPolicyCache } from "../../core/policy.js";
import { resetFakeKeyring } from "../helpers/fake-keyring.js";

let dir: string;

beforeEach(() => {
  resetFakeKeyring();
  clearPolicyCache();
  dir = mkdtempSync(join(tmpdir(), "qring-secret-exists-"));
  writeFileSync(
    join(dir, ".q-ring.json"),
    JSON.stringify({ policy: { mcp: { deniedKeys: ["DENIED_KEY"], deniedTags: ["prod"] } } }),
  );
  setPolicyRoot(dir);
  setSecret("DENIED_KEY", "v1", { scope: "global", source: "cli" });
  setSecret("TAGGED_KEY", "v2", { scope: "global", source: "cli", tags: ["prod"] });
  setSecret("OPEN_KEY", "v3", { scope: "global", source: "cli" });
});

afterEach(() => {
  setPolicyRoot(process.cwd());
  clearPolicyCache();
  rmSync(dir, { recursive: true, force: true });
});

const mcp = () => ({ scope: "global" as const, source: "mcp" as const, projectPath: dir });

describe("hasSecret (visibility) versus secretExists (truth, for write paths)", () => {
  it("hasSecret hides policy-protected keys from an MCP caller", () => {
    expect(hasSecret("DENIED_KEY", mcp())).toBe(false);
    expect(hasSecret("TAGGED_KEY", mcp())).toBe(false);
    expect(hasSecret("OPEN_KEY", mcp())).toBe(true);
  });

  it("secretExists reports that they exist, so a write path never reads hidden as absent", () => {
    expect(secretExists("DENIED_KEY", mcp())).toBe(true);
    expect(secretExists("TAGGED_KEY", mcp())).toBe(true);
    expect(secretExists("OPEN_KEY", mcp())).toBe(true);
    expect(secretExists("NO_SUCH_KEY", mcp())).toBe(false);
  });

  it("secretExists treats an expired secret as absent, like hasSecret", () => {
    setSecret("EXPIRED_KEY", "v4", {
      scope: "global",
      source: "cli",
      expiresAt: new Date(Date.now() - 1000).toISOString(),
    });
    expect(secretExists("EXPIRED_KEY", { scope: "global" })).toBe(false);
    expect(hasSecret("EXPIRED_KEY", { scope: "global" })).toBe(false);
  });
});
