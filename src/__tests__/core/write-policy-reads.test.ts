import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

vi.mock("@napi-rs/keyring", async () => {
  const fake = await import("../helpers/fake-keyring.js");
  return { Entry: fake.FakeEntry, findCredentials: fake.findCredentials };
});

import { importDotenv } from "../../core/import.js";
import { setPolicyRoot, clearPolicyCache } from "../../core/policy.js";
import { FakeEntry, resetFakeKeyring } from "../helpers/fake-keyring.js";

let dir: string;
const KEYS = Array.from({ length: 10 }, (_, i) => `KEY_${i}`);
const CONTENT = KEYS.map((k) => `${k}=value-for-${k}`).join("\n");

beforeEach(() => {
  resetFakeKeyring();
  clearPolicyCache();
  dir = mkdtempSync(join(tmpdir(), "qring-write-reads-"));
  setPolicyRoot(dir);
});

afterEach(() => {
  vi.restoreAllMocks();
  setPolicyRoot(process.cwd());
  clearPolicyCache();
  rmSync(dir, { recursive: true, force: true });
});

/** Keyring reads of the imported keys' entries (audit bookkeeping excluded). */
function keyReads(spy: { mock: { contexts: unknown[] } }): number {
  return spy.mock.contexts.filter((ctx) =>
    KEYS.includes((ctx as unknown as { account: string }).account),
  ).length;
}

describe("the write-policy check only reads the keyring when it must", () => {
  it("a CLI import of N keys does no policy reads (one metadata read per key)", () => {
    const reads = vi.spyOn(FakeEntry.prototype, "getPassword");
    importDotenv(CONTENT, { scope: "global", projectPath: dir, source: "cli" });
    expect(keyReads(reads)).toBe(KEYS.length);
  });

  it("an MCP import with no deniedTags policy does no policy reads either", () => {
    writeFileSync(
      join(dir, ".q-ring.json"),
      JSON.stringify({ policy: { mcp: { deniedKeys: ["OTHER"] } } }),
    );
    clearPolicyCache();
    const reads = vi.spyOn(FakeEntry.prototype, "getPassword");
    importDotenv(CONTENT, { scope: "global", projectPath: dir, source: "mcp" });
    expect(keyReads(reads)).toBe(KEYS.length);
  });
});
