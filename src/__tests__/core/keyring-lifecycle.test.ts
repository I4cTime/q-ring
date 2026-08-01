import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdirSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

vi.mock("@napi-rs/keyring", async () => {
  const fake = await import("../helpers/fake-keyring.js");
  return { Entry: fake.FakeEntry, findCredentials: fake.findCredentials };
});

import { setSecret, deleteSecret } from "../../core/keyring.js";
import { clearPolicyCache } from "../../core/policy.js";
import { resetFakeKeyring } from "../helpers/fake-keyring.js";

const dir = join(tmpdir(), `qring-keyring-life-${Date.now()}`);

describe("setSecret + policy.secrets", () => {
  beforeEach(() => {
    resetFakeKeyring();
    clearPolicyCache();
    mkdirSync(dir, { recursive: true });
    writeFileSync(
      join(dir, ".q-ring.json"),
      JSON.stringify({
        policy: { secrets: { maxTtlSeconds: 100 } },
      }),
      "utf8",
    );
  });

  afterEach(() => {
    clearPolicyCache();
    try {
      deleteSecret("TTL_TEST_KEY", { scope: "project", projectPath: dir });
    } catch {
      /* ignore */
    }
    rmSync(dir, { recursive: true, force: true });
  });

  it("throws when ttl exceeds policy maxTtlSeconds", () => {
    expect(() =>
      setSecret("TTL_TEST_KEY", "x", {
        scope: "project",
        projectPath: dir,
        ttlSeconds: 9999,
        source: "cli",
      }),
    ).toThrow(/TTL/);
  });

  it("allows ttl within policy maxTtlSeconds", () => {
    expect(() =>
      setSecret("TTL_TEST_KEY", "x", {
        scope: "project",
        projectPath: dir,
        ttlSeconds: 50,
        source: "cli",
      }),
    ).not.toThrow();
  });
});
