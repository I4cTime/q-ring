import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdirSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

vi.mock("@napi-rs/keyring", async () => {
  const fake = await import("../helpers/fake-keyring.js");
  return { Entry: fake.FakeEntry, findCredentials: fake.findCredentials };
});

import { setSecret, getSecret, deleteSecret } from "../../core/keyring.js";
import { clearPolicyCache, PolicyConfigError } from "../../core/policy.js";
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

describe("getSecret under a .q-ring.json that is not valid JSON", () => {
  const corruptDir = join(tmpdir(), `qring-keyring-corrupt-${process.pid}-${Date.now()}`);
  let errSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    resetFakeKeyring();
    clearPolicyCache();
    mkdirSync(corruptDir, { recursive: true });
    errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
  });

  afterEach(() => {
    errSpy.mockRestore();
    clearPolicyCache();
    rmSync(corruptDir, { recursive: true, force: true });
  });

  it("denies an MCP read instead of serving the secret", () => {
    const opts = { scope: "project" as const, projectPath: corruptDir };
    setSecret("CORRUPT_TEST_KEY", "s3cret-value", { ...opts, source: "cli" });
    expect(getSecret("CORRUPT_TEST_KEY", { ...opts, source: "mcp" })).toBe("s3cret-value");

    writeFileSync(join(corruptDir, ".q-ring.json"), "{ not json", "utf8");
    expect(() => getSecret("CORRUPT_TEST_KEY", { ...opts, source: "mcp" })).toThrow(
      PolicyConfigError,
    );
  });
});
