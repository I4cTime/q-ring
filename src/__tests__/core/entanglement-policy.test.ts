import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdirSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

// Redirect ~/.config (entanglement/audit registries) to a temp home so links
// never persist across tests or into the developer's real config.
vi.mock("node:os", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:os")>();
  const fs = await import("node:fs");
  const path = await import("node:path");
  let home: string | null = null;
  return {
    ...actual,
    homedir: () => {
      if (!home) home = fs.mkdtempSync(path.join(actual.tmpdir(), "qring-eh-"));
      return home;
    },
  };
});
vi.mock("@napi-rs/keyring", async () => {
  const fake = await import("../helpers/fake-keyring.js");
  return { Entry: fake.FakeEntry, findCredentials: fake.findCredentials };
});

import { homedir } from "node:os";
import {
  setSecret,
  getSecret,
  entangleSecrets,
} from "../../core/keyring.js";
import { setPolicyRoot, clearPolicyCache } from "../../core/policy.js";
import { resetFakeKeyring } from "../helpers/fake-keyring.js";

const dir = join(tmpdir(), `qring-entangle-policy-${process.pid}`);

describe("entanglement propagation respects policy (A2)", () => {
  beforeEach(() => {
    resetFakeKeyring();
    clearPolicyCache();
    // wipe any registry state from a prior test in this file
    rmSync(join(homedir(), ".config", "q-ring"), { recursive: true, force: true });
    rmSync(dir, { recursive: true, force: true });
    mkdirSync(dir, { recursive: true });
    // Deny reads/writes of PROD_DB_PASSWORD via project policy, and pin the
    // policy root to this dir (as the MCP server does at startup).
    writeFileSync(
      join(dir, ".q-ring.json"),
      JSON.stringify({ policy: { mcp: { deniedKeys: ["PROD_DB_PASSWORD"] } } }),
      "utf8",
    );
    setPolicyRoot(dir);
  });

  afterEach(() => {
    setPolicyRoot(process.cwd()); // reset the module-global for other suites
    clearPolicyCache();
    rmSync(dir, { recursive: true, force: true });
  });

  it("an MCP write to SCRATCH cannot overwrite a policy-denied entangled target", () => {
    // Seed the protected secret directly (CLI source bypasses policy, as the
    // local operator legitimately can).
    setSecret("PROD_DB_PASSWORD", "the-real-password", { scope: "global", source: "cli" });
    setSecret("SCRATCH", "innocent", { scope: "global", source: "cli" });

    // Link them (CLI). The link now exists in the registry.
    entangleSecrets(
      "SCRATCH",
      { scope: "global", source: "cli" },
      "PROD_DB_PASSWORD",
      { scope: "global", source: "cli" },
    );

    // The attack: an MCP-sourced write to SCRATCH tries to propagate into the
    // denied key. Propagation must be blocked.
    setSecret("SCRATCH", "attacker-value", {
      scope: "global",
      source: "mcp",
      projectPath: dir,
    });

    // PROD_DB_PASSWORD is unchanged (read via CLI to bypass the read gate).
    expect(getSecret("PROD_DB_PASSWORD", { scope: "global", source: "cli" })).toBe(
      "the-real-password",
    );
  });

  it("propagation to a non-denied target still works for an MCP write", () => {
    setSecret("MIRROR_A", "v0", { scope: "global", source: "cli" });
    setSecret("MIRROR_B", "v0", { scope: "global", source: "cli" });
    entangleSecrets(
      "MIRROR_A",
      { scope: "global", source: "cli" },
      "MIRROR_B",
      { scope: "global", source: "cli" },
    );

    setSecret("MIRROR_A", "v1", { scope: "global", source: "mcp", projectPath: dir });
    expect(getSecret("MIRROR_B", { scope: "global", source: "cli" })).toBe("v1");
  });
});
