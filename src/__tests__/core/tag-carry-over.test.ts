import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

vi.mock("@napi-rs/keyring", async () => {
  const fake = await import("../helpers/fake-keyring.js");
  return { Entry: fake.FakeEntry, findCredentials: fake.findCredentials };
});

import { setSecret, getSecret, getEnvelope } from "../../core/keyring.js";
import { importDotenv } from "../../core/import.js";
import { promoteSecret } from "../../core/promote.js";
import { runHealthScan } from "../../core/agent.js";
import { setPolicyRoot, clearPolicyCache } from "../../core/policy.js";
import { createProgram } from "../../cli/commands.js";
import { registerSecretTools } from "../../mcp/tools/secrets.js";
import { resetFakeKeyring } from "../helpers/fake-keyring.js";

let dir: string;

beforeEach(() => {
  resetFakeKeyring();
  clearPolicyCache();
  dir = mkdtempSync(join(tmpdir(), "qring-tag-carry-"));
  setPolicyRoot(dir);
});

afterEach(() => {
  vi.restoreAllMocks();
  setPolicyRoot(process.cwd());
  clearPolicyCache();
  rmSync(dir, { recursive: true, force: true });
});

const meta = (key: string) => getEnvelope(key, { scope: "global" })!.envelope.meta;

function seed(key = "PROD_DB"): void {
  setSecret(key, "v1", {
    scope: "global",
    source: "cli",
    tags: ["prod", "db"],
    description: "primary database",
  });
}

describe("re-setting a secret keeps its tags and description", () => {
  it("a write without tags keeps them (the rotation case)", () => {
    seed();
    setSecret("PROD_DB", "v2", { scope: "global", source: "cli" });
    expect(meta("PROD_DB").tags).toEqual(["prod", "db"]);
    expect(meta("PROD_DB").description).toBe("primary database");
    expect(getSecret("PROD_DB", { scope: "global", silent: true })).toBe("v2");
  });

  it("clearTags removes the tags and keeps the description", () => {
    seed();
    setSecret("PROD_DB", "v2", { scope: "global", source: "cli", clearTags: true });
    expect(meta("PROD_DB").tags).toBeUndefined();
    expect(meta("PROD_DB").description).toBe("primary database");
  });

  it("new tags replace the old ones", () => {
    seed();
    setSecret("PROD_DB", "v2", { scope: "global", source: "cli", tags: ["staging"] });
    expect(meta("PROD_DB").tags).toEqual(["staging"]);
  });

  it("promote, import over an existing key and agent auto-rotation keep them too", () => {
    setSecret("MULTI", "", {
      scope: "global",
      source: "cli",
      states: { dev: "d", prod: "p" },
      defaultEnv: "dev",
      tags: ["prod"],
      description: "multi-env",
    });
    promoteSecret("MULTI", { from: "dev", to: "staging", scope: "global" });
    expect(meta("MULTI").tags).toEqual(["prod"]);
    expect(meta("MULTI").description).toBe("multi-env");

    seed("IMPORTED");
    importDotenv("IMPORTED=v2", { scope: "global", source: "cli" });
    expect(meta("IMPORTED").tags).toEqual(["prod", "db"]);

    setSecret("EXPIRING", "v1", {
      scope: "global",
      source: "cli",
      tags: ["prod"],
      expiresAt: new Date(Date.now() - 1000).toISOString(),
    });
    runHealthScan({ autoRotate: true, projectPaths: [dir] });
    expect(meta("EXPIRING").tags).toEqual(["prod"]);
  });

  it("a tag-denied key stays protected after a CLI rotation, and MCP set_secret is still refused", async () => {
    writeFileSync(
      join(dir, ".q-ring.json"),
      JSON.stringify({ policy: { mcp: { deniedTags: ["prod"] } } }),
    );
    clearPolicyCache();
    seed();
    setSecret("PROD_DB", "rotated", { scope: "global", source: "cli" });

    expect(() =>
      getSecret("PROD_DB", { scope: "global", source: "mcp", projectPath: dir }),
    ).toThrow(/Tag "prod"/);

    let setTool: ((p: Record<string, unknown>) => Promise<unknown>) | undefined;
    const stub = {
      tool: (n: string, ...rest: unknown[]) => {
        if (n === "set_secret") setTool = rest[rest.length - 1] as typeof setTool;
      },
    };
    registerSecretTools(stub as unknown as McpServer);
    await expect(
      setTool!({
        key: "PROD_DB",
        value: "attacker",
        scope: "global",
        projectPath: dir,
        clearTags: true,
      }),
    ).rejects.toThrow(/Policy Denied/);
    expect(getSecret("PROD_DB", { scope: "global", silent: true })).toBe("rotated");
    expect(meta("PROD_DB").tags).toEqual(["prod", "db"]);
  });
});

describe("qring set --clear-tags", () => {
  async function run(...argv: string[]): Promise<void> {
    vi.spyOn(console, "log").mockImplementation(() => {});
    const program = createProgram();
    program.exitOverride();
    await program.parseAsync(argv, { from: "user" });
  }

  it("keeps tags by default and clears them with the flag", async () => {
    await run("set", "CLI_KEY", "v1", "--global", "--tags", "prod", "--description", "d");
    await run("set", "CLI_KEY", "v2", "--global");
    expect(meta("CLI_KEY").tags).toEqual(["prod"]);
    expect(meta("CLI_KEY").description).toBe("d");

    await run("set", "CLI_KEY", "v3", "--global", "--clear-tags");
    expect(meta("CLI_KEY").tags).toBeUndefined();
  });
});
