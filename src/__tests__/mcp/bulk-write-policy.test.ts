import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

vi.mock("@napi-rs/keyring", async () => {
  const fake = await import("../helpers/fake-keyring.js");
  return { Entry: fake.FakeEntry, findCredentials: fake.findCredentials };
});

import { resetFakeKeyring } from "../helpers/fake-keyring.js";
import { setSecret, getSecret } from "../../core/keyring.js";
import { importDotenv } from "../../core/import.js";
import { teleportPack } from "../../core/teleport.js";
import { setPolicyRoot, clearPolicyCache } from "../../core/policy.js";
import { registerSecretTools } from "../../mcp/tools/secrets.js";
import { registerTeleportTools } from "../../mcp/tools/teleport.js";

type Result = { content: { text: string }[]; isError?: boolean };
type Handler = (params: Record<string, unknown>) => Promise<Result>;

function tools(): Map<string, Handler> {
  const map = new Map<string, Handler>();
  const stub = {
    tool: (n: string, ...rest: unknown[]) => map.set(n, rest[rest.length - 1] as Handler),
  };
  registerSecretTools(stub as unknown as McpServer);
  registerTeleportTools(stub as unknown as McpServer);
  return map;
}

let dir: string;
const read = (k: string) => getSecret(k, { scope: "global", silent: true });

beforeEach(() => {
  resetFakeKeyring();
  clearPolicyCache();
  dir = mkdtempSync(join(tmpdir(), "qring-bulk-policy-"));
  writeFileSync(
    join(dir, ".q-ring.json"),
    JSON.stringify({ policy: { mcp: { deniedKeys: ["DENIED_KEY"], deniedTags: ["prod"] } } }),
  );
  setPolicyRoot(dir);
  setSecret("DENIED_KEY", "protected-1", { scope: "global", source: "cli" });
  setSecret("TAGGED_KEY", "protected-2", { scope: "global", source: "cli", tags: ["prod"] });
});

afterEach(() => {
  setPolicyRoot(process.cwd());
  clearPolicyCache();
  rmSync(dir, { recursive: true, force: true });
});

// Protected keys sit between allowed ones: a writer that throws on the
// first denial leaves the keys after it unwritten.
const ENTRIES = [
  ["A_OK", "a-value"],
  ["DENIED_KEY", "attacker-1"],
  ["TAGGED_KEY", "attacker-2"],
  ["Z_OK", "z-value"],
] as const;

function expectOutcome() {
  expect(read("A_OK")).toBe("a-value");
  expect(read("Z_OK")).toBe("z-value");
  expect(read("DENIED_KEY")).toBe("protected-1");
  expect(read("TAGGED_KEY")).toBe("protected-2");
}

describe("bulk MCP writers skip protected keys instead of aborting", () => {
  it("importDotenv (mcp) writes the allowed keys and lists the skipped ones with reasons", () => {
    const content = ENTRIES.map(([k, v]) => `${k}=${v}`).join("\n");
    const result = importDotenv(content, {
      scope: "global",
      projectPath: dir,
      source: "mcp",
      skipExisting: true,
    });
    expectOutcome();
    expect(result.imported).toEqual(["A_OK", "Z_OK"]);
    expect(result.skippedByPolicy).toEqual([
      { key: "DENIED_KEY", reason: expect.stringContaining("denied by project policy") },
      { key: "TAGGED_KEY", reason: expect.stringContaining('Tag "prod"') },
    ]);
  });

  it("import_dotenv tool reports the policy skips", async () => {
    const res = await tools().get("import_dotenv")!({
      content: ENTRIES.map(([k, v]) => `${k}=${v}`).join("\n"),
      scope: "global",
      projectPath: dir,
      skipExisting: false,
      dryRun: false,
    });
    expectOutcome();
    expect(res.isError).toBeUndefined();
    expect(res.content[0].text).toContain("Skipped (policy): DENIED_KEY");
    expect(res.content[0].text).toContain("Skipped (policy): TAGGED_KEY");
  });

  it("teleport_unpack writes the allowed keys and lists the skipped ones", async () => {
    const bundle = teleportPack(
      ENTRIES.map(([key, value]) => ({ key, value })),
      "pw",
    );
    const res = await tools().get("teleport_unpack")!({
      bundle,
      passphrase: "pw",
      scope: "global",
      projectPath: dir,
      dryRun: false,
    });
    expectOutcome();
    expect(res.isError).toBeUndefined();
    expect(res.content[0].text).toContain("Imported 2 secret(s)");
    expect(res.content[0].text).toContain("Skipped (policy): DENIED_KEY");
    expect(res.content[0].text).toContain("Skipped (policy): TAGGED_KEY");
  });
});
