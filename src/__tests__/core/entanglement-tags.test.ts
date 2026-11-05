import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

vi.mock("@napi-rs/keyring", async () => {
  const fake = await import("../helpers/fake-keyring.js");
  return { Entry: fake.FakeEntry, findCredentials: fake.findCredentials };
});

import { setSecret, getSecret, entangleSecrets } from "../../core/keyring.js";
import { queryAudit } from "../../core/observer.js";
import { setPolicyRoot, clearPolicyCache } from "../../core/policy.js";
import { registerSecretTools } from "../../mcp/tools/secrets.js";
import { resetFakeKeyring } from "../helpers/fake-keyring.js";

type Result = { content: { text: string }[]; isError?: boolean };
type Handler = (params: Record<string, unknown>) => Promise<Result>;

function tool(name: string): Handler {
  const tools = new Map<string, Handler>();
  const stub = {
    tool: (n: string, ...rest: unknown[]) => tools.set(n, rest[rest.length - 1] as Handler),
  };
  registerSecretTools(stub as unknown as McpServer);
  return tools.get(name)!;
}

let dir: string;
let configDir: string;
const PROD_VALUE = "the-real-prod-password";

beforeEach(() => {
  resetFakeKeyring();
  clearPolicyCache();
  dir = mkdtempSync(join(tmpdir(), "qring-entangle-tags-"));
  configDir = mkdtempSync(join(tmpdir(), "qring-entangle-tags-cfg-"));
  process.env.QRING_CONFIG_DIR = configDir;
  writeFileSync(
    join(dir, ".q-ring.json"),
    JSON.stringify({ policy: { mcp: { deniedTags: ["prod"] } } }),
  );
  setPolicyRoot(dir);
  setSecret("PROD", PROD_VALUE, { scope: "global", source: "cli", tags: ["prod"] });
  setSecret("SCRATCH", "scratch-value", { scope: "global", source: "cli" });
});

afterEach(() => {
  setPolicyRoot(process.cwd());
  clearPolicyCache();
  delete process.env.QRING_CONFIG_DIR;
  rmSync(dir, { recursive: true, force: true });
  rmSync(configDir, { recursive: true, force: true });
});

describe("entanglement respects deniedTags", () => {
  it("write path: an MCP write to SCRATCH does not propagate into a tag-denied PROD", () => {
    entangleSecrets("SCRATCH", { scope: "global", source: "cli" }, "PROD", {
      scope: "global",
      source: "cli",
    });

    setSecret("SCRATCH", "attacker-value", { scope: "global", source: "mcp", projectPath: dir });

    expect(getSecret("PROD", { scope: "global", silent: true })).toBe(PROD_VALUE);
    const denied = queryAudit({ action: "policy_deny", key: "PROD" });
    expect(denied).toHaveLength(1);
    expect(denied[0].detail).toContain("blocked entangled propagation from SCRATCH");
    expect(JSON.stringify(queryAudit())).not.toContain("attacker-value");
  });

  it("read path: entangle_secrets over MCP refuses a link from a tag-denied key", async () => {
    const res = await tool("entangle_secrets")({
      sourceKey: "PROD",
      targetKey: "SCRATCH",
      sourceScope: "global",
      targetScope: "global",
      sourceProjectPath: dir,
      targetProjectPath: dir,
    });
    expect(res.isError).toBe(true);
    expect(res.content[0].text).toMatch(/Policy Denied: Tag "prod"/);

    // No link was made: an operator write to PROD stays out of SCRATCH.
    setSecret("PROD", "rotated-prod-password", { scope: "global", source: "cli" });
    expect(getSecret("SCRATCH", { scope: "global", silent: true })).toBe("scratch-value");
  });
});
