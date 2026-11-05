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
import { teleportPack } from "../../core/teleport.js";
import { setPolicyRoot, clearPolicyCache } from "../../core/policy.js";
import { registerSecretTools } from "../../mcp/tools/secrets.js";
import { registerTeleportTools } from "../../mcp/tools/teleport.js";
import { registerEnvironmentTools } from "../../mcp/tools/environments.js";

type Result = { content: { type: "text"; text: string }[]; isError?: boolean };
type Handler = (params: Record<string, unknown>) => Promise<Result>;

function captureTools(): Map<string, Handler> {
  const tools = new Map<string, Handler>();
  const stub = {
    tool: (name: string, ...rest: unknown[]) => {
      tools.set(name, rest[rest.length - 1] as Handler);
    },
  };
  registerSecretTools(stub as unknown as McpServer);
  registerTeleportTools(stub as unknown as McpServer);
  registerEnvironmentTools(stub as unknown as McpServer);
  return tools;
}

/** A tool either throws (the SDK turns that into isError) or returns isError. */
async function call(tool: Handler, params: Record<string, unknown>): Promise<string | null> {
  try {
    const res = await tool(params);
    return res.isError ? res.content.map((c) => c.text).join("\n") : null;
  } catch (err) {
    return err instanceof Error ? err.message : String(err);
  }
}

let dir: string;
let tools: Map<string, Handler>;

const PROTECTED = "real-protected-value";
const read = (key: string) => getSecret(key, { scope: "global", silent: true });

beforeEach(() => {
  resetFakeKeyring();
  clearPolicyCache();
  dir = mkdtempSync(join(tmpdir(), "qring-write-policy-"));
  writeFileSync(
    join(dir, ".q-ring.json"),
    JSON.stringify({
      policy: { mcp: { deniedKeys: ["PROD_DB_PASSWORD"], deniedTags: ["prod"] } },
    }),
  );
  setPolicyRoot(dir);
  tools = captureTools();
  setSecret("PROD_DB_PASSWORD", PROTECTED, { scope: "global", source: "cli" });
  setSecret("TAGGED_KEY", PROTECTED, { scope: "global", source: "cli", tags: ["prod"] });
});

afterEach(() => {
  setPolicyRoot(process.cwd());
  clearPolicyCache();
  rmSync(dir, { recursive: true, force: true });
});

describe("MCP writes are held to key policy", () => {
  it("set_secret cannot overwrite a denied key or a key with a denied tag", async () => {
    for (const key of ["PROD_DB_PASSWORD", "TAGGED_KEY"]) {
      const err = await call(tools.get("set_secret")!, {
        key,
        value: "attacker-value",
        scope: "global",
        projectPath: dir,
      });
      expect(err).toMatch(/Policy Denied/);
      expect(read(key)).toBe(PROTECTED);
    }
  });

  it("set_secret with env cannot overwrite a denied key either", async () => {
    const err = await call(tools.get("set_secret")!, {
      key: "PROD_DB_PASSWORD",
      value: "attacker-value",
      env: "prod",
      scope: "global",
      projectPath: dir,
    });
    expect(err).toMatch(/Policy Denied/);
    expect(read("PROD_DB_PASSWORD")).toBe(PROTECTED);
  });

  it("teleport_unpack cannot plant over a denied key", async () => {
    const bundle = teleportPack([{ key: "PROD_DB_PASSWORD", value: "attacker-value" }], "pw");
    const res = await tools.get("teleport_unpack")!({
      bundle,
      passphrase: "pw",
      scope: "global",
      projectPath: dir,
    });
    // Skipped and reported (see bulk-write-policy.test.ts), never written.
    expect(res.content[0].text).toMatch(/Skipped \(policy\): PROD_DB_PASSWORD/);
    expect(read("PROD_DB_PASSWORD")).toBe(PROTECTED);
  });

  it("import_dotenv cannot overwrite a denied key", async () => {
    await call(tools.get("import_dotenv")!, {
      content: "PROD_DB_PASSWORD=attacker-value\n",
      scope: "global",
      projectPath: dir,
      skipExisting: false,
      dryRun: false,
    });
    expect(read("PROD_DB_PASSWORD")).toBe(PROTECTED);
  });

  it("generate_secret saveAs cannot overwrite a denied key", async () => {
    const err = await call(tools.get("generate_secret")!, {
      format: "api-key",
      saveAs: "PROD_DB_PASSWORD",
      scope: "global",
      projectPath: dir,
    });
    expect(err).toMatch(/Policy Denied/);
    expect(read("PROD_DB_PASSWORD")).toBe(PROTECTED);
  });

  it("ordinary keys stay writable over MCP", async () => {
    const err = await call(tools.get("set_secret")!, {
      key: "SCRATCH",
      value: "fine",
      scope: "global",
      projectPath: dir,
    });
    expect(err).toBeNull();
    expect(read("SCRATCH")).toBe("fine");
  });
});
