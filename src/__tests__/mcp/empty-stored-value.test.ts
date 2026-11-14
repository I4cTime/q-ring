/**
 * A key whose stored value is empty (lost by the OS keyring) reaches an MCP
 * client as a tool error carrying the empty-value message.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

vi.mock("@napi-rs/keyring", async () => {
  const fake = await import("../helpers/fake-keyring.js");
  return { Entry: fake.FakeEntry, findCredentials: fake.findCredentials };
});

import { FakeEntry, fakeKeyringDump, resetFakeKeyring } from "../helpers/fake-keyring.js";
import { globalService } from "../../core/scope.js";
import { clearPolicyCache, setPolicyRoot } from "../../core/policy.js";
import { setSecret } from "../../core/keyring.js";
import { registerSecretTools } from "../../mcp/tools/secrets.js";
import { registerToolingTools } from "../../mcp/tools/tooling.js";

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
  registerToolingTools(stub as unknown as McpServer);
  return tools;
}

/** A tool either throws (the SDK turns that into isError with the message) or returns isError. */
async function errorText(tool: Handler, params: Record<string, unknown>): Promise<string | null> {
  try {
    const res = await tool(params);
    return res.isError ? res.content.map((c) => c.text).join("\n") : null;
  } catch (err) {
    return err instanceof Error ? err.message : String(err);
  }
}

const EMPTY_TEXT = /"LOST_KEY" \(global scope\): the stored value is empty, likely lost by the OS keyring/;

let tools: Map<string, Handler>;
let dir: string;

beforeEach(() => {
  resetFakeKeyring();
  clearPolicyCache();
  dir = mkdtempSync(join(tmpdir(), "qring-mcp-empty-"));
  setPolicyRoot(dir);
  new FakeEntry(globalService(), "LOST_KEY").setPassword("");
  tools = captureTools();
});

afterEach(() => {
  setPolicyRoot(process.cwd());
  clearPolicyCache();
  rmSync(dir, { recursive: true, force: true });
});

describe("MCP tools on a key whose stored value is empty", () => {
  it("get_secret returns a tool error with the empty-value message", async () => {
    const text = await errorText(tools.get("get_secret")!, { key: "LOST_KEY", scope: "global" });
    expect(text).toMatch(EMPTY_TEXT);
    expect(fakeKeyringDump().get(`${globalService()}\0LOST_KEY`)).toBe("");
  });

  it("inspect_secret returns a tool error with the empty-value message", async () => {
    const text = await errorText(tools.get("inspect_secret")!, { key: "LOST_KEY", scope: "global" });
    expect(text).toMatch(EMPTY_TEXT);
  });

  it("set_secret with an env re-sets it", async () => {
    const res = await tools.get("set_secret")!({
      key: "LOST_KEY",
      value: "fresh-value",
      env: "dev",
      scope: "global",
    });
    expect(res.isError).toBeFalsy();
    expect(fakeKeyringDump().get(`${globalService()}\0LOST_KEY`)).toContain("fresh-value");
  });
});

describe("MCP surfacing of a lost key", () => {
  it("list_secrets marks it emptyStored and leaves the field off healthy entries", async () => {
    setSecret("GOOD_KEY", "good", { scope: "global" });
    const res = await tools.get("list_secrets")!({ scope: "global" });
    const entries = JSON.parse(res.content[0].text).data.entries as Record<string, unknown>[];
    expect(entries.find((e) => e.key === "LOST_KEY")?.emptyStored).toBe(true);
    expect(entries.find((e) => e.key === "GOOD_KEY")).not.toHaveProperty("emptyStored");
  });

  it("exec_with_secrets names it in the result note", async () => {
    const res = await tools.get("exec_with_secrets")!({
      command: process.execPath,
      args: ["-e", "process.exit(0)"],
      profile: "ci",
      scope: "global",
      projectPath: dir,
    });
    const out = res.content.map((c) => c.text).join("\n");
    expect(out).toContain("Exit code: 0");
    expect(out).toMatch(/NOTE: .*stored value empty.*LOST_KEY/);
  });

  it("analyze_secrets does not report it as never accessed", async () => {
    const res = await tools.get("analyze_secrets")!({ scope: "global" });
    const analysis = JSON.parse(res.content[0].text) as { neverAccessed: string[] };
    expect(analysis.neverAccessed).not.toContain("LOST_KEY");
  });
});
