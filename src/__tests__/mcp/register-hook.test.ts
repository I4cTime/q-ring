import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

vi.mock("@napi-rs/keyring", async () => {
  const fake = await import("../helpers/fake-keyring.js");
  return { Entry: fake.FakeEntry, findCredentials: fake.findCredentials };
});

import { resetFakeKeyring } from "../helpers/fake-keyring.js";
import { setSecret } from "../../core/keyring.js";
import { enableHook, fireHooks, listHooks } from "../../core/hooks.js";
import { registerHookTools } from "../../mcp/tools/hooks.js";

type Result = { content: { type: "text"; text: string }[]; isError?: boolean };
type Handler = (params: Record<string, unknown>) => Promise<Result>;

function registerHook(): Handler {
  let handler: Handler | undefined;
  const stub = {
    tool: (name: string, ...rest: unknown[]) => {
      if (name === "register_hook") handler = rest[rest.length - 1] as Handler;
    },
  };
  registerHookTools(stub as unknown as McpServer);
  return handler!;
}

let configDir: string;
let marker: string;

beforeEach(() => {
  resetFakeKeyring();
  configDir = mkdtempSync(join(tmpdir(), "qring-hook-mcp-"));
  process.env.QRING_CONFIG_DIR = configDir;
  marker = join(configDir, "hook-ran");
});

afterEach(() => {
  delete process.env.QRING_CONFIG_DIR;
  rmSync(configDir, { recursive: true, force: true });
});

describe("register_hook (MCP)", () => {
  it.skipIf(process.platform === "win32")(
    "registers a shell hook disabled, so an agent cannot plant a command that runs on the next write",
    async () => {
      const res = await registerHook()({
        type: "shell",
        keyPattern: "*",
        actions: ["write"],
        command: `touch ${marker}`,
      });
      const entry = JSON.parse(res.content[0].text) as {
        id: string;
        enabled: boolean;
        note?: string;
      };
      expect(entry.enabled).toBe(false);
      expect(entry.note).toContain(`qring hook enable ${entry.id}`);

      // The operator's next write does not run it...
      await fireHooks({
        action: "write",
        key: "ANY_KEY",
        scope: "global",
        timestamp: new Date().toISOString(),
        source: "cli",
      });
      expect(existsSync(marker)).toBe(false);

      // ...until the operator arms it.
      enableHook(entry.id);
      setSecret("ANY_KEY", "value-123", { scope: "global", source: "cli" });
      await vi.waitFor(() => expect(existsSync(marker)).toBe(true));
    },
  );

  it("registers a signal hook disabled too", async () => {
    const res = await registerHook()({
      type: "signal",
      key: "K",
      actions: ["write"],
      signalTarget: "some-daemon",
      signalName: "SIGKILL",
    });
    expect((JSON.parse(res.content[0].text) as { enabled: boolean }).enabled).toBe(false);
  });

  it("keeps http hooks (SSRF-guarded, no values) enabled", async () => {
    await registerHook()({
      type: "http",
      key: "K",
      actions: ["write"],
      url: "https://hooks.example.com/q-ring",
    });
    expect(listHooks().map((h) => h.enabled)).toEqual([true]);
  });
});
