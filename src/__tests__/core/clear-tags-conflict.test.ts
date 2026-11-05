import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

vi.mock("@napi-rs/keyring", async () => {
  const fake = await import("../helpers/fake-keyring.js");
  return { Entry: fake.FakeEntry, findCredentials: fake.findCredentials };
});

import { setSecret, getSecret, getEnvelope } from "../../core/keyring.js";
import { createProgram } from "../../cli/commands.js";
import { registerSecretTools } from "../../mcp/tools/secrets.js";
import { resetFakeKeyring } from "../helpers/fake-keyring.js";

beforeEach(() => {
  resetFakeKeyring();
  setSecret("K", "original", { scope: "global", source: "cli", tags: ["prod"] });
});

afterEach(() => {
  vi.restoreAllMocks();
});

const unchanged = () => {
  expect(getSecret("K", { scope: "global", silent: true })).toBe("original");
  expect(getEnvelope("K", { scope: "global" })!.envelope.meta.tags).toEqual(["prod"]);
};

describe("--tags together with --clear-tags is refused", () => {
  it("CLI: exits 1 without writing", async () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    const exit = vi.spyOn(process, "exit").mockImplementation(((code?: number) => {
      throw new Error(`exit ${code}`);
    }) as typeof process.exit);
    const program = createProgram();
    program.exitOverride();
    await expect(
      program.parseAsync(["set", "K", "new", "--global", "--tags", "x", "--clear-tags"], {
        from: "user",
      }),
    ).rejects.toThrow("exit 1");
    expect(exit).toHaveBeenCalledWith(1);
    unchanged();
  });

  it("MCP set_secret: returns an error without writing", async () => {
    let setTool:
      | ((
          p: Record<string, unknown>,
        ) => Promise<{ content: { text: string }[]; isError?: boolean }>)
      | undefined;
    const stub = {
      tool: (n: string, ...rest: unknown[]) => {
        if (n === "set_secret") setTool = rest[rest.length - 1] as typeof setTool;
      },
    };
    registerSecretTools(stub as unknown as McpServer);
    const res = await setTool!({
      key: "K",
      value: "new",
      scope: "global",
      tags: ["x"],
      clearTags: true,
    });
    expect(res.isError).toBe(true);
    expect(res.content[0].text).toMatch(/either `tags` or `clearTags`/);
    unchanged();
  });
});
