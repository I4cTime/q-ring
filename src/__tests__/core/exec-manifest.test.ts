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
import { setSecret } from "../../core/keyring.js";
import { execCommand, NO_MANIFEST_NOTE } from "../../core/exec.js";
import { clearPolicyCache, setPolicyRoot } from "../../core/policy.js";
import { clearCollapseCache } from "../../core/collapse.js";
import { registerToolingTools } from "../../mcp/tools/tooling.js";

let dir: string;
let elsewhere: string;
const PRINT_ENV =
  "console.log(JSON.stringify(['A_KEY','B_KEY','C_KEY','TAR_OPTIONS'].filter((k) => process.env[k] !== undefined)))";

function writeConfig(withManifest: boolean): void {
  writeFileSync(
    join(dir, ".q-ring.json"),
    JSON.stringify({
      ...(withManifest ? { secrets: { A_KEY: { required: true }, B_KEY: {} } } : {}),
      policy: { exec: { allowCommands: [process.execPath] } },
    }),
  );
  clearPolicyCache();
  clearCollapseCache();
}

beforeEach(() => {
  resetFakeKeyring();
  dir = mkdtempSync(join(tmpdir(), "qring-exec-manifest-"));
  elsewhere = mkdtempSync(join(tmpdir(), "qring-exec-elsewhere-"));
  setPolicyRoot(dir);
  for (const k of ["A_KEY", "B_KEY", "C_KEY"]) {
    setSecret(k, `${k.toLowerCase()}-value`, { scope: "global", source: "cli" });
  }
  // What an agent plants: a tar inline-code gadget.
  setSecret("TAR_OPTIONS", "--checkpoint=1 --checkpoint-action=exec=id", {
    scope: "global",
    source: "mcp",
    projectPath: dir,
  });
});

afterEach(() => {
  setPolicyRoot(process.cwd());
  clearPolicyCache();
  clearCollapseCache();
  rmSync(dir, { recursive: true, force: true });
  rmSync(elsewhere, { recursive: true, force: true });
});

const run = (keys?: string[], projectPath = dir) =>
  execCommand({
    command: process.execPath,
    args: ["-e", PRINT_ENV],
    keys,
    scope: "global",
    projectPath,
    source: "mcp",
    captureOutput: true,
  });

const injected = (stdout: string) => JSON.parse(stdout.trim()) as string[];

describe("exec_with_secrets injects only what the manifest declares", () => {
  it("the child sees the declared keys only", async () => {
    writeConfig(true);
    const result = await run();
    expect(injected(result.stdout)).toEqual(["A_KEY", "B_KEY"]);
    expect(result.note).toBeUndefined();
  });

  it("even when the agent names an undeclared key in `keys`", async () => {
    writeConfig(true);
    expect(injected((await run(["TAR_OPTIONS", "C_KEY", "A_KEY"])).stdout)).toEqual(["A_KEY"]);
  });

  it("the manifest comes from the pinned policy root, not a caller-chosen projectPath", async () => {
    writeConfig(true);
    expect(injected((await run(undefined, elsewhere)).stdout)).toEqual(["A_KEY", "B_KEY"]);
  });

  it("without a manifest every scoped secret is injected (denylist applied) and the result says so", async () => {
    writeConfig(false);
    const result = await run();
    expect(injected(result.stdout)).toEqual(["A_KEY", "B_KEY", "C_KEY"]);
    expect(result.note).toBe(NO_MANIFEST_NOTE);

    let tool:
      ((p: Record<string, unknown>) => Promise<{ content: { text: string }[] }>) | undefined;
    const stub = {
      tool: (n: string, ...rest: unknown[]) => {
        if (n === "exec_with_secrets") tool = rest[rest.length - 1] as typeof tool;
      },
    };
    registerToolingTools(stub as unknown as McpServer);
    const res = await tool!({
      command: process.execPath,
      args: ["-e", PRINT_ENV],
      profile: "unrestricted",
      scope: "global",
      projectPath: dir,
    });
    expect(res.content[0].text).toContain(`NOTE: ${NO_MANIFEST_NOTE}`);
  });
});
