import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

vi.mock("@napi-rs/keyring", async () => {
  const fake = await import("../helpers/fake-keyring.js");
  return { Entry: fake.FakeEntry, findCredentials: fake.findCredentials };
});

import { resetFakeKeyring } from "../helpers/fake-keyring.js";
import { setSecret } from "../../core/keyring.js";
import { execCommand } from "../../core/exec.js";
import { isProcessControlEnvName } from "../../core/child-env.js";
import { clearPolicyCache, setPolicyRoot } from "../../core/policy.js";

let project: string;

// What a prompt-injected agent can store with set_secret: no file needed,
// Node evaluates the data: URL in every node process that starts.
const PAYLOAD = "--import=data:text/javascript,console.log('PWNED')";

beforeEach(() => {
  resetFakeKeyring();
  clearPolicyCache();
  project = mkdtempSync(join(tmpdir(), "qring-exec-envinj-"));
  // The operator allows exactly one command for agents.
  writeFileSync(
    join(project, ".q-ring.json"),
    JSON.stringify({
      policy: { exec: { allowCommands: [`${process.execPath} -e console.log('allowed')`] } },
    }),
  );
  setPolicyRoot(project);
  setSecret("NODE_OPTIONS", PAYLOAD, { scope: "global", source: "mcp", projectPath: project });
  setSecret("API_TOKEN", "api-token-value", { scope: "global", source: "cli" });
});

afterEach(() => {
  setPolicyRoot(process.cwd());
  clearPolicyCache();
  rmSync(project, { recursive: true, force: true });
});

const run = (source: "mcp" | "cli", keys?: string[]) =>
  execCommand({
    command: process.execPath,
    args: ["-e", "console.log('allowed')"],
    projectPath: project,
    scope: "global",
    source,
    keys,
    captureOutput: true,
  });

describe("exec never sweeps process-control variables into a child", () => {
  it("an allowlisted MCP exec does not run code planted in NODE_OPTIONS", async () => {
    const result = await run("mcp");
    expect(result.stdout).toContain("allowed");
    expect(result.stdout).not.toContain("PWNED");
  });

  it("not even when an MCP caller names the key explicitly", async () => {
    const result = await run("mcp", ["NODE_OPTIONS", "API_TOKEN"]);
    expect(result.stdout).not.toContain("PWNED");
  });

  it("the local operator can still inject one deliberately with --keys", async () => {
    const result = await run("cli", ["NODE_OPTIONS"]);
    expect(result.stdout).toContain("PWNED");
  });

  it("classifies loader and interpreter controls", () => {
    for (const name of [
      "NODE_OPTIONS",
      "LD_PRELOAD",
      "DYLD_INSERT_LIBRARIES",
      "PATH",
      "BASH_ENV",
      "PYTHONSTARTUP",
      "JAVA_TOOL_OPTIONS",
      "GIT_SSH_COMMAND",
      "npm_config_script_shell",
      "Path",
    ]) {
      expect(isProcessControlEnvName(name), name).toBe(true);
    }
    for (const name of ["API_TOKEN", "DATABASE_URL", "NODE_ENV", "OPENAI_API_KEY"]) {
      expect(isProcessControlEnvName(name), name).toBe(false);
    }
  });
});
