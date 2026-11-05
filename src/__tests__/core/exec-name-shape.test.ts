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
import { runCommand } from "../../core/run.js";
import { clearPolicyCache, setPolicyRoot } from "../../core/policy.js";
import { clearCollapseCache } from "../../core/collapse.js";

const NOTE = '[QRING] not injecting "stripe-key": not a plain environment variable name\n';
const PRINT =
  "console.log(JSON.stringify([process.env['stripe-key'] ? 'set' : null, process.env.VALID_KEY ? 'set' : null]))";

let dir: string;
let stderr: string[];

beforeEach(() => {
  resetFakeKeyring();
  clearPolicyCache();
  clearCollapseCache();
  dir = mkdtempSync(join(tmpdir(), "qring-name-shape-"));
  setPolicyRoot(dir);
  setSecret("stripe-key", "sk-dashed-name-value", { scope: "global", source: "cli" });
  setSecret("VALID_KEY", "valid-value-123", { scope: "global", source: "cli" });
  stderr = [];
  const realWrite = process.stderr.write.bind(process.stderr);
  vi.spyOn(process.stderr, "write").mockImplementation(((chunk: unknown, ...rest: unknown[]) => {
    stderr.push(String(chunk));
    return (realWrite as (...a: unknown[]) => boolean)(chunk, ...rest);
  }) as typeof process.stderr.write);
});

afterEach(() => {
  vi.restoreAllMocks();
  setPolicyRoot(process.cwd());
  clearPolicyCache();
  clearCollapseCache();
  rmSync(dir, { recursive: true, force: true });
});

const execCli = (keys?: string[]) =>
  execCommand({
    command: process.execPath,
    args: ["-e", PRINT],
    keys,
    scope: "global",
    projectPath: dir,
    source: "cli",
    captureOutput: true,
  });

describe("the name-shape rule on the CLI path", () => {
  it("qring exec skips a dashed key with the exact note, valid keys still inject", async () => {
    const result = await execCli();
    expect(JSON.parse(result.stdout.trim())).toEqual([null, "set"]);
    expect(stderr).toContain(NOTE);
  });

  it("--keys cannot override the shape rule", async () => {
    const result = await execCli(["stripe-key", "VALID_KEY"]);
    expect(JSON.parse(result.stdout.trim())).toEqual([null, "set"]);
    expect(stderr).toContain(NOTE);
  });

  it("qring run applies it to manifest keys too", async () => {
    writeFileSync(
      join(dir, ".q-ring.json"),
      JSON.stringify({ secrets: { "stripe-key": {}, VALID_KEY: {} } }),
    );
    clearCollapseCache();
    const result = await runCommand({
      command: process.execPath,
      args: ["-e", PRINT],
      projectPath: dir,
      captureOutput: true,
    });
    expect(JSON.parse(result.stdout.trim())).toEqual([null, "set"]);
    expect(stderr).toContain(NOTE);
  });
});
