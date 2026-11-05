import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

vi.mock("@napi-rs/keyring", async () => {
  const fake = await import("../helpers/fake-keyring.js");
  return { Entry: fake.FakeEntry, findCredentials: fake.findCredentials };
});

// getPolicySummary passes through to the real one unless a test overrides it.
const summaryOverride = vi.hoisted(() => ({ impl: null as null | (() => never) }));
vi.mock("../../core/policy.js", async (importOriginal) => {
  const real = await importOriginal<typeof import("../../core/policy.js")>();
  return {
    ...real,
    getPolicySummary: (...args: Parameters<typeof real.getPolicySummary>) =>
      summaryOverride.impl ? summaryOverride.impl() : real.getPolicySummary(...args),
  };
});

import { createProgram } from "../../cli/commands.js";
import { clearPolicyCache } from "../../core/policy.js";

const originalCwd = process.cwd();
let dir: string;
let stdout: string[];
let stderr: string[];

beforeEach(() => {
  summaryOverride.impl = null;
  clearPolicyCache();
  dir = mkdtempSync(join(tmpdir(), "qring-policy-cmd-"));
  writeFileSync(join(dir, ".q-ring.json"), "{ not json");
  process.chdir(dir); // `qring policy` reads the cwd's .q-ring.json
  stdout = [];
  stderr = [];
  vi.spyOn(process.stdout, "write").mockImplementation((chunk: string | Uint8Array) => {
    stdout.push(String(chunk));
    return true;
  });
  vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => {
    stdout.push(args.map(String).join(" ") + "\n");
  });
  vi.spyOn(console, "error").mockImplementation((...args: unknown[]) => {
    stderr.push(args.map(String).join(" ") + "\n");
  });
  vi.spyOn(console, "warn").mockImplementation((...args: unknown[]) => {
    stderr.push(args.map(String).join(" ") + "\n");
  });
});

afterEach(() => {
  vi.restoreAllMocks();
  summaryOverride.impl = null;
  process.chdir(originalCwd);
  clearPolicyCache();
  process.exitCode = undefined;
  rmSync(dir, { recursive: true, force: true });
});

function runPolicy(...extra: string[]) {
  return createProgram().parseAsync(["node", "qring", "policy", ...extra]);
}

describe("qring policy on a .q-ring.json that is not valid JSON", () => {
  it("prints the error and exits 1", async () => {
    await runPolicy();
    const out = stdout.join("");
    expect(out).toContain("Governance Policy");
    expect(out).toMatch(/Invalid config: .*\.q-ring\.json is not valid JSON/);
    expect(process.exitCode).toBe(1);
  });

  it("--json prints exactly { policyError } on stdout and exits 1", async () => {
    await runPolicy("--json");
    const out = stdout.join("");
    const parsed = JSON.parse(out) as Record<string, unknown>; // nothing but JSON
    expect(Object.keys(parsed)).toEqual(["policyError"]);
    expect(parsed.policyError).toMatch(/not valid JSON/);
    expect(process.exitCode).toBe(1);
    // The loud fail-closed warning goes to stderr, never into the JSON.
    expect(stderr.join("")).toMatch(/q-ring: Invalid config/);
  });

  it("does not swallow an error that is not a PolicyConfigError", async () => {
    summaryOverride.impl = () => {
      throw new Error("disk on fire");
    };
    await expect(runPolicy("--json")).rejects.toThrow("disk on fire");
    expect(stdout.join("")).not.toContain("policyError");
    expect(process.exitCode).not.toBe(1);
  });
});
