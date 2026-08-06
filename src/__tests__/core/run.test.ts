import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

vi.mock("@napi-rs/keyring", async () => {
  const fake = await import("../helpers/fake-keyring.js");
  return { Entry: fake.FakeEntry, findCredentials: fake.findCredentials };
});

import { resetFakeKeyring } from "../helpers/fake-keyring.js";
import { setSecret } from "../../core/keyring.js";
import { clearCollapseCache } from "../../core/collapse.js";
import { buildRunPlan, runCommand } from "../../core/run.js";

let project: string;

beforeEach(() => {
  resetFakeKeyring();
  clearCollapseCache();
  project = mkdtempSync(join(tmpdir(), "qring-run-test-"));
});

afterEach(() => {
  rmSync(project, { recursive: true, force: true });
});

function writeManifest(secrets: Record<string, object>): void {
  writeFileSync(join(project, ".q-ring.json"), JSON.stringify({ secrets }));
  clearCollapseCache();
}

describe("buildRunPlan", () => {
  it("injects manifest keys from the keyring (project over global)", () => {
    writeManifest({ API_KEY: { required: true } });
    setSecret("API_KEY", "from-project", { scope: "project", projectPath: project, silent: true });

    const plan = buildRunPlan({ command: "true", args: [], projectPath: project, silent: true });

    expect(plan.envMap.API_KEY).toBe("from-project");
    expect(plan.injected).toContainEqual({ name: "API_KEY", source: "manifest" });
    expect(plan.secretsToRedact).toContain("from-project");
    expect(plan.missingRequired).toEqual([]);
  });

  it("reports missing required manifest keys", () => {
    writeManifest({ MISSING_ONE: { required: true }, OPTIONAL_ONE: { required: false } });

    const plan = buildRunPlan({ command: "true", args: [], projectPath: project, silent: true });

    expect(plan.missingRequired).toEqual(["MISSING_ONE"]);
    expect(plan.missingOptional).toEqual(["OPTIONAL_ONE"]);
  });

  it("treats manifest keys as required by default", () => {
    writeManifest({ UNSPECIFIED: {} });
    const plan = buildRunPlan({ command: "true", args: [], projectPath: project, silent: true });
    expect(plan.missingRequired).toEqual(["UNSPECIFIED"]);
  });

  it("resolves qring:// refs in the default .env and passes plain values through", () => {
    setSecret("DB_URL", "postgres://real", { scope: "project", projectPath: project, silent: true });
    writeFileSync(
      join(project, ".env"),
      'DATABASE_URL=qring://project/DB_URL\nLOG_LEVEL=debug\n',
    );

    const plan = buildRunPlan({ command: "true", args: [], projectPath: project, silent: true });

    expect(plan.envMap.DATABASE_URL).toBe("postgres://real");
    expect(plan.envMap.LOG_LEVEL).toBe("debug");
    expect(plan.injected).toContainEqual({ name: "DATABASE_URL", source: "env-file-ref" });
    expect(plan.injected).toContainEqual({ name: "LOG_LEVEL", source: "env-file" });
    expect(plan.secretsToRedact).toContain("postgres://real");
  });

  it("a missing ref in a .env file is fatal", () => {
    writeFileSync(join(project, ".env"), "TOKEN=qring:///NOT_STORED\n");
    const plan = buildRunPlan({ command: "true", args: [], projectPath: project, silent: true });
    expect(plan.missingRequired).toEqual(["TOKEN"]);
  });

  it("env-file values win over manifest values", () => {
    writeManifest({ SHARED: { required: true } });
    setSecret("SHARED", "manifest-value", { scope: "project", projectPath: project, silent: true });
    writeFileSync(join(project, ".env"), "SHARED=file-value\n");

    const plan = buildRunPlan({ command: "true", args: [], projectPath: project, silent: true });
    expect(plan.envMap.SHARED).toBe("file-value");
  });

  it("explicit env files override the default and missing files throw", () => {
    writeFileSync(join(project, "custom.env"), "FROM_CUSTOM=1\n");
    const plan = buildRunPlan({
      command: "true", args: [], projectPath: project, silent: true,
      envFiles: ["custom.env"],
    });
    expect(plan.envMap.FROM_CUSTOM).toBe("1");

    expect(() =>
      buildRunPlan({
        command: "true", args: [], projectPath: project, silent: true,
        envFiles: ["nope.env"],
      }),
    ).toThrow(/Env file not found/);
  });

  it("--no-manifest skips manifest resolution", () => {
    writeManifest({ WOULD_FAIL: { required: true } });
    const plan = buildRunPlan({
      command: "true", args: [], projectPath: project, silent: true,
      useManifest: false,
    });
    expect(plan.missingRequired).toEqual([]);
    expect(plan.injected).toEqual([]);
  });
});

describe("runCommand", () => {
  it("fails fast when required secrets are missing", async () => {
    writeManifest({ REQUIRED_KEY: { required: true } });
    await expect(
      runCommand({ command: "true", args: [], projectPath: project, silent: true }),
    ).rejects.toThrow(/Missing required secrets: REQUIRED_KEY/);
  });

  it("runs the child with injected env and redacts secret output", async () => {
    writeManifest({ INJECTED_TOKEN: { required: true } });
    setSecret("INJECTED_TOKEN", "super-secret-value", {
      scope: "project", projectPath: project, silent: true,
    });

    const result = await runCommand({
      command: process.execPath,
      args: ["-e", "console.log('token is ' + process.env.INJECTED_TOKEN)"],
      projectPath: project,
      silent: true,
      captureOutput: true,
    });

    expect(result.code).toBe(0);
    expect(result.stdout).toContain("[QRING:REDACTED]");
    expect(result.stdout).not.toContain("super-secret-value");
  });

  it("enforces the exec profile deny list", async () => {
    await expect(
      runCommand({
        command: "curl", args: ["http://example.com"],
        projectPath: project, silent: true, profile: "restricted", captureOutput: true,
      }),
    ).rejects.toThrow(/denies command/);
  });
});
