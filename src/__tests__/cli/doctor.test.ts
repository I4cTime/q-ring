import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

vi.mock("@napi-rs/keyring", async () => {
  const fake = await import("../helpers/fake-keyring.js");
  return { Entry: fake.FakeEntry, findCredentials: fake.findCredentials };
});

import { createProgram } from "../../cli/commands.js";
import { clearPolicyCache } from "../../core/policy.js";
import { resetFakeKeyring } from "../helpers/fake-keyring.js";

interface Check {
  name: string;
  status: "ok" | "warn" | "fail";
  detail: string;
}

let dir: string;

beforeEach(() => {
  resetFakeKeyring();
  clearPolicyCache();
  dir = mkdtempSync(join(tmpdir(), "qring-doctor-"));
  vi.spyOn(console, "error").mockImplementation(() => {});
});

afterEach(() => {
  vi.restoreAllMocks();
  clearPolicyCache();
  process.exitCode = undefined;
  rmSync(dir, { recursive: true, force: true });
});

async function runDoctor(...extra: string[]): Promise<string> {
  const out: string[] = [];
  vi.spyOn(process.stdout, "write").mockImplementation((chunk: string | Uint8Array) => {
    out.push(String(chunk));
    return true;
  });
  vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => {
    out.push(args.map(String).join(" ") + "\n");
  });
  await createProgram().parseAsync(["node", "qring", "doctor", "--project-path", dir, ...extra]);
  return out.join("");
}

describe("qring doctor on a .q-ring.json that is not valid JSON", () => {
  it("reports the policy as a fail check inside the full JSON report", async () => {
    writeFileSync(join(dir, ".q-ring.json"), "{ not json");
    const report = JSON.parse(await runDoctor("--json")) as {
      ok: boolean;
      data: { checks: Check[]; healthy: boolean };
    };
    const names = report.data.checks.map((c) => c.name);
    expect(names).toEqual([
      "node runtime",
      "keyring backend",
      "audit log",
      "project manifest",
      "governance policy",
      "approval bindings",
      "qring-mcp binary",
    ]);
    const policy = report.data.checks.find((c) => c.name === "governance policy")!;
    expect(policy.status).toBe("fail");
    expect(policy.detail).toContain("not valid JSON");
    expect(policy.detail).toContain(join(dir, ".q-ring.json"));
    expect(report.data.checks.find((c) => c.name === "project manifest")!.status).toBe("fail");
    expect(report.data.healthy).toBe(false);
    expect(process.exitCode).toBe(1);
  });

  it("prints every check in the human report", async () => {
    writeFileSync(join(dir, ".q-ring.json"), "{ not json");
    const out = await runDoctor();
    expect(out).toMatch(/governance policy.*Invalid config/);
    expect(out).toContain("approval bindings");
    expect(out).toContain("qring-mcp binary");
    expect(out).toMatch(/check\(s\) failed/);
  });

  it("reads the policy from --project-path, not the cwd", async () => {
    writeFileSync(
      join(dir, ".q-ring.json"),
      JSON.stringify({ policy: { mcp: { denyTools: ["audit_log"] } } }),
    );
    const report = JSON.parse(await runDoctor("--json")) as { data: { checks: Check[] } };
    const policy = report.data.checks.find((c) => c.name === "governance policy")!;
    expect(policy.status).toBe("ok");
    expect(policy.detail).toContain("mcp");
  });
});
