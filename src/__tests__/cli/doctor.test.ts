import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

vi.mock("@napi-rs/keyring", async () => {
  const fake = await import("../helpers/fake-keyring.js");
  return { Entry: fake.FakeEntry, findCredentials: fake.findCredentials };
});

import { createProgram } from "../../cli/commands.js";
import { sniffDefaultKeyring } from "../../cli/commands/doctor.js";
import { clearPolicyCache } from "../../core/policy.js";
import { createEnvelope } from "../../core/envelope.js";
import { globalService } from "../../core/scope.js";
import { queryAudit } from "../../core/observer.js";
import { FakeEntry, resetFakeKeyring } from "../helpers/fake-keyring.js";

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
      "keyring storage format",
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

describe("sniffDefaultKeyring", () => {
  it("reports no-dir when the keyrings folder does not exist", () => {
    expect(sniffDefaultKeyring(join(dir, "nope"))).toEqual({ format: "no-dir" });
  });

  it("detects a plaintext passwordless keyring named by the default alias", () => {
    writeFileSync(join(dir, "default"), "Default_keyring\n");
    writeFileSync(join(dir, "Default_keyring.keyring"), "[keyring]\ndisplay-name=Default keyring\n");
    expect(sniffDefaultKeyring(dir)).toEqual({ format: "plaintext", name: "Default_keyring" });
  });

  it("detects the encrypted format from its magic", () => {
    writeFileSync(join(dir, "default"), "secure");
    writeFileSync(join(dir, "secure.keyring"), Buffer.from("GnomeKeyring\n\r\0\n\x00\x01binary", "latin1"));
    expect(sniffDefaultKeyring(dir)).toEqual({ format: "encrypted", name: "secure" });
  });

  it("falls back to login when there is no default alias", () => {
    writeFileSync(join(dir, "login.keyring"), "[keyring]\n");
    expect(sniffDefaultKeyring(dir)).toEqual({ format: "plaintext", name: "login" });
  });

  it("reports a missing file and an unknown format", () => {
    expect(sniffDefaultKeyring(dir)).toEqual({ format: "missing", name: "login" });
    writeFileSync(join(dir, "login.keyring"), "something else");
    expect(sniffDefaultKeyring(dir)).toEqual({ format: "unknown", name: "login" });
  });
});

describe.runIf(process.platform === "linux")("qring doctor keyring storage format", () => {
  let dataHome: string;
  let savedDataHome: string | undefined;

  beforeEach(() => {
    savedDataHome = process.env.XDG_DATA_HOME;
    dataHome = mkdtempSync(join(tmpdir(), "qring-doctor-data-"));
    process.env.XDG_DATA_HOME = dataHome;
  });

  afterEach(() => {
    process.env.XDG_DATA_HOME = savedDataHome;
    rmSync(dataHome, { recursive: true, force: true });
  });

  type StorageCheck = Check & {
    converted?: { key: string; scope: string }[];
    convertFailed?: { key: string; scope: string }[];
  };
  const storageCheck = async (...extra: string[]) => {
    const report = JSON.parse(await runDoctor("--json", ...extra)) as {
      data: { checks: StorageCheck[] };
    };
    return report.data.checks.find((c) => c.name === "keyring storage format")!;
  };

  it("is ok and not applicable without a keyrings folder", async () => {
    const check = await storageCheck();
    expect(check.status).toBe("ok");
    expect(check.detail).toContain("not applicable");
  });

  it("is ok on an encrypted default keyring", async () => {
    mkdirSync(join(dataHome, "keyrings"));
    writeFileSync(join(dataHome, "keyrings", "login.keyring"), "GnomeKeyring\n\r\0\n");
    expect((await storageCheck()).status).toBe("ok");
  });

  it("warns on a plaintext keyring and names the keys at risk and the keys lost", async () => {
    mkdirSync(join(dataHome, "keyrings"));
    writeFileSync(join(dataHome, "keyrings", "login.keyring"), "[keyring]\n");
    new FakeEntry(globalService(), "AT_RISK").setPassword(JSON.stringify(createEnvelope('a"b')));
    new FakeEntry(globalService(), "LOST").setPassword("");
    new FakeEntry(globalService(), "FINE").setPassword(JSON.stringify(createEnvelope("ok")));
    const check = await storageCheck();
    expect(check.status).toBe("warn");
    expect(check.detail).toContain("passwordless and kept as plain text");
    expect(check.detail).toContain("still at risk: AT_RISK (global)");
    expect(check.detail).toContain("run `qring doctor --fix` to convert them");
    expect(check.detail).not.toContain("qring get");
    expect(check.converted).toBeUndefined();
    expect(check.detail).toContain("LOST (global) - value lost, set it again");
    expect(check.detail).not.toContain("FINE");
  });

  it("says so when a plaintext keyring has nothing at risk", async () => {
    mkdirSync(join(dataHome, "keyrings"));
    writeFileSync(join(dataHome, "keyrings", "login.keyring"), "[keyring]\n");
    const check = await storageCheck();
    expect(check.status).toBe("warn");
    expect(check.detail).toContain("no entries at risk in global scope and this project");
  });

  it("--fix converts at-risk entries before the backend probe and reports them", async () => {
    mkdirSync(join(dataHome, "keyrings"));
    writeFileSync(join(dataHome, "keyrings", "login.keyring"), "[keyring]\n");
    new FakeEntry(globalService(), "AT_RISK").setPassword(JSON.stringify(createEnvelope('a"b')));
    new FakeEntry(globalService(), "LOST").setPassword("");
    const order: string[] = [];
    const realSet = FakeEntry.prototype.setPassword;
    vi.spyOn(FakeEntry.prototype, "setPassword").mockImplementation(function (
      this: FakeEntry,
      password: string,
    ) {
      order.push((this as unknown as { account: string }).account);
      return realSet.call(this, password);
    });

    const check = await storageCheck("--fix");

    expect(order.indexOf("AT_RISK")).toBeGreaterThanOrEqual(0);
    expect(order.indexOf("AT_RISK")).toBeLessThan(order.indexOf("PROBE"));
    expect(check.status).toBe("warn");
    expect(check.converted).toEqual([{ key: "AT_RISK", scope: "global" }]);
    expect(check.convertFailed).toEqual([]);
    expect(check.detail).toContain("converted to the safe form: AT_RISK (global)");
    expect(check.detail).not.toContain("still at risk");
    expect(check.detail).toContain("already empty: LOST (global)");
    expect(new FakeEntry(globalService(), "AT_RISK").getPassword()).not.toContain("\\");
    expect(queryAudit({}).some((e) => e.key === "AT_RISK" && e.detail === "storage form converted")).toBe(true);
  });

  it("keeps the displayed order of the checks", async () => {
    const report = JSON.parse(await runDoctor("--json", "--fix")) as { data: { checks: Check[] } };
    expect(report.data.checks.map((c) => c.name).slice(0, 3)).toEqual([
      "node runtime",
      "keyring backend",
      "keyring storage format",
    ]);
  });
});
