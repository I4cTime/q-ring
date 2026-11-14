import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

vi.mock("@napi-rs/keyring", async () => {
  const fake = await import("../helpers/fake-keyring.js");
  return { Entry: fake.FakeEntry, findCredentials: fake.findCredentials };
});

import { FakeEntry, fakeKeyringDump, resetFakeKeyring } from "../helpers/fake-keyring.js";
import {
  EmptyStoredValueError,
  convertStorageRisks,
  deleteSecret,
  exportSecrets,
  findStorageRisks,
  getEnvelope,
  getSecret,
  hasSecret,
  listSecrets,
  secretExists,
  setSecret,
} from "../../core/keyring.js";
import { createEnvelope, parseEnvelope, collapseValue } from "../../core/envelope.js";
import { importDotenv } from "../../core/import.js";
import { lintFiles } from "../../core/linter.js";
import { globalService, projectService } from "../../core/scope.js";
import { queryAudit } from "../../core/observer.js";
import { execCommand } from "../../core/exec.js";
import { clearPolicyCache } from "../../core/policy.js";

const raw = (service: string, key: string) => fakeKeyringDump().get(`${service}\0${key}`);
const plant = (service: string, key: string, stored: string) =>
  new FakeEntry(service, key).setPassword(stored);

let project: string;

beforeEach(() => {
  resetFakeKeyring();
  clearPolicyCache();
  project = mkdtempSync(join(tmpdir(), "qring-empty-stored-"));
  plant(globalService(), "LOST_KEY", "");
});

afterEach(() => {
  vi.restoreAllMocks();
  clearPolicyCache();
  rmSync(project, { recursive: true, force: true });
});

describe("a key whose stored value is empty", () => {
  it("getSecret fails with EmptyStoredValueError naming key and scope, and writes nothing", () => {
    let caught: unknown;
    try {
      getSecret("LOST_KEY", { scope: "global" });
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(EmptyStoredValueError);
    const message = (caught as Error).message;
    expect(message).toContain('"LOST_KEY"');
    expect(message).toContain("global scope");
    expect(message).toContain("stored value is empty");
    expect(message).toContain("likely lost by the OS keyring");
    expect(message).toContain("qring doctor");
    expect(raw(globalService(), "LOST_KEY")).toBe("");
  });

  it("getEnvelope fails the same way and writes nothing", () => {
    expect(() => getEnvelope("LOST_KEY", { scope: "global" })).toThrow(EmptyStoredValueError);
    expect(raw(globalService(), "LOST_KEY")).toBe("");
  });

  it("setSecret re-sets it with fresh metadata", () => {
    setSecret("LOST_KEY", "new-value", { scope: "global" });
    const parsed = parseEnvelope(raw(globalService(), "LOST_KEY")!)!;
    expect(parsed.value).toBe("new-value");
    expect(parsed.meta.accessCount).toBe(0);
    expect(getSecret("LOST_KEY", { scope: "global", silent: true })).toBe("new-value");
  });

  it("deleteSecret removes it", () => {
    expect(deleteSecret("LOST_KEY", { scope: "global" })).toBe(true);
    expect(raw(globalService(), "LOST_KEY")).toBeUndefined();
  });

  it("hasSecret and secretExists count it as absent", () => {
    expect(hasSecret("LOST_KEY", { scope: "global" })).toBe(false);
    expect(hasSecret("LOST_KEY", { scope: "global", source: "mcp" })).toBe(false);
    expect(secretExists("LOST_KEY", { scope: "global" })).toBe(false);
  });

  it("hasSecret and secretExists move on to the next scope", () => {
    plant(projectService(project), "LOST_KEY", "");
    setSecret("LOST_KEY", "global-copy", { scope: "global" });
    expect(hasSecret("LOST_KEY", { projectPath: project })).toBe(true);
    expect(secretExists("LOST_KEY", { projectPath: project })).toBe(true);
  });

  it("import --skip-existing restores it", () => {
    const envFile = join(project, ".env");
    writeFileSync(envFile, "LOST_KEY=restored-value\n");
    const result = importDotenv(envFile, { scope: "global", skipExisting: true });
    expect(result.imported).toEqual(["LOST_KEY"]);
    expect(getSecret("LOST_KEY", { scope: "global", silent: true })).toBe("restored-value");
  });

  it("lint --fix stores the literal it removes from the source", () => {
    const literal = "sk-abcdef1234567890abcdef1234567890";
    const file = join(project, "app.ts");
    writeFileSync(file, `const api_key = "${literal}";\n`);
    const [result] = lintFiles([file], { fix: true, scope: "global", projectPath: project });
    plant(globalService(), result.keyName, "");
    // Re-run on a fresh copy now that the stored value is empty.
    writeFileSync(file, `const api_key = "${literal}";\n`);
    const [again] = lintFiles([file], { fix: true, scope: "global", projectPath: project });
    expect(again.fixed).toBe(true);
    expect(readFileSync(file, "utf8")).not.toContain(literal);
    expect(getSecret(again.keyName, { scope: "global", silent: true })).toBe(literal);
  });

  it("listSecrets keeps the entry, marked emptyStored, without throwing", () => {
    setSecret("GOOD_KEY", "good", { scope: "global" });
    const entries = listSecrets({ scope: "global" });
    const lost = entries.find((e) => e.key === "LOST_KEY");
    expect(lost).toEqual({ key: "LOST_KEY", scope: "global", emptyStored: true });
    expect(entries.find((e) => e.key === "GOOD_KEY")?.emptyStored).toBeUndefined();
  });

  it("exportSecrets skips it with one warning naming the key", () => {
    setSecret("GOOD_KEY", "good", { scope: "global" });
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const out = exportSecrets({ scope: "global", format: "json" });
    expect(JSON.parse(out)).toEqual({ GOOD_KEY: "good" });
    const lines = warn.mock.calls.map((c) => String(c[0])).filter((l) => l.includes("LOST_KEY"));
    expect(lines).toHaveLength(1);
    expect(lines[0]).toContain("empty");
  });

  it("exec skips it with one stderr warning and still runs", async () => {
    setSecret("GOOD_KEY", "good-value-123", { scope: "global" });
    const stderr: string[] = [];
    vi.spyOn(process.stderr, "write").mockImplementation((chunk: string | Uint8Array) => {
      stderr.push(String(chunk));
      return true;
    });
    const result = await execCommand({
      command: process.execPath,
      args: ["-e", "console.log(JSON.stringify([process.env.GOOD_KEY ? 'set' : 'unset', 'LOST_KEY' in process.env]))"],
      projectPath: project,
      scope: "global",
      source: "cli",
      captureOutput: true,
    });
    expect(result.code).toBe(0);
    expect(result.stdout).toContain('["set",false]');
    expect(stderr.filter((l) => l.includes('"LOST_KEY"'))).toHaveLength(1);
  });
});

describe("findStorageRisks", () => {
  it("reports plain JSON with a backslash as escape and an empty string as empty", () => {
    const escaped = createEnvelope('has "quotes"');
    plant(globalService(), "ESCAPED", JSON.stringify(escaped));
    plant(globalService(), "PLAIN", JSON.stringify(createEnvelope("no-escapes")));
    plant(globalService(), "LEGACY_SLASH", "C:\\path");
    plant(
      globalService(),
      "ALREADY_SAFE",
      JSON.stringify({
        v: 1,
        enc: "b64",
        data: Buffer.from(JSON.stringify(escaped), "utf8").toString("base64"),
      }),
    );
    plant(projectService(project), "PROJECT_ESCAPED", JSON.stringify(createEnvelope("a\nb")));
    plant(projectService(project), "PROJECT_LOST", "");

    expect(findStorageRisks({ projectPath: project })).toEqual([
      { key: "ESCAPED", scope: "global", kind: "escape" },
      { key: "LEGACY_SLASH", scope: "global", kind: "escape" },
      { key: "LOST_KEY", scope: "global", kind: "empty" },
      { key: "PROJECT_ESCAPED", scope: "project", kind: "escape" },
      { key: "PROJECT_LOST", scope: "project", kind: "empty" },
    ]);
    // Without a projectPath only global scope is scanned.
    expect(findStorageRisks().map((r) => r.key)).toEqual(["ESCAPED", "LEGACY_SLASH", "LOST_KEY"]);
  });

  it("never writes, records no audit event and bumps no access count", () => {
    plant(globalService(), "ESCAPED", JSON.stringify(createEnvelope('x"y')));
    const before = fakeKeyringDump();
    const eventsBefore = queryAudit({}).length;
    findStorageRisks({ projectPath: project });
    expect(fakeKeyringDump()).toEqual(before);
    expect(queryAudit({}).length).toBe(eventsBefore);
  });
});

describe.runIf(process.platform === "linux")("reading an at-risk entry on Linux", () => {
  it("converts it to the safe form and keeps the exact value", () => {
    const value = 'multi\nline "quoted" \\ value';
    plant(globalService(), "ESCAPED", JSON.stringify(createEnvelope(value)));
    expect(getSecret("ESCAPED", { scope: "global" })).toBe(value);
    const stored = raw(globalService(), "ESCAPED")!;
    expect(JSON.parse(stored)).toMatchObject({ v: 1, enc: "b64" });
    // eslint-disable-next-line no-control-regex
    expect(/[\\\u0000-\u001f]/.test(stored)).toBe(false);
    expect(collapseValue(parseEnvelope(stored)!)).toBe(value);
    expect(findStorageRisks().map((r) => r.key)).toEqual(["LOST_KEY"]);
  });
});

describe("entries the keyring empties between two reads", () => {
  /** Make Entry.getPassword return "" for `key` from its `fromCall`-th call on. */
  const emptyAfter = (key: string, fromCall: number) => {
    const real = FakeEntry.prototype.getPassword;
    let calls = 0;
    vi.spyOn(FakeEntry.prototype, "getPassword").mockImplementation(function (this: FakeEntry) {
      const value = real.call(this);
      if ((this as unknown as { account: string }).account !== key) return value;
      calls++;
      return calls >= fromCall ? "" : value;
    });
  };

  it("exec skips a key listed healthy but empty when read", async () => {
    setSecret("RACED_KEY", "raced-value-123", { scope: "global" });
    emptyAfter("RACED_KEY", 1);
    const stderr: string[] = [];
    vi.spyOn(process.stderr, "write").mockImplementation((chunk: string | Uint8Array) => {
      stderr.push(String(chunk));
      return true;
    });
    const result = await execCommand({
      command: process.execPath,
      args: ["-e", "console.log('RACED_KEY' in process.env)"],
      projectPath: project,
      scope: "global",
      source: "cli",
      captureOutput: true,
    });
    expect(result.code).toBe(0);
    expect(result.stdout).toContain("false");
    expect(stderr.filter((l) => l.includes('not injecting "RACED_KEY"'))).toHaveLength(1);
  });

  it("getSecret returns the value and writes it back when the re-read finds it empty", () => {
    const value = 'multi\nline "quoted"';
    plant(globalService(), "RESCUED", JSON.stringify(createEnvelope(value)));
    emptyAfter("RESCUED", 2);
    expect(getSecret("RESCUED", { scope: "global" })).toBe(value);
    vi.restoreAllMocks();
    const stored = raw(globalService(), "RESCUED")!;
    const parsed = parseEnvelope(stored)!;
    expect(collapseValue(parsed)).toBe(value);
    expect(parsed.meta.accessCount).toBe(1);
    if (process.platform === "linux") {
      expect(JSON.parse(stored)).toMatchObject({ v: 1, enc: "b64" });
    }
  });
});

describe("convertStorageRisks", () => {
  it("rewrites at-risk entries from one snapshot, expired and canary ones included, without reads", () => {
    const expired = createEnvelope('old "value"', { expiresAt: new Date(Date.now() - 60_000).toISOString() });
    const canary = createEnvelope('fake\\token', { canary: true });
    plant(globalService(), "EXPIRED", JSON.stringify(expired));
    plant(globalService(), "CANARY", JSON.stringify(canary));
    plant(globalService(), "PLAIN", JSON.stringify(createEnvelope("no-escapes")));
    plant(projectService(project), "PROJ", "C:\\legacy");
    const plainBefore = raw(globalService(), "PLAIN");
    const before = new Set(queryAudit({}).map((e) => JSON.stringify(e)));

    const result = convertStorageRisks({ projectPath: project });

    expect(result).toEqual({
      converted: [
        { key: "CANARY", scope: "global" },
        { key: "EXPIRED", scope: "global" },
        { key: "PROJ", scope: "project" },
      ],
      failed: [],
    });
    expect(raw(globalService(), "PLAIN")).toBe(plainBefore);
    const canaryAfter = parseEnvelope(raw(globalService(), "CANARY")!)!;
    expect(canaryAfter.value).toBe("fake\\token");
    expect(canaryAfter.meta.canary).toBe(true);
    expect(canaryAfter.meta.accessCount).toBe(0);
    expect(collapseValue(parseEnvelope(raw(globalService(), "EXPIRED")!)!)).toBe('old "value"');
    expect(collapseValue(parseEnvelope(raw(projectService(project), "PROJ")!)!)).toBe("C:\\legacy");

    const events = queryAudit({}).filter((e) => !before.has(JSON.stringify(e)));
    expect(events.some((e) => e.action === "canary")).toBe(false);
    expect(events.some((e) => e.action === "read")).toBe(false);
    const converted = events.filter((e) => e.detail === "storage form converted");
    expect(converted.map((e) => e.key).sort()).toEqual(["CANARY", "EXPIRED", "PROJ"]);
    expect(converted.every((e) => e.action === "write")).toBe(true);
    if (process.platform === "linux") {
      expect(findStorageRisks({ projectPath: project }).map((r) => r.key)).toEqual(["LOST_KEY"]);
    }
  });

  it("writes from the snapshot even when the stored copy is emptied meanwhile", () => {
    const value = 'a "quoted" value';
    plant(globalService(), "RACED", JSON.stringify(createEnvelope(value)));
    vi.spyOn(FakeEntry.prototype, "getPassword").mockReturnValue("");
    expect(convertStorageRisks().converted).toEqual([{ key: "RACED", scope: "global" }]);
    vi.restoreAllMocks();
    expect(collapseValue(parseEnvelope(raw(globalService(), "RACED")!)!)).toBe(value);
  });
});
