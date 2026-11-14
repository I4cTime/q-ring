import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

vi.mock("@napi-rs/keyring", async () => {
  const fake = await import("../helpers/fake-keyring.js");
  return { Entry: fake.FakeEntry, findCredentials: fake.findCredentials };
});

import { FakeEntry, fakeKeyringDump, resetFakeKeyring } from "../helpers/fake-keyring.js";
import {
  EmptyStoredValueError,
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
import { createEnvelope, parseEnvelope, isSafeForm, collapseValue } from "../../core/envelope.js";
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

  it("hasSecret and secretExists stay true", () => {
    expect(hasSecret("LOST_KEY", { scope: "global" })).toBe(true);
    expect(hasSecret("LOST_KEY", { scope: "global", source: "mcp" })).toBe(true);
    expect(secretExists("LOST_KEY", { scope: "global" })).toBe(true);
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
    expect(isSafeForm(stored)).toBe(true);
    // eslint-disable-next-line no-control-regex
    expect(/[\\\u0000-\u001f]/.test(stored)).toBe(false);
    expect(collapseValue(parseEnvelope(stored)!)).toBe(value);
    expect(findStorageRisks().map((r) => r.key)).toEqual(["LOST_KEY"]);
  });
});
