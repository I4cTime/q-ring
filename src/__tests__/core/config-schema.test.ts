import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdirSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  loadPolicy,
  checkKeyReadPolicy,
  clearPolicyCache,
  PolicyConfigError,
} from "../../core/policy.js";

const dir = join(tmpdir(), `qring-config-schema-${process.pid}`);
const cfg = join(dir, ".q-ring.json");

function writePolicy(policy: unknown): void {
  writeFileSync(cfg, JSON.stringify({ policy }), "utf8");
  clearPolicyCache();
}

describe(".q-ring.json policy validation (B3)", () => {
  let errSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    rmSync(dir, { recursive: true, force: true });
    mkdirSync(dir, { recursive: true });
    clearPolicyCache();
    errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
  });

  afterEach(() => {
    errSpy.mockRestore();
    clearPolicyCache();
    rmSync(dir, { recursive: true, force: true });
  });

  it("accepts a well-formed policy", () => {
    writePolicy({ mcp: { denyTools: ["exec_with_secrets"], deniedKeys: ["PROD_DB"] } });
    const p = loadPolicy(dir);
    expect(p.mcp?.denyTools).toEqual(["exec_with_secrets"]);
  });

  it("throws loudly on a typo'd key instead of silently ignoring it", () => {
    // `denytools` (lowercase t) is the classic footgun: intended to deny a
    // tool, silently dropped by the old code, leaving the tool allowed.
    writePolicy({ mcp: { denytools: ["exec_with_secrets"] } });
    expect(() => loadPolicy(dir)).toThrow(PolicyConfigError);
    expect(errSpy).toHaveBeenCalled();
  });

  it("throws on a wrong-typed field", () => {
    writePolicy({ secrets: { maxTtlSeconds: "not-a-number" } });
    expect(() => loadPolicy(dir)).toThrow(PolicyConfigError);
  });

  it("fails closed: an invalid policy makes key-read checks throw (deny), not allow", () => {
    writePolicy({ mcp: { deniedKeys: "PROD_DB" } }); // should be an array
    // The important property: we do NOT fall through to { allowed: true }.
    expect(() => checkKeyReadPolicy("ANYTHING", undefined, dir)).toThrow(
      PolicyConfigError,
    );
  });

  it("recovers once the file is corrected (mtime-keyed re-evaluation)", () => {
    writePolicy({ mcp: { denytools: ["x"] } });
    expect(() => loadPolicy(dir)).toThrow(PolicyConfigError);
    // fix the typo
    writePolicy({ mcp: { denyTools: ["x"] } });
    expect(loadPolicy(dir).mcp?.denyTools).toEqual(["x"]);
  });
});
