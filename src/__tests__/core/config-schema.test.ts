import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdirSync, writeFileSync, rmSync, chmodSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  loadPolicy,
  checkKeyReadPolicy,
  checkToolPolicy,
  checkWrapToolPolicy,
  clearPolicyCache,
  PolicyConfigError,
} from "../../core/policy.js";
import {
  clearCollapseCache,
  collapseEnvironment,
  readProjectConfig,
  readProjectConfigState,
} from "../../core/collapse.js";

const dir = join(tmpdir(), `qring-config-schema-${process.pid}`);
const cfg = join(dir, ".q-ring.json");

function writePolicy(policy: unknown): void {
  writeFileSync(cfg, JSON.stringify({ policy }), "utf8");
  clearPolicyCache();
  clearCollapseCache(); // policy reads via collapse's config cache
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

describe("a .q-ring.json that is not valid JSON fails closed", () => {
  let errSpy: ReturnType<typeof vi.spyOn>;

  // Raw writes with no cache clearing: the content change alone must be seen.
  function writeRaw(text: string): void {
    writeFileSync(cfg, text, "utf8");
  }

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

  it("loadPolicy throws PolicyConfigError naming the path", () => {
    writeRaw('{ "policy": { "mcp": { "deniedKeys": ["PROD_DB"] } ');
    expect(() => loadPolicy(dir)).toThrow(PolicyConfigError);
    expect(() => loadPolicy(dir)).toThrow(cfg);
    expect(() => loadPolicy(dir)).toThrow(/not valid JSON/);
  });

  it("denies the callers that go through loadPolicy instead of allowing", () => {
    writeRaw("{ not json");
    expect(() => checkKeyReadPolicy("PROD_DB", undefined, dir)).toThrow(PolicyConfigError);
    expect(() => checkToolPolicy("get_secret", dir)).toThrow(PolicyConfigError);
    expect(() => checkWrapToolPolicy("anything", dir)).toThrow(PolicyConfigError);
  });

  it("caches the error (logged once) and clears it when the content is fixed", () => {
    writeRaw("{ not json");
    expect(() => loadPolicy(dir)).toThrow(PolicyConfigError);
    expect(() => loadPolicy(dir)).toThrow(PolicyConfigError);
    expect(errSpy).toHaveBeenCalledTimes(1);

    writeRaw(JSON.stringify({ policy: { mcp: { deniedKeys: ["PROD_DB"] } } }));
    expect(loadPolicy(dir).mcp?.deniedKeys).toEqual(["PROD_DB"]);
    expect(checkKeyReadPolicy("PROD_DB", undefined, dir).allowed).toBe(false);
    expect(checkKeyReadPolicy("OTHER", undefined, dir).allowed).toBe(true);
  });

  it("treats JSON that is not an object as invalid too", () => {
    for (const text of ["null", "[]", '"policy"', "42"]) {
      writeRaw(text);
      expect(() => loadPolicy(dir), text).toThrow(/not a JSON object/);
    }
  });

  it("an absent file still means no policy", () => {
    expect(loadPolicy(dir)).toEqual({});
    expect(checkKeyReadPolicy("ANYTHING", undefined, dir).allowed).toBe(true);
    expect(readProjectConfigState(dir).state).toBe("absent");
    expect(errSpy).not.toHaveBeenCalled();
  });

  it("env detection still reads a corrupt file as no config", () => {
    writeRaw("{ not json");
    expect(readProjectConfig(dir)).toBeNull();
    expect(readProjectConfigState(dir).state).toBe("invalid");
    expect(() => collapseEnvironment({ projectPath: dir })).not.toThrow();
  });
});

describe("a .q-ring.json that exists but cannot be read fails closed", () => {
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
    try {
      chmodSync(cfg, 0o644);
    } catch {
      /* not there, or a directory */
    }
    rmSync(dir, { recursive: true, force: true });
  });

  it("a directory named .q-ring.json throws, is cached, and clears when replaced", () => {
    mkdirSync(cfg);
    expect(() => loadPolicy(dir)).toThrow(PolicyConfigError);
    expect(() => loadPolicy(dir)).toThrow(/cannot be read/);
    expect(() => loadPolicy(dir)).toThrow(cfg);
    expect(errSpy).toHaveBeenCalledTimes(1);

    // Replace the directory with a valid file; no cache reset.
    rmSync(cfg, { recursive: true, force: true });
    writeFileSync(cfg, JSON.stringify({ policy: { mcp: { denyTools: ["x"] } } }), "utf8");
    expect(loadPolicy(dir).mcp?.denyTools).toEqual(["x"]);
  });

  it.skipIf(process.platform === "win32" || process.getuid?.() === 0)(
    "an unreadable file (mode 000) throws EACCES and clears once readable",
    () => {
      writeFileSync(cfg, JSON.stringify({ policy: { mcp: { denyTools: ["x"] } } }), "utf8");
      chmodSync(cfg, 0o000);
      expect(() => loadPolicy(dir)).toThrow(/cannot be read \(EACCES\)/);
      expect(() => loadPolicy(dir)).toThrow(PolicyConfigError);
      expect(errSpy).toHaveBeenCalledTimes(1);

      chmodSync(cfg, 0o644);
      expect(loadPolicy(dir).mcp?.denyTools).toEqual(["x"]);
    },
  );
});

describe("config cache keeps one entry per path (#132 follow-up)", () => {
  const dirA = join(tmpdir(), `qring-config-cache-a-${process.pid}`);
  const dirB = join(tmpdir(), `qring-config-cache-b-${process.pid}`);

  beforeEach(() => {
    for (const [d, tool] of [
      [dirA, "a_tool"],
      [dirB, "b_tool"],
    ] as const) {
      mkdirSync(d, { recursive: true });
      writeFileSync(
        join(d, ".q-ring.json"),
        JSON.stringify({ policy: { mcp: { denyTools: [tool] } } }),
      );
    }
    clearPolicyCache();
  });

  afterEach(() => {
    vi.restoreAllMocks();
    clearPolicyCache();
    rmSync(dirA, { recursive: true, force: true });
    rmSync(dirB, { recursive: true, force: true });
  });

  it("alternating two paths re-uses state and policy with no re-parse", () => {
    // Round 1 fills the cache: the MCP policy root and an agent projectPath.
    const stateA = readProjectConfigState(dirA);
    const stateB = readProjectConfigState(dirB);
    const policyA = loadPolicy(dirA);
    const policyB = loadPolicy(dirB);
    expect(policyA.mcp?.denyTools).toEqual(["a_tool"]);
    expect(policyB.mcp?.denyTools).toEqual(["b_tool"]);

    const parse = vi.spyOn(JSON, "parse");
    for (let i = 0; i < 3; i++) {
      expect(readProjectConfigState(dirA)).toBe(stateA);
      expect(readProjectConfig(dirB)).toBe(stateB.config);
      expect(loadPolicy(dirA)).toBe(policyA); // same object: no schema re-check
      expect(readProjectConfigState(dirB)).toBe(stateB);
      expect(loadPolicy(dirB)).toBe(policyB);
    }
    expect(parse).not.toHaveBeenCalled();
  });

  it("drops the oldest path once more than 8 are cached", () => {
    const first = readProjectConfigState(dirA);
    for (let i = 0; i < 8; i++) readProjectConfigState(join(dirB, `missing-${i}`));
    expect(readProjectConfigState(dirA)).not.toBe(first); // evicted, re-read
    expect(readProjectConfigState(dirA)).toEqual(first);
  });

  it("keeps a recently used path when an older one is evicted", () => {
    const a = readProjectConfigState(dirA);
    const b = readProjectConfigState(dirB);
    for (let i = 0; i < 6; i++) readProjectConfigState(join(dirB, `missing-${i}`));
    expect(readProjectConfigState(dirA)).toBe(a); // touched: now most recent
    readProjectConfigState(join(dirB, "missing-6"));
    readProjectConfigState(join(dirB, "missing-7")); // 10 seen, cap 8
    expect(readProjectConfigState(dirA)).toBe(a);
    expect(readProjectConfigState(dirB)).not.toBe(b);
  });
});
