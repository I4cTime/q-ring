import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdirSync, writeFileSync, rmSync, statSync, utimesSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  checkWrapToolPolicy,
  wrapToolRequiresApproval,
  getWrapRateLimit,
  wrapRedactsResults,
  getPolicySummary,
  clearPolicyCache,
  loadPolicy,
  PolicyConfigError,
} from "../../core/policy.js";
import { readProjectConfig } from "../../core/collapse.js";

const dir = join(tmpdir(), `qring-policy-wrap-${process.pid}-${Date.now()}`);

function writePolicy(policy: unknown) {
  writeFileSync(join(dir, ".q-ring.json"), JSON.stringify({ policy }));
  clearPolicyCache();
}

beforeEach(() => {
  mkdirSync(dir, { recursive: true });
  clearPolicyCache();
});
afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
  clearPolicyCache();
});

describe("policy.wrap", () => {
  it("allows everything with no wrap section", () => {
    writePolicy({ mcp: { denyTools: ["delete_secret"] } });
    expect(checkWrapToolPolicy("anything", dir).allowed).toBe(true);
    expect(wrapToolRequiresApproval("anything", dir)).toBe(false);
    expect(getWrapRateLimit("anything", dir)).toBeUndefined();
    expect(wrapRedactsResults(dir)).toBe(true);
    expect(getPolicySummary(dir).hasWrapPolicy).toBe(false);
  });

  it("denies by exact name and by glob, deny beating allow", () => {
    writePolicy({ wrap: { allowTools: ["*"], denyTools: ["rm_*", "shell"] } });
    expect(checkWrapToolPolicy("rm_rf", dir).allowed).toBe(false);
    expect(checkWrapToolPolicy("shell", dir).allowed).toBe(false);
    expect(checkWrapToolPolicy("search", dir).allowed).toBe(true);
    expect(checkWrapToolPolicy("rm_rf", dir).policySource).toContain("denyTools");
  });

  it("an allow list refuses anything not matched", () => {
    writePolicy({ wrap: { allowTools: ["github_*"] } });
    expect(checkWrapToolPolicy("github_search", dir).allowed).toBe(true);
    expect(checkWrapToolPolicy("slack_post", dir).allowed).toBe(false);
    expect(checkWrapToolPolicy("slack_post", dir).policySource).toContain("allowTools");
  });

  it("globs are anchored and regex-safe", () => {
    writePolicy({ wrap: { denyTools: ["a.b*"] } });
    expect(checkWrapToolPolicy("a.bc", dir).allowed).toBe(false);
    expect(checkWrapToolPolicy("axbc", dir).allowed).toBe(true); // "." is literal
    expect(checkWrapToolPolicy("xa.b", dir).allowed).toBe(true); // anchored
  });

  it("approveTools and rate limits resolve with per-tool overrides", () => {
    writePolicy({
      wrap: {
        approveTools: ["deploy_*"],
        rateLimit: { maxCalls: 10, perSeconds: 60 },
        toolRateLimits: { "search*": { maxCalls: 2, perSeconds: 1 } },
        redactResults: false,
      },
    });
    expect(wrapToolRequiresApproval("deploy_prod", dir)).toBe(true);
    expect(wrapToolRequiresApproval("read_file", dir)).toBe(false);
    expect(getWrapRateLimit("search_docs", dir)).toEqual({ maxCalls: 2, perSeconds: 1 });
    expect(getWrapRateLimit("read_file", dir)).toEqual({ maxCalls: 10, perSeconds: 60 });
    expect(wrapRedactsResults(dir)).toBe(false);
    expect(getPolicySummary(dir).hasWrapPolicy).toBe(true);
  });

  it("fails closed on unknown keys or bad shapes", () => {
    writePolicy({ wrap: { denytools: ["x"] } });
    expect(() => loadPolicy(dir)).toThrow(PolicyConfigError);
    writePolicy({ wrap: { rateLimit: { maxCalls: 0, perSeconds: 60 } } });
    expect(() => loadPolicy(dir)).toThrow(PolicyConfigError);
  });
});

// Issue #132: on Windows two writes inside one millisecond share an mtime, and
// the config caches used to key on mtime alone, so the previous policy was
// served. These write back to back WITHOUT clearing any cache, then force the
// same mtime, the same size and (in-place rewrite) the same inode.
describe("config cache invalidation (#132)", () => {
  const cfg = () => join(dir, ".q-ring.json");
  const FIXED = 1_700_000_000; // whole seconds, so mtimeMs is exactly equal

  function writeRaw(policy: unknown): void {
    writeFileSync(cfg(), JSON.stringify({ policy }));
    utimesSync(cfg(), FIXED, FIXED);
  }

  it("serves the second of two same-mtime, same-size writes", () => {
    writeRaw({ wrap: { denyTools: ["aaa_*"] } });
    expect(readProjectConfig(dir)?.policy?.wrap?.denyTools).toEqual(["aaa_*"]);
    expect(loadPolicy(dir).wrap?.denyTools).toEqual(["aaa_*"]);
    const first = statSync(cfg());

    writeRaw({ wrap: { denyTools: ["bbb_*"] } });
    const second = statSync(cfg());
    // The fingerprint fields an mtime/size/inode key would see are all equal.
    expect(second.mtimeMs).toBe(first.mtimeMs);
    expect(second.size).toBe(first.size);
    expect(second.ino).toBe(first.ino);

    expect(readProjectConfig(dir)?.policy?.wrap?.denyTools).toEqual(["bbb_*"]);
    expect(loadPolicy(dir).wrap?.denyTools).toEqual(["bbb_*"]);
    expect(checkWrapToolPolicy("aaa_x", dir).allowed).toBe(true);
    expect(checkWrapToolPolicy("bbb_x", dir).allowed).toBe(false);
  });

  it("serves the second of two same-mtime writes of different size", () => {
    writeRaw({ wrap: { allowTools: ["github_*"] } });
    expect(checkWrapToolPolicy("axbc", dir).allowed).toBe(false);

    writeRaw({ wrap: { denyTools: ["a.b*"] } });
    expect(readProjectConfig(dir)?.policy?.wrap?.denyTools).toEqual(["a.b*"]);
    expect(checkWrapToolPolicy("axbc", dir).allowed).toBe(true);
    expect(checkWrapToolPolicy("a.bc", dir).allowed).toBe(false);
  });

  it("an invalid policy keeps failing closed until the content changes", () => {
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      writeRaw({ wrap: { denytools: ["xxx"] } }); // typo: unknown key
      expect(() => loadPolicy(dir)).toThrow(PolicyConfigError);
      expect(() => loadPolicy(dir)).toThrow(PolicyConfigError); // cached, still throws
      expect(errSpy).toHaveBeenCalledTimes(1);

      writeRaw({ wrap: { denyTools: ["xxx"] } }); // fixed, same mtime and size
      expect(loadPolicy(dir).wrap?.denyTools).toEqual(["xxx"]);
    } finally {
      errSpy.mockRestore();
    }
  });

  it("clearPolicyCache also drops the collapse config cache", () => {
    writeRaw({ wrap: { denyTools: ["aaa_*"] } });
    const before = readProjectConfig(dir);
    clearPolicyCache();
    const after = readProjectConfig(dir);
    expect(after).toEqual(before);
    expect(after).not.toBe(before); // re-read, not served from the old cache
  });
});
