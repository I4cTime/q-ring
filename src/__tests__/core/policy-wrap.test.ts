import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdirSync, writeFileSync, rmSync } from "node:fs";
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
