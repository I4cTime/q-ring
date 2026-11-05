import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { checkWrapToolPolicy, clearPolicyCache, setPolicyRoot } from "../../core/policy.js";
import { RateLimiter, RATE_LIMITER_MAX_TOOLS } from "../../core/wrap.js";

describe("wrap tool-name globs", () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "qring-wrap-glob-"));
    writeFileSync(
      join(dir, ".q-ring.json"),
      JSON.stringify({ policy: { wrap: { denyTools: ["delete_*", "*_admin"] } } }),
    );
    setPolicyRoot(dir);
    clearPolicyCache();
  });
  afterEach(() => {
    setPolicyRoot(process.cwd());
    clearPolicyCache();
    rmSync(dir, { recursive: true, force: true });
  });

  it("a newline in a tool name cannot dodge a deny glob", () => {
    expect(checkWrapToolPolicy("delete_\nrepo", dir).allowed).toBe(false);
    expect(checkWrapToolPolicy("x\ny_admin", dir).allowed).toBe(false);
    expect(checkWrapToolPolicy("search", dir).allowed).toBe(true);
  });
});

describe("wrap rate limiter is bounded", () => {
  const limit = { maxCalls: 2, perSeconds: 60 };

  it("never tracks more than RATE_LIMITER_MAX_TOOLS names", () => {
    const limiter = new RateLimiter();
    const t0 = 1_000_000;
    for (let i = 0; i < RATE_LIMITER_MAX_TOOLS; i++) limiter.take(`spray_${i}`, limit, t0);
    expect(limiter.size).toBe(RATE_LIMITER_MAX_TOOLS);

    // Every tracked window is still live: the new name is refused rather
    // than evicting one (which would reset that tool's count).
    expect(limiter.take("one_more", limit, t0 + 1)).toBe(false);
    expect(limiter.size).toBe(RATE_LIMITER_MAX_TOOLS);

    // Once windows have passed, the oldest expired entry makes room.
    expect(limiter.take("one_more", limit, t0 + 61_000)).toBe(true);
    expect(limiter.size).toBe(RATE_LIMITER_MAX_TOOLS);
  });

  it("a name spray cannot reset a live tool's window", () => {
    const limiter = new RateLimiter();
    const t0 = 2_000_000;
    expect(limiter.take("deploy", limit, t0)).toBe(true);
    expect(limiter.take("deploy", limit, t0)).toBe(true);
    expect(limiter.take("deploy", limit, t0)).toBe(false);
    for (let i = 0; i < RATE_LIMITER_MAX_TOOLS * 2; i++) limiter.take(`spray_${i}`, limit, t0 + 1);
    expect(limiter.take("deploy", limit, t0 + 2)).toBe(false);
  });
});
