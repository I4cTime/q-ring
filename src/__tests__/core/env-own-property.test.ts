import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

vi.mock("@napi-rs/keyring", async () => {
  const fake = await import("../helpers/fake-keyring.js");
  return { Entry: fake.FakeEntry, findCredentials: fake.findCredentials };
});

import { resetFakeKeyring } from "../helpers/fake-keyring.js";
import { setSecret } from "../../core/keyring.js";
import { collapseValue, createEnvelope } from "../../core/envelope.js";
import { promoteSecret, diffEnvironments } from "../../core/promote.js";
import { clearCollapseCache, collapseEnvironment } from "../../core/collapse.js";

const PROTO_NAMES = ["constructor", "toString", "__proto__", "hasOwnProperty", "valueOf"];

beforeEach(() => {
  resetFakeKeyring();
});

describe("environment names never resolve to Object.prototype members", () => {
  it("collapseValue falls back to the default state", () => {
    const envelope = createEnvelope("", {
      states: { dev: "dev-value", prod: "prod-value" },
      defaultEnv: "dev",
    });
    for (const env of PROTO_NAMES) {
      expect(collapseValue(envelope, env), env).toBe("dev-value");
    }
  });

  it("promote reports a missing source state instead of copying a function", () => {
    setSecret("API_KEY", "", {
      scope: "global",
      source: "cli",
      states: { dev: "dev-value", prod: "prod-value" },
      defaultEnv: "dev",
    });
    for (const from of ["constructor", "toString", "valueOf"]) {
      expect(
        () => promoteSecret("API_KEY", { from, to: "staging", scope: "global" }),
        from,
      ).toThrow(/has no value for env/);
    }
    // A prototype name as the target is just an absent state.
    expect(
      promoteSecret("API_KEY", { from: "dev", to: "toString", scope: "global" }).previous,
    ).toBe("absent");
  });

  it("diff treats prototype names as absent environments", () => {
    setSecret("API_KEY", "", {
      scope: "global",
      source: "cli",
      states: { dev: "dev-value", prod: "prod-value" },
      defaultEnv: "dev",
    });
    const result = diffEnvironments({ a: "constructor", b: "toString", scope: "global" });
    expect(result.entries).toEqual([]);
    expect(result.drift).toBe(false);
  });

  describe("branch map", () => {
    let repo: string;
    let nodeEnv: string | undefined;

    beforeEach(() => {
      repo = mkdtempSync(join(tmpdir(), "qring-proto-branch-"));
      execFileSync("git", ["init", "-q", "-b", "constructor", repo]);
      // rev-parse needs a commit to name the branch.
      execFileSync("git", [
        "-C",
        repo,
        "-c",
        "user.name=qring-test",
        "-c",
        "user.email=qring-test@example.invalid",
        "-c",
        "commit.gpgsign=false",
        "commit",
        "-q",
        "--allow-empty",
        "-m",
        "init",
      ]);
      nodeEnv = process.env.NODE_ENV;
      delete process.env.NODE_ENV;
      delete process.env.QRING_ENV;
      clearCollapseCache();
    });

    afterEach(() => {
      if (nodeEnv !== undefined) process.env.NODE_ENV = nodeEnv;
      clearCollapseCache();
      rmSync(repo, { recursive: true, force: true });
    });

    it("a branch named constructor maps to no environment", () => {
      expect(collapseEnvironment({ projectPath: repo })).toBeNull();
    });
  });
});
