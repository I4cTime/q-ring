import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { readFileSync, writeFileSync, rmSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  grantApproval,
  hasApproval,
  listApprovals,
  countLegacyApprovals,
} from "../../core/approval.js";
import { serviceForScope } from "../../core/scope.js";

const GLOBAL = serviceForScope("global");

describe("approval HMAC + project binding", () => {
  let prevHome: string | undefined;
  let prevUserProfile: string | undefined;
  let dir: string;

  beforeEach(() => {
    prevHome = process.env.HOME;
    prevUserProfile = process.env.USERPROFILE;
    dir = join(tmpdir(), `qring-approval-${Date.now()}-${Math.random().toString(16).slice(2)}`);
    mkdirSync(dir, { recursive: true });
    process.env.HOME = dir;
    process.env.USERPROFILE = dir;
  });

  afterEach(() => {
    if (prevHome === undefined) delete process.env.HOME;
    else process.env.HOME = prevHome;
    if (prevUserProfile === undefined) delete process.env.USERPROFILE;
    else process.env.USERPROFILE = prevUserProfile;
    rmSync(dir, { recursive: true, force: true });
  });

  const storePath = () => join(dir, ".config", "q-ring", "approvals.json");

  it("accepts a freshly granted approval", () => {
    grantApproval("API_KEY", "global", GLOBAL, 3600);
    expect(hasApproval("API_KEY", "global", GLOBAL)).toBe(true);
  });

  it("rejects tampered HMAC (timing-safe compare)", () => {
    grantApproval("API_KEY", "global", GLOBAL, 3600);
    const data = JSON.parse(readFileSync(storePath(), "utf8")) as {
      approvals: { hmac: string }[];
    };
    data.approvals[0].hmac = "f".repeat(64);
    writeFileSync(storePath(), JSON.stringify(data));
    expect(hasApproval("API_KEY", "global", GLOBAL)).toBe(false);
    expect(listApprovals()[0].tampered).toBe(true);
  });

  it("rejects wrong-length HMAC without throwing", () => {
    grantApproval("API_KEY", "global", GLOBAL, 3600);
    const data = JSON.parse(readFileSync(storePath(), "utf8")) as {
      approvals: { hmac: string }[];
    };
    data.approvals[0].hmac = "abc";
    writeFileSync(storePath(), JSON.stringify(data));
    expect(hasApproval("API_KEY", "global", GLOBAL)).toBe(false);
  });

  it("HMAC covers workspace, sessionId, and service so none can be silently forged", () => {
    grantApproval("API_KEY", "global", GLOBAL, 3600, {
      workspace: "/work/a",
      sessionId: "sess-1",
    });
    const data = JSON.parse(readFileSync(storePath(), "utf8")) as {
      approvals: { workspace?: string; service?: string; hmac: string }[];
    };
    data.approvals[0].workspace = "/attacker";
    data.approvals[0].service = "q-ring:project:someone-else";
    writeFileSync(storePath(), JSON.stringify(data));
    expect(hasApproval("API_KEY", "global", GLOBAL)).toBe(false);
    expect(listApprovals()[0].tampered).toBe(true);
  });

  // ---- A5: cross-project isolation ----

  it("an approval for project A does NOT satisfy project B (same key, same scope label)", () => {
    const svcA = serviceForScope("project", { projectPath: "/home/me/project-a" });
    const svcB = serviceForScope("project", { projectPath: "/home/me/project-b" });
    expect(svcA).not.toBe(svcB);

    grantApproval("API_KEY", "project", svcA, 3600);
    expect(hasApproval("API_KEY", "project", svcA)).toBe(true);
    expect(hasApproval("API_KEY", "project", svcB)).toBe(false);
  });

  it("a pre-v0.14 approval without a service binding fails closed", () => {
    // Simulate a legacy entry: valid HMAC-less shape as written by old code —
    // easiest is to grant then strip the service field, which invalidates the
    // HMAC (service is now in the payload), so it must not be honored.
    grantApproval("API_KEY", "project", serviceForScope("project", { projectPath: "/p" }), 3600);
    const data = JSON.parse(readFileSync(storePath(), "utf8")) as {
      approvals: { service?: string }[];
    };
    delete data.approvals[0].service;
    writeFileSync(storePath(), JSON.stringify(data));

    expect(countLegacyApprovals()).toBe(1);
    // no service matches an entry that has none
    expect(
      hasApproval("API_KEY", "project", serviceForScope("project", { projectPath: "/p" })),
    ).toBe(false);
  });
});
