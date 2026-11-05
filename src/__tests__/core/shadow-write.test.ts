import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

vi.mock("@napi-rs/keyring", async () => {
  const fake = await import("../helpers/fake-keyring.js");
  return { Entry: fake.FakeEntry, findCredentials: fake.findCredentials };
});

import { setSecret, getSecret } from "../../core/keyring.js";
import { queryAudit } from "../../core/observer.js";
import { setPolicyRoot, clearPolicyCache } from "../../core/policy.js";
import { resetFakeKeyring } from "../helpers/fake-keyring.js";

let dir: string;
const PROD_URL = "postgres://prod-user:prod-pass@db.internal/prod";

beforeEach(() => {
  resetFakeKeyring();
  clearPolicyCache();
  dir = mkdtempSync(join(tmpdir(), "qring-shadow-"));
  process.env.QRING_AUDIT_DIR = join(dir, "audit");
  writeFileSync(
    join(dir, ".q-ring.json"),
    JSON.stringify({ policy: { mcp: { deniedTags: ["prod"] } } }),
  );
  setPolicyRoot(dir);
});

afterEach(() => {
  setPolicyRoot(process.cwd());
  clearPolicyCache();
  delete process.env.QRING_AUDIT_DIR;
  rmSync(dir, { recursive: true, force: true });
});

// The operator's scope-less resolution: project first, then global.
const resolved = () => getSecret("DATABASE_URL", { projectPath: dir, silent: true });

describe("an MCP write cannot shadow a tag-denied copy in another scope", () => {
  it("refuses a project-scope write over a prod-tagged global DATABASE_URL", () => {
    setSecret("DATABASE_URL", PROD_URL, { scope: "global", source: "cli", tags: ["prod"] });

    expect(() =>
      setSecret("DATABASE_URL", "postgres://attacker.example/db", {
        scope: "project",
        projectPath: dir,
        source: "mcp",
      }),
    ).toThrow(/Policy Denied: Tag "prod"/);

    expect(resolved()).toBe(PROD_URL);
    const denied = queryAudit({ action: "policy_deny", key: "DATABASE_URL" });
    expect(denied).toHaveLength(1);
    expect(denied[0].detail).toContain("write refused");
    expect(JSON.stringify(queryAudit())).not.toContain("attacker.example");
  });

  it("allows the write when no copy in any scope is denied", () => {
    setSecret("DATABASE_URL", "postgres://dev/db", { scope: "global", source: "cli" });

    setSecret("DATABASE_URL", "postgres://project/db", {
      scope: "project",
      projectPath: dir,
      source: "mcp",
    });

    expect(resolved()).toBe("postgres://project/db");
    expect(queryAudit({ action: "policy_deny" })).toHaveLength(0);
  });
});
