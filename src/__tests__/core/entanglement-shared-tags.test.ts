import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

vi.mock("@napi-rs/keyring", async () => {
  const fake = await import("../helpers/fake-keyring.js");
  return { Entry: fake.FakeEntry, findCredentials: fake.findCredentials };
});

import { setSecret, getSecret, getEnvelope, entangleSecrets } from "../../core/keyring.js";
import { queryAudit } from "../../core/observer.js";
import { setPolicyRoot, clearPolicyCache } from "../../core/policy.js";
import { resetFakeKeyring } from "../helpers/fake-keyring.js";

let dir: string;

beforeEach(() => {
  resetFakeKeyring();
  clearPolicyCache();
  dir = mkdtempSync(join(tmpdir(), "qring-shared-tags-"));
  process.env.QRING_CONFIG_DIR = join(dir, "config");
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
  delete process.env.QRING_CONFIG_DIR;
  delete process.env.QRING_AUDIT_DIR;
  rmSync(dir, { recursive: true, force: true });
});

const mcp = { scope: "global" as const, source: "mcp" as const };
const tagsOf = (key: string) => getEnvelope(key, { scope: "global" })?.envelope.meta.tags ?? [];

describe("entangled partners share deny tags", () => {
  it("a link made while the source was untagged stops leaking once the operator tags it", () => {
    setSecret("PROD_DB_URL", "postgres://staging/db", { scope: "global", source: "cli" });
    setSecret("SCRATCH", "scratch-value", { scope: "global", source: "cli" });
    // Allowed at the time: nothing is tagged yet.
    entangleSecrets("PROD_DB_URL", { ...mcp, projectPath: dir }, "SCRATCH", {
      ...mcp,
      projectPath: dir,
    });

    // The operator later tags the source prod and writes it from the CLI.
    setSecret("PROD_DB_URL", "postgres://prod-user:prod-pass@db/prod", {
      scope: "global",
      source: "cli",
      tags: ["prod"],
    });

    expect(tagsOf("SCRATCH")).toContain("prod");
    expect(() => getSecret("SCRATCH", { ...mcp, projectPath: dir })).toThrow(
      /Policy Denied: Tag "prod"/,
    );
    const propagated = queryAudit({ action: "entangle", key: "SCRATCH" });
    expect(propagated.some((e) => e.detail?.includes("tag: prod"))).toBe(true);
  });

  it("a link made while the source is already tagged copies the tag at once", () => {
    setSecret("PROD_DB_URL", "postgres://prod/db", {
      scope: "global",
      source: "cli",
      tags: ["prod", "db"],
    });
    setSecret("SCRATCH", "scratch-value", { scope: "global", source: "cli", tags: ["mine"] });

    entangleSecrets("PROD_DB_URL", { scope: "global", source: "cli" }, "SCRATCH", {
      scope: "global",
      source: "cli",
    });

    // Only deny tags travel; the partner keeps its own.
    expect(tagsOf("SCRATCH").sort()).toEqual(["mine", "prod"]);
    expect(() => getSecret("SCRATCH", { ...mcp, projectPath: dir })).toThrow(/Tag "prod"/);
  });
});
