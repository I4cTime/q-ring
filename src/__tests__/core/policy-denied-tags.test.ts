import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

vi.mock("@napi-rs/keyring", async () => {
  const fake = await import("../helpers/fake-keyring.js");
  return { Entry: fake.FakeEntry, findCredentials: fake.findCredentials };
});

import {
  setSecret,
  getSecret,
  getEnvelope,
  hasSecret,
  listSecrets,
  deleteSecret,
  exportSecrets,
} from "../../core/keyring.js";
import { setPolicyRoot, clearPolicyCache } from "../../core/policy.js";
import { resetFakeKeyring } from "../helpers/fake-keyring.js";

let dir: string;
const mcp = () => ({ scope: "global" as const, source: "mcp" as const, projectPath: dir });

describe("policy.mcp.deniedTags is enforced on MCP reads", () => {
  beforeEach(() => {
    resetFakeKeyring();
    clearPolicyCache();
    dir = mkdtempSync(join(tmpdir(), "qring-denied-tags-"));
    writeFileSync(
      join(dir, ".q-ring.json"),
      JSON.stringify({ policy: { mcp: { deniedTags: ["prod"] } } }),
    );
    setPolicyRoot(dir);

    setSecret("PROD_TOKEN", "prod-token-value", {
      scope: "global",
      source: "cli",
      tags: ["prod", "payments"],
    });
    setSecret("DEV_TOKEN", "dev-token-value", { scope: "global", source: "cli", tags: ["dev"] });
  });

  afterEach(() => {
    setPolicyRoot(process.cwd());
    clearPolicyCache();
    rmSync(dir, { recursive: true, force: true });
  });

  it("get_secret / inspect paths refuse a key carrying a denied tag", () => {
    expect(() => getSecret("PROD_TOKEN", mcp())).toThrow(/Policy Denied: Tag "prod"/);
    expect(() => getEnvelope("PROD_TOKEN", mcp())).toThrow(/Policy Denied: Tag "prod"/);
    expect(getSecret("DEV_TOKEN", mcp())).toBe("dev-token-value");
  });

  it("has / list / export hide it", () => {
    expect(hasSecret("PROD_TOKEN", mcp())).toBe(false);
    expect(listSecrets(mcp()).map((e) => e.key)).toEqual(["DEV_TOKEN"]);
    const exported = exportSecrets({ ...mcp(), format: "json" });
    expect(exported).not.toContain("prod-token-value");
    expect(exported).toContain("dev-token-value");
  });

  it("delete refuses it and leaves the value in place", () => {
    expect(() => deleteSecret("PROD_TOKEN", mcp())).toThrow(/Policy Denied: Tag "prod"/);
    expect(getSecret("PROD_TOKEN", { scope: "global", silent: true })).toBe("prod-token-value");
  });

  it("the local operator (CLI source) is not governed by MCP policy", () => {
    expect(getSecret("PROD_TOKEN", { scope: "global", source: "cli" })).toBe("prod-token-value");
  });
});
