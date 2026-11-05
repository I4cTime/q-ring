import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { registerHook, fireHooks } from "../../core/hooks.js";
import { queryAudit } from "../../core/observer.js";

let configDir: string;
let auditDir: string;

beforeEach(() => {
  configDir = mkdtempSync(join(tmpdir(), "qring-hook-ssrf-cfg-"));
  auditDir = mkdtempSync(join(tmpdir(), "qring-hook-ssrf-audit-"));
  process.env.QRING_CONFIG_DIR = configDir;
  process.env.QRING_AUDIT_DIR = auditDir;
  delete process.env.QRING_ALLOW_PRIVATE_HOOKS;
});

afterEach(() => {
  delete process.env.QRING_CONFIG_DIR;
  delete process.env.QRING_AUDIT_DIR;
  rmSync(configDir, { recursive: true, force: true });
  rmSync(auditDir, { recursive: true, force: true });
});

describe("hook SSRF block audit", () => {
  it("records scheme and host only, never the path or query", async () => {
    // A private address: the SSRF guard blocks it, so nothing leaves the test.
    registerHook({
      type: "http",
      match: { key: "K", action: ["write"] },
      url: "http://127.0.0.1:8080/hooks/T0SECRETPATH/xyz?token=hook-token-value",
      enabled: true,
    });

    await fireHooks({
      action: "write",
      key: "K",
      scope: "global",
      timestamp: new Date().toISOString(),
      source: "cli",
    });

    const blocked = queryAudit({ action: "policy_deny", key: "K" });
    expect(blocked).toHaveLength(1);
    expect(blocked[0].detail).toBe("hook SSRF blocked: http://127.0.0.1:8080");
    const everything = JSON.stringify(queryAudit());
    expect(everything).not.toContain("T0SECRETPATH");
    expect(everything).not.toContain("hook-token-value");
  });
});
