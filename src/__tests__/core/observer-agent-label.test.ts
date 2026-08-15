import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

vi.mock("@napi-rs/keyring", async () => {
  const fake = await import("../helpers/fake-keyring.js");
  return { Entry: fake.FakeEntry, findCredentials: fake.findCredentials };
});

import {
  logAudit,
  queryAudit,
  exportAudit,
  setAuditAgentLabel,
  getAuditAgentLabel,
} from "../../core/observer.js";
import { resetFakeKeyring } from "../helpers/fake-keyring.js";

let auditDir: string;

beforeEach(() => {
  resetFakeKeyring();
  setAuditAgentLabel(null);
  auditDir = mkdtempSync(join(tmpdir(), "qring-agent-label-"));
  process.env.QRING_AUDIT_DIR = auditDir;
});
afterEach(() => {
  setAuditAgentLabel(null);
  delete process.env.QRING_AUDIT_DIR;
  rmSync(auditDir, { recursive: true, force: true });
});

describe("per-agent identity audit label", () => {
  it("stamps events logged after the label is set", () => {
    logAudit({ action: "read", key: "BEFORE", scope: "q-ring:global", source: "mcp" });
    setAuditAgentLabel("claude-code@2.1.0");
    logAudit({ action: "read", key: "AFTER", scope: "q-ring:global", source: "mcp" });

    expect(queryAudit({ key: "BEFORE" })[0].agent).toBeUndefined();
    expect(queryAudit({ key: "AFTER" })[0].agent).toBe("claude-code@2.1.0");
  });

  it("filters queries by agent", () => {
    setAuditAgentLabel("cursor@1.0.0");
    logAudit({ action: "read", key: "K1", scope: "q-ring:global", source: "mcp" });
    setAuditAgentLabel("windsurf@3.0.0");
    logAudit({ action: "read", key: "K2", scope: "q-ring:global", source: "mcp" });

    const cursorEvents = queryAudit({ agent: "cursor@1.0.0" });
    expect(cursorEvents.length).toBe(1);
    expect(cursorEvents[0].key).toBe("K1");
  });

  it("sanitizes untrusted labels: control chars stripped, length capped", () => {
    setAuditAgentLabel("evil\n\x00client\x1b[31m@1.0" + "a".repeat(300));
    const label = getAuditAgentLabel();
    expect(label).not.toBeNull();
    expect(label).not.toContain("\n");
    expect(label).not.toContain("\x00");
    expect(label).not.toContain("\x1b");
    expect(label!.length).toBeLessThanOrEqual(128);

    setAuditAgentLabel("\x00\x01\x02");
    expect(getAuditAgentLabel()).toBeNull();
  });

  it("appears as a CSV column in exports", () => {
    setAuditAgentLabel("claude-code@2.1.0");
    logAudit({ action: "read", key: "CSV_KEY", scope: "q-ring:global", source: "mcp" });
    const csv = exportAudit({ format: "csv" });
    expect(csv.split("\n")[0]).toContain("agent");
    expect(csv).toContain("claude-code@2.1.0");
  });

  it("an explicit event agent wins over the ambient label", () => {
    setAuditAgentLabel("ambient@1.0");
    logAudit({
      action: "read",
      key: "EXPLICIT",
      scope: "q-ring:global",
      source: "mcp",
      agent: "explicit@2.0",
    });
    expect(queryAudit({ key: "EXPLICIT" })[0].agent).toBe("explicit@2.0");
  });
});
