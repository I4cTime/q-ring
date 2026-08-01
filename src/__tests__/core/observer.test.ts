import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtempSync, rmSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createHash } from "node:crypto";

vi.mock("@napi-rs/keyring", async () => {
  const fake = await import("../helpers/fake-keyring.js");
  return { Entry: fake.FakeEntry, findCredentials: fake.findCredentials };
});

import {
  logAudit,
  queryAudit,
  verifyAuditChain,
  exportAudit,
  detectAnomalies,
} from "../../core/observer.js";
import {
  resetFakeKeyring,
  setKeyringUnavailable,
} from "../helpers/fake-keyring.js";

let auditDir: string;
const auditFile = () => join(auditDir, "audit.jsonl");

function seed(n = 3): void {
  for (let i = 0; i < n; i++) {
    logAudit({ action: "read", key: `K${i}`, scope: "q-ring:global", source: "cli" });
  }
}

beforeEach(() => {
  resetFakeKeyring();
  auditDir = mkdtempSync(join(tmpdir(), "qring-audit-"));
  process.env.QRING_AUDIT_DIR = auditDir;
});
afterEach(() => {
  delete process.env.QRING_AUDIT_DIR;
  rmSync(auditDir, { recursive: true, force: true });
});

describe("observer / audit basics", () => {
  it("logAudit does not throw and queryAudit filters by key", () => {
    expect(() => seed()).not.toThrow();
    logAudit({ action: "write", key: "FIND_ME", scope: "q-ring:global", source: "cli" });
    const events = queryAudit({ key: "FIND_ME" });
    expect(events.length).toBeGreaterThanOrEqual(1);
    expect(events.every((e) => e.key === "FIND_ME")).toBe(true);
  });

  it("exportAudit json is valid JSON and detectAnomalies returns an array", () => {
    seed();
    expect(() => JSON.parse(exportAudit({ format: "json" }))).not.toThrow();
    expect(Array.isArray(detectAnomalies())).toBe(true);
  });
});

describe("audit chain tamper-evidence (A6)", () => {
  it("an intact chain verifies", () => {
    seed(4);
    expect(verifyAuditChain().intact).toBe(true);
  });

  it("detects a mid-file edit via the per-line hash", () => {
    seed(4);
    const lines = readFileSync(auditFile(), "utf8").split("\n").filter(Boolean);
    const ev = JSON.parse(lines[1]);
    ev.key = "TAMPERED";
    lines[1] = JSON.stringify(ev);
    writeFileSync(auditFile(), lines.join("\n") + "\n");
    expect(verifyAuditChain().intact).toBe(false);
  });

  it("detects tail truncation via the keyed anchor (self-consistent prefix)", () => {
    seed(4);
    // Drop the last line. The remaining prefix is a perfectly valid SHA-256
    // chain — only the keyed anchor (head no longer matches) reveals the cut.
    const lines = readFileSync(auditFile(), "utf8").split("\n").filter(Boolean);
    writeFileSync(auditFile(), lines.slice(0, -1).join("\n") + "\n");

    const result = verifyAuditChain();
    expect(result.intact).toBe(false);
    expect(result.reason).toMatch(/anchor/i);
  });

  it("detects a full self-consistent rewrite via the keyed anchor", () => {
    seed(3);
    // Attacker rebuilds a fresh, internally-consistent SHA-256 chain from
    // scratch (no HMAC key), then can't match the anchor stored in the keyring.
    const rebuilt: string[] = [];
    let prev: string | undefined;
    for (let i = 0; i < 3; i++) {
      const ev = {
        timestamp: new Date(Date.now() + i).toISOString(),
        action: "read",
        key: `FAKE${i}`,
        scope: "q-ring:global",
        source: "cli",
        pid: 1,
        prevHash: prev,
      };
      const line = JSON.stringify(ev);
      rebuilt.push(line);
      prev = createHash("sha256").update(line).digest("hex");
    }
    writeFileSync(auditFile(), rebuilt.join("\n") + "\n");

    const result = verifyAuditChain();
    expect(result.intact).toBe(false);
    expect(result.reason).toMatch(/anchor/i);
  });

  it("without a keyring, still verifies per-line (anchor check skipped)", () => {
    // No anchor was ever written; the log is a valid SHA-256 chain.
    seed(3);
    setKeyringUnavailable(new Error("no secret service"));
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    expect(verifyAuditChain().intact).toBe(true);
    errSpy.mockRestore();
  });
});
