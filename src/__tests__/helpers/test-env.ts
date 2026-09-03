/**
 * Global test environment isolation (wired via vitest `setupFiles`).
 *
 * Without this, test files that never set QRING_AUDIT_DIR append their audit
 * events to the developer's REAL ~/.config/q-ring/audit.jsonl (with the HMAC
 * anchor going to the mocked keyring — leaving the real chain's anchor
 * stale), and every fork contends on the real lock dir with any live q-ring
 * MCP server on the machine — the root cause of a transient suite failure
 * (held lock → 5s logAudit stalls → test timeouts / dropped-event count
 * mismatches, self-healing after the 30s stale-steal).
 */
import { afterEach } from "vitest";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const defaultAuditDir = mkdtempSync(join(tmpdir(), "qring-test-audit-"));

// Locks NEVER touch the real home during tests, even when a test file swaps
// QRING_AUDIT_DIR (file-lock prefers QRING_LOCK_DIR over everything).
process.env.QRING_LOCK_DIR = mkdtempSync(join(tmpdir(), "qring-test-locks-"));
process.env.QRING_AUDIT_DIR = defaultAuditDir;

// Test files legitimately set their own QRING_AUDIT_DIR and delete it in
// afterEach — restore the isolated default so later tests in the worker
// don't fall back to the real home. (Setup-file afterEach hooks run after
// the test file's own, so this sees the post-cleanup state.)
afterEach(() => {
  if (!process.env.QRING_AUDIT_DIR) {
    process.env.QRING_AUDIT_DIR = defaultAuditDir;
  }
});
