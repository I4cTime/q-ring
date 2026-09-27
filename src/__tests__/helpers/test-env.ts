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
const defaultConfigDir = mkdtempSync(join(tmpdir(), "qring-test-config-"));

// Locks NEVER touch the real home during tests, even when a test file swaps
// QRING_AUDIT_DIR (file-lock prefers QRING_LOCK_DIR over everything).
process.env.QRING_LOCK_DIR = mkdtempSync(join(tmpdir(), "qring-test-locks-"));
process.env.QRING_AUDIT_DIR = defaultAuditDir;
// Registries (hooks, entanglement, approvals, canary webhooks, memory,
// observer) live under QRING_CONFIG_DIR — one temp dir per fork, so parallel
// test files can't race on the same JSON file and nothing lands in the
// developer's real ~/.config/q-ring.
process.env.QRING_CONFIG_DIR = defaultConfigDir;

// Test files legitimately set their own QRING_AUDIT_DIR and delete it in
// afterEach — restore the isolated default so later tests in the worker
// don't fall back to the real home. (Setup-file afterEach hooks run after
// the test file's own, so this sees the post-cleanup state.)
afterEach(() => {
  if (!process.env.QRING_AUDIT_DIR) {
    process.env.QRING_AUDIT_DIR = defaultAuditDir;
  }
  // Same for the registry dir: a test that swaps HOME (or mocks homedir)
  // clears QRING_CONFIG_DIR so the code under test resolves through HOME;
  // put the isolated default back afterwards.
  if (!process.env.QRING_CONFIG_DIR) {
    process.env.QRING_CONFIG_DIR = defaultConfigDir;
  }
});
