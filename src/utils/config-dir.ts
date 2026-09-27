/**
 * Where q-ring keeps its per-user registries (hooks, entanglement, canary
 * webhooks, approvals, memory, observer state, lock dir fallback).
 *
 * Defaults to ~/.config/q-ring. `QRING_CONFIG_DIR` overrides it — the test
 * suite points every fork at its own temp dir so parallel test files never
 * race on the same registry JSON (the source of a flaky "registry corrupt"
 * failure) and never touch the developer's real registries. The audit log
 * and lock dir keep their own, more specific knobs (`QRING_AUDIT_DIR`,
 * `QRING_LOCK_DIR`) which take precedence for their files.
 */
import { homedir } from "node:os";
import { join } from "node:path";

export const CONFIG_DIR_ENV = "QRING_CONFIG_DIR";

export function configDir(): string {
  const override = process.env[CONFIG_DIR_ENV];
  if (override && override.trim()) return override;
  return join(homedir(), ".config", "q-ring");
}
