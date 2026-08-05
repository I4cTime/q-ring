import {
  mkdirSync,
  writeFileSync,
  unlinkSync,
  readFileSync,
  statSync,
} from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";

/** Non-spinning synchronous sleep — yields the CPU instead of busy-waiting. */
function sleepSync(ms: number): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

/** True if a process with this pid exists (EPERM = exists but not ours). */
function isProcessAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return (err as NodeJS.ErrnoException).code === "EPERM";
  }
}

export interface FileLockOptions {
  /** Subdirectory under ~/.config/q-ring holding the lock file. */
  dir?: string;
  /** Max time to wait to acquire before throwing (ms). */
  timeoutMs?: number;
  /** Age past which a lock whose holder we can't disprove is stolen (ms). */
  staleMs?: number;
}

/**
 * Run `fn` while holding an exclusive on-disk lock named `name`.
 *
 * A crash while holding the lock used to deadlock every future caller (the old
 * JIT lock wrote its pid but never read it back, and spun the CPU while
 * waiting). This version steals a lock whose holder process is gone, or that is
 * older than `staleMs`, and sleeps without busy-spinning between attempts.
 * Synchronous by design — callers (secret reads, audit appends) run in sync
 * contexts.
 */
export function withFileLock<T>(
  name: string,
  fn: () => T,
  opts: FileLockOptions = {},
): T {
  const lockDir = join(homedir(), ".config", "q-ring", opts.dir ?? "locks");
  mkdirSync(lockDir, { recursive: true, mode: 0o700 });
  const safe = Buffer.from(name, "utf8").toString("base64url");
  const lockPath = join(lockDir, `${safe}.lock`);
  const deadline = Date.now() + (opts.timeoutMs ?? 8000);
  const staleMs = opts.staleMs ?? 30_000;

  while (Date.now() < deadline) {
    // Acquisition and the critical section are separate try blocks: if they
    // shared one, an exception thrown by fn() would be caught by the retry
    // logic below and resurface 8s later as a bogus "could not acquire lock"
    // timeout instead of propagating.
    let acquired = false;
    try {
      writeFileSync(lockPath, `${process.pid}\n`, { flag: "wx", mode: 0o600 });
      acquired = true;
    } catch {
      try {
        const holderPid = parseInt(readFileSync(lockPath, "utf8").trim(), 10);
        const ageMs = Date.now() - statSync(lockPath).mtimeMs;
        const stale =
          (Number.isInteger(holderPid) && holderPid > 0 && !isProcessAlive(holderPid)) ||
          ageMs > staleMs;
        if (stale) {
          unlinkSync(lockPath);
          continue;
        }
      } catch {
        // Lock vanished between our failed create and this inspection — retry.
      }
      sleepSync(15);
    }

    if (acquired) {
      try {
        return fn();
      } finally {
        try {
          unlinkSync(lockPath);
        } catch {
          /* ignore */
        }
      }
    }
  }
  throw new Error(`Could not acquire lock "${name}" (timeout)`);
}
