import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import {
  mkdirSync,
  writeFileSync,
  existsSync,
  rmSync,
  utimesSync,
} from "node:fs";
import { join } from "node:path";

// Isolate ~/.config to a temp home.
vi.mock("node:os", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:os")>();
  const fs = await import("node:fs");
  const path = await import("node:path");
  let home: string | null = null;
  return {
    ...actual,
    homedir: () => {
      if (!home) home = fs.mkdtempSync(path.join(actual.tmpdir(), "qring-lock-"));
      return home;
    },
  };
});

import { homedir } from "node:os";
import { withFileLock } from "../../utils/file-lock.js";

const lockDir = () => join(homedir(), ".config", "q-ring", "locks");
const lockFile = (name: string) =>
  join(lockDir(), `${Buffer.from(name, "utf8").toString("base64url")}.lock`);

describe("withFileLock stale recovery (B1)", () => {
  beforeEach(() => {
    rmSync(lockDir(), { recursive: true, force: true });
    mkdirSync(lockDir(), { recursive: true });
  });
  afterEach(() => {
    rmSync(lockDir(), { recursive: true, force: true });
  });

  it("runs fn and releases the lock in the happy path", () => {
    const out = withFileLock("k", () => 42, { timeoutMs: 2000 });
    expect(out).toBe(42);
    expect(existsSync(lockFile("k"))).toBe(false);
  });

  it("steals a lock held by a dead process instead of deadlocking", () => {
    // A crashed holder left this behind (pid 999999 does not exist).
    writeFileSync(lockFile("k"), "999999\n", { flag: "wx" });
    const out = withFileLock("k", () => "recovered", { timeoutMs: 3000 });
    expect(out).toBe("recovered");
  });

  it("steals a lock older than staleMs even if the pid looks alive", () => {
    // Own pid (alive), but the lock is ancient.
    writeFileSync(lockFile("k"), `${process.pid}\n`, { flag: "wx" });
    const old = new Date(Date.now() - 120_000);
    utimesSync(lockFile("k"), old, old);
    const out = withFileLock("k", () => "stolen", { timeoutMs: 3000, staleMs: 30_000 });
    expect(out).toBe("stolen");
  });

  it("times out when a live, fresh lock is held by another process", () => {
    // Own pid, fresh mtime → not stale → cannot acquire → times out fast.
    writeFileSync(lockFile("k"), `${process.pid}\n`, { flag: "wx" });
    expect(() =>
      withFileLock("k", () => "never", { timeoutMs: 200, staleMs: 30_000 }),
    ).toThrow(/Could not acquire lock/);
  });
});
