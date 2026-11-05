import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { tmpdir } from "node:os";
import { join } from "node:path";

// Simulate a full disk: the next write of the store gets half its bytes
// down, then fails, the way a real ENOSPC or a crash mid-write would.
const failNextStoreWrite = vi.hoisted(() => ({ on: false }));
vi.mock("node:fs", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs")>();
  const writeFileSync = ((path: unknown, data: unknown, options?: unknown) => {
    if (failNextStoreWrite.on && typeof data === "string" && data.startsWith("qfile1:")) {
      failNextStoreWrite.on = false;
      actual.writeFileSync(path as string, data.slice(0, data.length / 2), options as never);
      const err = new Error("ENOSPC: no space left on device") as NodeJS.ErrnoException;
      err.code = "ENOSPC";
      throw err;
    }
    return actual.writeFileSync(path as never, data as never, options as never);
  }) as typeof actual.writeFileSync;
  return { ...actual, writeFileSync, default: { ...actual, writeFileSync } };
});

import { mkdtempSync, readdirSync, rmSync } from "node:fs";
import { Entry } from "../../core/backend.js";

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "qring-file-atomic-"));
  process.env.QRING_BACKEND = "file";
  process.env.QRING_FILE_PASSPHRASE = "correct horse battery staple";
  process.env.QRING_FILE_BACKEND_PATH = join(dir, "store.enc");
});

afterEach(() => {
  failNextStoreWrite.on = false;
  delete process.env.QRING_BACKEND;
  delete process.env.QRING_FILE_PASSPHRASE;
  delete process.env.QRING_FILE_BACKEND_PATH;
  rmSync(dir, { recursive: true, force: true });
});

describe("file backend store writes are atomic", () => {
  it("a write that fails halfway leaves every existing secret readable", () => {
    for (let i = 0; i < 5; i++) new Entry("q-ring:global", `KEY_${i}`).setPassword(`value-${i}`);

    failNextStoreWrite.on = true;
    expect(() => new Entry("q-ring:global", "NEW_KEY").setPassword("new-value")).toThrow(/ENOSPC/);

    for (let i = 0; i < 5; i++) {
      expect(new Entry("q-ring:global", `KEY_${i}`).getPassword()).toBe(`value-${i}`);
    }
    expect(new Entry("q-ring:global", "NEW_KEY").getPassword()).toBeNull();
    // ...and no half-written temp file is left beside the store.
    expect(readdirSync(dir)).toEqual(["store.enc"]);
  });
});
