import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { lstatSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { Entry, BackendUnavailableError } from "../../core/backend.js";

let dir: string;
let storePath: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "qring-store-symlink-"));
  storePath = join(dir, "store.enc");
  process.env.QRING_BACKEND = "file";
  process.env.QRING_FILE_PASSPHRASE = "correct horse battery staple";
});

afterEach(() => {
  delete process.env.QRING_BACKEND;
  delete process.env.QRING_FILE_PASSPHRASE;
  delete process.env.QRING_FILE_BACKEND_PATH;
  rmSync(dir, { recursive: true, force: true });
});

describe.skipIf(process.platform === "win32")(
  "file backend with a symlink at the store path",
  () => {
    it("a symlink to a valid store elsewhere is replaced by a regular file; the target is untouched", () => {
      const elsewhere = join(dir, "elsewhere.enc");
      process.env.QRING_FILE_BACKEND_PATH = elsewhere;
      new Entry("q-ring:global", "OLD_KEY").setPassword("old-value");
      const targetBytes = readFileSync(elsewhere);

      symlinkSync(elsewhere, storePath);
      process.env.QRING_FILE_BACKEND_PATH = storePath;
      new Entry("q-ring:global", "NEW_KEY").setPassword("new-value");

      // The write landed in a new regular file at the store path...
      expect(lstatSync(storePath).isSymbolicLink()).toBe(false);
      expect(new Entry("q-ring:global", "OLD_KEY").getPassword()).toBe("old-value");
      expect(new Entry("q-ring:global", "NEW_KEY").getPassword()).toBe("new-value");
      // ...and never through the link.
      expect(readFileSync(elsewhere).equals(targetBytes)).toBe(true);
    });

    it("a symlink to something that is not a store is refused, and the target is untouched", () => {
      const other = join(dir, "notes.txt");
      writeFileSync(other, "not a store");
      symlinkSync(other, storePath);
      process.env.QRING_FILE_BACKEND_PATH = storePath;

      expect(() => new Entry("q-ring:global", "K").setPassword("v")).toThrow(
        BackendUnavailableError,
      );
      expect(readFileSync(other, "utf8")).toBe("not a store");
      expect(lstatSync(storePath).isSymbolicLink()).toBe(true);
    });
  },
);
