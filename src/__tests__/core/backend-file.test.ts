import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Entry, findCredentials, activeBackend, BackendUnavailableError } from "../../core/backend.js";
import { setSecret, getSecret, deleteSecret } from "../../core/keyring.js";

let dir: string;
let storeFile: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "qring-file-backend-"));
  storeFile = join(dir, "store.enc");
  process.env.QRING_BACKEND = "file";
  process.env.QRING_FILE_PASSPHRASE = "correct horse battery staple";
  process.env.QRING_FILE_BACKEND_PATH = storeFile;
});

afterEach(() => {
  delete process.env.QRING_BACKEND;
  delete process.env.QRING_FILE_PASSPHRASE;
  delete process.env.QRING_FILE_BACKEND_PATH;
  rmSync(dir, { recursive: true, force: true });
});

describe("backend selection", () => {
  it("defaults to the OS keyring", () => {
    delete process.env.QRING_BACKEND;
    expect(activeBackend()).toBe("keyring");
  });

  it("selects the file backend on QRING_BACKEND=file", () => {
    expect(activeBackend()).toBe("file");
  });

  it("rejects unknown backends", () => {
    process.env.QRING_BACKEND = "vault";
    expect(() => activeBackend()).toThrow(BackendUnavailableError);
  });
});

describe("file backend Entry", () => {
  it("round-trips set/get/delete", () => {
    const entry = new Entry("qring-test-svc", "MY_KEY");
    expect(entry.getPassword()).toBeNull();

    entry.setPassword("value-1");
    expect(entry.getPassword()).toBe("value-1");

    expect(entry.deleteCredential()).toBe(true);
    expect(entry.getPassword()).toBeNull();
    expect(entry.deleteCredential()).toBe(false);
  });

  it("findCredentials lists only the requested service", () => {
    new Entry("svc-a", "K1").setPassword("v1");
    new Entry("svc-a", "K2").setPassword("v2");
    new Entry("svc-b", "K3").setPassword("v3");

    const creds = findCredentials("svc-a");
    expect(creds).toHaveLength(2);
    expect(creds.map((c) => c.account).sort()).toEqual(["K1", "K2"]);
  });

  it("persists encrypted — plaintext never touches disk, mode is 0600", () => {
    new Entry("svc", "KEY").setPassword("super-secret-plaintext");

    const raw = readFileSync(storeFile, "utf8");
    expect(raw.startsWith("qfile1:")).toBe(true);
    expect(raw).not.toContain("super-secret-plaintext");
    expect(raw).not.toContain("KEY");
    if (process.platform !== "win32") {
      // Windows has no POSIX mode bits (reports 0o666 regardless).
      expect(statSync(storeFile).mode & 0o777).toBe(0o600);
    }
  });

  it("fails closed without a passphrase", () => {
    delete process.env.QRING_FILE_PASSPHRASE;
    expect(() => new Entry("svc", "K").setPassword("v")).toThrow(BackendUnavailableError);
    expect(() => new Entry("svc", "K").setPassword("v")).toThrow(/QRING_FILE_PASSPHRASE/);
  });

  it("wrong passphrase cannot decrypt", () => {
    new Entry("svc", "K").setPassword("v");
    process.env.QRING_FILE_PASSPHRASE = "wrong passphrase";
    expect(() => new Entry("svc", "K").getPassword()).toThrow(/Cannot decrypt/);
  });

  it("tampered store is rejected (GCM auth)", () => {
    new Entry("svc", "K").setPassword("v");
    const raw = readFileSync(storeFile, "utf8").trim();
    const parts = raw.split(":");
    // Flip a byte in the ciphertext.
    const ct = Buffer.from(parts[4], "base64");
    ct[0] ^= 0xff;
    parts[4] = ct.toString("base64");
    writeFileSync(storeFile, parts.join(":"));

    expect(() => new Entry("svc", "K").getPassword()).toThrow(/Cannot decrypt|tampered/);
  });
});

describe("keyring.ts on the file backend", () => {
  const PROJECT = "/tmp/qring-file-backend-project";

  it("setSecret/getSecret/deleteSecret work end-to-end with envelopes", () => {
    setSecret("FILE_BACKED", "the-value", { scope: "project", projectPath: PROJECT, silent: true });
    expect(getSecret("FILE_BACKED", { scope: "project", projectPath: PROJECT, silent: true })).toBe("the-value");

    deleteSecret("FILE_BACKED", { scope: "project", projectPath: PROJECT, silent: true });
    expect(getSecret("FILE_BACKED", { scope: "project", projectPath: PROJECT, silent: true })).toBeNull();
  });
});
