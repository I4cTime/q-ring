import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
} from "node:crypto";

// Redirect ~/.config to a throwaway temp home, and replace the OS keyring with
// the in-memory fake, so this suite never touches the real keychain or the
// developer's real agent-memory store.
vi.mock("node:os", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:os")>();
  const fs = await import("node:fs");
  const path = await import("node:path");
  let home: string | null = null;
  return {
    ...actual,
    homedir: () => {
      if (!home) home = fs.mkdtempSync(path.join(actual.tmpdir(), "qring-mem-"));
      return home;
    },
  };
});
vi.mock("@napi-rs/keyring", async () => {
  const fake = await import("../helpers/fake-keyring.js");
  return { Entry: fake.FakeEntry, findCredentials: fake.findCredentials };
});

import { homedir } from "node:os";
import * as os from "node:os";
import {
  remember,
  recall,
  listMemory,
  forget,
  clearMemory,
  MemoryKeyUnavailableError,
} from "../../core/memory.js";
import {
  resetFakeKeyring,
  setKeyringUnavailable,
} from "../helpers/fake-keyring.js";

const memPath = () => join(homedir(), ".config", "q-ring", "agent-memory.enc");

beforeEach(() => {
  resetFakeKeyring();
  delete process.env.QRING_MEMORY_PASSPHRASE;
  clearMemory();
});
afterEach(() => {
  delete process.env.QRING_MEMORY_PASSPHRASE;
});

describe("agent memory — basic ops", () => {
  it("stores and recalls a value", () => {
    remember("note", "hello world");
    expect(recall("note")).toBe("hello world");
  });

  it("overwrites a key and lists/forgets", () => {
    remember("k", "v1");
    remember("k", "v2");
    expect(recall("k")).toBe("v2");
    remember("b", "2");
    expect(listMemory().map((m) => m.key).sort()).toEqual(["b", "k"]);
    expect(forget("k")).toBe(true);
    expect(recall("k")).toBeNull();
    expect(forget("nope")).toBe(false);
  });
});

describe("agent memory — key hardening (A4)", () => {
  it("fails closed when no keyring and no passphrase (no derivable-key downgrade)", () => {
    const before = existsSync(memPath()) ? readFileSync(memPath()) : null;
    setKeyringUnavailable(new Error("no secret service"));
    expect(() => remember("x", "secret")).toThrow(MemoryKeyUnavailableError);
    // the failed write persisted nothing — file is byte-for-byte unchanged
    const after = existsSync(memPath()) ? readFileSync(memPath()) : null;
    expect(after).toEqual(before);
  });

  it("uses a passphrase (PBKDF2) when the keyring is unavailable", () => {
    setKeyringUnavailable(new Error("no secret service"));
    process.env.QRING_MEMORY_PASSPHRASE = "correct horse battery staple";
    remember("x", "secret");
    expect(recall("x")).toBe("secret");

    // persisted blob is the v2 passphrase format...
    const blob = readFileSync(memPath(), "utf8");
    expect(blob.startsWith("qmem2:")).toBe(true);

    // ...and is NOT recoverable from the machine fingerprint alone — proving we
    // did not silently downgrade to the legacy hostname+username key.
    const legacyKey = createHash("sha256")
      .update(`qring-memory:${os.hostname()}:${os.userInfo().username}`)
      .digest();
    // v2 body is `qmem2:<salt>:<iv:tag:ct>`; try to decrypt the ct with legacyKey
    const [, , iv, tag, ct] = blob.split(":");
    expect(() => {
      const d = createDecipheriv("aes-256-gcm", legacyKey, Buffer.from(iv, "base64"));
      d.setAuthTag(Buffer.from(tag, "base64"));
      d.update(Buffer.from(ct, "base64"));
      d.final();
    }).toThrow();
  });

  it("cannot decrypt a passphrase store once the passphrase is removed", () => {
    setKeyringUnavailable(new Error("no secret service"));
    process.env.QRING_MEMORY_PASSPHRASE = "s3kret-pass";
    remember("x", "secret");
    expect(recall("x")).toBe("secret");

    delete process.env.QRING_MEMORY_PASSPHRASE;
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    expect(recall("x")).toBeNull(); // degrades to empty, loudly
    expect(errSpy).toHaveBeenCalled();
    errSpy.mockRestore();
  });

  it("still reads a pre-A4 machine-key store (migration read)", () => {
    // Simulate a legacy store: AES-256-GCM under the machine-derived key.
    const legacyKey = createHash("sha256")
      .update(`qring-memory:${os.hostname()}:${os.userInfo().username}`)
      .digest();
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", legacyKey, iv);
    const store = JSON.stringify({
      entries: { old: { value: "legacy-value", updatedAt: "2026-01-01T00:00:00Z" } },
    });
    const enc = Buffer.concat([cipher.update(store, "utf8"), cipher.final()]);
    const blob = `${iv.toString("base64")}:${cipher.getAuthTag().toString("base64")}:${enc.toString("base64")}`;
    writeFileSync(memPath(), blob, "utf8");

    // keyring unavailable so the only key that decrypts it is the legacy one
    setKeyringUnavailable(new Error("no secret service"));
    expect(recall("old")).toBe("legacy-value");
  });
});
