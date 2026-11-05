import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { createCipheriv, pbkdf2Sync, randomBytes } from "node:crypto";
import { teleportPack, teleportUnpack } from "../../core/teleport.js";
import {
  resetDeprecationWarnings,
  SILENCE_DEPRECATIONS_ENV,
} from "../../core/deprecation.js";

/** Build a pre-bump bundle (PBKDF2 100k, no `iter` field) the old code produced. */
function legacyBundle(
  secrets: { key: string; value: string; scope?: string }[],
  passphrase: string,
): string {
  const plaintext = JSON.stringify({
    secrets,
    exportedAt: new Date().toISOString(),
  });
  const salt = randomBytes(32);
  const iv = randomBytes(12);
  const key = pbkdf2Sync(passphrase, salt, 100000, 32, "sha512");
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  const bundle = {
    v: 1,
    data: encrypted.toString("base64"),
    salt: salt.toString("base64"),
    iv: iv.toString("base64"),
    tag: tag.toString("base64"),
    createdAt: new Date().toISOString(),
    count: secrets.length,
  };
  return Buffer.from(JSON.stringify(bundle)).toString("base64");
}

describe("teleport pack/unpack", () => {
  const secrets = [
    { key: "API_KEY", value: "sk-abc123", scope: "project" },
    { key: "DB_PASS", value: "p@ssw0rd" },
  ];
  const passphrase = "test-passphrase-42";

  it("packs secrets into a non-empty base64 string", () => {
    const bundle = teleportPack(secrets, passphrase);
    expect(bundle.length).toBeGreaterThan(0);
  });

  it("uses a 12-byte AES-GCM IV (NIST-recommended nonce length)", () => {
    const bundle = teleportPack(secrets, passphrase);
    const inner = JSON.parse(
      Buffer.from(bundle, "base64").toString("utf8"),
    ) as { iv: string };
    const iv = Buffer.from(inner.iv, "base64");
    expect(iv.length).toBe(12);
  });

  it("round-trips secrets through pack and unpack", () => {
    const bundle = teleportPack(secrets, passphrase);
    const payload = teleportUnpack(bundle, passphrase);
    expect(payload.secrets).toHaveLength(2);
    expect(payload.secrets[0].key).toBe("API_KEY");
    expect(payload.secrets[0].value).toBe("sk-abc123");
    expect(payload.secrets[1].key).toBe("DB_PASS");
    expect(payload.secrets[1].value).toBe("p@ssw0rd");
    expect(payload.exportedAt).toBeTruthy();
  });

  it("preserves scope metadata", () => {
    const bundle = teleportPack(secrets, passphrase);
    const payload = teleportUnpack(bundle, passphrase);
    expect(payload.secrets[0].scope).toBe("project");
    expect(payload.secrets[1].scope).toBeUndefined();
  });

  it("throws on wrong passphrase", () => {
    const bundle = teleportPack(secrets, passphrase);
    expect(() => teleportUnpack(bundle, "wrong-password")).toThrow(
      /ERR_TELEPORT_BAD_PASSPHRASE/,
    );
  });

  it("throws on corrupted bundle", () => {
    expect(() => teleportUnpack("not-a-bundle", passphrase)).toThrow();
  });

  it("handles empty secrets array", () => {
    const bundle = teleportPack([], passphrase);
    const payload = teleportUnpack(bundle, passphrase);
    expect(payload.secrets).toHaveLength(0);
  });

  it("records the PBKDF2 iteration count in new bundles", () => {
    const bundle = teleportPack(secrets, passphrase);
    const inner = JSON.parse(
      Buffer.from(bundle, "base64").toString("utf8"),
    ) as { iter?: number };
    expect(inner.iter).toBe(210000);
  });

  it("still decrypts legacy bundles that predate the iteration bump", () => {
    const bundle = legacyBundle(secrets, passphrase);
    const payload = teleportUnpack(bundle, passphrase);
    expect(payload.secrets[0].value).toBe("sk-abc123");
    expect(payload.secrets[1].value).toBe("p@ssw0rd");
  });
});

describe("teleport v1 bundles without iter (Deprecated in 0.19)", () => {
  const secrets = [{ key: "API_KEY", value: "sk-abc123" }];
  const passphrase = "test-passphrase-42";
  let stderr: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    resetDeprecationWarnings();
    delete process.env[SILENCE_DEPRECATIONS_ENV];
    stderr = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
  });
  afterEach(() => {
    stderr.mockRestore();
    delete process.env[SILENCE_DEPRECATIONS_ENV];
  });

  it("warns once on unpack of an iter-less bundle, not twice", () => {
    expect(teleportUnpack(legacyBundle(secrets, passphrase), passphrase).secrets).toEqual(secrets);
    teleportUnpack(legacyBundle(secrets, passphrase), passphrase);
    expect(stderr).toHaveBeenCalledTimes(1);
    const line = String(stderr.mock.calls[0][0]);
    expect(line).toMatch(/^q-ring: deprecated: .*predates 0\.12\.0.*Removed in 1\.0\.\n$/);
  });

  it("does not warn for a current bundle", () => {
    teleportUnpack(teleportPack(secrets, passphrase), passphrase);
    expect(stderr).not.toHaveBeenCalled();
  });

  it("is silent with QRING_SILENCE_DEPRECATIONS=1", () => {
    process.env[SILENCE_DEPRECATIONS_ENV] = "1";
    teleportUnpack(legacyBundle(secrets, passphrase), passphrase);
    expect(stderr).not.toHaveBeenCalled();
  });
});
