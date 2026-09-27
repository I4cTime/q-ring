import { describe, it, expect, beforeEach, vi } from "vitest";
import { generateKeyPairSync, randomBytes } from "node:crypto";

vi.mock("@napi-rs/keyring", async () => {
  const fake = await import("../helpers/fake-keyring.js");
  return { Entry: fake.FakeEntry, findCredentials: fake.findCredentials };
});

import {
  resetFakeKeyring,
  fakeKeyringDump,
  FakeEntry,
} from "../helpers/fake-keyring.js";
import {
  teleportPack,
  teleportPackFor,
  teleportUnpack,
  teleportUnpackWith,
  teleportUnpackAuto,
  inspectTeleportBundle,
  parseRecipient,
  formatRecipient,
  recipientId,
  generateTeleportIdentity,
  loadTeleportIdentity,
  requireTeleportIdentity,
  TeleportBundleV2Schema,
  TELEPORT_KEYRING_SERVICE,
  TELEPORT_KEYRING_ACCOUNT,
} from "../../core/teleport.js";

/** A throwaway X25519 identity that never touches the keyring. */
function freshIdentity() {
  const { privateKey, publicKey } = generateKeyPairSync("x25519");
  const recipient = formatRecipient(publicKey);
  return {
    privateKey,
    privatePem: privateKey.export({ format: "pem", type: "pkcs8" }) as string,
    recipient,
    id: recipientId(parseRecipient(recipient)),
  };
}

function decode(bundle: string): Record<string, unknown> {
  return JSON.parse(Buffer.from(bundle, "base64").toString("utf8"));
}

function encode(obj: unknown): string {
  return Buffer.from(JSON.stringify(obj)).toString("base64");
}

const secrets = [
  { key: "API_KEY", value: "sk-abc123", scope: "project" },
  { key: "DB_PASS", value: "p@ssw0rd" },
];

describe("teleport v2 recipient strings", () => {
  it("formats as qring1 + 43 base64url chars and round-trips through parse", () => {
    const raw = randomBytes(32);
    const recipient = formatRecipient(raw);
    expect(recipient).toMatch(/^qring1[A-Za-z0-9_-]{43}$/);
    expect(recipient).not.toContain("=");
    expect(parseRecipient(recipient).equals(raw)).toBe(true);
    expect(formatRecipient(parseRecipient(recipient))).toBe(recipient);
  });

  it("formats a KeyObject the same as its raw bytes", () => {
    const { publicKey } = generateKeyPairSync("x25519");
    const fromKey = formatRecipient(publicKey);
    expect(formatRecipient(parseRecipient(fromKey))).toBe(fromKey);
  });

  it("rejects garbage with ERR_TELEPORT_BAD_RECIPIENT", () => {
    for (const bad of [
      "",
      "qring1",
      "age1abcdef",
      "qring1" + "A".repeat(42),
      "qring1" + "A".repeat(44),
      "qring1" + "A".repeat(42) + "=",
      "qring1" + "A".repeat(42) + "+",
      "qring2" + "A".repeat(43),
      "not a recipient at all",
    ]) {
      expect(() => parseRecipient(bad)).toThrow(/ERR_TELEPORT_BAD_RECIPIENT/);
    }
  });

  it("tolerates surrounding whitespace", () => {
    const recipient = formatRecipient(randomBytes(32));
    expect(formatRecipient(parseRecipient(`  ${recipient}\n`))).toBe(recipient);
  });

  it("derives an 8-hex recipient id from SHA-256 of the raw key", () => {
    const id = recipientId(randomBytes(32));
    expect(id).toMatch(/^[0-9a-f]{8}$/);
  });
});

describe("teleport v2 pack/unpack", () => {
  it("round-trips with a single recipient (KeyObject and PEM)", () => {
    const alice = freshIdentity();
    const bundle = teleportPackFor(secrets, [alice.recipient]);

    const viaKey = teleportUnpackWith(bundle, alice.privateKey);
    expect(viaKey.secrets).toEqual(secrets);
    expect(viaKey.exportedAt).toBeTruthy();

    const viaPem = teleportUnpackWith(bundle, alice.privatePem);
    expect(viaPem.secrets).toEqual(secrets);
  });

  it("round-trips with three recipients, each opening independently", () => {
    const [a, b, c] = [freshIdentity(), freshIdentity(), freshIdentity()];
    const bundle = teleportPackFor(secrets, [a.recipient, b.recipient, c.recipient]);

    const inner = decode(bundle) as { recipients: { id: string }[] };
    expect(inner.recipients.map((r) => r.id).sort()).toEqual(
      [a.id, b.id, c.id].sort(),
    );

    for (const who of [a, b, c]) {
      expect(teleportUnpackWith(bundle, who.privateKey).secrets).toEqual(secrets);
    }
  });

  it("dedupes a recipient passed twice", () => {
    const a = freshIdentity();
    const bundle = teleportPackFor(secrets, [a.recipient, a.recipient]);
    expect((decode(bundle) as { recipients: unknown[] }).recipients).toHaveLength(1);
  });

  it("emits the documented v2 bundle shape", () => {
    const a = freshIdentity();
    const inner = decode(teleportPackFor(secrets, [a.recipient]));
    expect(TeleportBundleV2Schema.safeParse(inner).success).toBe(true);
    expect(inner.v).toBe(2);
    expect(inner.count).toBe(2);
    expect(typeof inner.createdAt).toBe("string");
    expect(inner.ephemeral).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(Buffer.from(inner.ephemeral as string, "base64url")).toHaveLength(32);
    expect(Buffer.from(inner.iv as string, "base64")).toHaveLength(12);
    expect(Buffer.from(inner.tag as string, "base64")).toHaveLength(16);
    const [r] = inner.recipients as { id: string; wrap: string; iv: string; tag: string }[];
    expect(r.id).toBe(a.id);
    expect(Buffer.from(r.wrap, "base64")).toHaveLength(32);
    expect(Buffer.from(r.iv, "base64")).toHaveLength(12);
    expect(Buffer.from(r.tag, "base64")).toHaveLength(16);
    // No key material other than the ephemeral public key leaves the packer.
    expect(Object.keys(inner).sort()).toEqual(
      ["count", "createdAt", "data", "ephemeral", "iv", "recipients", "tag", "v"],
    );
  });

  it("uses a fresh ephemeral key per bundle", () => {
    const a = freshIdentity();
    const one = decode(teleportPackFor(secrets, [a.recipient]));
    const two = decode(teleportPackFor(secrets, [a.recipient]));
    expect(one.ephemeral).not.toBe(two.ephemeral);
  });

  it("refuses to pack with no recipients or a bad one", () => {
    expect(() => teleportPackFor(secrets, [])).toThrow(/ERR_TELEPORT_NO_RECIPIENTS/);
    expect(() => teleportPackFor(secrets, ["qring1nope"])).toThrow(
      /ERR_TELEPORT_BAD_RECIPIENT/,
    );
  });

  it("fails for a non-recipient identity with ERR_TELEPORT_NOT_A_RECIPIENT", () => {
    const a = freshIdentity();
    const mallory = freshIdentity();
    const bundle = teleportPackFor(secrets, [a.recipient]);
    expect(() => teleportUnpackWith(bundle, mallory.privateKey)).toThrow(
      /ERR_TELEPORT_NOT_A_RECIPIENT/,
    );
    // The error names who it IS for, so the receiver can ask for a re-pack.
    expect(() => teleportUnpackWith(bundle, mallory.privateKey)).toThrow(a.id);
  });

  it("detects a tampered payload as ERR_TELEPORT_CORRUPT", () => {
    const a = freshIdentity();
    const inner = decode(teleportPackFor(secrets, [a.recipient]));
    const data = Buffer.from(inner.data as string, "base64");
    data[0] ^= 0xff;
    inner.data = data.toString("base64");
    expect(() => teleportUnpackWith(encode(inner), a.privateKey)).toThrow(
      /ERR_TELEPORT_CORRUPT/,
    );
  });

  it("detects a tampered wrap as ERR_TELEPORT_CORRUPT", () => {
    const a = freshIdentity();
    const inner = decode(teleportPackFor(secrets, [a.recipient])) as {
      recipients: { wrap: string }[];
    };
    const wrap = Buffer.from(inner.recipients[0].wrap, "base64");
    wrap[5] ^= 0x01;
    inner.recipients[0].wrap = wrap.toString("base64");
    expect(() => teleportUnpackWith(encode(inner), a.privateKey)).toThrow(
      /ERR_TELEPORT_CORRUPT/,
    );
  });

  it("detects a tampered payload tag and a swapped ephemeral key", () => {
    const a = freshIdentity();
    const good = decode(teleportPackFor(secrets, [a.recipient]));

    const badTag = { ...good, tag: Buffer.alloc(16, 7).toString("base64") };
    expect(() => teleportUnpackWith(encode(badTag), a.privateKey)).toThrow(
      /ERR_TELEPORT_CORRUPT/,
    );

    const swapped = { ...good, ephemeral: randomBytes(32).toString("base64url") };
    expect(() => teleportUnpackWith(encode(swapped), a.privateKey)).toThrow(
      /ERR_TELEPORT_CORRUPT/,
    );
  });

  it("rejects the wrong bundle shape and unparseable input as corrupt", () => {
    const a = freshIdentity();
    expect(() => teleportUnpackWith("not-a-bundle", a.privateKey)).toThrow(
      /ERR_TELEPORT_CORRUPT/,
    );
    const v1 = teleportPack(secrets, "pw");
    expect(() => teleportUnpackWith(v1, a.privateKey)).toThrow(/ERR_TELEPORT_CORRUPT/);
    expect(() => teleportUnpackWith(encode({ v: 2 }), a.privateKey)).toThrow(
      /ERR_TELEPORT_CORRUPT/,
    );
  });

  it("rejects an unusable PEM as a bad identity", () => {
    const a = freshIdentity();
    const bundle = teleportPackFor(secrets, [a.recipient]);
    expect(() => teleportUnpackWith(bundle, "-----BEGIN NOPE-----")).toThrow(
      /ERR_TELEPORT_BAD_IDENTITY/,
    );
  });
});

describe("teleportUnpackAuto / inspectTeleportBundle", () => {
  it("still unpacks v1 bundles with a passphrase", () => {
    const bundle = teleportPack(secrets, "hunter2");
    expect(inspectTeleportBundle(bundle)).toEqual({ v: 1, count: 2 });
    expect(teleportUnpackAuto(bundle, { passphrase: "hunter2" }).secrets).toEqual(secrets);
    expect(teleportUnpack(bundle, "hunter2").secrets).toEqual(secrets);
    expect(() => teleportUnpackAuto(bundle, { passphrase: "wrong" })).toThrow(
      /ERR_TELEPORT_BAD_PASSPHRASE/,
    );
  });

  it("picks v2 by the parsed v field and reports recipients", () => {
    const [a, b] = [freshIdentity(), freshIdentity()];
    const bundle = teleportPackFor(secrets, [a.recipient, b.recipient]);
    const info = inspectTeleportBundle(bundle);
    expect(info.v).toBe(2);
    expect(info.count).toBe(2);
    if (info.v === 2) expect(info.recipients.sort()).toEqual([a.id, b.id].sort());
    expect(teleportUnpackAuto(bundle, { identity: b.privateKey }).secrets).toEqual(secrets);
  });

  it("explains which credential is missing", () => {
    const a = freshIdentity();
    expect(() => teleportUnpackAuto(teleportPack(secrets, "pw"), {})).toThrow(
      /ERR_TELEPORT_PASSPHRASE_REQUIRED/,
    );
    expect(() =>
      teleportUnpackAuto(teleportPackFor(secrets, [a.recipient]), { passphrase: "pw" }),
    ).toThrow(/ERR_TELEPORT_NO_IDENTITY.*keygen/);
  });

  it("rejects unknown versions as corrupt", () => {
    expect(() => inspectTeleportBundle(encode({ v: 3 }))).toThrow(
      /ERR_TELEPORT_CORRUPT.*v=3/,
    );
    expect(() => inspectTeleportBundle("!!!")).toThrow(/ERR_TELEPORT_CORRUPT/);
  });
});

describe("teleport identity in the keyring", () => {
  beforeEach(() => resetFakeKeyring());

  it("keygen stores a PKCS8 private key in q-ring-teleport/identity and identity reads it back", () => {
    expect(loadTeleportIdentity()).toBeNull();
    expect(() => requireTeleportIdentity()).toThrow(/ERR_TELEPORT_NO_IDENTITY.*keygen/);

    const created = generateTeleportIdentity();
    expect(created.recipient).toMatch(/^qring1[A-Za-z0-9_-]{43}$/);

    const stored = fakeKeyringDump().get(
      `${TELEPORT_KEYRING_SERVICE}\0${TELEPORT_KEYRING_ACCOUNT}`,
    );
    expect(stored).toBeTruthy();
    // PKCS8 DER for X25519 is 48 bytes; the public recipient is never stored.
    expect(Buffer.from(stored!, "base64")).toHaveLength(48);
    expect(stored).not.toContain(created.recipient.slice(6));

    const loaded = loadTeleportIdentity();
    expect(loaded?.recipient).toBe(created.recipient);
    expect(loaded?.id).toBe(created.id);
    expect(requireTeleportIdentity().recipient).toBe(created.recipient);
  });

  it("refuses to overwrite without force, replaces with force", () => {
    const first = generateTeleportIdentity();
    expect(() => generateTeleportIdentity()).toThrow(/ERR_TELEPORT_IDENTITY_EXISTS/);
    expect(loadTeleportIdentity()?.recipient).toBe(first.recipient);

    const second = generateTeleportIdentity({ force: true });
    expect(second.recipient).not.toBe(first.recipient);
    expect(loadTeleportIdentity()?.recipient).toBe(second.recipient);
  });

  it("unpacks a bundle addressed to the stored identity end to end", () => {
    const me = generateTeleportIdentity();
    const bundle = teleportPackFor(secrets, [me.recipient]);
    const identity = requireTeleportIdentity();
    expect(teleportUnpackAuto(bundle, { identity: identity.privateKey }).secrets).toEqual(
      secrets,
    );
  });

  it("flags an unreadable stored identity", () => {
    new FakeEntry(TELEPORT_KEYRING_SERVICE, TELEPORT_KEYRING_ACCOUNT).setPassword(
      Buffer.from("garbage").toString("base64"),
    );
    expect(() => loadTeleportIdentity()).toThrow(/ERR_TELEPORT_BAD_IDENTITY/);
  });
});
