/**
 * Quantum Teleportation: securely share/transfer secrets between machines.
 *
 * Generates encrypted bundles that can be shared via any channel.
 *
 * - v1 (passphrase): AES-256-GCM under a PBKDF2-HMAC-SHA512 key derived from
 *   a passphrase exchanged out-of-band.
 * - v2 (recipient packs): age-style public-key encryption. The packer wraps a
 *   random content key for each recipient's X25519 public key (ECDH with an
 *   ephemeral key, HKDF-SHA256, AES-256-GCM key wrap). No shared secret is
 *   needed — recipients publish a `qring1...` string once and keep their
 *   private key in the OS keyring (`qring teleport keygen`).
 */

import {
  randomBytes,
  createCipheriv,
  createDecipheriv,
  createHash,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  hkdfSync,
  pbkdf2Sync,
  type KeyObject,
} from "node:crypto";
import { z } from "zod";
import { Entry } from "./backend.js";

const ALGORITHM = "aes-256-gcm";
const KEY_LENGTH = 32;
/** NIST / OpenSSL recommendation for AES-GCM (96-bit nonce). */
const IV_LENGTH = 12;
const SALT_LENGTH = 32;
/** OWASP-recommended floor for PBKDF2-HMAC-SHA512 (2023). */
const PBKDF2_ITERATIONS = 210000;
/** Bundles without an explicit `iter` predate the bump; decrypt at the old cost. */
const LEGACY_PBKDF2_ITERATIONS = 100000;

export interface TeleportBundle {
  /** Format version */
  v: 1;
  /** Base64-encoded encrypted payload */
  data: string;
  /** Base64-encoded salt for key derivation */
  salt: string;
  /** Base64-encoded initialization vector */
  iv: string;
  /** Base64-encoded auth tag */
  tag: string;
  /** ISO timestamp of creation */
  createdAt: string;
  /** Number of secrets in the bundle */
  count: number;
  /** PBKDF2 iteration count used for key derivation (absent = legacy 100k). */
  iter?: number;
}

export interface TeleportPayload {
  secrets: { key: string; value: string; scope?: string }[];
  exportedAt: string;
  exportedBy?: string;
}

export const TeleportBundleSchema = z.object({
  v: z.literal(1),
  data: z.string(),
  salt: z.string(),
  iv: z.string(),
  tag: z.string(),
  createdAt: z.string(),
  count: z.number(),
  iter: z.number().optional(),
});

export const TeleportPayloadSchema = z.object({
  secrets: z.array(
    z.object({
      key: z.string(),
      value: z.string(),
      scope: z.string().optional(),
    }),
  ),
  exportedAt: z.string(),
  exportedBy: z.string().optional(),
});

function deriveKey(
  passphrase: string,
  salt: Buffer,
  iterations: number = PBKDF2_ITERATIONS,
): Buffer {
  return pbkdf2Sync(passphrase, salt, iterations, KEY_LENGTH, "sha512");
}

/** base64 → JSON, with the v1-era error codes preserved. */
function decodeBundle(encoded: string): unknown {
  let bundleJson: string;
  try {
    bundleJson = Buffer.from(encoded, "base64").toString("utf8");
  } catch {
    throw new Error("ERR_TELEPORT_CORRUPT: invalid base64 bundle");
  }

  try {
    return JSON.parse(bundleJson);
  } catch {
    throw new Error("ERR_TELEPORT_CORRUPT: bundle is not valid JSON");
  }
}

function parsePayload(decrypted: Buffer): TeleportPayload {
  let rawPayload: unknown;
  try {
    rawPayload = JSON.parse(decrypted.toString("utf8"));
  } catch {
    throw new Error("ERR_TELEPORT_CORRUPT: decrypted payload is not valid JSON");
  }

  const payload = TeleportPayloadSchema.safeParse(rawPayload);
  if (!payload.success) {
    throw new Error(
      `ERR_TELEPORT_CORRUPT: invalid payload (${payload.error.message})`,
    );
  }
  return payload.data;
}

/**
 * Pack secrets into an encrypted teleport bundle.
 */
export function teleportPack(
  secrets: { key: string; value: string; scope?: string }[],
  passphrase: string,
): string {
  const payload: TeleportPayload = {
    secrets,
    exportedAt: new Date().toISOString(),
  };

  const plaintext = JSON.stringify(payload);
  const salt = randomBytes(SALT_LENGTH);
  const iv = randomBytes(IV_LENGTH);
  const key = deriveKey(passphrase, salt, PBKDF2_ITERATIONS);

  const cipher = createCipheriv(ALGORITHM, key, iv);
  const encrypted = Buffer.concat([
    cipher.update(plaintext, "utf8"),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();

  const bundle: TeleportBundle = {
    v: 1,
    data: encrypted.toString("base64"),
    salt: salt.toString("base64"),
    iv: iv.toString("base64"),
    tag: tag.toString("base64"),
    createdAt: new Date().toISOString(),
    count: secrets.length,
    iter: PBKDF2_ITERATIONS,
  };

  return Buffer.from(JSON.stringify(bundle)).toString("base64");
}

/**
 * Unpack and decrypt a teleport bundle.
 */
export function teleportUnpack(
  encoded: string,
  passphrase: string,
): TeleportPayload {
  const rawBundle = decodeBundle(encoded);

  const parsedBundle = TeleportBundleSchema.safeParse(rawBundle);
  if (!parsedBundle.success) {
    throw new Error(
      `ERR_TELEPORT_CORRUPT: invalid bundle shape (${parsedBundle.error.message})`,
    );
  }
  const bundle = parsedBundle.data;

  const salt = Buffer.from(bundle.salt, "base64");
  const iv = Buffer.from(bundle.iv, "base64");
  const tag = Buffer.from(bundle.tag, "base64");
  const encrypted = Buffer.from(bundle.data, "base64");
  const key = deriveKey(passphrase, salt, bundle.iter ?? LEGACY_PBKDF2_ITERATIONS);

  const decipher = createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(tag);

  let decrypted: Buffer;
  try {
    decrypted = Buffer.concat([
      decipher.update(encrypted),
      decipher.final(),
    ]);
  } catch {
    throw new Error("ERR_TELEPORT_BAD_PASSPHRASE: decryption failed (wrong passphrase or corrupt data)");
  }

  return parsePayload(decrypted);
}

// ─── v2: recipient packs (X25519 + HKDF-SHA256 + AES-256-GCM key wrap) ───

/** Recipient strings look like `qring1` + base64url(raw 32-byte X25519 pub). */
const RECIPIENT_PREFIX = "qring1";
const RECIPIENT_RE = /^qring1([A-Za-z0-9_-]{43})$/;
const X25519_RAW_LENGTH = 32;
/** AAD binding the payload ciphertext to the v2 format. */
const V2_AAD = "qring-teleport-v2";
/** HKDF info for the per-recipient wrapping key. */
const V2_WRAP_INFO = "qring-teleport-v2-wrap";
/** Where our own private key lives: OS keyring, never a file. */
export const TELEPORT_KEYRING_SERVICE = "q-ring-teleport";
export const TELEPORT_KEYRING_ACCOUNT = "identity";

export interface TeleportRecipientEntry {
  /** First 8 hex chars of SHA-256(raw recipient public key). */
  id: string;
  /** Base64 AES-256-GCM ciphertext of the content-encryption key. */
  wrap: string;
  /** Base64 IV for the wrap. */
  iv: string;
  /** Base64 auth tag for the wrap. */
  tag: string;
}

export interface TeleportBundleV2 {
  v: 2;
  createdAt: string;
  count: number;
  /** base64url raw 32-byte ephemeral X25519 public key. */
  ephemeral: string;
  recipients: TeleportRecipientEntry[];
  /** Base64 IV for the payload. */
  iv: string;
  /** Base64 auth tag for the payload. */
  tag: string;
  /** Base64 AES-256-GCM ciphertext of the JSON payload. */
  data: string;
}

export const TeleportBundleV2Schema = z.object({
  v: z.literal(2),
  createdAt: z.string(),
  count: z.number(),
  ephemeral: z.string(),
  recipients: z
    .array(
      z.object({
        id: z.string(),
        wrap: z.string(),
        iv: z.string(),
        tag: z.string(),
      }),
    )
    .min(1),
  iv: z.string(),
  tag: z.string(),
  data: z.string(),
});

export interface TeleportIdentity {
  /** Our X25519 private key (never serialised by callers). */
  privateKey: KeyObject;
  /** Our public recipient string (`qring1...`). */
  recipient: string;
  /** Our recipient id, as it appears in bundles addressed to us. */
  id: string;
}

function rawPublicKey(key: KeyObject): Buffer {
  const jwk = key.export({ format: "jwk" });
  if (jwk.kty !== "OKP" || jwk.crv !== "X25519" || typeof jwk.x !== "string") {
    throw new Error("ERR_TELEPORT_BAD_RECIPIENT: not an X25519 public key");
  }
  const raw = Buffer.from(jwk.x, "base64url");
  if (raw.length !== X25519_RAW_LENGTH) {
    throw new Error("ERR_TELEPORT_BAD_RECIPIENT: not an X25519 public key");
  }
  return raw;
}

function publicKeyFromRaw(raw: Buffer): KeyObject {
  return createPublicKey({
    key: { kty: "OKP", crv: "X25519", x: raw.toString("base64url") },
    format: "jwk",
  });
}

/** `qring1` + base64url(raw public key), no padding. */
export function formatRecipient(publicKey: KeyObject | Buffer): string {
  const raw = Buffer.isBuffer(publicKey) ? publicKey : rawPublicKey(publicKey);
  if (raw.length !== X25519_RAW_LENGTH) {
    throw new Error("ERR_TELEPORT_BAD_RECIPIENT: public key must be 32 raw bytes");
  }
  return `${RECIPIENT_PREFIX}${raw.toString("base64url")}`;
}

/**
 * Parse a recipient string back into the raw 32-byte X25519 public key.
 * Throws `ERR_TELEPORT_BAD_RECIPIENT` on anything that is not exactly
 * `qring1` + 43 base64url characters decoding to 32 bytes.
 */
export function parseRecipient(str: string): Buffer {
  const trimmed = typeof str === "string" ? str.trim() : "";
  const match = RECIPIENT_RE.exec(trimmed);
  if (!match) {
    throw new Error(
      `ERR_TELEPORT_BAD_RECIPIENT: expected "${RECIPIENT_PREFIX}" followed by a base64url X25519 public key (run \`qring teleport identity\` on the recipient's machine to get one)`,
    );
  }
  const raw = Buffer.from(match[1], "base64url");
  if (raw.length !== X25519_RAW_LENGTH) {
    throw new Error(
      "ERR_TELEPORT_BAD_RECIPIENT: recipient key does not decode to 32 bytes",
    );
  }
  return raw;
}

/** First 8 hex chars of SHA-256(raw public key). */
export function recipientId(rawPub: Buffer): string {
  return createHash("sha256").update(rawPub).digest("hex").slice(0, 8);
}

/** HKDF-SHA256(ikm=shared, salt=ephemeralPub||recipientPub, info, 32). */
function deriveWrapKey(
  shared: Buffer,
  ephemeralPub: Buffer,
  recipientPub: Buffer,
): Buffer {
  return Buffer.from(
    hkdfSync(
      "sha256",
      shared,
      Buffer.concat([ephemeralPub, recipientPub]),
      V2_WRAP_INFO,
      KEY_LENGTH,
    ),
  );
}

/**
 * Pack secrets for one or more recipients (no shared passphrase).
 *
 * A fresh content-encryption key encrypts the payload; the CEK is then
 * wrapped once per recipient under a key agreed via X25519 with a
 * single-use ephemeral keypair. The CEK and every intermediate key are
 * zeroised before returning; the ephemeral private key is discarded.
 */
export function teleportPackFor(
  secrets: { key: string; value: string; scope?: string }[],
  recipients: string[],
): string {
  const seen = new Map<string, Buffer>();
  for (const r of recipients) {
    const raw = parseRecipient(r);
    seen.set(recipientId(raw), raw);
  }
  if (seen.size === 0) {
    throw new Error("ERR_TELEPORT_NO_RECIPIENTS: at least one recipient is required");
  }

  const payload: TeleportPayload = {
    secrets,
    exportedAt: new Date().toISOString(),
  };
  const plaintext = JSON.stringify(payload);

  const cek = randomBytes(KEY_LENGTH);
  const iv = randomBytes(IV_LENGTH);
  const cipher = createCipheriv(ALGORITHM, cek, iv);
  cipher.setAAD(Buffer.from(V2_AAD, "utf8"));
  const encrypted = Buffer.concat([
    cipher.update(plaintext, "utf8"),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();

  const ephemeral = generateKeyPairSync("x25519");
  const ephemeralPub = rawPublicKey(ephemeral.publicKey);

  const wrapped: TeleportRecipientEntry[] = [];
  for (const [id, recipientPub] of seen) {
    const shared = diffieHellman({
      privateKey: ephemeral.privateKey,
      publicKey: publicKeyFromRaw(recipientPub),
    });
    const wrapKey = deriveWrapKey(shared, ephemeralPub, recipientPub);
    shared.fill(0);

    const wrapIv = randomBytes(IV_LENGTH);
    const wrapCipher = createCipheriv(ALGORITHM, wrapKey, wrapIv);
    wrapCipher.setAAD(Buffer.from(id, "utf8"));
    const wrap = Buffer.concat([wrapCipher.update(cek), wrapCipher.final()]);
    const wrapTag = wrapCipher.getAuthTag();
    wrapKey.fill(0);

    wrapped.push({
      id,
      wrap: wrap.toString("base64"),
      iv: wrapIv.toString("base64"),
      tag: wrapTag.toString("base64"),
    });
  }
  cek.fill(0);

  const bundle: TeleportBundleV2 = {
    v: 2,
    createdAt: new Date().toISOString(),
    count: secrets.length,
    ephemeral: ephemeralPub.toString("base64url"),
    recipients: wrapped,
    iv: iv.toString("base64"),
    tag: tag.toString("base64"),
    data: encrypted.toString("base64"),
  };

  return Buffer.from(JSON.stringify(bundle)).toString("base64");
}

function toPrivateKey(identity: string | KeyObject): KeyObject {
  if (typeof identity !== "string") return identity;
  try {
    return createPrivateKey(identity);
  } catch {
    throw new Error("ERR_TELEPORT_BAD_IDENTITY: private key is not a valid PEM");
  }
}

/**
 * Unpack a v2 bundle with our X25519 private key (PEM string or KeyObject).
 *
 * Throws `ERR_TELEPORT_NOT_A_RECIPIENT` when no entry matches our recipient
 * id, and `ERR_TELEPORT_CORRUPT` when the bundle is malformed or any GCM
 * tag fails (tampered payload, tampered wrap, or a swapped ephemeral key).
 */
export function teleportUnpackWith(
  encoded: string,
  identity: string | KeyObject,
): TeleportPayload {
  const privateKey = toPrivateKey(identity);
  const rawBundle = decodeBundle(encoded);

  const parsedBundle = TeleportBundleV2Schema.safeParse(rawBundle);
  if (!parsedBundle.success) {
    throw new Error(
      `ERR_TELEPORT_CORRUPT: invalid bundle shape (${parsedBundle.error.message})`,
    );
  }
  const bundle = parsedBundle.data;

  const myPub = rawPublicKey(createPublicKey(privateKey));
  const myId = recipientId(myPub);
  const mine = bundle.recipients.filter((r) => r.id === myId);
  if (mine.length === 0) {
    const ids = bundle.recipients.map((r) => r.id).join(", ");
    throw new Error(
      `ERR_TELEPORT_NOT_A_RECIPIENT: bundle is addressed to [${ids}], not to ${myId}`,
    );
  }

  const ephemeralPub = Buffer.from(bundle.ephemeral, "base64url");
  if (ephemeralPub.length !== X25519_RAW_LENGTH) {
    throw new Error("ERR_TELEPORT_CORRUPT: ephemeral key is not 32 bytes");
  }

  let ephemeralKey: KeyObject;
  try {
    ephemeralKey = publicKeyFromRaw(ephemeralPub);
  } catch {
    throw new Error("ERR_TELEPORT_CORRUPT: ephemeral key is not a valid X25519 point");
  }
  const shared = diffieHellman({ privateKey, publicKey: ephemeralKey });
  const wrapKey = deriveWrapKey(shared, ephemeralPub, myPub);
  shared.fill(0);

  // 8 hex chars of id leave room for a (vanishingly unlikely) collision, so
  // try every entry that claims our id before giving up.
  let cek: Buffer | null = null;
  for (const entry of mine) {
    try {
      const decipher = createDecipheriv(
        ALGORITHM,
        wrapKey,
        Buffer.from(entry.iv, "base64"),
      );
      decipher.setAAD(Buffer.from(entry.id, "utf8"));
      decipher.setAuthTag(Buffer.from(entry.tag, "base64"));
      cek = Buffer.concat([
        decipher.update(Buffer.from(entry.wrap, "base64")),
        decipher.final(),
      ]);
      break;
    } catch {
      cek = null;
    }
  }
  wrapKey.fill(0);
  if (cek === null || cek.length !== KEY_LENGTH) {
    cek?.fill(0);
    throw new Error(
      "ERR_TELEPORT_CORRUPT: could not unwrap content key (tampered bundle or mismatched identity)",
    );
  }

  let decrypted: Buffer;
  try {
    const decipher = createDecipheriv(
      ALGORITHM,
      cek,
      Buffer.from(bundle.iv, "base64"),
    );
    decipher.setAAD(Buffer.from(V2_AAD, "utf8"));
    decipher.setAuthTag(Buffer.from(bundle.tag, "base64"));
    decrypted = Buffer.concat([
      decipher.update(Buffer.from(bundle.data, "base64")),
      decipher.final(),
    ]);
  } catch {
    throw new Error("ERR_TELEPORT_CORRUPT: payload authentication failed (tampered bundle)");
  } finally {
    cek.fill(0);
  }

  return parsePayload(decrypted);
}

export type TeleportBundleInfo =
  | { v: 1; count: number }
  | { v: 2; count: number; recipients: string[] };

/**
 * Cheap, non-decrypting look at a bundle: which format it is, how many
 * secrets it claims, and (v2) which recipient ids it is addressed to.
 */
export function inspectTeleportBundle(encoded: string): TeleportBundleInfo {
  const raw = decodeBundle(encoded);
  const v1 = TeleportBundleSchema.safeParse(raw);
  if (v1.success) return { v: 1, count: v1.data.count };
  const v2 = TeleportBundleV2Schema.safeParse(raw);
  if (v2.success) {
    return {
      v: 2,
      count: v2.data.count,
      recipients: v2.data.recipients.map((r) => r.id),
    };
  }
  const version =
    raw !== null && typeof raw === "object" && "v" in raw
      ? String((raw as { v: unknown }).v)
      : "unknown";
  throw new Error(
    `ERR_TELEPORT_CORRUPT: unsupported or malformed bundle (v=${version})`,
  );
}

/**
 * Unpack either format: v1 needs `passphrase`, v2 needs `identity`.
 */
export function teleportUnpackAuto(
  encoded: string,
  creds: { passphrase?: string; identity?: string | KeyObject },
): TeleportPayload {
  const info = inspectTeleportBundle(encoded);
  if (info.v === 1) {
    if (creds.passphrase === undefined) {
      throw new Error(
        "ERR_TELEPORT_PASSPHRASE_REQUIRED: this is a passphrase (v1) bundle",
      );
    }
    return teleportUnpack(encoded, creds.passphrase);
  }
  if (creds.identity === undefined) {
    throw new Error(
      "ERR_TELEPORT_NO_IDENTITY: this bundle is addressed to recipient keys — run `qring teleport keygen` to create yours",
    );
  }
  return teleportUnpackWith(encoded, creds.identity);
}

// ─── Identity storage (OS keyring only) ───

function identityFrom(privateKey: KeyObject): TeleportIdentity {
  const raw = rawPublicKey(createPublicKey(privateKey));
  return { privateKey, recipient: formatRecipient(raw), id: recipientId(raw) };
}

/**
 * Generate a fresh X25519 identity and store the private key (PKCS8 DER,
 * base64) in the keyring under `q-ring-teleport` / `identity`.
 * Refuses to overwrite an existing identity unless `force` is set.
 */
export function generateTeleportIdentity(
  options: { force?: boolean } = {},
): TeleportIdentity {
  const entry = new Entry(TELEPORT_KEYRING_SERVICE, TELEPORT_KEYRING_ACCOUNT);
  if (!options.force && entry.getPassword()) {
    throw new Error(
      "ERR_TELEPORT_IDENTITY_EXISTS: a teleport identity already exists — pass --force to replace it (bundles sent to the old key become unreadable)",
    );
  }
  const { privateKey } = generateKeyPairSync("x25519");
  const der = privateKey.export({ format: "der", type: "pkcs8" });
  entry.setPassword(der.toString("base64"));
  der.fill(0);
  return identityFrom(privateKey);
}

/** Load our identity from the keyring, or null if none was generated yet. */
export function loadTeleportIdentity(): TeleportIdentity | null {
  const stored = new Entry(
    TELEPORT_KEYRING_SERVICE,
    TELEPORT_KEYRING_ACCOUNT,
  ).getPassword();
  if (!stored) return null;
  let privateKey: KeyObject;
  try {
    privateKey = createPrivateKey({
      key: Buffer.from(stored, "base64"),
      format: "der",
      type: "pkcs8",
    });
  } catch {
    throw new Error(
      "ERR_TELEPORT_BAD_IDENTITY: stored teleport identity is unreadable — run `qring teleport keygen --force`",
    );
  }
  return identityFrom(privateKey);
}

/** Load our identity or throw the keygen hint. */
export function requireTeleportIdentity(): TeleportIdentity {
  const identity = loadTeleportIdentity();
  if (!identity) {
    throw new Error(
      "ERR_TELEPORT_NO_IDENTITY: no teleport identity found — run `qring teleport keygen` first",
    );
  }
  return identity;
}
