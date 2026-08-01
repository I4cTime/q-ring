/**
 * Agent Memory — Persistent State Across Sessions
 *
 * Stores key-value pairs in an encrypted JSON file so the AI agent
 * can remember decisions, rotations performed, and project-specific
 * context between conversations.
 *
 * Data is encrypted with AES-256-GCM. The key is a random 32-byte key stored in
 * the OS keyring. Where no keyring is available (headless Linux, most
 * containers/CI), a key is derived from QRING_MEMORY_PASSPHRASE (PBKDF2); if
 * neither is present, writes fail closed rather than fall back to a
 * machine-derivable key that any local process could recompute (A4). The old
 * hostname+username-derived key is retained for *reading* pre-existing stores.
 */

import { existsSync, readFileSync, writeFileSync, mkdirSync, chmodSync } from "node:fs";
import { join } from "node:path";
import { homedir, hostname, userInfo } from "node:os";
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
  pbkdf2Sync,
} from "node:crypto";
import { Entry } from "@napi-rs/keyring";

const MEMORY_FILE = "agent-memory.enc";
const KEYRING_SERVICE = "qring-memory-key";
const KEYRING_ACCOUNT = "encryption-key";

function getMemoryDir(): string {
  const dir = join(homedir(), ".config", "q-ring");
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
  }
  return dir;
}

/**
 * Persist the encrypted memory blob with owner-only permissions. `mode` on
 * writeFileSync only applies when creating the file, so chmod additionally fixes
 * a store written world-readable by an older version. Best-effort chmod.
 */
function writeMemoryFile(path: string, data: string): void {
  writeFileSync(path, data, { mode: 0o600 });
  try {
    chmodSync(path, 0o600);
  } catch {
    /* ignore */
  }
}

function getMemoryPath(): string {
  return join(getMemoryDir(), MEMORY_FILE);
}

const PBKDF2_ITERATIONS = 210_000; // OWASP 2023 floor, matches teleport.ts
const KEY_LENGTH = 32;
const PASSPHRASE_ENV = "QRING_MEMORY_PASSPHRASE";
const V2_PREFIX = "qmem2"; // passphrase-encrypted blob: qmem2:<salt>:<iv:tag:ct>

/** Thrown when no secure key is available to encrypt (or decrypt) memory. */
export class MemoryKeyUnavailableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "MemoryKeyUnavailableError";
  }
}

/**
 * The pre-A4 fallback key: SHA-256 of hostname+username. NOT secret — any local
 * process can recompute it. Retained ONLY to read stores written by older
 * versions; never used to encrypt new data.
 */
function deriveLegacyKey(): Buffer {
  const fingerprint = `qring-memory:${hostname()}:${userInfo().username}`;
  return createHash("sha256").update(fingerprint).digest();
}

function passphrase(): string | undefined {
  const p = process.env[PASSPHRASE_ENV];
  return p && p.length > 0 ? p : undefined;
}

function derivePassphraseKey(salt: Buffer): Buffer {
  return pbkdf2Sync(passphrase()!, salt, PBKDF2_ITERATIONS, KEY_LENGTH, "sha512");
}

/**
 * The random key from the OS keyring (created on first use), or null if no
 * keyring backend is available on this host.
 */
function keyringKey(): Buffer | null {
  try {
    const entry = new Entry(KEYRING_SERVICE, KEYRING_ACCOUNT);
    const stored = entry.getPassword();
    if (stored) return Buffer.from(stored, "base64");
    const key = randomBytes(KEY_LENGTH);
    entry.setPassword(key.toString("base64"));
    return key;
  } catch {
    return null;
  }
}

function encryptWith(data: string, key: Buffer): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([cipher.update(data, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `${iv.toString("base64")}:${tag.toString("base64")}:${encrypted.toString("base64")}`;
}

function decryptWith(blob: string, key: Buffer): string {
  const parts = blob.split(":");
  if (parts.length !== 3) throw new Error("Invalid encrypted format");
  const iv = Buffer.from(parts[0], "base64");
  const tag = Buffer.from(parts[1], "base64");
  const encrypted = Buffer.from(parts[2], "base64");

  const decipher = createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  return decipher.update(encrypted) + decipher.final("utf8");
}

function encrypt(data: string): string {
  const kk = keyringKey();
  if (kk) return encryptWith(data, kk);

  if (passphrase()) {
    const salt = randomBytes(16);
    const key = derivePassphraseKey(salt);
    return `${V2_PREFIX}:${salt.toString("base64")}:${encryptWith(data, key)}`;
  }

  throw new MemoryKeyUnavailableError(
    `Cannot persist agent memory: the OS keyring is unavailable and ${PASSPHRASE_ENV} ` +
      `is not set. Refusing to encrypt with a machine-derivable key (any local process ` +
      `could recompute it and read your memory). Set ${PASSPHRASE_ENV} to a strong ` +
      `passphrase, or run on a host with an OS keyring.`,
  );
}

function decrypt(blob: string): string {
  // Passphrase-encrypted (v2): salt is embedded; needs QRING_MEMORY_PASSPHRASE.
  if (blob.startsWith(`${V2_PREFIX}:`)) {
    if (!passphrase()) {
      throw new MemoryKeyUnavailableError(
        `Agent memory was encrypted with ${PASSPHRASE_ENV} but it is not set — cannot decrypt.`,
      );
    }
    const rest = blob.slice(V2_PREFIX.length + 1);
    const sep = rest.indexOf(":");
    const salt = Buffer.from(rest.slice(0, sep), "base64");
    return decryptWith(rest.slice(sep + 1), derivePassphraseKey(salt));
  }

  // Legacy 3-part format: try the keyring key first, then the machine-derived
  // key for read-only migration of pre-A4 stores.
  const kk = keyringKey();
  if (kk) {
    try {
      return decryptWith(blob, kk);
    } catch {
      /* fall through to legacy machine key */
    }
  }

  const plain = decryptWith(blob, deriveLegacyKey());
  // Re-encrypt under the keyring key if one is now available — but never persist
  // under the derivable legacy key. Without a secure key, read but don't rewrite.
  if (kk) {
    try {
      writeMemoryFile(getMemoryPath(), encryptWith(plain, kk));
    } catch {
      /* best-effort migration */
    }
  }
  return plain;
}

interface MemoryStore {
  entries: Record<string, { value: string; updatedAt: string }>;
}

function loadStore(): MemoryStore {
  const path = getMemoryPath();
  if (!existsSync(path)) {
    return { entries: {} };
  }
  try {
    const raw = readFileSync(path, "utf8");
    const decrypted = decrypt(raw);
    return JSON.parse(decrypted);
  } catch (err) {
    // A store that exists but can't be decrypted because the key is unavailable
    // is surfaced loudly (so "empty memory" isn't mistaken for "no memory"),
    // but reads still degrade to empty rather than crashing the caller.
    if (err instanceof MemoryKeyUnavailableError) {
      console.error(`q-ring: ${err.message}`);
    }
    return { entries: {} };
  }
}

function saveStore(store: MemoryStore): void {
  const json = JSON.stringify(store);
  const encrypted = encrypt(json);
  writeMemoryFile(getMemoryPath(), encrypted);
}

/**
 * Store a value in agent memory.
 */
export function remember(key: string, value: string): void {
  const store = loadStore();
  store.entries[key] = {
    value,
    updatedAt: new Date().toISOString(),
  };
  saveStore(store);
}

/**
 * Retrieve a value from agent memory.
 */
export function recall(key: string): string | null {
  const store = loadStore();
  return store.entries[key]?.value ?? null;
}

/**
 * List all keys in agent memory.
 */
export function listMemory(): Array<{ key: string; updatedAt: string }> {
  const store = loadStore();
  return Object.entries(store.entries).map(([key, entry]) => ({
    key,
    updatedAt: entry.updatedAt,
  }));
}

/**
 * Delete a key from agent memory.
 */
export function forget(key: string): boolean {
  const store = loadStore();
  if (key in store.entries) {
    delete store.entries[key];
    saveStore(store);
    return true;
  }
  return false;
}

/**
 * Clear all agent memory.
 */
export function clearMemory(): void {
  saveStore({ entries: {} });
}
