/**
 * Agent Memory — Persistent State Across Sessions
 *
 * Stores key-value pairs in an encrypted JSON file so the AI agent
 * can remember decisions, rotations performed, and project-specific
 * context between conversations.
 *
 * Data is encrypted using AES-256-GCM derived from a machine-specific
 * fingerprint (hostname + username), so it only decrypts on the same machine.
 */

import { existsSync, readFileSync, writeFileSync, mkdirSync, chmodSync } from "node:fs";
import { join } from "node:path";
import { homedir, hostname, userInfo } from "node:os";
import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";
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

function deriveLegacyKey(): Buffer {
  const fingerprint = `qring-memory:${hostname()}:${userInfo().username}`;
  return createHash("sha256").update(fingerprint).digest();
}

function getOrCreateKey(): Buffer {
  try {
    const entry = new Entry(KEYRING_SERVICE, KEYRING_ACCOUNT);
    const stored = entry.getPassword();
    if (stored) return Buffer.from(stored, "base64");

    const key = randomBytes(32);
    entry.setPassword(key.toString("base64"));
    return key;
  } catch {
    console.warn("[q-ring] OS keyring unavailable for memory key — falling back to machine-derived key");
    return deriveLegacyKey();
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
  return encryptWith(data, getOrCreateKey());
}

function decrypt(blob: string): string {
  const key = getOrCreateKey();
  try {
    return decryptWith(blob, key);
  } catch {
    // Migration: try legacy key, re-encrypt with new key if successful
    const legacy = deriveLegacyKey();
    const plain = decryptWith(blob, legacy);
    writeMemoryFile(getMemoryPath(), encryptWith(plain, key));
    return plain;
  }
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
  } catch {
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
