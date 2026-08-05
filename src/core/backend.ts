/**
 * Keyring Backend Selection
 *
 * Every module that used to talk to `@napi-rs/keyring` directly goes through
 * this shim instead. Two backends:
 *
 * - `keyring` (default): the OS keychain via @napi-rs/keyring — unchanged
 *   behavior.
 * - `file` (opt-in, `QRING_BACKEND=file`): an AES-256-GCM-encrypted JSON
 *   store for hosts with no Secret Service at all (headless Linux, CI,
 *   containers). The key is derived from `QRING_FILE_PASSPHRASE` via PBKDF2;
 *   with no passphrase set, every operation fails closed — consistent with
 *   the v0.14 rule that q-ring never encrypts under a machine-derivable key.
 *
 * The file backend is deliberately explicit-only: a missing OS keyring does
 * NOT silently fall back to it, because silent fallback would change the
 * at-rest security story without the user choosing it.
 */

import { Entry as NapiEntry, findCredentials as napiFindCredentials } from "@napi-rs/keyring";
import { existsSync, readFileSync, writeFileSync, mkdirSync, chmodSync } from "node:fs";
import { dirname, join } from "node:path";
import { homedir } from "node:os";
import { createCipheriv, createDecipheriv, randomBytes, pbkdf2Sync } from "node:crypto";
import { withFileLock } from "../utils/file-lock.js";

const PASSPHRASE_ENV = "QRING_FILE_PASSPHRASE";
const BACKEND_ENV = "QRING_BACKEND";
const PATH_ENV = "QRING_FILE_BACKEND_PATH";

const PBKDF2_ITERATIONS = 210_000; // OWASP 2023 floor, matches memory.ts/teleport.ts
const KEY_LENGTH = 32;
const FILE_PREFIX = "qfile1"; // qfile1:<saltB64>:<iv>:<tag>:<ciphertext>

export class BackendUnavailableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "BackendUnavailableError";
  }
}

export type BackendName = "keyring" | "file";

export function activeBackend(): BackendName {
  const requested = process.env[BACKEND_ENV];
  if (requested === "file") return "file";
  if (requested && requested !== "keyring") {
    throw new BackendUnavailableError(
      `Unknown ${BACKEND_ENV} "${requested}" — expected "keyring" or "file".`,
    );
  }
  return "keyring";
}

// ─── File backend ───

function storePath(): string {
  return (
    process.env[PATH_ENV] ??
    join(homedir(), ".config", "q-ring", "file-backend.enc")
  );
}

function passphrase(): string {
  const p = process.env[PASSPHRASE_ENV];
  if (!p) {
    throw new BackendUnavailableError(
      `${BACKEND_ENV}=file requires ${PASSPHRASE_ENV} to be set. q-ring refuses to ` +
        `store secrets under a machine-derivable key — set a strong passphrase, or ` +
        `use the OS keyring backend.`,
    );
  }
  return p;
}

// PBKDF2 at 210k iterations costs real time; the salt is stable per store
// file, so cache the derived key for the (salt, passphrase) pair in-process.
let keyCache: { salt: string; pass: string; key: Buffer } | null = null;

function deriveKey(saltB64: string): Buffer {
  const pass = passphrase();
  if (keyCache && keyCache.salt === saltB64 && keyCache.pass === pass) {
    return keyCache.key;
  }
  const key = pbkdf2Sync(pass, Buffer.from(saltB64, "base64"), PBKDF2_ITERATIONS, KEY_LENGTH, "sha512");
  keyCache = { salt: saltB64, pass, key };
  return key;
}

type StoreMap = Record<string, string>;

function loadStore(): { map: StoreMap; salt: string } {
  const path = storePath();
  if (!existsSync(path)) {
    return { map: {}, salt: randomBytes(16).toString("base64") };
  }

  const blob = readFileSync(path, "utf8").trim();
  const parts = blob.split(":");
  if (parts.length !== 5 || parts[0] !== FILE_PREFIX) {
    throw new BackendUnavailableError(
      `${path} is not a valid q-ring file-backend store (expected ${FILE_PREFIX}:...).`,
    );
  }
  const [, salt, ivB64, tagB64, ctB64] = parts;

  const decipher = createDecipheriv("aes-256-gcm", deriveKey(salt), Buffer.from(ivB64, "base64"));
  decipher.setAuthTag(Buffer.from(tagB64, "base64"));
  let plaintext: string;
  try {
    plaintext = decipher.update(Buffer.from(ctB64, "base64")) + decipher.final("utf8");
  } catch {
    throw new BackendUnavailableError(
      `Cannot decrypt ${path} — wrong ${PASSPHRASE_ENV}, or the store was tampered with.`,
    );
  }
  return { map: JSON.parse(plaintext) as StoreMap, salt };
}

function saveStore(map: StoreMap, salt: string): void {
  const path = storePath();
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });

  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", deriveKey(salt), iv);
  const ct = Buffer.concat([cipher.update(JSON.stringify(map), "utf8"), cipher.final()]);
  const blob = [
    FILE_PREFIX,
    salt,
    iv.toString("base64"),
    cipher.getAuthTag().toString("base64"),
    ct.toString("base64"),
  ].join(":");

  writeFileSync(path, blob + "\n", { mode: 0o600 });
  try {
    chmodSync(path, 0o600);
  } catch {
    /* best-effort */
  }
}

const SEP = "\0";

function fileMutate<T>(fn: (map: StoreMap) => T): T {
  return withFileLock("file-backend", () => {
    const { map, salt } = loadStore();
    const result = fn(map);
    saveStore(map, salt);
    return result;
  });
}

// ─── Uniform interface ───

/**
 * Drop-in for @napi-rs/keyring's Entry, routed to the active backend.
 * Backend choice is evaluated per call, not at import time, so tests and
 * long-lived processes see env changes.
 */
export class Entry {
  private napi?: NapiEntry;

  constructor(
    private readonly service: string,
    private readonly account: string,
  ) {}

  private delegate(): NapiEntry {
    this.napi ??= new NapiEntry(this.service, this.account);
    return this.napi;
  }

  private storeKey(): string {
    return `${this.service}${SEP}${this.account}`;
  }

  getPassword(): string | null {
    if (activeBackend() === "file") {
      return loadStore().map[this.storeKey()] ?? null;
    }
    return this.delegate().getPassword();
  }

  setPassword(password: string): void {
    if (activeBackend() === "file") {
      fileMutate((map) => {
        map[this.storeKey()] = password;
      });
      return;
    }
    this.delegate().setPassword(password);
  }

  deleteCredential(): boolean {
    if (activeBackend() === "file") {
      return fileMutate((map) => {
        const existed = this.storeKey() in map;
        delete map[this.storeKey()];
        return existed;
      });
    }
    return this.delegate().deleteCredential();
  }

  // @napi-rs/keyring's other delete alias, used by `qring doctor`.
  deletePassword(): boolean {
    return this.deleteCredential();
  }
}

export function findCredentials(service: string): { account: string; password: string }[] {
  if (activeBackend() === "file") {
    const { map } = loadStore();
    const prefix = `${service}${SEP}`;
    return Object.entries(map)
      .filter(([k]) => k.startsWith(prefix))
      .map(([k, password]) => ({ account: k.slice(prefix.length), password }));
  }
  return napiFindCredentials(service);
}
