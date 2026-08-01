/**
 * In-memory stand-in for `@napi-rs/keyring`, keyed by `service\0account`.
 *
 * Lets tests exercise the real `keyring.ts` / `memory.ts` logic (envelopes,
 * decay, approval gate, entanglement, JIT) with only the OS keychain syscall
 * replaced — so the suite is deterministic and portable across ubuntu/macOS/
 * Windows CI runners, none of which reliably have a Secret Service backend.
 *
 * Usage (top of a test file — `vi.mock` is hoisted, so the factory pulls the
 * fake in via dynamic import rather than an out-of-scope reference):
 *
 *   vi.mock("@napi-rs/keyring", async () => {
 *     const fake = await import("../helpers/fake-keyring.js");
 *     return { Entry: fake.FakeEntry, findCredentials: fake.findCredentials };
 *   });
 *   import { resetFakeKeyring } from "../helpers/fake-keyring.js";
 *   beforeEach(() => resetFakeKeyring());
 */

const SEP = "\0";
const store = new Map<string, string>();

/** When set, every keyring operation throws — simulates "no OS keyring available". */
let unavailable: Error | null = null;

function guard(): void {
  if (unavailable) throw unavailable;
}

export class FakeEntry {
  constructor(
    private readonly service: string,
    private readonly account: string,
  ) {}

  private key(): string {
    return `${this.service}${SEP}${this.account}`;
  }

  getPassword(): string | null {
    guard();
    return store.get(this.key()) ?? null;
  }

  setPassword(password: string): void {
    guard();
    store.set(this.key(), password);
  }

  deleteCredential(): boolean {
    guard();
    return store.delete(this.key());
  }

  // @napi-rs/keyring's other delete alias, used by `qring doctor`.
  deletePassword(): boolean {
    return this.deleteCredential();
  }
}

export function findCredentials(
  service: string,
): { account: string; password: string }[] {
  guard();
  const prefix = `${service}${SEP}`;
  const out: { account: string; password: string }[] = [];
  for (const [k, password] of store) {
    if (k.startsWith(prefix)) {
      out.push({ account: k.slice(prefix.length), password });
    }
  }
  return out;
}

/** Clear all fake credentials. Call in `beforeEach`. */
export function resetFakeKeyring(): void {
  store.clear();
  unavailable = null;
}

/**
 * Make every subsequent keyring operation throw, simulating a host with no
 * Secret Service (headless Linux, most containers/CI). Pass null to restore.
 */
export function setKeyringUnavailable(err: Error | null): void {
  unavailable = err;
}

/** Direct read of the backing store, for assertions that bypass the code path. */
export function fakeKeyringDump(): Map<string, string> {
  return new Map(store);
}
