/**
 * @napi-rs/keyring 2.x throws for a locked / unreachable credential store
 * (1.x returned null / false). The backend wraps those into a
 * BackendUnavailableError that tells the user what to do.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

const boom = () => {
  throw new Error("Platform secure storage failure: the collection is locked");
};

vi.mock("@napi-rs/keyring", () => ({
  Entry: class {
    getPassword() { boom(); }
    setPassword() {}
    deleteCredential() { boom(); }
    deletePassword() { boom(); }
  },
  findCredentials: () => [],
}));

import { BackendUnavailableError, Entry } from "../../core/backend.js";

describe("backend: native keyring failures", () => {
  beforeEach(() => {
    delete process.env.QRING_BACKEND;
  });

  it("read failure becomes a BackendUnavailableError with guidance", () => {
    const entry = new Entry("svc", "KEY");
    expect(() => entry.getPassword()).toThrow(BackendUnavailableError);
    expect(() => entry.getPassword()).toThrow(/keyring read failed.*locked or unreachable.*QRING_BACKEND=file/s);
  });

  it("delete failure becomes a BackendUnavailableError", () => {
    const entry = new Entry("svc", "KEY");
    expect(() => entry.deleteCredential()).toThrow(/keyring delete failed/);
    expect(() => entry.deletePassword()).toThrow(BackendUnavailableError);
  });
});
