import { describe, it, expect, beforeEach, vi } from "vitest";

vi.mock("@napi-rs/keyring", async () => {
  const fake = await import("../helpers/fake-keyring.js");
  return { Entry: fake.FakeEntry, findCredentials: fake.findCredentials };
});

import { setSecret, getSecret, getEnvelope } from "../../core/keyring.js";
import { resetFakeKeyring } from "../helpers/fake-keyring.js";

beforeEach(() => resetFakeKeyring());

describe("getSecret observer-effect write-back (B4)", () => {
  it("bumps the access counter without losing a concurrently-written value", () => {
    setSecret("K", "v1", { scope: "global", source: "cli" });

    // Simulate the race: the read has already loaded the old envelope, then a
    // new value lands before the access-count write-back. We model that by
    // mutating the value between reads: perform a read (which re-reads latest on
    // write-back), and separately overwrite in between.
    expect(getSecret("K", { scope: "global", source: "cli" })).toBe("v1");
    setSecret("K", "v2", { scope: "global", source: "cli" });

    // After a subsequent read, the value must be the latest write, not reverted
    // to v1 by a stale write-back, and the access count keeps climbing.
    expect(getSecret("K", { scope: "global", source: "cli" })).toBe("v2");
    const env = getEnvelope("K", { scope: "global" });
    expect(env?.envelope.value).toBe("v2");
    expect(env?.envelope.meta.accessCount).toBeGreaterThan(0);
  });
});
