import { describe, it, expect, beforeEach, vi } from "vitest";

vi.mock("@napi-rs/keyring", async () => {
  const fake = await import("../helpers/fake-keyring.js");
  return { Entry: fake.FakeEntry, findCredentials: fake.findCredentials };
});

import { setSecret, getEnvelope, isValidRotateEveryDays } from "../../core/keyring.js";
import { resetFakeKeyring } from "../helpers/fake-keyring.js";

const KEY = "ROTATION_TEST_KEY";
const meta = () => getEnvelope(KEY, { scope: "global" })!.envelope.meta;
const tick = () => new Promise((r) => setTimeout(r, 5));

describe("setSecret — rotatedAt / rotateEveryDays", () => {
  beforeEach(() => {
    resetFakeKeyring();
  });

  it("stamps rotatedAt on first write and persists rotateEveryDays", () => {
    setSecret(KEY, "v1", { scope: "global", rotateEveryDays: 90 });
    const m = meta();
    expect(m.rotatedAt).toBeTruthy();
    expect(Number.isFinite(Date.parse(m.rotatedAt!))).toBe(true);
    expect(m.rotateEveryDays).toBe(90);
  });

  it("does not reset rotatedAt on a metadata-only re-set of the same value", async () => {
    setSecret(KEY, "v1", { scope: "global", rotateEveryDays: 90 });
    const first = meta().rotatedAt;
    await tick();
    setSecret(KEY, "v1", { scope: "global", description: "same value, new desc" });
    const m = meta();
    expect(m.rotatedAt).toBe(first);
    expect(m.description).toBe("same value, new desc");
    // interval survives a re-set that does not mention it
    expect(m.rotateEveryDays).toBe(90);
  });

  it("resets rotatedAt when the value changes (what `qring rotate` does)", async () => {
    setSecret(KEY, "v1", { scope: "global", rotateEveryDays: 30 });
    const first = meta().rotatedAt!;
    await tick();
    setSecret(KEY, "v2", { scope: "global" });
    const m = meta();
    expect(Date.parse(m.rotatedAt!)).toBeGreaterThan(Date.parse(first));
    expect(m.rotateEveryDays).toBe(30);
  });

  it("treats a superposition state change as a rotation, an identical states map as not", async () => {
    setSecret(KEY, "", { scope: "global", states: { dev: "a", prod: "b" }, rotateEveryDays: 60 });
    const first = meta().rotatedAt!;
    await tick();
    setSecret(KEY, "", { scope: "global", states: { dev: "a", prod: "b" } });
    expect(meta().rotatedAt).toBe(first);
    await tick();
    setSecret(KEY, "", { scope: "global", states: { dev: "a", prod: "c" } });
    expect(Date.parse(meta().rotatedAt!)).toBeGreaterThan(Date.parse(first));
  });

  it("lets a later write change the interval", () => {
    setSecret(KEY, "v1", { scope: "global", rotateEveryDays: 90 });
    setSecret(KEY, "v1", { scope: "global", rotateEveryDays: 7 });
    expect(meta().rotateEveryDays).toBe(7);
  });

  it("rejects an out-of-range or fractional interval", () => {
    for (const bad of [0, -1, 3651, 1.5, Number.NaN]) {
      expect(() => setSecret(KEY, "v1", { scope: "global", rotateEveryDays: bad })).toThrow(
        /rotateEveryDays/,
      );
    }
    expect(isValidRotateEveryDays(1)).toBe(true);
    expect(isValidRotateEveryDays(3650)).toBe(true);
    expect(isValidRotateEveryDays(3651)).toBe(false);
  });
});
