import { describe, it, expect } from "vitest";
import {
  createEnvelope,
  parseEnvelope,
  serializeEnvelope,
  collapseValue,
  checkDecay,
  recordAccess,
  wrapLegacy,
} from "../../core/envelope.js";

describe("createEnvelope", () => {
  it("creates an envelope with a single value", () => {
    const env = createEnvelope("my-secret");
    expect(env.v).toBe(1);
    expect(env.value).toBe("my-secret");
    expect(env.meta.createdAt).toBeTruthy();
    expect(env.meta.accessCount).toBe(0);
  });

  it("stores optional metadata", () => {
    const env = createEnvelope("s", {
      description: "test",
      tags: ["a", "b"],
      ttlSeconds: 60,
    });
    expect(env.meta.description).toBe("test");
    expect(env.meta.tags).toEqual(["a", "b"]);
    expect(env.meta.ttlSeconds).toBe(60);
  });

  it("stores superposition states", () => {
    const env = createEnvelope("default-val", {
      states: { dev: "dev-val", prod: "prod-val" },
    });
    expect(env.states?.dev).toBe("dev-val");
    expect(env.states?.prod).toBe("prod-val");
  });
});

describe("parseEnvelope / serializeEnvelope", () => {
  it("round-trips an envelope through serialize and parse", () => {
    const original = createEnvelope("test", { tags: ["x"] });
    const json = serializeEnvelope(original);
    const parsed = parseEnvelope(json);
    expect(parsed).not.toBeNull();
    expect(parsed!.value).toBe("test");
    expect(parsed!.meta.tags).toEqual(["x"]);
  });

  it("returns null for invalid JSON", () => {
    expect(parseEnvelope("not-json")).toBeNull();
  });

  it("returns null for JSON missing v field", () => {
    expect(parseEnvelope('{"value":"x"}')).toBeNull();
  });
});

describe("wrapLegacy", () => {
  it("wraps a raw string into a v1 envelope", () => {
    const env = wrapLegacy("raw-value");
    expect(env.v).toBe(1);
    expect(env.value).toBe("raw-value");
  });
});

describe("collapseValue", () => {
  it("returns the single value when no states exist", () => {
    const env = createEnvelope("only");
    expect(collapseValue(env)).toBe("only");
  });

  it("collapses to the requested environment", () => {
    const env = createEnvelope("default", {
      states: { dev: "dev-secret", prod: "prod-secret" },
    });
    expect(collapseValue(env, "dev")).toBe("dev-secret");
    expect(collapseValue(env, "prod")).toBe("prod-secret");
  });

  it("falls back to first state for unknown env when no defaultEnv", () => {
    const env = createEnvelope("fallback", { states: { dev: "d" } });
    expect(collapseValue(env, "staging")).toBe("d");
  });

  it("falls back to defaultEnv state for unknown env", () => {
    const env = createEnvelope("fallback", {
      states: { dev: "d", prod: "p" },
      defaultEnv: "prod",
    });
    expect(collapseValue(env, "staging")).toBe("p");
  });
});

describe("checkDecay", () => {
  it("reports healthy for a fresh envelope with no TTL", () => {
    const env = createEnvelope("healthy");
    const decay = checkDecay(env);
    expect(decay.isExpired).toBe(false);
    expect(decay.isStale).toBe(false);
  });

  it("reports expired when expiresAt computed from TTL has elapsed", () => {
    const env = createEnvelope("old", { ttlSeconds: 1 });
    env.meta.expiresAt = new Date(Date.now() - 5000).toISOString();
    const decay = checkDecay(env);
    expect(decay.isExpired).toBe(true);
  });

  it("reports expired when expiresAt is in the past", () => {
    const env = createEnvelope("old");
    env.meta.expiresAt = new Date(Date.now() - 1000).toISOString();
    const decay = checkDecay(env);
    expect(decay.isExpired).toBe(true);
  });
});

describe("recordAccess", () => {
  it("increments accessCount and sets lastAccessedAt", () => {
    const env = createEnvelope("val");
    expect(env.meta.accessCount).toBe(0);
    const updated = recordAccess(env);
    expect(updated.meta.accessCount).toBe(1);
    expect(updated.meta.lastAccessedAt).toBeTruthy();
  });

  it("returns a new object (immutable)", () => {
    const env = createEnvelope("val");
    const updated = recordAccess(env);
    expect(updated).not.toBe(env);
    expect(env.meta.accessCount).toBe(0);
  });
});

describe("serializeEnvelope safe form", () => {
  // A backslash or any character below U+0020.
  // eslint-disable-next-line no-control-regex
  const UNSAFE = /[\\\u0000-\u001f]/;
  const decodeInner = (stored: string) =>
    Buffer.from(JSON.parse(stored).data, "base64").toString("utf8");

  it("stores a value with a newline, a double quote and a backslash without escapes", () => {
    const value = 'line one\nsaid "hi"\\path';
    const env = createEnvelope(value);
    const stored = serializeEnvelope(env, { safe: true });
    expect(UNSAFE.test(stored)).toBe(false);
    expect(JSON.parse(stored)).toMatchObject({ v: 1, enc: "b64" });
    expect(decodeInner(stored)).toBe(JSON.stringify(env));
    expect(collapseValue(parseEnvelope(stored)!)).toBe(value);
  });

  it("uses the safe form when only the metadata needs an escape", () => {
    const env = createEnvelope("plain-value", { description: 'the "prod" key' });
    const stored = serializeEnvelope(env, { safe: true });
    expect(UNSAFE.test(stored)).toBe(false);
    const parsed = parseEnvelope(stored)!;
    expect(parsed.value).toBe("plain-value");
    expect(parsed.meta.description).toBe('the "prod" key');
  });

  it("round trips a states map whose values carry escapes", () => {
    const states = { dev: 'a"b', prod: "c\\d\ne" };
    const env = createEnvelope("", { states, defaultEnv: "dev" });
    const stored = serializeEnvelope(env, { safe: true });
    expect(UNSAFE.test(stored)).toBe(false);
    const parsed = parseEnvelope(stored)!;
    expect(parsed.states).toEqual(states);
    expect(collapseValue(parsed, "prod")).toBe("c\\d\ne");
  });

  it("round trips a control character", () => {
    const value = "bell\u0007tab\tnul\u0000end\u0003";
    const stored = serializeEnvelope(createEnvelope(value), { safe: true });
    expect(UNSAFE.test(stored)).toBe(false);
    expect(collapseValue(parseEnvelope(stored)!)).toBe(value);
  });

  it("keeps an envelope that needs no escape as plain JSON, byte for byte", () => {
    const env = createEnvelope("sk-plain-123", { description: "no escapes", tags: ["a"] });
    expect(serializeEnvelope(env, { safe: true })).toBe(JSON.stringify(env));
  });

  it("keeps plain JSON with safe: false even when it carries escapes", () => {
    const env = createEnvelope('multi\nline "quoted"');
    const stored = serializeEnvelope(env, { safe: false });
    expect(stored).toBe(JSON.stringify(env));
    expect(collapseValue(parseEnvelope(stored)!)).toBe('multi\nline "quoted"');
  });

  it("defaults safe to Linux only", () => {
    const env = createEnvelope("a\nb");
    const stored = serializeEnvelope(env);
    expect(stored === JSON.stringify(env)).toBe(process.platform !== "linux");
  });

  it("does not treat a wrapper with garbage inner data as an envelope", () => {
    expect(parseEnvelope('{"v":1,"enc":"b64","data":"!!!not base64!!!"}')).toBeNull();
    const notEnvelope = Buffer.from('{"value":"x"}', "utf8").toString("base64");
    expect(parseEnvelope(`{"v":1,"enc":"b64","data":"${notEnvelope}"}`)).toBeNull();
  });
});
