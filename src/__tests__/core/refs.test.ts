import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("@napi-rs/keyring", async () => {
  const fake = await import("../helpers/fake-keyring.js");
  return { Entry: fake.FakeEntry, findCredentials: fake.findCredentials };
});

import { resetFakeKeyring } from "../helpers/fake-keyring.js";
import { setSecret } from "../../core/keyring.js";
import {
  isRef,
  parseRef,
  resolveRef,
  resolveRefsInMap,
} from "../../core/refs.js";

const PROJECT = "/tmp/qring-refs-test-project";

beforeEach(() => resetFakeKeyring());

describe("parseRef", () => {
  it("parses project-scoped refs", () => {
    const ref = parseRef("qring://project/DATABASE_URL");
    expect(ref.scope).toBe("project");
    expect(ref.key).toBe("DATABASE_URL");
    expect(ref.env).toBeUndefined();
  });

  it("parses global-scoped refs", () => {
    const ref = parseRef("qring://global/OPENAI_API_KEY");
    expect(ref.scope).toBe("global");
    expect(ref.key).toBe("OPENAI_API_KEY");
  });

  it("parses auto-scope refs (empty host)", () => {
    const ref = parseRef("qring:///STRIPE_KEY");
    expect(ref.scope).toBeUndefined();
    expect(ref.key).toBe("STRIPE_KEY");
  });

  it("parses an env pin", () => {
    const ref = parseRef("qring://project/DATABASE_URL?env=prod");
    expect(ref.env).toBe("prod");
  });

  it("preserves key case exactly (key lives in the path)", () => {
    const ref = parseRef("qring://project/MixedCase_Key1");
    expect(ref.key).toBe("MixedCase_Key1");
  });

  it("rejects the key-in-host footgun with a corrective message", () => {
    expect(() => parseRef("qring://DATABASE_URL")).toThrow(/key belongs in the path/);
    expect(() => parseRef("qring://DATABASE_URL")).toThrow(/qring:\/\/\/DATABASE_URL/);
  });

  it("rejects unknown scopes", () => {
    expect(() => parseRef("qring://team/KEY")).toThrow(/key belongs in the path|expected qring/);
  });

  it("rejects invalid key characters", () => {
    expect(() => parseRef("qring://project/1BAD")).toThrow(/not a valid secret key/);
    expect(() => parseRef("qring://project/BAD-KEY")).toThrow(/not a valid secret key/);
  });

  it("rejects unknown query parameters", () => {
    expect(() => parseRef("qring://project/KEY?scope=global")).toThrow(/unknown query parameter/);
  });

  it("rejects non-refs", () => {
    expect(() => parseRef("plain-value")).toThrow(/Not a qring/);
  });
});

describe("isRef", () => {
  it("detects refs and non-refs", () => {
    expect(isRef("qring://project/KEY")).toBe(true);
    expect(isRef("postgres://user:pass@host/db")).toBe(false);
    expect(isRef("")).toBe(false);
  });
});

describe("resolveRef", () => {
  it("resolves a project-scoped ref", () => {
    setSecret("DB_URL", "postgres://db", { scope: "project", projectPath: PROJECT, silent: true });
    const value = resolveRef(parseRef("qring://project/DB_URL"), {
      projectPath: PROJECT,
      silent: true,
    });
    expect(value).toBe("postgres://db");
  });

  it("auto scope prefers project over global", () => {
    setSecret("API_KEY", "global-value", { scope: "global", silent: true });
    setSecret("API_KEY", "project-value", { scope: "project", projectPath: PROJECT, silent: true });
    const value = resolveRef(parseRef("qring:///API_KEY"), {
      projectPath: PROJECT,
      silent: true,
    });
    expect(value).toBe("project-value");
  });

  it("auto scope falls back to global", () => {
    setSecret("ONLY_GLOBAL", "g", { scope: "global", silent: true });
    const value = resolveRef(parseRef("qring:///ONLY_GLOBAL"), {
      projectPath: PROJECT,
      silent: true,
    });
    expect(value).toBe("g");
  });

  it("returns null for missing keys", () => {
    const value = resolveRef(parseRef("qring://global/NOPE"), { silent: true });
    expect(value).toBeNull();
  });

  it("an explicit scope does not fall back", () => {
    setSecret("GLOBAL_ONLY", "g", { scope: "global", silent: true });
    const value = resolveRef(parseRef("qring://project/GLOBAL_ONLY"), {
      projectPath: PROJECT,
      silent: true,
    });
    expect(value).toBeNull();
  });

  it("honors the env pin against superposition states", () => {
    setSecret("MULTI", "dev-value", {
      scope: "global",
      silent: true,
      states: { dev: "dev-value", prod: "prod-value" } as Record<string, string>,
    });
    const prod = resolveRef(parseRef("qring://global/MULTI?env=prod"), { silent: true });
    expect(prod).toBe("prod-value");
  });
});

describe("resolveRefsInMap", () => {
  it("resolves refs, passes plain values, reports missing", () => {
    setSecret("PRESENT", "secret-value", { scope: "global", silent: true });
    const { resolved, secretValues, missing } = resolveRefsInMap(
      {
        PLAIN: "hello",
        FROM_RING: "qring://global/PRESENT",
        GONE: "qring://global/ABSENT",
      },
      { silent: true },
    );
    expect(resolved.PLAIN).toBe("hello");
    expect(resolved.FROM_RING).toBe("secret-value");
    expect(resolved.GONE).toBeUndefined();
    expect(secretValues).toEqual(["secret-value"]);
    expect(missing).toHaveLength(1);
    expect(missing[0].name).toBe("GONE");
    expect(missing[0].ref.key).toBe("ABSENT");
  });

  it("throws on malformed refs instead of passing them through", () => {
    expect(() => resolveRefsInMap({ BAD: "qring://SOME_KEY" }, { silent: true })).toThrow(
      /key belongs in the path/,
    );
  });
});
