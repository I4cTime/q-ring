import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("@napi-rs/keyring", async () => {
  const fake = await import("../helpers/fake-keyring.js");
  return { Entry: fake.FakeEntry, findCredentials: fake.findCredentials };
});

import { resetFakeKeyring } from "../helpers/fake-keyring.js";
import { getEnvelope, setSecret } from "../../core/keyring.js";
import {
  diffEnvironments,
  promoteSecret,
  PromoteConflictError,
} from "../../core/promote.js";

const silent = { silent: true } as const;

function states(key: string) {
  return getEnvelope(key, { scope: "global" })?.envelope.states;
}

describe("promoteSecret", () => {
  beforeEach(() => {
    resetFakeKeyring();
    setSecret("API_KEY", "", { states: { dev: "dev-1", staging: "stg-1" }, defaultEnv: "dev", ...silent });
  });

  it("copies the source state into a missing target state", () => {
    const r = promoteSecret("API_KEY", { from: "staging", to: "prod", ...silent });
    expect(r).toMatchObject({ from: "staging", to: "prod", previous: "absent", changed: true, scope: "global" });
    expect(states("API_KEY")).toEqual({ dev: "dev-1", staging: "stg-1", prod: "stg-1" });
    // metadata such as defaultEnv survives
    expect(getEnvelope("API_KEY", { scope: "global" })?.envelope.defaultEnv).toBe("dev");
  });

  it("is a no-op when the target already matches", () => {
    promoteSecret("API_KEY", { from: "staging", to: "prod", ...silent });
    const again = promoteSecret("API_KEY", { from: "staging", to: "prod", ...silent });
    expect(again.previous).toBe("same");
    expect(again.changed).toBe(false);
  });

  it("refuses to overwrite a differing target without force, then obeys force", () => {
    setSecret("API_KEY", "", { states: { dev: "dev-1", staging: "stg-1", prod: "old" }, defaultEnv: "dev", ...silent });
    expect(() => promoteSecret("API_KEY", { from: "staging", to: "prod", ...silent })).toThrow(PromoteConflictError);
    expect(states("API_KEY")?.prod).toBe("old");
    const r = promoteSecret("API_KEY", { from: "staging", to: "prod", force: true, ...silent });
    expect(r.previous).toBe("different");
    expect(states("API_KEY")?.prod).toBe("stg-1");
  });

  it("explains missing sources, collapsed secrets and bad names", () => {
    expect(() => promoteSecret("API_KEY", { from: "qa", to: "prod", ...silent })).toThrow(/no value for env "qa" \(available: dev, staging\)/);
    setSecret("FLAT", "single", silent);
    expect(() => promoteSecret("FLAT", { from: "dev", to: "prod", ...silent })).toThrow(/single value/);
    expect(() => promoteSecret("NOPE", { from: "dev", to: "prod", ...silent })).toThrow(/not found/);
    expect(() => promoteSecret("API_KEY", { from: "dev", to: "dev", ...silent })).toThrow(/both "dev"/);
    expect(() => promoteSecret("API_KEY", { from: "de v", to: "prod", ...silent })).toThrow(/invalid/);
  });
});

describe("diffEnvironments", () => {
  beforeEach(() => {
    resetFakeKeyring();
    setSecret("SAME", "", { states: { dev: "x", prod: "x" }, ...silent });
    setSecret("DIFF", "", { states: { dev: "x", prod: "y" }, ...silent });
    setSecret("DEV_ONLY", "", { states: { dev: "x" }, ...silent });
    setSecret("PROD_ONLY", "", { states: { prod: "x" }, ...silent });
    setSecret("FLAT", "single", silent);
    setSecret("OTHER_ENVS", "", { states: { qa: "x" }, ...silent });
  });

  it("classifies every key without returning values", () => {
    const d = diffEnvironments({ a: "dev", b: "prod", ...silent });
    const byKey = Object.fromEntries(d.entries.map((e) => [e.key, e.status]));
    expect(byKey).toEqual({
      SAME: "same",
      DIFF: "different",
      DEV_ONLY: "only-a",
      PROD_ONLY: "only-b",
      FLAT: "collapsed",
    });
    expect(d.summary).toEqual({ same: 1, different: 1, "only-a": 1, "only-b": 1, collapsed: 1 });
    expect(d.drift).toBe(true);
    expect(JSON.stringify(d)).not.toMatch(/"x"|"y"|single/);
  });

  it("restricts to requested keys and reports no drift when aligned", () => {
    const d = diffEnvironments({ a: "dev", b: "prod", keys: ["SAME", "FLAT"], ...silent });
    expect(d.entries.map((e) => e.key).sort()).toEqual(["FLAT", "SAME"]);
    expect(d.drift).toBe(false);
  });
});
