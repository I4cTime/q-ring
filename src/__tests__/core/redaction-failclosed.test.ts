/**
 * Fail-closed behaviour when a redaction set cannot be built (review #6):
 * exec must not spawn, the airlock must fall back to verbatim-only matching
 * and, failing that, withhold results.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

const mode = vi.hoisted(() => ({ failFull: false, failVerbatim: false }));

vi.mock("../../core/redaction.js", async (importOriginal) => {
  const real = await importOriginal<typeof import("../../core/redaction.js")>();
  class FlakyRedactionSet extends real.RedactionSet {
    constructor(
      entries: readonly import("../../core/redaction.js").RedactionEntry[],
      options: import("../../core/redaction.js").RedactionSetOptions = {},
    ) {
      if (options.verbatimOnly ? mode.failVerbatim : mode.failFull) {
        throw new Error("simulated redaction build failure");
      }
      super(entries, options);
    }
  }
  return { ...real, RedactionSet: FlakyRedactionSet };
});

vi.mock("node:child_process", async (importOriginal) => {
  const real = await importOriginal<typeof import("node:child_process")>();
  return { ...real, spawn: vi.fn(real.spawn) };
});

vi.mock("@napi-rs/keyring", async () => {
  const fake = await import("../helpers/fake-keyring.js");
  return { Entry: fake.FakeEntry, findCredentials: fake.findCredentials };
});

import { spawn } from "node:child_process";
import { spawnRedacted, getProfile } from "../../core/exec.js";
import { createRedactor, RedactionUnavailableError } from "../../core/wrap-redact.js";
import { setSecret } from "../../core/keyring.js";
import { resetFakeKeyring } from "../helpers/fake-keyring.js";

const SECRET = "Zq7vK2mX9pL4wR8tY1nB6cH3jF5dG0sAe2Uo4Ii8";
let auditDir: string;

beforeEach(() => {
  mode.failFull = false;
  mode.failVerbatim = false;
  vi.mocked(spawn).mockClear();
  resetFakeKeyring();
  auditDir = mkdtempSync(join(tmpdir(), "qring-failclosed-audit-"));
  process.env.QRING_AUDIT_DIR = auditDir;
});
afterEach(() => {
  delete process.env.QRING_AUDIT_DIR;
  rmSync(auditDir, { recursive: true, force: true });
});

function runChild() {
  const envMap: Record<string, string> = {};
  for (const [k, v] of Object.entries(process.env)) if (v !== undefined) envMap[k] = v;
  envMap.K = SECRET;
  return spawnRedacted({
    profile: getProfile("unrestricted"),
    command: process.execPath,
    args: ["-e", "console.log('k=' + process.env.K + ' slice=' + process.env.K.slice(0, 20))"],
    envMap,
    secretsToRedact: [{ name: "K", value: SECRET }],
    captureOutput: true,
  });
}

describe("spawnRedacted builds redaction before spawning", () => {
  it("redacts normally when the set builds", async () => {
    const r = await runChild();
    expect(r.stdout.trim()).toBe("k=[QRING:REDACTED:K] slice=[QRING:REDACTED:K]");
    expect(spawn).toHaveBeenCalledTimes(1);
  });

  it("falls back to verbatim-only matching when the full build fails", async () => {
    mode.failFull = true;
    const r = await runChild();
    expect(r.stdout).toContain("k=[QRING:REDACTED:K]");
    expect(r.stdout).not.toContain(`k=${SECRET}`);
  });

  it("rejects WITHOUT spawning when no redaction set can be built", async () => {
    mode.failFull = true;
    mode.failVerbatim = true;
    await expect(runChild()).rejects.toThrow(/output redaction could not be set up/);
    expect(spawn).not.toHaveBeenCalled();
  });
});

describe("createRedactor never runs with an empty set after a failed build", () => {
  beforeEach(() => {
    setSecret("STRIPE_KEY", SECRET, { scope: "global", silent: true });
  });

  it("full build", () => {
    const r = createRedactor();
    expect(r.text(`x ${SECRET.slice(0, 20)} y`)).toBe("x [QRING:REDACTED:STRIPE_KEY] y");
  });

  it("falls back to verbatim-only when the full build fails", () => {
    mode.failFull = true;
    const r = createRedactor();
    expect(r.text(`x ${SECRET} y`)).toBe("x [QRING:REDACTED:STRIPE_KEY] y");
  });

  it("fails closed when even the verbatim build fails, and recovers once it builds", () => {
    mode.failFull = true;
    mode.failVerbatim = true;
    const r = createRedactor();
    expect(() => r.text(`x ${SECRET} y`)).toThrow(RedactionUnavailableError);
    expect(() => r.result({ content: [{ type: "text", text: SECRET }] })).toThrow(
      RedactionUnavailableError,
    );
    // Retried on the next result, not after a 60 s back-off.
    mode.failFull = false;
    mode.failVerbatim = false;
    expect(r.text(`x ${SECRET} y`)).toBe("x [QRING:REDACTED:STRIPE_KEY] y");
  });
});
