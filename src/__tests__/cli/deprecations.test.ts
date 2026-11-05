/**
 * CLI deprecation warnings (docs/stability.md, "Deprecated in 0.19"). Each
 * warning must fire once per process, stay silent under
 * QRING_SILENCE_DEPRECATIONS=1, and never touch stdout — `--json` consumers
 * parse stdout.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";

vi.mock("@napi-rs/keyring", async () => {
  const fake = await import("../helpers/fake-keyring.js");
  return { Entry: fake.FakeEntry, findCredentials: fake.findCredentials };
});

const ciValidateBatchMock = vi.hoisted(() => vi.fn());
vi.mock("../../core/validate.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../core/validate.js")>();
  return { ...actual, ciValidateBatch: ciValidateBatchMock };
});

import { createProgram } from "../../cli/commands.js";
import { setSecret } from "../../core/keyring.js";
import { resetFakeKeyring } from "../helpers/fake-keyring.js";
import { resetDeprecationWarnings, SILENCE_DEPRECATIONS_ENV } from "../../core/deprecation.js";

let out: string[];
let err: string[];

async function run(...argv: string[]): Promise<void> {
  const program = createProgram();
  program.exitOverride();
  await program.parseAsync(argv, { from: "user" });
}

const stdoutText = () => out.join("");
const deprecations = () => err.filter((l) => l.startsWith("q-ring: deprecated:"));

beforeEach(() => {
  resetFakeKeyring();
  resetDeprecationWarnings();
  delete process.env[SILENCE_DEPRECATIONS_ENV];
  process.exitCode = undefined;
  out = [];
  err = [];
  vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => {
    out.push(args.map(String).join(" ") + "\n");
  });
  vi.spyOn(process.stdout, "write").mockImplementation((chunk: unknown) => {
    out.push(String(chunk));
    return true;
  });
  vi.spyOn(process.stderr, "write").mockImplementation((chunk: unknown) => {
    err.push(String(chunk));
    return true;
  });
  ciValidateBatchMock.mockReset();
});

afterEach(() => {
  vi.restoreAllMocks();
  delete process.env[SILENCE_DEPRECATIONS_ENV];
  process.exitCode = undefined;
});

describe("qring approve <key> --list", () => {
  it("warns once, pointing at `qring approvals`", async () => {
    await run("approve", "ANY", "--list");
    await run("approve", "ANY", "--list");
    expect(deprecations()).toEqual([
      "q-ring: deprecated: `qring approve <key> --list` is deprecated; use `qring approvals` instead. Removed in 1.0.\n",
    ]);
  });

  it("is silent with QRING_SILENCE_DEPRECATIONS=1", async () => {
    process.env[SILENCE_DEPRECATIONS_ENV] = "1";
    await run("approve", "ANY", "--list");
    expect(deprecations()).toEqual([]);
  });

  it("`qring approvals` does not warn", async () => {
    await run("approvals");
    expect(deprecations()).toEqual([]);
  });
});

describe.each([
  ["context", ["context", "--json"], ["--json", "context"]],
  ["policy", ["policy", "--json"], ["--json", "policy"]],
])("qring %s --json (bare shape)", (name, sub, root) => {
  it("warns once on stderr; stdout stays the unchanged bare JSON payload", async () => {
    await run(...sub);
    const first = stdoutText();
    const parsed = JSON.parse(first);
    expect(parsed).not.toHaveProperty("ok"); // shape unchanged until 1.0
    expect(first).not.toContain("deprecated");

    await run(...root); // root --json is the same path
    expect(deprecations()).toHaveLength(1);
    expect(deprecations()[0]).toBe(
      `q-ring: deprecated: \`qring ${name} --json\` prints a bare payload; 1.0 switches it to the { ok, data } wrapper. Removed in 1.0.\n`,
    );
  });

  it("is silent with QRING_SILENCE_DEPRECATIONS=1", async () => {
    process.env[SILENCE_DEPRECATIONS_ENV] = "1";
    await run(...sub);
    expect(deprecations()).toEqual([]);
    JSON.parse(stdoutText());
  });

  it("does not warn without --json", async () => {
    await run(sub[0]);
    expect(deprecations()).toEqual([]);
  });
});

describe("qring ci:validate --json (bare shape)", () => {
  const passing = {
    results: [
      {
        key: "API_KEY",
        validation: {
          valid: true,
          status: "valid",
          message: "ok",
          latencyMs: 1,
          provider: "openai",
        },
        requiresRotation: false,
      },
    ],
    allValid: true,
    failCount: 0,
  };

  beforeEach(() => {
    setSecret("API_KEY", "placeholder-value-for-ci-validate", { scope: "global", source: "cli" });
  });

  it("warns once on stderr; stdout stays the unchanged bare JSON payload", async () => {
    ciValidateBatchMock.mockResolvedValue(passing);
    await run("ci:validate", "--global", "--json");
    await run("--json", "ci:validate", "--global");
    const chunks = out.join("");
    expect(chunks).not.toContain("deprecated");
    expect(deprecations()).toEqual([
      "q-ring: deprecated: `qring ci:validate --json` prints a bare payload; 1.0 switches it to the { ok, data } wrapper. Removed in 1.0.\n",
    ]);
  });

  it("is silent with QRING_SILENCE_DEPRECATIONS=1", async () => {
    process.env[SILENCE_DEPRECATIONS_ENV] = "1";
    ciValidateBatchMock.mockResolvedValue(passing);
    await run("ci:validate", "--global", "--json");
    expect(deprecations()).toEqual([]);
  });
});
