/**
 * `--json` contract fixes: `qring ci:validate --json` exits 1 on failure (as
 * the README promises), and `qring mcp approvals` honours the root `--json`.
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

let out: string[];

async function run(...argv: string[]): Promise<void> {
  const program = createProgram();
  program.exitOverride();
  await program.parseAsync(argv, { from: "user" });
}

const stdoutText = () => out.join("");

beforeEach(() => {
  resetFakeKeyring();
  process.exitCode = undefined;
  out = [];
  vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => {
    out.push(args.map(String).join(" ") + "\n");
  });
  vi.spyOn(process.stdout, "write").mockImplementation((chunk: unknown) => {
    out.push(String(chunk));
    return true;
  });
  vi.spyOn(process.stderr, "write").mockImplementation(() => true);
  ciValidateBatchMock.mockReset();
});

afterEach(() => {
  vi.restoreAllMocks();
  process.exitCode = undefined;
});

describe("qring ci:validate --json exit code", () => {
  const failing = {
    results: [
      {
        key: "API_KEY",
        validation: {
          valid: false,
          status: "invalid",
          message: "401",
          latencyMs: 1,
          provider: "openai",
        },
        requiresRotation: true,
      },
    ],
    allValid: false,
    failCount: 1,
  };
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

  it("exits 1 when a secret fails, as the README promises", async () => {
    ciValidateBatchMock.mockResolvedValue(failing);
    await run("ci:validate", "--global", "--json");
    expect(process.exitCode).toBe(1);
    expect(JSON.parse(stdoutText())).toEqual(failing);
  });

  it("exits 0 when every secret passes", async () => {
    ciValidateBatchMock.mockResolvedValue(passing);
    await run("ci:validate", "--global", "--json");
    expect(process.exitCode ?? 0).toBe(0);
  });
});

describe("qring mcp approvals", () => {
  it("honours the root --json", async () => {
    await run("--json", "mcp", "approvals");
    expect(JSON.parse(stdoutText())).toEqual({ approvals: [] });
  });

  it("still honours the subcommand --json", async () => {
    await run("mcp", "approvals", "--json");
    expect(JSON.parse(stdoutText())).toEqual({ approvals: [] });
  });

  it("prints human output without --json", async () => {
    await run("mcp", "approvals");
    expect(stdoutText()).toContain("No airlock approvals");
  });
});
