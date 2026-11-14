/**
 * A key whose stored value is empty (lost by the OS keyring) reaches the CLI
 * user as a readable error or warning, never as an empty value.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";

vi.mock("@napi-rs/keyring", async () => {
  const fake = await import("../helpers/fake-keyring.js");
  return { Entry: fake.FakeEntry, findCredentials: fake.findCredentials };
});

import { createProgram } from "../../cli/commands.js";
import { EmptyStoredValueError } from "../../core/keyring.js";
import { globalService } from "../../core/scope.js";
import { FakeEntry, fakeKeyringDump, resetFakeKeyring } from "../helpers/fake-keyring.js";

const EMPTY_TEXT = /"LOST_KEY" \(global scope\): the stored value is empty, likely lost by the OS keyring/;

async function run(...argv: string[]): Promise<void> {
  const program = createProgram();
  program.exitOverride();
  await program.parseAsync(argv, { from: "user" });
}

beforeEach(() => {
  resetFakeKeyring();
  process.exitCode = undefined;
  new FakeEntry(globalService(), "LOST_KEY").setPassword("");
  vi.spyOn(console, "log").mockImplementation(() => {});
});

afterEach(() => {
  vi.restoreAllMocks();
  process.exitCode = undefined;
});

describe("CLI on a key whose stored value is empty", () => {
  // Core errors reach src/index.ts, which prints err.message and exits 1.
  it("qring get fails with the empty-value message and writes nothing", async () => {
    const stdout = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
    const err = await run("get", "LOST_KEY", "-g").catch((e: unknown) => e);
    expect(err).toBeInstanceOf(EmptyStoredValueError);
    expect((err as Error).message).toMatch(EMPTY_TEXT);
    expect(stdout).not.toHaveBeenCalled();
    expect(fakeKeyringDump().get(`${globalService()}\0LOST_KEY`)).toBe("");
  });

  it("qring inspect fails with the empty-value message", async () => {
    const err = await run("inspect", "LOST_KEY", "-g").catch((e: unknown) => e);
    expect(err).toBeInstanceOf(EmptyStoredValueError);
    expect((err as Error).message).toMatch(EMPTY_TEXT);
  });

  it("qring exec warns on stderr, skips the key and still runs the command", async () => {
    const stderr: string[] = [];
    vi.spyOn(process.stderr, "write").mockImplementation((chunk: string | Uint8Array) => {
      stderr.push(String(chunk));
      return true;
    });
    vi.spyOn(console, "error").mockImplementation((...args: unknown[]) => {
      stderr.push(args.map(String).join(" "));
    });
    const exit = vi.spyOn(process, "exit").mockImplementation((() => undefined) as never);
    await run("exec", "-g", "--", process.execPath, "-e", "process.exit(0)");
    expect(exit).toHaveBeenCalledWith(0);
    const warning = stderr.join("");
    expect(warning).toContain('not injecting "LOST_KEY"');
    expect(warning).toContain("stored value is empty");
  });

  it("qring set over it works again", async () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    await run("set", "LOST_KEY", "fresh-value", "-g");
    expect(fakeKeyringDump().get(`${globalService()}\0LOST_KEY`)).toContain("fresh-value");
  });
});

describe("qring list on a key whose stored value is empty", () => {
  it("marks the row in the table", async () => {
    const lines: string[] = [];
    vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => {
      lines.push(args.map(String).join(" "));
    });
    await run("list", "-g");
    const row = lines.find((l) => l.includes("LOST_KEY"));
    expect(row).toContain("empty - value lost");
  });

  it("adds emptyStored: true to its --json entry only", async () => {
    const out: string[] = [];
    vi.spyOn(process.stdout, "write").mockImplementation((chunk: string | Uint8Array) => {
      out.push(String(chunk));
      return true;
    });
    vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => {
      out.push(args.map(String).join(" "));
    });
    new FakeEntry(globalService(), "GOOD_KEY").setPassword("plain-legacy");
    await run("list", "-g", "--json");
    const parsed = JSON.parse(out.join("")) as unknown;
    const entries = (Array.isArray(parsed) ? parsed : (parsed as { data: unknown[] }).data) as Record<string, unknown>[];
    expect(entries.find((e) => e.key === "LOST_KEY")?.emptyStored).toBe(true);
    expect(entries.find((e) => e.key === "GOOD_KEY")).not.toHaveProperty("emptyStored");
  });
});
