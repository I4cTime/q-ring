import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import {
  warnDeprecated,
  resetDeprecationWarnings,
  SILENCE_DEPRECATIONS_ENV,
} from "../../core/deprecation.js";

let stderr: ReturnType<typeof vi.spyOn>;
let stdout: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  resetDeprecationWarnings();
  delete process.env[SILENCE_DEPRECATIONS_ENV];
  stderr = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
  stdout = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
});

afterEach(() => {
  stderr.mockRestore();
  stdout.mockRestore();
  delete process.env[SILENCE_DEPRECATIONS_ENV];
});

describe("warnDeprecated", () => {
  it("writes one prefixed line to stderr, never stdout", () => {
    expect(warnDeprecated("x", "use y instead. Removed in 1.0.")).toBe(true);
    expect(stderr).toHaveBeenCalledTimes(1);
    expect(stderr.mock.calls[0][0]).toBe("q-ring: deprecated: use y instead. Removed in 1.0.\n");
    expect(stdout).not.toHaveBeenCalled();
  });

  it("warns once per id per process", () => {
    warnDeprecated("x", "first");
    expect(warnDeprecated("x", "first")).toBe(false);
    expect(stderr).toHaveBeenCalledTimes(1);
    warnDeprecated("other", "second id still warns");
    expect(stderr).toHaveBeenCalledTimes(2);
  });

  it("is silent with QRING_SILENCE_DEPRECATIONS=1", () => {
    process.env[SILENCE_DEPRECATIONS_ENV] = "1";
    expect(warnDeprecated("x", "quiet")).toBe(false);
    expect(stderr).not.toHaveBeenCalled();
  });

  it("only the exact value 1 silences", () => {
    process.env[SILENCE_DEPRECATIONS_ENV] = "true";
    warnDeprecated("x", "still loud");
    expect(stderr).toHaveBeenCalledTimes(1);
  });
});
