import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { checkJitHttpProvisionUrl } from "../../core/ssrf.js";
import { resetDeprecationWarnings, SILENCE_DEPRECATIONS_ENV } from "../../core/deprecation.js";

const OVERRIDE_VARS = ["QRING_ALLOW_PRIVATE_HOOKS", "Q_RING_ALLOW_PRIVATE_HOOKS"] as const;

describe("checkJitHttpProvisionUrl", () => {
  let prev: Record<string, string | undefined>;

  beforeEach(() => {
    // Clear BOTH spellings of the override so a value in the developer's
    // shell can never make a "blocks" test pass for the wrong reason.
    prev = {};
    for (const name of OVERRIDE_VARS) {
      prev[name] = process.env[name];
      delete process.env[name];
    }
  });

  afterEach(() => {
    for (const name of OVERRIDE_VARS) {
      if (prev[name] === undefined) delete process.env[name];
      else process.env[name] = prev[name];
    }
  });

  it("blocks IP-literal loopback without needing DNS", () => {
    expect(checkJitHttpProvisionUrl("http://127.0.0.1/foo")).toContain("Blocked");
  });

  it("blocks hostnames that resolve to loopback (sync DNS)", () => {
    const r = checkJitHttpProvisionUrl("http://localhost/foo");
    expect(r).not.toBeNull();
    expect(r).toContain("Blocked");
  });

  it("fails closed when DNS resolution throws", () => {
    const r = checkJitHttpProvisionUrl("https://quantum-ring-ssrf-jit.invalid/path");
    expect(r).not.toBeNull();
    expect(r).toContain("DNS resolution failed");
  });

  it("blocks non-http(s) schemes", () => {
    expect(checkJitHttpProvisionUrl("file:///etc/passwd")).toContain("only allows http:");
  });

  it("allows public IP literals", () => {
    expect(checkJitHttpProvisionUrl("https://1.1.1.1/path")).toBeNull();
  });
});

describe("checkJitHttpProvisionUrl private-address override", () => {
  const PRIVATE_URL = "http://127.0.0.1/token";
  let prev: Record<string, string | undefined>;
  let stderr: ReturnType<typeof vi.spyOn>;

  const deprecationLines = () =>
    stderr.mock.calls
      .map((c: unknown[]) => String(c[0]))
      .filter((l: string) => l.startsWith("q-ring: deprecated:"));

  beforeEach(() => {
    prev = {};
    for (const name of [...OVERRIDE_VARS, SILENCE_DEPRECATIONS_ENV]) {
      prev[name] = process.env[name];
      delete process.env[name];
    }
    resetDeprecationWarnings();
    stderr = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
  });

  afterEach(() => {
    stderr.mockRestore();
    for (const name of [...OVERRIDE_VARS, SILENCE_DEPRECATIONS_ENV]) {
      if (prev[name] === undefined) delete process.env[name];
      else process.env[name] = prev[name];
    }
  });

  it("blocks a private URL with neither override name set", () => {
    expect(checkJitHttpProvisionUrl(PRIVATE_URL)).toContain(
      "Set QRING_ALLOW_PRIVATE_HOOKS=1 to override.",
    );
    expect(deprecationLines()).toEqual([]);
  });

  it("allows a private URL with the canonical QRING_ALLOW_PRIVATE_HOOKS=1, without a warning", () => {
    process.env.QRING_ALLOW_PRIVATE_HOOKS = "1";
    expect(checkJitHttpProvisionUrl(PRIVATE_URL)).toBeNull();
    expect(deprecationLines()).toEqual([]);
  });

  it("allows a private URL with the legacy Q_RING_ALLOW_PRIVATE_HOOKS=1 and warns once", () => {
    process.env.Q_RING_ALLOW_PRIVATE_HOOKS = "1";
    expect(checkJitHttpProvisionUrl(PRIVATE_URL)).toBeNull();
    expect(checkJitHttpProvisionUrl(PRIVATE_URL)).toBeNull();
    expect(deprecationLines()).toEqual([
      "q-ring: deprecated: Q_RING_ALLOW_PRIVATE_HOOKS is deprecated; set QRING_ALLOW_PRIVATE_HOOKS=1 instead. Removed in 1.0.\n",
    ]);
  });
});
