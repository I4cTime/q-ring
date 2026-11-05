import { describe, it, expect, afterEach, beforeEach, vi } from "vitest";
import {
  isPrivateIP,
  checkSSRF,
  checkSSRFSync,
  guardedLookup,
  privateTargetsAllowed,
} from "../../core/ssrf.js";
import { resetDeprecationWarnings, SILENCE_DEPRECATIONS_ENV } from "../../core/deprecation.js";

function lookupVia(host: string): Promise<{ err: NodeJS.ErrnoException | null }> {
  return new Promise((resolve) => {
    guardedLookup(host, {}, (err) => resolve({ err }));
  });
}

describe("isPrivateIP", () => {
  it("blocks 127.x.x.x (loopback)", () => {
    expect(isPrivateIP("127.0.0.1")).toBe(true);
    expect(isPrivateIP("127.255.255.255")).toBe(true);
  });

  it("blocks 10.x.x.x", () => {
    expect(isPrivateIP("10.0.0.1")).toBe(true);
    expect(isPrivateIP("10.255.255.255")).toBe(true);
  });

  it("blocks 172.16-31.x.x", () => {
    expect(isPrivateIP("172.16.0.1")).toBe(true);
    expect(isPrivateIP("172.31.255.255")).toBe(true);
    expect(isPrivateIP("172.15.0.1")).toBe(false);
    expect(isPrivateIP("172.32.0.1")).toBe(false);
  });

  it("blocks 192.168.x.x", () => {
    expect(isPrivateIP("192.168.0.1")).toBe(true);
    expect(isPrivateIP("192.168.255.255")).toBe(true);
  });

  it("blocks link-local 169.254.x.x", () => {
    expect(isPrivateIP("169.254.1.1")).toBe(true);
  });

  it("blocks 0.0.0.0", () => {
    expect(isPrivateIP("0.0.0.0")).toBe(true);
  });

  it("blocks IPv6 loopback and private", () => {
    expect(isPrivateIP("::1")).toBe(true);
    expect(isPrivateIP("::")).toBe(true);
    expect(isPrivateIP("fc00::1")).toBe(true);
    expect(isPrivateIP("fd12::1")).toBe(true);
    expect(isPrivateIP("fe80::1")).toBe(true);
  });

  it("blocks IPv4-mapped IPv6", () => {
    expect(isPrivateIP("::ffff:127.0.0.1")).toBe(true);
    expect(isPrivateIP("::ffff:10.0.0.1")).toBe(true);
  });

  it("allows public IPs", () => {
    expect(isPrivateIP("8.8.8.8")).toBe(false);
    expect(isPrivateIP("1.1.1.1")).toBe(false);
    expect(isPrivateIP("203.0.113.1")).toBe(false);
  });
});

describe("checkSSRF", () => {
  it("blocks http://127.0.0.1", async () => {
    const result = await checkSSRF("http://127.0.0.1/test");
    expect(result).toContain("Blocked");
  });

  it("blocks http://[::1]", async () => {
    const result = await checkSSRF("http://[::1]/test");
    expect(result).toContain("Blocked");
  });

  it("returns null for public IP literal URLs (no hostname DNS)", async () => {
    const result = await checkSSRF("https://8.8.8.8/test");
    expect(result).toBeNull();
  });

  it("respects Q_RING_ALLOW_PRIVATE_HOOKS override", async () => {
    const orig = process.env.Q_RING_ALLOW_PRIVATE_HOOKS;
    process.env.Q_RING_ALLOW_PRIVATE_HOOKS = "1";
    try {
      const result = await checkSSRF("http://127.0.0.1/test");
      expect(result).toBeNull();
    } finally {
      if (orig === undefined) delete process.env.Q_RING_ALLOW_PRIVATE_HOOKS;
      else process.env.Q_RING_ALLOW_PRIVATE_HOOKS = orig;
    }
  });
});

describe("checkSSRFSync", () => {
  it("blocks IP-literal private URLs synchronously", () => {
    expect(checkSSRFSync("http://10.0.0.1/path")).toContain("Blocked");
    expect(checkSSRFSync("http://192.168.1.1/path")).toContain("Blocked");
  });

  it("returns null for public IPs", () => {
    expect(checkSSRFSync("https://1.1.1.1/path")).toBeNull();
  });

  it("returns null for hostnames (no DNS in sync mode)", () => {
    expect(checkSSRFSync("https://example.com/path")).toBeNull();
  });
});

describe("guardedLookup (connect-time DNS-rebinding guard)", () => {
  // Clear BOTH spellings of the override before each test.
  const OVERRIDE_VARS = ["QRING_ALLOW_PRIVATE_HOOKS", "Q_RING_ALLOW_PRIVATE_HOOKS"] as const;
  const orig: Record<string, string | undefined> = {};
  for (const name of OVERRIDE_VARS) orig[name] = process.env[name];
  beforeEach(() => {
    for (const name of OVERRIDE_VARS) delete process.env[name];
  });
  afterEach(() => {
    for (const name of OVERRIDE_VARS) {
      if (orig[name] === undefined) delete process.env[name];
      else process.env[name] = orig[name];
    }
  });

  it("blocks resolution to a private/loopback address", async () => {
    const { err } = await lookupVia("127.0.0.1");
    expect(err).not.toBeNull();
    expect(err?.code).toBe("EQRINGSSRF");
  });

  it("allows resolution to a public address", async () => {
    const { err } = await lookupVia("8.8.8.8");
    expect(err).toBeNull();
  });

  it("respects the canonical QRING_ALLOW_PRIVATE_HOOKS override", async () => {
    process.env.QRING_ALLOW_PRIVATE_HOOKS = "1";
    const { err } = await lookupVia("127.0.0.1");
    expect(err).toBeNull();
  });

  it("respects the legacy Q_RING_ALLOW_PRIVATE_HOOKS override", async () => {
    process.env.Q_RING_ALLOW_PRIVATE_HOOKS = "1";
    const { err } = await lookupVia("127.0.0.1");
    expect(err).toBeNull();
  });
});

describe("QRING_ALLOW_PRIVATE_HOOKS (canonical) vs Q_RING_ALLOW_PRIVATE_HOOKS (Deprecated in 0.19)", () => {
  const saved = {
    canonical: process.env.QRING_ALLOW_PRIVATE_HOOKS,
    legacy: process.env.Q_RING_ALLOW_PRIVATE_HOOKS,
  };
  let stderr: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    resetDeprecationWarnings();
    delete process.env.QRING_ALLOW_PRIVATE_HOOKS;
    delete process.env.Q_RING_ALLOW_PRIVATE_HOOKS;
    delete process.env[SILENCE_DEPRECATIONS_ENV];
    stderr = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
  });
  afterEach(() => {
    stderr.mockRestore();
    delete process.env[SILENCE_DEPRECATIONS_ENV];
    if (saved.canonical === undefined) delete process.env.QRING_ALLOW_PRIVATE_HOOKS;
    else process.env.QRING_ALLOW_PRIVATE_HOOKS = saved.canonical;
    if (saved.legacy === undefined) delete process.env.Q_RING_ALLOW_PRIVATE_HOOKS;
    else process.env.Q_RING_ALLOW_PRIVATE_HOOKS = saved.legacy;
  });

  it("is off by default", () => {
    expect(privateTargetsAllowed()).toBe(false);
    expect(checkSSRFSync("http://127.0.0.1/x")).toContain("QRING_ALLOW_PRIVATE_HOOKS=1");
    expect(stderr).not.toHaveBeenCalled();
  });

  it("QRING_ALLOW_PRIVATE_HOOKS=1 enables it without a warning", async () => {
    process.env.QRING_ALLOW_PRIVATE_HOOKS = "1";
    expect(checkSSRFSync("http://127.0.0.1/x")).toBeNull();
    expect(await checkSSRF("http://127.0.0.1/x")).toBeNull();
    expect(stderr).not.toHaveBeenCalled();
  });

  it("the old name alone still enables it and warns once, not twice", async () => {
    process.env.Q_RING_ALLOW_PRIVATE_HOOKS = "1";
    expect(checkSSRFSync("http://127.0.0.1/x")).toBeNull();
    expect(await checkSSRF("http://10.0.0.1/x")).toBeNull();
    expect(stderr).toHaveBeenCalledTimes(1);
    expect(String(stderr.mock.calls[0][0])).toBe(
      "q-ring: deprecated: Q_RING_ALLOW_PRIVATE_HOOKS is deprecated; set QRING_ALLOW_PRIVATE_HOOKS=1 instead. Removed in 1.0.\n",
    );
  });

  it("both names set: no warning", () => {
    process.env.QRING_ALLOW_PRIVATE_HOOKS = "1";
    process.env.Q_RING_ALLOW_PRIVATE_HOOKS = "1";
    expect(privateTargetsAllowed()).toBe(true);
    expect(stderr).not.toHaveBeenCalled();
  });

  it("old name with QRING_SILENCE_DEPRECATIONS=1: enabled, silent", () => {
    process.env.Q_RING_ALLOW_PRIVATE_HOOKS = "1";
    process.env[SILENCE_DEPRECATIONS_ENV] = "1";
    expect(privateTargetsAllowed()).toBe(true);
    expect(stderr).not.toHaveBeenCalled();
  });
});
