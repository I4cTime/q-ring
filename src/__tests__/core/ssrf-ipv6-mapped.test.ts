import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
  isPrivateIP,
  checkSSRF,
  checkSSRFSync,
  checkJitHttpProvisionUrl,
  guardedLookup,
} from "../../core/ssrf.js";

/**
 * Regression coverage for the IPv4-mapped-IPv6 SSRF-guard bypass (fixed in
 * 0.13.1). The WHATWG URL parser canonicalizes an IPv4-mapped literal to the
 * hex-group form, which the old dotted-decimal-only regex did not match:
 *   http://[::ffff:127.0.0.1]/       → hostname ::ffff:7f00:1
 *   http://[::ffff:169.254.169.254]/ → hostname ::ffff:a9fe:a9fe (cloud metadata)
 * Reachable by an ordinary MCP agent via register_hook, and escalating to
 * cloud-credential exfiltration via the http JIT provider.
 */

const stripBrackets = (h: string) => h.replace(/^\[|\]$/g, "");

function lookupVia(host: string): Promise<{ err: NodeJS.ErrnoException | null }> {
  return new Promise((resolve) => {
    guardedLookup(host, {}, (err) => resolve({ err }));
  });
}

describe("isPrivateIP — IPv4-mapped IPv6 (hex-group canonical form)", () => {
  it("blocks the hex-group forms the URL parser actually produces", () => {
    expect(isPrivateIP("::ffff:7f00:1")).toBe(true); // 127.0.0.1
    expect(isPrivateIP("::ffff:a9fe:a9fe")).toBe(true); // 169.254.169.254 (metadata)
    expect(isPrivateIP("::ffff:0a00:1")).toBe(true); // 10.0.0.1
    expect(isPrivateIP("::ffff:c0a8:1")).toBe(true); // 192.168.0.1
  });

  it("still blocks the dotted-decimal mapped form", () => {
    expect(isPrivateIP("::ffff:169.254.169.254")).toBe(true);
  });

  it("allows mapped PUBLIC addresses in either form (no over-block)", () => {
    expect(isPrivateIP("::ffff:8.8.8.8")).toBe(false);
    expect(isPrivateIP("::ffff:808:808")).toBe(false); // 8.8.8.8, hex-group form
  });

  it("allows genuine public unicast IPv6 (regression guard)", () => {
    expect(isPrivateIP("2606:4700:4700::1111")).toBe(false);
  });

  it("matches the verdict for both canonical spellings of the same address", () => {
    // Documents the vector: URL canonicalization must not change the verdict.
    const hostname = stripBrackets(new URL("http://[::ffff:127.0.0.1]/").hostname);
    expect(hostname).toBe("::ffff:7f00:1");
    expect(isPrivateIP(hostname)).toBe(isPrivateIP("127.0.0.1"));
  });
});

describe("SSRF entry points block the mapped-metadata address", () => {
  let prev: string | undefined;
  beforeEach(() => {
    prev = process.env.Q_RING_ALLOW_PRIVATE_HOOKS;
    delete process.env.Q_RING_ALLOW_PRIVATE_HOOKS;
  });
  afterEach(() => {
    if (prev === undefined) delete process.env.Q_RING_ALLOW_PRIVATE_HOOKS;
    else process.env.Q_RING_ALLOW_PRIVATE_HOOKS = prev;
  });

  const METADATA = "http://[::ffff:169.254.169.254]/latest/meta-data/";

  it("checkSSRF (async, hook path) blocks it", async () => {
    expect(await checkSSRF(METADATA)).toContain("Blocked");
  });

  it("checkSSRFSync blocks it", () => {
    expect(checkSSRFSync(METADATA)).toContain("Blocked");
  });

  it("checkJitHttpProvisionUrl (credential-exfil path) blocks it", () => {
    expect(checkJitHttpProvisionUrl(METADATA)).toContain("Blocked");
  });

  it("guardedLookup (connect-time rebinding guard) blocks it", async () => {
    const { err } = await lookupVia("::ffff:a9fe:a9fe");
    expect(err).not.toBeNull();
    expect(err?.code).toBe("EQRINGSSRF");
  });

  it("all four paths still allow a mapped public literal", async () => {
    const PUBLIC = "http://[::ffff:8.8.8.8]/";
    expect(await checkSSRF(PUBLIC)).toBeNull();
    expect(checkSSRFSync(PUBLIC)).toBeNull();
    expect(checkJitHttpProvisionUrl(PUBLIC)).toBeNull();
    const { err } = await lookupVia("::ffff:808:808");
    expect(err).toBeNull();
  });
});
