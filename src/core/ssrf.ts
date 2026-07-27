/**
 * SSRF Protection — shared guard for HTTP requests to user-controlled URLs.
 *
 * Blocks requests to private/loopback/link-local addresses unless
 * Q_RING_ALLOW_PRIVATE_HOOKS=1 is set.
 */

import { lookup } from "node:dns/promises";
import * as dns from "node:dns";
import { lookup as dnsLookup, type LookupAddress } from "node:dns";
import { isIPv4, isIPv6 } from "node:net";
import ipaddr from "ipaddr.js";

/** `lookupSync` exists at runtime (Node 18+); some @types/node versions omit it from typings. */
function lookupAddressesSync(hostname: string): { address: string; family: number }[] {
  const lookupSync = (dns as typeof dns & {
    lookupSync(
      host: string,
      options: { all: true },
    ): { address: string; family: number }[];
  }).lookupSync;
  return lookupSync(hostname, { all: true });
}

function isHostnameIpLiteral(hostname: string): boolean {
  if (isIPv4(hostname)) return true;
  if (hostname.startsWith("[") && hostname.endsWith("]")) {
    return isIPv6(hostname.slice(1, -1));
  }
  return isIPv6(hostname);
}

/**
 * IPv4 ranges an outbound request must never reach. `reserved` (which includes
 * the TEST-NET documentation blocks) and `multicast` are deliberately omitted to
 * preserve the historical "public IPs pass" contract.
 */
const BLOCKED_IPV4_RANGES = new Set<string>([
  "unspecified",
  "broadcast",
  "linkLocal",
  "loopback",
  "carrierGradeNat",
  "private",
]);

/**
 * True if an IP *literal* points somewhere an outbound request must never go:
 * loopback, private, link-local, carrier-grade NAT, unspecified/broadcast, and —
 * for IPv6 — every non-unicast range plus the IPv4-in-IPv6 transition forms that
 * can smuggle those targets past a naive string check.
 *
 * Parsing is delegated to `ipaddr.js` rather than matched with regexes, because
 * the WHATWG URL parser canonicalizes an IPv4-mapped literal like
 * `[::ffff:127.0.0.1]` to the hex-group form `::ffff:7f00:1` (and
 * `[::ffff:169.254.169.254]` → `::ffff:a9fe:a9fe`, i.e. cloud metadata), which a
 * dotted-decimal-only regex silently let through. Structured parsing covers every
 * canonical form of the same address.
 *
 * Returns false for non-IP strings (hostnames); DNS resolution is handled by the
 * callers, which re-run this check against each resolved address.
 */
export function isPrivateIP(ip: string): boolean {
  let addr: ipaddr.IPv4 | ipaddr.IPv6;
  try {
    addr = ipaddr.parse(ip);
  } catch {
    return false;
  }

  if (addr.kind() === "ipv6") {
    const v6 = addr as ipaddr.IPv6;
    // Unwrap IPv4-mapped addresses and judge the embedded IPv4, so both the
    // dotted (`::ffff:127.0.0.1`) and hex-group (`::ffff:7f00:1`) canonical forms
    // resolve to the same verdict.
    if (v6.isIPv4MappedAddress()) {
      return isBlockedIPv4(v6.toIPv4Address());
    }
    // Only genuine global unicast IPv6 is allowed out. Everything else —
    // loopback, link-local, unique-local, unspecified, multicast, reserved, and
    // the IPv4-embedding 6to4/teredo/rfc6052/rfc6145 transition ranges — is a
    // potential internal-target smuggling vector and is blocked.
    return v6.range() !== "unicast";
  }

  return isBlockedIPv4(addr as ipaddr.IPv4);
}

function isBlockedIPv4(addr: ipaddr.IPv4): boolean {
  return BLOCKED_IPV4_RANGES.has(addr.range());
}

/**
 * Async SSRF check — resolves DNS and blocks private addresses.
 * Returns null if safe, or a human-readable block message.
 */
export async function checkSSRF(url: string): Promise<string | null> {
  if (process.env.Q_RING_ALLOW_PRIVATE_HOOKS === "1") return null;

  try {
    const parsed = new URL(url);
    const hostname = parsed.hostname.replace(/^\[|\]$/g, "");

    if (isPrivateIP(hostname)) {
      return `Blocked: URL resolves to private address (${hostname}). Set Q_RING_ALLOW_PRIVATE_HOOKS=1 to override.`;
    }

    const results = await lookup(hostname, { all: true });
    for (const { address } of results) {
      if (isPrivateIP(address)) {
        return `Blocked: URL "${hostname}" resolves to private address ${address}. Set Q_RING_ALLOW_PRIVATE_HOOKS=1 to override.`;
      }
    }
  } catch {
    // DNS failure will surface as a request error downstream
  }
  return null;
}

type GuardedLookupCallback = (
  err: NodeJS.ErrnoException | null,
  address: string | LookupAddress[],
  family?: number,
) => void;

/**
 * A `lookup` function for http(s).request that re-validates the resolved
 * address at connection time. This closes the DNS-rebinding TOCTOU window
 * where a hostname passes {@link checkSSRF} but resolves to a private/loopback
 * address moments later when the socket actually connects. Fails closed.
 */
export function guardedLookup(
  hostname: string,
  options: dns.LookupOptions,
  callback: GuardedLookupCallback,
): void {
  if (process.env.Q_RING_ALLOW_PRIVATE_HOOKS === "1") {
    (dnsLookup as (h: string, o: dns.LookupOptions, cb: GuardedLookupCallback) => void)(
      hostname,
      options,
      callback,
    );
    return;
  }

  (dnsLookup as (h: string, o: dns.LookupOptions, cb: GuardedLookupCallback) => void)(
    hostname,
    options,
    (err, address, family) => {
      if (err) return callback(err, address, family);
      const list = Array.isArray(address)
        ? address
        : [{ address, family: family ?? 0 }];
      for (const a of list) {
        if (isPrivateIP(a.address)) {
          const blocked: NodeJS.ErrnoException = Object.assign(
            new Error(
              `Blocked: "${hostname}" resolved to private address ${a.address} at connect time.`,
            ),
            { code: "EQRINGSSRF" },
          );
          return callback(blocked, address, family);
        }
      }
      callback(null, address, family);
    },
  );
}

/**
 * Sync SSRF check — validates IP literals only (no DNS resolution).
 * Suitable for sync contexts where async DNS lookup isn't possible.
 */
export function checkSSRFSync(url: string): string | null {
  if (process.env.Q_RING_ALLOW_PRIVATE_HOOKS === "1") return null;

  try {
    const parsed = new URL(url);
    const hostname = parsed.hostname.replace(/^\[|\]$/g, "");

    if (isPrivateIP(hostname)) {
      return `Blocked: URL resolves to private address (${hostname}). Set Q_RING_ALLOW_PRIVATE_HOOKS=1 to override.`;
    }
  } catch {
    // malformed URL — will fail downstream
  }
  return null;
}

/**
 * JIT HTTP provisioning runs in a sync path and cannot use async DNS.
 * This performs {@link lookupSync} so hostnames cannot bypass {@link checkSSRFSync}
 * by resolving to loopback/private only at request time. Fails closed on DNS errors.
 */
export function checkJitHttpProvisionUrl(url: string): string | null {
  if (process.env.Q_RING_ALLOW_PRIVATE_HOOKS === "1") return null;

  try {
    const parsed = new URL(url);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return "Blocked: JIT HTTP provider only allows http: or https: URLs.";
    }
    const hostname = parsed.hostname.replace(/^\[|\]$/g, "");
    if (!hostname) {
      return "Blocked: empty hostname in JIT URL.";
    }

    if (isPrivateIP(hostname)) {
      return `Blocked: URL resolves to private address (${hostname}). Set Q_RING_ALLOW_PRIVATE_HOOKS=1 to override.`;
    }

    if (isHostnameIpLiteral(hostname)) {
      return null;
    }

    let results: { address: string; family: number }[];
    try {
      results = lookupAddressesSync(hostname);
    } catch {
      return `Blocked: DNS resolution failed for "${hostname}" (JIT HTTP provisioning fails closed).`;
    }

    if (!results.length) {
      return `Blocked: DNS returned no addresses for "${hostname}".`;
    }

    for (const { address } of results) {
      if (isPrivateIP(address)) {
        return `Blocked: URL "${hostname}" resolves to private address ${address}. Set Q_RING_ALLOW_PRIVATE_HOOKS=1 to override.`;
      }
    }
  } catch {
    return "Blocked: malformed JIT HTTP URL.";
  }
  return null;
}
