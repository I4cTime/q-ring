import { describe, it, expect, vi } from "vitest";
import { RedactionTransform, getProfile } from "../../core/exec.js";
import {
  RedactionSet,
  MAX_SLICE_WINDOWS,
  redactionToken,
  resetSliceCapWarning,
  type RedactionEntry,
} from "../../core/redaction.js";

function runThrough(entries: RedactionEntry[], chunks: (string | Buffer)[]): Promise<string> {
  const t = new RedactionTransform(entries);
  const out: Buffer[] = [];
  return new Promise((resolve, reject) => {
    t.on("data", (d) => out.push(Buffer.isBuffer(d) ? d : Buffer.from(d)));
    t.on("end", () => resolve(Buffer.concat(out).toString("utf8")));
    t.on("error", reject);
    for (const c of chunks) t.write(c);
    t.end();
  });
}

const NAME = "API_KEY";
const T = `[QRING:REDACTED:${NAME}]`;
const R = "[QRING:REDACTED]";
/** 40 high-entropy chars (fake). */
const S = "Zq7vK2mX9pL4wR8tY1nB6cH3jF5dG0sAe2Uo4Ii8";
const named = (value: string, name: string = NAME): RedactionEntry[] => [{ name, value }];

/** Split a string into two chunks at `at`. */
const split = (s: string, at: number) => [s.slice(0, at), s.slice(at)];

describe("RedactionTransform chunk boundaries", () => {
  it("redacts a secret contained in one chunk", async () => {
    const out = await runThrough(named("sk-abc123def"), ["the key is sk-abc123def done"]);
    expect(out).toBe(`the key is ${T} done`);
  });

  it("redacts a secret split exactly at a chunk boundary", async () => {
    const out = await runThrough(named("sk-abc123def"), ["the key is sk-abc1", "23def and more"]);
    expect(out).toBe(`the key is ${T} and more`);
  });

  it("redacts a secret fed one byte at a time", async () => {
    const secret = "sk-supersecretvalue";
    const chunks = `x ${secret} y`.split("");
    const out = await runThrough(named(secret), chunks);
    expect(out).toBe(`x ${T} y`);
  });

  it("passes through unchanged when the secret never appears", async () => {
    const out = await runThrough(named("sk-neverhere"), ["hello world, nothing to hide"]);
    expect(out).toBe("hello world, nothing to hide");
  });

  it("flushes a secret whose tail is buffered at stream end", async () => {
    const out = await runThrough(named("sk-endsecret"), ["trailing sk-endsecret"]);
    expect(out).toBe(`trailing ${T}`);
  });

  it("does not target secrets of 5 chars or fewer", async () => {
    const out = await runThrough(named("short"), ["a short word"]);
    expect(out).toBe("a short word");
  });

  it("redacts a multi-byte UTF-8 secret split across raw Buffer chunks", async () => {
    // The secret contains multi-byte chars; split its raw bytes at a
    // non-character boundary so a naive chunk.toString() would corrupt it.
    const secret = "pässwörd-sëcret-café";
    const full = Buffer.from(`before ${secret} after`, "utf8");
    // find a split index that lands in the middle of a multi-byte sequence
    let splitAt = full.indexOf(0xc3); // lead byte of ä/ö/ë/é in UTF-8
    expect(splitAt).toBeGreaterThan(0);
    splitAt += 1; // split between the two bytes of the sequence
    const out = await runThrough(named(secret), [
      full.subarray(0, splitAt),
      full.subarray(splitAt),
    ]);
    expect(out).toBe(`before ${T} after`);
  });

  it("redacts a derived (hex) form split across chunks", async () => {
    const hex = Buffer.from(S).toString("hex");
    const line = `dump: ${hex} end`;
    const out = await runThrough(named(S), split(line, 6 + 37));
    expect(out).toBe(`dump: ${T} end`);
  });

  it("redacts a mid-string base64 form fed one byte at a time", async () => {
    const line = `Authorization: Basic ${Buffer.from(`user:${S}`).toString("base64")}\n`;
    const out = await runThrough(named(S), line.split(""));
    expect(out).toMatch(
      /^Authorization: Basic [A-Za-z0-9+/]{0,8}\[QRING:REDACTED:API_KEY\][A-Za-z0-9+/=]{0,4}\n$/,
    );
  });

  it("redacts a slice split across chunks", async () => {
    const line = `head ${S.slice(0, 25)} tail`;
    const out = await runThrough(named(S), split(line, 15));
    expect(out).toBe(`head ${T} tail`);
  });
});

describe("redaction of encoded forms (#121)", () => {
  // A value whose base64 contains both '+' and '/', so standard and URL-safe differ.
  const V = "p~~~s???w>>>rd-0123";

  it("precondition: standard and URL-safe base64 of the test value differ", () => {
    const std = Buffer.from(V).toString("base64");
    expect(std).toMatch(/[+/]/);
    expect(Buffer.from(V).toString("base64url")).not.toBe(std.replace(/=+$/, ""));
  });

  it("standard base64 (padding ignored)", async () => {
    const b64 = Buffer.from(V).toString("base64");
    expect(b64).toMatch(/=$/);
    const out = await runThrough(named(V), [`auth ${b64} end`]);
    expect(out).toMatch(/^auth \[QRING:REDACTED:API_KEY\][A-Za-z0-9+/]?=* end$/);
  });

  it("URL-safe base64", async () => {
    const b64url = Buffer.from(V).toString("base64url");
    const out = await runThrough(named(V), [`?t=${b64url}&x=1`]);
    expect(out).toMatch(/^\?t=\[QRING:REDACTED:API_KEY\][A-Za-z0-9_-]?&x=1$/);
  });

  it("base64 mid-string at all three alignments", async () => {
    for (const prefix of ["", "a", "ab", "user:"]) {
      const b64 = Buffer.from(`${prefix}${S}`).toString("base64");
      const out = await runThrough(named(S), [`Basic ${b64}`]);
      expect(out, `prefix "${prefix}"`).toMatch(
        /^Basic [A-Za-z0-9+/]{0,8}\[QRING:REDACTED:API_KEY\][A-Za-z0-9+/=]{0,4}$/,
      );
    }
  });

  it("lowercase hex of the UTF-8 bytes", async () => {
    const out = await runThrough(named(S), [`hex=${Buffer.from(S).toString("hex")};`]);
    expect(out).toBe(`hex=${T};`);
  });

  it("uppercase hex of the UTF-8 bytes", async () => {
    const out = await runThrough(named(S), [
      `HEX=${Buffer.from(S).toString("hex").toUpperCase()};`,
    ]);
    expect(out).toBe(`HEX=${T};`);
  });

  it("encodeURIComponent form", async () => {
    const value = "p@ss/word:with spaces&more";
    expect(encodeURIComponent(value)).not.toBe(value);
    const out = await runThrough(named(value), [`GET /cb?token=${encodeURIComponent(value)} 200`]);
    expect(out).toBe(`GET /cb?token=${T} 200`);
  });

  it("JSON-escaped form (quotes and backslashes)", async () => {
    const value = 'ab"cd\\ef-gh';
    const out = await runThrough(named(value), [JSON.stringify({ k: value })]);
    expect(out).toBe(`{"k":"${T}"}`);
  });

  it("JSON-escaped form with escaped forward slashes", async () => {
    const value = "pg://u:p@host/db";
    const escaped = JSON.stringify(value).slice(1, -1).replace(/\//g, "\\/");
    const out = await runThrough(named(value), [`{"url":"${escaped}"}`]);
    expect(out).toBe(`{"url":"${T}"}`);
  });
});

describe("redaction of sliced secrets (#122)", () => {
  it("prefix slice", async () => {
    const out = await runThrough(named(S), [`log: ${S.slice(0, 20)}... (truncated)`]);
    expect(out).toBe(`log: ${T}... (truncated)`);
  });

  it("suffix slice", async () => {
    const out = await runThrough(named(S), [`key ending ${S.slice(-18)}!`]);
    expect(out).toBe(`key ending ${T}!`);
  });

  it("mid slice, extended to the whole run", async () => {
    const out = await runThrough(named(S), [`x=${S.slice(10, 30)};`]);
    expect(out).toBe(`x=${T};`);
  });

  it("two slices in one line", async () => {
    const out = await runThrough(named(S), [`a ${S.slice(0, 16)} b ${S.slice(24)} c`]);
    expect(out).toBe(`a ${T} b ${T} c`);
  });

  it("does NOT match a 15-char slice", async () => {
    const line = `a ${S.slice(5, 20)} b`;
    const out = await runThrough(named(S), [line]);
    expect(out).toBe(line);
  });

  it("a verbatim hit is one replacement, not many", async () => {
    const out = await runThrough(named(S), [`pre${S}post ${S}`]);
    expect(out).toBe(`pre${T}post ${T}`);
  });

  it("skips window matching above the cap and warns once, without values", () => {
    resetSliceCapWarning();
    const write = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
    try {
      // Deterministic pseudo-random value with more windows than the cap.
      let x = 7;
      const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
      const big = Array.from({ length: MAX_SLICE_WINDOWS + 100 }, () => {
        x = (Math.imul(x, 1103515245) + 12345) >>> 0;
        return chars[(x >>> 16) % chars.length];
      }).join("");

      const set = new RedactionSet([{ name: "BIG_KEY", value: big }]);
      new RedactionSet([{ name: "BIG_KEY", value: big }]);
      expect(set.slicing).toBe(false);
      expect(write).toHaveBeenCalledTimes(1);
      const msg = String(write.mock.calls[0][0]);
      expect(msg).toContain("cap");
      expect(msg).not.toContain(big.slice(0, 16));
      expect(msg).not.toContain("BIG_KEY");

      // Verbatim still redacted; a slice is not.
      expect(set.redact(`v=${big}`)).toBe("v=[QRING:REDACTED:BIG_KEY]");
      const slice = big.slice(100, 140);
      expect(set.redact(`s=${slice}`)).toBe(`s=${slice}`);

      // Under the cap, slicing stays on.
      expect(
        new RedactionSet([{ name: "K", value: big.slice(0, MAX_SLICE_WINDOWS + 15) }]).slicing,
      ).toBe(true);
    } finally {
      write.mockRestore();
      resetSliceCapWarning();
    }
  });
});

describe("named replacement token (#123)", () => {
  it("names the keyring key the value came from", async () => {
    const out = await runThrough([{ name: "OPENAI_API_KEY", value: S }], [`key=${S}`]);
    expect(out).toBe("key=[QRING:REDACTED:OPENAI_API_KEY]");
  });

  it("falls back to [QRING:REDACTED] when the name is unknown", async () => {
    const out = await runThrough([{ value: S }], [`key=${S} and ${S.slice(0, 20)}`]);
    expect(out).toBe(`key=${R} and ${R}`);
  });

  it("distinguishes two secrets in one line, including derived forms", async () => {
    const other = "other-secret-value-xyz";
    const out = await runThrough(
      [
        { name: "DB_URL", value: other },
        { name: NAME, value: S },
      ],
      [`${other} ${Buffer.from(S).toString("hex")}`],
    );
    expect(out).toBe(`[QRING:REDACTED:DB_URL] ${T}`);
  });

  it("keeps the token parseable for odd key names", () => {
    expect(redactionToken("weird name]")).toBe("[QRING:REDACTED:weird_name_]");
    expect(redactionToken(undefined)).toBe(R);
    expect(redactionToken("")).toBe(R);
  });
});

describe("restricted exec profile denies interpreters (A3)", () => {
  it("lists network tools and interpreters in restricted denyCommands", () => {
    const denies = new Set(getProfile("restricted").denyCommands ?? []);
    for (const c of ["curl", "wget", "python3", "node", "bash", "perl", "ruby"]) {
      expect(denies.has(c)).toBe(true);
    }
  });
});
