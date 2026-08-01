import { describe, it, expect } from "vitest";
import { RedactionTransform, getProfile } from "../../core/exec.js";

function runThrough(
  patterns: string[],
  chunks: (string | Buffer)[],
): Promise<string> {
  const t = new RedactionTransform(patterns);
  const out: Buffer[] = [];
  return new Promise((resolve, reject) => {
    t.on("data", (d) => out.push(Buffer.isBuffer(d) ? d : Buffer.from(d)));
    t.on("end", () => resolve(Buffer.concat(out).toString("utf8")));
    t.on("error", reject);
    for (const c of chunks) t.write(c);
    t.end();
  });
}

const R = "[QRING:REDACTED]";

describe("RedactionTransform chunk boundaries", () => {
  it("redacts a secret contained in one chunk", async () => {
    const out = await runThrough(["sk-abc123def"], ["the key is sk-abc123def done"]);
    expect(out).toContain(R);
    expect(out).not.toContain("sk-abc123def");
  });

  it("redacts a secret split exactly at a chunk boundary", async () => {
    const out = await runThrough(["sk-abc123def"], ["the key is sk-abc1", "23def and more"]);
    expect(out).not.toContain("sk-abc123def");
    expect(out).toContain(R);
  });

  it("redacts a secret fed one byte at a time", async () => {
    const secret = "sk-supersecretvalue";
    const chunks = `x ${secret} y`.split("").map((ch) => ch);
    const out = await runThrough([secret], chunks);
    expect(out).not.toContain(secret);
  });

  it("passes through unchanged when the secret never appears", async () => {
    const out = await runThrough(["sk-neverhere"], ["hello world, nothing to hide"]);
    expect(out).toBe("hello world, nothing to hide");
  });

  it("flushes a secret whose tail is buffered at stream end", async () => {
    const out = await runThrough(["sk-endsecret"], ["trailing sk-endsecret"]);
    expect(out).not.toContain("sk-endsecret");
    expect(out).toContain(R);
  });

  it("does not target secrets of 5 chars or fewer", async () => {
    const out = await runThrough(["short"], ["a short word"]);
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
    const out = await runThrough([secret], [full.subarray(0, splitAt), full.subarray(splitAt)]);
    expect(out).not.toContain(secret);
    expect(out).toContain(R);
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
