import { describe, it, expect, afterAll, vi } from "vitest";

vi.mock("@napi-rs/keyring", async () => {
  const fake = await import("../helpers/fake-keyring.js");
  return { Entry: fake.FakeEntry, findCredentials: fake.findCredentials };
});

import { lintFiles } from "../../core/linter.js";
import { setSecret, getSecret } from "../../core/keyring.js";
import { setPolicyRoot, clearPolicyCache } from "../../core/policy.js";
import { resetFakeKeyring } from "../helpers/fake-keyring.js";
import {
  writeFileSync,
  readFileSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  statSync,
  utimesSync,
} from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

const TMP_DIR = join(tmpdir(), `qring-lint-test-${Date.now()}`);

function setup() {
  mkdirSync(TMP_DIR, { recursive: true });
}

afterAll(() => {
  rmSync(TMP_DIR, { recursive: true, force: true });
});

describe("lintFiles", () => {
  it("detects secrets in a file without fixing", () => {
    setup();
    const file = join(TMP_DIR, "app.ts");
    writeFileSync(
      file,
      'const api_key = "sk-abcdef1234567890abcdef1234567890";\n',
    );
    const results = lintFiles([file]);
    expect(results.length).toBeGreaterThanOrEqual(1);
    expect(results[0].fixed).toBe(false);
  });

  it("returns empty for clean files", () => {
    setup();
    const file = join(TMP_DIR, "clean.ts");
    writeFileSync(file, 'const name = "hello world";\n');
    const results = lintFiles([file]);
    expect(results).toHaveLength(0);
  });

  it("skips nonexistent files", () => {
    const results = lintFiles(["/tmp/does-not-exist-qring-lint.ts"]);
    expect(results).toHaveLength(0);
  });

  it("ignores placeholder values", () => {
    setup();
    const file = join(TMP_DIR, "safe.py");
    writeFileSync(file, 'password = "replace_me_with_real_password"\n');
    const results = lintFiles([file]);
    expect(results).toHaveLength(0);
  });
});

describe("lintFiles --fix from an MCP caller", () => {
  it("skips a key policy denies with a reason and keeps fixing the other files", () => {
    resetFakeKeyring();
    clearPolicyCache();
    const dir = mkdtempSync(join(tmpdir(), "qring-lint-mcp-"));
    try {
      writeFileSync(
        join(dir, ".q-ring.json"),
        JSON.stringify({ policy: { mcp: { deniedKeys: ["PASSWORD"] } } }),
      );
      setPolicyRoot(dir);
      setSecret("PASSWORD", "the-real-protected-value", { scope: "global", source: "cli" });

      const file1 = join(dir, "one.ts");
      const file2 = join(dir, "two.ts");
      const file3 = join(dir, "three.ts");
      writeFileSync(file1, 'const api_key = "sk-abcdef1234567890abcdef1234567890";\n');
      writeFileSync(file2, 'const password = "Xq9vL2mR7tK4pW8zN3bY6cH1";\n');
      writeFileSync(file3, 'const secret_token = "sk-zyxwvu0987654321zyxwvu0987654321";\n');

      const results = lintFiles([file1, file2, file3], {
        fix: true,
        scope: "global",
        projectPath: dir,
        source: "mcp",
      });

      const byKey = Object.fromEntries(results.map((r) => [r.keyName, r]));
      expect(byKey.API_KEY.fixed).toBe(true);
      expect(byKey.SECRET_TOKEN.fixed).toBe(true);
      expect(byKey.PASSWORD.fixed).toBe(false);
      expect(byKey.PASSWORD.skipped).toMatch(/denied by project policy/);

      // file1 and file3 rewritten and stored; file2 untouched; the
      // protected value is unchanged.
      expect(readFileSync(file1, "utf8")).toContain("process.env.API_KEY");
      expect(readFileSync(file3, "utf8")).toContain("process.env.SECRET_TOKEN");
      expect(readFileSync(file2, "utf8")).toContain("Xq9vL2mR7tK4pW8zN3bY6cH1");
      expect(getSecret("API_KEY", { scope: "global", silent: true })).toBe(
        "sk-abcdef1234567890abcdef1234567890",
      );
      expect(getSecret("SECRET_TOKEN", { scope: "global", silent: true })).toBe(
        "sk-zyxwvu0987654321zyxwvu0987654321",
      );
      expect(getSecret("PASSWORD", { scope: "global", silent: true })).toBe(
        "the-real-protected-value",
      );
    } finally {
      setPolicyRoot(process.cwd());
      clearPolicyCache();
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("lintFiles --fix leaves a file alone when nothing in it was fixed", () => {
  it("is byte-identical, CRLF included, with an unchanged mtime", () => {
    resetFakeKeyring();
    clearPolicyCache();
    const dir = mkdtempSync(join(tmpdir(), "qring-lint-noop-"));
    try {
      writeFileSync(
        join(dir, ".q-ring.json"),
        JSON.stringify({ policy: { mcp: { deniedKeys: ["PASSWORD"] } } }),
      );
      setPolicyRoot(dir);
      setSecret("PASSWORD", "the-real-protected-value", { scope: "global", source: "cli" });

      const crlf = join(dir, "crlf.ts");
      const lf = join(dir, "lf.ts");
      const crlfBytes =
        'const x = 1;\r\nconst password = "Xq9vL2mR7tK4pW8zN3bY6cH1";\r\nexport {};\r\n';
      const lfBytes = 'const password = "Xq9vL2mR7tK4pW8zN3bY6cH1";\n';
      writeFileSync(crlf, crlfBytes);
      writeFileSync(lf, lfBytes);
      const past = new Date("2026-01-01T00:00:00Z");
      utimesSync(crlf, past, past);
      utimesSync(lf, past, past);

      const results = lintFiles([crlf, lf], {
        fix: true,
        scope: "global",
        projectPath: dir,
        source: "mcp",
      });

      expect(results.every((r) => r.skipped)).toBe(true);
      expect(readFileSync(crlf, "utf8")).toBe(crlfBytes);
      expect(readFileSync(lf, "utf8")).toBe(lfBytes);
      expect(statSync(crlf).mtimeMs).toBe(past.getTime());
      expect(statSync(lf).mtimeMs).toBe(past.getTime());
    } finally {
      setPolicyRoot(process.cwd());
      clearPolicyCache();
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
