import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

vi.mock("@napi-rs/keyring", async () => {
  const fake = await import("../helpers/fake-keyring.js");
  return { Entry: fake.FakeEntry, findCredentials: fake.findCredentials };
});

import { resetFakeKeyring } from "../helpers/fake-keyring.js";
import { setSecret } from "../../core/keyring.js";
import { execCommand } from "../../core/exec.js";
import { isCredentialShapedName, isProcessControlEnvName } from "../../core/child-env.js";
import { clearPolicyCache, setPolicyRoot } from "../../core/policy.js";
import { clearCollapseCache } from "../../core/collapse.js";

const NAMES = [
  "GOAUTH",
  "MAVEN_OPTS",
  "DATABASE_URL",
  "STRIPE_KEY",
  "OPENAI_API_KEY",
  "SENTRY_DSN",
  "MY_CONFIG",
];
// Prints which names reached the child (never their values, which redaction would mask).
const PRINT = `console.log(JSON.stringify(${JSON.stringify(NAMES)}.filter((k) => process.env[k] !== undefined)))`;

let dir: string;

beforeEach(() => {
  resetFakeKeyring();
  clearPolicyCache();
  clearCollapseCache();
  dir = mkdtempSync(join(tmpdir(), "qring-cred-shape-"));
  // A policy but no `secrets` manifest.
  writeFileSync(
    join(dir, ".q-ring.json"),
    JSON.stringify({ policy: { exec: { allowCommands: [process.execPath] } } }),
  );
  setPolicyRoot(dir);
  // Planted by an agent: a Go auth helper and a JVM option hook.
  setSecret("GOAUTH", "command /tmp/evil.sh", { scope: "global", source: "mcp", projectPath: dir });
  setSecret("MAVEN_OPTS", "-XX:OnOutOfMemoryError=/tmp/evil.sh", {
    scope: "global",
    source: "mcp",
    projectPath: dir,
  });
  for (const [k, v] of [
    ["DATABASE_URL", "postgres://u:p@db/app"],
    ["STRIPE_KEY", "sk_live_abcdef123456"],
    ["OPENAI_API_KEY", "sk-openai-abcdef123456"],
    ["SENTRY_DSN", "https://abc@sentry.io/1"],
    ["MY_CONFIG", "config-value-123"],
  ]) {
    setSecret(k, v, { scope: "global", source: "cli" });
  }
});

afterEach(() => {
  vi.restoreAllMocks();
  setPolicyRoot(process.cwd());
  clearPolicyCache();
  clearCollapseCache();
  rmSync(dir, { recursive: true, force: true });
});

const run = (source: "mcp" | "cli", keys?: string[]) =>
  execCommand({
    command: process.execPath,
    args: ["-e", PRINT],
    keys,
    scope: "global",
    projectPath: dir,
    source,
    captureOutput: true,
  });

describe("exec_with_secrets without a manifest injects only credential-shaped names", () => {
  it("planted hooks never reach the child; credential-shaped names do; others are skipped and named", async () => {
    const result = await run("mcp");
    expect(JSON.parse(result.stdout.trim())).toEqual([
      "DATABASE_URL",
      "STRIPE_KEY",
      "OPENAI_API_KEY",
      "SENTRY_DSN",
    ]);
    expect(result.note).toContain("skipped: MY_CONFIG");
    expect(result.note).toContain("declare secrets there to lift this rule");
    // Names only: no value appears in the note.
    expect(result.note).not.toContain("config-value-123");
    // Denylisted names are not "skipped by shape"; they are never candidates.
    expect(result.note).not.toContain("GOAUTH");
  });

  it("naming a non-credential key in `keys` does not lift the rule", async () => {
    const result = await run("mcp", ["MY_CONFIG", "GOAUTH"]);
    expect(JSON.parse(result.stdout.trim())).toEqual([]);
  });

  it("the CLI path still injects MY_CONFIG (and still denies the hooks)", async () => {
    vi.spyOn(process.stderr, "write").mockImplementation(() => true);
    const result = await run("cli");
    const seen = JSON.parse(result.stdout.trim()) as string[];
    expect(seen).toContain("MY_CONFIG");
    expect(seen).not.toContain("GOAUTH");
    expect(seen).not.toContain("MAVEN_OPTS");
  });
});

describe("the new denylist entries", () => {
  it.each([
    "GOAUTH",
    "GOINSECURE",
    "GONOSUMDB",
    "GONOSUMCHECK",
    "GOSUMDB",
    "GOPRIVATE",
    "GOFLAGS",
    "CGO_CFLAGS",
    "CGO_LDFLAGS",
    "TARGET_CC",
    "HOST_CC",
    "MAVEN_OPTS",
    "GRADLE_OPTS",
    "SBT_OPTS",
    "ANT_OPTS",
    "RUSTUP_TOOLCHAIN",
    "JAVA_TOOL_OPTIONS",
    "_JAVA_OPTIONS",
    "JDK_JAVA_OPTIONS",
  ])("%s is denied", (name) => {
    expect(isProcessControlEnvName(name)).toBe(true);
  });

  it("credential names inside a denied family stay injectable; hard prefixes never do", () => {
    expect(isProcessControlEnvName("MAVEN_PASSWORD")).toBe(false);
    expect(isProcessControlEnvName("GRADLE_PUBLISH_KEY")).toBe(false);
    expect(isProcessControlEnvName("BASH_FUNC_X_KEY")).toBe(true);
    expect(isProcessControlEnvName("GIT_CONFIG_KEY")).toBe(true);
  });

  it.each([
    ["DATABASE_URL", true],
    ["SENTRY_DSN", true],
    ["GOOGLE_APPLICATION_CREDENTIALS", true],
    ["TLS_CERT", true],
    ["JWT_SECRET", true],
    ["MY_CONFIG", false],
    ["LOG_LEVEL", false],
    ["KEYBOARD_LAYOUT", false],
  ])("%s credential-shaped: %s", (name, expected) => {
    expect(isCredentialShapedName(name)).toBe(expected);
  });
});
