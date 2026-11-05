import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { chmodSync, existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

vi.mock("@napi-rs/keyring", async () => {
  const fake = await import("../helpers/fake-keyring.js");
  return { Entry: fake.FakeEntry, findCredentials: fake.findCredentials };
});

import { resetFakeKeyring } from "../helpers/fake-keyring.js";
import { setSecret } from "../../core/keyring.js";
import { execCommand } from "../../core/exec.js";
import { isProcessControlEnvName } from "../../core/child-env.js";
import { clearPolicyCache, setPolicyRoot } from "../../core/policy.js";

/**
 * Gadgets: an agent that may only run an allowlisted git or make command
 * plants a secret whose NAME is a variable the tool obeys. On the base the
 * child runs the planted program and the marker appears.
 */
let dir: string;
let marker: string;
let payload: string;

function allow(commands: string[]): void {
  writeFileSync(
    join(dir, ".q-ring.json"),
    JSON.stringify({ policy: { exec: { allowCommands: commands } } }),
  );
  clearPolicyCache();
}

beforeEach(() => {
  resetFakeKeyring();
  clearPolicyCache();
  dir = mkdtempSync(join(tmpdir(), "qring-exec-gadget-"));
  marker = join(dir, "PWNED");
  payload = join(dir, "payload.sh");
  writeFileSync(payload, `#!/bin/sh\ntouch "${marker}"\n`);
  chmodSync(payload, 0o755);
  setPolicyRoot(dir);
});

afterEach(() => {
  setPolicyRoot(process.cwd());
  clearPolicyCache();
  rmSync(dir, { recursive: true, force: true });
});

const plant = (name: string, value: string) =>
  setSecret(name, value, { scope: "global", source: "mcp", projectPath: dir });

const run = (command: string, args: string[]) =>
  execCommand({
    command,
    args,
    projectPath: dir,
    scope: "global",
    source: "mcp",
    captureOutput: true,
  });

describe.skipIf(process.platform === "win32")(
  "allowlisted tools cannot be steered by planted env vars",
  () => {
    it("git diff with GIT_EXTERNAL_DIFF", async () => {
      const a = join(dir, "a.txt");
      const b = join(dir, "b.txt");
      writeFileSync(a, "one\n");
      writeFileSync(b, "two\n");
      allow(["git diff"]);
      plant("GIT_EXTERNAL_DIFF", payload);

      await run("git", ["diff", "--no-index", a, b]);

      expect(existsSync(marker)).toBe(false);
    });

    it("make with MAKEFILES", async () => {
      const makefile = join(dir, "Makefile");
      writeFileSync(makefile, "all:\n\t@true\n");
      writeFileSync(join(dir, "evil.mk"), `$(shell ${payload})\n`);
      allow(["make -f"]);
      plant("MAKEFILES", join(dir, "evil.mk"));

      await run("make", ["-f", makefile, "all"]);

      expect(existsSync(marker)).toBe(false);
    });

    it("make with MAKEFLAGS", async () => {
      const makefile = join(dir, "Makefile");
      writeFileSync(makefile, "all:\n\t@true\n");
      allow(["make -f"]);
      plant("MAKEFLAGS", `--eval=$(shell ${payload})`);

      await run("make", ["-f", makefile, "all"]);

      expect(existsSync(marker)).toBe(false);
    });
  },
);

describe("process-control families", () => {
  it("denies the helper, toolchain and config-path families", () => {
    for (const name of [
      "GIT_EXTERNAL_DIFF",
      "GIT_ASKPASS",
      "GIT_PROXY_COMMAND",
      "GIT_PAGER",
      "GIT_CONFIG_KEY_0",
      "SSH_ASKPASS",
      "PAGER",
      "EDITOR",
      "VISUAL",
      "BROWSER",
      "MAKEFLAGS",
      "MAKEFILES",
      "RUSTC_WRAPPER",
      "RUSTC",
      "CARGO_BUILD_RUSTC_WRAPPER",
      "GLIBC_TUNABLES",
      "GOFLAGS",
      "GOTOOLCHAIN",
      "NODE_EXTRA_CA_CERTS",
      "PYTHONWARNINGS",
      "HOME",
      "SHELL",
      "TMPDIR",
      "KUBECONFIG",
      "DOCKER_HOST",
      "AWS_CONFIG_FILE",
      "CC",
      "LESSOPEN",
    ]) {
      expect(isProcessControlEnvName(name), name).toBe(true);
    }
  });

  it("keeps credentials that live inside a family injectable", () => {
    for (const name of [
      "NPM_TOKEN",
      "NODE_AUTH_TOKEN",
      "CARGO_REGISTRY_TOKEN",
      "SSH_PRIVATE_KEY",
      "NODE_ENV",
      "GOOGLE_API_KEY",
      "GITHUB_TOKEN",
      "AWS_SECRET_ACCESS_KEY",
    ]) {
      expect(isProcessControlEnvName(name), name).toBe(false);
    }
  });
});
