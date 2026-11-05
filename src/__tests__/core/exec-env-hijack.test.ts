import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { chmodSync, existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";

vi.mock("@napi-rs/keyring", async () => {
  const fake = await import("../helpers/fake-keyring.js");
  return { Entry: fake.FakeEntry, findCredentials: fake.findCredentials };
});

import { resetFakeKeyring } from "../helpers/fake-keyring.js";
import { setSecret } from "../../core/keyring.js";
import { execCommand } from "../../core/exec.js";
import { hasEnvNameShape, isProcessControlEnvName } from "../../core/child-env.js";
import { clearPolicyCache, setPolicyRoot } from "../../core/policy.js";

/** What exec does with a keyring key name over MCP: inject or not. */
const blockedOverMcp = (name: string) => !hasEnvNameShape(name) || isProcessControlEnvName(name);

describe("child-hijacking variable names are never injected over MCP", () => {
  it.each([
    // bash exported functions and other non-identifier names
    "BASH_FUNC_ls%%",
    "BASH_FUNC_echo%%",
    "BASH_FUNC_ls",
    "() { :; }",
    "with.dot",
    "with-dash",
    "1LEADING_DIGIT",
    "",
    // interpreters and loaders
    "LUA_INIT",
    "LUA_INIT_5_4",
    "NODE_OPTIONS",
    "LD_PRELOAD",
    "DYLD_INSERT_LIBRARIES",
    "PYTHONSTARTUP",
    "PERL5OPT",
    "RUBYOPT",
    "JAVA_TOOL_OPTIONS",
    "_JAVA_OPTIONS",
    "JDK_JAVA_OPTIONS",
    "BASH_ENV",
    "ENV",
    "PATH",
    // helpers tools spawn
    "GIT_EXTERNAL_DIFF",
    "GIT_SSH_COMMAND",
    "GIT_SSL_NO_VERIFY",
    "SSH_ASKPASS",
    "PAGER",
    "EDITOR",
    "MAKEFLAGS",
    "RUSTC_WRAPPER",
    // network hijack: proxies and trust stores
    "HTTP_PROXY",
    "http_proxy",
    "HTTPS_PROXY",
    "https_proxy",
    "ALL_PROXY",
    "all_proxy",
    "NO_PROXY",
    "no_proxy",
    "OPENSSL_CONF",
    "OPENSSL_MODULES",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "CURL_CA_BUNDLE",
    "REQUESTS_CA_BUNDLE",
    "NODE_EXTRA_CA_CERTS",
    "AWS_CA_BUNDLE",
    // package managers and runtimes
    "PIP_INDEX_URL",
    "PIP_CONFIG_FILE",
    "COMPOSER_HOME",
    "GEM_HOME",
    "BUNDLE_GEMFILE",
    "NIX_PATH",
    "DOTNET_STARTUP_HOOKS",
    "GOFLAGS",
    // inline-code gadgets in common tools
    "TAR_OPTIONS",
    "CFLAGS",
    "CXXFLAGS",
    "CPPFLAGS",
    "LDFLAGS",
    "RSYNC_RSH",
    "RSYNC_CONNECT_PROG",
    "CVS_RSH",
    "SVN_SSH",
    "KUBECTL_EXTERNAL_DIFF",
    "CLASSPATH",
    "PHPRC",
    "UV_INDEX_URL",
    "POETRY_REPOSITORIES_X_URL",
    "PIPENV_PYPI_MIRROR",
    "CONDA_PREFIX",
    "CLOUDSDK_PYTHON",
    "GH_HOST",
  ])("%s", (name) => {
    expect(blockedOverMcp(name)).toBe(true);
  });

  it.each([
    "API_TOKEN",
    "DATABASE_URL",
    "NPM_TOKEN",
    "GEM_HOST_API_KEY",
    "OPENAI_API_KEY",
    "GH_TOKEN",
  ])("%s stays injectable", (name) => {
    expect(blockedOverMcp(name)).toBe(false);
  });
});

describe.skipIf(process.platform === "win32" || !existsSync("/bin/bash"))(
  "the bash exported-function gadget, run for real",
  () => {
    let dir: string;

    beforeEach(() => {
      resetFakeKeyring();
      clearPolicyCache();
      dir = mkdtempSync(join(tmpdir(), "qring-bashfunc-"));
      setPolicyRoot(dir);
      // What an agent plants with set_secret: an exported `ls` function.
      setSecret("BASH_FUNC_ls%%", "() { echo PWNED; }", {
        scope: "global",
        source: "mcp",
        projectPath: dir,
      });
    });

    afterEach(() => {
      setPolicyRoot(process.cwd());
      clearPolicyCache();
      rmSync(dir, { recursive: true, force: true });
    });

    const run = (command: string, args: string[], allow: string) => {
      writeFileSync(
        join(dir, ".q-ring.json"),
        JSON.stringify({ policy: { exec: { allowCommands: [allow] } } }),
      );
      clearPolicyCache();
      return execCommand({
        command,
        args,
        projectPath: dir,
        scope: "global",
        source: "mcp",
        captureOutput: true,
      });
    };

    it("a #!/bin/bash script that calls ls", async () => {
      const script = join(dir, "build.sh");
      writeFileSync(script, `#!/bin/bash\nls "${dir}" > /dev/null\nls -d "${dir}"\n`);
      chmodSync(script, 0o755);
      const result = await run(script, [], script);
      expect(result.stdout).not.toContain("PWNED");
      expect(result.stdout).toContain(dir);
    });

    it.skipIf(!existsSync("/bin/sh"))("sh -c ls (bash as /bin/sh, posix mode)", async () => {
      const result = await run("/bin/sh", ["-c", `ls -d "${dir}"`], "/bin/sh -c ls");
      expect(result.stdout).not.toContain("PWNED");
    });
  },
);

function isGnuTar(): boolean {
  try {
    return execFileSync("tar", ["--version"], { encoding: "utf8" }).includes("GNU tar");
  } catch {
    return false;
  }
}

describe.skipIf(process.platform === "win32" || !isGnuTar())(
  "the tar --checkpoint-action gadget, run for real",
  () => {
    let dir: string;
    let marker: string;

    beforeEach(() => {
      resetFakeKeyring();
      clearPolicyCache();
      dir = mkdtempSync(join(tmpdir(), "qring-tar-gadget-"));
      marker = join(dir, "PWNED");
      const payload = join(dir, "payload.sh");
      writeFileSync(payload, `#!/bin/sh\ntouch "${marker}"\n`);
      chmodSync(payload, 0o755);
      writeFileSync(join(dir, "input.txt"), "data\n");
      writeFileSync(
        join(dir, ".q-ring.json"),
        JSON.stringify({ policy: { exec: { allowCommands: ["tar -cf"] } } }),
      );
      setPolicyRoot(dir);
      setSecret("TAR_OPTIONS", `--checkpoint=1 --checkpoint-action=exec=${payload}`, {
        scope: "global",
        source: "mcp",
        projectPath: dir,
      });
    });

    afterEach(() => {
      setPolicyRoot(process.cwd());
      clearPolicyCache();
      rmSync(dir, { recursive: true, force: true });
    });

    it.each(["mcp", "cli"] as const)(
      "an allowlisted `tar -cf` (%s) does not run it",
      async (source) => {
        await execCommand({
          command: "tar",
          args: ["-cf", join(dir, "out.tar"), "-C", dir, "input.txt"],
          projectPath: dir,
          scope: "global",
          source,
          captureOutput: true,
        });
        expect(existsSync(marker)).toBe(false);
      },
    );
  },
);
