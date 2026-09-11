#!/usr/bin/env node
/**
 * Build a cross-platform MCPB bundle (.mcpb) of the published q-ring
 * release — the format Smithery (and MCPB-aware clients) install from.
 *
 *   node scripts/build-mcpb.mjs            # bundles the version in package.json
 *   node scripts/build-mcpb.mjs 0.14.1     # bundles an explicit npm version
 *
 * Strategy: vendor the PUBLISHED npm package (not the working tree) plus
 * every mainstream @napi-rs/keyring platform binary, so one bundle runs on
 * macOS / Linux / Windows, x64 + arm64 (glibc & musl). npm normally refuses
 * foreign-platform binaries; --force overrides. Output lands in
 * dist-mcpb/qring-<version>.mcpb (~13 MB packed).
 *
 * Smithery gotcha: the manifest must NOT declare a `tools` array —
 * `smithery mcp publish` rejects bundles that do (smithery-ai/cli#787),
 * and Smithery does NOT scan local bundles, so a CLI publish leaves the
 * listing with "No capabilities found" and Capability Quality 0/40. This
 * script therefore also runs the vendored server, captures its real
 * `tools/list`, and writes a Smithery deploy payload
 * (dist-mcpb/qring-<version>.smithery.json) that
 * scripts/smithery-publish.mjs sends straight to the registry API.
 */
import { execSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync, copyFileSync, readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
const version = process.argv[2] ?? pkg.version;

const KEYRING_VERSION = pkg.dependencies["@napi-rs/keyring"].replace(/^\^/, "");
const PLATFORM_PKGS = [
  "darwin-arm64",
  "darwin-x64",
  "win32-x64-msvc",
  "win32-arm64-msvc",
  "linux-x64-gnu",
  "linux-arm64-gnu",
  "linux-x64-musl",
  "linux-arm64-musl",
];

const stage = join(tmpdir(), `qring-mcpb-${version}`);
rmSync(stage, { recursive: true, force: true });
mkdirSync(stage, { recursive: true });

writeFileSync(
  join(stage, "package.json"),
  JSON.stringify(
    {
      name: "q-ring-bundle",
      version,
      private: true,
      dependencies: {
        "@i4ctime/q-ring": version,
        ...Object.fromEntries(PLATFORM_PKGS.map((p) => [`@napi-rs/keyring-${p}`, KEYRING_VERSION])),
      },
    },
    null,
    2,
  ),
);

writeFileSync(
  join(stage, "manifest.json"),
  JSON.stringify(
    {
      manifest_version: "0.2",
      name: "q-ring",
      display_name: "q-ring",
      version,
      description: "OS keychain secrets for AI coding agents, over MCP.",
      long_description:
        "q-ring anchors secrets to your OS's native vault — macOS Keychain, Linux " +
        "Secret Service, Windows Credential Vault — and exposes them through 44 " +
        "policy-governed MCP tools. Environment-aware values (superposition), " +
        "TTL/decay, linked rotation (entanglement), encrypted transfer bundles, " +
        "redacted exec, and a tamper-evident audit log. Local-first: no cloud " +
        "account. AGPL-3.0.",
      author: { name: "I4C Studio", email: "i4c.studio.dev@gmail.com", url: "https://i4c.studio" },
      homepage: "https://qring.i4c.studio",
      documentation: "https://qring.i4c.studio/docs",
      support: "https://github.com/I4cTime/q-ring/issues",
      license: "AGPL-3.0-only",
      repository: { type: "git", url: "https://github.com/I4cTime/q-ring" },
      keywords: ["secrets", "keychain", "security", "mcp", "api-keys", "credentials"],
      icon: "icon.png",
      server: {
        type: "node",
        entry_point: "node_modules/@i4ctime/q-ring/dist/mcp.js",
        mcp_config: {
          command: "node",
          args: ["${__dirname}/node_modules/@i4ctime/q-ring/dist/mcp.js"],
          env: { QRING_ENV: "${user_config.qring_env}" },
        },
      },
      // Smithery's deploy step 400s ("No values to set") on manifests with no
      // icon/user_config to project into the listing — keep both present.
      user_config: {
        qring_env: {
          type: "string",
          title: "Environment override",
          description:
            "Force a q-ring environment context (dev, staging, prod). Leave " +
            "empty to auto-detect from QRING_ENV/NODE_ENV/git branch.",
          required: false,
        },
      },
      compatibility: { platforms: ["darwin", "linux", "win32"], runtimes: { node: ">=20" } },
    },
    null,
    2,
  ),
);
copyFileSync(join(root, "assets", "icon-512.png"), join(stage, "icon.png"));

const run = (cmd, cwd) => execSync(cmd, { cwd, stdio: "inherit" });
run("npm install --omit=dev --no-audit --no-fund --force", stage);
run("npx -y @anthropic-ai/mcpb validate manifest.json", stage);

// Smoke test + capability capture: run the vendored entry the way a client
// would (initialize → initialized → tools/list) in a scrubbed env with no
// keychain, no dbus and an empty HOME — the same conditions as a fresh
// install — and keep the tool list for the Smithery deploy payload.
const entry = "node_modules/@i4ctime/q-ring/dist/mcp.js";
const rpc = [
  {
    jsonrpc: "2.0",
    id: 1,
    method: "initialize",
    params: {
      protocolVersion: "2025-06-18",
      capabilities: {},
      clientInfo: { name: "build-mcpb", version: "1.0" },
    },
  },
  { jsonrpc: "2.0", method: "notifications/initialized" },
  { jsonrpc: "2.0", id: 2, method: "tools/list" },
];
const probeHome = mkdtempSync(join(tmpdir(), "qring-mcpb-probe-"));
const probe = execSync(`node ${entry}`, {
  cwd: stage,
  input: rpc.map((m) => JSON.stringify(m)).join("\n") + "\n",
  env: { PATH: process.env.PATH, HOME: probeHome },
  timeout: 20000,
}).toString();
rmSync(probeHome, { recursive: true, force: true });
const replies = probe
  .split("\n")
  .filter(Boolean)
  .map((l) => {
    try {
      return JSON.parse(l);
    } catch {
      return null;
    }
  });
const init = replies.find((r) => r?.id === 1)?.result;
const tools = replies.find((r) => r?.id === 2)?.result?.tools;
if (init?.serverInfo?.version !== version) {
  console.error("smoke test failed — server did not report the expected version:\n" + probe);
  process.exit(1);
}
if (!Array.isArray(tools) || tools.length === 0 || tools.some((t) => !t.inputSchema)) {
  console.error("smoke test failed — tools/list returned no usable tools:\n" + probe);
  process.exit(1);
}
console.log(
  `tools/list: ${tools.length} tools, ${tools.filter((t) => t.description).length} with descriptions`,
);

const outDir = join(root, "dist-mcpb");
mkdirSync(outDir, { recursive: true });
const bundleName = `qring-${version}.mcpb`;
run(`npx -y @anthropic-ai/mcpb pack . ${bundleName}`, stage);
copyFileSync(join(stage, bundleName), join(outDir, bundleName));
// Smithery deploy payload — the same shape `smithery mcp publish` builds
// from the manifest (see getBundleDeployPayload in smithery-ai/cli), but with
// serverCard.tools filled from the live tools/list above, which the manifest
// format cannot express (MCPB forbids inputSchema; the registry requires it).
const configSchema = {
  type: "object",
  required: [],
  properties: {
    qring_env: {
      type: "string",
      title: "Environment override",
      description:
        "Force a q-ring environment context (dev, staging, prod). Leave empty to auto-detect from QRING_ENV/NODE_ENV/git branch.",
    },
  },
};
const payload = {
  type: "stdio",
  runtime: "node",
  configSchema,
  serverCard: {
    serverInfo: { name: "q-ring", version },
    tools: tools.map(({ name, description, inputSchema, outputSchema, annotations }) => ({
      name,
      description,
      inputSchema,
      ...(outputSchema ? { outputSchema } : {}),
      ...(annotations ? { annotations } : {}),
    })),
  },
};
const payloadName = `qring-${version}.smithery.json`;
writeFileSync(join(outDir, payloadName), JSON.stringify(payload, null, 2));
console.log(`\nbundle:  dist-mcpb/${bundleName}`);
console.log(`payload: dist-mcpb/${payloadName}`);
console.log(`publish: node scripts/smithery-publish.mjs dist-mcpb/${bundleName} -n i4ctime/q-ring`);
