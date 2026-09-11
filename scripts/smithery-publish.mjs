#!/usr/bin/env node
/**
 * Publish an MCPB bundle to Smithery straight through the registry API,
 * bypassing `smithery mcp publish`.
 *
 *   node scripts/smithery-publish.mjs dist-mcpb/qring-<version>.mcpb -n i4ctime/q-ring [--dry-run]
 *
 * Why not the CLI: it builds the release's serverCard from manifest.json
 * only, and the MCPB manifest cannot carry tool inputSchemas (MCPB forbids
 * the key; the registry requires it — smithery-ai/cli#787). Bundles
 * published via the CLI therefore list with "No capabilities found" and a
 * Capability Quality score of 0/40. The API's PUT /servers/{name}/releases
 * accepts the full serverCard directly, so we send the one
 * scripts/build-mcpb.mjs captured from the server's real tools/list
 * (dist-mcpb/qring-<version>.smithery.json, expected next to the bundle).
 *
 * Auth: SMITHERY_API_KEY (same value `smithery auth whoami --full` prints).
 * Polls the release until it reaches a terminal status.
 */
import { readFileSync, statSync } from "node:fs";
import { basename } from "node:path";

const API = "https://api.smithery.ai";
const args = process.argv.slice(2);
const dryRun = args.includes("--dry-run");
const nameIdx = args.indexOf("-n");
const qualifiedName = nameIdx >= 0 ? args[nameIdx + 1] : undefined;
const bundlePath = args.find((a) => a.endsWith(".mcpb"));
if (!bundlePath || !qualifiedName) {
  console.error("usage: smithery-publish.mjs <bundle.mcpb> -n <namespace/server> [--dry-run]");
  process.exit(2);
}
const payloadPath = bundlePath.replace(/\.mcpb$/, ".smithery.json");
const payload = JSON.parse(readFileSync(payloadPath, "utf8"));
const tools = payload.serverCard?.tools ?? [];
if (payload.type !== "stdio" || tools.length === 0 || tools.some((t) => !t.inputSchema)) {
  console.error(`refusing to publish: ${payloadPath} has no usable serverCard.tools`);
  process.exit(1);
}
const version = payload.serverCard.serverInfo.version;
const size = statSync(bundlePath).size;
console.log(
  `${qualifiedName} v${version}: ${basename(bundlePath)} (${(size / 1048576).toFixed(1)} MB), ${tools.length} tools`,
);
if (dryRun) {
  console.log("dry run — not publishing");
  process.exit(0);
}

const key = process.env.SMITHERY_API_KEY;
if (!key) {
  console.error("SMITHERY_API_KEY is not set");
  process.exit(1);
}
const encoded = encodeURIComponent(qualifiedName);
const headers = { Authorization: `Bearer ${key}` };

const form = new FormData();
form.append("payload", JSON.stringify(payload));
form.append(
  "bundle",
  new Blob([readFileSync(bundlePath)], { type: "application/zip" }),
  "server.mcpb",
);
const res = await fetch(`${API}/servers/${encoded}/releases`, {
  method: "PUT",
  headers,
  body: form,
});
const text = await res.text();
if (!res.ok) {
  console.error(`publish failed: ${res.status} ${text}`);
  process.exit(1);
}
const { deploymentId, status, warnings } = JSON.parse(text);
for (const w of warnings ?? []) console.warn(`warning: ${w}`);
console.log(`release ${deploymentId} accepted (${status})`);

const TERMINAL = new Set(["SUCCESS", "FAILURE", "FAILURE_SCAN", "CANCELLED", "CANCELED"]);
let final = status;
const deadline = Date.now() + 5 * 60 * 1000;
while (!TERMINAL.has(final) && Date.now() < deadline) {
  await new Promise((r) => setTimeout(r, 5000));
  const poll = await fetch(`${API}/servers/${encoded}/releases/${deploymentId}`, { headers });
  if (!poll.ok) {
    console.warn(`poll: ${poll.status}`);
    continue;
  }
  const body = await poll.json();
  if (body.status !== final) console.log(`status: ${body.status}`);
  final = body.status;
  if (TERMINAL.has(final))
    for (const l of body.logs ?? [])
      console.log(`  ${typeof l === "string" ? l : (l.message ?? JSON.stringify(l))}`);
}
if (final !== "SUCCESS") {
  console.error(`release ended with status ${final}`);
  process.exit(1);
}
console.log(`published: https://smithery.ai/servers/${qualifiedName}`);
