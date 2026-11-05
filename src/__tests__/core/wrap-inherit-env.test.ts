import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { connectDownstream } from "../../core/wrap.js";

/**
 * A dependency-free stdio MCP server: answers initialize, tools/list and one
 * tools/call ("env") that reports the variables it was started with.
 */
const STUB_SERVER = `
const readline = require("node:readline");
const rl = readline.createInterface({ input: process.stdin });
const send = (msg) => process.stdout.write(JSON.stringify(msg) + "\\n");
rl.on("line", (line) => {
  let msg;
  try { msg = JSON.parse(line); } catch { return; }
  if (msg.id === undefined) return;
  if (msg.method === "initialize") {
    send({ jsonrpc: "2.0", id: msg.id, result: {
      protocolVersion: msg.params.protocolVersion,
      capabilities: { tools: {} },
      serverInfo: { name: "env-stub", version: "1.0.0" },
    } });
  } else if (msg.method === "tools/list") {
    send({ jsonrpc: "2.0", id: msg.id, result: { tools: [
      { name: "env", inputSchema: { type: "object" } },
    ] } });
  } else if (msg.method === "tools/call") {
    const pick = ["QRING_FILE_PASSPHRASE", "QRING_MEMORY_PASSPHRASE", "QRING_TEST_UNRELATED"];
    const seen = Object.fromEntries(pick.map((k) => [k, process.env[k] ?? null]));
    send({ jsonrpc: "2.0", id: msg.id, result: { content: [{ type: "text", text: JSON.stringify(seen) }] } });
  } else {
    send({ jsonrpc: "2.0", id: msg.id, error: { code: -32601, message: "not found" } });
  }
});
`;

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "qring-wrap-inherit-"));
  writeFileSync(join(dir, "stub-server.cjs"), STUB_SERVER);
  process.env.QRING_FILE_PASSPHRASE = "file-store-master-key";
  process.env.QRING_MEMORY_PASSPHRASE = "memory-master-key";
  process.env.QRING_TEST_UNRELATED = "present";
});

afterEach(() => {
  delete process.env.QRING_FILE_PASSPHRASE;
  delete process.env.QRING_MEMORY_PASSPHRASE;
  delete process.env.QRING_TEST_UNRELATED;
  rmSync(dir, { recursive: true, force: true });
});

describe("qring mcp wrap --inherit-env", () => {
  it("passes the parent environment minus q-ring's master keys", async () => {
    const client = await connectDownstream({
      command: process.execPath,
      args: [join(dir, "stub-server.cjs")],
      inheritEnv: true,
    });
    try {
      const res = (await client.callTool({ name: "env", arguments: {} })) as {
        content: { text: string }[];
      };
      const seen = JSON.parse(res.content[0].text) as Record<string, string | null>;
      expect(seen.QRING_FILE_PASSPHRASE).toBeNull();
      expect(seen.QRING_MEMORY_PASSPHRASE).toBeNull();
      expect(seen.QRING_TEST_UNRELATED).toBe("present");
    } finally {
      await client.close();
    }
  });
});
