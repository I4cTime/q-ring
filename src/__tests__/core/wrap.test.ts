import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  McpError,
  ErrorCode,
  ListToolsRequestSchema,
  CallToolRequestSchema,
  ToolListChangedNotificationSchema,
} from "@modelcontextprotocol/sdk/types.js";

vi.mock("@napi-rs/keyring", async () => {
  const fake = await import("../helpers/fake-keyring.js");
  return { Entry: fake.FakeEntry, findCredentials: fake.findCredentials };
});

import { createAirlockServer } from "../../core/wrap.js";
import { queryAudit, setAuditAgentLabel } from "../../core/observer.js";
import { resetFakeKeyring } from "../helpers/fake-keyring.js";

let auditDir: string;

/** Fake downstream MCP server with one working and one failing tool. */
function buildDownstream(): McpServer {
  const server = new McpServer({ name: "fake-downstream", version: "1.0.0" });
  server.tool("echo", "Echoes the message back", { msg: z.string() }, async ({ msg }) => ({
    content: [{ type: "text", text: `echo: ${msg}` }],
  }));
  server.tool("explode", "Always fails", {}, async () => {
    throw new Error("downstream boom");
  });
  server.tool("ticker", "Reports progress", {}, async (_args, extra) => {
    for (let i = 1; i <= 3; i++) {
      await extra.sendNotification({
        method: "notifications/progress",
        params: {
          progressToken: extra._meta?.progressToken ?? 0,
          progress: i,
          total: 3,
        },
      });
    }
    return { content: [{ type: "text", text: "done" }] };
  });
  return server;
}

/** Wire downstream server ↔ airlock ↔ host client over in-memory transports. */
async function buildAirlock() {
  const downstream = buildDownstream();
  const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
  await downstream.connect(serverSide);

  const downstreamClient = new Client({ name: "q-ring-airlock", version: "test" });
  await downstreamClient.connect(clientSide);

  const proxy = createAirlockServer(downstreamClient, {
    label: "fake-downstream-cmd",
    correlationId: "wrap-test-session",
  });
  const [hostSide, proxySide] = InMemoryTransport.createLinkedPair();
  await proxy.connect(proxySide);

  const host = new Client({ name: "test-host", version: "9.9.9" });
  await host.connect(hostSide);

  return { host, proxy, downstream, downstreamClient };
}

beforeEach(() => {
  resetFakeKeyring();
  setAuditAgentLabel(null);
  auditDir = mkdtempSync(join(tmpdir(), "qring-wrap-"));
  process.env.QRING_AUDIT_DIR = auditDir;
});
afterEach(() => {
  setAuditAgentLabel(null);
  delete process.env.QRING_AUDIT_DIR;
  rmSync(auditDir, { recursive: true, force: true });
});

describe("mcp airlock proxy", () => {
  it("advertises the downstream identity behind the airlock banner", async () => {
    const { host } = await buildAirlock();
    expect(host.getServerVersion()?.name).toBe("fake-downstream (q-ring airlock)");
  });

  it("forwards tools/list verbatim", async () => {
    const { host } = await buildAirlock();
    const { tools } = await host.listTools();
    const names = tools.map((t) => t.name).sort();
    expect(names).toEqual(["echo", "explode", "ticker"]);
    const echo = tools.find((t) => t.name === "echo")!;
    expect(echo.description).toBe("Echoes the message back");
    expect(echo.inputSchema.properties).toHaveProperty("msg");
  });

  it("forwards tool calls and audits them without logging arguments", async () => {
    const { host } = await buildAirlock();
    const result = await host.callTool({
      name: "echo",
      arguments: { msg: "super-secret-value" },
    });
    expect((result.content as Array<{ text: string }>)[0].text).toBe(
      "echo: super-secret-value",
    );

    const events = queryAudit({ action: "wrap", correlationId: "wrap-test-session" });
    expect(events.length).toBe(1);
    expect(events[0].detail).toContain('tool call "echo"');
    expect(events[0].detail).toContain("fake-downstream-cmd");
    // Arguments may contain secrets — they must never reach the audit log.
    expect(JSON.stringify(events[0])).not.toContain("super-secret-value");
  });

  it("stamps audited calls with the host client's identity label", async () => {
    const { host } = await buildAirlock();
    await host.callTool({ name: "echo", arguments: { msg: "hi" } });
    const events = queryAudit({ action: "wrap", correlationId: "wrap-test-session" });
    expect(events[0].agent).toBe("test-host@9.9.9");
  });

  it("surfaces downstream failures as isError results, not crashes", async () => {
    const { host } = await buildAirlock();
    const result = await host.callTool({ name: "explode", arguments: {} });
    // The MCP SDK converts handler throws into isError results downstream;
    // whichever side reports it, the host sees a failed-call result and the
    // airlock stays up.
    expect(result.isError).toBe(true);
    const text = (result.content as Array<{ text: string }>)[0].text;
    expect(text).toContain("downstream boom");

    // Airlock still healthy afterwards.
    const ok = await host.callTool({ name: "echo", arguments: { msg: "alive" } });
    expect((ok.content as Array<{ text: string }>)[0].text).toBe("echo: alive");
  });

  it("passes downstream protocol errors through as JSON-RPC errors, not isError results", async () => {
    // High-level McpServer downstreams convert unknown-tool to isError
    // themselves (forwarded verbatim, tested above via `explode`). Low-level
    // Server downstreams answer with real JSON-RPC errors — the airlock must
    // not rewrite THOSE into successful-looking isError results.
    const raw = new Server(
      { name: "raw-downstream", version: "1.0.0" },
      { capabilities: { tools: {} } },
    );
    raw.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: [] }));
    raw.setRequestHandler(CallToolRequestSchema, async () => {
      throw new McpError(ErrorCode.InvalidParams, "Tool no_such_tool not found");
    });
    const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
    await raw.connect(serverSide);
    const downstreamClient = new Client({ name: "q-ring-airlock", version: "test" });
    await downstreamClient.connect(clientSide);

    const proxy = createAirlockServer(downstreamClient, {
      label: "raw",
      correlationId: "wrap-test-raw",
    });
    const [hostSide, proxySide] = InMemoryTransport.createLinkedPair();
    await proxy.connect(proxySide);
    const host = new Client({ name: "test-host", version: "9.9.9" });
    await host.connect(hostSide);

    await expect(
      host.callTool({ name: "no_such_tool", arguments: {} }),
    ).rejects.toBeInstanceOf(McpError);
  });

  it("relays progress notifications under the host's own token", async () => {
    const { host } = await buildAirlock();
    const seen: Array<{ progress: number; total?: number }> = [];
    const result = await host.callTool(
      { name: "ticker", arguments: {} },
      undefined,
      { onprogress: (p) => seen.push(p) },
    );
    expect((result.content as Array<{ text: string }>)[0].text).toBe("done");
    expect(seen.map((p) => p.progress)).toEqual([1, 2, 3]);
    expect(seen[0].total).toBe(3);
  });

  it("relays tools/list_changed from a dynamic downstream", async () => {
    const { host, downstream } = await buildAirlock();
    const notified = new Promise<void>((resolve) => {
      host.setNotificationHandler(ToolListChangedNotificationSchema, () => {
        resolve();
        return Promise.resolve();
      });
    });
    await downstream.server.sendToolListChanged();
    await notified; // resolves only if the airlock relayed it
  });

  it("answers tools/list with an empty list for a downstream without tools", async () => {
    const bare = new McpServer({ name: "no-tools", version: "1.0.0" });
    const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
    await bare.connect(serverSide);
    const downstreamClient = new Client({ name: "q-ring-airlock", version: "test" });
    await downstreamClient.connect(clientSide);

    const proxy = createAirlockServer(downstreamClient, {
      label: "bare",
      correlationId: "wrap-test-bare",
    });
    const [hostSide, proxySide] = InMemoryTransport.createLinkedPair();
    await proxy.connect(proxySide);
    const host = new Client({ name: "test-host", version: "9.9.9" });
    await host.connect(hostSide);

    const { tools } = await host.listTools();
    expect(tools).toEqual([]);
  });

  it("audits one wrap event per call", async () => {
    const { host } = await buildAirlock();
    await host.callTool({ name: "echo", arguments: { msg: "1" } });
    await host.callTool({ name: "echo", arguments: { msg: "2" } });
    await host.callTool({ name: "explode", arguments: {} });
    const events = queryAudit({ action: "wrap", correlationId: "wrap-test-session" });
    expect(events.length).toBe(3);
  });
});
