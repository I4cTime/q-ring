import { describe, it, expect } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { createMcpServer } from "../../mcp/server.js";
import { TOOL_ANNOTATIONS } from "../../mcp/tool-annotations.js";

const HINTS = ["readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"] as const;

async function listTools() {
  const server = createMcpServer();
  const client = new Client({ name: "annotations-test", version: "1.0" });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  await client.connect(clientTransport);
  const { tools } = await client.listTools();
  await client.close();
  await server.close();
  return tools;
}

describe("MCP tool annotations", () => {
  it("every registered tool advertises all four behavior hints", async () => {
    const tools = await listTools();
    expect(tools.length).toBeGreaterThan(0);
    for (const tool of tools) {
      const a = tool.annotations;
      expect(a, `${tool.name} has no annotations`).toBeDefined();
      for (const hint of HINTS) {
        expect(typeof a?.[hint], `${tool.name}.${hint} is not a boolean`).toBe("boolean");
      }
    }
  });

  it("the annotations table and the registered tools match exactly", async () => {
    const tools = await listTools();
    const registered = tools.map((t) => t.name).sort();
    const tabled = Object.keys(TOOL_ANNOTATIONS).sort();
    expect(tabled).toEqual(registered);
  });

  it("read-only tools are never marked destructive", async () => {
    const tools = await listTools();
    for (const tool of tools) {
      if (tool.annotations?.readOnlyHint) {
        expect(tool.annotations.destructiveHint, `${tool.name} is read-only yet destructive`).toBe(
          false,
        );
      }
    }
  });

  it("tools whose descriptions declare themselves read-only carry readOnlyHint", async () => {
    const tools = await listTools();
    for (const tool of tools) {
      // Sentence-initial "Read-only" is an unconditional claim; mid-sentence
      // mentions ("without saveAs the call is read-only") are conditional.
      if (/(^|[.;] )Read-only\b/.test(tool.description ?? "")) {
        expect(
          tool.annotations?.readOnlyHint,
          `${tool.name} says read-only but is not annotated so`,
        ).toBe(true);
      }
    }
  });
});
