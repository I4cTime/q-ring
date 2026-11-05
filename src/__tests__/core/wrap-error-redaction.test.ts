import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { ErrorCode, McpError } from "@modelcontextprotocol/sdk/types.js";

vi.mock("@napi-rs/keyring", async () => {
  const fake = await import("../helpers/fake-keyring.js");
  return { Entry: fake.FakeEntry, findCredentials: fake.findCredentials };
});

import { createAirlockServer } from "../../core/wrap.js";
import { createRedactor } from "../../core/wrap-redact.js";
import { queryAudit } from "../../core/observer.js";
import { clearPolicyCache, setPolicyRoot } from "../../core/policy.js";
import { setSecret } from "../../core/keyring.js";
import { resetFakeKeyring } from "../helpers/fake-keyring.js";

const SECRET = "sk-live-ERRPATH-0123456789abcdef";

let auditDir: string;
let projectDir: string;

type Behaviour = {
  callTool?: (opts: {
    onprogress?: (p: { progress: number; message?: string }) => void;
  }) => unknown;
  readResource?: () => unknown;
  getPrompt?: () => unknown;
};

/**
 * A downstream client stub: the airlock only uses this surface, and a stub
 * lets the test choose exactly what the wrapped server throws or reports.
 */
function stubDownstream(b: Behaviour): Client {
  return {
    getServerVersion: () => ({ name: "hostile-downstream", version: "1.0.0" }),
    getServerCapabilities: () => ({ tools: {}, resources: {}, prompts: {} }),
    getInstructions: () => undefined,
    setNotificationHandler: () => {},
    listTools: async () => ({ tools: [{ name: "t", inputSchema: { type: "object" } }] }),
    listResources: async () => ({ resources: [] }),
    listResourceTemplates: async () => ({ resourceTemplates: [] }),
    listPrompts: async () => ({ prompts: [] }),
    callTool: async (
      _p: unknown,
      _s: unknown,
      opts: Parameters<NonNullable<Behaviour["callTool"]>>[0],
    ) => b.callTool!(opts),
    readResource: async () => b.readResource!(),
    getPrompt: async () => b.getPrompt!(),
  } as unknown as Client;
}

async function connect(b: Behaviour) {
  const proxy = createAirlockServer(
    stubDownstream(b),
    { label: "hostile", correlationId: "wrap-err-session" },
    { projectPath: projectDir, redactor: createRedactor({ projectPath: projectDir }) },
  );
  const [hostSide, proxySide] = InMemoryTransport.createLinkedPair();
  await proxy.connect(proxySide);
  const host = new Client({ name: "test-host", version: "1.0.0" });
  await host.connect(hostSide);
  return host;
}

function auditText(): string {
  return JSON.stringify(queryAudit());
}

beforeEach(() => {
  resetFakeKeyring();
  auditDir = mkdtempSync(join(tmpdir(), "qring-wrap-err-audit-"));
  projectDir = mkdtempSync(join(tmpdir(), "qring-wrap-err-proj-"));
  process.env.QRING_AUDIT_DIR = auditDir;
  setPolicyRoot(projectDir);
  setSecret("STRIPE_KEY", SECRET, { scope: "global", source: "cli", silent: true });
});

afterEach(() => {
  delete process.env.QRING_AUDIT_DIR;
  rmSync(auditDir, { recursive: true, force: true });
  rmSync(projectDir, { recursive: true, force: true });
  clearPolicyCache();
});

describe("airlock: downstream text outside results is redacted too", () => {
  it("a JSON-RPC error from a tool call", async () => {
    const host = await connect({
      callTool: () => {
        throw new McpError(ErrorCode.InvalidParams, `401 for token ${SECRET}`, { token: SECRET });
      },
    });
    const err = await host.callTool({ name: "t", arguments: {} }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(McpError);
    expect((err as McpError).code).toBe(ErrorCode.InvalidParams);
    expect((err as McpError).message).not.toContain(SECRET);
    expect((err as McpError).message).toContain("401 for token");
    expect(JSON.stringify((err as McpError).data ?? null)).not.toContain(SECRET);
  });

  it("a plain error from a tool call, in the result and in the audit log", async () => {
    const host = await connect({
      callTool: () => {
        throw new Error(`connection refused using ${SECRET}`);
      },
    });
    const res = (await host.callTool({ name: "t", arguments: {} })) as {
      content: { text: string }[];
      isError?: boolean;
    };
    expect(res.isError).toBe(true);
    expect(res.content[0].text).toContain("airlock: downstream error: connection refused using");
    expect(res.content[0].text).not.toContain(SECRET);
    expect(auditText()).toContain("connection refused using");
    expect(auditText()).not.toContain(SECRET);
  });

  it("a progress message relayed to the host", async () => {
    const host = await connect({
      callTool: (opts) => {
        opts.onprogress?.({ progress: 1, message: `using ${SECRET}` });
        return { content: [{ type: "text", text: "ok" }] };
      },
    });
    const messages: string[] = [];
    await host.callTool({ name: "t", arguments: {} }, undefined, {
      onprogress: (p) => {
        if (p.message) messages.push(p.message);
      },
    });
    await vi.waitFor(() => expect(messages).toHaveLength(1));
    expect(messages[0]).toContain("using ");
    expect(messages[0]).not.toContain(SECRET);
  });

  it("errors from resource reads and prompt gets, and the audited resource URI", async () => {
    const host = await connect({
      readResource: () => {
        throw new McpError(ErrorCode.InternalError, `cannot open db with ${SECRET}`);
      },
      getPrompt: () => {
        throw new Error(`prompt store auth ${SECRET} rejected`);
      },
    });
    const readErr = await host
      .readResource({ uri: `db://app?password=${SECRET}` })
      .catch((e: unknown) => e as Error);
    expect(readErr.message).toContain("cannot open db with");
    expect(readErr.message).not.toContain(SECRET);

    const promptErr = await host.getPrompt({ name: "p" }).catch((e: unknown) => e as Error);
    expect(promptErr.message).toContain("rejected");
    expect(promptErr.message).not.toContain(SECRET);

    expect(auditText()).toContain("resource read db://app?password=");
    expect(auditText()).not.toContain(SECRET);
  });
});
