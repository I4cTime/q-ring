import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { z } from "zod";
import { McpServer, ResourceTemplate } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";

vi.mock("@napi-rs/keyring", async () => {
  const fake = await import("../helpers/fake-keyring.js");
  return { Entry: fake.FakeEntry, findCredentials: fake.findCredentials };
});

import { createAirlockServer, WRAP_APPROVAL_SCOPE, wrapApprovalService } from "../../core/wrap.js";
import { createRedactor, REDACTED } from "../../core/wrap-redact.js";
import { queryAudit, setAuditAgentLabel } from "../../core/observer.js";
import { clearPolicyCache, setPolicyRoot } from "../../core/policy.js";
import { grantApproval } from "../../core/approval.js";
import { setSecret } from "../../core/keyring.js";
import { resetFakeKeyring } from "../helpers/fake-keyring.js";

let auditDir: string;
let projectDir: string;
const SECRET = "sk-live-EXFIL-ME-0123456789abcdef";

function writePolicy(policy: unknown) {
  writeFileSync(join(projectDir, ".q-ring.json"), JSON.stringify({ policy }));
  clearPolicyCache();
}

/** Downstream with tools, a static + templated resource, and a prompt. */
function buildDownstream(): McpServer {
  const server = new McpServer({ name: "rich-downstream", version: "2.0.0" });
  server.tool("echo", "Echoes", { msg: z.string() }, async ({ msg }) => ({
    content: [{ type: "text", text: `echo: ${msg}` }],
  }));
  server.tool("leak", "Returns the operator's secret", {}, async () => ({
    content: [{ type: "text", text: `token=${SECRET} done` }],
    structuredContent: { token: SECRET },
  }));
  server.tool("deploy_prod", "Needs approval", {}, async () => ({
    content: [{ type: "text", text: "deployed" }],
  }));
  server.tool("rm_rf", "Denied by policy", {}, async () => ({
    content: [{ type: "text", text: "gone" }],
  }));
  server.registerResource(
    "config",
    "cfg://app",
    { title: "App config", mimeType: "text/plain" },
    async (uri) => ({ contents: [{ uri: uri.href, text: `api_key=${SECRET}` }] }),
  );
  server.registerResource(
    "note",
    new ResourceTemplate("note://{id}", { list: undefined }),
    { title: "Note" },
    async (uri, { id }) => ({ contents: [{ uri: uri.href, text: `note ${id}` }] }),
  );
  server.registerPrompt(
    "summarize",
    { description: "Summarize", argsSchema: { topic: z.string() } },
    async ({ topic }) => ({
      messages: [
        { role: "user", content: { type: "text", text: `Summarize ${topic} using ${SECRET}` } },
      ],
    }),
  );
  return server;
}

async function buildAirlock(opts: { redact?: boolean } = {}) {
  const downstream = buildDownstream();
  const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
  await downstream.connect(serverSide);
  const downstreamClient = new Client({ name: "q-ring-airlock", version: "test" });
  await downstreamClient.connect(clientSide);

  const redactor = opts.redact ? createRedactor({ projectPath: projectDir }) : undefined;
  const proxy = createAirlockServer(
    downstreamClient,
    { label: "rich-cmd", correlationId: "wrap-v2-session" },
    { projectPath: projectDir, redactor },
  );
  const [hostSide, proxySide] = InMemoryTransport.createLinkedPair();
  await proxy.connect(proxySide);
  const host = new Client({ name: "test-host", version: "1.0.0" });
  await host.connect(hostSide);
  return { host, proxy, downstream, downstreamClient };
}

const text = (r: unknown) => (r as { content: Array<{ text: string }> }).content[0].text;

beforeEach(() => {
  resetFakeKeyring();
  setAuditAgentLabel(null);
  auditDir = mkdtempSync(join(tmpdir(), "qring-wrapv2-audit-"));
  projectDir = mkdtempSync(join(tmpdir(), "qring-wrapv2-proj-"));
  mkdirSync(projectDir, { recursive: true });
  process.env.QRING_AUDIT_DIR = auditDir;
  setPolicyRoot(projectDir);
});
afterEach(() => {
  setAuditAgentLabel(null);
  delete process.env.QRING_AUDIT_DIR;
  rmSync(auditDir, { recursive: true, force: true });
  rmSync(projectDir, { recursive: true, force: true });
  clearPolicyCache();
});

describe("airlock v2: resources and prompts passthrough", () => {
  it("advertises only the capabilities the downstream has", async () => {
    const { host } = await buildAirlock();
    const caps = host.getServerCapabilities()!;
    expect(caps.tools).toBeDefined();
    expect(caps.resources).toBeDefined();
    expect(caps.prompts).toBeDefined();
  });

  it("lists and reads resources, auditing the URI", async () => {
    const { host } = await buildAirlock();
    const { resources } = await host.listResources();
    expect(resources.map((r) => r.uri)).toContain("cfg://app");
    const { resourceTemplates } = await host.listResourceTemplates();
    expect(resourceTemplates.map((t) => t.uriTemplate)).toContain("note://{id}");

    const read = await host.readResource({ uri: "note://42" });
    expect((read.contents[0] as { text: string }).text).toBe("note 42");

    const events = queryAudit({ action: "wrap", correlationId: "wrap-v2-session" });
    expect(events.some((e) => e.detail?.includes("resource read note://42"))).toBe(true);
  });

  it("lists and gets prompts without logging arguments", async () => {
    const { host } = await buildAirlock();
    const { prompts } = await host.listPrompts();
    expect(prompts.map((p) => p.name)).toContain("summarize");
    const got = await host.getPrompt({ name: "summarize", arguments: { topic: "TOPSECRET-ARG" } });
    expect((got.messages[0].content as { text: string }).text).toContain("Summarize TOPSECRET-ARG");
    const events = queryAudit({ action: "wrap", correlationId: "wrap-v2-session" });
    expect(events.some((e) => e.detail?.includes('prompt get "summarize"'))).toBe(true);
    expect(JSON.stringify(events)).not.toContain("TOPSECRET-ARG");
  });
});

describe("airlock v2: result redaction", () => {
  beforeEach(() => {
    setSecret("STRIPE_KEY", SECRET, { scope: "global", silent: true });
  });

  it("scrubs known secret values from tool results, structured content, resources and prompts", async () => {
    const { host } = await buildAirlock({ redact: true });
    const call = await host.callTool({ name: "leak", arguments: {} });
    expect(text(call)).toBe(`token=${REDACTED} done`);
    expect((call.structuredContent as { token: string }).token).toBe(REDACTED);

    const read = await host.readResource({ uri: "cfg://app" });
    expect((read.contents[0] as { text: string }).text).toBe(`api_key=${REDACTED}`);

    const got = await host.getPrompt({ name: "summarize", arguments: { topic: "x" } });
    expect((got.messages[0].content as { text: string }).text).not.toContain(SECRET);
  });

  it("does not touch results when no redactor is wired", async () => {
    const { host } = await buildAirlock({ redact: false });
    const call = await host.callTool({ name: "leak", arguments: {} });
    expect(text(call)).toContain(SECRET);
  });

  it("silent reads for the redaction set never write audit events", async () => {
    await buildAirlock({ redact: true }).then(({ host }) =>
      host.callTool({ name: "leak", arguments: {} }),
    );
    expect(queryAudit({ action: "read", key: "STRIPE_KEY" })).toHaveLength(0);
  });
});

describe("airlock v2: wrap policy", () => {
  it("hides denied tools from tools/list and refuses calls with a policy_deny audit", async () => {
    writePolicy({ wrap: { denyTools: ["rm_*"] } });
    const { host } = await buildAirlock();
    const { tools } = await host.listTools();
    expect(tools.map((t) => t.name)).not.toContain("rm_rf");
    expect(tools.map((t) => t.name)).toContain("echo");

    const result = await host.callTool({ name: "rm_rf", arguments: {} });
    expect(result.isError).toBe(true);
    expect(text(result)).toContain("policy denied");
    const denials = queryAudit({ action: "policy_deny", correlationId: "wrap-v2-session" });
    expect(denials).toHaveLength(1);
    expect(denials[0].detail).toContain('"rm_rf"');
    // Nothing was forwarded.
    expect(queryAudit({ action: "wrap", correlationId: "wrap-v2-session" })).toHaveLength(0);
  });

  it("gates approveTools behind a live qring mcp approve grant", async () => {
    writePolicy({ wrap: { approveTools: ["deploy_*"] } });
    const { host } = await buildAirlock();
    const blocked = await host.callTool({ name: "deploy_prod", arguments: {} });
    expect(blocked.isError).toBe(true);
    expect(text(blocked)).toContain("qring mcp approve deploy_prod");

    grantApproval("deploy_prod", WRAP_APPROVAL_SCOPE, wrapApprovalService(projectDir), 60, {
      reason: "test",
    });
    const ok = await host.callTool({ name: "deploy_prod", arguments: {} });
    expect(ok.isError).toBeFalsy();
    expect(text(ok)).toBe("deployed");
  });

  it("enforces sliding-window rate limits per tool", async () => {
    writePolicy({ wrap: { toolRateLimits: { echo: { maxCalls: 2, perSeconds: 60 } } } });
    const { host } = await buildAirlock();
    for (let i = 0; i < 2; i++) {
      const r = await host.callTool({ name: "echo", arguments: { msg: "hi" } });
      expect(r.isError).toBeFalsy();
    }
    const third = await host.callTool({ name: "echo", arguments: { msg: "hi" } });
    expect(third.isError).toBe(true);
    expect(text(third)).toContain("rate limit exceeded");
    // Other tools are unaffected.
    const other = await host.callTool({ name: "deploy_prod", arguments: {} });
    expect(other.isError).toBeFalsy();
  });

  it("fails closed when the policy file is invalid", async () => {
    writePolicy({ wrap: { denytools: ["x"] } });
    const { host } = await buildAirlock();
    const { tools } = await host.listTools();
    expect(tools).toHaveLength(0);
    const r = await host.callTool({ name: "echo", arguments: { msg: "hi" } });
    expect(r.isError).toBe(true);
    expect(text(r)).toContain("Invalid policy");
  });
});
