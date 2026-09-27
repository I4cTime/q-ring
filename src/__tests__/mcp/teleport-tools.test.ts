import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateKeyPairSync } from "node:crypto";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

vi.mock("@napi-rs/keyring", async () => {
  const fake = await import("../helpers/fake-keyring.js");
  return { Entry: fake.FakeEntry, findCredentials: fake.findCredentials };
});

import { resetFakeKeyring } from "../helpers/fake-keyring.js";
import { setSecret, getSecret } from "../../core/keyring.js";
import {
  formatRecipient,
  generateTeleportIdentity,
  teleportUnpackWith,
  inspectTeleportBundle,
} from "../../core/teleport.js";
import { registerTeleportTools } from "../../mcp/tools/teleport.js";

type Handler = (params: Record<string, unknown>) => Promise<{
  content: { type: "text"; text: string }[];
  isError?: boolean;
}>;

/** Capture the tool callbacks without spinning up a real MCP transport. */
function captureTools(): Map<string, Handler> {
  const tools = new Map<string, Handler>();
  const stub = {
    tool: (name: string, ..._rest: unknown[]) => {
      const handler = _rest[_rest.length - 1] as Handler;
      tools.set(name, handler);
    },
  };
  registerTeleportTools(stub as unknown as McpServer);
  return tools;
}

let project: string;
let pack: Handler;
let unpack: Handler;

beforeEach(() => {
  resetFakeKeyring();
  project = mkdtempSync(join(tmpdir(), "qring-teleport-mcp-"));
  const tools = captureTools();
  pack = tools.get("teleport_pack")!;
  unpack = tools.get("teleport_unpack")!;
  setSecret("API_KEY", "sk-live-1", { scope: "project", projectPath: project, silent: true });
  setSecret("DB_PASS", "hunter2", { scope: "project", projectPath: project, silent: true });
});

afterEach(() => {
  rmSync(project, { recursive: true, force: true });
});

describe("teleport_pack (MCP)", () => {
  it("requires exactly one of passphrase or recipients", async () => {
    const neither = await pack({ scope: "project", projectPath: project });
    expect(neither.isError).toBe(true);
    expect(neither.content[0].text).toMatch(/exactly one/);

    const { publicKey } = generateKeyPairSync("x25519");
    const both = await pack({
      scope: "project",
      projectPath: project,
      passphrase: "pw",
      recipients: [formatRecipient(publicKey)],
    });
    expect(both.isError).toBe(true);

    const emptyList = await pack({ scope: "project", projectPath: project, recipients: [] });
    expect(emptyList.isError).toBe(true);
  });

  it("rejects a malformed recipient before reading any secret", async () => {
    const res = await pack({
      scope: "project",
      projectPath: project,
      recipients: ["qring1-not-a-key"],
    });
    expect(res.isError).toBe(true);
    expect(res.content[0].text).toMatch(/ERR_TELEPORT_BAD_RECIPIENT/);
  });

  it("still packs v1 with a passphrase", async () => {
    const res = await pack({ scope: "project", projectPath: project, passphrase: "pw" });
    expect(res.isError).toBeUndefined();
    expect(inspectTeleportBundle(res.content[0].text)).toEqual({ v: 1, count: 2 });
  });

  it("packs a v2 recipient bundle (comma-separated recipients allowed)", async () => {
    const a = generateKeyPairSync("x25519");
    const b = generateKeyPairSync("x25519");
    const res = await pack({
      scope: "project",
      projectPath: project,
      keys: ["API_KEY"],
      recipients: [`${formatRecipient(a.publicKey)}, ${formatRecipient(b.publicKey)}`],
    });
    expect(res.isError).toBeUndefined();
    const bundle = res.content[0].text;
    const info = inspectTeleportBundle(bundle);
    expect(info.v).toBe(2);
    if (info.v === 2) expect(info.recipients).toHaveLength(2);
    const payload = teleportUnpackWith(bundle, b.privateKey);
    expect(payload.secrets).toEqual([{ key: "API_KEY", value: "sk-live-1", scope: "project" }]);
  });
});

describe("teleport_unpack (MCP)", () => {
  it("unpacks a v2 bundle with the keyring identity and never returns key material", async () => {
    const me = generateTeleportIdentity();
    const packed = await pack({
      scope: "project",
      projectPath: project,
      recipients: [me.recipient],
    });
    const bundle = packed.content[0].text;

    const dry = await unpack({ bundle, dryRun: true, scope: "global" });
    expect(dry.isError).toBeUndefined();
    expect(dry.content[0].text).toContain(`${me.id} (you)`);
    expect(dry.content[0].text).toContain("Would import 2 secrets");
    expect(dry.content[0].text).not.toContain("PRIVATE");
    expect(dry.content[0].text).not.toContain(me.recipient);
    expect(getSecret("API_KEY", { scope: "global" })).toBeNull();

    const wet = await unpack({ bundle, dryRun: false, scope: "global" });
    expect(wet.isError).toBeUndefined();
    expect(wet.content[0].text).toBe("Imported 2 secret(s) from teleport bundle");
    expect(getSecret("API_KEY", { scope: "global" })).toBe("sk-live-1");
    expect(getSecret("DB_PASS", { scope: "global" })).toBe("hunter2");
  });

  it("errors with the keygen hint when there is no identity", async () => {
    const { publicKey } = generateKeyPairSync("x25519");
    const packed = await pack({
      scope: "project",
      projectPath: project,
      recipients: [formatRecipient(publicKey)],
    });
    const res = await unpack({ bundle: packed.content[0].text, dryRun: true, scope: "global" });
    expect(res.isError).toBe(true);
    const body = JSON.parse(res.content[0].text) as { ok: boolean; error: { message: string } };
    expect(body.ok).toBe(false);
    expect(body.error.message).toMatch(/ERR_TELEPORT_NO_IDENTITY.*keygen/);
  });

  it("errors when the bundle is addressed to someone else", async () => {
    generateTeleportIdentity();
    const { publicKey } = generateKeyPairSync("x25519");
    const packed = await pack({
      scope: "project",
      projectPath: project,
      recipients: [formatRecipient(publicKey)],
    });
    const res = await unpack({ bundle: packed.content[0].text, dryRun: true, scope: "global" });
    expect(res.isError).toBe(true);
    expect(res.content[0].text).toMatch(/ERR_TELEPORT_NOT_A_RECIPIENT/);
  });

  it("v1 bundles still need a passphrase and reject a wrong one", async () => {
    const packed = await pack({ scope: "project", projectPath: project, passphrase: "pw" });
    const bundle = packed.content[0].text;

    const missing = await unpack({ bundle, dryRun: true, scope: "global" });
    expect(missing.isError).toBe(true);
    expect(missing.content[0].text).toMatch(/ERR_TELEPORT_PASSPHRASE_REQUIRED/);

    const wrong = await unpack({ bundle, passphrase: "nope", dryRun: true, scope: "global" });
    expect(wrong.isError).toBe(true);
    expect(wrong.content[0].text).toMatch(/ERR_TELEPORT_BAD_PASSPHRASE/);

    const ok = await unpack({ bundle, passphrase: "pw", dryRun: true, scope: "global" });
    expect(ok.isError).toBeUndefined();
    expect(ok.content[0].text).toContain("Would import 2 secrets");
  });
});
