import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { basename, dirname, join } from "node:path";
import { tmpdir } from "node:os";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";

vi.mock("@napi-rs/keyring", async () => {
  const fake = await import("../helpers/fake-keyring.js");
  return { Entry: fake.FakeEntry, findCredentials: fake.findCredentials };
});

// Canary trips raise desktop notices and webhook sends; keep both offline.
vi.mock("../../core/notify.js", () => ({
  notificationsEnabled: vi.fn(() => false),
  notifyUser: vi.fn(() => true),
}));
const httpRequestMock = vi.hoisted(() => vi.fn());
vi.mock("../../utils/http-request.js", () => ({ httpRequest: httpRequestMock }));

import { createMcpServer } from "../../mcp/server.js";
import { CANARY_RESOURCE_ENV } from "../../mcp/resources.js";
import { logAudit, setAuditAgentLabel } from "../../core/observer.js";
import { clearPolicyCache, setPolicyRoot } from "../../core/policy.js";
import { setSecret, getSecret, deleteSecret } from "../../core/keyring.js";
import { plantCanary } from "../../core/canary.js";
import { resetCanaryAlertThrottle } from "../../core/canary-alert.js";
import { addCanaryAlert } from "../../core/canary-webhooks.js";
import { resetFakeKeyring } from "../helpers/fake-keyring.js";

const DAY_MS = 86_400_000;

let auditDir: string;
let projectDir: string;
const originalCwd = process.cwd();

beforeEach(() => {
  resetFakeKeyring();
  resetCanaryAlertThrottle();
  setAuditAgentLabel(null);
  httpRequestMock.mockReset();
  httpRequestMock.mockResolvedValue({ statusCode: 204, body: "" });
  auditDir = mkdtempSync(join(tmpdir(), "qring-introspect-audit-"));
  projectDir = mkdtempSync(join(tmpdir(), "qring-introspect-project-"));
  process.env.QRING_AUDIT_DIR = auditDir;
  process.env.QRING_CANARY_ALERTS_PATH = join(auditDir, "canary-alerts.json");
  delete process.env[CANARY_RESOURCE_ENV];
  process.chdir(projectDir);
  clearPolicyCache();
});
afterEach(() => {
  vi.useRealTimers();
  setAuditAgentLabel(null);
  process.chdir(originalCwd);
  setPolicyRoot(originalCwd);
  clearPolicyCache();
  delete process.env.QRING_AUDIT_DIR;
  delete process.env.QRING_CANARY_ALERTS_PATH;
  delete process.env[CANARY_RESOURCE_ENV];
  rmSync(auditDir, { recursive: true, force: true });
  rmSync(projectDir, { recursive: true, force: true });
});

function textOf(result: { contents: ({ text?: string } | { blob?: string })[] }): string {
  const first = result.contents[0];
  if (!("text" in first) || typeof first.text !== "string")
    throw new Error("expected text contents");
  return first.text;
}

async function read(uri: string): Promise<{ text: string; json: Record<string, unknown> }> {
  const server = createMcpServer();
  const client = new Client({ name: "introspect-test", version: "1.0" });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  await client.connect(clientTransport);
  try {
    const res = await client.readResource({ uri });
    expect(res.contents[0].mimeType).toBe("application/json");
    const text = textOf(res);
    return { text, json: JSON.parse(text) as Record<string, unknown> };
  } finally {
    await client.close();
    await server.close();
  }
}

function writePolicy(policy: unknown) {
  writeFileSync(join(projectDir, ".q-ring.json"), JSON.stringify({ policy }));
  clearPolicyCache();
}

/** Store a secret whose value last changed `daysAgo` days ago. */
function setAged(key: string, value: string, daysAgo: number, rotateEveryDays?: number) {
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(Date.now() - daysAgo * DAY_MS);
  setSecret(key, value, { scope: "global", rotateEveryDays, source: "cli" });
  vi.useRealTimers();
}

describe("MCP resources: introspection", () => {
  it("advertises qring://policy, qring://rotation and qring://canaries", async () => {
    const server = createMcpServer();
    const client = new Client({ name: "introspect-test", version: "1.0" });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    await client.connect(clientTransport);
    try {
      const { resources } = await client.listResources();
      const byUri = new Map(resources.map((r) => [r.uri, r]));
      for (const uri of ["qring://policy", "qring://rotation", "qring://canaries"]) {
        const r = byUri.get(uri);
        expect(r, uri).toBeDefined();
        expect(r!.mimeType).toBe("application/json");
        expect(r!.description).toMatch(/Never contains secret values/);
      }
      // Standing rule: resources only, the tool count does not move.
      const { tools } = await client.listTools();
      expect(tools).toHaveLength(46);
    } finally {
      await client.close();
      await server.close();
    }
  });
});

describe("qring://policy", () => {
  it("says there is no policy instead of erroring", async () => {
    const { json } = await read("qring://policy");
    expect(json).toMatchObject({
      valid: true,
      hasPolicy: false,
      sections: [],
      hasMcpPolicy: false,
      hasExecPolicy: false,
      hasSecretPolicy: false,
      hasWrapPolicy: false,
      details: {},
    });
    expect(json.message).toMatch(/No policy/);
    // The resource reports the path loadPolicy resolves (the pinned policy
    // root, i.e. the server's launch CWD). process.cwd() is already a realpath
    // while tmpdir() may be a symlink (macOS /var -> /private/var), so compare
    // normalised directories; the file itself does not exist here.
    const file = String(json.file);
    expect(basename(file)).toBe(".q-ring.json");
    expect(realpathSync.native(dirname(file))).toBe(realpathSync.native(projectDir));
  });

  it("returns each section's rules", async () => {
    writePolicy({
      mcp: { denyTools: ["delete_secret"], deniedKeys: ["PROD_DB"] },
      exec: { allowCommands: ["npm"], maxRuntimeSeconds: 30 },
      wrap: { approveTools: ["github_*"], rateLimit: { maxCalls: 5, perSeconds: 60 } },
    });
    const { json } = await read("qring://policy");
    expect(json.hasPolicy).toBe(true);
    expect(json.sections).toEqual(["mcp", "exec", "wrap"]);
    expect(json.hasSecretPolicy).toBe(false);
    expect(json.details).toEqual({
      mcp: { denyTools: ["delete_secret"], deniedKeys: ["PROD_DB"] },
      exec: { allowCommands: ["npm"], maxRuntimeSeconds: 30 },
      wrap: { approveTools: ["github_*"], rateLimit: { maxCalls: 5, perSeconds: 60 } },
    });
    expect(json.message).toBeUndefined();
  });

  it("reports a malformed policy in the JSON", async () => {
    writePolicy({ mcp: { denytools: ["typo"] } });
    vi.spyOn(console, "error").mockImplementation(() => {});
    const { json } = await read("qring://policy");
    expect(json).toMatchObject({ valid: false, hasPolicy: true });
    expect(json.error).toMatch(/fail closed/);
  });

  it("goes dark when policy denies get_policy_summary", async () => {
    writePolicy({ mcp: { denyTools: ["get_policy_summary"], deniedKeys: ["PROD_DB"] } });
    const { json, text } = await read("qring://policy");
    expect(json.hidden).toBe(true);
    expect(text).not.toContain("PROD_DB");
  });
});

describe("qring://rotation", () => {
  it("has an empty state", async () => {
    setSecret("NO_REMINDER", "plain-value-123", { scope: "global", source: "cli" });
    const { json } = await read("qring://rotation");
    expect(json).toMatchObject({ entries: [], dueCount: 0, scheduledCount: 0 });
    expect(json.message).toMatch(/No secrets have a rotation reminder/);
  });

  it("lists scheduled secrets most overdue first, without values", async () => {
    setAged("FRESH_KEY", "value-fresh-aaaaaaaa", 1, 90); // ok
    setAged("STALE_KEY", "value-stale-bbbbbbbb", 100, 30); // overdue by 70
    setAged("SOON_KEY", "value-soon-cccccccc", 28, 30); // due-soon
    setAged("LATE_KEY", "value-late-dddddddd", 40, 30); // overdue by 10
    setAged("UNSCHEDULED", "value-none-eeeeeeee", 400);

    const { json, text } = await read("qring://rotation");
    const entries = json.entries as {
      key: string;
      scope: string;
      state: string;
      summary: string;
      lastRotatedAt: string;
      rotateEveryDays: number;
      dueAt: string;
      daysUntilDue: number;
    }[];
    expect(entries.map((e) => e.key)).toEqual(["STALE_KEY", "LATE_KEY", "SOON_KEY", "FRESH_KEY"]);
    expect(entries.map((e) => e.state)).toEqual(["overdue", "overdue", "due-soon", "ok"]);
    expect(entries[0]).toMatchObject({ scope: "global", rotateEveryDays: 30 });
    expect(entries[0].summary).toMatch(/^overdue \d+d$/);
    expect(typeof entries[0].lastRotatedAt).toBe("string");
    expect(typeof entries[0].dueAt).toBe("string");
    expect(json.dueCount).toBe(3);
    expect(json.scheduledCount).toBe(4);
    expect(text).not.toMatch(/value-(fresh|stale|soon|late|none)/);
    expect(text).not.toContain("UNSCHEDULED");
  });

  it("drops keys hidden by key policy and goes dark when list_secrets is denied", async () => {
    setAged("PROD_DB", "value-prod-ffffffff", 100, 30);
    setAged("DEV_DB", "value-dev-gggggggg", 100, 30);
    writePolicy({ mcp: { deniedKeys: ["PROD_DB"] } });
    let { json } = await read("qring://rotation");
    expect((json.entries as { key: string }[]).map((e) => e.key)).toEqual(["DEV_DB"]);

    writePolicy({ mcp: { denyTools: ["list_secrets"] } });
    ({ json } = await read("qring://rotation"));
    expect(json).toMatchObject({ hidden: true, entries: [], dueCount: 0, scheduledCount: 0 });
  });
});

describe("qring://canaries", () => {
  /**
   * Run steps one second apart on a fake clock (an hour ago), so "after it
   * was planted" never depends on two calls landing in the same millisecond.
   */
  function onClock(...steps: (() => void)[]) {
    vi.useFakeTimers({ toFake: ["Date"] });
    const start = Date.now() - 60 * 60 * 1000;
    steps.forEach((step, i) => {
      vi.setSystemTime(start + i * 1000);
      step();
    });
    vi.useRealTimers();
  }

  function trip(key: string, opts: { scope: "global" | "project"; projectPath?: string }) {
    setAuditAgentLabel("cursor@1.2.3");
    getSecret(key, { ...opts, source: "mcp" });
    setAuditAgentLabel(null);
  }

  function plantAndTrip() {
    let value = "";
    onClock(
      () => ({ value } = plantCanary("AWS_SECRET_ACCESS_KEY", { format: "aws" })),
      () => trip("AWS_SECRET_ACCESS_KEY", { scope: "global" }),
      () => plantCanary("QUIET_TRAP", { format: "github" }),
    );
    return value;
  }

  type CanaryRow = {
    key: string;
    state: string;
    tripCount: number;
    lastTrip: {
      at: string;
      source: string | null;
      agent: string | null;
      detail: string | null;
    } | null;
    unattributedEvents?: number;
  };

  it("does not carry a deleted canary's trips over to one planted again under the key", async () => {
    onClock(
      () => plantCanary("REPLANTED", { format: "aws" }),
      () => trip("REPLANTED", { scope: "global" }),
      () => deleteSecret("REPLANTED", { scope: "global", source: "cli" }), // records a trip too
      () => plantCanary("REPLANTED", { format: "aws" }),
    );
    process.env[CANARY_RESOURCE_ENV] = "1";
    const { json } = await read("qring://canaries");
    const [c] = json.canaries as CanaryRow[];
    expect(c).toMatchObject({ key: "REPLANTED", state: "quiet", tripCount: 0, lastTrip: null });
    expect(c.unattributedEvents).toBeUndefined();
  });

  it("marks a canary tripped by a read after it was planted again", async () => {
    onClock(
      () => plantCanary("REPLANTED", { format: "aws" }),
      () => deleteSecret("REPLANTED", { scope: "global", source: "cli" }),
      () => plantCanary("REPLANTED", { format: "aws" }),
      () => trip("REPLANTED", { scope: "global" }),
    );
    process.env[CANARY_RESOURCE_ENV] = "1";
    const { json } = await read("qring://canaries");
    const [c] = json.canaries as CanaryRow[];
    expect(c).toMatchObject({ key: "REPLANTED", state: "tripped", tripCount: 1 });
    expect(c.lastTrip).toMatchObject({ source: "mcp", agent: "cursor@1.2.3" });
    expect(c.lastTrip!.detail).not.toMatch(/deleted/);
  });

  it("never attributes a project-scope trip event it cannot tie to this project", async () => {
    const projectPath = process.cwd();
    onClock(
      () => plantCanary("PROJ_TRAP", { format: "github", scope: "project", projectPath }),
      // Same key, same scope name, another project: indistinguishable in the audit chain.
      () =>
        logAudit({
          action: "canary",
          key: "PROJ_TRAP",
          scope: "project",
          source: "mcp",
          detail: "CANARY TRIPPED: honeytoken read via mcp",
        }),
    );
    process.env[CANARY_RESOURCE_ENV] = "1";
    let { json } = await read("qring://canaries");
    let [c] = json.canaries as CanaryRow[];
    expect(c).toMatchObject({
      key: "PROJ_TRAP",
      state: "quiet",
      tripCount: 0,
      lastTrip: null,
      unattributedEvents: 1,
    });

    // A real read of this project's canary still shows up, from its own envelope.
    trip("PROJ_TRAP", { scope: "project", projectPath });
    ({ json } = await read("qring://canaries"));
    [c] = json.canaries as CanaryRow[];
    expect(c).toMatchObject({ state: "tripped", tripCount: 1, unattributedEvents: 2 });
    expect(c.lastTrip).toMatchObject({ source: null, agent: null });
  });

  it("is dark by default: no key names, no values, no count", async () => {
    const value = plantAndTrip();
    const { json, text } = await read("qring://canaries");
    expect(json).toMatchObject({ exposed: false, canaries: [], alerts: [] });
    expect(json.reason).toContain(CANARY_RESOURCE_ENV);
    expect(text).not.toContain("AWS_SECRET_ACCESS_KEY");
    expect(text).not.toContain("QUIET_TRAP");
    expect(text).not.toContain(value);
  });

  it("with the operator opt-in lists canaries, last trip and alert hosts, never values", async () => {
    const value = plantAndTrip();
    addCanaryAlert({
      type: "discord",
      url: "https://discord.com/api/webhooks/123456/SuperSecretWebhookToken",
      description: "security channel",
    });
    process.env[CANARY_RESOURCE_ENV] = "1";

    const { json, text } = await read("qring://canaries");
    expect(json.exposed).toBe(true);
    const canaries = json.canaries as {
      key: string;
      scope: string;
      format: string;
      state: string;
      tripCount: number;
      lastTrip: { at: string; source: string; agent: string | null } | null;
    }[];
    const tripped = canaries.find((c) => c.key === "AWS_SECRET_ACCESS_KEY")!;
    expect(tripped).toMatchObject({ scope: "global", format: "aws", state: "tripped" });
    expect(tripped.tripCount).toBeGreaterThan(0);
    expect(tripped.lastTrip).toMatchObject({ source: "mcp", agent: "cursor@1.2.3" });
    const quiet = canaries.find((c) => c.key === "QUIET_TRAP")!;
    expect(quiet).toMatchObject({ format: "github", state: "quiet", tripCount: 0, lastTrip: null });

    expect(json.alerts).toEqual([
      {
        id: expect.any(String),
        type: "discord",
        enabled: true,
        target: "https://discord.com",
        description: "security channel",
      },
    ]);

    expect(text).not.toContain(value);
    expect(text).not.toContain("SuperSecretWebhookToken");
    expect(text).not.toContain("/api/webhooks");
  });

  it("has an empty state when opted in with nothing planted", async () => {
    process.env[CANARY_RESOURCE_ENV] = "1";
    const { json } = await read("qring://canaries");
    expect(json).toEqual({ exposed: true, canaries: [], alerts: [] });
  });

  it("stays dark when policy denies audit_log, even with the opt-in", async () => {
    plantAndTrip();
    process.env[CANARY_RESOURCE_ENV] = "1";
    writePolicy({ mcp: { denyTools: ["audit_log"] } });
    const { json, text } = await read("qring://canaries");
    expect(json).toMatchObject({ exposed: false, canaries: [], alerts: [] });
    expect(text).not.toContain("AWS_SECRET_ACCESS_KEY");
  });

  it("reading it does not trip a canary", async () => {
    plantCanary("UNTOUCHED_TRAP", { format: "generic" });
    process.env[CANARY_RESOURCE_ENV] = "1";
    await read("qring://canaries");
    const { json } = await read("qring://canaries");
    const [c] = json.canaries as { key: string; tripCount: number; state: string }[];
    expect(c).toMatchObject({ key: "UNTOUCHED_TRAP", tripCount: 0, state: "quiet" });
  });
});

describe("introspection resources under a .q-ring.json that is not valid JSON", () => {
  // Written after any setup that itself goes through the policy (setSecret,
  // plantCanary); every read below must answer with data, never throw.
  function corruptConfig() {
    writeFileSync(join(projectDir, ".q-ring.json"), "{ not json");
    clearPolicyCache();
    vi.spyOn(console, "error").mockImplementation(() => {});
  }

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("qring://policy reports the file as invalid", async () => {
    corruptConfig();
    const { json } = await read("qring://policy");
    expect(json).toMatchObject({ valid: false, hasPolicy: true });
    expect(json.file).toMatch(/\.q-ring\.json$/);
    expect(json.error).toMatch(/not valid JSON/);
  });

  it("qring://rotation is hidden with a policyError and no key names", async () => {
    setAged("STALE_KEY", "value-stale-bbbbbbbb", 100, 30);
    corruptConfig();
    const { json, text } = await read("qring://rotation");
    expect(json).toMatchObject({ hidden: true, entries: [], dueCount: 0, scheduledCount: 0 });
    expect(json.policyError).toMatch(/not valid JSON/);
    expect(text).not.toContain("STALE_KEY");
  });

  it("qring://canaries is not exposed, with a policyError, even with the opt-in", async () => {
    plantCanary("CORRUPT_TRAP", { format: "generic" });
    process.env[CANARY_RESOURCE_ENV] = "1";
    corruptConfig();
    const { json, text } = await read("qring://canaries");
    expect(json).toMatchObject({ exposed: false, canaries: [], alerts: [] });
    expect(json.policyError).toMatch(/not valid JSON/);
    expect(text).not.toContain("CORRUPT_TRAP");
  });
});
