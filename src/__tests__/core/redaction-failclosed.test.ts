/**
 * Fail-closed behaviour when a redaction set cannot be built: exec must not
 * spawn, the airlock must fall back to verbatim-only matching and, failing
 * that, withhold results. Also: one unreadable secret never empties the
 * airlock's set, and a collection that fails outright withholds results.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

const mode = vi.hoisted(() => ({ failFull: false, failVerbatim: false, failList: false }));

vi.mock("../../core/redaction.js", async (importOriginal) => {
  const real = await importOriginal<typeof import("../../core/redaction.js")>();
  class FlakyRedactionSet extends real.RedactionSet {
    constructor(
      entries: readonly import("../../core/redaction.js").RedactionEntry[],
      options: import("../../core/redaction.js").RedactionSetOptions = {},
    ) {
      if (options.verbatimOnly ? mode.failVerbatim : mode.failFull) {
        throw new Error("simulated redaction build failure");
      }
      super(entries, options);
    }
  }
  return { ...real, RedactionSet: FlakyRedactionSet };
});

vi.mock("node:child_process", async (importOriginal) => {
  const real = await importOriginal<typeof import("node:child_process")>();
  return { ...real, spawn: vi.fn(real.spawn) };
});

vi.mock("../../core/keyring.js", async (importOriginal) => {
  const real = await importOriginal<typeof import("../../core/keyring.js")>();
  return {
    ...real,
    listSecrets: (...args: Parameters<typeof real.listSecrets>) => {
      if (mode.failList) throw new Error("simulated keyring listing failure");
      return real.listSecrets(...args);
    },
  };
});

vi.mock("@napi-rs/keyring", async () => {
  const fake = await import("../helpers/fake-keyring.js");
  return { Entry: fake.FakeEntry, findCredentials: fake.findCredentials };
});

import { spawn } from "node:child_process";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { spawnRedacted, getProfile } from "../../core/exec.js";
import {
  createRedactor,
  collectSecretValues,
  RedactionUnavailableError,
} from "../../core/wrap-redact.js";
import { createAirlockServer } from "../../core/wrap.js";
import { queryAudit } from "../../core/observer.js";
import { clearPolicyCache, setPolicyRoot } from "../../core/policy.js";
import { setSecret } from "../../core/keyring.js";
import { resetFakeKeyring } from "../helpers/fake-keyring.js";

const SECRET = "Zq7vK2mX9pL4wR8tY1nB6cH3jF5dG0sAe2Uo4Ii8";
let auditDir: string;

beforeEach(() => {
  mode.failFull = false;
  mode.failVerbatim = false;
  mode.failList = false;
  vi.mocked(spawn).mockClear();
  resetFakeKeyring();
  auditDir = mkdtempSync(join(tmpdir(), "qring-failclosed-audit-"));
  process.env.QRING_AUDIT_DIR = auditDir;
});
afterEach(() => {
  delete process.env.QRING_AUDIT_DIR;
  rmSync(auditDir, { recursive: true, force: true });
});

function runChild() {
  const envMap: Record<string, string> = {};
  for (const [k, v] of Object.entries(process.env)) if (v !== undefined) envMap[k] = v;
  envMap.K = SECRET;
  return spawnRedacted({
    profile: getProfile("unrestricted"),
    command: process.execPath,
    args: ["-e", "console.log('k=' + process.env.K + ' slice=' + process.env.K.slice(0, 20))"],
    envMap,
    secretsToRedact: [{ name: "K", value: SECRET }],
    captureOutput: true,
  });
}

describe("spawnRedacted builds redaction before spawning", () => {
  it("redacts normally when the set builds", async () => {
    const r = await runChild();
    expect(r.stdout.trim()).toBe("k=[QRING:REDACTED:K] slice=[QRING:REDACTED:K]");
    expect(spawn).toHaveBeenCalledTimes(1);
  });

  it("falls back to verbatim-only matching when the full build fails", async () => {
    mode.failFull = true;
    const r = await runChild();
    expect(r.stdout).toContain("k=[QRING:REDACTED:K]");
    expect(r.stdout).not.toContain(`k=${SECRET}`);
  });

  it("rejects WITHOUT spawning when no redaction set can be built", async () => {
    mode.failFull = true;
    mode.failVerbatim = true;
    await expect(runChild()).rejects.toThrow(/output redaction could not be set up/);
    expect(spawn).not.toHaveBeenCalled();
  });
});

describe("createRedactor never runs with an empty set after a failed build", () => {
  beforeEach(() => {
    setSecret("STRIPE_KEY", SECRET, { scope: "global", silent: true });
  });

  it("full build", () => {
    const r = createRedactor();
    expect(r.text(`x ${SECRET.slice(0, 20)} y`)).toBe("x [QRING:REDACTED:STRIPE_KEY] y");
  });

  it("falls back to verbatim-only when the full build fails", () => {
    mode.failFull = true;
    const r = createRedactor();
    expect(r.text(`x ${SECRET} y`)).toBe("x [QRING:REDACTED:STRIPE_KEY] y");
  });

  it("fails closed when even the verbatim build fails, and recovers once it builds", () => {
    mode.failFull = true;
    mode.failVerbatim = true;
    const r = createRedactor();
    expect(() => r.text(`x ${SECRET} y`)).toThrow(RedactionUnavailableError);
    expect(() => r.result({ content: [{ type: "text", text: SECRET }] })).toThrow(
      RedactionUnavailableError,
    );
    // Retried on the next result, not after a 60 s back-off.
    mode.failFull = false;
    mode.failVerbatim = false;
    expect(r.text(`x ${SECRET} y`)).toBe("x [QRING:REDACTED:STRIPE_KEY] y");
  });
});

describe("airlock collection never fails open", () => {
  it("skips one unreadable secret (template naming a missing key), still redacts the rest", () => {
    const write = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
    try {
      setSecret("BROKEN_URL", "postgres://u:{{MISSING_KEY}}@db/x", {
        scope: "global",
        silent: true,
      });
      setSecret("STRIPE_KEY", SECRET, { scope: "global", silent: true });

      const stats = { skipped: 0 };
      const entries = collectSecretValues({}, stats);
      expect(stats.skipped).toBe(1);
      expect(entries.map((e) => e.name)).toEqual(["STRIPE_KEY"]);

      const r = createRedactor();
      expect(r.text(`x ${SECRET} y`)).toBe("x [QRING:REDACTED:STRIPE_KEY] y");
      r.invalidate();
      r.text("again");
      // One counts-only note per redactor.
      const notes = write.mock.calls
        .map((c) => String(c[0]))
        .filter((m) => m.includes("could not be read"));
      expect(notes).toHaveLength(1);
      expect(notes[0]).toContain("1 secret(s)");
      expect(notes[0]).not.toContain("BROKEN_URL");
    } finally {
      write.mockRestore();
    }
  });

  it("withholds results when collection fails with no earlier set, then recovers", async () => {
    setSecret("STRIPE_KEY", SECRET, { scope: "global", silent: true });
    const projectDir = mkdtempSync(join(tmpdir(), "qring-failclosed-proj-"));
    setPolicyRoot(projectDir);
    try {
      const downstream = new McpServer({ name: "leaky", version: "1.0.0" });
      downstream.tool("leak", "Returns a secret", {}, async () => ({
        content: [{ type: "text", text: `token=${SECRET}` }],
      }));
      const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
      await downstream.connect(serverSide);
      const downstreamClient = new Client({ name: "q-ring-airlock", version: "test" });
      await downstreamClient.connect(clientSide);
      const proxy = createAirlockServer(
        downstreamClient,
        { label: "leaky-cmd", correlationId: "failclosed-session" },
        { projectPath: projectDir, redactor: createRedactor({ projectPath: projectDir }) },
      );
      const [hostSide, proxySide] = InMemoryTransport.createLinkedPair();
      await proxy.connect(proxySide);
      const host = new Client({ name: "test-host", version: "1.0.0" });
      await host.connect(hostSide);

      mode.failList = true;
      const withheld = await host.callTool({ name: "leak", arguments: {} });
      expect(withheld.isError).toBe(true);
      expect(JSON.stringify(withheld)).not.toContain(SECRET);
      expect((withheld.content as Array<{ text: string }>)[0].text).toBe(
        "airlock: result withheld: secret redaction is unavailable",
      );
      const events = queryAudit({ action: "wrap", correlationId: "failclosed-session" });
      expect(events.some((e) => e.detail?.includes("result withheld"))).toBe(true);

      // Retried on the next result: once listing works, results flow, redacted.
      mode.failList = false;
      const ok = await host.callTool({ name: "leak", arguments: {} });
      expect(ok.isError).toBeFalsy();
      expect((ok.content as Array<{ text: string }>)[0].text).toBe(
        "token=[QRING:REDACTED:STRIPE_KEY]",
      );
    } finally {
      rmSync(projectDir, { recursive: true, force: true });
      clearPolicyCache();
    }
  });

  it("keeps the last good set when a later collection fails", () => {
    setSecret("STRIPE_KEY", SECRET, { scope: "global", silent: true });
    const r = createRedactor();
    expect(r.text(SECRET)).toBe("[QRING:REDACTED:STRIPE_KEY]");
    mode.failList = true;
    r.invalidate();
    expect(r.text(SECRET)).toBe("[QRING:REDACTED:STRIPE_KEY]");
  });
});
