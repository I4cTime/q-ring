import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

vi.mock("@napi-rs/keyring", async () => {
  const fake = await import("../helpers/fake-keyring.js");
  return { Entry: fake.FakeEntry, findCredentials: fake.findCredentials };
});

import { resetFakeKeyring } from "../helpers/fake-keyring.js";
import { setSecret, getEnvelope } from "../../core/keyring.js";
import { queryAudit } from "../../core/observer.js";
import { setPolicyRoot, clearPolicyCache } from "../../core/policy.js";
import { registerToolingTools } from "../../mcp/tools/tooling.js";

type Handler = (params: Record<string, unknown>) => Promise<{ content: { text: string }[] }>;

function agentScan(): Handler {
  let handler: Handler | undefined;
  const stub = {
    tool: (n: string, ...rest: unknown[]) => {
      if (n === "agent_scan") handler = rest[rest.length - 1] as Handler;
    },
  };
  registerToolingTools(stub as unknown as McpServer);
  return handler!;
}

let dir: string;
const expired = () => new Date(Date.now() - 60_000).toISOString();
const storedValue = (key: string) => getEnvelope(key, { scope: "global" })?.envelope.value;

beforeEach(() => {
  resetFakeKeyring();
  clearPolicyCache();
  dir = mkdtempSync(join(tmpdir(), "qring-agent-scan-"));
  writeFileSync(
    join(dir, ".q-ring.json"),
    JSON.stringify({ policy: { mcp: { deniedKeys: ["DENIED_KEY"], deniedTags: ["prod"] } } }),
  );
  setPolicyRoot(dir);
  setSecret("DENIED_KEY", "protected-1", { scope: "global", source: "cli", expiresAt: expired() });
  setSecret("TAGGED_KEY", "protected-2", {
    scope: "global",
    source: "cli",
    tags: ["prod"],
    expiresAt: expired(),
  });
  setSecret("OPEN_KEY", "old-open-value", { scope: "global", source: "cli", expiresAt: expired() });
});

afterEach(() => {
  setPolicyRoot(process.cwd());
  clearPolicyCache();
  rmSync(dir, { recursive: true, force: true });
});

describe("agent_scan autoRotate over MCP", () => {
  it("never rotates a policy-protected key, lists it as skipped, and audits writes as mcp", async () => {
    const res = await agentScan()({ autoRotate: true, projectPaths: [dir] });
    const report = JSON.parse(res.content[0].text) as {
      rotated: string[];
      rotationSkipped: { key: string; reason: string }[];
    };

    expect(storedValue("DENIED_KEY")).toBe("protected-1");
    expect(storedValue("TAGGED_KEY")).toBe("protected-2");
    expect(storedValue("OPEN_KEY")).not.toBe("old-open-value");

    expect(report.rotated).toEqual(["OPEN_KEY"]);
    expect(report.rotationSkipped.map((s) => s.key).sort()).toEqual(["DENIED_KEY", "TAGGED_KEY"]);

    const writes = queryAudit({ action: "write", key: "OPEN_KEY" }).filter(
      (e) => e.detail === "auto-rotated by agent (expired)",
    );
    expect(writes[0].source).toBe("mcp");
  });
});
