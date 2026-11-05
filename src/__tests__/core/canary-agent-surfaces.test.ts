import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

vi.mock("@napi-rs/keyring", async () => {
  const fake = await import("../helpers/fake-keyring.js");
  return { Entry: fake.FakeEntry, findCredentials: fake.findCredentials };
});

vi.mock("../../core/notify.js", () => ({
  notificationsEnabled: vi.fn(() => false),
  notifyUser: vi.fn(() => true),
  notifyApprovalRequested: vi.fn(),
}));

import { getSecret } from "../../core/keyring.js";
import { plantCanary } from "../../core/canary.js";
import { resetCanaryAlertThrottle } from "../../core/canary-alert.js";
import { logAudit } from "../../core/observer.js";
import { getProjectContext } from "../../core/context.js";
import { collectSnapshot } from "../../core/dashboard.js";
import { registerToolingTools } from "../../mcp/tools/tooling.js";
import { resetFakeKeyring } from "../helpers/fake-keyring.js";

let auditDir: string;

beforeEach(() => {
  resetFakeKeyring();
  resetCanaryAlertThrottle();
  auditDir = mkdtempSync(join(tmpdir(), "qring-canary-surfaces-"));
  process.env.QRING_AUDIT_DIR = auditDir;
  plantCanary("HONEY_TOKEN", { format: "github" });
  getSecret("HONEY_TOKEN", { scope: "global", source: "cli" }); // a trip
  logAudit({
    action: "canary_alert",
    key: "HONEY_TOKEN",
    scope: "global",
    source: "hook",
    detail: "delivery blocked (http://10.0.0.5)",
  });
});

afterEach(() => {
  delete process.env.QRING_AUDIT_DIR;
  rmSync(auditDir, { recursive: true, force: true });
});

const HIDDEN = ["canary", "canary_alert"];

describe("agent-reachable audit readers hide canary records", () => {
  it("get_project_context's recent actions", () => {
    const ctx = getProjectContext({ scope: "global", source: "mcp" });
    expect(ctx.recentActions.length).toBeGreaterThan(0);
    expect(ctx.recentActions.filter((a) => HIDDEN.includes(a.action))).toEqual([]);
  });

  it("a dashboard started for an agent, while the operator's keeps them", () => {
    const agent = collectSnapshot(true);
    expect(agent.audit.filter((e) => HIDDEN.includes(e.action))).toEqual([]);
    expect(JSON.stringify(agent.sessions)).not.toContain("delivery blocked");
    expect(agent.sessions.every((s) => !s.countsByAction.canary)).toBe(true);

    const operator = collectSnapshot();
    expect(operator.audit.some((e) => e.action === "canary")).toBe(true);
  });

  it("analyze_secrets", async () => {
    let analyze:
      ((p: Record<string, unknown>) => Promise<{ content: { text: string }[] }>) | undefined;
    const stub = {
      tool: (n: string, ...rest: unknown[]) => {
        if (n === "analyze_secrets") analyze = rest[rest.length - 1] as typeof analyze;
      },
    };
    registerToolingTools(stub as unknown as McpServer);
    const res = await analyze!({ scope: "global" });
    expect(res.content[0].text).not.toContain("canary");
  });
});
