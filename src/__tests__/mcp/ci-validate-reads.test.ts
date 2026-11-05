import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
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

import { resetFakeKeyring } from "../helpers/fake-keyring.js";
import { setSecret } from "../../core/keyring.js";
import { plantCanary } from "../../core/canary.js";
import { resetCanaryAlertThrottle } from "../../core/canary-alert.js";
import { queryAudit } from "../../core/observer.js";
import { registerValidationTools } from "../../mcp/tools/validation.js";

type Handler = (params: Record<string, unknown>) => Promise<unknown>;

function captureTool(name: string): Handler {
  const tools = new Map<string, Handler>();
  const stub = {
    tool: (toolName: string, ...rest: unknown[]) => {
      tools.set(toolName, rest[rest.length - 1] as Handler);
    },
  };
  registerValidationTools(stub as unknown as McpServer);
  return tools.get(name)!;
}

let auditDir: string;

beforeEach(() => {
  resetFakeKeyring();
  resetCanaryAlertThrottle();
  auditDir = mkdtempSync(join(tmpdir(), "qring-ci-validate-"));
  process.env.QRING_AUDIT_DIR = auditDir;
});

afterEach(() => {
  delete process.env.QRING_AUDIT_DIR;
  rmSync(auditDir, { recursive: true, force: true });
});

describe("ci_validate_secrets (MCP) reads like any other bulk read", () => {
  it("records a read per secret and trips canaries it sweeps", async () => {
    // Neither value matches a provider prefix, so no request leaves the test.
    setSecret("PLAIN_VALUE", "plain-value-123", { scope: "global", source: "cli" });
    plantCanary("SWEPT_CANARY", { format: "generic" });

    await captureTool("ci_validate_secrets")({ scope: "global" });

    expect(queryAudit({ action: "read", key: "PLAIN_VALUE" })).toHaveLength(1);
    expect(queryAudit({ action: "read", key: "SWEPT_CANARY" })).toHaveLength(1);
    // Without the trip, a batch validation hands an agent every canary's
    // value (and a provider's "invalid" verdict on it) with no alarm.
    expect(queryAudit({ action: "canary", key: "SWEPT_CANARY" })).toHaveLength(1);
  });
});
