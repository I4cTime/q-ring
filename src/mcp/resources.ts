import { join } from "node:path";
import { McpServer, ResourceTemplate } from "@modelcontextprotocol/sdk/server/mcp.js";
import {
  checkToolPolicy,
  getPolicyRoot,
  getPolicySummary,
  PolicyConfigError,
  type PolicyConfig,
} from "../core/policy.js";
import { listCanaries } from "../core/canary.js";
import { listCanaryAlerts } from "../core/canary-webhooks.js";
import { listSecrets, type KeyringOptions } from "../core/keyring.js";
import { queryAudit } from "../core/observer.js";
import { buildRotationSchedule, describeRotation } from "../core/rotation.js";
import {
  listAgentSessionsForAgents,
  summariseSession,
  type SessionQuery,
} from "../core/sessions.js";

/**
 * MCP resources exposed by the q-ring server.
 *
 * Standing rule: state an agent should *look at* is a resource, not a tool.
 * The agent session timeline is the first: `qring://sessions` lists every
 * agent session the audit chain knows about, `qring://sessions/{id}` is one
 * session's timeline.
 *
 * Both are agent surfaces, so they read through `listAgentSessionsForAgents`,
 * which strips canary trips before anything is summarised — a honeytoken must
 * never be discoverable from the agent side. They also honour the operator's
 * one switch for audit visibility: denying the `audit_log` tool in
 * `.q-ring.json` policy hides these resources too.
 *
 * The introspection resources follow the same pattern — each goes dark when
 * policy denies the tool that already exposes the same information:
 *   - `qring://policy`   — the `get_policy_summary` view (gate: get_policy_summary)
 *   - `qring://rotation` — the `rotate:due --all` list   (gate: list_secrets)
 *   - `qring://canaries` — planted canaries and alert channels. Canary
 *     *identity* is the asset (docs/threat-model.md), so this one is dark by
 *     default and lists nothing unless the operator launched the server with
 *     QRING_MCP_EXPOSE_CANARIES=1; denying `audit_log` hides it regardless.
 * None of them ever reads or returns a secret value.
 */

const MIME = "application/json";
const LIST_URI = "qring://sessions";
const POLICY_URI = "qring://policy";
const CANARIES_URI = "qring://canaries";
const ROTATION_URI = "qring://rotation";

/** Operator opt-in for `qring://canaries`, set in the MCP server's launch env. */
export const CANARY_RESOURCE_ENV = "QRING_MCP_EXPOSE_CANARIES";

/** Window a resource read covers; agents don't need the whole chain. */
const RESOURCE_QUERY: SessionQuery = {
  since: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString(),
  limit: 50,
  maxEvents: 200,
};

function toolVisible(toolName: string): boolean {
  return checkToolPolicy(toolName).allowed;
}

function auditVisible(): boolean {
  return toolVisible("audit_log");
}

function hiddenBy(toolName: string): string {
  return `Hidden: .q-ring.json policy denies the ${toolName} tool.`;
}

function jsonContents(uri: URL, body: unknown) {
  return {
    contents: [{ uri: uri.href, mimeType: MIME, text: JSON.stringify(body, null, 2) }],
  };
}

/** Same scope resolution as the MCP tools: launch CWD, `mcp` source (key policy applies). */
function mcpListOpts(): KeyringOptions {
  return { projectPath: process.cwd(), source: "mcp" };
}

const POLICY_SECTIONS = [
  "mcp",
  "exec",
  "secrets",
  "wrap",
] as const satisfies readonly (keyof PolicyConfig)[];

function readPolicyResource() {
  // The path as loadPolicy resolves it (pinned root, else CWD) and names it in
  // its own error message, so `file` and `error` always agree. Not realpath'd:
  // it is the path the operator launched the server in.
  const file = join(getPolicyRoot() ?? process.cwd(), ".q-ring.json");
  try {
    if (!toolVisible("get_policy_summary")) {
      return { hidden: true, reason: hiddenBy("get_policy_summary") };
    }
    const summary = getPolicySummary();
    const sections = POLICY_SECTIONS.filter((k) => summary.details[k] !== undefined);
    return {
      file,
      valid: true,
      hasPolicy: sections.length > 0,
      sections,
      ...summary,
      ...(sections.length === 0
        ? {
            message:
              "No policy in .q-ring.json: governance allows every tool, key and exec command (per-secret approval and other metadata still apply).",
          }
        : {}),
    };
  } catch (err) {
    // A malformed policy fails closed everywhere else; here the useful answer
    // is to say so in the JSON, so the agent can tell the operator.
    if (err instanceof PolicyConfigError) {
      return { file, valid: false, hasPolicy: true, error: err.message };
    }
    throw err;
  }
}

function readRotationResource() {
  if (!toolVisible("list_secrets")) {
    return {
      hidden: true,
      reason: hiddenBy("list_secrets"),
      entries: [],
      dueCount: 0,
      scheduledCount: 0,
    };
  }
  const { scheduled, due } = buildRotationSchedule(listSecrets(mcpListOpts()));
  return {
    entries: scheduled.map(({ key, scope, rotation }) => ({
      key,
      scope,
      state: rotation.state,
      summary: describeRotation(rotation),
      lastRotatedAt: rotation.lastRotatedAt,
      ageDays: rotation.ageDays,
      rotateEveryDays: rotation.rotateEveryDays,
      dueAt: rotation.dueAt,
      daysUntilDue: rotation.daysUntilDue,
    })),
    dueCount: due.length,
    scheduledCount: scheduled.length,
    ...(scheduled.length === 0
      ? {
          message:
            "No secrets have a rotation reminder (the operator sets one with: qring set KEY --rotate-every 90).",
        }
      : {}),
  };
}

/** Alert channel target without its path: webhook paths and ntfy topics are credentials. */
function alertTarget(url: string): string {
  try {
    const u = new URL(url);
    return `${u.protocol}//${u.host}`;
  } catch {
    return "(unparseable URL)";
  }
}

function readCanariesResource() {
  if (process.env[CANARY_RESOURCE_ENV] !== "1") {
    return {
      exposed: false,
      reason: `Canary identities are hidden from agents unless the operator starts the q-ring MCP server with ${CANARY_RESOURCE_ENV}=1.`,
      canaries: [],
      alerts: [],
    };
  }
  if (!auditVisible()) {
    return { exposed: false, reason: hiddenBy("audit_log"), canaries: [], alerts: [] };
  }

  // One audit pass for every canary; newest first, so the first hit per key wins.
  const trips = queryAudit({ action: "canary" });
  const canaries = listCanaries(mcpListOpts()).map((c) => {
    const last = trips.find((e) => e.key === c.key && (!e.scope || e.scope === c.scope));
    const lastTrip = last
      ? {
          at: last.timestamp,
          source: last.source,
          agent: last.agent ?? null,
          detail: last.detail ?? null,
        }
      : c.lastTrippedAt
        ? { at: c.lastTrippedAt, source: null, agent: null, detail: null }
        : null;
    // Explicit field allowlist: nothing value-shaped can ride along if
    // CanaryStatus ever grows.
    return {
      key: c.key,
      scope: c.scope,
      format: c.format ?? "generic",
      plantedAt: c.plantedAt,
      state: c.tripCount > 0 || lastTrip ? "tripped" : "quiet",
      tripCount: c.tripCount,
      lastTrip,
    };
  });
  const alerts = listCanaryAlerts().map((ch) => ({
    id: ch.id,
    type: ch.type,
    enabled: ch.enabled,
    target: alertTarget(ch.url),
    ...(ch.description ? { description: ch.description } : {}),
  }));
  return { exposed: true, canaries, alerts };
}

export function registerMcpResources(server: McpServer): void {
  server.registerResource(
    "agent-sessions",
    LIST_URI,
    {
      title: "Agent sessions",
      description:
        "Audit activity folded into per-agent sessions (last 7 days): which MCP client did what, when, against which key names. Summaries only — read qring://sessions/{id} for a session's event timeline. Never contains secret values.",
      mimeType: MIME,
    },
    async (uri) => {
      const sessions = auditVisible()
        ? listAgentSessionsForAgents(RESOURCE_QUERY).map(summariseSession)
        : [];
      return {
        contents: [{ uri: uri.href, mimeType: MIME, text: JSON.stringify({ sessions }, null, 2) }],
      };
    },
  );

  server.registerResource(
    "agent-session",
    new ResourceTemplate("qring://sessions/{id}", {
      list: async () => {
        if (!auditVisible()) return { resources: [] };
        return {
          resources: listAgentSessionsForAgents(RESOURCE_QUERY).map((s) => ({
            uri: `${LIST_URI}/${s.id}`,
            name: s.wrapLabel ? `airlock: ${s.wrapLabel}` : s.agent,
            description: `${s.eventCount} events, ${s.startedAt} → ${s.endedAt}`,
            mimeType: MIME,
          })),
        };
      },
    }),
    {
      title: "Agent session timeline",
      description:
        "One agent session's audit timeline, most recent event first. Key names and actions only — never secret values.",
      mimeType: MIME,
    },
    async (uri, variables) => {
      const id = String(variables.id ?? "");
      const session = auditVisible()
        ? listAgentSessionsForAgents({ ...RESOURCE_QUERY, limit: undefined }).find(
            (s) => s.id === id,
          )
        : undefined;
      if (!session) throw new Error(`Session not found: ${id}`);
      return {
        contents: [{ uri: uri.href, mimeType: MIME, text: JSON.stringify(session, null, 2) }],
      };
    },
  );

  server.registerResource(
    "policy",
    POLICY_URI,
    {
      title: "Governance policy",
      description:
        "The project's .q-ring.json governance policy: which sections exist (mcp, exec, secrets, wrap) and their rules — allowed/denied tools, readable/denied keys and tags, exec allow/deny commands and runtime limit, approval and rotation-format tags, airlock (wrap) tool lists and rate limits. Read it once before planning work that reads secrets, runs exec_with_secrets or goes through a wrapped server, rather than learning the rules from denials; use the check_policy tool for a verdict on one action. Says so in the JSON when there is no policy or it is malformed. Hidden when policy denies get_policy_summary. Never contains secret values.",
      mimeType: MIME,
    },
    async (uri) => jsonContents(uri, readPolicyResource()),
  );

  server.registerResource(
    "rotation",
    ROTATION_URI,
    {
      title: "Rotation reminders",
      description:
        "Every secret with a rotation reminder, most overdue first (the `qring rotate:due --all` list): key, scope, state (ok, due-soon, overdue), last rotated, interval in days, due date. Read it at the start of maintenance work or when asked what needs rotating, then act on the overdue entries with rotate_secret. Keys hidden by key policy are left out. Hidden when policy denies list_secrets. Never contains secret values.",
      mimeType: MIME,
    },
    async (uri) => jsonContents(uri, readRotationResource()),
  );

  server.registerResource(
    "canaries",
    CANARIES_URI,
    {
      title: "Canary honeytokens",
      description: `Planted canary honeytokens: key name, scope, token format, trip count, last trip (time, source, client) and the alert channels (type and host only). Read it when the operator asks whether a tripwire fired or where canary alerts go. Off by default: lists nothing unless the operator started the server with ${CANARY_RESOURCE_ENV}=1, and hidden when policy denies audit_log. Never contains secret values, not even the fake canary values.`,
      mimeType: MIME,
    },
    async (uri) => jsonContents(uri, readCanariesResource()),
  );
}
