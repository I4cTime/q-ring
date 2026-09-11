import { McpServer, ResourceTemplate } from "@modelcontextprotocol/sdk/server/mcp.js";
import { checkToolPolicy } from "../core/policy.js";
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
 */

const MIME = "application/json";
const LIST_URI = "qring://sessions";

/** Window a resource read covers; agents don't need the whole chain. */
const RESOURCE_QUERY: SessionQuery = {
  since: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString(),
  limit: 50,
  maxEvents: 200,
};

function auditVisible(): boolean {
  return checkToolPolicy("audit_log").allowed;
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
}
