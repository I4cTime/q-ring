import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { listSecrets } from "../../core/keyring.js";
import {
  queryAudit,
  detectAnomalies,
  verifyAuditChain,
  exportAudit,
} from "../../core/observer.js";
import { text, opts, enforceToolPolicy, commonSchemas } from "./_shared.js";

const { teamId, orgId, scope, projectPath } = commonSchemas;

export function registerAuditTools(server: McpServer): void {
  server.tool(
    "audit_log",
    [
      "[audit] Query the q-ring audit log — a tamper-evident record of every read/write/delete touching a secret.",
      "Use to investigate 'who accessed KEY recently?' or to feed an agent the access timeline for a specific credential; prefer `detect_anomalies` for automated unusual-pattern detection and `health_check` for decay-state-plus-anomalies in one call.",
      "Read-only. Returns one line per event in chronological order, formatted `timestamp | action | key | [scope] | env:NAME | detail`. Returns 'No audit events found' when the filter matches nothing.",
    ].join(" "),
    {
      key: z
        .string()
        .optional()
        .describe(
          "Limit to events touching this exact key. Omit for the full log.",
        ),
      action: z
        .enum([
          "read",
          "write",
          "delete",
          "list",
          "export",
          "generate",
          "entangle",
          "tunnel",
          "teleport",
          "collapse",
          "approve",
          "revoke",
          "policy_deny",
          "rotate",
          "push",
          "wrap",
        ])
        .optional()
        .describe(
          "Limit to a single action verb (e.g. 'read' to see only reads). Omit for all actions.",
        ),
      agent: z
        .string()
        .optional()
        .describe(
          "Limit to events stamped with this agent label (clientInfo name@version). Omit for all agents.",
        ),
      limit: z
        .number()
        .optional()
        .default(20)
        .describe(
          "Maximum events to return, newest first. Defaults to 20. Increase for deeper investigations.",
        ),
    },
    async (params) => {
      const toolBlock = enforceToolPolicy("audit_log");
      if (toolBlock) return toolBlock;

      // Canary trip events are operator-facing counter-intelligence: exposing
      // them over MCP would let an agent enumerate which tripwires fired.
      // CLI `qring audit` remains the surface for reviewing trips.
      const events = queryAudit({
        key: params.key,
        action: params.action,
        agent: params.agent,
      })
        .filter((e) => e.action !== "canary")
        .slice(0, params.limit);

      if (events.length === 0) return text("No audit events found");

      const lines = events.map((e) => {
        const parts = [e.timestamp, e.action];
        if (e.key) parts.push(e.key);
        if (e.scope) parts.push(`[${e.scope}]`);
        if (e.env) parts.push(`env:${e.env}`);
        if (e.agent) parts.push(`agent:${e.agent}`);
        if (e.detail) parts.push(e.detail);
        return parts.join(" | ");
      });

      return text(lines.join("\n"));
    },
  );

  server.tool(
    "detect_anomalies",
    [
      "[audit] Scan the audit history for suspicious access patterns — burst reads of the same key, off-hours access, and other heuristics.",
      "Use as a quick triage signal when investigating a single key or before letting an agent rotate credentials; prefer `health_check` for a scope-wide decay+anomaly summary, and `agent_scan` for multi-project JSON reports with optional auto-rotation.",
      "Read-only; never mutates secrets or the audit log. Returns one line per finding formatted `[type] description`, or 'No anomalies detected' when the log looks clean.",
    ].join(" "),
    {
      key: z
        .string()
        .optional()
        .describe(
          "If provided, narrow the scan to this exact key. Omit to scan across every key in the audit log.",
        ),
    },
    async (params) => {
      const toolBlock = enforceToolPolicy("detect_anomalies");
      if (toolBlock) return toolBlock;

      const anomalies = detectAnomalies(params.key);
      if (anomalies.length === 0) return text("No anomalies detected");

      const lines = anomalies.map((a) => `[${a.type}] ${a.description}`);
      return text(lines.join("\n"));
    },
  );

  server.tool(
    "health_check",
    [
      "[health] Run a single read-only sweep over every secret in the requested scope and report counts of healthy/stale/expired secrets plus any current audit anomalies.",
      "Use as the default 'is everything OK?' command for an agent or operator; prefer `check_project` to validate manifest compliance specifically, `detect_anomalies` for audit-only triage, and `agent_scan` for multi-project JSON output or optional auto-rotation.",
      "Read-only — never writes. Returns a multi-line text summary: header counts (Total / Healthy / Stale / Expired / No decay / Anomalies), then per-secret `EXPIRED:` / `STALE:` issue lines, then per-anomaly `[type] description` lines.",
    ].join(" "),
    {
      scope,
      projectPath,
      teamId,
      orgId,
    },
    async (params) => {
      const toolBlock = enforceToolPolicy("health_check", params.projectPath);
      if (toolBlock) return toolBlock;

      const entries = listSecrets(opts(params));
      const anomalies = detectAnomalies();

      let healthy = 0;
      let stale = 0;
      let expired = 0;
      let noDecay = 0;
      const issues: string[] = [];

      for (const entry of entries) {
        if (!entry.decay?.timeRemaining) {
          noDecay++;
          continue;
        }
        if (entry.decay.isExpired) {
          expired++;
          issues.push(`EXPIRED: ${entry.key}`);
        } else if (entry.decay.isStale) {
          stale++;
          issues.push(
            `STALE: ${entry.key} (${entry.decay.lifetimePercent}%, ${entry.decay.timeRemaining} left)`,
          );
        } else {
          healthy++;
        }
      }

      const summary = [
        `Secrets: ${entries.length} total`,
        `Healthy: ${healthy} | Stale: ${stale} | Expired: ${expired} | No decay: ${noDecay}`,
        `Anomalies: ${anomalies.length}`,
      ];

      if (issues.length > 0) {
        summary.push("", "Issues:", ...issues);
      }
      if (anomalies.length > 0) {
        summary.push(
          "",
          "Anomalies:",
          ...anomalies.map((a) => `[${a.type}] ${a.description}`),
        );
      }

      return text(summary.join("\n"));
    },
  );

  server.tool(
    "verify_audit_chain",
    [
      "[audit] Recompute the SHA-256 hash chain over the audit log and confirm no event has been mutated, deleted, or reordered.",
      "Use periodically as a tamper-evidence check, or whenever you suspect the audit log has been touched outside q-ring; the result is informational — this tool does not repair the chain if it is broken.",
      "Read-only. Returns JSON `{ ok, valid, brokenAt? }` where `valid` is `true` for an intact chain and `brokenAt` (when present) names the first event whose hash did not match.",
    ].join(" "),
    {},
    async () => {
      const toolBlock = enforceToolPolicy("verify_audit_chain");
      if (toolBlock) return toolBlock;

      const result = verifyAuditChain();
      return text(JSON.stringify(result, null, 2));
    },
  );

  server.tool(
    "export_audit",
    [
      "[audit] Export the audit log as a portable text artifact suitable for archiving or feeding into another SIEM/analyzer.",
      "Use for compliance exports, after-the-fact investigations, or to hand the trail to a non-MCP consumer; prefer `audit_log` for an in-conversation tail and `verify_audit_chain` to confirm integrity before exporting.",
      "Read-only. Returns the rendered text directly (no JSON wrapper). 'jsonl' is one event per line; 'json' is a single array; 'csv' is a header row plus events. Time filters are applied to the event timestamps before formatting.",
    ].join(" "),
    {
      since: z
        .string()
        .optional()
        .describe(
          "Inclusive lower bound on event timestamp, ISO 8601. Example: '2026-04-01T00:00:00Z'. Omit for no lower bound.",
        ),
      until: z
        .string()
        .optional()
        .describe(
          "Inclusive upper bound on event timestamp, ISO 8601. Omit for now/no upper bound.",
        ),
      format: z
        .enum(["jsonl", "json", "csv"])
        .optional()
        .default("jsonl")
        .describe(
          "Output format. 'jsonl' (default) is most stream-friendly; 'json' is a single array; 'csv' is spreadsheet-friendly.",
        ),
    },
    async (params) => {
      const toolBlock = enforceToolPolicy("export_audit");
      if (toolBlock) return toolBlock;

      const output = exportAudit({
        since: params.since,
        until: params.until,
        format: params.format,
        // Same rationale as audit_log: trip records stay operator-facing.
        excludeActions: ["canary"],
      });
      return text(output);
    },
  );
}
