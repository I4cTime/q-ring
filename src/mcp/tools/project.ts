import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { toolAnnotations } from "../tool-annotations.js";
import { getSecret, getEnvelope } from "../../core/keyring.js";
import { checkDecay } from "../../core/envelope.js";
import { collapseEnvironment, readProjectConfig } from "../../core/collapse.js";
import { getProjectContext } from "../../core/context.js";
import { text, opts, enforceToolPolicy, commonSchemas } from "./_shared.js";

const { teamId, orgId, scope, projectPath, env } = commonSchemas;

export function registerProjectTools(server: McpServer): void {
  server.tool(
    "check_project",
    [
      "[project] Compare the keys declared in the project's `.q-ring.json` manifest against what is actually present in the keyring.",
      "Use as the canonical 'is this project ready to run' gate before starting a dev server, deploying, or onboarding a teammate; prefer `health_check` for a scope-wide decay sweep (no manifest), and `agent_scan` for multi-project scans with optional auto-rotation.",
      "Read-only; does not mutate the keyring or audit log materially beyond a 'list' read. Returns JSON `{ total, present, missing, expired, stale, ready, secrets: [...] }` where `ready` is true only when nothing is missing or expired. Errors with 'No secrets manifest found in .q-ring.json' if the project has no manifest.",
    ].join(" "),
    {
      projectPath,
    },
    toolAnnotations("check_project"),
    async (params) => {
      const toolBlock = enforceToolPolicy("check_project", params.projectPath);
      if (toolBlock) return toolBlock;

      const pp = params.projectPath ?? process.cwd();
      const config = readProjectConfig(pp);

      if (!config?.secrets || Object.keys(config.secrets).length === 0) {
        return text("No secrets manifest found in .q-ring.json", true);
      }

      const results: Record<string, unknown>[] = [];
      let presentCount = 0;
      let missingCount = 0;
      let expiredCount = 0;
      let staleCount = 0;

      for (const [key, manifest] of Object.entries(config.secrets)) {
        const result = getEnvelope(key, { projectPath: pp, source: "mcp" });

        if (!result) {
          const status = manifest.required !== false ? "missing" : "optional_missing";
          if (manifest.required !== false) missingCount++;
          results.push({
            key,
            status,
            required: manifest.required !== false,
            description: manifest.description,
          });
          continue;
        }

        const decay = checkDecay(result.envelope);

        if (decay.isExpired) {
          expiredCount++;
          results.push({
            key,
            status: "expired",
            timeRemaining: decay.timeRemaining,
            description: manifest.description,
          });
        } else if (decay.isStale) {
          staleCount++;
          results.push({
            key,
            status: "stale",
            lifetimePercent: decay.lifetimePercent,
            timeRemaining: decay.timeRemaining,
            description: manifest.description,
          });
        } else {
          presentCount++;
          results.push({ key, status: "ok", description: manifest.description });
        }
      }

      const summary = {
        total: Object.keys(config.secrets).length,
        present: presentCount,
        missing: missingCount,
        expired: expiredCount,
        stale: staleCount,
        ready: missingCount === 0 && expiredCount === 0,
        secrets: results,
      };

      return text(JSON.stringify(summary, null, 2));
    },
  );

  server.tool(
    "env_generate",
    [
      "[project] Render a complete `.env` file body from the project's `.q-ring.json` manifest, resolving each declared key from the keyring.",
      "Use when a build step or local runtime needs a real `.env` materialized on disk and you want exactly the keys the manifest declares; prefer `export_secrets` when you want every key in scope (manifest-agnostic) and `exec_with_secrets` to inject secrets into a child process without writing them to a file.",
      "Reads values (records 'read' audit events) and collapses superposition for the requested env. Returns the raw `.env` text, with `# MISSING (required): KEY` / `# EXPIRED: KEY` / `# STALE: KEY` warnings appended as comments. Missing keys appear as commented-out `# KEY=` placeholders so the file remains a valid drop-in.",
    ].join(" "),
    {
      projectPath,
      env,
    },
    toolAnnotations("env_generate"),
    async (params) => {
      const toolBlock = enforceToolPolicy("env_generate", params.projectPath);
      if (toolBlock) return toolBlock;

      const pp = params.projectPath ?? process.cwd();
      const config = readProjectConfig(pp);

      if (!config?.secrets || Object.keys(config.secrets).length === 0) {
        return text("No secrets manifest found in .q-ring.json", true);
      }

      const lines: string[] = [];
      const warnings: string[] = [];

      for (const [key, manifest] of Object.entries(config.secrets)) {
        const value = getSecret(key, {
          projectPath: pp,
          env: params.env,
          source: "mcp",
        });

        if (value === null) {
          if (manifest.required !== false) {
            warnings.push(`MISSING (required): ${key}`);
          }
          lines.push(`# ${key}=`);
          continue;
        }

        const result = getEnvelope(key, { projectPath: pp, source: "mcp" });
        if (result) {
          const decay = checkDecay(result.envelope);
          if (decay.isExpired) warnings.push(`EXPIRED: ${key}`);
          else if (decay.isStale) warnings.push(`STALE: ${key}`);
        }

        const escaped = value.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\n/g, "\\n");
        lines.push(`${key}="${escaped}"`);
      }

      const output = lines.join("\n");
      const result =
        warnings.length > 0
          ? `${output}\n\n# Warnings:\n${warnings.map((w) => `# ${w}`).join("\n")}`
          : output;

      return text(result);
    },
  );

  server.tool(
    "detect_environment",
    [
      "[project] Resolve which environment slug (e.g. 'dev', 'staging', 'prod') the current invocation should collapse to.",
      "Use before reading secrets when you want to mirror the same env q-ring would auto-pick (e.g. to log it, or to pass through to another tool); prefer passing an explicit `env` to `get_secret`/`env_generate` when you already know which env you want.",
      "Read-only; checks the QRING_ENV env var, NODE_ENV, the project's `.q-ring.json`, and the current git branch in priority order. Returns JSON `{ env, source }` (e.g. `{ env: 'dev', source: 'NODE_ENV' }`), or a plain message indicating that no env could be detected.",
    ].join(" "),
    {
      projectPath,
    },
    toolAnnotations("detect_environment"),
    async (params) => {
      const toolBlock = enforceToolPolicy("detect_environment", params.projectPath);
      if (toolBlock) return toolBlock;

      const result = collapseEnvironment({
        projectPath: params.projectPath ?? process.cwd(),
      });

      if (!result) {
        return text("No environment detected. Set QRING_ENV, NODE_ENV, or create .q-ring.json");
      }

      return text(JSON.stringify(result, null, 2));
    },
  );

  server.tool(
    "get_project_context",
    [
      "[agent] Return a single redacted snapshot of everything an AI agent typically wants to know about this project: secrets present (keys + metadata only), detected env, manifest declarations, configured providers, registered hooks, and recent audit activity.",
      "Use this as the very first call in a session to orient the agent before it asks for any individual secret; prefer `list_secrets` for a flat key listing, `check_project` for manifest-vs-keyring drift, and `audit_log` for a deeper access trail.",
      "Read-only and value-safe — no plaintext secret values are ever included. Returns a single pretty-printed JSON document; shape is intentionally broad and may grow over time, so read defensively.",
    ].join(" "),
    {
      scope,
      projectPath,
      teamId,
      orgId,
    },
    toolAnnotations("get_project_context"),
    async (params) => {
      const toolBlock = enforceToolPolicy("get_project_context", params.projectPath);
      if (toolBlock) return toolBlock;

      const context = getProjectContext(opts(params));
      return text(JSON.stringify(context, null, 2));
    },
  );
}
