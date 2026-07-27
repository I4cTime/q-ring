import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { listSecrets } from "../../core/keyring.js";
import { runHealthScan } from "../../core/agent.js";
import { queryAudit } from "../../core/observer.js";
import { execCommand } from "../../core/exec.js";
import { scanCodebase } from "../../core/scan.js";
import { lintFiles } from "../../core/linter.js";
import { checkExecPolicy } from "../../core/policy.js";
import { text, opts, enforceToolPolicy, commonSchemas } from "./_shared.js";

const { teamId, orgId, scope, projectPath } = commonSchemas;

export function registerToolingTools(server: McpServer): void {
  server.tool(
    "exec_with_secrets",
    [
      "[exec] Run a child shell command with project secrets injected as environment variables and any leaked secret values redacted from captured stdout/stderr before they return to the agent.",
      "Use to let an agent run a script that needs credentials (`npm run db:migrate`, `terraform plan`, `vercel deploy`) without ever putting plaintext values in the chat; prefer `env_generate` if you need to write a `.env` file to disk and `validate_secret` for upstream liveness checks.",
      "Spawns a real child process — has whatever side effects the command itself causes (writes, network, exec). Subject to BOTH tool policy and exec policy (allowlist/denylist). Returns a text body with `Exit code: N` then `STDOUT:` and `STDERR:` blocks; both streams are scrubbed against the secret values that were injected.",
    ].join(" "),
    {
      command: z
        .string()
        .describe(
          "Executable name or full command to run. Example: 'pnpm', 'node', '/usr/bin/env'. Must be allowed by exec policy.",
        ),
      args: z
        .array(z.string())
        .optional()
        .describe(
          "Positional arguments passed to `command`. Example: ['run', 'db:migrate']. Each element is passed verbatim with no extra shell parsing.",
        ),
      keys: z
        .array(z.string())
        .optional()
        .describe(
          "Whitelist of exact key names to inject. Omit to inject every secret in scope (subject to `tags`).",
        ),
      tags: z
        .array(z.string())
        .optional()
        .describe(
          "Inject only secrets carrying at least one of these tags. Combinable with `keys` as an AND filter.",
        ),
      profile: z
        .enum(["unrestricted", "restricted", "ci"])
        .optional()
        .default("restricted")
        .describe(
          "Exec sandbox profile. 'restricted' (default) denies a fixed list of network-tool binaries (curl, wget, ssh, scp, nc, netcat, ncat), strips proxy env vars, and caps runtime at 30s — it is NOT a real sandbox: it does not restrict PATH, and interpreters invoked directly (python, node, perl, etc.) can still make network requests and read the injected secret env vars. 'ci' allows network with a 300s cap and blocks a few destructive commands; 'unrestricted' inherits the full server environment. For untrusted commands use OS-level isolation (containers, network namespaces), not this profile.",
        ),
      scope,
      projectPath,
      teamId,
      orgId,
    },
    async (params) => {
      const toolBlock = enforceToolPolicy("exec_with_secrets", params.projectPath);
      if (toolBlock) return toolBlock;

      const execBlock = checkExecPolicy(params.command, params.projectPath);
      if (!execBlock.allowed) {
        return text(`Policy Denied: ${execBlock.reason}`, true);
      }

      try {
        const result = await execCommand({
          command: params.command,
          args: params.args ?? [],
          keys: params.keys,
          tags: params.tags,
          profile: params.profile,
          scope: params.scope,
          projectPath: params.projectPath,
          source: "mcp",
          captureOutput: true,
        });

        const output: string[] = [];
        output.push(`Exit code: ${result.code}`);
        if (result.stdout) output.push(`STDOUT:\n${result.stdout}`);
        if (result.stderr) output.push(`STDERR:\n${result.stderr}`);

        return text(output.join("\n\n"));
      } catch (err) {
        return text(
          `Execution failed: ${err instanceof Error ? err.message : String(err)}`,
          true,
        );
      }
    },
  );

  server.tool(
    "scan_codebase_for_secrets",
    [
      "[scan] Walk a directory tree and flag plausible hardcoded secrets using regex heuristics plus Shannon-entropy scoring on string literals.",
      "Use as a one-shot 'is anything leaking in this repo?' audit before commit/release; prefer `lint_files` when you already know the specific files to check (and want optional auto-fix).",
      "Read-only — never modifies source files. Honors `.gitignore`. Returns JSON array of `{ file, line, key, value, kind }` findings, or 'No hardcoded secrets found in the specified directory.' when clean. False positives are possible — review before treating as ground truth.",
    ].join(" "),
    {
      dirPath: z
        .string()
        .describe(
          "Directory to scan, absolute or relative to the server cwd. The scan recurses into subdirectories.",
        ),
    },
    async (params) => {
      const toolBlock = enforceToolPolicy("scan_codebase_for_secrets");
      if (toolBlock) return toolBlock;

      try {
        const results = scanCodebase(params.dirPath);
        if (results.length === 0) {
          return text("No hardcoded secrets found in the specified directory.");
        }
        return text(JSON.stringify(results, null, 2));
      } catch (err) {
        return text(
          `Scan failed: ${err instanceof Error ? err.message : String(err)}`,
          true,
        );
      }
    },
  );

  server.tool(
    "lint_files",
    [
      "[scan] Inspect a specific list of files for hardcoded secrets and, when `fix` is true, replace each finding with `process.env.KEY` while storing the extracted value into the keyring.",
      "Use to migrate a known set of files (e.g. just-changed files in a pre-commit hook) into q-ring; prefer `scan_codebase_for_secrets` for a whole-tree audit and `import_dotenv` to ingest an existing .env.",
      "With `fix: false` this is read-only. With `fix: true` this MUTATES the listed source files in place (review with git diff!) and writes one new secret per finding to the keyring. Returns a JSON array of `{ file, line, key, value, kind }` findings, or 'No hardcoded secrets found in the specified files.'.",
    ].join(" "),
    {
      files: z
        .array(z.string())
        .describe(
          "Absolute or relative paths to lint. Non-existent paths surface as scan errors.",
        ),
      fix: z
        .boolean()
        .optional()
        .default(false)
        .describe(
          "If true, rewrite the source files to read `process.env.KEY` and store the extracted value in the keyring. If false (default), only report findings.",
        ),
      scope,
      projectPath,
      teamId,
      orgId,
    },
    async (params) => {
      const toolBlock = enforceToolPolicy("lint_files", params.projectPath);
      if (toolBlock) return toolBlock;

      try {
        const results = lintFiles(params.files, {
          fix: params.fix,
          scope: params.scope as "global" | "project" | undefined,
          projectPath: params.projectPath,
        });
        if (results.length === 0) {
          return text("No hardcoded secrets found in the specified files.");
        }
        return text(JSON.stringify(results, null, 2));
      } catch (err) {
        return text(
          `Lint failed: ${err instanceof Error ? err.message : String(err)}`,
          true,
        );
      }
    },
  );

  server.tool(
    "analyze_secrets",
    [
      "[agent] Cross-reference the secrets in scope with recent audit events to produce a usage profile and rotation/retirement suggestions.",
      "Use as a quarterly hygiene check or as input to a planner that decides what to rotate or delete; prefer `health_check` for decay-only triage and `audit_log` to inspect access timelines for one key.",
      "Read-only; uses the most recent ~500 audit events. Returns JSON `{ total, expired, stale, neverAccessed: [...], noRotationFormat: [...], mostAccessed: [{ key, reads }] }`. `neverAccessed` and `noRotationFormat` are good candidates for cleanup or for adding rotation hints.",
    ].join(" "),
    {
      scope,
      projectPath,
      teamId,
      orgId,
    },
    async (params) => {
      const toolBlock = enforceToolPolicy("analyze_secrets", params.projectPath);
      if (toolBlock) return toolBlock;

      const o = opts(params);
      const entries = listSecrets({ ...o, silent: true });
      const audit = queryAudit({ limit: 500 });

      const accessMap = new Map<string, number>();
      for (const e of audit) {
        if (e.action === "read" && e.key) {
          accessMap.set(e.key, (accessMap.get(e.key) || 0) + 1);
        }
      }

      const analysis = {
        total: entries.length,
        expired: entries.filter((e) => e.decay?.isExpired).length,
        stale: entries.filter((e) => e.decay?.isStale && !e.decay?.isExpired)
          .length,
        neverAccessed: entries
          .filter((e) => (e.envelope?.meta.accessCount ?? 0) === 0)
          .map((e) => e.key),
        noRotationFormat: entries
          .filter((e) => !e.envelope?.meta.rotationFormat)
          .map((e) => e.key),
        mostAccessed: [...accessMap.entries()]
          .sort((a, b) => b[1] - a[1])
          .slice(0, 10)
          .map(([key, count]) => ({ key, reads: count })),
      };

      return text(JSON.stringify(analysis, null, 2));
    },
  );

  // One process-scoped instance; reusing across tool invocations avoids
  // leaking listeners when the MCP client pings `status_dashboard` twice.
  let dashboardInstance: { port: number; url: string; close: () => void } | null = null;

  server.tool(
    "status_dashboard",
    [
      "[dashboard] Start a local web dashboard (`http://127.0.0.1:PORT`) that streams live KPIs, secret tables, manifest gaps, hooks, audit events, and anomalies via Server-Sent Events.",
      "Use when an operator (or an agent on behalf of one) wants a richer visual surface than chat output; prefer `health_check` / `analyze_secrets` for one-shot text summaries inside the conversation.",
      "Side effect: binds an HTTP server on the requested port (one process-wide instance — re-running returns the existing URL instead of starting a second server). Never exposes secret values. Returns the URL string to open in a browser.",
    ].join(" "),
    {
      port: z
        .number()
        .optional()
        .default(9876)
        .describe(
          "TCP port to listen on (default 9876). Pick another port if 9876 is already in use; the call fails if binding errors.",
        ),
    },
    async (params) => {
      const toolBlock = enforceToolPolicy("status_dashboard");
      if (toolBlock) return toolBlock;

      if (dashboardInstance) {
        return text(
          `Dashboard already running at ${dashboardInstance.url}`,
        );
      }

      const { startDashboardServer } = await import("../../core/dashboard.js");
      dashboardInstance = startDashboardServer({ port: params.port });

      return text(
        `Dashboard started at ${dashboardInstance.url}\nOpen this URL in a browser to see live quantum status. The token is required for access.`,
      );
    },
  );

  server.tool(
    "agent_scan",
    [
      "[agent] Run a multi-project health pass that gathers decay status, audit anomalies, and `.q-ring.json` manifest gaps across one or more project paths and (optionally) auto-rotates expired secrets with freshly generated values.",
      "Use as the canonical 'agent maintenance loop' across a portfolio of repos; prefer `health_check` for a single read-only scope, `detect_anomalies` for audit-only triage, and `check_project` for a single-project manifest check.",
      "With `autoRotate=false` (default) this is read-only. With `autoRotate=true` it OVERWRITES expired secret values in the keyring with generated replacements — credential changes that may break upstream integrations until they are propagated. Subject to tool policy. Returns a JSON report of per-project findings and any rotations performed.",
    ].join(" "),
    {
      autoRotate: z
        .boolean()
        .optional()
        .default(false)
        .describe(
          "If true, replace expired secrets with newly generated values (using each secret's `rotationFormat`/`rotationPrefix`). Only enable when intentional rotation is desired — this is destructive on the upstream side.",
        ),
      projectPaths: z
        .array(z.string())
        .optional()
        .describe(
          "List of absolute project roots to scan. Defaults to `[server.cwd]` when omitted.",
        ),
    },
    async (params) => {
      const toolBlock = enforceToolPolicy("agent_scan");
      if (toolBlock) return toolBlock;

      const report = runHealthScan({
        autoRotate: params.autoRotate,
        projectPaths: params.projectPaths ?? [process.cwd()],
      });
      return text(JSON.stringify(report, null, 2));
    },
  );
}
