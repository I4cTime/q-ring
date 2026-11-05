/**
 * Quantum Agent: autonomous background monitor for secret health.
 *
 * Runs as a long-lived process that periodically:
 * - Checks for expired/stale secrets (decay monitoring)
 * - Detects access anomalies (observer analysis)
 * - Logs health reports
 * - Can trigger rotation callbacks
 *
 * Designed to run as `qring agent` or be invoked by the MCP server.
 */

import { listSecrets, setSecret, checkKeyWritePolicy } from "./keyring.js";
import { checkDecay } from "./envelope.js";
import { detectAnomalies, logAudit } from "./observer.js";
import { generateSecret } from "./noise.js";
import { fireHooks } from "./hooks.js";
import { c, SYMBOLS } from "../utils/colors.js";

export interface AgentConfig {
  /** Check interval in seconds (default: 60) */
  intervalSeconds: number;
  /** Auto-rotate expired secrets with generated values */
  autoRotate: boolean;
  /** Project paths to monitor */
  projectPaths: string[];
  /** Verbose output */
  verbose: boolean;
  /**
   * Who the auto-rotation writes are attributed to and judged as. The MCP
   * agent_scan tool passes "mcp" so its rotations face the same key policy
   * as any other MCP write; the local daemon keeps "agent".
   */
  writeSource?: "agent" | "mcp";
}

export interface AgentReport {
  timestamp: string;
  totalSecrets: number;
  healthy: number;
  stale: number;
  expired: number;
  anomalies: number;
  rotated: string[];
  /** Expired keys auto-rotation left alone because key policy denies the write. */
  rotationSkipped: { key: string; reason: string }[];
  warnings: string[];
}

function defaultConfig(): AgentConfig {
  return {
    intervalSeconds: 60,
    autoRotate: false,
    projectPaths: [process.cwd()],
    verbose: false,
  };
}

export function runHealthScan(config: Partial<AgentConfig> = {}): AgentReport {
  const cfg = { ...defaultConfig(), ...config };

  const report: AgentReport = {
    timestamp: new Date().toISOString(),
    totalSecrets: 0,
    healthy: 0,
    stale: 0,
    expired: 0,
    anomalies: 0,
    rotated: [],
    rotationSkipped: [],
    warnings: [],
  };
  const writeSource = cfg.writeSource ?? "agent";

  // Scan global scope
  const globalEntries = listSecrets({ scope: "global", source: "agent" });

  // Scan project scopes
  const projectEntries = cfg.projectPaths.flatMap((pp) =>
    listSecrets({ scope: "project", projectPath: pp, source: "agent" }),
  );

  const allEntries = [...globalEntries, ...projectEntries];
  report.totalSecrets = allEntries.length;

  for (const entry of allEntries) {
    if (!entry.envelope) continue;

    const decay = checkDecay(entry.envelope);

    if (decay.isExpired) {
      report.expired++;
      report.warnings.push(
        `EXPIRED: ${entry.key} [${entry.scope}] — expired ${decay.timeRemaining}`,
      );

      const writeOpts = {
        scope: entry.scope,
        projectPath: cfg.projectPaths[0],
        source: writeSource,
      };
      const decision = cfg.autoRotate ? checkKeyWritePolicy(entry.key, writeOpts) : null;
      if (decision && !decision.allowed) {
        report.rotationSkipped.push({
          key: entry.key,
          reason: decision.reason ?? "denied by policy",
        });
      } else if (cfg.autoRotate) {
        const fmt = (entry.envelope?.meta.rotationFormat ?? "api-key") as import("./noise.js").NoiseFormat;
        const prefix = entry.envelope?.meta.rotationPrefix;
        const newValue = generateSecret({ format: fmt, prefix });
        setSecret(entry.key, newValue, writeOpts);
        report.rotated.push(entry.key);
        logAudit({
          action: "write",
          key: entry.key,
          scope: entry.scope,
          source: writeSource,
          detail: "auto-rotated by agent (expired)",
        });
        fireHooks({
          action: "rotate",
          key: entry.key,
          scope: entry.scope,
          timestamp: new Date().toISOString(),
          source: writeSource,
        }, entry.envelope?.meta.tags).catch(() => {});
      }
    } else if (decay.isStale) {
      report.stale++;
      report.warnings.push(
        `STALE: ${entry.key} [${entry.scope}] — ${decay.lifetimePercent}% lifetime, ${decay.timeRemaining} remaining`,
      );
    } else {
      report.healthy++;
    }
  }

  // Check for anomalies
  const anomalies = detectAnomalies();
  report.anomalies = anomalies.length;
  for (const a of anomalies) {
    report.warnings.push(`ANOMALY [${a.type}]: ${a.description}`);
  }

  return report;
}

function formatReport(report: AgentReport, verbose: boolean): string {
  const lines: string[] = [];

  lines.push(
    `${c.bold(`${SYMBOLS.shield} q-ring agent scan`)} ${c.dim(report.timestamp)}`,
  );
  lines.push(
    `  ${c.dim("secrets:")} ${report.totalSecrets}  ${c.green(`${SYMBOLS.check} ${report.healthy}`)}  ${c.yellow(`${SYMBOLS.warning} ${report.stale}`)}  ${c.red(`${SYMBOLS.cross} ${report.expired}`)}  ${c.dim(`anomalies: ${report.anomalies}`)}`,
  );

  if (report.rotated.length > 0) {
    lines.push(
      `  ${c.cyan(`${SYMBOLS.zap} auto-rotated:`)} ${report.rotated.join(", ")}`,
    );
  }

  if (verbose && report.warnings.length > 0) {
    lines.push("");
    for (const w of report.warnings) {
      if (w.startsWith("EXPIRED")) lines.push(`  ${c.red(w)}`);
      else if (w.startsWith("STALE")) lines.push(`  ${c.yellow(w)}`);
      else if (w.startsWith("ANOMALY")) lines.push(`  ${c.magenta(w)}`);
      else lines.push(`  ${w}`);
    }
  }

  return lines.join("\n");
}

/**
 * Run the agent as a continuous background monitor.
 */
export async function startAgent(config: Partial<AgentConfig> = {}): Promise<void> {
  const cfg = { ...defaultConfig(), ...config };

  console.log(
    `${c.bold(`${SYMBOLS.zap} q-ring agent started`)} ${c.dim(`(interval: ${cfg.intervalSeconds}s, auto-rotate: ${cfg.autoRotate})`)}`,
  );
  console.log(
    c.dim(`  monitoring: global + ${cfg.projectPaths.length} project(s)`),
  );
  console.log();

  const scan = () => {
    const report = runHealthScan(cfg);
    console.log(formatReport(report, cfg.verbose));

    if (report.warnings.length > 0 || cfg.verbose) {
      console.log();
    }
  };

  // Initial scan
  scan();

  // Continuous monitoring
  const interval = setInterval(scan, cfg.intervalSeconds * 1000);

  // Graceful shutdown
  const shutdown = () => {
    clearInterval(interval);
    console.log(`\n${c.dim("q-ring agent stopped")}`);
    process.exit(0);
  };

  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);

  // Keep alive
  await new Promise(() => {});
}
