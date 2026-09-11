import type { Command } from "commander";
import { listSecrets } from "../../core/keyring.js";
import { queryAudit, detectAnomalies, verifyAuditChain, exportAudit } from "../../core/observer.js";
import { listAgentSessions } from "../../core/sessions.js";
import { writeFileSync } from "node:fs";
import { c, SYMBOLS } from "../../utils/colors.js";
import { emitJson } from "../helpers.js";
import { buildOpts } from "../options.js";

/** `--since` accepts an ISO date or a duration such as 30m, 24h, 7d. */
export function parseSince(value: string): string {
  const m = value.trim().match(/^(\d+)\s*([mhd])$/i);
  if (m) {
    const unit = { m: 60, h: 3600, d: 86400 }[m[2].toLowerCase() as "m" | "h" | "d"];
    return new Date(Date.now() - Number(m[1]) * unit * 1000).toISOString();
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    throw new Error(`--since: "${value}" is not an ISO date or a duration like 24h / 7d`);
  }
  return date.toISOString();
}

function fmtSeconds(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h`;
  return `${Math.floor(seconds / 86400)}d`;
}

export function registerAuditCommands(program: Command): void {
  program
    .command("audit")
    .description("View the audit log (observer effect)")
    .option("-k, --key <key>", "Filter by key")
    .option("-a, --action <action>", "Filter by action (read, write, delete, etc.)")
    .option("--agent <label>", "Filter by agent label (clientInfo name@version)")
    .option("-n, --limit <n>", "Number of events to show", parseInt, 20)
    .option("--anomalies", "Detect access anomalies")
    .option("--json", "Output as JSON")
    .action((cmd) => {
      if (cmd.anomalies) {
        const anomalies = detectAnomalies(cmd.key);
        if (emitJson(program, cmd, { anomalies })) return;
        if (anomalies.length === 0) {
          console.log(`${SYMBOLS.shield} ${c.green("No anomalies detected")}`);
          return;
        }

        console.log(
          `\n${SYMBOLS.warning} ${c.bold(c.yellow(`${anomalies.length} anomaly/anomalies detected`))}\n`,
        );
        for (const a of anomalies) {
          console.log(`  ${c.yellow(a.type)} ${a.description}`);
        }
        console.log();
        return;
      }

      const events = queryAudit({
        key: cmd.key,
        action: cmd.action,
        agent: cmd.agent,
        limit: cmd.limit,
      });

      if (emitJson(program, cmd, { events })) return;

      if (events.length === 0) {
        console.log(c.dim("No audit events found"));
        return;
      }

      console.log(c.bold(`\n  ${SYMBOLS.eye} Audit log (${events.length} events)\n`));

      for (const event of events) {
        const ts = new Date(event.timestamp).toLocaleString();
        const actionColor =
          event.action === "read"
            ? c.blue
            : event.action === "write"
              ? c.green
              : event.action === "delete"
                ? c.red
                : c.yellow;

        const parts = [
          c.dim(ts),
          actionColor(event.action.padEnd(8)),
          event.key ? c.bold(event.key) : "",
          event.scope ? c.dim(`[${event.scope}]`) : "",
          event.agent ? c.cyan(`⟨${event.agent}⟩`) : "",
          event.detail ? c.dim(event.detail) : "",
        ];

        console.log(`  ${parts.filter(Boolean).join("  ")}`);
      }
      console.log();
    });

  program
    .command("audit:verify")
    .description("Verify the integrity of the audit hash chain")
    .option("--json", "Output as JSON")
    .action((cmd) => {
      const result = verifyAuditChain();
      if (emitJson(program, cmd, result)) {
        if (!result.intact && result.totalEvents > 0) process.exitCode = 1;
        return;
      }
      if (result.totalEvents === 0) {
        console.log(c.dim("  No audit events to verify"));
        return;
      }

      if (result.intact) {
        console.log(
          `${SYMBOLS.shield} ${c.green("Audit chain intact")} — ${result.totalEvents} events verified`,
        );
      } else {
        console.log(`${SYMBOLS.cross} ${c.red("Audit chain BROKEN")} at event #${result.brokenAt}`);
        console.log(
          c.dim(`  ${result.validEvents}/${result.totalEvents} events valid before break`),
        );
        if (result.brokenEvent) {
          console.log(
            c.dim(
              `  Broken event: ${result.brokenEvent.timestamp} ${result.brokenEvent.action} ${result.brokenEvent.key ?? ""}`,
            ),
          );
        }
        process.exitCode = 1;
      }
    });

  program
    .command("audit:export")
    .description("Export audit events in a portable format")
    .option("--since <date>", "Start date (ISO 8601)")
    .option("--until <date>", "End date (ISO 8601)")
    .option("--format <fmt>", "Output format: jsonl, json, csv", "jsonl")
    .option("-o, --output <file>", "Write to file instead of stdout")
    .action((cmd) => {
      const output = exportAudit({
        since: cmd.since,
        until: cmd.until,
        format: cmd.format,
      });

      if (cmd.output) {
        writeFileSync(cmd.output, output);
        console.log(`${SYMBOLS.check} Exported to ${cmd.output}`);
      } else {
        console.log(output);
      }
    });

  program
    .command("audit:sessions")
    .description("Audit activity folded into per-agent sessions (who did what, per MCP client)")
    .option("--agent <label>", "Only sessions for this agent label (clientInfo name@version)")
    .option("--since <when>", "ISO date, or a duration like 24h / 7d (default: 7d)")
    .option("-n, --limit <n>", "Max sessions to show", parseInt, 20)
    .option("-v, --verbose", "Print each session's event lines")
    .option("--json", "Output as JSON")
    .action((cmd) => {
      const sessions = listAgentSessions({
        agent: cmd.agent,
        since: parseSince(cmd.since ?? "7d"),
        limit: cmd.limit,
      });

      if (emitJson(program, cmd, { sessions })) return;

      if (sessions.length === 0) {
        console.log(
          c.dim(
            "No agent sessions in range. Sessions appear once an MCP client (Cursor, Claude Code, Kiro, or an airlock) has touched the ring.",
          ),
        );
        return;
      }

      console.log(c.bold(`\n  ${SYMBOLS.eye} Agent sessions (${sessions.length})\n`));
      for (const s of sessions) {
        const started = new Date(s.startedAt);
        const ended = new Date(s.endedAt);
        const seconds = Math.max(0, Math.round((ended.getTime() - started.getTime()) / 1000));
        const who = s.wrapLabel ? `airlock: ${s.wrapLabel}` : s.agent;
        const head = [
          c.cyan(`⟨${who}⟩`),
          c.dim(`[${s.source}]`),
          c.dim(
            `${started.toLocaleString()} → ${ended.toLocaleTimeString()} (${fmtSeconds(seconds)})`,
          ),
          `${s.eventCount} events`,
          s.denials > 0 ? c.red(`${s.denials} denied`) : c.green("0 denied"),
          s.countsByAction.canary ? c.red(`${s.countsByAction.canary} canary trips`) : "",
        ];
        console.log(`  ${head.filter(Boolean).join("  ")}`);
        console.log(c.dim(`    id ${s.id} · keys: ${s.keys.length ? s.keys.join(", ") : "—"}`));
        if (cmd.verbose) {
          for (const e of s.events) {
            const parts = [
              c.dim(new Date(e.timestamp).toLocaleTimeString()),
              (e.action === "policy_deny" || e.action === "canary" ? c.red : c.yellow)(
                e.action.padEnd(11),
              ),
              e.key ? c.bold(e.key) : "",
              e.detail ? c.dim(e.detail) : "",
            ];
            console.log(`      ${parts.filter(Boolean).join("  ")}`);
          }
        }
        console.log();
      }
    });

  program
    .command("health")
    .description("Check the health of all secrets")
    .option("-g, --global", "Check global scope only")
    .option("-p, --project", "Check project scope only")
    .option("--project-path <path>", "Explicit project path")
    .option("--json", "Output as JSON")
    .action((cmd) => {
      const opts = buildOpts(cmd);
      const entries = listSecrets(opts);

      const expiredKeys: string[] = [];
      const staleKeys: Array<{ key: string; lifetimePercent: number; timeRemaining: string }> = [];
      let healthy = 0;
      let noDecay = 0;

      for (const entry of entries) {
        if (!entry.decay || !entry.decay.timeRemaining) {
          noDecay++;
        } else if (entry.decay.isExpired) {
          expiredKeys.push(entry.key);
        } else if (entry.decay.isStale) {
          staleKeys.push({
            key: entry.key,
            lifetimePercent: entry.decay.lifetimePercent,
            timeRemaining: entry.decay.timeRemaining,
          });
        } else {
          healthy++;
        }
      }

      if (
        emitJson(program, cmd, {
          total: entries.length,
          healthy,
          noDecay,
          expired: expiredKeys,
          stale: staleKeys,
          anomalies: entries.length === 0 ? [] : detectAnomalies(),
        })
      ) {
        return;
      }

      if (entries.length === 0) {
        console.log(c.dim("No secrets to check"));
        return;
      }

      console.log(c.bold(`\n  ${SYMBOLS.shield} Secret health report\n`));

      for (const key of expiredKeys) {
        console.log(`  ${c.red(SYMBOLS.cross)} ${c.bold(key)} ${c.bgRed(c.white(" EXPIRED "))}`);
      }
      for (const s of staleKeys) {
        console.log(
          `  ${c.yellow(SYMBOLS.warning)} ${c.bold(s.key)} ${c.yellow(`stale (${s.lifetimePercent}%, ${s.timeRemaining} left)`)}`,
        );
      }

      console.log(
        `\n  ${c.green(`${SYMBOLS.check} ${healthy} healthy`)}  ${c.yellow(`${SYMBOLS.warning} ${staleKeys.length} stale`)}  ${c.red(`${SYMBOLS.cross} ${expiredKeys.length} expired`)}  ${c.dim(`${noDecay} no decay`)}`,
      );

      const anomalies = detectAnomalies();
      if (anomalies.length > 0) {
        console.log(
          `\n  ${c.yellow(`${SYMBOLS.warning} ${anomalies.length} access anomaly/anomalies detected`)} ${c.dim("(run: qring audit --anomalies)")}`,
        );
      }

      console.log();
    });
}
