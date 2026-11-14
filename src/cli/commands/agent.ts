import type { Command } from "commander";
import { listSecrets } from "../../core/keyring.js";
import { startAgent, runHealthScan } from "../../core/agent.js";
import { queryAudit } from "../../core/observer.js";
import {
  remember,
  recall,
  listMemory,
  forget,
  clearMemory,
} from "../../core/memory.js";
import { c, SYMBOLS } from "../../utils/colors.js";
import { safeStr, emitJson } from "../helpers.js";
import { confirm } from "../../utils/prompt.js";
import { buildOpts } from "../options.js";

export function registerAgentCommands(program: Command): void {
  // ─── Agent Memory ───

  program
    .command("remember <key> <value>")
    .description(
      "Store a key-value pair in encrypted agent memory (persists across sessions)",
    )
    .action((key: string, value: string) => {
      remember(key, value);
      console.log(`${SYMBOLS.check} ${c.green("remembered")} ${c.bold(key)}`);
    });

  program
    .command("recall [key]")
    .description("Retrieve a value from agent memory, or list all keys")
    .option("--json", "Output as JSON (list mode only)")
    .action((key: string | undefined, cmd) => {
      if (!key) {
        const entries = listMemory();
        if (
          emitJson(
            program,
            cmd,
            entries.map((e) => ({ key: e.key, updatedAt: e.updatedAt })),
          )
        ) {
          return;
        }
        if (entries.length === 0) {
          console.log(c.dim("Agent memory is empty."));
          return;
        }
        console.log(
          `\n${SYMBOLS.zap} ${c.bold("Agent Memory")} (${entries.length} entries)\n`,
        );
        for (const e of entries) {
          console.log(
            `  ${c.bold(e.key)}  ${c.dim(new Date(e.updatedAt).toLocaleString())}`,
          );
        }
        console.log();
        return;
      }

      const value = recall(key);
      if (value === null) {
        console.log(c.dim(`No memory found for "${key}"`));
      } else {
        console.log(safeStr(value));
      }
    });

  program
    .command("forget <key>")
    .description("Delete a key from agent memory")
    .option("--all", "Clear all agent memory")
    .option("-y, --yes", "Skip the confirmation prompt")
    .action(async (key: string, cmd) => {
      if (cmd.all) {
        const count = listMemory().length;
        if (
          !(await confirm(
            `Clear ALL agent memory (${count} entr${count === 1 ? "y" : "ies"})? This cannot be undone.`,
            { assumeYes: cmd.yes },
          ))
        ) {
          console.error(c.dim("Aborted."));
          process.exitCode = 1;
          return;
        }
        clearMemory();
        console.log(`${SYMBOLS.check} ${c.yellow("cleared")} all agent memory`);
        return;
      }
      const removed = forget(key);
      if (removed) {
        console.log(`${SYMBOLS.check} ${c.yellow("forgot")} ${c.bold(key)}`);
      } else {
        console.log(c.dim(`No memory found for "${key}"`));
      }
    });

  // ─── Analytics ───

  program
    .command("analyze")
    .description(
      "Analyze secret usage patterns and provide optimization suggestions",
    )
    .option("-g, --global", "Global scope only")
    .option("-p, --project", "Project scope only")
    .option("--project-path <path>", "Explicit project path")
    .option("--json", "Output as JSON")
    .action((cmd) => {
      const opts = buildOpts(cmd);
      // A lost key (empty stored value) is not analyzed: it would read as
      // merely never accessed. `qring list` shows it, marked empty.
      const entries = listSecrets({ ...opts, silent: true }).filter((e) => !e.emptyStored);
      const audit = queryAudit({ limit: 1000 });

      const accessMap = new Map<string, number>();
      for (const e of audit) {
        if (e.action === "read" && e.key) {
          accessMap.set(e.key, (accessMap.get(e.key) || 0) + 1);
        }
      }

      const sorted = [...accessMap.entries()].sort((a, b) => b[1] - a[1]);
      const neverAccessed = entries.filter((e) => {
        const count = e.envelope?.meta.accessCount ?? 0;
        return count === 0;
      });
      const jsonExpired = entries.filter((e) => e.decay?.isExpired);
      const jsonStale = entries.filter(
        (e) => e.decay?.isStale && !e.decay?.isExpired,
      );
      const jsonNoRotation = entries.filter(
        (e) => !e.envelope?.meta.rotationFormat && !e.decay?.isExpired,
      );

      if (
        emitJson(program, cmd, {
          mostAccessed: sorted
            .slice(0, 5)
            .map(([key, reads]) => ({ key, reads })),
          neverAccessed: neverAccessed.map((e) => e.key),
          expired: jsonExpired.map((e) => e.key),
          stale: jsonStale.map((e) => ({
            key: e.key,
            timeRemaining: e.decay?.timeRemaining ?? null,
          })),
          summary: {
            total: entries.length,
            active: entries.length - jsonExpired.length,
            expired: jsonExpired.length,
            stale: jsonStale.length,
            neverAccessed: neverAccessed.length,
            withRotationConfig: entries.length - jsonNoRotation.length,
          },
        })
      ) {
        return;
      }

      console.log(`\n${SYMBOLS.zap} ${c.bold("Secret Usage Analysis")}\n`);

      if (sorted.length > 0) {
        console.log(`  ${c.bold("Most accessed:")}`);
        for (const [key, count] of sorted.slice(0, 5)) {
          console.log(`    ${c.bold(key)} — ${c.cyan(count.toString())} reads`);
        }
        console.log();
      }

      if (neverAccessed.length > 0) {
        console.log(
          `  ${c.bold("Never accessed:")} ${c.yellow(neverAccessed.length.toString())} secrets`,
        );
        for (const e of neverAccessed.slice(0, 8)) {
          const age = e.envelope?.meta.createdAt
            ? c.dim(
                `(created ${new Date(e.envelope.meta.createdAt).toLocaleDateString()})`,
              )
            : "";
          console.log(`    ${c.dim(SYMBOLS.cross)} ${e.key} ${age}`);
        }
        console.log();
      }

      const expired = entries.filter((e) => e.decay?.isExpired);
      const stale = entries.filter(
        (e) => e.decay?.isStale && !e.decay?.isExpired,
      );
      if (expired.length > 0) {
        console.log(
          `  ${c.red("Expired:")} ${expired.length} secrets need rotation or cleanup`,
        );
        for (const e of expired.slice(0, 5)) {
          console.log(`    ${c.red(SYMBOLS.cross)} ${e.key}`);
        }
        console.log();
      }
      if (stale.length > 0) {
        console.log(
          `  ${c.yellow("Stale (>75% lifetime):")} ${stale.length} secrets approaching expiry`,
        );
        for (const e of stale.slice(0, 5)) {
          console.log(
            `    ${c.yellow(SYMBOLS.warning)} ${e.key} ${c.dim(`(${e.decay?.timeRemaining} remaining)`)}`,
          );
        }
        console.log();
      }

      const globalOnly = entries.filter((e) => e.scope === "global");
      const withProjectTags = globalOnly.filter((e) =>
        e.envelope?.meta.tags?.some((t) =>
          ["backend", "frontend", "db", "api"].includes(t),
        ),
      );
      if (withProjectTags.length > 0) {
        console.log(`  ${c.bold("Scope suggestions:")}`);
        console.log(
          `    ${withProjectTags.length} global secret(s) have project-specific tags — consider moving to project scope`,
        );
        console.log();
      }

      const noRotation = entries.filter(
        (e) => !e.envelope?.meta.rotationFormat && !e.decay?.isExpired,
      );
      if (noRotation.length > 0) {
        console.log(`  ${c.bold("Rotation suggestions:")}`);
        console.log(
          `    ${noRotation.length} secret(s) have no rotation format set`,
        );
        console.log(
          `    Use ${c.bold("qring set <key> <value> --rotation-format api-key")} to enable auto-rotation`,
        );
        console.log();
      }

      console.log(`  ${c.bold("Summary:")}`);
      console.log(`    Total secrets: ${entries.length}`);
      console.log(`    Active: ${entries.length - expired.length}`);
      console.log(`    Expired: ${expired.length}`);
      console.log(`    Stale: ${stale.length}`);
      console.log(`    Never accessed: ${neverAccessed.length}`);
      console.log(
        `    With rotation config: ${entries.length - noRotation.length}`,
      );
      console.log();
    });

  // ─── Agent Mode ───

  program
    .command("agent")
    .description("Start the autonomous agent (background monitor)")
    .option(
      "-i, --interval <seconds>",
      "Scan interval in seconds",
      parseInt,
      60,
    )
    .option("--auto-rotate", "Auto-rotate expired secrets")
    .option("-v, --verbose", "Verbose output with all warnings")
    .option(
      "--project-path <paths>",
      "Comma-separated project paths to monitor",
    )
    .option("--once", "Run a single scan and exit (no daemon)")
    .action(async (cmd) => {
      const projectPaths = cmd.projectPath
        ? cmd.projectPath.split(",").map((p: string) => p.trim())
        : [process.cwd()];

      if (cmd.once) {
        const report = runHealthScan({
          autoRotate: cmd.autoRotate,
          projectPaths,
          verbose: cmd.verbose,
        });

        console.log(JSON.stringify(report, null, 2));
        return;
      }

      await startAgent({
        intervalSeconds: cmd.interval,
        autoRotate: cmd.autoRotate,
        projectPaths,
        verbose: cmd.verbose,
      });
    });
}
