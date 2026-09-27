import type { Command } from "commander";
import { diffEnvironments, promoteSecret, PromoteConflictError } from "../../core/promote.js";
import { confirm } from "../../utils/prompt.js";
import { c, envBadge, scopeColor, SYMBOLS } from "../../utils/colors.js";
import { emitJson, wantsJsonOutput } from "../helpers.js";
import { buildOpts } from "../options.js";

const STATUS_LABEL: Record<string, string> = {
  same: c.green("same"),
  different: c.yellow("different"),
  "only-a": c.red("missing in B"),
  "only-b": c.red("missing in A"),
  collapsed: c.dim("single value"),
};

export function registerEnvironmentCommands(program: Command): void {
  program
    .command("promote <key>")
    .description("Copy a secret's value from one environment to another (superposition)")
    .requiredOption("--from <env>", "Source environment")
    .requiredOption("--to <env>", "Target environment")
    .option("-g, --global", "Global scope")
    .option("-p, --project", "Project scope (uses cwd)")
    .option("--team <id>", "Team scope")
    .option("--org <id>", "Org scope")
    .option("--project-path <path>", "Explicit project path")
    .option("-f, --force", "Overwrite a differing target value without asking")
    .option("-y, --yes", "Alias for --force")
    .action(async (key: string, cmd) => {
      const opts = buildOpts(cmd);
      const json = wantsJsonOutput(program, cmd);
      const run = (force: boolean) =>
        promoteSecret(key, { ...opts, from: cmd.from, to: cmd.to, force });
      try {
        let result;
        try {
          result = run(Boolean(cmd.force || cmd.yes));
        } catch (err) {
          if (!(err instanceof PromoteConflictError) || json) throw err;
          const ok = await confirm(
            `${SYMBOLS.warning} ${c.bold(key)} already has a different value for ${envBadge(cmd.to)}. Overwrite it with the ${envBadge(cmd.from)} value?`,
          );
          if (!ok) {
            console.error(c.dim("Cancelled."));
            process.exitCode = 1;
            return;
          }
          result = run(true);
        }
        if (emitJson(program, cmd, result)) return;
        const verb = result.changed ? c.green("promoted") : c.dim("already in sync");
        console.log(
          `${SYMBOLS.check} ${verb} ${c.bold(key)} ${envBadge(result.from)} ${c.dim("→")} ${envBadge(result.to)} ${c.dim(`[${scopeColor(result.scope)}]`)}`,
        );
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        if (json) console.log(JSON.stringify({ ok: false, error: message }));
        else console.error(c.red(`${SYMBOLS.cross} ${message}`));
        process.exitCode = 1;
      }
    });

  program
    .command("diff <envA> <envB>")
    .description("Compare two environments key by key — statuses only, never values (exit 1 on drift)")
    .option("-k, --keys <keys>", "Comma-separated keys to compare (default: all visible)")
    .option("-g, --global", "Global scope")
    .option("-p, --project", "Project scope (uses cwd)")
    .option("--team <id>", "Team scope")
    .option("--org <id>", "Org scope")
    .option("--project-path <path>", "Explicit project path")
    .action((envA: string, envB: string, cmd) => {
      const opts = buildOpts(cmd);
      const keys = cmd.keys ? String(cmd.keys).split(",").map((k: string) => k.trim()).filter(Boolean) : undefined;
      try {
        const result = diffEnvironments({ ...opts, a: envA, b: envB, keys });
        if (result.drift) process.exitCode = 1;
        if (emitJson(program, cmd, result)) return;
        if (result.entries.length === 0) {
          console.log(c.dim(`No secrets carry ${envA} or ${envB} states.`));
          return;
        }
        console.log(`${envBadge(envA)} ${c.dim("A")}   ${envBadge(envB)} ${c.dim("B")}`);
        const width = Math.max(...result.entries.map((e) => e.key.length));
        for (const e of result.entries) {
          console.log(
            `  ${c.bold(e.key.padEnd(width))}  ${STATUS_LABEL[e.status] ?? e.status}  ${c.dim(`[${scopeColor(e.scope)}]`)}`,
          );
        }
        const s = result.summary;
        console.log(
          c.dim(
            `\n${s.same} same · ${s.different} different · ${s["only-a"]} only in A · ${s["only-b"]} only in B · ${s.collapsed} single-value`,
          ),
        );
        if (result.drift) {
          console.log(c.yellow(`${SYMBOLS.warning} drift detected — promote with: qring promote KEY --from ${envA} --to ${envB}`));
        } else {
          console.log(c.green(`${SYMBOLS.check} environments aligned`));
        }
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        if (wantsJsonOutput(program, cmd)) console.log(JSON.stringify({ ok: false, error: message }));
        else console.error(c.red(`${SYMBOLS.cross} ${message}`));
        process.exitCode = 1;
      }
    });
}
