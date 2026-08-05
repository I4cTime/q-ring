import type { Command } from "commander";
import { runCommand, buildRunPlan, type RunOptions } from "../../core/run.js";
import { setupEditor, EDITORS, type Editor } from "../../core/setup.js";
import { c, SYMBOLS } from "../../utils/colors.js";
import { wantsJsonOutput } from "../helpers.js";

export function registerBridgeCommands(program: Command): void {
  program
    .command("run <command...>")
    .description(
      "Run a command with only declared secrets injected — .q-ring.json manifest keys plus qring:// refs from .env (output auto-redacted)",
    )
    .option("--project-path <path>", "Explicit project path")
    .option("-e, --env <env>", "Environment context")
    .option("--env-file <files...>", "Env file(s) to load (default: ./.env when present)")
    .option("--no-manifest", "Skip .q-ring.json manifest keys")
    .option("--profile <name>", "Exec profile: unrestricted, restricted, ci")
    .option("--strict", "Missing optional manifest keys are fatal too")
    .option("--dry-run", "Show what would be injected without running")
    .action(async (commandArgs: string[], cmd) => {
      const opts: RunOptions = {
        command: commandArgs[0],
        args: commandArgs.slice(1),
        projectPath: cmd.projectPath ?? process.cwd(),
        env: cmd.env,
        envFiles: cmd.envFile,
        useManifest: cmd.manifest !== false,
        profile: cmd.profile,
        strict: cmd.strict === true,
        source: "cli",
      };

      try {
        if (cmd.dryRun) {
          const plan = buildRunPlan({ ...opts, silent: true });
          console.log(`\n${SYMBOLS.zap} ${c.bold("qring run")} ${c.dim("(dry run)")}`);
          if (plan.envFiles.length > 0) {
            console.log(`  Env files: ${plan.envFiles.map((f) => c.cyan(f)).join(", ")}`);
          }
          for (const v of plan.injected) {
            console.log(`  ${c.green(SYMBOLS.check)} ${v.name} ${c.dim(`(${v.source})`)}`);
          }
          for (const name of plan.missingOptional) {
            console.log(`  ${c.yellow("?")} ${name} ${c.dim("(optional, missing)")}`);
          }
          for (const name of plan.missingRequired) {
            console.log(`  ${c.red(SYMBOLS.cross)} ${name} ${c.dim("(required, MISSING)")}`);
          }
          process.exit(plan.missingRequired.length > 0 ? 1 : 0);
        }

        const { code, plan } = await runCommand(opts);
        if (plan.missingOptional.length > 0) {
          console.error(
            c.yellow(
              `${SYMBOLS.warning} Optional secrets not found: ${plan.missingOptional.join(", ")}`,
            ),
          );
        }
        process.exit(code);
      } catch (err) {
        console.error(
          c.red(
            `${SYMBOLS.cross} Run failed: ${err instanceof Error ? err.message : String(err)}`,
          ),
        );
        process.exit(1);
      }
    });

  program
    .command("setup <editor>")
    .description(
      `Wire the q-ring MCP server into an editor's MCP config (${EDITORS.join(", ")})`,
    )
    .option("-g, --global", "Write the per-user config instead of the project one")
    .option("--project-path <path>", "Explicit project path")
    .option("--force", "Replace an existing q-ring entry that differs")
    .option("--dry-run", "Show what would change without writing")
    .option("--json", "Output as JSON")
    .action((editor: string, cmd) => {
      if (!EDITORS.includes(editor as Editor)) {
        console.error(
          c.red(`${SYMBOLS.cross} Unknown editor "${editor}" — expected one of: ${EDITORS.join(", ")}`),
        );
        process.exit(1);
      }

      try {
        const result = setupEditor({
          editor: editor as Editor,
          global: cmd.global === true,
          projectPath: cmd.projectPath ?? process.cwd(),
          force: cmd.force === true,
          dryRun: cmd.dryRun === true,
        });

        if (wantsJsonOutput(program, cmd)) {
          console.log(JSON.stringify(result, null, 2));
          return;
        }

        const verb =
          result.action === "created" ? "Created" :
          result.action === "updated" ? "Updated" : "Already configured";
        const prefix = result.dryRun ? c.dim("[dry-run] ") : "";
        console.log(
          `\n${SYMBOLS.check} ${prefix}${c.bold(verb)}: ${c.cyan(result.configPath)} ${c.dim(`(server "${result.serverName}")`)}`,
        );
        for (const warning of result.warnings) {
          console.log(`  ${c.yellow("!")} ${warning}`);
        }
        if (result.action !== "unchanged") {
          console.log(c.dim(`  Restart ${editor} to pick up the MCP server. Verify with: qring doctor`));
        }
      } catch (err) {
        console.error(
          c.red(
            `${SYMBOLS.cross} Setup failed: ${err instanceof Error ? err.message : String(err)}`,
          ),
        );
        process.exit(1);
      }
    });
}
