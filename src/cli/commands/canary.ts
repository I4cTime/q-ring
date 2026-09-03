import type { Command } from "commander";
import { c, SYMBOLS } from "../../utils/colors.js";
import { buildOpts } from "../options.js";
import { emitJson } from "../helpers.js";
import {
  plantCanary,
  disarmCanary,
  listCanaries,
  CANARY_FORMATS,
  DEFAULT_CANARY_FORMAT,
} from "../../core/canary.js";

export function registerCanaryCommands(program: Command): void {
  const canary = program
    .command("canary")
    .description("Honeytokens — fake credentials that raise the alarm on read");

  canary
    .command("plant <key>")
    .description("Plant a fake credential; any read fires a loud alert")
    .option(
      "-f, --format <format>",
      `Token shape to imitate (${Object.keys(CANARY_FORMATS).join(", ")})`,
      DEFAULT_CANARY_FORMAT,
    )
    .option("--value <value>", "Plant this exact value instead of generating one")
    .option("--description <text>", "Cover description (none by default — no tell)")
    .option("--force", "Overwrite an existing non-canary secret at this key")
    .option("--json", "Output the plant result as JSON")
    .option("-g, --global", "Global scope (default)")
    .option("-p, --project", "Project scope")
    .option("--team <id>", "Team scope")
    .option("--org <id>", "Org scope")
    .option("--project-path <path>", "Project path (defaults to cwd)")
    .action((key: string, cmd) => {
      const result = plantCanary(key, {
        ...buildOpts(cmd),
        format: cmd.format,
        value: cmd.value,
        description: cmd.description,
        force: cmd.force === true,
      });
      if (emitJson(program, cmd, result)) return;

      console.log(
        `${SYMBOLS.sparkle} ${c.yellow("canary planted")} ${c.bold(result.key)} ${c.dim(`(${result.format}, ${result.scope} scope)`)}`,
      );
      console.log(c.dim(`  value: ${result.value}`));
      console.log(
        c.dim(
          "  Reads return this fake value and fire a desktop alert + a 'canary' audit event.",
        ),
      );
      console.log(
        c.dim("  Watch trips with: qring canary list · qring audit --action canary"),
      );
    });

  canary
    .command("disarm <key>")
    .description("Clear the canary flag so reads stop alarming (value stays fake)")
    .option("-g, --global", "Global scope")
    .option("-p, --project", "Project scope")
    .option("--team <id>", "Team scope")
    .option("--org <id>", "Org scope")
    .option("--project-path <path>", "Project path (defaults to cwd)")
    .action((key: string, cmd) => {
      if (disarmCanary(key, buildOpts(cmd))) {
        console.log(
          `${SYMBOLS.check} ${c.green("disarmed")} ${c.bold(key)} ${c.dim("— now an ordinary secret; the stored value is still fake until you overwrite it")}`,
        );
      } else {
        console.error(c.red(`${SYMBOLS.cross} "${key}" is not a canary`));
        process.exit(1);
      }
    });

  canary
    .command("list")
    .alias("ls")
    .description("List planted canaries and their trip counts")
    .option("--json", "Output as JSON")
    .option("-g, --global", "Global scope only")
    .option("-p, --project", "Project scope only")
    .option("--team <id>", "Team scope")
    .option("--org <id>", "Org scope")
    .option("--project-path <path>", "Project path (defaults to cwd)")
    .action((cmd) => {
      const canaries = listCanaries(buildOpts(cmd));
      if (emitJson(program, cmd, { canaries })) return;

      if (canaries.length === 0) {
        console.log(c.dim("No canaries planted. Plant one: qring canary plant AWS_SECRET_ACCESS_KEY --format aws"));
        return;
      }

      console.log(c.bold(`\n  ${SYMBOLS.eye} Canaries (${canaries.length})\n`));
      for (const entry of canaries) {
        const parts = [c.bold(entry.key)];
        parts.push(c.dim(`${entry.format ?? "generic"} · ${entry.scope}`));
        if (entry.tripCount > 0) {
          parts.push(c.red(`trips: ${entry.tripCount}`));
          if (entry.lastTrippedAt) {
            parts.push(c.red(`last: ${entry.lastTrippedAt}`));
          }
        } else {
          parts.push(c.green("no trips"));
        }
        console.log(`  ${SYMBOLS.eye} ${parts.join("  ")}`);
      }
      console.log();
    });
}
