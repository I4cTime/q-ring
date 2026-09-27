import type { Command } from "commander";
import type { Scope } from "../../core/scope.js";
import {
  getSecret,
  setSecret,
  listSecrets,
  getEnvelope,
} from "../../core/keyring.js";
import { readProjectConfig } from "../../core/collapse.js";
import {
  validateSecret,
  rotateWithProvider,
  ciValidateBatch,
  registry as providerRegistry,
} from "../../core/validate.js";
import {
  rotationStatus,
  describeRotation,
  compareRotationUrgency,
} from "../../core/rotation.js";
import { c, SYMBOLS, scopeColor } from "../../utils/colors.js";
import { wantsJsonOutput, emitJson, safeStr } from "../helpers.js";
import { buildOpts } from "../options.js";
import { rotationBadge } from "./secrets.js";

export function registerValidationCommands(program: Command): void {
  program
    .command("validate [key]")
    .description("Test if a secret is actually valid with its target service")
    .option("-g, --global", "Global scope only")
    .option("-p, --project", "Project scope only")
    .option("--project-path <path>", "Explicit project path")
    .option(
      "--provider <name>",
      "Force a specific provider (openai, stripe, github, aws, http)",
    )
    .option(
      "--all",
      "Validate all secrets that have a detectable provider",
    )
    .option(
      "--manifest",
      "Only validate manifest-declared secrets (with --all)",
    )
    .option("--list-providers", "List all available providers")
    .option("--json", "Output as JSON")
    .action(async (key: string | undefined, cmd) => {
      if (cmd.listProviders) {
        if (emitJson(program, cmd, { providers: providerRegistry.listProviders() })) {
          return;
        }
        console.log(
          c.bold(`\n  ${SYMBOLS.shield} Available validation providers\n`),
        );
        for (const p of providerRegistry.listProviders()) {
          const prefixes = p.prefixes?.length
            ? c.dim(` (${p.prefixes.join(", ")})`)
            : "";
          console.log(
            `  ${c.cyan(p.name.padEnd(10))} ${p.description}${prefixes}`,
          );
        }
        console.log();
        return;
      }

      if (!key && !cmd.all) {
        console.error(c.red(`${SYMBOLS.cross} Provide a key name or use --all`));
        process.exit(1);
      }

      const opts = buildOpts(cmd);

      if (cmd.all) {
        let entries = listSecrets(opts);
        const projectPath = cmd.projectPath ?? process.cwd();

        if (cmd.manifest) {
          const config = readProjectConfig(projectPath);
          if (config?.secrets) {
            const manifestKeys = new Set(Object.keys(config.secrets));
            entries = entries.filter((e) => manifestKeys.has(e.key));
          }
        }

        const jsonMode = wantsJsonOutput(program, cmd);
        if (!jsonMode) {
          console.log(c.bold(`\n  ${SYMBOLS.shield} Validating secrets\n`));
        }

        let validated = 0;
        let skipped = 0;
        const jsonResults: Array<{
          key: string;
          status: string;
          provider: string;
          latencyMs: number;
          message?: string;
        }> = [];

        for (const entry of entries) {
          const value = getSecret(entry.key, { ...opts, scope: entry.scope });
          if (!value) {
            skipped++;
            continue;
          }

          const provHint = entry.envelope?.meta.provider ?? cmd.provider;
          const result = await validateSecret(value, { provider: provHint });

          if (result.status === "unknown") {
            skipped++;
            continue;
          }

          validated++;
          if (jsonMode) {
            jsonResults.push({
              key: entry.key,
              status: result.status,
              provider: result.provider,
              latencyMs: result.latencyMs,
              message: result.status !== "valid" ? result.message : undefined,
            });
            continue;
          }
          const icon =
            result.status === "valid"
              ? c.green(SYMBOLS.check)
              : result.status === "invalid"
                ? c.red(SYMBOLS.cross)
                : c.yellow(SYMBOLS.warning);
          const statusText =
            result.status === "valid"
              ? c.green("valid")
              : result.status === "invalid"
                ? c.red("invalid")
                : c.yellow("error");

          console.log(
            `  ${icon} ${c.bold(entry.key.padEnd(24))} ${statusText}  ${c.dim(`(${result.provider}, ${result.latencyMs}ms)`)}${result.status !== "valid" ? ` ${c.dim("— " + result.message)}` : ""}`,
          );
        }

        if (jsonMode) {
          emitJson(program, cmd, { results: jsonResults, validated, skipped });
          return;
        }

        console.log(
          `\n  ${c.dim(`${validated} validated, ${skipped} skipped (no provider)`)}\n`,
        );
        return;
      }

      const value = getSecret(key!, opts);
      if (!value) {
        console.error(c.red(`${SYMBOLS.cross} Secret "${key}" not found`));
        process.exit(1);
      }

      const envelope = getEnvelope(key!, opts);
      const provHint = envelope?.envelope.meta.provider ?? cmd.provider;
      const result = await validateSecret(value, { provider: provHint });

      if (
        emitJson(program, cmd, {
          key,
          status: result.status,
          provider: result.provider,
          latencyMs: result.latencyMs,
          message: result.message,
        })
      ) {
        return;
      }

      const icon =
        result.status === "valid"
          ? c.green(SYMBOLS.check)
          : result.status === "invalid"
            ? c.red(SYMBOLS.cross)
            : result.status === "error"
              ? c.yellow(SYMBOLS.warning)
              : c.dim("○");

      console.log(
        `\n  ${icon} ${c.bold(key!)}  ${result.status}  ${c.dim(`(${result.provider}, ${result.latencyMs}ms)`)}`,
      );
      if (result.message && result.status !== "valid") {
        console.log(`    ${c.dim(result.message)}`);
      }
      console.log();
    });

  program
    .command("rotate <key>")
    .description(
      "Attempt issuer-native rotation of a secret via its provider",
    )
    .option("-g, --global", "Global scope")
    .option("-p, --project", "Project scope")
    .option("--project-path <path>", "Explicit project path")
    .option("--provider <name>", "Force a specific provider")
    .option("--json", "Output as JSON")
    .action(async (key: string, cmd) => {
      const opts = buildOpts(cmd);
      const value = getSecret(key, opts);
      if (!value) {
        console.error(c.red(`${SYMBOLS.cross} Secret "${key}" not found`));
        process.exitCode = 1;
        return;
      }

      const result = await rotateWithProvider(value, cmd.provider);
      if (result.rotated && result.newValue) {
        setSecret(key, result.newValue, {
          ...opts,
          scope: opts.scope ?? "global",
        });
      }

      if (
        emitJson(program, cmd, {
          key,
          rotated: !!(result.rotated && result.newValue),
          provider: result.provider,
          message: result.message,
        })
      ) {
        return;
      }

      if (result.rotated && result.newValue) {
        console.log(
          `${SYMBOLS.check} ${c.green("Rotated")} ${c.bold(key)} via ${result.provider}`,
        );
        console.log(c.dim(`  ${result.message}`));
      } else {
        console.log(c.yellow(`${SYMBOLS.warning} ${result.message}`));
      }
    });

  program
    .command("rotate:due")
    .description(
      "List secrets whose rotation reminder is due soon or overdue (--all: every scheduled secret)",
    )
    .option("-g, --global", "Global scope only")
    .option("-p, --project", "Project scope only")
    .option("--team <id>", "Team scope only")
    .option("--org <id>", "Org scope only")
    .option("--project-path <path>", "Explicit project path")
    .option("--all", "Include scheduled secrets that are not yet due")
    .option("--json", "Output as JSON")
    .action((cmd) => {
      const opts = buildOpts(cmd);
      const entries = listSecrets(opts);

      const scheduled = entries
        .filter((e) => e.envelope)
        .map((e) => ({
          key: safeStr(e.key),
          scope: safeStr(e.scope),
          rotation: rotationStatus(e.envelope!.meta),
        }))
        .filter((e) => e.rotation.state !== "unscheduled")
        .sort((a, b) => compareRotationUrgency(a.rotation, b.rotation));

      const due = scheduled.filter(
        (e) => e.rotation.state === "due-soon" || e.rotation.state === "overdue",
      );
      const shown = cmd.all ? scheduled : due;

      if (
        emitJson(program, cmd, {
          entries: shown,
          dueCount: due.length,
          scheduledCount: scheduled.length,
        })
      ) {
        return;
      }

      if (shown.length === 0) {
        console.log(
          c.dim(
            scheduled.length === 0
              ? "No secrets have a rotation reminder (set one with: qring set KEY --rotate-every 90)"
              : `Nothing due — ${scheduled.length} scheduled secret(s) are on track`,
          ),
        );
        return;
      }

      console.log(
        c.bold(
          `\n  ${SYMBOLS.shield} Rotation reminders (${due.length} due of ${scheduled.length} scheduled)\n`,
        ),
      );
      const maxKeyLen = Math.max(...shown.map((e) => e.key.length));
      for (const e of shown) {
        const r = e.rotation;
        console.log(
          `  ${c.dim("[")}${scopeColor(e.scope as Scope)}${c.dim("]")}  ${c.bold(e.key.padEnd(maxKeyLen))}  ${rotationBadge(r.state)}  ${describeRotation(r)}  ${c.dim(`(last rotated ${r.ageDays}d ago, every ${r.rotateEveryDays}d)`)}`,
        );
      }
      console.log();
    });

  program
    .command("ci:validate")
    .description(
      "CI-oriented batch validation of all secrets (exit code 1 on failure)",
    )
    .option("-g, --global", "Global scope")
    .option("-p, --project", "Project scope")
    .option("--project-path <path>", "Explicit project path")
    .option("--json", "Output as JSON")
    .action(async (cmd) => {
      const opts = buildOpts(cmd);
      const entries = listSecrets(opts);

      const secrets = entries
        .map((e) => {
          const val = getSecret(e.key, {
            ...opts,
            scope: e.scope,
            silent: true,
          });
          if (!val) return null;
          const provider = e.envelope?.meta.provider;
          const validationUrl = e.envelope?.meta.validationUrl;
          return { key: e.key, value: val, provider, validationUrl };
        })
        .filter((s): s is NonNullable<typeof s> => s !== null);

      if (secrets.length === 0) {
        console.log(c.dim("No secrets to validate"));
        return;
      }

      const report = await ciValidateBatch(secrets);

      if (wantsJsonOutput(program, cmd)) {
        console.log(JSON.stringify(report, null, 2));
      } else {
        console.log(
          c.bold(`\n  CI Secret Validation: ${report.results.length} secrets\n`),
        );
        for (const r of report.results) {
          const icon = r.validation.valid ? SYMBOLS.check : SYMBOLS.cross;
          const color = r.validation.valid ? c.green : c.red;
          console.log(
            `  ${icon} ${color(r.key)} [${r.validation.provider}] ${r.validation.message}`,
          );
          if (r.requiresRotation) console.log(c.dim(`    → rotation required`));
        }
        console.log();

        if (!report.allValid) {
          console.log(c.red(`  ${report.failCount} secret(s) failed validation`));
          process.exitCode = 1;
        } else {
          console.log(c.green(`  All secrets valid`));
        }
      }
    });
}
