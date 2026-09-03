import type { Command } from "commander";
import {
  getSecret,
  setSecret,
  deleteSecret,
  hasSecret,
  listSecrets,
  exportSecrets,
  getEnvelope,
  type SetSecretOptions,
} from "../../core/keyring.js";
import type { Scope } from "../../core/scope.js";
import { checkDecay } from "../../core/envelope.js";
import { importDotenv } from "../../core/import.js";
import { promptSecret, confirm } from "../../utils/prompt.js";
import {
  c,
  scopeColor,
  decayIndicator,
  envBadge,
  SYMBOLS,
} from "../../utils/colors.js";
import { safeStr, safeNum, safeArr, wantsJsonOutput, emitJson } from "../helpers.js";
import { buildOpts } from "../options.js";
import { filterSecretsByKeyGlob } from "../../services/list-secrets-filter.js";

export function registerSecretsCommands(program: Command): void {
  program
    .command("set <key> [value]")
    .description("Store a secret (with optional quantum metadata)")
    .option("-g, --global", "Store in global scope")
    .option("-p, --project", "Store in project scope (uses cwd)")
    .option("--team <id>", "Store in team scope")
    .option("--org <id>", "Store in org scope")
    .option("--project-path <path>", "Explicit project path")
    .option(
      "-e, --env <env>",
      "Set value for a specific environment (superposition)",
    )
    .option(
      "--ttl <seconds>",
      "Time-to-live in seconds (quantum decay)",
      parseInt,
    )
    .option("--expires <iso>", "Expiry timestamp (ISO 8601)")
    .option("--description <desc>", "Human-readable description")
    .option("--tags <tags>", "Comma-separated tags")
    .option(
      "--rotation-format <format>",
      "Format for auto-rotation (api-key, password, uuid, hex, base64, alphanumeric, token)",
    )
    .option("--rotation-prefix <prefix>", "Prefix for auto-rotation (e.g. sk-)")
    .option(
      "--requires-approval",
      "Require explicit user approval for MCP agents to read",
    )
    .option(
      "--jit-provider <provider>",
      "Use a Just-In-Time provider to dynamically generate this secret",
    )
    .action(async (key: string, value: string | undefined, cmd) => {
      const opts = buildOpts(cmd);

      if (!value) {
        value = await promptSecret(
          `${SYMBOLS.key} Enter value for ${c.bold(key)}: `,
        );
        if (!value) {
          console.error(c.red(`${SYMBOLS.cross} No value provided, aborting.`));
          process.exit(1);
        }
      }

      const setOpts: SetSecretOptions = {
        ...opts,
        ttlSeconds: cmd.ttl,
        expiresAt: cmd.expires,
        description: cmd.description,
        tags: cmd.tags?.split(",").map((t: string) => t.trim()),
        rotationFormat: cmd.rotationFormat,
        rotationPrefix: cmd.rotationPrefix,
        requiresApproval: cmd.requiresApproval,
        jitProvider: cmd.jitProvider,
      };

      // A canary flag survives overwrites by design (an agent must not be
      // able to launder a tripwire away) — warn the operator so a real
      // credential doesn't quietly inherit the alarm.
      const priorEnvelope = getEnvelope(key, opts);
      if (priorEnvelope?.envelope.meta.canary) {
        console.error(
          c.yellow(
            `${SYMBOLS.warning} "${key}" is a canary honeytoken — the alarm stays armed on the new value. Disarm first with: qring canary disarm ${key}`,
          ),
        );
      }

      if (cmd.env) {
        const existing = priorEnvelope;
        const states = existing?.envelope?.states ?? {};
        states[cmd.env] = value;

        if (existing?.envelope?.value && !states["default"]) {
          states["default"] = existing.envelope.value;
        }

        setOpts.states = states;
        setOpts.defaultEnv = existing?.envelope?.defaultEnv ?? cmd.env;
        setSecret(key, "", setOpts);

        console.log(
          `${SYMBOLS.check} ${c.green("saved")} ${c.bold(key)} ${envBadge(cmd.env)} ${c.dim(`[${scopeColor(opts.scope ?? "global")}]`)}`,
        );
      } else {
        setSecret(key, value, setOpts);
        const extras: string[] = [];
        if (cmd.ttl) extras.push(`${SYMBOLS.clock} ttl=${cmd.ttl}s`);
        if (cmd.description) extras.push(c.dim(cmd.description));

        console.log(
          `${SYMBOLS.check} ${c.green("saved")} ${c.bold(key)} ${c.dim(`[${scopeColor(opts.scope ?? "global")}]`)} ${extras.join(" ")}`,
        );
      }
    });

  program
    .command("get <key>")
    .description("Retrieve a secret (collapses superposition if needed)")
    .option("-g, --global", "Look only in global scope")
    .option("-p, --project", "Look only in project scope")
    .option("--team <id>", "Look only in team scope")
    .option("--org <id>", "Look only in org scope")
    .option("--project-path <path>", "Explicit project path")
    .option("-e, --env <env>", "Force a specific environment")
    .option("--raw", "Print the secret value only (for scripts and piping)")
    .action((key: string, cmd) => {
      const opts = buildOpts(cmd);
      const value = getSecret(key, opts);

      if (value === null) {
        console.error(c.red(`${SYMBOLS.cross} Secret "${key}" not found`));
        process.exit(1);
      }

      if (cmd.raw) {
        process.stdout.write(value);
        return;
      }

      const payload = wantsJsonOutput(program, cmd)
        ? { ok: true as const, data: { key, value } }
        : { key, value };
      // Intentional user-visible output (this is `qring get`). Use
      // process.stdout.write instead of console.log so static analysis
      // (CodeQL `js/clear-text-logging`) does not flag it as logging.
      process.stdout.write(JSON.stringify(payload) + "\n");
    });

  program
    .command("has <key>")
    .description(
      "Check whether a secret exists (exit 0 if present, 1 if not) — decay-aware",
    )
    .option("-g, --global", "Look only in global scope")
    .option("-p, --project", "Look only in project scope")
    .option("--team <id>", "Look only in team scope")
    .option("--org <id>", "Look only in org scope")
    .option("--project-path <path>", "Explicit project path")
    .option("-q, --quiet", "No output, exit code only (for scripts)")
    .action((key: string, cmd) => {
      const opts = buildOpts(cmd);
      const exists = hasSecret(key, opts);

      if (!cmd.quiet) {
        if (wantsJsonOutput(program, cmd)) {
          console.log(JSON.stringify({ ok: true, data: { key, exists } }));
        } else {
          console.log(exists ? "true" : "false");
        }
      }
      if (!exists) process.exitCode = 1;
    });

  program
    .command("delete <key>")
    .alias("rm")
    .description("Remove a secret from the keyring")
    .option("-g, --global", "Delete from global scope only")
    .option("-p, --project", "Delete from project scope only")
    .option("--project-path <path>", "Explicit project path")
    .option("-y, --yes", "Skip the confirmation prompt")
    .option("--json", "Output as JSON")
    .action(async (key: string, cmd) => {
      const opts = buildOpts(cmd);

      if (!(await confirm(`Delete secret ${key}?`, { assumeYes: cmd.yes }))) {
        console.error(c.dim("Aborted."));
        process.exitCode = 1;
        return;
      }

      const deleted = deleteSecret(key, opts);

      if (!deleted) {
        console.error(c.red(`${SYMBOLS.cross} Secret "${key}" not found`));
        process.exit(1);
      }

      if (emitJson(program, cmd, { key, deleted: true })) return;
      console.log(`${SYMBOLS.check} ${c.green("deleted")} ${c.bold(key)}`);
    });

  program
    .command("list")
    .alias("ls")
    .description("List all secrets with quantum status indicators")
    .option("-g, --global", "List global scope only")
    .option("-p, --project", "List project scope only")
    .option("--team <id>", "List team scope only")
    .option("--org <id>", "List org scope only")
    .option("--project-path <path>", "Explicit project path")
    .option("--show-decay", "Show decay/expiry status")
    .option("-t, --tag <tag>", "Filter by tag")
    .option("--expired", "Show only expired secrets")
    .option("--stale", "Show only stale secrets (75%+ decay)")
    .option("-f, --filter <pattern>", "Glob pattern on key name")
    .option("--json", "Output as JSON")
    .action((cmd) => {
      const opts = buildOpts(cmd);
      let entries = listSecrets(opts);

      if (cmd.tag) {
        entries = entries.filter((e) =>
          e.envelope?.meta.tags?.includes(cmd.tag),
        );
      }
      if (cmd.expired) {
        entries = entries.filter((e) => e.decay?.isExpired);
      }
      if (cmd.stale) {
        entries = entries.filter(
          (e) => e.decay?.isStale && !e.decay?.isExpired,
        );
      }
      if (cmd.filter) {
        entries = filterSecretsByKeyGlob(entries, cmd.filter);
      }

      if (
        emitJson(
          program,
          cmd,
          entries.map((e) => ({
            key: safeStr(e.key),
            scope: safeStr(e.scope),
            type: e.envelope?.states ? "superposition" : "collapsed",
            environments: e.envelope?.states
              ? Object.keys(e.envelope.states).map(safeStr)
              : undefined,
            tags: safeArr(e.envelope?.meta.tags),
            accessCount: safeNum(e.envelope?.meta.accessCount),
            entangledCount: safeNum(e.envelope?.meta.entangled?.length),
            decay: e.decay ?? null,
          })),
        )
      ) {
        return;
      }

      if (entries.length === 0) {
        console.log(c.dim("No secrets found"));
        return;
      }

      console.log(
        c.bold(`\n  ${SYMBOLS.key} q-ring secrets (${entries.length})\n`),
      );

      const maxKeyLen = Math.max(...entries.map((e) => e.key.length));

      for (const entry of entries) {
        const parts: string[] = [];

        const key = safeStr(entry.key);
        const scope = safeStr(entry.scope) as Scope;
        const envs = entry.envelope?.states
          ? Object.keys(entry.envelope.states).map(safeStr)
          : null;
        const entangledCount = safeNum(entry.envelope?.meta.entangled?.length);
        const accessCount = safeNum(entry.envelope?.meta.accessCount);
        const tags = safeArr(entry.envelope?.meta.tags);
        const decayPct = safeNum(entry.decay?.lifetimePercent);
        const expired = !!entry.decay?.isExpired;
        const timeLeft = safeStr(entry.decay?.timeRemaining);

        parts.push(c.dim("[") + scopeColor(scope) + c.dim("]"));
        parts.push(c.bold(key.padEnd(maxKeyLen)));

        if (envs) {
          parts.push(c.magenta(`[${envs.join("|")}]`));
        }

        if (entry.decay && (decayPct > 0 || expired)) {
          parts.push(decayIndicator(decayPct, expired));
          if (timeLeft && !expired) {
            parts.push(c.dim(timeLeft));
          }
        }

        if (entangledCount > 0) {
          parts.push(c.cyan(`${SYMBOLS.link} ${entangledCount}`));
        }

        if (accessCount > 0) {
          parts.push(c.dim(`${SYMBOLS.eye} ${accessCount}`));
        }

        if (tags.length > 0) {
          parts.push(c.dim(tags.map((t) => `#${t}`).join(" ")));
        }

        console.log(`  ${parts.join("  ")}`);
      }

      console.log();
    });

  program
    .command("inspect <key>")
    .description("Show full quantum state of a secret")
    .option("-g, --global", "Inspect global scope only")
    .option("-p, --project", "Inspect project scope only")
    .option("--project-path <path>", "Explicit project path")
    .option("--json", "Output as JSON")
    .action((key: string, cmd) => {
      const opts = buildOpts(cmd);
      const result = getEnvelope(key, opts);

      if (!result) {
        console.error(c.red(`${SYMBOLS.cross} Secret "${key}" not found`));
        process.exit(1);
      }

      const { envelope, scope } = result;
      const decay = checkDecay(envelope);

      if (
        emitJson(program, cmd, {
          key: safeStr(key),
          scope: safeStr(scope),
          type: envelope.states ? "superposition" : "collapsed",
          environments: envelope.states
            ? Object.keys(envelope.states).map(safeStr)
            : undefined,
          defaultEnv: envelope.defaultEnv ? safeStr(envelope.defaultEnv) : undefined,
          createdAt: safeStr(envelope.meta.createdAt),
          updatedAt: safeStr(envelope.meta.updatedAt),
          accessCount: safeNum(envelope.meta.accessCount),
          lastAccessedAt: envelope.meta.lastAccessedAt
            ? safeStr(envelope.meta.lastAccessedAt)
            : undefined,
          description: envelope.meta.description
            ? safeStr(envelope.meta.description)
            : undefined,
          tags: safeArr(envelope.meta.tags),
          entangled: (envelope.meta.entangled ?? []).map((l) => ({
            service: safeStr(l.service),
            key: safeStr(l.key),
          })),
          decay,
        })
      ) {
        return;
      }

      const safeScope = safeStr(scope) as Scope;
      const createdAt = safeStr(envelope.meta.createdAt);
      const updatedAt = safeStr(envelope.meta.updatedAt);
      const accessCount = safeNum(envelope.meta.accessCount);
      const lastAccess = safeStr(envelope.meta.lastAccessedAt);
      const desc = safeStr(envelope.meta.description);
      const tags = safeArr(envelope.meta.tags);
      const entangled = (envelope.meta.entangled ?? []).map((l) => ({
        service: safeStr(l.service),
        key: safeStr(l.key),
      }));
      const stateEnvs = envelope.states
        ? Object.keys(envelope.states).map(safeStr)
        : null;
      const defaultEnv = safeStr(envelope.defaultEnv);
      const decayTime = safeStr(decay.timeRemaining);
      const decayPct = safeNum(decay.lifetimePercent);
      const expired = !!decay.isExpired;

      console.log(`\n  ${c.bold(SYMBOLS.key + " " + key)}`);
      console.log(`  ${c.dim("scope:")}     ${scopeColor(safeScope)}`);

      if (stateEnvs) {
        console.log(`  ${c.dim("type:")}      ${c.magenta("superposition")}`);
        console.log(`  ${c.dim("states:")}`);
        for (const env of stateEnvs) {
          const isDefault = env === defaultEnv;
          console.log(
            `    ${envBadge(env)} ${isDefault ? c.dim("(default)") : ""}`,
          );
        }
      } else {
        console.log(`  ${c.dim("type:")}      ${c.green("collapsed")}`);
      }

      console.log(`  ${c.dim("created:")}   ${createdAt}`);
      console.log(`  ${c.dim("updated:")}   ${updatedAt}`);
      console.log(`  ${c.dim("accessed:")}  ${accessCount} times`);

      if (lastAccess) {
        console.log(`  ${c.dim("last read:")} ${lastAccess}`);
      }

      if (desc) {
        console.log(`  ${c.dim("desc:")}      ${desc}`);
      }

      if (tags.length > 0) {
        console.log(
          `  ${c.dim("tags:")}      ${tags.map((t) => c.cyan(`#${t}`)).join(" ")}`,
        );
      }

      if (decayTime) {
        console.log(
          `  ${c.dim("decay:")}     ${decayIndicator(decayPct, expired)} ${decayTime}`,
        );
      }

      if (entangled.length > 0) {
        console.log(`  ${c.dim("entangled:")}`);
        for (const link of entangled) {
          console.log(`    ${SYMBOLS.link} ${link.service}/${link.key}`);
        }
      }

      console.log();
    });

  program
    .command("export")
    .description("Export secrets as .env or JSON (collapses superposition)")
    .option("-f, --format <format>", "Output format: env or json", "env")
    .option("-g, --global", "Export global scope only")
    .option("-p, --project", "Export project scope only")
    .option("--project-path <path>", "Explicit project path")
    .option("-e, --env <env>", "Force environment for collapse")
    .option("-k, --keys <keys>", "Comma-separated key names to export")
    .option("-t, --tags <tags>", "Comma-separated tags to filter by")
    .action((cmd) => {
      const opts = buildOpts(cmd);
      const output = exportSecrets({
        ...opts,
        format: cmd.format,
        keys: cmd.keys?.split(",").map((k: string) => k.trim()),
        tags: cmd.tags?.split(",").map((t: string) => t.trim()),
      });
      process.stdout.write(output + "\n");
    });

  program
    .command("import <file>")
    .description("Import secrets from a .env file")
    .option("-g, --global", "Import to global scope")
    .option("-p, --project", "Import to project scope")
    .option("--project-path <path>", "Explicit project path")
    .option("-e, --env <env>", "Environment context")
    .option("--skip-existing", "Skip keys that already exist")
    .option("--dry-run", "Preview what would be imported without saving")
    .option("--json", "Output as JSON")
    .action((file: string, cmd) => {
      const opts = buildOpts(cmd);

      const result = importDotenv(file, {
        scope: opts.scope as "global" | "project" | undefined,
        projectPath: opts.projectPath,
        source: "cli",
        skipExisting: cmd.skipExisting,
        dryRun: cmd.dryRun,
      });

      if (emitJson(program, cmd, { file, dryRun: !!cmd.dryRun, ...result })) {
        return;
      }

      if (cmd.dryRun) {
        console.log(
          `\n  ${SYMBOLS.package} ${c.bold("Dry run")} — would import ${result.imported.length} of ${result.total} secrets:\n`,
        );
        for (const key of result.imported) {
          console.log(`  ${SYMBOLS.key} ${c.bold(key)}`);
        }
        if (result.skipped.length > 0) {
          console.log(
            `\n  ${c.dim(`Skipped (existing): ${result.skipped.join(", ")}`)}`,
          );
        }
      } else {
        console.log(
          `${SYMBOLS.check} ${c.green("imported")} ${result.imported.length} secret(s) from ${c.bold(file)}`,
        );
        if (result.skipped.length > 0) {
          console.log(
            c.dim(
              `  skipped ${result.skipped.length} existing: ${result.skipped.join(", ")}`,
            ),
          );
        }
      }

      console.log();
    });
}
