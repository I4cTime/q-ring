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
import { pushSecrets, PUSH_TARGETS, type PushTarget } from "../../core/push.js";
import {
  addCanaryAlert,
  listCanaryAlerts,
  removeCanaryAlert,
  setCanaryAlertEnabled,
  sendCanaryAlerts,
  describeAlertUrl,
  type CanaryAlertType,
} from "../../core/canary-webhooks.js";

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
    .option(
      "--push <target>",
      `Also push the planted value to a deployment platform (${PUSH_TARGETS.join(", ")}) so a leaked CI/deploy environment carries a tripwire`,
    )
    .option("--repo <owner/name>", "GitHub repository (with --push github)")
    .option("--vercel-env <envs>", "Comma-separated Vercel environments (with --push vercel)")
    .option("--json", "Output the plant result as JSON")
    .option("-g, --global", "Global scope (default)")
    .option("-p, --project", "Project scope")
    .option("--team <id>", "Team scope")
    .option("--org <id>", "Org scope")
    .option("--project-path <path>", "Project path (defaults to cwd)")
    .action((key: string, cmd) => {
      const pushTarget = cmd.push as string | undefined;
      if (pushTarget && !PUSH_TARGETS.includes(pushTarget as PushTarget)) {
        console.error(
          c.red(
            `${SYMBOLS.cross} Unknown push target "${pushTarget}" — expected one of: ${PUSH_TARGETS.join(", ")}`,
          ),
        );
        process.exit(1);
      }

      const opts = buildOpts(cmd);
      const result = plantCanary(key, {
        ...opts,
        format: cmd.format,
        value: cmd.value,
        description: cmd.description,
        force: cmd.force === true,
      });

      // Push the value we just generated — reading it back would trip it.
      const push = pushTarget
        ? pushSecrets({
            target: pushTarget as PushTarget,
            keys: [key],
            presetValues: { [key]: result.value },
            canaryKeys: [key],
            projectPath: opts.projectPath ?? process.cwd(),
            repo: cmd.repo,
            vercelEnvs: cmd.vercelEnv?.split(",").map((e: string) => e.trim()),
            source: "cli",
          })
        : undefined;

      if (emitJson(program, cmd, { ...result, push })) {
        if (push && push.failed.length > 0) process.exit(1);
        return;
      }

      console.log(
        `${SYMBOLS.sparkle} ${c.yellow("canary planted")} ${c.bold(result.key)} ${c.dim(`(${result.format}, ${result.scope} scope)`)}`,
      );
      console.log(c.dim(`  value: ${result.value}`));
      console.log(
        c.dim("  Reads return this fake value and fire a desktop alert + a 'canary' audit event."),
      );
      console.log(c.dim("  Watch trips with: qring canary list · qring audit --action canary"));
      if (push) {
        if (push.pushed.length > 0) {
          console.log(
            `${SYMBOLS.link} ${c.yellow("pushed")} ${c.bold(key)} ${c.dim(`to ${push.target}${cmd.repo ? ` (${cmd.repo})` : ""}`)}`,
          );
          console.log(
            c.dim(
              "  Caveat: q-ring only sees reads that go through q-ring. Someone using the leaked value on the platform side is not observable here — pair it with the provider's own alerting if you need that.",
            ),
          );
        }
        for (const { error } of push.failed) {
          console.error(c.red(`${SYMBOLS.cross} push to ${push.target} failed — ${error}`));
        }
        if (push.failed.length > 0) process.exit(1);
      }
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
        console.log(
          c.dim(
            "No canaries planted. Plant one: qring canary plant AWS_SECRET_ACCESS_KEY --format aws",
          ),
        );
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

  const alert = canary
    .command("alert")
    .description("Webhook channels that receive canary trips (Discord, Slack, ntfy, generic JSON)");

  alert
    .command("add")
    .description("Register a webhook channel for canary trips")
    .option("--discord <url>", "Discord webhook URL")
    .option("--slack <url>", "Slack incoming-webhook URL")
    .option("--ntfy <url>", "ntfy topic URL (e.g. https://ntfy.sh/my-topic)")
    .option("--url <url>", "Generic endpoint — receives a JSON POST")
    .option("--description <text>", "Human-readable label")
    .option("--json", "Output as JSON")
    .action((cmd) => {
      const picked: [CanaryAlertType, string | undefined][] = [
        ["discord", cmd.discord],
        ["slack", cmd.slack],
        ["ntfy", cmd.ntfy],
        ["generic", cmd.url],
      ];
      const chosen = picked.filter(([, url]) => typeof url === "string");
      if (chosen.length !== 1) {
        console.error(
          c.red(`${SYMBOLS.cross} Specify exactly one of --discord, --slack, --ntfy, or --url`),
        );
        process.exit(1);
      }
      const [type, url] = chosen[0];
      const channel = addCanaryAlert({ type, url: url!, description: cmd.description });
      if (emitJson(program, cmd, channel)) return;
      console.log(
        `${SYMBOLS.check} ${c.green("registered")} canary alert ${c.bold(channel.id)} (${type}) ${c.dim(describeAlertUrl(channel.url))}`,
      );
      console.log(c.dim(`  Send a drill: qring canary alert test ${channel.id}`));
    });

  alert
    .command("list")
    .alias("ls")
    .description("List canary alert channels")
    .option("--json", "Output as JSON")
    .action((cmd) => {
      const channels = listCanaryAlerts();
      if (emitJson(program, cmd, { channels })) return;
      if (channels.length === 0) {
        console.log(
          c.dim("No alert channels. Add one: qring canary alert add --discord <webhook-url>"),
        );
        return;
      }
      console.log(c.bold(`\n  ${SYMBOLS.eye} Canary alert channels (${channels.length})\n`));
      for (const ch of channels) {
        const state = ch.enabled ? c.green("enabled") : c.dim("disabled");
        const desc = ch.description ? c.dim(` — ${ch.description}`) : "";
        console.log(
          `  ${c.bold(ch.id)}  ${ch.type.padEnd(7)} ${state}  ${c.dim(describeAlertUrl(ch.url))}${desc}`,
        );
      }
      console.log();
    });

  alert
    .command("remove <id>")
    .alias("rm")
    .description("Remove an alert channel")
    .action((id: string) => {
      if (removeCanaryAlert(id)) {
        console.log(`${SYMBOLS.check} ${c.green("removed")} canary alert ${c.bold(id)}`);
      } else {
        console.error(c.red(`${SYMBOLS.cross} No alert channel with id "${id}"`));
        process.exit(1);
      }
    });

  for (const [verb, enabled] of [
    ["enable", true],
    ["disable", false],
  ] as const) {
    alert
      .command(`${verb} <id>`)
      .description(`${verb === "enable" ? "Enable" : "Disable"} an alert channel`)
      .action((id: string) => {
        if (setCanaryAlertEnabled(id, enabled)) {
          console.log(`${SYMBOLS.check} ${c.green(`${verb}d`)} canary alert ${c.bold(id)}`);
        } else {
          console.error(c.red(`${SYMBOLS.cross} No alert channel with id "${id}"`));
          process.exit(1);
        }
      });
  }

  alert
    .command("test [id]")
    .description("Send a clearly-labelled test message to every enabled channel (or one id)")
    .option("--json", "Output as JSON")
    .action(async (id: string | undefined, cmd) => {
      const results = await sendCanaryAlerts(
        {
          key: "EXAMPLE_CANARY",
          scope: "global",
          source: "cli",
          agent: null,
          detail: "test message",
          timestamp: new Date().toISOString(),
          test: true,
        },
        id,
      );
      if (emitJson(program, cmd, { results })) return;
      if (results.length === 0) {
        console.log(c.dim(id ? `No channel with id "${id}"` : "No enabled alert channels"));
        process.exit(1);
      }
      for (const r of results) {
        const mark = r.success ? c.green(SYMBOLS.check) : c.red(SYMBOLS.cross);
        console.log(`  ${mark} ${c.bold(r.channelId)} ${r.type} ${c.dim(r.message)}`);
      }
      if (results.some((r) => !r.success)) process.exit(1);
    });
}
