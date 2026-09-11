import type { Command } from "commander";
import { c, SYMBOLS } from "../../utils/colors.js";
import { runWrap, WRAP_APPROVAL_SCOPE, wrapApprovalService } from "../../core/wrap.js";
import { grantApproval, revokeApproval, listApprovals } from "../../core/approval.js";

const collect = (value: string, previous: string[] = []) => [...previous, value];

export function registerMcpCommands(program: Command): void {
  const mcp = program
    .command("mcp")
    .description("MCP airlock — run third-party MCP servers behind q-ring");

  mcp
    .command("wrap [command...]")
    .description(
      "Proxy an MCP server through the airlock: spawned with a stripped env (or dialed over HTTP), every tool call / resource read / prompt audited, results scrubbed of known secrets, policy.wrap enforced. Use -- before the server command: qring mcp wrap -- npx some-server",
    )
    .option(
      "--url <url>",
      "Wrap a remote Streamable HTTP MCP endpoint instead of spawning a command",
    )
    .option(
      "--header <name:value>",
      "Extra request header for --url (repeatable)",
      collect,
      [] as string[],
    )
    .option(
      "--auth-secret <KEY>",
      "q-ring key whose value is sent as `Authorization: Bearer …` to --url (audited read)",
    )
    .option(
      "--inherit-env",
      "Pass the full parent environment to the wrapped server (default: minimal safe env)",
    )
    .option("--no-redact", "Do not scrub known secret values from results")
    .option("--label <label>", "Session label for audit events (default: the command line / url)")
    .option(
      "--project-path <path>",
      "Project whose .q-ring.json policy governs the session (default: cwd)",
    )
    .action(async (commandArgs: string[], cmd) => {
      try {
        if (!cmd.url && commandArgs.length === 0) {
          throw new Error("give a server command after -- or pass --url");
        }
        const code = await runWrap({
          command: commandArgs[0],
          args: commandArgs.slice(1),
          url: cmd.url,
          headers: cmd.header,
          authSecret: cmd.authSecret,
          inheritEnv: cmd.inheritEnv === true,
          // commander turns --no-redact into redact:false; undefined → policy decides
          redact: cmd.redact === false ? false : undefined,
          label: cmd.label,
          projectPath: cmd.projectPath,
        });
        process.exit(code);
      } catch (err) {
        console.error(
          c.red(
            `${SYMBOLS.cross} Airlock failed: ${err instanceof Error ? err.message : String(err)}`,
          ),
        );
        process.exit(1);
      }
    });

  mcp
    .command("approve <tool>")
    .description(
      "Grant a time-limited approval for a wrapped tool listed in policy.wrap.approveTools (or revoke it)",
    )
    .option("--for <seconds>", "Approval lifetime in seconds", (v) => parseInt(v, 10), 3600)
    .option("--reason <text>", "Why this tool is being approved")
    .option("--revoke", "Revoke an existing approval instead")
    .option("--project-path <path>", "Project the airlock runs in (default: cwd)")
    .action((tool: string, cmd) => {
      const projectPath: string = cmd.projectPath ?? process.cwd();
      const service = wrapApprovalService(projectPath);
      if (cmd.revoke) {
        if (revokeApproval(tool, WRAP_APPROVAL_SCOPE, service)) {
          console.log(
            `${SYMBOLS.check} ${c.green("revoked")} airlock approval for ${c.bold(tool)}`,
          );
        } else {
          console.error(c.red(`${SYMBOLS.cross} no airlock approval found for "${tool}"`));
          process.exit(1);
        }
        return;
      }
      const entry = grantApproval(tool, WRAP_APPROVAL_SCOPE, service, cmd.for, {
        reason: cmd.reason ?? "manual airlock approval",
      });
      console.log(
        `${SYMBOLS.check} ${c.green("approved")} wrapped tool ${c.bold(tool)} for ${cmd.for}s`,
      );
      console.log(c.dim(`  id=${entry.id} reason="${entry.reason}" expires=${entry.expiresAt}`));
      console.log(
        c.dim(
          "  Applies to airlocks launched from this project directory (policy.wrap.approveTools).",
        ),
      );
    });

  mcp
    .command("approvals")
    .description("List live airlock tool approvals for this project")
    .option("--project-path <path>", "Project the airlock runs in (default: cwd)")
    .option("--json", "Output as JSON")
    .action((cmd) => {
      const service = wrapApprovalService(cmd.projectPath ?? process.cwd());
      const entries = listApprovals().filter(
        (a) => a.scope === WRAP_APPROVAL_SCOPE && a.service === service,
      );
      if (cmd.json) {
        console.log(JSON.stringify({ approvals: entries }, null, 2));
        return;
      }
      if (entries.length === 0) {
        console.log(
          c.dim(
            'No airlock approvals. Grant one: qring mcp approve <tool> --for 3600 --reason "…"',
          ),
        );
        return;
      }
      for (const a of entries) {
        const state = a.tampered
          ? c.red("TAMPERED")
          : a.valid
            ? c.green("valid")
            : c.yellow("expired");
        console.log(
          `  ${SYMBOLS.check} ${c.bold(a.key)}  ${state}  ${c.dim(`expires ${a.expiresAt} · ${a.reason}`)}`,
        );
      }
    });
}
