import type { Command } from "commander";
import { c, SYMBOLS } from "../../utils/colors.js";
import { runWrap } from "../../core/wrap.js";

export function registerMcpCommands(program: Command): void {
  const mcp = program
    .command("mcp")
    .description("MCP airlock — run third-party MCP servers behind q-ring");

  mcp
    .command("wrap <command...>")
    .description(
      "Proxy an MCP server through the airlock: spawned with a stripped env, every tool call audited. Use -- before the server command: qring mcp wrap -- npx some-server",
    )
    .option(
      "--inherit-env",
      "Pass the full parent environment to the wrapped server (default: minimal safe env)",
    )
    .option("--label <label>", "Session label for audit events (default: the command line)")
    .action(async (commandArgs: string[], cmd) => {
      try {
        const code = await runWrap({
          command: commandArgs[0],
          args: commandArgs.slice(1),
          inheritEnv: cmd.inheritEnv === true,
          label: cmd.label,
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
}
