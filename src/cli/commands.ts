import { Command, Help } from "commander";
import { PACKAGE_VERSION } from "../version.js";
import { c, SYMBOLS } from "../utils/colors.js";
import { registerSecretsCommands } from "./commands/secrets.js";
import { registerProjectCommands } from "./commands/project.js";
import { registerQuantumCommands } from "./commands/quantum.js";
import { registerValidationCommands } from "./commands/validation.js";
import { registerToolingCommands } from "./commands/tooling.js";
import { registerAuditCommands } from "./commands/audit.js";
import { registerHookCommands } from "./commands/hooks.js";
import { registerAgentCommands } from "./commands/agent.js";
import { registerSecurityCommands } from "./commands/security.js";
import { registerBridgeCommands } from "./commands/bridges.js";
import { registerDoctorCommand } from "./commands/doctor.js";
import { registerCompletionCommand } from "./commands/completion.js";

/**
 * Display groups for the CLI help screen.
 *
 * Maps top-level command names (including their first alias) to a category.
 * Any command not present here falls under "Other".
 */
const COMMAND_GROUPS: Array<{
  name: string;
  symbol: string;
  commands: string[];
}> = [
  {
    name: "Secrets",
    symbol: SYMBOLS.key,
    commands: [
      "set",
      "get",
      "has",
      "delete",
      "list",
      "inspect",
      "export",
      "import",
    ],
  },
  {
    name: "Project",
    symbol: SYMBOLS.package,
    commands: ["context", "check", "env", "env:generate", "wizard"],
  },
  {
    name: "Quantum",
    symbol: SYMBOLS.sparkle,
    commands: [
      "generate",
      "entangle",
      "disentangle",
      "tunnel",
      "teleport",
    ],
  },
  {
    name: "Validation & Rotation",
    symbol: SYMBOLS.shield,
    commands: ["validate", "rotate", "ci:validate"],
  },
  {
    name: "Dev Tooling",
    symbol: SYMBOLS.zap,
    commands: ["exec", "scan", "lint", "status", "doctor", "completion"],
  },
  {
    name: "Bridges",
    symbol: SYMBOLS.link,
    commands: ["run", "setup"],
  },
  {
    name: "Audit & Health",
    symbol: SYMBOLS.eye,
    commands: ["audit", "audit:verify", "audit:export", "health"],
  },
  {
    name: "Hooks",
    symbol: SYMBOLS.link,
    commands: [
      "hook:install",
      "hook:uninstall",
      "hook:run",
      "hook",
    ],
  },
  {
    name: "Agent Memory",
    symbol: SYMBOLS.ghost,
    commands: ["remember", "recall", "forget", "analyze", "agent"],
  },
  {
    name: "Security & Governance",
    symbol: SYMBOLS.lock,
    commands: ["approve", "approvals", "policy"],
  },
];

class GroupedHelp extends Help {
  override formatHelp(cmd: Command, helper: Help): string {
    // Keep the default formatting for subcommands — only the top-level
    // `qring` command gets the grouped treatment.
    if (cmd.parent) return super.formatHelp(cmd, helper);

    const termWidth = helper.padWidth(cmd, helper);
    const helpWidth = helper.helpWidth ?? 80;

    const sections: string[] = [];
    sections.push(
      `${c.bold("qring")} ${c.dim(`v${PACKAGE_VERSION}`)} ${c.dim("—")} ${c.dim(
        "quantum keyring for AI coding tools",
      )}`,
    );
    sections.push("");
    sections.push(`${c.bold("Usage:")}  qring [options] [command]`);

    const options = helper.visibleOptions(cmd);
    if (options.length > 0) {
      sections.push("");
      sections.push(c.bold("Options:"));
      for (const opt of options) {
        const term = helper.optionTerm(opt);
        const desc = helper.optionDescription(opt);
        sections.push(formatRow(term, desc, termWidth, helpWidth));
      }
    }

    const commands = helper.visibleCommands(cmd);
    if (commands.length === 0) return sections.join("\n") + "\n";

    const byName = new Map<string, Command>();
    for (const sub of commands) byName.set(sub.name(), sub);

    const used = new Set<string>();

    for (const group of COMMAND_GROUPS) {
      const members = group.commands
        .map((n) => byName.get(n))
        .filter((x): x is Command => Boolean(x));
      if (members.length === 0) continue;
      for (const m of members) used.add(m.name());

      sections.push("");
      sections.push(`${group.symbol} ${c.bold(group.name)}`);
      for (const sub of members) {
        sections.push(
          formatRow(
            helper.subcommandTerm(sub),
            helper.subcommandDescription(sub),
            termWidth,
            helpWidth,
          ),
        );
      }
    }

    const other = commands.filter((sub) => !used.has(sub.name()));
    if (other.length > 0) {
      sections.push("");
      sections.push(c.bold("Other:"));
      for (const sub of other) {
        sections.push(
          formatRow(
            helper.subcommandTerm(sub),
            helper.subcommandDescription(sub),
            termWidth,
            helpWidth,
          ),
        );
      }
    }

    sections.push("");
    sections.push(
      c.dim(
        `Run ${c.bold("qring <command> --help")} to see detailed flags for any command.`,
      ),
    );
    return sections.join("\n") + "\n";
  }
}

function formatRow(
  term: string,
  description: string,
  termWidth: number,
  helpWidth: number,
): string {
  const indent = "  ";
  const gap = "  ";
  const padded = term.padEnd(termWidth);
  if (!description) return `${indent}${padded}`;
  const available = Math.max(helpWidth - indent.length - termWidth - gap.length, 20);
  const desc = wrapText(description, available).replace(
    /\n/g,
    `\n${indent}${" ".repeat(termWidth)}${gap}`,
  );
  return `${indent}${padded}${gap}${c.dim(desc)}`;
}

function wrapText(text: string, width: number): string {
  if (text.length <= width) return text;
  const lines: string[] = [];
  let current = "";
  for (const word of text.split(/\s+/)) {
    if (current.length + word.length + 1 > width) {
      lines.push(current);
      current = word;
    } else {
      current = current ? `${current} ${word}` : word;
    }
  }
  if (current) lines.push(current);
  return lines.join("\n");
}

export function createProgram(): Command {
  const program = new Command()
    .name("qring")
    .description(
      `${c.bold("q-ring")} ${c.dim("— quantum keyring for AI coding tools")}`,
    )
    .version(PACKAGE_VERSION)
    .option("--json", "Machine-readable JSON output for supported commands")
    .configureHelp({
      sortSubcommands: false,
      sortOptions: false,
    })
    .showHelpAfterError(c.dim("(run `qring --help` for usage)"));

  (program as Command).createHelp = () => new GroupedHelp();

  registerSecretsCommands(program);
  registerProjectCommands(program);
  registerQuantumCommands(program);
  registerValidationCommands(program);
  registerToolingCommands(program);
  registerAuditCommands(program);
  registerHookCommands(program);
  registerAgentCommands(program);
  registerSecurityCommands(program);
  registerBridgeCommands(program);
  registerDoctorCommand(program);
  registerCompletionCommand(program);

  return program;
}
