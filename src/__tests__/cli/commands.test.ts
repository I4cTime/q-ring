import { describe, it, expect } from "vitest";
import { createProgram } from "../../cli/commands.js";

describe("createProgram", () => {
  it("returns a Commander program", () => {
    const program = createProgram();
    expect(program).toBeDefined();
    expect(program.name()).toBe("qring");
  });

  it("registers all expected top-level commands", () => {
    const program = createProgram();
    const commands = program.commands.map((c) => c.name());

    const expected = [
      "set", "get", "delete", "list", "inspect", "export", "import",
      "check", "validate", "exec", "scan", "lint", "context",
      "remember", "recall", "forget", "approve", "approvals",
      "hook:install", "hook:uninstall", "hook:run",
      "wizard", "analyze", "env", "generate", "entangle", "disentangle",
      "tunnel", "teleport", "audit", "audit:verify", "audit:export",
      "health", "hook", "env:generate", "status", "agent",
      "rotate", "ci:validate", "policy", "canary", "mcp",
    ];

    for (const name of expected) {
      expect(commands).toContain(name);
    }
  });

  it("registers tunnel subcommands", () => {
    const program = createProgram();
    const tunnelCmd = program.commands.find((c) => c.name() === "tunnel");
    expect(tunnelCmd).toBeDefined();
    const subNames = tunnelCmd!.commands.map((c) => c.name());
    expect(subNames).toContain("create");
    expect(subNames).toContain("read");
    expect(subNames).toContain("destroy");
    expect(subNames).toContain("list");
  });

  it("registers teleport subcommands", () => {
    const program = createProgram();
    const tpCmd = program.commands.find((c) => c.name() === "teleport");
    expect(tpCmd).toBeDefined();
    const subNames = tpCmd!.commands.map((c) => c.name());
    expect(subNames).toContain("pack");
    expect(subNames).toContain("unpack");
  });

  it("registers canary subcommands", () => {
    const program = createProgram();
    const canaryCmd = program.commands.find((c) => c.name() === "canary");
    expect(canaryCmd).toBeDefined();
    const subNames = canaryCmd!.commands.map((c) => c.name());
    expect(subNames).toContain("plant");
    expect(subNames).toContain("list");
  });

  it("registers mcp subcommands", () => {
    const program = createProgram();
    const mcpCmd = program.commands.find((c) => c.name() === "mcp");
    expect(mcpCmd).toBeDefined();
    const subNames = mcpCmd!.commands.map((c) => c.name());
    expect(subNames).toContain("wrap");
  });

  it("registers hook subcommands", () => {
    const program = createProgram();
    const hookCmd = program.commands.find((c) => c.name() === "hook");
    expect(hookCmd).toBeDefined();
    const subNames = hookCmd!.commands.map((c) => c.name());
    expect(subNames).toContain("add");
    expect(subNames).toContain("list");
    expect(subNames).toContain("remove");
    expect(subNames).toContain("enable");
    expect(subNames).toContain("disable");
    expect(subNames).toContain("test");
  });
});
