import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setupEditor, configPathFor } from "../../core/setup.js";

let project: string;

beforeEach(() => {
  project = mkdtempSync(join(tmpdir(), "qring-setup-test-"));
});

afterEach(() => {
  rmSync(project, { recursive: true, force: true });
});

function readConfig(path: string): Record<string, any> {
  return JSON.parse(readFileSync(path, "utf8"));
}

describe("setupEditor", () => {
  it("creates a fresh cursor config", () => {
    const result = setupEditor({ editor: "cursor", projectPath: project });

    expect(result.action).toBe("created");
    expect(result.configPath).toBe(join(project, ".cursor", "mcp.json"));
    const config = readConfig(result.configPath);
    expect(config.mcpServers["q-ring"].command).toBe("qring-mcp");
  });

  it("kiro entry carries the read-only autoApprove list", () => {
    const result = setupEditor({ editor: "kiro", projectPath: project });

    expect(result.configPath).toBe(join(project, ".kiro", "settings", "mcp.json"));
    const entry = readConfig(result.configPath).mcpServers["q-ring"];
    expect(entry.disabled).toBe(false);
    expect(entry.autoApprove).toContain("list_secrets");
    expect(entry.autoApprove).not.toContain("set_secret");
  });

  it("claude entry is stdio-typed at .mcp.json", () => {
    const result = setupEditor({ editor: "claude", projectPath: project });

    expect(result.configPath).toBe(join(project, ".mcp.json"));
    expect(readConfig(result.configPath).mcpServers["q-ring"].type).toBe("stdio");
  });

  it("claude --global refuses and points at the claude CLI", () => {
    expect(() => configPathFor("claude", true, project)).toThrow(/claude mcp add/);
  });

  it("preserves other servers when merging into an existing config", () => {
    const configPath = join(project, ".cursor", "mcp.json");
    mkdirSync(join(project, ".cursor"), { recursive: true });
    writeFileSync(
      configPath,
      JSON.stringify({ mcpServers: { other: { command: "other-mcp" } } }),
    );

    const result = setupEditor({ editor: "cursor", projectPath: project });

    expect(result.action).toBe("updated");
    const config = readConfig(configPath);
    expect(config.mcpServers.other.command).toBe("other-mcp");
    expect(config.mcpServers["q-ring"].command).toBe("qring-mcp");
  });

  it("is idempotent — a matching entry is unchanged", () => {
    setupEditor({ editor: "cursor", projectPath: project });
    const result = setupEditor({ editor: "cursor", projectPath: project });
    expect(result.action).toBe("unchanged");
    expect(result.warnings).toEqual([]);
  });

  it("does not clobber a diverging q-ring entry without --force", () => {
    const configPath = join(project, ".cursor", "mcp.json");
    mkdirSync(join(project, ".cursor"), { recursive: true });
    writeFileSync(
      configPath,
      JSON.stringify({ mcpServers: { "q-ring": { command: "custom-wrapper" } } }),
    );

    const result = setupEditor({ editor: "cursor", projectPath: project });
    expect(result.action).toBe("unchanged");
    expect(result.warnings[0]).toMatch(/--force/);
    expect(readConfig(configPath).mcpServers["q-ring"].command).toBe("custom-wrapper");

    const forced = setupEditor({ editor: "cursor", projectPath: project, force: true });
    expect(forced.action).toBe("updated");
    expect(readConfig(configPath).mcpServers["q-ring"].command).toBe("qring-mcp");
  });

  it("dry-run reports without writing", () => {
    const result = setupEditor({ editor: "cursor", projectPath: project, dryRun: true });
    expect(result.action).toBe("created");
    expect(result.dryRun).toBe(true);
    expect(existsSync(result.configPath)).toBe(false);
  });

  it("throws on invalid existing JSON instead of clobbering it", () => {
    mkdirSync(join(project, ".cursor"), { recursive: true });
    writeFileSync(join(project, ".cursor", "mcp.json"), "{not json");
    expect(() => setupEditor({ editor: "cursor", projectPath: project })).toThrow(/not valid JSON/);
  });
});
