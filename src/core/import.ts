/**
 * Import module: parse .env files and bulk-store secrets into q-ring.
 */

import { readFileSync } from "node:fs";
import { setSecret, hasSecret, checkKeyWritePolicy, type SetSecretOptions } from "./keyring.js";

export interface ImportOptions {
  scope?: "global" | "project";
  projectPath?: string;
  env?: string;
  source?: "cli" | "mcp" | "agent" | "api";
  skipExisting?: boolean;
  dryRun?: boolean;
}

export interface ImportResult {
  imported: string[];
  /** Keys left alone because they already exist (skipExisting). */
  skipped: string[];
  /** Keys key policy does not let this caller write, with the reason. */
  skippedByPolicy: { key: string; reason: string }[];
  total: number;
}

/**
 * Parse .env content into key-value pairs.
 * Handles comments, blank lines, quoted values, and basic multiline.
 */
export function parseDotenv(content: string): Map<string, string> {
  const result = new Map<string, string>();
  const lines = content.split(/\r?\n/);

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();

    if (!line || line.startsWith("#")) continue;

    const eqIdx = line.indexOf("=");
    if (eqIdx === -1) continue;

    const key = line.slice(0, eqIdx).trim();
    let value = line.slice(eqIdx + 1).trim();

    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }

    const escapeMap: Record<string, string> = {
      n: "\n", r: "\r", t: "\t", "\\": "\\", '"': '"',
    };
    value = value.replace(/\\([nrt"\\])/g, (_, ch) => escapeMap[ch] ?? ch);

    // Strip inline comments only when the `#` is preceded by whitespace (the
    // dotenv convention), so unquoted values like `foo#bar` are preserved.
    if (!line.includes('"') && !line.includes("'")) {
      const commentMatch = value.match(/\s#/);
      if (commentMatch && commentMatch.index !== undefined) {
        value = value.slice(0, commentMatch.index).trim();
      }
    }

    if (key) result.set(key, value);
  }

  return result;
}

/**
 * Import secrets from a .env file path or raw content string.
 */
export function importDotenv(
  filePathOrContent: string,
  options: ImportOptions = {},
): ImportResult {
  let content: string;

  // The file-path convenience (read from disk if the arg is a path) is only
  // safe for the trusted local CLI. For MCP/agent/api callers the argument is
  // always treated as literal .env content — otherwise an agent could pass a
  // path like ~/.aws/credentials and exfiltrate it through the keyring.
  const source = options.source ?? "cli";
  if (source === "cli") {
    try {
      content = readFileSync(filePathOrContent, "utf8");
    } catch {
      content = filePathOrContent;
    }
  } else {
    content = filePathOrContent;
  }

  const pairs = parseDotenv(content);
  const result: ImportResult = {
    imported: [],
    skipped: [],
    skippedByPolicy: [],
    total: pairs.size,
  };

  for (const [key, value] of pairs) {
    // Policy first, for every key: a protected key is reported and skipped,
    // never thrown on halfway through the file after earlier keys landed.
    const decision = checkKeyWritePolicy(key, {
      scope: options.scope ?? "global",
      projectPath: options.projectPath ?? process.cwd(),
      source: options.source ?? "cli",
    });
    if (!decision.allowed) {
      result.skippedByPolicy.push({ key, reason: decision.reason ?? "denied by policy" });
      continue;
    }

    if (options.skipExisting && hasSecret(key, {
      scope: options.scope,
      projectPath: options.projectPath,
      source: options.source ?? "cli",
    })) {
      result.skipped.push(key);
      continue;
    }

    if (options.dryRun) {
      result.imported.push(key);
      continue;
    }

    const setOpts: SetSecretOptions = {
      scope: options.scope ?? "global",
      projectPath: options.projectPath ?? process.cwd(),
      source: options.source ?? "cli",
    };

    setSecret(key, value, setOpts);
    result.imported.push(key);
  }

  return result;
}
