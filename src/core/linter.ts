/**
 * Secret-Aware Linter
 *
 * Scans individual files (or staged git content) for hardcoded secrets and
 * optionally rewrites them with `process.env.KEY` references, storing the
 * discovered values in q-ring.
 */

import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { basename, extname } from "node:path";
import { type ScanResult } from "./scan.js";
import { setSecret, secretExists, checkKeyWritePolicy } from "./keyring.js";
import { findSecretsInLine, calculateEntropy } from "./secrets-detect.js";

export interface LintResult extends ScanResult {
  fixed: boolean;
  /**
   * Why a requested fix was not applied: key policy does not let this
   * caller write the key. The literal is left in place (rewriting it to an
   * env reference without storing the value would lose it).
   */
  skipped?: string;
}

export interface LintOptions {
  fix?: boolean;
  scope?: import("./scope.js").Scope;
  projectPath?: string;
  /** Who is fixing: an MCP caller's writes are held to key policy. Default "cli". */
  source?: "cli" | "mcp";
}

const ENV_REF_BY_EXT: Record<string, (key: string) => string> = {
  ".ts": (k) => `process.env.${k}`,
  ".tsx": (k) => `process.env.${k}`,
  ".js": (k) => `process.env.${k}`,
  ".jsx": (k) => `process.env.${k}`,
  ".mjs": (k) => `process.env.${k}`,
  ".cjs": (k) => `process.env.${k}`,
  ".py": (k) => `os.environ["${k}"]`,
  ".rb": (k) => `ENV["${k}"]`,
  ".go": (k) => `os.Getenv("${k}")`,
  ".rs": (k) => `std::env::var("${k}")`,
  ".java": (k) => `System.getenv("${k}")`,
  ".kt": (k) => `System.getenv("${k}")`,
  ".cs": (k) => `Environment.GetEnvironmentVariable("${k}")`,
  ".php": (k) => `getenv('${k}')`,
  ".sh": (k) => `\${${k}}`,
  ".bash": (k) => `\${${k}}`,
};

function getEnvRef(filePath: string, keyName: string): string {
  const ext = extname(filePath).toLowerCase();
  const formatter = ENV_REF_BY_EXT[ext];
  return formatter ? formatter(keyName) : `process.env.${keyName}`;
}

/**
 * Lint specific files for hardcoded secrets.
 */
export function lintFiles(
  files: string[],
  opts: LintOptions = {},
): LintResult[] {
  const results: LintResult[] = [];

  for (const file of files) {
    if (!existsSync(file)) continue;

    let content: string;
    try {
      content = readFileSync(file, "utf8");
    } catch {
      continue;
    }

    if (content.includes("\0")) continue;

    const lines = content.split(/\r?\n/);
    const fixes: Array<{
      line: number;
      original: string;
      replacement: string;
      keyName: string;
      value: string;
      result: LintResult;
    }> = [];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const matches = findSecretsInLine(line);

      for (const m of matches) {
        const varNameUpper = m.varName.toUpperCase();
        const entropy = calculateEntropy(m.value);
        const shouldFix = opts.fix === true;

        const result: LintResult = {
          file,
          line: i + 1,
          keyName: varNameUpper,
          match: m.value,
          context: line.trim(),
          entropy: parseFloat(entropy.toFixed(2)),
          fixed: shouldFix,
        };
        results.push(result);

        if (shouldFix) {
          const envRef = getEnvRef(file, varNameUpper);
          fixes.push({
            line: i,
            original: `${m.quote}${m.value}${m.quote}`,
            replacement: envRef,
            keyName: varNameUpper,
            value: m.value,
            result,
          });
        }
      }
    }

    if (opts.fix && fixes.length > 0) {
      // Split keeping each line's own terminator: line i is parts[2 * i],
      // its "\n" or "\r\n" is parts[2 * i + 1]. Rejoining reproduces the
      // file byte for byte, mixed line endings included, so only a line
      // whose content a fix changed can differ.
      const parts = content.split(/(\r?\n)/);
      const lineCount = Math.ceil(parts.length / 2);
      for (const fix of fixes.reverse()) {
        // Policy first: a key this caller may not write is skipped with a
        // reason and its literal left alone; the other fixes, in this file
        // and the next, still run (no abort halfway through a batch).
        const decision = checkKeyWritePolicy(fix.keyName, {
          scope: opts.scope ?? "global",
          projectPath: opts.projectPath,
          source: opts.source ?? "cli",
        });
        if (!decision.allowed) {
          fix.result.fixed = false;
          fix.result.skipped = decision.reason ?? "denied by policy";
          continue;
        }

        const lineIdx = fix.line;
        if (lineIdx >= 0 && lineIdx < lineCount) {
          parts[2 * lineIdx] = parts[2 * lineIdx].replace(fix.original, fix.replacement);
        }

        // True existence, not the caller's policy-filtered view (hasSecret).
        if (
          !secretExists(fix.keyName, {
            scope: opts.scope,
            projectPath: opts.projectPath,
          })
        ) {
          setSecret(fix.keyName, fix.value, {
            scope: opts.scope ?? "global",
            projectPath: opts.projectPath,
            source: opts.source ?? "cli",
            description: `Auto-imported from ${basename(file)}:${fix.line + 1}`,
          });
        }
      }

      // Write only a real change: a file whose every fix was skipped by
      // policy must stay byte-identical (no line-ending rewrite, no mtime
      // bump).
      const updated = parts.join("");
      if (updated !== content) writeFileSync(file, updated, "utf8");
    }
  }

  return results;
}
