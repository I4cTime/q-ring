/**
 * Shared heuristics for hardcoded-secret detection (scan + lint).
 * Both `scan.ts` and `linter.ts` use this module so rules stay aligned.
 */

/** Same pattern for assignment-style secrets in source lines. */
export const SECRET_ASSIGNMENT_PATTERN =
  /((?:api_?key|secret|token|password|auth|credential|access_?key)[a-z0-9_]*)\s*[:=]\s*(['"])([^'"]+)\2/gi;

export interface SecretMatchInLine {
  varName: string;
  value: string;
  quote: string;
}

export function calculateEntropy(str: string): number {
  if (!str) return 0;
  const len = str.length;
  const frequencies = new Map<string, number>();

  for (let i = 0; i < len; i++) {
    const char = str[i];
    frequencies.set(char, (frequencies.get(char) || 0) + 1);
  }

  let entropy = 0;
  for (const count of frequencies.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }

  return entropy;
}

export function isPlaceholderValue(value: string): boolean {
  const lv = value.toLowerCase();
  return (
    lv.includes("example") ||
    lv.includes("your_") ||
    lv.includes("placeholder") ||
    lv.includes("replace_me") ||
    lv.includes("xxx")
  );
}

function passesSecretHeuristic(value: string, entropy: number): boolean {
  return entropy > 3.5 || value.startsWith("sk-") || value.startsWith("ghp_");
}

/**
 * Find all secret-like assignments on one line (same behavior as the linter:
 * every match on the line is considered).
 */
export function findSecretsInLine(line: string): SecretMatchInLine[] {
  if (line.length > 500) return [];

  const out: SecretMatchInLine[] = [];
  SECRET_ASSIGNMENT_PATTERN.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = SECRET_ASSIGNMENT_PATTERN.exec(line)) !== null) {
    const varName = match[1];
    const quote = match[2];
    const value = match[3];

    if (value.length < 8) continue;
    if (isPlaceholderValue(value)) continue;

    const entropy = calculateEntropy(value);
    if (!passesSecretHeuristic(value, entropy)) continue;

    out.push({ varName, value, quote });
  }
  return out;
}
