import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { DASHBOARD_TOKENS, tokensToCssVars } from "../../core/dashboard-tokens.js";
import { getDashboardHtml } from "../../core/dashboard-html.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const read = (rel: string) => readFileSync(join(root, rel), "utf8");

describe("dashboard tokens (the Quantum skin)", () => {
  it("renders the site's accent and bg-deep into the :root block", () => {
    const css = tokensToCssVars();
    expect(css.startsWith(":root{")).toBe(true);
    expect(css).toContain("--accent:#00d1ff;");
    expect(css).toContain("--bg-deep:#000102;");
    expect(css).toContain(`--radius-md:${DASHBOARD_TOKENS.radius.md};`);
    expect(css).toContain(`--motion-ease:${DASHBOARD_TOKENS.motion.ease};`);
  });

  it("is what the served page carries", () => {
    const page = getDashboardHtml("test-token");
    expect(page).toContain(tokensToCssVars());
  });

  it("keeps every colour literal in the tokens file", () => {
    for (const rel of ["core/dashboard-html.ts", "dashboard-client/main.js"]) {
      const src = read(rel);
      expect(src.match(/#[0-9a-fA-F]{6}\b/g), `6-digit hex in ${rel}`).toBeNull();
      expect(src.match(/#[0-9a-fA-F]{3}(?:[0-9a-fA-F]{5})?\b/g), `hex in ${rel}`).toBeNull();
      expect(src.match(/\b(?:rgba?|hsla?)\(/g), `rgb/hsl literal in ${rel}`).toBeNull();
    }
  });
});
