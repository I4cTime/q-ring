/**
 * Design tokens for the `qring status` dashboard: the Quantum skin.
 *
 * These values MIRROR the `:root` `--skin-*` block of
 * apps/qring/app/globals.css in the i4c-sites repo (the q-ring marketing
 * site), so the local dashboard reads as the same product as the site.
 * Change them together: a value edited here and not there (or the other way
 * round) is drift. Nothing is imported from the site; the page stays fully
 * self-contained and offline.
 *
 * This file is the ONLY place a colour literal lives for the dashboard.
 * dashboard-html.ts renders the `:root` block with tokensToCssVars(), and
 * both it and src/dashboard-client/main.js refer to colours through CSS
 * variables only (tints use color-mix() over those variables).
 * src/__tests__/core/dashboard-tokens.test.ts fails on a hex or rgba literal
 * anywhere else.
 *
 * Contrast notes carried over from the site's table (WCAG 2.x, on bg-card):
 *   text-dim 5.33, accent 10.69, danger (text red) 6.87, warning 9.51,
 *   success 8.43, brand-text 6.59. brandDeep (#7b2dff) is 3.6:1 on bg-deep:
 *   glow, gradient and fill only, never text. dangerFill is a fill/signal
 *   colour (3.6:1 on bg-card); text uses `danger`. Never put text-dim on an
 *   accent-dim tint (4.12:1); use text-secondary there.
 */

export const DASHBOARD_TOKENS = {
  color: {
    bgDeep: "#000102",
    bgSection: "#05070b",
    bgAlt: "#080a10",
    bgCard: "#0b0d14",
    bgCardHover: "#11141c",
    border: "#1e2129",
    separator: "#191c24",
    segment: "#1a1e27",

    textPrimary: "#f3f5f9",
    textSecondary: "#c0c4cd",
    textDim: "#828690",

    accent: "#00d1ff",
    accentForeground: "#000102",
    accentBright: "#66e3ff",
    accentDim: "rgba(0, 209, 255, 0.15)",
    accentGlow: "rgba(0, 209, 255, 0.4)",

    /** Brand gradient end: glow, gradient and fill only, never text. */
    brandDeep: "#7b2dff",
    /** Text-safe violet (the site's brand-violet-text). */
    brandText: "#a082ff",
    brandDim: "rgba(123, 45, 255, 0.15)",
    brandGlow: "rgba(123, 45, 255, 0.4)",

    success: "#22c373",
    warning: "#eba941",
    /** Text-safe red. */
    danger: "#f0718a",
    /** Red fill / signal; not text-safe on cards. */
    dangerFill: "#c72c4c",

    bgTerminal: "#0c0c0c",
    terminalChrome: "#1a1a1a",
    terminalChromeBorder: "#2a2a2a",
  },
  radius: {
    xs: "6px",
    sm: "10px",
    md: "16px",
    lg: "24px",
  },
  motion: {
    fast: "200ms",
    base: "300ms",
    ease: "cubic-bezier(0.22, 1, 0.36, 1)",
  },
  font: {
    display: "system-ui, -apple-system, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif",
    mono: "ui-monospace, 'SF Mono', 'Cascadia Code', 'JetBrains Mono', 'Fira Code', Consolas, 'Liberation Mono', monospace",
  },
} as const;

export type DashboardTokens = typeof DASHBOARD_TOKENS;

/** camelCase token name to a kebab-case CSS custom property name. */
function kebab(name: string): string {
  return name.replace(/[A-Z]/g, (c) => "-" + c.toLowerCase());
}

/**
 * Render the tokens as the page's `:root { ... }` block.
 *
 * Colours become `--<name>` (bgDeep is `--bg-deep`), radii `--radius-<size>`,
 * motion `--motion-fast`, `--motion-base`, `--motion-ease`, fonts
 * `--font-display` and `--font-mono`. Two derived values ride along: the
 * opt-in signature glow (`--glow`, cyan plus violet) and the brand gradient
 * (`--brand-gradient`), both built from the variables above.
 */
export function tokensToCssVars(tokens: DashboardTokens = DASHBOARD_TOKENS): string {
  const lines: string[] = [];
  for (const [name, value] of Object.entries(tokens.color)) {
    lines.push(`  --${kebab(name)}:${value};`);
  }
  for (const [name, value] of Object.entries(tokens.radius)) {
    lines.push(`  --radius-${name}:${value};`);
  }
  for (const [name, value] of Object.entries(tokens.motion)) {
    lines.push(`  --motion-${name}:${value};`);
  }
  for (const [name, value] of Object.entries(tokens.font)) {
    lines.push(`  --font-${name}:${value};`);
  }
  lines.push(
    "  --glow:0 0 20px color-mix(in srgb,var(--accent) 12%,transparent),0 0 40px color-mix(in srgb,var(--brand-deep) 8%,transparent);",
  );
  lines.push("  --brand-gradient:linear-gradient(135deg,var(--accent),var(--brand-deep));");
  return `:root{\n${lines.join("\n")}\n}`;
}
