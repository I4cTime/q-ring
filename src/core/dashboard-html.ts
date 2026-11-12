/**
 * Self-contained HTML dashboard for q-ring quantum status.
 *
 * Wears the Quantum skin of the q-ring marketing site: the palette, radii and
 * motion come from DASHBOARD_TOKENS (src/core/dashboard-tokens.ts, which
 * mirrors apps/qring/app/globals.css in the i4c-sites repo), flat cards on
 * bg-card with a 1 px border, cyan as the one accent, and the cyan to violet
 * gradient and glow kept for the brand mark only. Every colour below is a CSS
 * variable; tints are color-mix() over those variables. No hex or rgba
 * literal lives in this file (dashboard-tokens.test.ts checks).
 *
 * The page is fully self-contained and offline: inline CSS plus an inlined
 * Preact + htm client bundle (see DASHBOARD_CLIENT, generated from
 * src/dashboard-client/main.js), system font stacks, no external fetch.
 * Rendering is VDOM-diffed so the SSE stream updates data in place.
 *
 * Layout:
 *   1. Sticky header with brand, version, project path, live/paused state,
 *      pause+refresh controls, last-update timestamp.
 *   2. KPI tiles (the site's StatsRow): label, big tabular number, one hint.
 *   3. Health donut + Environment + Manifest + Policy cards.
 *   4. Searchable + sortable secrets table.
 *   5. Quantum cards: Decay, Rotation, Superposition, Entanglement, Tunnels.
 *   6. Governance: Approvals, Hooks, Canary (operator view only), Memory.
 *   7. Agent sessions, Anomalies (full-width).
 *   8. Audit log with the chain status pill and a console-style feed.
 *
 * Breakpoints: 768 px (single column, KPI tiles two per row, header wraps
 * and stops sticking) and 480 px (tighter gutters, table scrolls inside its
 * card). prefers-reduced-motion turns off the pulses and transitions.
 */

import { DASHBOARD_CLIENT } from "./dashboard-client.js";
import { tokensToCssVars } from "./dashboard-tokens.js";

/** Escape a value for safe embedding inside an inline <script> string literal. */
function jsString(value: string): string {
  return JSON.stringify(value).replace(/</g, "\\u003c");
}

export interface DashboardHtmlOptions {
  /**
   * Started for an MCP agent. The client then leaves out the operator-only
   * cards (the Canary card); the snapshot carries no canary data either.
   */
  agentView?: boolean;
}

export function getDashboardHtml(token: string, options: DashboardHtmlOptions = {}): string {
  const config = `{token:${jsString(token)},agentView:${options.agentView === true ? "true" : "false"}}`;
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<meta name="color-scheme" content="dark"/>
<title>q-ring - quantum status</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
${tokensToCssVars()}
html{background:var(--bg-deep);color:var(--text-primary);font-family:var(--font-display);font-size:16px;line-height:1.5;-webkit-text-size-adjust:100%}
body{min-height:100vh;overflow-x:hidden;background:var(--bg-deep)}
code{font-family:var(--font-mono);font-size:.92em;color:var(--text-secondary)}
:focus-visible{outline:2px solid var(--accent-bright);outline-offset:2px}

/* Hidden SVG defs for the brand gradient */
.svg-defs{position:absolute;width:0;height:0;overflow:hidden}
.grad-start{stop-color:var(--accent)}
.grad-end{stop-color:var(--brand-deep)}

.container{max-width:1320px;margin:0 auto;padding:20px 20px 48px}

/* Header */
.header{position:sticky;top:12px;z-index:5;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px 16px;margin-bottom:20px;padding:12px 16px;background:var(--bg-section);border:1px solid var(--border);border-radius:var(--radius-md)}
.header-left{display:flex;align-items:center;gap:10px 14px;flex-wrap:wrap;min-width:0}
.header h1{font-size:1.4rem;font-weight:700;letter-spacing:-.02em;display:flex;align-items:center;gap:10px;line-height:1.2}
.header h1 .q-icon{display:flex;filter:drop-shadow(0 0 6px var(--accent-glow)) drop-shadow(0 0 14px var(--brand-glow))}
.header h1 .brand{background:linear-gradient(135deg,var(--accent),var(--brand-text));-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent}
.header h1 .sub{color:var(--text-dim);font-weight:500;font-size:1rem;letter-spacing:0;-webkit-text-fill-color:var(--text-dim)}
.meta-chip{font-family:var(--font-mono);font-size:.72rem;color:var(--text-secondary);background:var(--bg-card);border:1px solid var(--border);padding:3px 10px;border-radius:999px;display:inline-flex;align-items:center;gap:6px;max-width:340px;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.meta-chip svg{width:11px;height:11px;flex-shrink:0;color:var(--text-dim)}
.header-right{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.status-dot{width:8px;height:8px;border-radius:50%;background:var(--success);display:inline-block;animation:pulse 2s ease-in-out infinite}
.status-dot.disconnected{background:var(--danger);animation:none}
.status-dot.paused{background:var(--warning);animation:none}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.35}}
.conn-label{font-size:.76rem;color:var(--text-secondary);display:flex;align-items:center;gap:6px;font-family:var(--font-mono)}
.btn{font-family:var(--font-display);font-size:.78rem;font-weight:500;color:var(--text-secondary);background:var(--bg-card);border:1px solid var(--border);padding:5px 12px;border-radius:var(--radius-sm);cursor:pointer;display:inline-flex;align-items:center;gap:6px;text-decoration:none;transition:background-color var(--motion-fast) var(--motion-ease),border-color var(--motion-fast) var(--motion-ease),color var(--motion-fast) var(--motion-ease)}
.btn:hover{background:var(--bg-card-hover);border-color:var(--accent);color:var(--text-primary)}
.btn svg{width:13px;height:13px}
.btn.active{background:var(--accent-dim);color:var(--accent-bright);border-color:var(--accent)}
.kbd{font-family:var(--font-mono);font-size:.66rem;color:var(--text-secondary);background:var(--bg-card);border:1px solid var(--border);border-bottom-width:2px;padding:1px 6px;border-radius:var(--radius-xs);margin:0 2px}

/* KPI tiles (the site's StatsRow) */
.kpi-strip{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px;margin-bottom:20px}
.kpi{min-width:0;background:var(--bg-card);border:1px solid var(--border);border-radius:var(--radius-md);padding:12px 14px;display:flex;flex-direction:column;gap:4px;transition:background-color var(--motion-fast) var(--motion-ease)}
.kpi:hover{background:var(--bg-card-hover)}
.kpi-label{font-size:.68rem;text-transform:uppercase;letter-spacing:.08em;color:var(--text-dim);font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.kpi-value{font-family:var(--font-mono);font-size:1.5rem;font-weight:600;line-height:1.15;color:var(--text-primary);font-variant-numeric:tabular-nums;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.kpi-value.warning{color:var(--warning)}
.kpi-value.danger{color:var(--danger)}
.kpi-value.green{color:var(--success)}
.kpi-value.dim{color:var(--text-dim)}
.kpi-sub{font-size:.7rem;color:var(--text-secondary);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}

/* Grid */
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(min(360px,100%),1fr));gap:16px;margin-bottom:16px}
.grid-wide{grid-column:1/-1}

/* Cards: flat, bg-card, 1 px border, radius 16 */
.card{min-width:0;background:var(--bg-card);border:1px solid var(--border);border-radius:var(--radius-md);padding:18px 20px;transition:background-color var(--motion-base) var(--motion-ease),border-color var(--motion-base) var(--motion-ease)}
.card:hover{background:var(--bg-card-hover)}
.card-title{font-size:1rem;color:var(--text-primary);margin-bottom:14px;display:flex;align-items:center;flex-wrap:wrap;gap:8px 10px;font-weight:600;letter-spacing:-.01em}
.card-title svg{width:16px;height:16px;flex-shrink:0;color:var(--accent)}
.card-title .title-aside{margin-left:auto;font-family:var(--font-mono);font-size:.72rem;color:var(--text-dim);font-weight:400;display:flex;align-items:center;gap:6px;font-variant-numeric:tabular-nums}
.card-lede{font-size:.84rem;color:var(--text-secondary);margin:-8px 0 12px}

/* Health donut */
.health-row{display:flex;align-items:center;gap:24px;flex-wrap:wrap}
.donut-wrap{position:relative;width:100px;height:100px;flex-shrink:0}
.donut-wrap svg{transform:rotate(-90deg)}
.donut-wrap .donut-label{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;flex-direction:column;font-family:var(--font-mono);font-size:1.5rem;font-weight:600;line-height:1;font-variant-numeric:tabular-nums}
.donut-wrap .donut-label small{font-family:var(--font-display);font-size:.68rem;color:var(--text-dim);font-weight:500;margin-top:4px;text-transform:uppercase;letter-spacing:.08em}
.health-legend{display:flex;flex-direction:column;gap:6px;font-family:var(--font-mono);color:var(--text-secondary)}
.legend-item{display:flex;align-items:center;gap:8px;font-size:.82rem}
.legend-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}
.scope-row{display:flex;gap:6px;margin-top:14px;flex-wrap:wrap;font-family:var(--font-mono);font-size:.72rem;color:var(--text-secondary)}
.scope-pill{padding:2px 9px;border-radius:999px;background:var(--bg-deep);border:1px solid var(--border)}
.scope-pill strong{color:var(--text-primary);margin-right:4px;font-weight:600}

/* Decay bars */
.decay-list{display:flex;flex-direction:column;gap:8px;max-height:280px;overflow-y:auto}
.decay-item{display:flex;align-items:center;gap:10px;min-width:0}
.decay-key{font-family:var(--font-mono);font-size:.84rem;min-width:0;flex:0 1 180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.decay-bar{flex:1;min-width:40px;height:6px;border-radius:3px;background:var(--segment);overflow:hidden;position:relative}
.decay-fill{height:100%;border-radius:3px;transition:width var(--motion-base) var(--motion-ease)}
.decay-time{font-size:.8rem;color:var(--text-dim);min-width:60px;text-align:right;font-family:var(--font-mono);font-variant-numeric:tabular-nums}
.rotation-list{display:flex;flex-direction:column;gap:8px;max-height:280px;overflow-y:auto}
.rotation-item{display:flex;align-items:center;gap:10px;min-width:0}
.rotation-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}
.rotation-key{font-family:var(--font-mono);font-size:.84rem;flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.rotation-scope{font-size:.7rem;color:var(--text-dim);text-transform:uppercase;letter-spacing:.06em}
.rotation-every{font-size:.78rem;color:var(--text-dim);font-family:var(--font-mono)}
.rotation-due{font-size:.8rem;min-width:84px;text-align:right;font-family:var(--font-mono);font-weight:600}
.scope-pill.rotation-due{color:var(--warning);min-width:0;text-align:left;font-size:.72rem}

/* Superposition pills */
.super-list{display:flex;flex-direction:column;gap:8px;max-height:280px;overflow-y:auto}
.super-item{display:flex;align-items:center;gap:6px 8px;flex-wrap:wrap}
.super-key{font-family:var(--font-mono);font-size:.84rem;min-width:100px;overflow-wrap:anywhere}
.env-pill{font-size:.7rem;padding:1px 8px;border-radius:999px;font-weight:600;font-family:var(--font-mono);border:1px solid transparent;white-space:nowrap}
.env-prod{background:color-mix(in srgb,var(--danger) 10%,transparent);color:var(--danger);border-color:color-mix(in srgb,var(--danger) 45%,transparent)}
.env-staging{background:color-mix(in srgb,var(--warning) 10%,transparent);color:var(--warning);border-color:color-mix(in srgb,var(--warning) 45%,transparent)}
.env-dev{background:color-mix(in srgb,var(--success) 10%,transparent);color:var(--success);border-color:color-mix(in srgb,var(--success) 45%,transparent)}
.env-default{background:var(--brand-dim);color:var(--brand-text);border-color:color-mix(in srgb,var(--brand-text) 35%,transparent)}
.env-test{background:var(--accent-dim);color:var(--accent-bright);border-color:color-mix(in srgb,var(--accent) 40%,transparent)}

/* Entanglement */
.entangle-list{display:flex;flex-direction:column;gap:6px;max-height:240px;overflow-y:auto}
.entangle-pair{display:flex;align-items:center;gap:8px;font-family:var(--font-mono);font-size:.82rem;flex-wrap:wrap}
.entangle-arrow{color:var(--accent)}
.entangle-graph{display:block;width:100%;height:auto;max-height:260px}
.entangle-edge{stroke:var(--accent);stroke-opacity:.45;stroke-width:1.2}
.entangle-node{fill:var(--accent-bright);stroke:var(--accent-dim);stroke-width:3;paint-order:stroke}
.entangle-label{fill:var(--text-secondary);font-family:var(--font-mono);font-size:9px}

/* Audit chain status pill (the site's AuditChain StatusPill) */
.chain-badge{display:inline-flex;align-items:center;gap:6px;font-family:var(--font-mono);font-size:.74rem;font-weight:500;padding:3px 10px;border-radius:999px;border:1px solid transparent;letter-spacing:0}
.chain-badge svg{width:13px;height:13px;flex-shrink:0;color:currentColor}
.chain-badge.ok{color:var(--success);background:color-mix(in srgb,var(--success) 10%,transparent);border-color:color-mix(in srgb,var(--success) 50%,transparent)}
.chain-badge.broken{color:var(--danger);background:color-mix(in srgb,var(--danger-fill) 12%,transparent);border-color:color-mix(in srgb,var(--danger) 60%,transparent)}
.chain-count{font-family:var(--font-mono);font-size:.74rem;font-weight:400;color:var(--text-dim);font-variant-numeric:tabular-nums}
.chain-note{font-family:var(--font-mono);font-size:.76rem;color:var(--danger);margin:-6px 0 12px}

/* Tunnels */
.tunnel-list{display:flex;flex-direction:column;gap:8px;max-height:240px;overflow-y:auto}
.tunnel-card{background:var(--bg-deep);border:1px solid var(--border);border-radius:var(--radius-sm);padding:10px 12px;font-size:.82rem;font-family:var(--font-mono);overflow-wrap:anywhere}
.tunnel-meta{display:flex;gap:12px;margin-top:4px;font-size:.76rem;color:var(--text-dim);flex-wrap:wrap}

/* Audit feed: the console transcript look */
.audit-toolbar{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:10px;align-items:center}
.audit-actions-strip{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:10px}
.audit-chip{font-family:var(--font-mono);font-size:.72rem;padding:3px 10px;border-radius:999px;background:var(--bg-card);border:1px solid var(--border);color:var(--text-secondary);cursor:pointer;transition:border-color var(--motion-fast) var(--motion-ease),color var(--motion-fast) var(--motion-ease)}
.audit-chip:hover{border-color:var(--accent);color:var(--text-primary)}
.audit-chip.active{background:var(--accent-dim);color:var(--accent-bright);border-color:var(--accent)}
.audit-chip strong{color:var(--text-primary);margin-left:6px;font-weight:600;font-variant-numeric:tabular-nums}
.audit-feed{display:flex;flex-direction:column;max-height:360px;overflow-y:auto;font-size:.8rem;font-family:var(--font-mono);line-height:1.6;background:var(--bg-terminal);border:1px solid var(--terminal-chrome-border);border-radius:var(--radius-sm);padding:8px 12px}
.audit-row{display:grid;grid-template-columns:64px 108px 56px minmax(0,1fr);gap:10px;padding:3px 0;border-bottom:1px solid var(--terminal-chrome);align-items:center}
.audit-row:last-child{border-bottom:0}
.audit-ts{color:var(--text-dim);font-variant-numeric:tabular-nums}
.audit-action{font-size:.72rem;font-weight:600;padding:0 8px;border-radius:999px;border:1px solid color-mix(in srgb,currentColor 45%,transparent);background:color-mix(in srgb,currentColor 10%,transparent);color:var(--text-secondary);white-space:nowrap;justify-self:start}
.audit-action.read,.audit-action.collapse{color:var(--accent)}
.audit-action.write,.audit-action.approve{color:var(--success)}
.audit-action.delete,.audit-action.revoke,.audit-action.policy_deny,.audit-action.canary,.audit-action.canary_alert{color:var(--danger)}
.audit-action.entangle,.audit-action.tunnel,.audit-action.rotate,.audit-action.wrap{color:var(--brand-text)}
.audit-action.teleport,.audit-action.generate,.audit-action.push{color:var(--warning)}
.audit-action.list,.audit-action.export{color:var(--text-dim)}
.audit-source{font-size:.7rem;color:var(--text-secondary);padding:0 8px;border-radius:999px;border:1px solid var(--border);background:var(--bg-card);text-transform:lowercase;white-space:nowrap;justify-self:start}
.audit-source:empty{display:none}
.audit-line{min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.audit-detail{color:var(--text-dim)}
.audit-key{color:var(--text-primary)}

/* Anomalies */
.anomaly-list{display:flex;flex-direction:column;gap:8px}
.anomaly-card{background:color-mix(in srgb,var(--danger-fill) 10%,transparent);border:1px solid color-mix(in srgb,var(--danger) 35%,transparent);border-radius:var(--radius-sm);padding:10px 14px}
.anomaly-type{font-size:.7rem;text-transform:uppercase;letter-spacing:.08em;color:var(--danger);font-weight:700;margin-bottom:2px}
.anomaly-desc{font-size:.86rem;color:var(--text-primary)}
.anomaly-hint{font-size:.74rem;color:var(--text-secondary);margin-top:4px;font-family:var(--font-mono)}

/* Environment badge */
.env-status{display:flex;align-items:center;gap:12px;flex-wrap:wrap}
.env-big{font-size:.95rem;padding:3px 14px}
.env-source{font-size:.78rem;color:var(--text-secondary);font-family:var(--font-mono)}

/* Manifest */
.manifest-bars{display:flex;flex-direction:column;gap:8px}
.manifest-row{display:flex;align-items:center;gap:8px;font-family:var(--font-mono);font-size:.78rem;color:var(--text-secondary)}
.manifest-bar{flex:1;height:6px;border-radius:3px;background:var(--segment);overflow:hidden}
.manifest-fill{height:100%;border-radius:3px;transition:width var(--motion-base) var(--motion-ease)}
.manifest-list{margin-top:10px;display:flex;flex-direction:column;gap:3px;font-family:var(--font-mono);font-size:.78rem;color:var(--text-secondary)}
.manifest-list .label{color:var(--text-dim);text-transform:uppercase;font-size:.66rem;letter-spacing:.08em;margin-top:6px}
.manifest-list .key-pill{display:inline-block;padding:1px 7px;background:var(--bg-deep);border:1px solid var(--border);border-radius:var(--radius-xs);margin:1px 3px 1px 0;font-size:.74rem}
.manifest-list .key-pill.miss{color:var(--danger);border-color:color-mix(in srgb,var(--danger) 50%,transparent)}
.manifest-list .key-pill.exp{color:var(--warning);border-color:color-mix(in srgb,var(--warning) 50%,transparent)}

/* Policy (the site's PolicyPanel, read-only) */
.policy-rows{display:flex;flex-direction:column;gap:2px;list-style:none}
.policy-row{display:flex;align-items:center;gap:10px;padding:5px 0;border-bottom:1px solid var(--separator);min-width:0}
.policy-row:last-child{border-bottom:0}
.policy-label{flex:1;min-width:0;font-family:var(--font-mono);font-size:.8rem;color:var(--text-primary);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.policy-value{font-family:var(--font-mono);font-size:.8rem;color:var(--text-primary);font-variant-numeric:tabular-nums;min-width:2ch;text-align:right}
.policy-value.zero{color:var(--text-dim)}
.policy-seg{display:inline-flex;flex-shrink:0;border:1px solid var(--border);background:var(--bg-deep);border-radius:var(--radius-sm);padding:2px}
.seg-chip{font-family:var(--font-mono);font-size:.7rem;padding:1px 8px;border-radius:var(--radius-xs);border:1px solid transparent;color:var(--text-dim);min-width:58px;text-align:center}
.seg-chip.allow{color:var(--success);background:color-mix(in srgb,var(--success) 10%,transparent);border-color:color-mix(in srgb,var(--success) 60%,transparent)}
.seg-chip.approve,.seg-chip.require,.seg-chip.limit{color:var(--warning);background:color-mix(in srgb,var(--warning) 10%,transparent);border-color:color-mix(in srgb,var(--warning) 60%,transparent)}
.seg-chip.deny{color:var(--danger);background:color-mix(in srgb,var(--danger-fill) 12%,transparent);border-color:color-mix(in srgb,var(--danger) 60%,transparent)}
.policy-row.off .seg-chip{color:var(--text-dim);background:transparent;border-color:transparent}

/* Approvals */
.approval-list{display:flex;flex-direction:column;gap:8px;max-height:240px;overflow-y:auto}
.approval-card{background:var(--bg-deep);border:1px solid color-mix(in srgb,var(--success) 40%,transparent);border-radius:var(--radius-sm);padding:10px 12px;font-size:.82rem}
.approval-card.tampered{border-color:var(--danger);background:color-mix(in srgb,var(--danger-fill) 10%,transparent)}
.approval-card.expiring{border-color:color-mix(in srgb,var(--warning) 50%,transparent)}
.approval-head{display:flex;justify-content:space-between;gap:8px;font-family:var(--font-mono);font-weight:600;flex-wrap:wrap}
.approval-reason{color:var(--text-secondary);font-size:.76rem;margin-top:3px}
.approval-meta{display:flex;gap:12px;margin-top:4px;font-size:.72rem;color:var(--text-dim);font-family:var(--font-mono);flex-wrap:wrap}

/* Hooks */
.hooks-list{display:flex;flex-direction:column;gap:6px;max-height:240px;overflow-y:auto}
.hook-row{display:flex;align-items:center;gap:8px;font-family:var(--font-mono);font-size:.8rem;padding:6px 10px;background:var(--bg-deep);border:1px solid var(--border);border-radius:var(--radius-sm);min-width:0}
.hook-row.disabled{opacity:.55}
.hook-type{font-size:.68rem;font-weight:600;padding:0 8px;border-radius:999px;border:1px solid transparent;white-space:nowrap;font-family:var(--font-mono)}
.hook-type.shell{color:var(--brand-text);background:var(--brand-dim);border-color:color-mix(in srgb,var(--brand-text) 35%,transparent)}
.hook-type.http{color:var(--accent-bright);background:var(--accent-dim);border-color:color-mix(in srgb,var(--accent) 40%,transparent)}
.hook-type.signal{color:var(--warning);background:color-mix(in srgb,var(--warning) 10%,transparent);border-color:color-mix(in srgb,var(--warning) 45%,transparent)}
.hook-summary{flex:1;min-width:0;color:var(--text-secondary);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.hook-id{color:var(--text-dim);font-size:.72rem}

/* Canary (the site's CanaryCard: none, armed, tripped) */
.canary-card.tripped{border-color:var(--danger);background:color-mix(in srgb,var(--danger-fill) 10%,var(--bg-card))}
.canary-card.tripped:hover{background:color-mix(in srgb,var(--danger-fill) 14%,var(--bg-card))}
.canary-card.tripped .card-title svg{color:var(--danger)}
.canary-card.armed .card-title svg{color:var(--warning)}
.canary-list{display:flex;flex-direction:column;gap:6px;list-style:none;max-height:240px;overflow-y:auto}
.canary-item{display:flex;align-items:center;gap:8px;font-size:.82rem;min-width:0}
.canary-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0;background:var(--warning);animation:pulse 2s ease-in-out infinite}
.canary-item.tripped .canary-dot{background:var(--danger)}
.canary-state{color:var(--warning);font-weight:500}
.canary-key{font-family:var(--font-mono);color:var(--text-primary);flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.canary-meta{font-family:var(--font-mono);font-size:.72rem;color:var(--text-dim);white-space:nowrap}
.canary-trip{display:flex;flex-direction:column;gap:2px;padding:8px 0 10px;border-bottom:1px solid color-mix(in srgb,var(--danger) 30%,transparent);margin-bottom:10px}
.canary-trip-by{color:var(--danger);font-weight:600;font-size:.9rem}
.canary-trip-detail{font-size:.78rem;color:var(--text-primary)}
.canary-trip-detail code{color:var(--text-primary)}

/* Agent sessions */
.sessions-list{display:flex;flex-direction:column;gap:6px;max-height:420px;overflow-y:auto}
.session{background:var(--bg-deep);border:1px solid var(--border);border-radius:var(--radius-sm);min-width:0}
.session.open{border-color:color-mix(in srgb,var(--accent) 50%,transparent)}
.session-row{display:flex;align-items:center;gap:8px;width:100%;padding:6px 10px;background:none;border:0;color:inherit;font:inherit;font-family:var(--font-mono);font-size:.8rem;text-align:left;cursor:pointer;min-width:0;border-radius:var(--radius-sm)}
.session-row:hover{background:var(--bg-card-hover)}
.session-caret{color:var(--text-dim);width:10px}
.session-agent{color:var(--accent-bright);font-weight:600;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.session-wrap{color:var(--text-secondary);max-width:28ch;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.session-meta{flex:1;min-width:0;color:var(--text-dim);font-size:.74rem;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.session-denials{font-size:.7rem;padding:0 8px;border-radius:999px;white-space:nowrap;color:var(--success);background:color-mix(in srgb,var(--success) 10%,transparent);border:1px solid color-mix(in srgb,var(--success) 40%,transparent)}
.session-denials.bad{color:var(--danger);background:color-mix(in srgb,var(--danger-fill) 12%,transparent);border-color:color-mix(in srgb,var(--danger) 50%,transparent)}
.session-detail{padding:6px 10px 10px;border-top:1px solid var(--border)}
.session-keys{color:var(--text-secondary);font-family:var(--font-mono);font-size:.74rem;padding:4px 0 6px;overflow-wrap:anywhere}

/* Secrets table */
.secrets-toolbar{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px;align-items:center}
.search{flex:1;min-width:180px;display:flex;align-items:center;gap:8px;background:var(--bg-deep);border:1px solid var(--border);border-radius:var(--radius-sm);padding:6px 10px;transition:border-color var(--motion-fast) var(--motion-ease)}
.search:focus-within{border-color:var(--accent);box-shadow:0 0 0 2px var(--accent-dim)}
.search svg{width:13px;height:13px;color:var(--text-dim);flex-shrink:0}
.search input{flex:1;min-width:0;background:transparent;border:none;outline:none;color:var(--text-primary);font-family:var(--font-mono);font-size:.82rem}
.search input::placeholder{color:var(--text-dim)}
.secrets-table-wrap{max-height:380px;overflow:auto;border:1px solid var(--border);border-radius:var(--radius-sm);background:var(--bg-deep);-webkit-overflow-scrolling:touch}
.secrets-table{width:100%;border-collapse:collapse;font-family:var(--font-mono);font-size:.78rem}
.secrets-table thead th{position:sticky;top:0;background:var(--bg-section);text-align:left;padding:8px 10px;color:var(--text-dim);font-family:var(--font-display);font-weight:600;font-size:.68rem;text-transform:uppercase;letter-spacing:.08em;border-bottom:1px solid var(--border);cursor:pointer;user-select:none;white-space:nowrap}
.secrets-table thead th:hover{color:var(--text-primary)}
.secrets-table thead th .sort-arrow{display:inline-block;margin-left:4px;color:var(--accent);opacity:0;font-size:.7rem}
.secrets-table thead th.sorted{color:var(--text-secondary)}
.secrets-table thead th.sorted .sort-arrow{opacity:1}
.secrets-table tbody td{padding:7px 10px;border-bottom:1px solid var(--separator);color:var(--text-secondary);vertical-align:middle;white-space:nowrap}
.secrets-table tbody tr:last-child td{border-bottom:0}
.secrets-table tbody tr:hover td{background:var(--bg-card-hover);color:var(--text-primary)}
.secrets-table .col-key{color:var(--text-primary);font-weight:500;max-width:240px;overflow:hidden;text-overflow:ellipsis}
.secrets-table .col-decay{min-width:110px}
.secrets-table .col-tags{max-width:200px;overflow:hidden}
.tag-pill{display:inline-block;font-size:.68rem;padding:0 7px;color:var(--brand-text);background:var(--brand-dim);border:1px solid color-mix(in srgb,var(--brand-text) 30%,transparent);border-radius:999px;margin-right:3px;font-family:var(--font-mono)}
.scope-tag{display:inline-block;font-size:.66rem;padding:0 7px;border-radius:var(--radius-xs);letter-spacing:.06em;font-weight:600;text-transform:uppercase;border:1px solid transparent}
.scope-tag.global{background:var(--accent-dim);color:var(--accent-bright)}
.scope-tag.project{background:color-mix(in srgb,var(--success) 12%,transparent);color:var(--success)}
.scope-tag.team{background:var(--brand-dim);color:var(--brand-text)}
.scope-tag.org{background:color-mix(in srgb,var(--warning) 12%,transparent);color:var(--warning)}
.type-tag{display:inline-block;font-size:.66rem;padding:0 7px;border-radius:var(--radius-xs);letter-spacing:.06em;text-transform:uppercase;background:var(--segment);color:var(--text-secondary)}
.type-tag.superposition{background:var(--brand-dim);color:var(--brand-text)}
.protected-icon{color:var(--warning);margin-left:4px;display:inline-flex;vertical-align:middle}
.protected-icon svg{width:12px;height:12px}
.mini-decay{display:inline-flex;align-items:center;gap:6px;width:100%}
.mini-decay-bar{flex:1;height:4px;border-radius:2px;background:var(--segment);overflow:hidden;min-width:30px}
.mini-decay-fill{height:100%;border-radius:2px;transition:width var(--motion-base) var(--motion-ease)}
.mini-decay-time{color:var(--text-dim);font-size:.7rem;min-width:38px;text-align:right}

/* Empty states */
.empty{color:var(--text-secondary);font-size:.86rem;padding:6px 0}
.empty-cta{margin-top:8px;display:block;font-family:var(--font-mono);font-size:.78rem;color:var(--accent);overflow-wrap:anywhere}
.empty-cta code{color:var(--accent)}

/* Footer */
.foot{margin-top:24px;text-align:center;color:var(--text-dim);font-size:.74rem;font-family:var(--font-mono);line-height:2}
.foot a{color:var(--accent-bright);text-decoration:none}
.foot a:hover{text-decoration:underline}

/* Scrollbar */
*{scrollbar-width:thin;scrollbar-color:var(--border) transparent}
::-webkit-scrollbar{width:6px;height:6px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--border);border-radius:3px}
::-webkit-scrollbar-thumb:hover{background:var(--text-dim)}

/* Tablet and down: one column, KPI tiles two per row, header wraps */
@media (max-width:768px){
  .container{padding:12px 14px 40px}
  .header{position:static;padding:12px 14px}
  .header-left,.header-right{width:100%}
  .meta-chip{max-width:100%}
  .grid{grid-template-columns:minmax(0,1fr)}
  .kpi-strip{grid-template-columns:repeat(2,minmax(0,1fr))}
  .card{padding:16px}
  .card-title .title-aside{margin-left:0;width:100%}
}

/* Phone: tighter gutters; the table scrolls inside its card */
@media (max-width:480px){
  .container{padding:10px 10px 32px}
  .header h1{font-size:1.2rem}
  .header h1 .sub{font-size:.9rem}
  .btn{padding:5px 10px}
  .kpi{padding:10px 12px}
  .kpi-value{font-size:1.25rem}
  .card{padding:14px 12px}
  .search{min-width:0;flex-basis:100%}
  .secrets-table{min-width:640px}
  .audit-row{grid-template-columns:auto auto minmax(0,1fr);row-gap:2px}
  .audit-row .audit-line{grid-column:1/-1}
  .audit-row .audit-source{justify-self:end}
  .rotation-every{display:none}
  .policy-label{white-space:normal}
}

@media (prefers-reduced-motion:reduce){
  *,*::before,*::after{animation:none!important;transition:none!important;scroll-behavior:auto!important}
}

/* Print */
@media print{
  .header-right{display:none}
  .header{position:static}
}
</style>
</head>
<body>

<!-- Brand gradient (cyan to violet), used by the brand mark only -->
<svg class="svg-defs" aria-hidden="true" focusable="false">
  <defs>
    <linearGradient id="neon-grad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" class="grad-start"/>
      <stop offset="100%" class="grad-end"/>
    </linearGradient>
  </defs>
</svg>

<!-- Preact mounts the entire UI here; see src/dashboard-client/main.js -->
<div id="app"></div>

<script>window.__QRING__=Object.freeze(${config});</script>
<script>${DASHBOARD_CLIENT}</script>
</body>
</html>`;
}
