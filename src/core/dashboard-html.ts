/**
 * Self-contained HTML dashboard for q-ring quantum status.
 *
 * Matches the gh-pages site design system: deep-navy palette, neon cyan→violet
 * SVG icons, glassmorphism cards. The page is fully self-contained and offline:
 * inline CSS plus an inlined Preact + htm client bundle (see DASHBOARD_CLIENT,
 * generated from src/dashboard-client/main.js). Rendering is VDOM-diffed so the
 * SSE stream updates data in place — entrance animations run once on mount
 * instead of replaying on every tick.
 *
 * Layout:
 *   1. Sticky header with brand, version, project path, live/paused state,
 *      pause+refresh controls, last-update timestamp.
 *   2. KPI strip — at-a-glance counters (total, healthy, stale/expired,
 *      protected, hooks, approvals, anomalies, audit-24h).
 *   3. Health donut + Environment + Manifest + Policy summary cards.
 *   4. Searchable + sortable secrets table (key, scope, env, type, decay,
 *      tags, last accessed).
 *   5. Quantum side panels — Decay, Superposition, Entanglement, Tunnels.
 *   6. Governance — Approvals, Hooks, Memory.
 *   7. Anomalies (full-width).
 *   8. Audit log with action+source+text filters and an action-count strip.
 */

import { DASHBOARD_CLIENT } from "./dashboard-client.js";

/** Escape a value for safe embedding inside an inline <script> string literal. */
function jsString(value: string): string {
  return JSON.stringify(value).replace(/</g, "\\u003c");
}

export function getDashboardHtml(token: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>q-ring — quantum status</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg-deep:#04080f;
  --bg-section:#080e18;
  --bg-card:#0f1a2e;
  --bg-card-hover:#142240;
  --border:#1a2d4a;
  --border-glow:#0ea5e9;

  --text-primary:#f8f8ff;
  --text-secondary:#c8cfe0;
  --text-dim:#8899b4;

  --accent:#0ea5e9;
  --accent-bright:#38bdf8;
  --accent-dim:rgba(14,165,233,0.15);
  --accent-glow:rgba(14,165,233,0.4);

  --danger:#ff5e5b;
  --warning:#fbbf24;
  --green:#22c55e;
  --violet:#a855f7;
  --pink:#ff0055;

  --font-display:system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;
  --font-mono:'SF Mono','Cascadia Code','Fira Code',Consolas,'Liberation Mono',monospace;

  --radius:12px;
  --radius-sm:8px;
  --radius-lg:20px;

  --glass-bg:rgba(15,26,46,0.65);
  --glass-border:rgba(26,45,74,0.8);
  --shadow-card:0 4px 24px -1px rgba(0,0,0,0.4),0 0 1px rgba(255,255,255,0.04);
  --shadow-glow:0 0 20px rgba(14,165,233,0.12),0 0 40px rgba(168,85,247,0.08);
}
html{background:var(--bg-deep);color:var(--text-primary);font-family:var(--font-display);font-size:16px;line-height:1.5}
body{min-height:100vh;overflow-x:hidden;position:relative}

/* Hidden SVG defs for gradient icons */
.svg-defs{position:absolute;width:0;height:0;overflow:hidden}

/* Mesh blobs */
.blob{position:fixed;border-radius:50%;filter:blur(100px);opacity:.12;pointer-events:none;z-index:0}
.blob-1{width:600px;height:600px;top:-120px;left:-100px;background:radial-gradient(circle,var(--accent),transparent 70%);animation:drift1 22s ease-in-out infinite}
.blob-2{width:500px;height:500px;bottom:-80px;right:-60px;background:radial-gradient(circle,var(--violet),transparent 70%);animation:drift2 26s ease-in-out infinite}
.blob-3{width:350px;height:350px;top:40%;left:50%;background:radial-gradient(circle,var(--green),transparent 70%);animation:drift3 30s ease-in-out infinite;opacity:.06}
@keyframes drift1{0%,100%{transform:translate(0,0) scale(1)}33%{transform:translate(60px,-40px) scale(1.08)}66%{transform:translate(-30px,50px) scale(.95)}}
@keyframes drift2{0%,100%{transform:translate(0,0) scale(1)}33%{transform:translate(-50px,30px) scale(1.05)}66%{transform:translate(40px,-60px) scale(.92)}}
@keyframes drift3{0%,100%{transform:translate(-50%,-50%) scale(1)}50%{transform:translate(-40%,-60%) scale(1.1)}}

.container{position:relative;z-index:1;max-width:1320px;margin:0 auto;padding:20px 20px 48px}

/* Header */
.header{position:sticky;top:0;z-index:5;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:14px;margin-bottom:20px;padding:14px 18px;background:rgba(4,8,15,0.85);backdrop-filter:blur(16px) saturate(1.2);-webkit-backdrop-filter:blur(16px) saturate(1.2);border:1px solid var(--border);border-radius:var(--radius)}
.header-left{display:flex;align-items:center;gap:14px;flex-wrap:wrap;min-width:0}
.header h1{font-family:var(--font-display);font-size:1.45rem;font-weight:700;letter-spacing:-.02em;display:flex;align-items:center;gap:10px}
.header h1 .q-icon{display:flex;filter:drop-shadow(0 0 6px rgba(14,165,233,0.6))}
.header h1 .brand{background:linear-gradient(135deg,#00D1FF,var(--violet));-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent}
.header h1 .sub{color:var(--text-dim);font-weight:400;font-size:1rem;-webkit-text-fill-color:var(--text-dim)}
.meta-chip{font-family:var(--font-mono);font-size:.72rem;color:var(--text-dim);background:rgba(255,255,255,.04);border:1px solid var(--border);padding:3px 8px;border-radius:99px;display:inline-flex;align-items:center;gap:6px;max-width:340px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.meta-chip svg{width:11px;height:11px;flex-shrink:0;opacity:.7}
.header-right{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.status-dot{width:8px;height:8px;border-radius:50%;background:var(--green);box-shadow:0 0 8px var(--green);display:inline-block;animation:pulse 2s ease-in-out infinite}
.status-dot.disconnected{background:var(--danger);box-shadow:0 0 8px var(--danger);animation:none}
.status-dot.paused{background:var(--warning);box-shadow:0 0 8px var(--warning);animation:none}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
.conn-label{font-size:.78rem;color:var(--text-dim);display:flex;align-items:center;gap:6px;font-family:var(--font-mono)}
.btn{font-family:var(--font-display);font-size:.78rem;font-weight:500;color:var(--text-secondary);background:rgba(255,255,255,.04);border:1px solid var(--border);padding:5px 11px;border-radius:var(--radius-sm);cursor:pointer;display:inline-flex;align-items:center;gap:5px;transition:background .2s,border-color .2s,color .2s}
.btn:hover{background:rgba(14,165,233,.08);border-color:var(--accent);color:var(--text-primary)}
.btn svg{width:13px;height:13px}
.btn.active{background:var(--accent-dim);color:var(--accent-bright);border-color:rgba(14,165,233,.4)}
.kbd{font-family:var(--font-mono);font-size:.65rem;color:var(--text-dim);background:rgba(255,255,255,.06);border:1px solid var(--border);border-bottom-width:2px;padding:1px 5px;border-radius:4px;margin-left:4px}

/* KPI strip */
.kpi-strip{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px;margin-bottom:20px}
.kpi{background:var(--glass-bg);backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);border:1px solid var(--glass-border);border-radius:var(--radius);padding:12px 14px;display:flex;flex-direction:column;gap:2px;transition:border-color .25s,transform .25s}
.kpi:hover{border-color:var(--border-glow);transform:translateY(-2px)}
.kpi-label{font-size:.66rem;text-transform:uppercase;letter-spacing:.1em;color:var(--text-dim);font-weight:600;display:flex;align-items:center;gap:6px}
.kpi-label svg{width:12px;height:12px;flex-shrink:0}
.kpi-value{font-family:var(--font-display);font-size:1.5rem;font-weight:700;line-height:1.1;color:var(--text-primary)}
.kpi-value.warning{color:var(--warning)}
.kpi-value.danger{color:var(--danger)}
.kpi-value.green{color:var(--green)}
.kpi-value.dim{color:var(--text-dim)}
.kpi-sub{font-size:.7rem;color:var(--text-dim);font-family:var(--font-mono)}

/* Grid */
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(360px,1fr));gap:16px;margin-bottom:16px}
.grid-wide{grid-column:1/-1}

/* Cards — reveal animation */
.card{background:var(--glass-bg);backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);border:1px solid var(--glass-border);border-radius:var(--radius);padding:18px 20px;box-shadow:var(--shadow-card);transition:border-color .3s,box-shadow .3s,transform .3s;opacity:0;transform:translateY(16px);animation:cardReveal .5s cubic-bezier(0.16,1,0.3,1) forwards}
.card:hover{border-color:var(--border-glow);box-shadow:var(--shadow-card),var(--shadow-glow)}
@keyframes cardReveal{to{opacity:1;transform:translateY(0)}}

.card-title{font-family:var(--font-display);font-size:.78rem;text-transform:uppercase;letter-spacing:.1em;color:var(--text-dim);margin-bottom:14px;display:flex;align-items:center;gap:8px;font-weight:600}
.card-title svg{width:16px;height:16px;flex-shrink:0;filter:drop-shadow(0 0 4px rgba(14,165,233,0.4))}
.card-title .title-aside{margin-left:auto;font-size:.7rem;color:var(--text-dim);font-weight:400;letter-spacing:.04em;text-transform:none;display:flex;align-items:center;gap:6px}

/* Health donut */
.health-row{display:flex;align-items:center;gap:24px}
.donut-wrap{position:relative;width:100px;height:100px;flex-shrink:0}
.donut-wrap svg{transform:rotate(-90deg)}
.donut-wrap .donut-label{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;flex-direction:column;font-size:1.5rem;font-weight:700;line-height:1;font-family:var(--font-display)}
.donut-wrap .donut-label small{font-size:.7rem;color:var(--text-dim);font-weight:400;margin-top:2px;letter-spacing:.04em}
.health-legend{display:flex;flex-direction:column;gap:6px;font-family:var(--font-mono)}
.legend-item{display:flex;align-items:center;gap:8px;font-size:.82rem}
.legend-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}
.scope-row{display:flex;gap:6px;margin-top:14px;flex-wrap:wrap;font-family:var(--font-mono);font-size:.72rem;color:var(--text-dim)}
.scope-pill{padding:2px 8px;border-radius:99px;background:rgba(255,255,255,.04);border:1px solid var(--border)}
.scope-pill strong{color:var(--text-primary);margin-right:4px;font-weight:600}

/* Decay bars */
.decay-list{display:flex;flex-direction:column;gap:8px;max-height:280px;overflow-y:auto}
.decay-item{display:flex;align-items:center;gap:10px}
.decay-key{font-family:var(--font-mono);font-size:.85rem;min-width:120px;max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.decay-bar{flex:1;height:6px;border-radius:3px;background:rgba(255,255,255,0.06);overflow:hidden;position:relative}
.decay-fill{height:100%;border-radius:3px;transition:width .6s ease}
.decay-time{font-size:.8rem;color:var(--text-dim);min-width:60px;text-align:right;font-family:var(--font-mono)}

/* Superposition pills */
.super-list{display:flex;flex-direction:column;gap:8px;max-height:280px;overflow-y:auto}
.super-item{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.super-key{font-family:var(--font-mono);font-size:.85rem;min-width:100px}
.env-pill{font-size:.72rem;padding:2px 8px;border-radius:99px;font-weight:600;letter-spacing:.03em;font-family:var(--font-mono)}
.env-prod{background:rgba(255,0,85,0.2);color:var(--pink);border:1px solid rgba(255,0,85,0.3)}
.env-staging{background:rgba(251,191,36,0.15);color:var(--warning);border:1px solid rgba(251,191,36,0.25)}
.env-dev{background:rgba(34,197,94,0.15);color:var(--green);border:1px solid rgba(34,197,94,0.25)}
.env-default{background:rgba(168,85,247,0.15);color:var(--violet);border:1px solid rgba(168,85,247,0.25)}
.env-test{background:rgba(14,165,233,0.15);color:var(--accent-bright);border:1px solid rgba(14,165,233,0.25)}

/* Entanglement */
.entangle-list{display:flex;flex-direction:column;gap:6px;max-height:240px;overflow-y:auto}
.entangle-pair{display:flex;align-items:center;gap:8px;font-family:var(--font-mono);font-size:.83rem}
.entangle-arrow{color:var(--accent-bright)}
.entangle-graph{display:block;width:100%;height:auto;max-height:260px}
.entangle-edge{stroke:var(--accent);stroke-opacity:.45;stroke-width:1.2}
.entangle-node{fill:var(--accent-bright);stroke:var(--accent-glow);stroke-width:3;paint-order:stroke}
.entangle-label{fill:var(--text-secondary);font-family:var(--font-mono);font-size:9px}

/* Audit chain badge */
.chain-badge{display:inline-flex;align-items:center;gap:6px;font-family:var(--font-mono);font-size:.78rem;padding:4px 10px;border-radius:999px;margin-bottom:10px}
.chain-badge.ok{color:var(--green);background:rgba(34,197,94,.1);border:1px solid rgba(34,197,94,.25)}
.chain-badge.broken{color:var(--danger);background:rgba(255,94,91,.12);border:1px solid rgba(255,94,91,.3)}

/* Tunnels */
.tunnel-list{display:flex;flex-direction:column;gap:8px;max-height:240px;overflow-y:auto}
.tunnel-card{background:rgba(168,85,247,0.06);border:1px solid rgba(168,85,247,0.15);border-radius:var(--radius-sm);padding:10px 12px;font-size:.83rem;font-family:var(--font-mono)}
.tunnel-meta{display:flex;gap:12px;margin-top:4px;font-size:.78rem;color:var(--text-dim)}

/* Audit feed */
.audit-toolbar{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:10px;align-items:center}
.audit-actions-strip{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:10px}
.audit-chip{font-family:var(--font-mono);font-size:.7rem;padding:2px 9px;border-radius:99px;background:rgba(255,255,255,.04);border:1px solid var(--border);color:var(--text-secondary);cursor:pointer;transition:all .2s}
.audit-chip:hover{border-color:var(--accent);color:var(--text-primary)}
.audit-chip.active{background:var(--accent-dim);color:var(--accent-bright);border-color:rgba(14,165,233,.4)}
.audit-chip strong{color:var(--text-primary);margin-left:5px;font-weight:600}
.audit-feed{display:flex;flex-direction:column;gap:2px;max-height:340px;overflow-y:auto;font-size:.82rem;font-family:var(--font-mono)}
.audit-row{display:grid;grid-template-columns:78px 76px 56px 1fr;gap:8px;padding:4px 0;border-bottom:1px solid rgba(255,255,255,0.03);align-items:baseline}
.audit-ts{color:var(--text-dim)}
.audit-action{font-weight:600}
.audit-action.read{color:var(--accent)}.audit-action.write{color:var(--green)}.audit-action.delete{color:var(--danger)}
.audit-action.entangle{color:var(--violet)}.audit-action.tunnel{color:var(--violet)}.audit-action.teleport{color:var(--warning)}
.audit-action.generate{color:var(--warning)}.audit-action.list{color:var(--text-dim)}.audit-action.export{color:var(--text-dim)}
.audit-action.collapse{color:var(--accent)}.audit-action.approve{color:var(--green)}.audit-action.revoke{color:var(--danger)}
.audit-action.policy_deny{color:var(--danger)}.audit-action.rotate{color:var(--violet)}
.audit-source{color:var(--text-dim);font-size:.72rem;text-transform:uppercase;letter-spacing:.04em}
.audit-detail{color:var(--text-dim);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.audit-key{color:var(--text-secondary)}

/* Anomalies */
.anomaly-list{display:flex;flex-direction:column;gap:8px}
.anomaly-card{background:rgba(255,94,91,0.06);border:1px solid rgba(255,94,91,0.15);border-radius:var(--radius-sm);padding:10px 14px;animation:anomaly-pulse 3s ease-in-out infinite}
@keyframes anomaly-pulse{0%,100%{border-color:rgba(255,94,91,0.15)}50%{border-color:rgba(255,94,91,0.4)}}
.anomaly-type{font-size:.7rem;text-transform:uppercase;letter-spacing:.06em;color:var(--danger);font-weight:700;margin-bottom:2px;font-family:var(--font-display)}
.anomaly-desc{font-size:.86rem;color:var(--text-primary)}
.anomaly-hint{font-size:.74rem;color:var(--text-dim);margin-top:4px;font-family:var(--font-mono)}

/* Environment badge */
.env-status{display:flex;align-items:center;gap:12px;flex-wrap:wrap}
.env-big{font-size:1rem;font-weight:700;padding:4px 14px;border-radius:var(--radius-sm)}
.env-source{font-size:.78rem;color:var(--text-dim);font-family:var(--font-mono)}

/* Manifest */
.manifest-bars{display:flex;flex-direction:column;gap:8px}
.manifest-row{display:flex;align-items:center;gap:8px;font-family:var(--font-mono);font-size:.78rem}
.manifest-bar{flex:1;height:6px;border-radius:3px;background:rgba(255,255,255,.06);overflow:hidden}
.manifest-fill{height:100%;border-radius:3px}
.manifest-list{margin-top:10px;display:flex;flex-direction:column;gap:3px;font-family:var(--font-mono);font-size:.78rem;color:var(--text-secondary)}
.manifest-list .label{color:var(--text-dim);text-transform:uppercase;font-size:.66rem;letter-spacing:.08em;margin-top:6px}
.manifest-list .key-pill{display:inline-block;padding:1px 6px;background:rgba(255,255,255,.04);border:1px solid var(--border);border-radius:4px;margin:1px 3px 1px 0;font-size:.74rem}
.manifest-list .key-pill.miss{color:var(--danger);border-color:rgba(255,94,91,.3)}
.manifest-list .key-pill.exp{color:var(--warning);border-color:rgba(251,191,36,.3)}

/* Policy */
.policy-rows{display:flex;flex-direction:column;gap:6px;font-family:var(--font-mono);font-size:.78rem;color:var(--text-secondary)}
.policy-row{display:flex;justify-content:space-between;padding:2px 0;border-bottom:1px solid rgba(255,255,255,.04)}
.policy-label{color:var(--text-dim)}
.policy-value{color:var(--text-primary)}
.policy-value.zero{color:var(--text-dim)}

/* Approvals */
.approval-list{display:flex;flex-direction:column;gap:8px;max-height:240px;overflow-y:auto}
.approval-card{background:rgba(34,197,94,.05);border:1px solid rgba(34,197,94,.2);border-radius:var(--radius-sm);padding:10px 12px;font-size:.82rem}
.approval-card.tampered{background:rgba(255,94,91,.06);border-color:rgba(255,94,91,.4)}
.approval-card.expiring{background:rgba(251,191,36,.06);border-color:rgba(251,191,36,.3)}
.approval-head{display:flex;justify-content:space-between;gap:8px;font-family:var(--font-mono);font-weight:600}
.approval-reason{color:var(--text-dim);font-size:.76rem;margin-top:3px}
.approval-meta{display:flex;gap:12px;margin-top:4px;font-size:.72rem;color:var(--text-dim);font-family:var(--font-mono)}

/* Hooks */
.hooks-list{display:flex;flex-direction:column;gap:6px;max-height:240px;overflow-y:auto}
.hook-row{display:flex;align-items:center;gap:8px;font-family:var(--font-mono);font-size:.8rem;padding:6px 10px;background:rgba(255,255,255,.03);border:1px solid var(--border);border-radius:var(--radius-sm)}
.hook-row.disabled{opacity:.5}
.hook-type{font-size:.7rem;text-transform:uppercase;font-weight:600;padding:1px 6px;border-radius:99px;letter-spacing:.04em}
.hook-type.shell{background:rgba(168,85,247,.15);color:var(--violet)}
.hook-type.http{background:rgba(14,165,233,.15);color:var(--accent-bright)}
.hook-type.signal{background:rgba(251,191,36,.15);color:var(--warning)}
.hook-summary{flex:1;color:var(--text-secondary);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.hook-id{color:var(--text-dim);font-size:.72rem}

/* Agent sessions */
.sessions-list{display:flex;flex-direction:column;gap:6px;max-height:420px;overflow-y:auto}
.session{background:rgba(255,255,255,.03);border:1px solid var(--border);border-radius:var(--radius-sm)}
.session.open{border-color:rgba(14,165,233,.35)}
.session-row{display:flex;align-items:center;gap:8px;width:100%;padding:6px 10px;background:none;border:0;color:inherit;font:inherit;font-family:var(--font-mono);font-size:.8rem;text-align:left;cursor:pointer}
.session-row:hover{background:rgba(255,255,255,.03)}
.session-caret{color:var(--text-dim);width:10px}
.session-agent{color:var(--accent-bright);font-weight:600}
.session-wrap{color:var(--text-secondary);max-width:28ch;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.session-meta{flex:1;color:var(--text-dim);font-size:.74rem;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.session-denials{font-size:.7rem;padding:1px 6px;border-radius:99px;background:rgba(34,197,94,.1);color:var(--green)}
.session-denials.bad{background:rgba(255,94,91,.12);color:var(--danger)}
.session-detail{padding:4px 10px 8px 28px;border-top:1px solid var(--border)}
.session-keys{color:var(--text-secondary);font-family:var(--font-mono);font-size:.74rem;padding:4px 0 6px}

/* Secrets table */
.secrets-toolbar{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px;align-items:center}
.search{flex:1;min-width:180px;display:flex;align-items:center;gap:6px;background:rgba(255,255,255,.04);border:1px solid var(--border);border-radius:var(--radius-sm);padding:5px 10px;transition:border-color .2s}
.search:focus-within{border-color:var(--accent);box-shadow:0 0 0 3px rgba(14,165,233,.12)}
.search svg{width:13px;height:13px;color:var(--text-dim);flex-shrink:0}
.search input{flex:1;background:transparent;border:none;outline:none;color:var(--text-primary);font-family:var(--font-mono);font-size:.82rem}
.search input::placeholder{color:var(--text-dim)}
.secrets-table-wrap{max-height:380px;overflow:auto;border:1px solid var(--border);border-radius:var(--radius-sm);background:rgba(4,8,15,.4)}
.secrets-table{width:100%;border-collapse:collapse;font-family:var(--font-mono);font-size:.78rem}
.secrets-table thead th{position:sticky;top:0;background:rgba(8,14,24,.95);backdrop-filter:blur(8px);text-align:left;padding:8px 10px;color:var(--text-dim);font-weight:600;font-size:.7rem;text-transform:uppercase;letter-spacing:.05em;border-bottom:1px solid var(--border);cursor:pointer;user-select:none;white-space:nowrap}
.secrets-table thead th:hover{color:var(--text-primary)}
.secrets-table thead th .sort-arrow{display:inline-block;margin-left:4px;color:var(--accent-bright);opacity:0;font-size:.7rem}
.secrets-table thead th.sorted .sort-arrow{opacity:1}
.secrets-table tbody td{padding:6px 10px;border-bottom:1px solid rgba(255,255,255,.03);color:var(--text-secondary);vertical-align:middle}
.secrets-table tbody tr:hover td{background:rgba(14,165,233,.05);color:var(--text-primary)}
.secrets-table .col-key{color:var(--text-primary);font-weight:500;max-width:240px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.secrets-table .col-decay{min-width:90px}
.secrets-table .col-tags{max-width:200px;overflow:hidden}
.tag-pill{display:inline-block;font-size:.68rem;padding:1px 6px;background:rgba(168,85,247,.1);color:var(--violet);border:1px solid rgba(168,85,247,.2);border-radius:99px;margin-right:3px;font-family:var(--font-mono)}
.scope-tag{display:inline-block;font-size:.68rem;padding:1px 6px;border-radius:4px;letter-spacing:.04em;font-weight:600;text-transform:uppercase}
.scope-tag.global{background:rgba(14,165,233,.15);color:var(--accent-bright)}
.scope-tag.project{background:rgba(34,197,94,.15);color:var(--green)}
.scope-tag.team{background:rgba(168,85,247,.15);color:var(--violet)}
.scope-tag.org{background:rgba(251,191,36,.15);color:var(--warning)}
.type-tag{display:inline-block;font-size:.68rem;padding:1px 6px;border-radius:4px;letter-spacing:.04em;text-transform:uppercase;background:rgba(255,255,255,.05);color:var(--text-dim)}
.type-tag.superposition{background:rgba(168,85,247,.12);color:var(--violet)}
.protected-icon{color:var(--warning);margin-left:4px;display:inline-flex;vertical-align:middle}
.mini-decay{display:inline-flex;align-items:center;gap:6px;width:100%}
.mini-decay-bar{flex:1;height:4px;border-radius:2px;background:rgba(255,255,255,.06);overflow:hidden;min-width:30px}
.mini-decay-fill{height:100%;border-radius:2px}
.mini-decay-time{color:var(--text-dim);font-size:.7rem;min-width:38px;text-align:right}

/* Empty states */
.empty{color:var(--text-dim);font-size:.86rem;font-style:italic;padding:8px 0}
.empty-cta{margin-top:6px;display:block;font-style:normal;font-family:var(--font-mono);font-size:.78rem;color:var(--accent-bright)}

/* Footer */
.foot{margin-top:24px;text-align:center;color:var(--text-dim);font-size:.72rem;font-family:var(--font-mono)}
.foot a{color:var(--accent-bright);text-decoration:none}
.foot a:hover{text-decoration:underline}

/* Scrollbar */
::-webkit-scrollbar{width:6px;height:6px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:rgba(255,255,255,0.08);border-radius:3px}
::-webkit-scrollbar-thumb:hover{background:rgba(255,255,255,0.15)}

/* Print */
@media print{
  .blob,.header-right{display:none}
  .header{position:static}
  body{background:#fff;color:#000}
}
</style>
</head>
<body>

<!-- Shared SVG gradient definition (referenced by the neon icons) -->
<svg class="svg-defs" aria-hidden="true" focusable="false">
  <defs>
    <linearGradient id="neon-grad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#00D1FF"/>
      <stop offset="100%" stop-color="#a855f7"/>
    </linearGradient>
  </defs>
</svg>

<div class="blob blob-1"></div>
<div class="blob blob-2"></div>
<div class="blob blob-3"></div>

<!-- Preact mounts the entire UI here; see src/dashboard-client/main.js -->
<div id="app"></div>

<script>window.__QRING__=Object.freeze({token:${jsString(token)}});</script>
<script>${DASHBOARD_CLIENT}</script>
</body>
</html>`;
}
