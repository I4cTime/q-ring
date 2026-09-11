/**
 * q-ring status dashboard — browser client (Preact + htm).
 *
 * Bundled into `src/core/dashboard-client.ts` by scripts/build-dashboard-client.mjs
 * and inlined into the served HTML. Reads its auth token from window.__QRING__.
 *
 * Rendering is component + VDOM based: the SSE stream only updates the data,
 * Preact diffs the DOM, so entrance animations (.card cardReveal) run once on
 * mount and the page no longer "reloads" on every 5s tick. Input focus/caret
 * and scroll positions are preserved automatically because DOM nodes persist.
 */
import { h, render } from "preact";
import { useState, useEffect, useRef, useMemo, useCallback } from "preact/hooks";
import htm from "htm";

const html = htm.bind(h);

const TOKEN = (window.__QRING__ && window.__QRING__.token) || "";
const Q = TOKEN ? "?token=" + encodeURIComponent(TOKEN) : "";

/* --- SVG icon library (neon gradient via #neon-grad in the page) --- */
const ic = (path) =>
  '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="url(#neon-grad)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">' +
  path +
  "</svg>";
const icons = {
  health: ic('<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>'),
  environment: ic('<polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>'),
  decay: ic('<path d="M5 22h14"/><path d="M5 2h14"/><path d="M17 22v-4.172a2 2 0 0 0-.586-1.414L12 12l-4.414 4.414A2 2 0 0 0 7 17.828V22"/><path d="M7 2v4.172a2 2 0 0 0 .586 1.414L12 12l4.414-4.414A2 2 0 0 0 17 6.172V2"/>'),
  superposition: ic('<polygon points="12 2 2 7 12 12 22 7 12 2"/><polyline points="2 17 12 22 22 17"/><polyline points="2 12 12 17 22 12"/>'),
  entangle: ic('<path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>'),
  tunnel: ic('<path d="M9 10h.01"/><path d="M15 10h.01"/><path d="M12 2a8 8 0 0 0-8 8v12l3-3 2.5 2.5L12 19l2.5 2.5L17 19l3 3V10a8 8 0 0 0-8-8z"/>'),
  anomaly: ic('<path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>'),
  audit: ic('<circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/>'),
  key: ic('<path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/>'),
  hook: ic('<path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>'),
  approve: ic('<path d="M9 11l3 3L22 4"/><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/>'),
  manifest: ic('<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/>'),
  policy: ic('<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/>'),
  memory: ic('<rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/><line x1="9" y1="2" x2="9" y2="4"/><line x1="15" y1="2" x2="15" y2="4"/><line x1="9" y1="20" x2="9" y2="22"/><line x1="15" y1="20" x2="15" y2="22"/><line x1="20" y1="9" x2="22" y2="9"/><line x1="20" y1="14" x2="22" y2="14"/><line x1="2" y1="9" x2="4" y2="9"/><line x1="2" y1="14" x2="4" y2="14"/>'),
  folder: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>',
  search: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>',
  lock: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>',
};

/* --- Formatters --- */
function envClass(e) {
  if (!e) return "env-default";
  const k = e.toLowerCase();
  if (k === "prod" || k === "production") return "env-prod";
  if (k === "staging" || k === "stage") return "env-staging";
  if (k === "dev" || k === "development") return "env-dev";
  if (k === "test" || k === "testing") return "env-test";
  return "env-default";
}
function decayColor(pct, expired) {
  if (expired) return "var(--danger)";
  if (pct >= 90) return "var(--danger)";
  if (pct >= 75) return "var(--warning)";
  return "var(--accent)";
}
function fmtTime(ts) {
  const d = new Date(ts);
  return (
    String(d.getHours()).padStart(2, "0") + ":" +
    String(d.getMinutes()).padStart(2, "0") + ":" +
    String(d.getSeconds()).padStart(2, "0")
  );
}
function fmtRelative(ts) {
  if (!ts) return "—";
  const diff = Math.floor((Date.now() - new Date(ts).getTime()) / 1000);
  if (isNaN(diff)) return "—";
  if (diff < 5) return "just now";
  if (diff < 60) return diff + "s ago";
  if (diff < 3600) return Math.floor(diff / 60) + "m ago";
  if (diff < 86400) return Math.floor(diff / 3600) + "h ago";
  return Math.floor(diff / 86400) + "d ago";
}
function fmtDuration(seconds) {
  if (seconds == null) return "—";
  if (seconds < 0) return "expired";
  if (seconds < 60) return seconds + "s";
  if (seconds < 3600) return Math.floor(seconds / 60) + "m";
  if (seconds < 86400) return Math.floor(seconds / 3600) + "h";
  return Math.floor(seconds / 86400) + "d";
}

/* --- Primitives --- */
// display:contents wrapper so the injected SVG participates in flex layout
// exactly as the old inline string did.
const Ico = ({ svg }) =>
  html`<span style="display:contents" dangerouslySetInnerHTML=${{ __html: svg }} />`;

function CardTitle({ icon, title, aside, asideStyle }) {
  return html`<div class="card-title">
    <${Ico} svg=${icon} />${title}
    ${aside != null
      ? html`<span class="title-aside" style=${asideStyle || ""}>${aside}</span>`
      : null}
  </div>`;
}

function Card({ delay = 0, wide = false, style = "", children }) {
  const cls = "card" + (wide ? " grid-wide" : "");
  const st = "animation-delay:" + delay + "ms" + (style ? ";" + style : "");
  return html`<div class=${cls} style=${st}>${children}</div>`;
}

function Empty({ children, cta }) {
  return html`<div class="empty">${children}${cta ? html`<span class="empty-cta">${cta}</span>` : null}</div>`;
}

/* --- Header --- */
function Header({ snap, paused, connState, onPause, onRefresh, lastUpdate }) {
  const connText = paused
    ? "paused"
    : connState === "live"
      ? "live"
      : connState === "reconnecting"
        ? "reconnecting…"
        : "connecting…";
  const dotCls =
    "status-dot" +
    (paused ? " paused" : connState === "reconnecting" ? " disconnected" : "");
  return html`
    <header class="header">
      <div class="header-left">
        <h1>
          <span class="q-icon"><svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="url(#neon-grad)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/></svg></span>
          <span class="brand">q-ring</span>
          <span class="sub">quantum status</span>
        </h1>
        <span class="meta-chip" title="q-ring version">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
          ${" v" + (snap ? snap.version : "")}
        </span>
        <span class="meta-chip" title="Project working directory">
          <${Ico} svg=${icons.folder} /> ${snap ? snap.projectPath : ""}
        </span>
      </div>
      <div class="header-right">
        <span class="conn-label" title="Last update from the live stream"><span>${lastUpdate}</span></span>
        <button class="btn" type="button" title="Pause / resume the live stream (P)" onClick=${onPause}>
          ${paused
            ? html`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="5 3 19 12 5 21 5 3"/></svg>`
            : html`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="6" y="4" width="4" height="16" rx="1"/><rect x="14" y="4" width="4" height="16" rx="1"/></svg>`}
          <span>${paused ? "Resume" : "Pause"}</span>
        </button>
        <button class="btn" type="button" title="Force-refresh now (R)" onClick=${onRefresh}>
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12a9 9 0 1 1-3.5-7.1"/><polyline points="21 3 21 9 15 9"/></svg>
          Refresh
        </button>
        <a class="btn" href=${"/api/status" + Q} target="_blank" rel="noopener" title="Open the raw JSON snapshot in a new tab">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>
          JSON
        </a>
        <span class="conn-label"><span class=${dotCls}></span><span>${connText}</span></span>
      </div>
    </header>
  `;
}

/* --- KPI strip --- */
function KpiStrip({ snap }) {
  const s = snap;
  const m = s.auditMetrics || { total: 0, byAction: {}, topRead: [] };
  const reads = m.byAction.read || 0;
  const writes = (m.byAction.write || 0) + (m.byAction.delete || 0) + (m.byAction.rotate || 0);
  const denied = m.byAction.policy_deny || 0;
  const enabledHooks = (s.hooks || []).filter((h) => h.enabled).length;
  const validApprovals = (s.approvals || []).filter((a) => a.valid).length;
  const anomalies = (s.anomalies || []).length;
  const items = [
    { label: "Secrets", icon: icons.key, value: s.health.total, sub: s.health.healthy + " healthy · " + s.health.stale + " stale · " + s.health.expired + " expired", cls: "" },
    { label: "Environment", icon: icons.environment, value: s.environment ? s.environment.env : "none", sub: s.environment ? "via " + s.environment.source : "no env detected", cls: s.environment ? "" : "dim" },
    { label: "Protected", icon: icons.lock, value: s.protectedCount, sub: "require approval", cls: s.protectedCount > 0 ? "warning" : "dim" },
    { label: "Approvals", icon: icons.approve, value: validApprovals, sub: "active grants", cls: validApprovals > 0 ? "green" : "dim" },
    { label: "Hooks", icon: icons.hook, value: enabledHooks, sub: "enabled / " + (s.hooks || []).length + " total", cls: enabledHooks > 0 ? "" : "dim" },
    { label: "Reads (24h)", icon: icons.audit, value: reads, sub: writes + " writes · " + denied + " denied", cls: "" },
    { label: "Anomalies", icon: icons.anomaly, value: anomalies, sub: anomalies ? "investigate now" : "all clear", cls: anomalies ? "danger" : "green" },
  ];
  return html`<section class="kpi-strip">
    ${items.map(
      (k) => html`<div class="kpi" key=${k.label}>
        <div class="kpi-label"><${Ico} svg=${k.icon} />${k.label}</div>
        <div class="kpi-value ${k.cls}">${k.value}</div>
        <div class="kpi-sub">${k.sub}</div>
      </div>`,
    )}
  </section>`;
}

/* --- Overview cards --- */
function HealthCard({ snap, delay }) {
  const h = snap.health;
  const total = h.total || 1;
  const r = 42, circ = 2 * Math.PI * r;
  const slices = [
    { v: h.healthy, c: "var(--accent)" },
    { v: h.stale, c: "var(--warning)" },
    { v: h.expired, c: "var(--danger)" },
    { v: h.noDecay, c: "var(--text-dim)" },
  ];
  let offset = 0;
  const rings = slices.map((sl, i) => {
    const len = (sl.v / total) * circ;
    const ring = html`<circle key=${i} cx="50" cy="50" r=${r} fill="none" stroke=${sl.c} stroke-width="12" stroke-dasharray=${len + " " + (circ - len)} stroke-dashoffset=${-offset} stroke-linecap="round" opacity="0.85" />`;
    offset += len;
    return ring;
  });
  const sc = snap.scopes || { global: 0, project: 0, team: 0, org: 0 };
  return html`<${Card} delay=${delay}>
    <${CardTitle} icon=${icons.health} title="Health Summary" aside=${h.healthy + "/" + h.total + " healthy"} />
    <div class="health-row">
      <div class="donut-wrap">
        <svg viewBox="0 0 100 100" width="100" height="100">${rings}</svg>
        <div class="donut-label">${h.total}<small>secrets</small></div>
      </div>
      <div class="health-legend">
        <div class="legend-item"><span class="legend-dot" style="background:var(--accent)"></span>Healthy ${h.healthy}</div>
        <div class="legend-item"><span class="legend-dot" style="background:var(--warning)"></span>Stale ${h.stale}</div>
        <div class="legend-item"><span class="legend-dot" style="background:var(--danger)"></span>Expired ${h.expired}</div>
        <div class="legend-item"><span class="legend-dot" style="background:var(--text-dim)"></span>No decay ${h.noDecay}</div>
      </div>
    </div>
    <div class="scope-row">
      ${["global", "project", "team", "org"].filter((k) => sc[k]).map(
        (k) => html`<span class="scope-pill" key=${k}><strong>${sc[k]}</strong>${k}</span>`,
      )}
    </div>
  <//>`;
}

function EnvCard({ snap, delay }) {
  const env = snap.environment;
  return html`<${Card} delay=${delay}>
    <${CardTitle} icon=${icons.environment} title="Environment" />
    ${env
      ? html`<div class="env-status"><span class="env-big env-pill ${envClass(env.env)}">${env.env}</span><span class="env-source">detected via ${env.source}</span></div>`
      : html`<${Empty} cta="$ qring env --project-path .">No environment detected.<//>`}
  <//>`;
}

function ManifestCard({ snap, delay }) {
  const m = snap.manifest;
  if (!m) {
    return html`<${Card} delay=${delay}>
      <${CardTitle} icon=${icons.manifest} title="Manifest" />
      <${Empty} cta=${html`$ qring wizard <name>`}>No <code>.q-ring.json</code> manifest in this project.<//>
    <//>`;
  }
  const ok = m.required - m.missing.length - m.expired.length - m.stale.length;
  const okPct = m.required ? Math.max(0, Math.round((ok / m.required) * 100)) : 100;
  const fillCol = m.missing.length ? "var(--danger)" : m.expired.length || m.stale.length ? "var(--warning)" : "var(--green)";
  const group = (label, keys, cls) =>
    html`<div class="label">${label} (${keys.length})</div><div>${keys.map((k) => html`<span class="key-pill ${cls}" key=${k}>${k}</span>`)}</div>`;
  const hasIssues = m.missing.length || m.expired.length || m.stale.length;
  return html`<${Card} delay=${delay}>
    <${CardTitle} icon=${icons.manifest} title="Manifest" aside=${m.required + " required / " + m.declared + " declared"} />
    <div class="manifest-bars">
      <div class="manifest-row"><span style="min-width:54px">healthy</span><div class="manifest-bar"><div class="manifest-fill" style=${"width:" + okPct + "%;background:" + fillCol}></div></div><span>${okPct}%</span></div>
    </div>
    <div class="manifest-list">
      ${m.missing.length ? group("Missing required", m.missing, "miss") : null}
      ${m.expired.length ? group("Expired", m.expired, "exp") : null}
      ${m.stale.length ? group("Stale", m.stale, "exp") : null}
      ${!hasIssues ? html`<div class="label">All required keys present and healthy.</div>` : null}
    </div>
  <//>`;
}

function PolicyCard({ snap, delay }) {
  const p = snap.policy || { counts: {} };
  const c = p.counts || {};
  const has = p.hasMcpPolicy || p.hasExecPolicy || p.hasSecretPolicy;
  if (!has) {
    return html`<${Card} delay=${delay}>
      <${CardTitle} icon=${icons.policy} title="Policy" />
      <${Empty} cta=${html`add <code>policy</code> to <code>.q-ring.json</code>`}>No governance policy declared.<//>
    <//>`;
  }
  const Row = ({ label, value }) =>
    html`<div class="policy-row"><span class="policy-label">${label}</span><span class="policy-value ${value ? "" : "zero"}">${value || "—"}</span></div>`;
  const aside = [p.hasMcpPolicy ? "mcp" : "", p.hasExecPolicy ? "exec" : "", p.hasSecretPolicy ? "secrets" : ""].filter(Boolean).join(" · ") || "none";
  return html`<${Card} delay=${delay}>
    <${CardTitle} icon=${icons.policy} title="Policy" aside=${aside} />
    <div class="policy-rows">
      <${Row} label="MCP allow tools" value=${c.allowTools} />
      <${Row} label="MCP deny tools" value=${c.denyTools} />
      <${Row} label="Denied keys" value=${c.deniedKeys} />
      <${Row} label="Denied tags" value=${c.deniedTags} />
      <${Row} label="Exec allow" value=${c.allowCommands} />
      <${Row} label="Exec deny" value=${c.denyCommands} />
      <${Row} label="Tag → approval" value=${c.requireApprovalForTags} />
      <${Row} label="Tag → rotation" value=${c.requireRotationFormatForTags} />
      ${p.maxTtlSeconds ? html`<${Row} label="Max TTL" value=${fmtDuration(p.maxTtlSeconds)} />` : null}
      ${p.maxRuntimeSeconds ? html`<${Row} label="Max exec runtime" value=${fmtDuration(p.maxRuntimeSeconds)} />` : null}
    </div>
  <//>`;
}

/* --- Quantum cards --- */
function DecayCard({ snap, delay }) {
  const withDecay = (snap.secrets || [])
    .filter((x) => x.decay && x.decay.timeRemaining)
    .sort((a, b) => (a.decay.secondsRemaining || 0) - (b.decay.secondsRemaining || 0));
  return html`<${Card} delay=${delay}>
    <${CardTitle} icon=${icons.decay} title="Decay Timers" aside=${withDecay.length + " tracked"} />
    ${!withDecay.length
      ? html`<${Empty} cta="$ qring set KEY --ttl 86400">No secrets with decay configured.<//>`
      : html`<div class="decay-list">${withDecay.slice(0, 12).map((x) => {
          const pct = Math.min(x.decay.lifetimePercent, 100);
          const col = decayColor(pct, x.decay.isExpired);
          const label = x.decay.isExpired ? "expired" : x.decay.timeRemaining || "";
          return html`<div class="decay-item" key=${x.scope + ":" + x.key}>
            <span class="decay-key" title=${x.key}>${x.key}</span>
            <div class="decay-bar"><div class="decay-fill" style=${"width:" + pct + "%;background:" + col}></div></div>
            <span class="decay-time" style=${"color:" + col}>${label}</span>
          </div>`;
        })}</div>`}
  <//>`;
}

function SuperpositionCard({ snap, delay }) {
  const sup = (snap.secrets || []).filter((x) => x.type === "superposition" && x.environments && x.environments.length);
  return html`<${Card} delay=${delay}>
    <${CardTitle} icon=${icons.superposition} title="Superposition" aside=${sup.length + " multi-env"} />
    ${!sup.length
      ? html`<${Empty} cta="$ qring set KEY --env prod">No secrets in superposition.<//>`
      : html`<div class="super-list">${sup.slice(0, 14).map((x) => html`<div class="super-item" key=${x.scope + ":" + x.key}>
          <span class="super-key">${x.key}</span>
          ${(x.environments || []).map((e) => html`<span class="env-pill ${envClass(e)}" key=${e}>${e}${e === x.defaultEnv ? " ✓" : ""}</span>`)}
        </div>`)}</div>`}
  <//>`;
}

function EntanglementCard({ snap, delay }) {
  const pairs = snap.entanglements || [];
  const seen = new Set();
  const unique = pairs.filter((p) => {
    const id = [p.source.service, p.source.key, p.target.service, p.target.key].sort().join("|");
    if (seen.has(id)) return false;
    seen.add(id);
    return true;
  });

  // Node/edge graph on a circular layout. Nodes are unique keys; an edge per
  // entangled pair. Falls back to the flat list when the graph gets crowded.
  const nodeNames = [];
  const nodeIndex = new Map();
  for (const p of unique) {
    for (const k of [p.source.key, p.target.key]) {
      if (!nodeIndex.has(k)) {
        nodeIndex.set(k, nodeNames.length);
        nodeNames.push(k);
      }
    }
  }
  const useGraph = unique.length > 0 && nodeNames.length <= 14;

  const W = 320, H = 210, cx = W / 2, cy = H / 2;
  const r = Math.min(W, H) / 2 - 34;
  const pos = nodeNames.map((_, i) => {
    const a = (2 * Math.PI * i) / nodeNames.length - Math.PI / 2;
    return { x: cx + r * Math.cos(a), y: cy + r * Math.sin(a) };
  });
  const trunc = (s) => (s.length > 14 ? s.slice(0, 12) + "…" : s);

  return html`<${Card} delay=${delay}>
    <${CardTitle} icon=${icons.entangle} title="Entanglement" aside=${unique.length + " pair" + (unique.length === 1 ? "" : "s") + " · " + nodeNames.length + " keys"} />
    ${!unique.length
      ? html`<${Empty} cta="$ qring entangle KEY_A KEY_B">No entangled secrets.<//>`
      : useGraph
        ? html`<svg class="entangle-graph" viewBox="0 0 ${W} ${H}" role="img" aria-label="Entanglement graph: ${unique.length} linked pairs">
            ${unique.map((p, i) => {
              const a = pos[nodeIndex.get(p.source.key)];
              const b = pos[nodeIndex.get(p.target.key)];
              return html`<line key=${"e" + i} x1=${a.x} y1=${a.y} x2=${b.x} y2=${b.y} class="entangle-edge" />`;
            })}
            ${nodeNames.map((name, i) => {
              const p = pos[i];
              const rightHalf = p.x >= cx;
              return html`<g key=${"n" + i}>
                <circle cx=${p.x} cy=${p.y} r="5" class="entangle-node" />
                <text x=${p.x + (rightHalf ? 9 : -9)} y=${p.y + 3.5} text-anchor=${rightHalf ? "start" : "end"} class="entangle-label">${trunc(name)}<title>${name}</title></text>
              </g>`;
            })}
          </svg>`
        : html`<div class="entangle-list">${unique.slice(0, 12).map((p, i) => html`<div class="entangle-pair" key=${i}>
            <span>${p.source.key}</span><span class="entangle-arrow">↔</span><span>${p.target.key}</span>
          </div>`)}</div>`}
  <//>`;
}

function TunnelsCard({ snap, delay }) {
  const tunnels = snap.tunnels || [];
  return html`<${Card} delay=${delay}>
    <${CardTitle} icon=${icons.tunnel} title="Quantum Tunnels" aside=${tunnels.length + " live"} />
    ${!tunnels.length
      ? html`<${Empty} cta=${html`$ qring tunnel create <value>`}>No active tunnels.<//>`
      : html`<div class="tunnel-list">${tunnels.map((t) => {
          const rem = t.expiresAt ? Math.max(0, Math.floor((t.expiresAt - Date.now()) / 1000)) : null;
          return html`<div class="tunnel-card" key=${t.id}>${t.id}<div class="tunnel-meta">
            <span>reads: ${t.accessCount}${t.maxReads ? "/" + t.maxReads : ""}</span>
            ${rem !== null ? html`<span>expires: ${rem}s</span>` : html`<span>no expiry</span>`}
          </div></div>`;
        })}</div>`}
  <//>`;
}

/* --- Governance cards --- */
function ApprovalsCard({ snap, delay }) {
  const list = snap.approvals || [];
  return html`<${Card} delay=${delay}>
    <${CardTitle} icon=${icons.approve} title="Approvals" aside=${list.filter((a) => a.valid).length + " valid"} />
    ${!list.length
      ? html`<${Empty} cta=${'$ qring approve KEY --for 1800 --reason "..."'}>No active approvals.<//>`
      : html`<div class="approval-list">${list.slice(0, 8).map((a) => {
          const cls = a.tampered ? "tampered" : a.secondsRemaining < 300 ? "expiring" : "";
          return html`<div class="approval-card ${cls}" key=${a.id}>
            <div class="approval-head"><span>${a.key}${a.tampered ? " ⚠ TAMPERED" : ""}</span><span>${fmtDuration(a.secondsRemaining)} left</span></div>
            <div class="approval-reason">${a.reason || "(no reason)"}</div>
            <div class="approval-meta"><span>scope:${a.scope}</span><span>by:${a.grantedBy}</span></div>
          </div>`;
        })}</div>`}
  <//>`;
}

function HooksCard({ snap, delay }) {
  const list = snap.hooks || [];
  return html`<${Card} delay=${delay}>
    <${CardTitle} icon=${icons.hook} title="Hooks" aside=${list.filter((h) => h.enabled).length + " enabled / " + list.length} />
    ${!list.length
      ? html`<${Empty} cta=${'$ qring hook add --tag payments --action rotate --exec "..."'}>No hooks registered.<//>`
      : html`<div class="hooks-list">${list.slice(0, 8).map((h) => html`<div class="hook-row ${h.enabled ? "" : "disabled"}" key=${h.id}>
          <span class="hook-type ${h.type}">${h.type}</span>
          <span class="hook-summary" title=${h.matchSummary}>${h.description || h.matchSummary}</span>
          <span class="hook-id">${h.id}</span>
        </div>`)}</div>`}
  <//>`;
}

function MemoryCard({ snap, delay }) {
  return html`<${Card} delay=${delay}>
    <${CardTitle} icon=${icons.memory} title="Agent Memory" />
    <div class="empty" style="display:flex;align-items:baseline;gap:8px;font-style:normal">
      <span style="font-size:1.6rem;font-weight:700;color:var(--text-primary);font-family:var(--font-display)">${snap.memoryKeys || 0}</span>
      <span>memory key${snap.memoryKeys === 1 ? "" : "s"} encrypted at <code>~/.config/q-ring/agent-memory.enc</code></span>
    </div>
  <//>`;
}

/* --- Anomalies --- */
function AnomaliesCard({ snap, delay }) {
  const list = snap.anomalies || [];
  if (!list.length) {
    return html`<${Card} delay=${delay} wide=${true}>
      <${CardTitle} icon=${icons.anomaly} title="Anomaly Alerts" aside="all clear" asideStyle="color:var(--green)" />
      <${Empty}>No anomalies detected — quantum field is stable.<//>
    <//>`;
  }
  const hintFor = (t) =>
    t === "tampered" ? "$ qring audit:verify"
    : t === "burst" ? "$ qring audit --key … --action read"
    : t === "unusual-hour" ? '$ qring audit --action read --since "1am"'
    : "$ qring audit --limit 100";
  return html`<${Card} delay=${delay} wide=${true}>
    <${CardTitle} icon=${icons.anomaly} title="Anomaly Alerts" aside=${list.length + " active"} asideStyle="color:var(--danger)" />
    <div class="anomaly-list">${list.map((a, i) => html`<div class="anomaly-card" key=${i}>
      <div class="anomaly-type">${a.type}</div>
      <div class="anomaly-desc">${a.description}</div>
      <div class="anomaly-hint">${hintFor(a.type)}</div>
    </div>`)}</div>
  <//>`;
}

/* --- Secrets table --- */
function filterSecrets(rows, query) {
  const q = query.trim().toLowerCase();
  if (!q) return rows.slice();
  if (q === "expired") return rows.filter((r) => r.decay && r.decay.isExpired);
  if (q === "stale") return rows.filter((r) => r.decay && r.decay.isStale && !r.decay.isExpired);
  if (q === "protected") return rows.filter((r) => r.requiresApproval);
  return rows.filter((r) => {
    const hay = [r.key, r.scope, r.type, r.provider || "", r.defaultEnv || "", (r.environments || []).join(" "), (r.tags || []).join(" ")].join(" ").toLowerCase();
    return hay.indexOf(q) !== -1;
  });
}
function sortRows(rows, sort) {
  const dir = sort.dir === "asc" ? 1 : -1;
  return rows.sort((a, b) => {
    let av, bv;
    switch (sort.col) {
      case "key": av = a.key; bv = b.key; break;
      case "scope": av = a.scope; bv = b.scope; break;
      case "env": av = a.defaultEnv || (a.environments || [])[0] || ""; bv = b.defaultEnv || (b.environments || [])[0] || ""; break;
      case "type": av = a.type; bv = b.type; break;
      case "decay": av = a.decay && a.decay.secondsRemaining != null ? a.decay.secondsRemaining : Infinity; bv = b.decay && b.decay.secondsRemaining != null ? b.decay.secondsRemaining : Infinity; break;
      case "tags": av = (a.tags || []).join(","); bv = (b.tags || []).join(","); break;
      case "lastAccessedAt":
      default: av = a.lastAccessedAt ? new Date(a.lastAccessedAt).getTime() : 0; bv = b.lastAccessedAt ? new Date(b.lastAccessedAt).getTime() : 0;
    }
    if (av < bv) return -1 * dir;
    if (av > bv) return 1 * dir;
    return 0;
  });
}

function SecretsSection({ snap, query, setQuery, sort, setSort, searchRef }) {
  const all = snap.secrets || [];
  const filtered = useMemo(() => sortRows(filterSecrets(all, query), sort), [all, query, sort]);
  const cols = [
    { id: "key", label: "Key" },
    { id: "scope", label: "Scope" },
    { id: "env", label: "Env" },
    { id: "type", label: "Type" },
    { id: "decay", label: "Decay" },
    { id: "tags", label: "Tags" },
    { id: "lastAccessedAt", label: "Last read" },
  ];
  const onSort = (col) => {
    if (sort.col === col) setSort({ col, dir: sort.dir === "asc" ? "desc" : "asc" });
    else setSort({ col, dir: col === "key" ? "asc" : "desc" });
  };
  return html`<section><${Card} wide=${true} style="margin-bottom:16px">
    <${CardTitle} icon=${icons.key} title="Secrets" aside=${filtered.length + " of " + all.length} />
    <div class="secrets-toolbar">
      <label class="search"><${Ico} svg=${icons.search} /><input ref=${searchRef} id="secretsSearch" type="search" placeholder="Filter by key, scope, env, tag, provider…" autocomplete="off" value=${query} onInput=${(e) => setQuery(e.target.value)} /></label>
      <button class="btn" type="button" onClick=${() => setQuery("expired")}>${snap.health.expired || 0} expired</button>
      <button class="btn" type="button" onClick=${() => setQuery("stale")}>${snap.health.stale || 0} stale</button>
      <button class="btn" type="button" onClick=${() => setQuery("protected")}>${snap.protectedCount || 0} protected</button>
      <button class="btn" type="button" onClick=${() => setQuery("")}>clear</button>
    </div>
    <div class="secrets-table-wrap">
      ${!filtered.length
        ? html`<div class="empty" style="padding:18px;text-align:center">No secrets match the filter.</div>`
        : html`<table class="secrets-table">
            <thead><tr>${cols.map((c) => html`<th key=${c.id} class=${sort.col === c.id ? "sorted" : ""} onClick=${() => onSort(c.id)}>${c.label}<span class="sort-arrow">${sort.dir === "asc" ? "▲" : "▼"}</span></th>`)}</tr></thead>
            <tbody>${filtered.map((r) => {
              const env = r.type === "superposition"
                ? (r.environments || []).map((e) => html`<span class="env-pill ${envClass(e)}" style="margin-right:3px" key=${e}>${e}${e === r.defaultEnv ? " ✓" : ""}</span>`)
                : html`<span class="env-pill env-default">—</span>`;
              const decayCell = r.decay && r.decay.timeRemaining
                ? (() => {
                    const pct = Math.min(r.decay.lifetimePercent, 100);
                    const col = decayColor(pct, r.decay.isExpired);
                    return html`<span class="mini-decay"><span class="mini-decay-bar"><span class="mini-decay-fill" style=${"width:" + pct + "%;background:" + col}></span></span><span class="mini-decay-time" style=${"color:" + col}>${r.decay.isExpired ? "expired" : r.decay.timeRemaining}</span></span>`;
                  })()
                : html`<span class="mini-decay-time">—</span>`;
              const tags = r.tags || [];
              return html`<tr key=${r.scope + ":" + r.key}>
                <td class="col-key" title=${r.key}>${r.key}${r.requiresApproval ? html`<span class="protected-icon" title="requires approval for MCP read"><${Ico} svg=${icons.lock} /></span>` : null}</td>
                <td><span class="scope-tag ${r.scope}">${r.scope}</span></td>
                <td>${env}</td>
                <td><span class="type-tag ${r.type}">${r.type}</span></td>
                <td class="col-decay">${decayCell}</td>
                <td class="col-tags">${tags.slice(0, 3).map((t) => html`<span class="tag-pill" key=${t}>${t}</span>`)}${tags.length > 3 ? "+" + (tags.length - 3) : ""}</td>
                <td>${fmtRelative(r.lastAccessedAt)}</td>
              </tr>`;
            })}</tbody>
          </table>`}
    </div>
  <//></section>`;
}

/* --- Agent sessions --- */
function SessionsCard({ snap, delay }) {
  const list = snap.sessions || [];
  const [open, setOpen] = useState({});
  const toggle = (id) => setOpen((o) => ({ ...o, [id]: !o[id] }));
  const span = (s) => {
    const secs = Math.max(0, Math.round((new Date(s.endedAt) - new Date(s.startedAt)) / 1000));
    return fmtDuration(secs);
  };
  return html`<${Card} delay=${delay} wide=${true}>
    <${CardTitle} icon=${icons.audit} title="Agent Sessions (24h)" aside=${list.length + " session" + (list.length === 1 ? "" : "s")} />
    ${!list.length
      ? html`<${Empty} cta=${"$ qring audit:sessions"}>No agent activity in the last 24h. Sessions appear once an MCP client or airlock touches the ring.<//>`
      : html`<div class="sessions-list">${list.slice(0, 12).map((s) => html`<div class="session ${open[s.id] ? "open" : ""}" key=${s.id}>
          <button type="button" class="session-row" onClick=${() => toggle(s.id)} title=${"session " + s.id}>
            <span class="session-caret">${open[s.id] ? "▾" : "▸"}</span>
            <span class="session-agent">${s.wrapLabel ? "airlock" : s.agent}</span>
            <span class="hook-type ${s.source === "mcp" ? "http" : s.source === "agent" ? "shell" : "signal"}">${s.source}</span>
            ${s.wrapLabel ? html`<span class="session-wrap" title=${s.wrapLabel}>${s.wrapLabel}</span>` : null}
            <span class="session-meta">${fmtRelative(s.endedAt)} · ${span(s)} · ${s.eventCount} events</span>
            <span class="session-denials ${s.denials ? "bad" : ""}">${s.denials ? s.denials + " denied" : "0 denied"}</span>
            ${s.countsByAction && s.countsByAction.canary ? html`<span class="session-denials bad">${s.countsByAction.canary} canary</span>` : null}
          </button>
          ${open[s.id]
            ? html`<div class="session-detail">
                <div class="session-keys">${s.keys.length ? "keys: " + s.keys.join(", ") : "no keys touched"}</div>
                <div class="audit-feed">${(s.recent || []).map((e, i) => html`<div class="audit-row" key=${i}>
                  <span class="audit-ts" title=${e.timestamp}>${fmtTime(e.timestamp)}</span>
                  <span class="audit-action ${e.action}">${e.action}</span>
                  <span></span>
                  <span><span class="audit-key">${e.key || "—"}</span> <span class="audit-detail">${e.detail || ""}</span></span>
                </div>`)}</div>
              </div>`
            : null}
        </div>`)}</div>`}
  <//>`;
}

/* --- Audit log --- */
function AuditCard({ snap, delay, filter, setFilter }) {
  const events = snap.audit || [];
  const m = snap.auditMetrics || { byAction: {}, bySource: {} };
  const filtered = events.filter((e) => {
    if (filter.action && e.action !== filter.action) return false;
    if (filter.source && e.source !== filter.source) return false;
    const txt = filter.text.trim().toLowerCase();
    if (txt) {
      const hay = [e.key || "", e.action, e.source, e.detail || "", e.scope || "", e.env || ""].join(" ").toLowerCase();
      if (hay.indexOf(txt) === -1) return false;
    }
    return true;
  });
  const allActions = ["read", "write", "delete", "rotate", "generate", "entangle", "tunnel", "teleport", "approve", "revoke", "policy_deny", "collapse", "export"];
  const allSources = ["cli", "mcp", "agent", "ci", "hook", "api"];
  const toggle = (field, val) => setFilter({ ...filter, [field]: filter[field] === val ? "" : val });
  const chain = snap.auditChain;
  return html`<${Card} delay=${delay} wide=${true}>
    <${CardTitle} icon=${icons.audit} title="Audit Log (24h)" aside=${filtered.length + " of " + events.length + " shown · window " + (m.windowSeconds || 86400) / 3600 + "h"} />
    ${chain && chain.totalEvents > 0
      ? html`<div class="chain-badge ${chain.intact ? "ok" : "broken"}" title="Hash-chain integrity — same check as qring audit:verify">
          ${chain.intact
            ? html`⛓ chain intact · ${chain.totalEvents} events verified`
            : html`⛓ chain BROKEN at event #${chain.brokenAt} · ${chain.validEvents}/${chain.totalEvents} valid — run $ qring audit:verify`}
        </div>`
      : null}
    <div class="audit-actions-strip">
      ${allActions.filter((a) => m.byAction[a]).length
        ? allActions.filter((a) => m.byAction[a]).map((a) => html`<span class="audit-chip ${filter.action === a ? "active" : ""}" key=${a} onClick=${() => toggle("action", a)}>${a}<strong>${m.byAction[a]}</strong></span>`)
        : html`<span class="empty" style="padding:0">no actions</span>`}
    </div>
    ${allSources.filter((src) => m.bySource[src]).length
      ? html`<div class="audit-actions-strip">${allSources.filter((src) => m.bySource[src]).map((src) => html`<span class="audit-chip ${filter.source === src ? "active" : ""}" key=${src} onClick=${() => toggle("source", src)}>${src}<strong>${m.bySource[src]}</strong></span>`)}</div>`
      : null}
    <div class="audit-toolbar">
      <label class="search"><${Ico} svg=${icons.search} /><input id="auditSearch" type="search" placeholder="Filter by key, detail, scope…" autocomplete="off" value=${filter.text} onInput=${(e) => setFilter({ ...filter, text: e.target.value })} /></label>
      <button class="btn" type="button" onClick=${() => setFilter({ action: "", source: "", text: "" })}>clear</button>
    </div>
    ${!filtered.length
      ? html`<${Empty}>No audit events match the filter.<//>`
      : html`<div class="audit-feed">${filtered.slice(0, 80).map((e, i) => html`<div class="audit-row" key=${i}>
          <span class="audit-ts" title=${e.timestamp}>${fmtTime(e.timestamp)}</span>
          <span class="audit-action ${e.action}">${e.action}</span>
          <span class="audit-source">${e.source}</span>
          <span><span class="audit-key">${e.key || "—"}</span> <span class="audit-detail">${e.detail || ""}</span></span>
        </div>`)}</div>`}
  <//>`;
}

/* --- App root --- */
function App() {
  const [snap, setSnap] = useState(null);
  const [paused, setPaused] = useState(false);
  const [connState, setConnState] = useState("connecting");
  const [query, setQuery] = useState("");
  const [sort, setSort] = useState({ col: "lastAccessedAt", dir: "desc" });
  const [auditFilter, setAuditFilter] = useState({ action: "", source: "", text: "" });
  const [, setTick] = useState(0); // forces relative-time refresh

  const pausedRef = useRef(paused);
  pausedRef.current = paused;
  const searchRef = useRef(null);

  const applySnap = useCallback((data) => {
    try { setSnap(typeof data === "string" ? JSON.parse(data) : data); } catch { /* ignore */ }
  }, []);

  const forceRefresh = useCallback(() => {
    fetch("/api/status" + Q, { cache: "no-store" }).then((r) => r.json()).then(applySnap).catch(() => {});
  }, [applySnap]);

  // SSE connection (mounted once).
  useEffect(() => {
    const es = new EventSource("/events" + Q);
    es.onopen = () => setConnState("live");
    es.onmessage = (e) => { if (!pausedRef.current) applySnap(e.data); };
    es.onerror = () => setConnState("reconnecting");
    return () => es.close();
  }, [applySnap]);

  // Tick every 5s so relative timestamps stay accurate even while paused.
  useEffect(() => {
    const t = setInterval(() => setTick((n) => n + 1), 5000);
    return () => clearInterval(t);
  }, []);

  // Keyboard shortcuts.
  useEffect(() => {
    const onKey = (e) => {
      const tag = e.target && e.target.tagName;
      if (tag === "INPUT" || tag === "TEXTAREA") {
        if (e.key === "Escape") e.target.blur();
        return;
      }
      if (e.key === "/") { e.preventDefault(); if (searchRef.current) searchRef.current.focus(); }
      else if (e.key === "p" || e.key === "P") setPaused((p) => !p);
      else if (e.key === "r" || e.key === "R") forceRefresh();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [forceRefresh]);

  const lastUpdate = snap ? "updated " + fmtRelative(snap.timestamp) : "—";

  if (!snap) {
    return html`<div class="container">
      <${Header} snap=${null} paused=${paused} connState=${connState} onPause=${() => setPaused((p) => !p)} onRefresh=${forceRefresh} lastUpdate=${lastUpdate} />
      <p class="foot"><span>Connecting to the live quantum stream…</span></p>
    </div>`;
  }

  const m = snap.auditMetrics || { total: 0 };
  return html`<div class="container">
    <${Header} snap=${snap} paused=${paused} connState=${connState} onPause=${() => setPaused((p) => !p)} onRefresh=${forceRefresh} lastUpdate=${lastUpdate} />
    <${KpiStrip} snap=${snap} />
    <section class="grid">
      <${HealthCard} snap=${snap} delay=${0} />
      <${EnvCard} snap=${snap} delay=${60} />
      <${ManifestCard} snap=${snap} delay=${120} />
      <${PolicyCard} snap=${snap} delay=${180} />
    </section>
    <${SecretsSection} snap=${snap} query=${query} setQuery=${setQuery} sort=${sort} setSort=${setSort} searchRef=${searchRef} />
    <section class="grid">
      <${DecayCard} snap=${snap} delay=${0} />
      <${SuperpositionCard} snap=${snap} delay=${60} />
      <${EntanglementCard} snap=${snap} delay=${120} />
      <${TunnelsCard} snap=${snap} delay=${180} />
    </section>
    <section class="grid">
      <${ApprovalsCard} snap=${snap} delay=${0} />
      <${HooksCard} snap=${snap} delay=${60} />
      <${MemoryCard} snap=${snap} delay=${120} />
    </section>
    <section class="grid">
      <${SessionsCard} snap=${snap} delay=${0} />
    </section>
    <section class="grid">
      <${AnomaliesCard} snap=${snap} delay=${0} />
      <${AuditCard} snap=${snap} delay=${60} filter=${auditFilter} setFilter=${setAuditFilter} />
    </section>
    <p class="foot">
      <span>${"q-ring v" + snap.version + " · snapshot " + fmtTime(snap.timestamp) + " · " + (m.total || 0) + " audit events in last 24h"}</span>
      · keyboard: <span class="kbd">/</span> search · <span class="kbd">P</span> pause · <span class="kbd">R</span> refresh
    </p>
  </div>`;
}

render(html`<${App} />`, document.getElementById("app"));
