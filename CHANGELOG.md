# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

This is a security- and reliability-hardening release from an internal adversarial
audit. Findings were self-discovered (no external reporter, no evidence of
exploitation); each is fixed here and documented below. All fixes ship with
regression tests, and the whole suite now runs against an in-memory keyring fake
instead of the host keychain.

### Security
- **Entanglement can no longer be used as a policy-bypass write primitive.**
  `entangle_secrets` was gated only by the coarse tool policy, and `set_secret`'s
  propagation loop wrote entangled targets with no policy check at all. An MCP
  agent could link a scratch key to a policy-denied key (e.g. `PROD_DB_PASSWORD`)
  and then overwrite the denied value by writing the scratch key. Both keys are
  now checked against the key-level policy at entangle time (against the pinned
  policy root), and every MCP-sourced propagation re-checks the target's policy
  before writing. The entanglement registry gained a `version` field and per-pair
  `createdBy` provenance.
- **Approvals are bound to the resolved project, not the coarse scope label.**
  `hasApproval` matched on the `"project"` label, which is identical for every
  project — so an approval for a key at `--scope project` in project A also
  satisfied the same key's approval gate in project B. Approvals now carry (and
  HMAC-cover) the resolved service identity (`q-ring:project:<hash>`).
- **`exec_with_secrets` `restricted` profile now denies interpreters and shells**
  (`python`, `node`, `deno`, `bun`, `perl`, `ruby`, `php`, `sh`, `bash`, `zsh`)
  in addition to network tools — otherwise `python -c '…'` could egress the
  injected secrets while the profile claimed to block network access. The tool
  description now states the real (still-not-a-sandbox) guarantee.
- **Agent memory no longer falls back to a machine-derivable key.** When the OS
  keyring was unavailable, memory was encrypted under `sha256(hostname+username)`
  — recomputable by any local process, i.e. functionally plaintext-at-rest on
  headless/CI hosts. Writes now use the keyring key, else a PBKDF2 key from
  `QRING_MEMORY_PASSPHRASE`, else fail closed. The old key is used only to *read*
  pre-existing stores.
- **The audit hash chain is now tamper-evident against truncation and rewrite.**
  The unkeyed SHA-256 per-line chain let an attacker drop trailing events or
  rewrite the whole file into a self-consistent chain. A keyed anchor — the HMAC
  of the head line under a random key in the OS keyring, stored outside the log —
  now backs `audit:verify`. Keyring-unavailable hosts degrade to per-line checks
  with a one-time warning (no derivable key).
- **Owner-only permissions on the audit log and agent memory.** `audit.jsonl` and
  `agent-memory.enc` (and their directory) are created `0o600`/`0o700`, with a
  best-effort chmod to tighten files left world-readable by older versions.
- **`RedactionTransform` no longer leaks multi-byte secrets split across output
  chunks.** `chunk.toString()` corrupted a UTF-8 sequence straddling a chunk
  boundary before matching ran; it now decodes with `StringDecoder`.

### Changed
- **`.q-ring.json` policy is validated with a strict schema and fails closed.** A
  typo in a deny rule (`denytools` for `denyTools`) was silently ignored, leaving
  the tool/key allowed. An invalid `policy` object now raises a
  `PolicyConfigError` (cached by mtime) so enforcement checks deny rather than
  fall through to allow.
- **`qring doctor`** reports pre-v0.14 approvals that lack a project binding and
  will not grant access until re-granted.

### Fixed
- **Corrupt registry files no longer silently wipe your data.** `entanglement.json`,
  `approvals.json`, and `hooks.json` treated an unparseable file the same as an
  absent one, so the next write overwrote it with an empty registry — destroying
  every link/grant/hook. A corrupt file is now moved aside to
  `<path>.corrupt-<timestamp>` with a loud warning, and the registry reinitializes
  from empty (data preserved in the backup).
- **The JIT provisioning lock no longer busy-waits or deadlocks.** It spun the CPU
  (freezing the single-threaded MCP event loop for up to 8s under contention) and
  a crashed holder deadlocked all future JIT reads. A shared file-lock util now
  steals locks held by a dead process or older than the stale window, and sleeps
  via `Atomics.wait` instead of spinning. The audit append reuses the same lock so
  concurrent writers can't branch the chain.
- **Concurrent writes are no longer clobbered by the read-time access counter.**
  `get_secret`'s "observer effect" wrote the access count back onto a stale
  envelope; it now re-reads first, so a value written concurrently is preserved
  (the counter is last-write-wins).
- **Environment collapse is cached.** `get_secret`/`export_secrets` shelled out
  `git rev-parse` (sync, up to 3s) and re-read `.q-ring.json` on every call that
  omitted an explicit env; the git branch is cached per-cwd for a short window and
  the config by mtime.

### Dependencies
- Cleared all high/moderate advisories from the audit gate: `fast-uri` ≥3.1.4
  (was `>=3.1.2 <4`), `@hono/node-server` ≥2.0.10 (the old `>=1.19.13` override
  targeted the wrong version line), `postcss` ≥8.5.18 (was `>=8.5.10`, still under
  the vulnerable ≤8.5.17), and a new `brace-expansion` ≥5.0.8 override.

### Notes
- **Breaking (approvals):** approvals granted before this release have no project
  binding and are invalidated — re-run `qring approve <key>`. Most self-resolve
  within the default 1h TTL; `qring doctor` flags any that remain.
- **Breaking (exec):** the `restricted` exec profile now blocks interpreters and
  shells by default. To run them with secrets, define a custom profile in
  `.q-ring.json` or use the `ci`/`unrestricted` profile.
- **Headless/CI:** agent memory now requires an OS keyring or
  `QRING_MEMORY_PASSPHRASE`; it will not persist under a derivable key.

## [0.13.1] — 2026-07-27

### Security
- **Hardened SSRF IP-literal matching for IPv6-mapped forms.** The private/loopback/
  link-local guard (`isPrivateIP`) now parses addresses structurally via `ipaddr.js`
  instead of regex-matching them, so IPv4-mapped IPv6 addresses are blocked in every
  canonical spelling — including the hex-group form the WHATWG URL parser produces
  (e.g. `[::ffff:127.0.0.1]` → `::ffff:7f00:1`), which the previous dotted-decimal-only
  match let through. Applies to all four guard entry points (`checkSSRF`,
  `checkSSRFSync`, the connect-time `guardedLookup` rebinding guard, and
  `checkJitHttpProvisionUrl`), closing the bypass for outbound hook URLs and HTTP JIT
  provisioning targets. Public unicast addresses (including IPv4-mapped public
  addresses) are unaffected. Regression tests added.

### Fixed
- **`exec_with_secrets` profile description now states the real guarantee.** The
  `restricted` profile's MCP tool description claimed it "limits PATH and inheritable
  env vars"; in fact it denies a fixed list of network-tool binaries, strips proxy env
  vars, and caps runtime — it does not restrict `PATH`, and interpreters invoked
  directly (`python`, `node`, …) can still perform network I/O and read the injected
  secrets. The description now says so and points to OS-level isolation for untrusted
  commands. (No behavior change; a hardened `restricted` profile follows in 0.14.0.)

### Dependencies
- **`ipaddr.js` promoted to a direct dependency** (`^1.9.1`; already present transitively).
  It backs the SSRF address parsing above. The published package's runtime dependency
  set is otherwise unchanged.

## [0.13.0] — 2026-07-11

### Dependencies
- **Fixed GHSA-h67p-54hq-rp68** (js-yaml quadratic-complexity DoS, dev-scope via eslint) with a `js-yaml >=4.2.0` override — resolves to 4.3.0.
- **Majors:** `commander` 14→15 (CLI verified end-to-end), `eslint` 9→10 (three findings from newly-default rules fixed in code), `@types/node` 25→26; GitHub Actions `checkout` v7, `setup-node` v6, `pnpm/action-setup` v6, `codeql-action` v4.
- **Minors:** in-range `pnpm update` across prod + dev deps; `vite` pin 8.0.16→8.1.4.

### Added
- **`qring has <key>`** — script-friendly existence check (exit 0 if present, 1 if not; `--quiet` for exit-code-only, honors `--json`). Decay-aware like the MCP `has_secret` tool, closing the last MCP→CLI parity gap.
- **Claude Code plugin is now a real installable plugin** — added `claude-code-plugin/.claude-plugin/plugin.json` and a repo-root `.claude-plugin/marketplace.json`, so it installs via `/plugin marketplace add I4cTime/quantum_ring` + `/plugin install qring@q-ring` instead of file copying. Plugin components (agents/commands/skills/hooks) moved from `claude-code-plugin/.claude/` to the plugin root to match the Claude Code plugin format; hooks are wired via `hooks/hooks.json` (`${CLAUDE_PLUGIN_ROOT}`) for plugin installs and `.claude/settings.json` for project-scoped sync installs. `sync-versions` now stamps both new manifests.
- **`CONTRIBUTING.md`** — dev environment, branch/commit conventions, and the list of files to keep in sync (parity doc, plugin manifests, dashboard client bundle).
- **Docker install instructions** in the README for the MCP-server container path.
- **CI smoke tests** — the built `qring` binary (`--version`, `--help`) and an MCP `initialize` handshake against `dist/mcp.js` now run in CI after the build.
- **`--json` is now honored by ~20 more commands** — `list`, `inspect`, `delete`, `import`, `audit`, `audit:verify`, `health`, `analyze`, `recall`, `check`, `env`, `validate` (single/`--all`/`--list-providers`), `rotate`, `tunnel list`, `hook list`, `approvals`, `scan`, `lint` all emit `{ ok: true, data: … }`, making the whole read surface scriptable. Previously only 4 commands supported the advertised global flag.
- **Confirmation prompts on destructive operations** — `delete`, `forget --all`, `teleport unpack` (overwriting existing keys), `wizard` (regenerating existing keys), and `env:generate -o` (existing file) now ask before proceeding. Pass `-y`/`--yes` to skip; non-interactive use without `--yes` errors instead of silently proceeding. **Breaking for scripts that relied on unconfirmed `qring delete`/`forget --all` — add `--yes`.**
- **Plugin skills are now generated from a single source** — `cursor-plugin/skills/*/SKILL.md` is canonical; `scripts/plugin-generate-skills.mjs` derives the Claude Code skills and Kiro steering files (`pnpm run plugin:gen-skills`). Reconciles the cosmetic drift that hand-copying had accumulated.
- **CI parity guard** (`pnpm run check:parity` + a `parity` CI job) — fails when the three plugins' command/agent/skill sets diverge, doc'd MCP tool counts don't match the registered count (44), manifest versions drift from `package.json`, generated skills are stale, or the committed dashboard client bundle differs from a fresh build.
- **Cross-platform CI matrix** (experimental, non-blocking) — macOS + Windows on Node 22, ubuntu on Node 24, and a Node 18 engines-floor leg (build + CLI smoke; vitest 4 needs Node 20+). Exercises the per-OS keyring backends for the first time.
- **`qring doctor`** — one-shot install diagnosis: keyring-backend round-trip probe (the headless-Linux failure mode), audit-dir writability + hash-chain integrity, `.q-ring.json` validity, active policy, and `qring-mcp` on `PATH`. Supports `--json`; exits 1 on any failed check.
- **`qring completion bash|zsh|fish`** — shell completion scripts generated from the live command tree, so they can never drift from the actual commands/flags.
- **Dashboard: entanglement graph** — entangled secrets now render as an SVG node/edge graph (circular layout, up to 14 keys; falls back to the pair list beyond that), as the docs always advertised.
- **Dashboard: audit-chain badge** — the Audit Log card shows hash-chain integrity live (same check as `qring audit:verify`), green when intact, red with the break position when tampered.
- **Tag-driven release automation** — `pnpm run release:prepare <patch|minor|major|x.y.z>` bumps the version, syncs all manifests, rolls the CHANGELOG, and runs the parity guard; pushing the `v*` tag then runs `release.yml`, which creates the GitHub Release (notes from the CHANGELOG) and chains the npm/MCP publish and Homebrew update via `workflow_call`. See `docs/releasing.md`.
- **Docs** — `docs/troubleshooting.md` (keyring backends, MCP connection, approval gate, policy-root pinning, scripting gotchas, AGPL FAQ), per-editor quickstarts (`docs/quickstart-{claude-code,cursor,kiro}.md`), `docs/releasing.md`, and a docs index in the README.

### Changed
- **CLI errors are now one-line messages instead of stack traces** — a central handler catches errors thrown by any command (policy denials, keyring backend failures) and prints them in red; set `QRING_DEBUG=1` for the full stack.
- **`pnpm audit` moved off the blocking CI path** — it runs as a separate non-blocking job, so a freshly disclosed advisory in a transitive dependency no longer fails unrelated PRs.
- **npm publish now triggers on `release: published`** (was `created`), so draft releases can no longer publish; `mcp-publisher` is pinned to v1.7.9 instead of `latest`; publish and Homebrew workflows gained concurrency guards.

### Fixed
- **`qring set <key>` no longer hangs when the value is piped** — `promptSecret` reads stdin to EOF when it isn't a TTY (e.g. `echo "$VALUE" | qring set KEY`).
- **Homebrew formula test** asserted the string `"qring"` in `qring --version` output, which prints only the bare version — `brew test` would have failed on every release. It now asserts the version string.
- **Status dashboard actually sends security headers** — `Content-Security-Policy` (default-deny, inline-only), `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` (keeps the `?token=` URL out of Referer headers), and `Cache-Control: no-store` on every response. Previously the page was CSP-*compatible* but no policy was enforced. Added tests for token auth (403) and the new headers.

## [0.12.0] — 2026-06-24

### Security
- **`export_secrets` now honors the approval gate** — bulk reads previously collapsed and returned approval-protected values (`requiresApproval`) without an approval grant, even though `get_secret` enforced the gate. Export over MCP now skips protected secrets that lack a valid approval and records a blocked-read audit event. CLI exports (`source: "cli"`) are unaffected.
- **Governance policy is anchored to the server's launch directory** — MCP callers supply `projectPath` freely, so resolving `.q-ring.json` policy from it let a malicious/compromised agent escape `denyTools` / `deniedKeys` / `deniedTags` by pointing at a directory with no policy. The MCP server now pins policy resolution to its startup CWD (`setPolicyRoot`). Project-scoped *secret* resolution still follows `projectPath`; only policy is pinned.
- **`import_dotenv` no longer reads arbitrary files over MCP** — the importer's path-or-content convenience (read from disk if the argument is a path) is now restricted to the trusted local CLI. MCP/agent/api callers always treat the argument as literal `.env` content, closing a local-file-disclosure vector (e.g. passing `~/.aws/credentials` to be parsed and re-read via `get_secret`).
- **SSRF protection now validates at connect time (DNS-rebinding guard)** — outbound HTTP(S) (validation providers, webhook hooks) re-checks the resolved IP via a guarded `lookup` when the socket connects, not only up front. This closes the TOCTOU window where a hostname passed `checkSSRF` then resolved to a private/loopback address. Honors `Q_RING_ALLOW_PRIVATE_HOOKS=1`.
- **Teleport key derivation strengthened** — PBKDF2-HMAC-SHA512 iterations raised from 100 000 to 210 000 (OWASP 2023 floor). Bundles now record their `iter` count, so existing (pre-bump) bundles still decrypt.
- **Status dashboard endpoints require a per-launch token** — the dashboard binds to `127.0.0.1`, but on a shared host any local user/process could read key names, the audit log, and approval grants. Every route now requires a random, timing-safe token (`?token=…`), surfaced in the URL printed by `qring status` and the `status_dashboard` MCP tool.

### Changed
- **Status dashboard rebuilt on Preact + htm** — the live page is now a component-based app with VDOM diffing instead of full-`innerHTML` re-rendering. The SSE stream updates data in place, so card entrance animations run once on mount rather than replaying on every 5-second tick (the old "reload/flicker on update" behavior), and input focus/caret and scroll positions are preserved for free. Still a single self-contained, offline, CSP-clean page: the Preact + htm runtime and the app are bundled (esbuild) into an inlined script via `src/dashboard-client/main.js` → `src/core/dashboard-client.ts` (generated by `pnpm run build:dashboard`, run automatically as part of `build`).
- **Exec network/command guards hardened** — `allowNetwork:false` now matches on the command basename (catches `/usr/bin/curl`), and `policy.exec.denyCommands` uses token/path-boundary matching instead of bare substring (denying `rm` no longer trips `charm`).
- **Policy cache invalidates on `.q-ring.json` change** — `loadPolicy` keys its cache on the config file's mtime, so a long-lived MCP server picks up edited policy without a restart.

### Fixed
- **dotenv inline-comment parsing** — an unquoted `#` is only treated as a comment when preceded by whitespace, so values like `COLOR=#ff0000` are preserved.
- **`generate_secret --format password` class guarantee** — passwords are now built from one guaranteed character per class and shuffled (CSPRNG), eliminating the rare case where the previous fixup pass overwrote the sole representative of a class.

### Dependencies
- **Cleared 23 open Dependabot alerts** (4 high / 17 medium / 2 low) by raising `pnpm.overrides` to patched transitive versions: `hono` ≥4.12.25, `qs` ≥6.15.2, `ip-address` ≥10.1.1, `fast-uri` ≥3.1.2 (`<4`), `esbuild` ≥0.28.1, `postcss` ≥8.5.10. Pinned `vite` ≥8.0.16 as an explicit `devDependency` (overrides don't apply to peer-only deps). All flagged packages are transitive via `@modelcontextprotocol/sdk`'s Express/Hono/ajv HTTP stack (runtime) or vitest/tsup (dev); q-ring uses the stdio MCP transport only, so the runtime ones were never on an executed code path.
- **Added dev dependencies for the dashboard build** — `preact`, `htm`, and `esbuild` (devDependencies only; the runtime is bundled and inlined, so the published package gains no new runtime dependencies — it still ships only `@modelcontextprotocol/sdk`, `@napi-rs/keyring`, `commander`, `zod`).

### Notes
- **Breaking (dashboard):** the dashboard now returns `403` without the token. Bookmarked `http://127.0.0.1:9876` URLs must be replaced with the tokenized URL printed at launch.
- **Behavioral (governance):** if you run a single MCP server across multiple project roots with per-project policies, only the launch directory's `.q-ring.json` policy now applies.
- Version propagated to the Cursor plugin, marketplace metadata, and SECURITY.md via `pnpm run sync-versions`.

## [0.11.7] — 2026-04-27

### Changed
- **MCP tool descriptions overhauled for Glama TDQS** — every one of the 44 MCP tools now ships a 3-sentence description hitting all six [Tool Definition Quality Score](https://glama.ai/blog/2026-04-03-tool-definition-quality-score-tdqs) dimensions (purpose, when-to-use vs. siblings, side effects/audit/network, parameter semantics, conciseness, returns). Common parameter schemas (`scope`, `projectPath`, `env`, `teamId`, `orgId`) and per-tool Zod `.describe()` strings now include formats, defaults, and concrete examples to lift the per-tool minimum score (which dominates the server-level grade at 60% mean / 40% min). README MCP tables resynced with the new one-liners.
- **`feature-docs-sync.mdc` rule rewritten** — drops stale `web/components/...` globs (the marketing site was extracted to its own repo in 0.11.5) and replaces them with an explicit `quantum_ring` ↔ `qring.i4c.studio` cross-repo file mapping covering `lib/data/{features,mcp-tools,cli-commands,cli-reference,changelog,version}.ts`.
- **`release-process.mdc` rule** — `Downstream Sync` table now lists the marketing site, Cursor plugin, Kiro plugin, and Claude Code plugin alongside Glama, with explicit commands and a note that the marketing-site sync is not enforced by `quantum_ring` CI.

### Notes
- No runtime / MCP wire-format changes — this is a documentation-quality release. Existing agents and integrations will see longer, clearer tool descriptions and richer parameter help when they next refresh `tools/list`, but tool names, parameter names, and return shapes are unchanged.
- After publish, trigger a Glama re-sync from the admin panel so the new descriptions feed the next TDQS scoring run.

## [0.11.5] — 2026-04-27

### Added
- **Kiro Power pack** (`kiro-plugin/`) — steering files, hook templates, and `mcp.json` for [Kiro](https://kiro.dev); `pnpm run plugin:sync:kiro` copies into `~/.kiro` or a project `.kiro` path.
- **Claude Code plugin** (`claude-code-plugin/`) — `CLAUDE.md`, project `.mcp.json`, agents, slash commands, skills, and hooks; `pnpm run plugin:sync:claude` for project install or `--user` for `~/.claude`.

### Removed
- **In-repo marketing site (`web/`)** — the embedded Next.js app was removed from this repository; public docs and marketing are served from **https://qring.i4c.studio**. Removed GitHub Actions workflows `deploy-pages.yml` and `nextjs.yml`, and the `web:extract-repo` script.

### Changed
- **`package.json` `homepage`** — now `https://qring.i4c.studio`.
- **Cursor plugin / marketplace metadata** — logo URL points at repo-root `assets/logo.png` on GitHub raw (replacing deleted `web/public/` paths).
- **README** — new “Editor plugins” section for Cursor, Kiro, and Claude Code, including sync commands and contributor notes.
- **`.gitignore`** — ignore `marketing/` and `local/` for local-only drafts.
- **MCP tool descriptions** — clearer operator guidance for `detect_anomalies`, `health_check`, `remove_hook`, `set_secret`, `delete_secret`, `entangle_secrets`, `disentangle_secrets`, and `agent_scan` (read-only versus mutating behavior and related tools).

## [0.11.0] — 2026-04-25

### Changed
- **Marketing site overhauled (`web/`)** — replaced the hand-rolled landing/docs/changelog with a full HeroUI v3 + HeroUI Pro implementation backed by Tailwind v4 and `lucide-react`. New surfaces: hero with social-card art and install picker, TrustStrip KPIs (locale-stable), WhyQRing comparison, IntegrationsCarousel, LiveDemo terminal driving a global ⌘K CommandPalette, AgentMode, CursorPlugin showcase, FAQ, FreeCallout, FinalCta. Docs page gains a pinned Floating TOC with manual scroll-spy and a copy-to-clipboard MCP prompt cookbook. Navbar contrast lifted, custom hash navigation handles same-page anchors and home-link scroll-to-top in App Router. Background tokens darkened for better text contrast over the WebGL backdrop.
- **Status dashboard rebuilt** — `qring status` (and the `status_dashboard` MCP tool) now serves a denser, more useful live page. New surfaces:
  - **KPI strip** — total secrets, detected env, protected count, active approvals, hooks (enabled / total), 24-hour read & write counts, denied-action count, and live anomaly count.
  - **Manifest panel** — declared / required / missing / expired / stale keys from `.q-ring.json`.
  - **Policy panel** — at-a-glance MCP / exec / secret-policy presence with allow-deny / approval / rotation counts.
  - **Approvals panel** — every grant with scope, reason, time-remaining, and tamper / expiry state.
  - **Hooks panel** — every registered shell / HTTP / signal hook with its `key` / `tag` / `event` match summary.
  - **Agent memory panel** — count of encrypted memory keys.
  - **Sortable + searchable secrets table** — key / scope / env / type / decay / tags / last-read columns with quick chips (`expired`, `stale`, `protected`) and a `/`-focusable search box.
  - **Audit log filters** — action chips (`read` / `write` / `delete` / `export`), source chips (`cli` / `mcp` / `hook` / `agent`), and a free-text filter.
  - **Top-bar controls** — pause SSE updates, force refresh, jump to raw JSON, and a relative "updated Ns ago" timestamp that keeps ticking while paused.
  - **Keyboard shortcuts** — `/` focus secrets search, `P` pause, `R` refresh, `Esc` blur.
- **Snapshot payload expanded** — `/api/status` and the SSE stream now also include `version`, `projectPath`, `scopes`, `protectedCount`, `manifest`, `policy`, `approvals`, `hooks`, `memoryKeys`, and `auditMetrics` (action / source counts, top read keys, total events in the last 24h).

### Fixed
- **Dashboard search input no longer loses focus** — the SSE re-render now uses a focus-preserving DOM swap that retains caret position, selection, and scroll offset across the 5-second tick (previously, typing a search term would be wiped out on every snapshot).

## [0.10.1] — 2026-04-24

### Fixed
- **Publish workflow** — removed the `npm install -g npm@latest` bootstrap step that crashed with `Cannot find module 'promise-retry'` on the Node 22 runner image. The bundled npm from `setup-node@v4` is sufficient for `npm publish --provenance --access public`. This bug had silently blocked the v0.9.9 and v0.10.0 publish runs (both were tagged on GitHub but never reached npm).
- **Publish workflow** — added a `workflow_dispatch` trigger with an optional `ref` input so a stuck release can be re-published from the Actions tab without re-tagging.

### Notes
- Functional code is unchanged from v0.10.0; the bump exists solely to ship a new npm artifact through the now-fixed pipeline. v0.10.0's tag and GitHub Release stay in place for traceability.

## [0.10.0] — 2026-04-24

### Security
- **Approval HMAC widened** — `computeHmac` now covers `workspace` and `sessionId` in addition to id/key/scope/reason/grantedBy/grantedAt/expiresAt, so tampering with workspace- or session-bound approvals is detected and tokens are rejected as `tampered`.
- **Approval HMAC timing-safe compare** — verification uses `crypto.timingSafeEqual` on fixed-length hex digests to reduce timing leakage.
- **Approval registry directory mode** — `~/.config/q-ring/` is created with explicit `mode: 0o700` for both the HMAC secret and the approvals registry.
- **JIT HTTP SSRF** — `checkJitHttpProvisionUrl` performs synchronous `dns.lookupSync` for non–IP-literal hostnames, blocks non-`http(s)` URLs, and **fails closed** on DNS errors (closes the “sync check passes hostname, child resolves to private” gap).
- **Teleport AES-GCM** — new bundles use a **12-byte** IV (recommended nonce length); unpacking unchanged for existing bundles.
- **Registry file permissions** — `entanglement.json` and `hooks.json` writes use mode `0o600`.
- **Shell hooks** — `exec` replaced with `execFile` (`/bin/sh -c` / Windows `cmd /d /s /c`) with bounded stdout buffer; signal hooks require a strict numeric PID or a constrained `pgrep -f` pattern (no spaces / metacharacters).

### Added
- **CLI decomposed by category** — replaced the monolithic `register-cli-part{1,2,3}.ts` files with nine themed modules under `src/cli/commands/` (`secrets`, `project`, `quantum`, `validation`, `tooling`, `audit`, `hooks`, `agent`, `security`) plus shared `helpers.ts` / `options.ts`.
- **MCP tools decomposed by category** — split the 1.5k-line `tool-registration.ts` into ten focused modules under `src/mcp/tools/` (`secrets`, `project`, `tunnel`, `teleport`, `validation`, `tooling`, `audit`, `hooks`, `agent`, `policy`) with a shared `_shared.ts` for Zod schemas and policy enforcement helpers.
- **Grouped CLI help** — custom `GroupedHelp` renderer displays commands under nine themed sections (Secrets, Project, Quantum, Validation & Rotation, Dev Tooling, Audit & Health, Hooks, Agent Memory, Security & Governance) with glyph headers and dimmed ungrouped fallback.
- `src/version.ts` — single `PACKAGE_VERSION` from `package.json` for CLI + MCP.
- `src/services/list-secrets-filter.ts` — shared glob/tag filtering used by CLI and MCP.
- Global `--json` flag + `qring get --raw`; bracketed MCP tool tags; JSON payloads for several tools; `get_policy_summary` policy-gated.
- `docs/cli-mcp-parity.md` — full CLI ↔ MCP command/tool mapping, with notes on shared behavior, intentional differences, and remaining CLI-only / MCP-only functionality.
- Cursor plugin: `/qring:dashboard`, `/qring:analyze`, `/qring:exec-safe`; `exec-with-secrets` skill; hook tweaks; `pnpm run plugin:sync` + `docs:publish-log` scripts.
- ESLint + Prettier (`pnpm run lint`, `pnpm run format`); CI runs lint on `main`/`develop` pushes.
- New tests: `keyring-lifecycle.test.ts`, `ssrf-jit.test.ts`, and an approval-tamper test that asserts the widened HMAC rejects forged `workspace` / `sessionId` fields (164 total tests across 24 files).

### Changed
- `get` CLI default output is JSON; use `--raw` for legacy stdout-only value.
- MCP: `get_secret`, `list_secrets`, `tunnel_*` create/read, `generate_secret` (unsaved), `agent_recall` return structured JSON text.
- `teleport_unpack` errors expose machine-readable `ERR_TELEPORT_*` messages (MCP returns JSON error object).
- Renamed `httpRequest_` → `httpRequest` across `src/utils/http-request.ts` and call sites (`core/hooks.ts`, `core/validate.ts`); the underlying `node:http` request is now imported as `httpRequestPlain` to avoid the shadowing that drove the old underscore suffix.

### Fixed
- `policy.secrets` is now enforced on `setSecret` via `checkSecretLifecyclePolicy`.
- JIT envelope refresh uses cross-process file lock under `~/.config/q-ring/jit-locks/`.
- `queryAudit` reads at most the last 12MB of `audit.jsonl` to cap memory.
- `matchGlob` ignores overlong branch patterns.
- `parseEnvelope` / teleport bundles validated with Zod; `checkDecay` handles invalid dates.
- JIT HTTP / AWS configs validated with Zod in `provision.ts`.
- Shared secret detection for `scan` + `lint` via `secrets-detect.ts`.
- Removed dead `src/services/types.ts` (`ServiceResult`/`okResult`/`errResult` were never imported) and the `void listSecrets;` tree-shake workaround in the MCP project tools.
- Silenced unused-parameter warnings in `src/core/exec.ts` (`_encoding`) and `src/core/keyring.ts` (`_match`) so `--noUnusedParameters` stays clean.

## [0.9.9] — 2026-03-25

### Security
- **hono >=4.12.12** — pnpm override resolving 5 medium vulnerabilities (cookie name bypass, setCookie validation, IPv4-mapped IPv6 in ipRestriction, serveStatic traversal, toSSG path traversal) in transitive dependency via `@modelcontextprotocol/sdk`.
- **@hono/node-server >=1.19.13** — pnpm override resolving serveStatic bypass in transitive dependency via `@modelcontextprotocol/sdk`.
- **vite >=8.0.5** — pnpm override resolving 3 vulnerabilities (2 high: fs.deny bypass + WebSocket file read; 1 medium: optimized deps .map traversal) in dev dependency via `vitest`.

## [0.9.8] — 2026-03-25

### Security
- **SSRF protection expanded** — extracted `checkSSRF` into shared `src/core/ssrf.ts` module; applied async guard to `validate.ts` (httpProvider) and sync guard to `provision.ts` (JIT HTTP provider). Blocks requests to private/loopback/link-local addresses.
- **Shell injection fix** — replaced `exec("pgrep -f ...")` with `spawn("pgrep", ["-f", target])` in `hooks.ts` to prevent shell metacharacter injection in signal hook targets.
- **Dashboard XSS fix** — `renderAudit` now escapes `e.action` through `esc()` in both class attributes and text content, preventing script injection via audit log entries.
- **MCP policy enforcement** — `listSecrets`, `exportSecrets`, `hasSecret`, `deleteSecret`, and `getEnvelope` now enforce `checkKeyReadPolicy` when `source === "mcp"`, closing a policy bypass for all read/write operations.
- **Tunnel ID crypto hardening** — replaced `Math.random()` with `crypto.randomBytes()` for tunnel ID generation, ensuring CSPRNG-quality identifiers.
- **Memory key hardening** — AES-256-GCM encryption key now stored in OS keyring (`@napi-rs/keyring`) instead of derived from `SHA-256(hostname+username)`. Includes automatic migration from legacy key derivation and fallback for environments without keyring access.
- **Glob-to-regex escaping** — regex metacharacters (`.+?^${}()|[]\\`) are now escaped before `*` → `.*` conversion in both `mcp/server.ts` (list_secrets filter) and `hooks.ts` (keyPattern matching), preventing ReDoS and unintended matches.
- **Exec profile hardening** — `denyCommands` matching upgraded from substring (`includes`) to word-boundary regex, preventing false positives and evasion via embedded substrings.
- **Dependency overrides** — added `path-to-regexp >=8.4.0` (root) pnpm override to resolve known vulnerability. `brace-expansion` in web is an upstream ESLint transitive dependency (minimatch@3 → brace-expansion@1) and cannot be overridden without breaking the API.
- **CSP meta tag** — added `Content-Security-Policy` meta tag to `web/app/layout.tsx` for defense-in-depth on GitHub Pages (where HTTP headers aren't configurable).

### Added
- **`src/core/ssrf.ts`** — new shared module exporting `isPrivateIP`, `checkSSRF` (async with DNS resolution), and `checkSSRFSync` (sync, IP-literal only).
- **SSRF test suite** — 12 tests covering private IP detection, async/sync SSRF guards, IPv4/IPv6/mapped addresses, and environment variable override.
- **Tunnel ID uniqueness test** — verifies 100 generated IDs are unique and match base64url suffix pattern.

## [0.9.7] — 2026-03-26

### Fixed
- **Nav anchor links on subpages** — clicking Features, Quick Start, Plugin, Dashboard, MCP, or Architecture from `/docs` or `/changelog` now routes back to the homepage before scrolling to the target section. Replaced plain `<a>` tags with Next.js `<Link>` for proper client-side navigation.

## [0.9.6] — 2026-03-26

### Security
- **Double-escaping fix** — `parseDotenv()` escape-sequence chain replaced with single-pass regex to prevent double-unescape of backslash sequences (CodeQL `js/double-escaping` alert #14, severity: high).
- **picomatch >=4.0.4 (web)** — pnpm override added to `web/package.json` resolving ReDoS (GHSA-c2c7-rcm5-vvqj) and method injection (GHSA-3v7f-55p6-f55p) in web lockfile.
- **Stale `package-lock.json` removed** — eliminated false-positive Dependabot alerts from an unused npm lockfile; added to `.gitignore`.

### Added
- **`parseDotenv` test suite** — 8 unit tests covering escape sequences, double-backslash handling, quoted values, inline comments, and edge cases (133 total tests).

## [0.9.5] — 2026-03-26

### Added
- **Cursor marketplace plugin** — `cursor-plugin/` with 3 rules, 4 skills, 2 agents, 5 commands, 2 hooks, MCP connector, and marketplace manifest. Surfaces all 44 MCP tools through IDE-native components.
- **Marketplace discovery** — `.cursor-plugin/marketplace.json` at repo root for monorepo-based plugin resolution.
- **Web: Cursor Plugin section** — homepage component with animated cards for all plugin components.
- **Web: Plugin nav link** — "Plugin" added to site navigation.
- **Web: Homebrew install tabs** — Homebrew option added to Hero and docs install commands.
- **README: Cursor Plugin section** — table summarizing all plugin components with marketplace install instructions.
- **README: Homebrew install** — `brew install i4ctime/tap/qring` added to Installation section.

### Changed
- **Web: docs page** — Step 4 added for Cursor Plugin with component grid and manual install terminal.
- **Web: Footer** — version updated from v0.9.1 to v0.9.4.

### Fixed
- **beforeShellExecution hook removed** — Cursor injects base64 metadata into hook commands, causing a circular block. Shell command warnings moved to the `secret-hygiene` rule instead.

### Security
- **picomatch >=4.0.4** — pnpm override added to resolve ReDoS vulnerability (GHSA-c2c7-rcm5-vvqj) and method injection (GHSA-3v7f-55p6-f55p) in `tsup > tinyglobby > picomatch`.

## [0.9.4] — 2026-03-25

### Added
- **Vitest test suite** — 125 tests across 17 files covering core modules (noise, envelope, tunnel, teleport, entanglement, scan, linter, memory, hooks, approval, observer, policy, collapse, scope), CLI command registration, and MCP tool registration (all 44 tools verified).
- **CI test step** — `pnpm run test:ci` added to `ci.yml` workflow after the build step.
- **Homebrew tap** — `I4cTime/homebrew-tap` repo with `Formula/qring.rb` for `brew tap I4cTime/tap && brew install qring`.
- **Homebrew auto-update workflow** — `update-homebrew.yml` triggers on release, waits for npm availability, computes sha256, and pushes the updated formula automatically.

## [0.9.3] — 2026-03-25

### Changed
- **Custom domain** — site now served at `qring.i4c.studio` instead of `i4ctime.github.io/quantum_ring`. Removed `basePath`, updated all asset paths and metadata.
- **Funding** — Ko-fi slug updated to `i4ctime`.
- **Favicon** — icon metadata added to layout for branded browser/Apple touch icons.
- **Deploy workflow** — CNAME file persists across `gh-pages` deploys.

## [0.9.2] — 2026-03-24

### Changed
- **README** — improved intro with structured feature list, added documentation link callout, replaced broken Glama badge with card layout, added License and MCP Tools badges, corrected MCP tool count from 31 to 44.
- **Docs page** — added short descriptions to every CLI command in the web reference.
- **Repo settings** — added CODEOWNERS, updated branch rulesets to require `check` + `analyze` status checks and code owner review, disabled default CodeQL setup.

## [0.9.1] — 2026-03-24

### Changed
- **CHANGELOG** — added missing Tier 4–6 feature entries (composite secrets, approvals, JIT, exec, scanner, linter, memory, context, governance, scopes, rotation, CI validation, audit export) to the v0.9.0 record.
- **Web landing site** — added 11 feature cards, 3 MCP tool groups (15 tools), 8 architecture modules; updated tool count from 31 to 44 and feature count from 13 to 24.
- **Web changelog** — synced with CHANGELOG.md.
- **Stats** — removed Tiers and Platforms cards; kept MCP Tools and Quantum Features.

## [0.9.0] — 2026-03-22

### Added
- **Composite / Templated Secrets** — store connection strings with `{{OTHER_KEY}}` placeholders that resolve dynamically on read. MCP tool: `get_secret` (template resolution is automatic).
- **User Approvals (Zero-Trust Agent)** — mark secrets with `--requires-approval` so MCP reads require HMAC-verified, scoped, time-limited approval tokens. CLI: `qring approve`, `qring approvals`. MCP: approval enforcement on `get_secret`.
- **JIT Provisioning** — dynamically generate short-lived tokens on read (AWS STS, Generic HTTP). CLI: `qring set --jit-provider aws-sts`. MCP: automatic JIT resolution on `get_secret`.
- **Secure Execution & Auto-Redaction** — `qring exec` injects secrets into command environments with automatic stdout/stderr redaction of known values. Exec profiles restrict allowed commands.
- **Exec Profiles** — `unrestricted`, `restricted` (blocks curl/wget/ssh, 30s timeout), and `ci` (5min timeout) profiles for `qring exec --profile`. MCP tool: `exec_with_secrets`.
- **Codebase Secret Scanner** — `qring scan` detects hardcoded credentials using regex heuristics and Shannon entropy analysis. MCP tool: `scan_codebase_for_secrets`.
- **Secret-Aware Linter** — `qring lint` scans specific files for hardcoded secrets with optional `--fix` to auto-replace with `process.env.KEY` references. MCP tool: `lint_files`.
- **Agent Memory** — encrypted, persistent key-value store for AI agent sessions. CLI: `qring remember`, `qring recall`, `qring forget`. MCP tools: `agent_remember`, `agent_recall`, `agent_forget`.
- **Project Context** — safe, redacted overview of project secrets, configuration, and state for agent system prompts. CLI: `qring context`. MCP tool: `get_project_context`.
- **Pre-Commit Secret Scanning** — `qring hook:install` adds a git pre-commit hook that blocks commits containing hardcoded secrets.
- **Secret Analytics** — `qring analyze` reports most accessed, unused, stale secrets and gives rotation recommendations. MCP tool: `analyze_secrets`.
- **Service Setup Wizard** — `qring wizard` scaffolds a new service integration with secrets, manifest entries, and hooks in one command.
- **Governance Policy** — `.q-ring.json` `policy` section for MCP tool gating, key access restrictions, exec allowlists, and secret lifecycle rules. CLI: `qring policy`. MCP tools: `check_policy`, `get_policy_summary`.
- **Team & Org Scopes** — `--team` and `--org` flags extend resolution beyond `global` and `project`. Cascade order: project → team → org → global.
- **Issuer-Native Rotation** — `qring rotate` attempts provider-native rotation (OpenAI, Stripe, etc.) or falls back to local generation. MCP tool: `rotate_secret`.
- **CI Secret Validation** — `qring ci:validate` batch-validates all secrets against providers in CI-friendly mode with structured pass/fail output. MCP tool: `ci_validate_secrets`.
- **Tamper-Evident Audit Verify & Export** — `qring audit:verify` checks SHA-256 hash chain integrity; `qring audit:export` outputs jsonl/json/csv. MCP tools: `verify_audit_chain`, `export_audit`.
- **Shared HTTP client** (`http-request`) for validation and hooks with timeouts and response size limits.
- **HTTP hook SSRF mitigation** — resolves hook URLs and blocks private/loopback targets by default; override with `Q_RING_ALLOW_PRIVATE_HOOKS=1` if needed. Denied attempts emit `policy_deny` audit events.
- **Next.js GitHub Pages site** (`web/`) — Tailwind CSS v4, Motion animations, Getting Started (`/docs`) and Changelog (`/changelog`) pages, mobile nav, copyable terminals, animated stats, interactive architecture diagram. Deploy via `deploy-pages.yml` and CI via `nextjs.yml`.

### Changed
- MCP server tool count increased from 31 to 44.
- Architecture expanded with Exec, Scan, Provision, Approval, Context, Linter, Memory, and Policy subsystems.
- **Dashboard** — pathname routing fixes, SSE backpressure, tighter CORS, inline/system fonts and assets for offline use.
- **README** — notes on SSRF protection for HTTP hooks.

## [0.4.0] — 2026-03-22

### Added
- **Secret Liveness Validation** — `qring validate` tests if a secret is actually valid with its target service. Built-in providers for OpenAI, Stripe, GitHub, AWS, and Generic HTTP with auto-detection from key prefixes. MCP tools: `validate_secret`, `list_providers`.
- **Hooks on Secret Change** — register shell commands, HTTP webhooks, or process signals that fire when secrets are written, deleted, or rotated. CLI: `qring hook add/list/remove/enable/disable/test`. MCP tools: `register_hook`, `list_hooks`, `remove_hook`.
- **`.env` file import** — `qring import .env` parses dotenv syntax and bulk-stores secrets. MCP tool: `import_dotenv`.
- **Project Secret Manifest** — declare required secrets in `.q-ring.json` and validate with `qring check`. MCP tool: `check_project`.
- **Env File Sync** — `qring env:generate` produces a `.env` from the project manifest. MCP tool: `env_generate`.
- **Disentangle command** — `qring disentangle` exposes the existing core function to CLI and MCP.
- **Selective Export** — `qring export --keys` and `--tags` filter which secrets are exported. Same filters on MCP `export_secrets`.
- **branchMap glob support** — `.q-ring.json` branchMap now supports `*` wildcards (e.g. `release/*`).
- **Configurable rotation** — `--rotation-format` and `--rotation-prefix` on `qring set` control auto-rotation shape.
- **Secret search/filtering** — `qring list --tag`, `--expired`, `--stale`, `--filter` flags.
- **Provider metadata** — `provider` field on `SecretMetadata` and `ManifestEntry` for validation auto-detection.

### Changed
- MCP server tool count increased from 20 to 31.
- Architecture expanded with Validate, Hooks, and Import subsystems.

## [0.3.2] — 2026-03-21

### Security
- Resolved 8 CodeQL `js/clear-text-logging` alerts by sanitizing keyring metadata before CLI output.

## [0.3.1] — 2026-03-21

### Fixed
- **Dashboard re-rendering** — Cards are now created once and updated in-place via differential DOM patching. No more flickering or re-animation on every SSE tick.
- **Audit log noise** — `qring list` calls from the dashboard no longer generate audit entries (silent mode) and `list` events are filtered from the dashboard feed.

### Changed
- **Increased dashboard font sizes** — Base font bumped from 14px to 16px; all panel text sizes proportionally increased for readability.
- **Header icon** — Replaced inline SVG with the project icon from gh-pages (`icon.png`).
- **README** — Added Quantum Status Dashboard section with CLI usage and flags; added Dashboard to architecture diagram.

## [0.3.0] — 2026-03-21

### Added
- **Quantum Status Dashboard** — `qring status` launches a local browser dashboard with live SSE updates showing health summary, decay timers, superposition states, entanglement graph, active tunnels, audit log, anomaly alerts, and environment detection.
- **MCP `status_dashboard` tool** — AI agents can start the dashboard server and return the URL.
- **MCP Registry support** — `server.json` and `mcpName` field for publishing to `registry.modelcontextprotocol.io`.
- **GitHub issue templates** — bug report and feature request forms.
- **SECURITY.md** — vulnerability disclosure policy.

### Changed
- Fixed shebang (`#!/usr/bin/env node`) now present on both `dist/index.js` and `dist/mcp.js`.
- Corrected `bin` paths in `package.json` per npm standards.

## [0.2.9] — 2026-03-21

### Changed
- Added `mcpName` field to `package.json` for MCP Registry compatibility.
- Fixed `tsup.config.ts` to add shebang to `dist/mcp.js`.

## [0.2.7] — 2026-03-20

### Added
- Initial public release with quantum keyring core, MCP server (20 tools), and CLI.
- Superposition, entanglement, tunneling, teleportation, decay, observer, and agent features.
- GitHub Pages landing site.
- Glama integration with `glama.json` and Dockerfile.
