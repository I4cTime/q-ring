---
name: "q-ring"
displayName: "q-ring — quantum keyring for AI agents"
description: "Secure secrets in the OS keychain with superposition, entanglement, audit trails, and 44 MCP tools — store and retrieve API keys, scan for leaks, rotate credentials, and enforce policy without pasting secrets into .env or chat."
keywords:
  - "q-ring"
  - "qring"
  - "secrets"
  - "api key"
  - "api keys"
  - "credentials"
  - "environment variables"
  - "dotenv"
  - ".env"
  - "keyring"
  - "MCP"
  - "token"
  - "password"
  - "rotation"
  - "secret scanning"
  - "vault"
author: "I4cTime"
---

# q-ring Power for Kiro

This power follows the official [Create powers](https://kiro.dev/docs/powers/create/) layout: `POWER.md`, root `mcp.json`, and `steering/`. Optional workspace hooks live in `hooks/` for onboarding copy into `.kiro/hooks/`.

The MCP server key in `mcp.json` is **`q-ring`**. Kiro may namespace it when the power loads; refer to whatever server name appears in the MCP panel when calling tools.

## Onboarding

### Step 1: Install q-ring and verify MCP

The power expects the q-ring CLI and MCP binary on your `PATH`:

```bash
pnpm add -g @i4ctime/q-ring
# or: npm install -g @i4ctime/q-ring
# or: brew install i4ctime/tap/qring
```

Verify:

```bash
qring-mcp --help
```

**CRITICAL:** If `qring-mcp` is not found, do **not** pretend q-ring tools work — tell the user to install `@i4ctime/q-ring` globally (or run from a local `q-ring` clone with `node dist/mcp.js`) and reload MCP in Kiro.

### Step 2: Add this folder as a Kiro Power (recommended)

1. Open Kiro → **Powers** panel → **Add power from Local Path**.
2. Select the `kiro-plugin` directory from the [q-ring](https://github.com/I4cTime/q-ring) repository (the folder that contains `POWER.md`, `mcp.json`, and `steering/`).
3. Confirm the power activates when the user mentions secrets, `.env`, API keys, or q-ring (see `keywords` in frontmatter).

To share publicly: push the `kiro-plugin/` tree to a public GitHub repo and others can use **Add power from GitHub** per [Create powers — Sharing your power](https://kiro.dev/docs/powers/create/). Curated community powers are listed at [github.com/kirodotdev/powers](https://github.com/kirodotdev/powers).

### Step 3 (optional): Workspace hooks

Copy the JSON hook files from this power’s `hooks/` directory into the workspace `.kiro/hooks/` if the user wants save-time linting and `.env` guards:

- `hooks/qring-scan-on-save.kiro.hook` — after saving source files, suggest `lint_files` for hardcoded secrets.
- `hooks/qring-env-file-edit.kiro.hook` — after editing `.env*`, suggest `import_dotenv` and `.gitignore` checks.
- `hooks/qring-session-init.kiro.hook` — manual button to run `get_project_context`.

If copying fails or the schema changes, recreate the same prompts from the hook `then.prompt` fields in the Kiro **Agent Hooks** UI.

### Alternative: Flatten into `~/.kiro` (no Power UI)

From the `q-ring` repo root:

```bash
pnpm run plugin:sync:kiro
```

This copies `mcp.json` → `~/.kiro/settings/mcp.json`, plus `steering/` and `hooks/` into the user’s `.kiro` tree. Use `--force` to overwrite an existing `mcp.json`, or merge the generated `mcp.json.qring-template` by hand.

## When to load steering files

Use the steering files under `steering/` for focused context. Reference them with `#filename` in chat (without `.md`) when you need that workflow, or rely on `inclusion: always` / `fileMatch` files when this power is installed into `.kiro/steering/` via `plugin:sync:kiro`.

| Situation | Steering file |
|-----------|----------------|
| Always-on secret hygiene (never hardcode) | `qring-secret-hygiene.md` |
| Always-on MCP / workflow for q-ring | `qring-workflow.md` |
| User has `.env` or `.env.*` open | `qring-env-file-safety.md` |
| Day-to-day store / retrieve / tunnels / teleport | `qring-secret-ops.md` |
| Audit, anomalies, policy, leak scan | `qring-security-auditor.md` |
| CRUD, import/export, superposition, entanglement | `qring-secret-management.md` |
| Scan or lint repo for hardcoded secrets | `qring-secret-scanning.md` |
| Health, validate, rotate, CI checks | `qring-secret-rotation.md` |
| `.q-ring.json`, manifest, hooks, policy | `qring-project-onboarding.md` |
| Run commands with injected + redacted env | `qring-exec-with-secrets.md` |
| Command-style: scan repo | `qring-cmd-scan-secrets.md` |
| Command-style: health report | `qring-cmd-health-check.md` |
| Command-style: rotate expired/stale | `qring-cmd-rotate-expired.md` |
| Command-style: bootstrap project | `qring-cmd-setup-project.md` |
| Command-style: teleport bundle | `qring-cmd-teleport-secrets.md` |
| Command-style: status dashboard | `qring-cmd-dashboard.md` |
| Command-style: exec with redaction | `qring-cmd-exec-safe.md` |
| Command-style: usage analytics | `qring-cmd-analyze.md` |

## Best practices (summary)

- Prefer q-ring MCP tools (`get_secret`, `set_secret`, `scan_codebase_for_secrets`, …) over pasting secrets into chat or plain-text `.env` files.
- Call `get_project_context` before bulk secret work to get a redacted manifest/policy view.
- For one-off values, use `tunnel_create`; for machine-to-machine transfer, use `teleport_pack` / `teleport_unpack`.

Full install notes and tables live in [`README.md`](README.md) in this directory.

## License and support

This power integrates with the q-ring MCP server (AGPL-3.0-only).

- [Privacy Policy](https://github.com/I4cTime/q-ring/blob/main/PRIVACY.md)
- [Support](https://discord.gg/5uEApw5uEz) — Discord, or email
  i4c.studio.dev@gmail.com, or [GitHub issues](https://github.com/I4cTime/q-ring/issues)
- [Security policy](https://github.com/I4cTime/q-ring/blob/main/SECURITY.md)
