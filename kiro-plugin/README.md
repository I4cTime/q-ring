# q-ring Kiro Power

Quantum keyring for AI agents — manage secrets, scan for leaks, rotate keys, and enforce policy directly from [Kiro](https://kiro.dev).

This directory is a Kiro **Power** as defined in [Create powers](https://kiro.dev/docs/powers/create/):

| Required / optional | File or folder | Role |
|---------------------|----------------|------|
| Required | [`POWER.md`](POWER.md) | Frontmatter (`name`, `displayName`, `description`, `keywords`, `author`), onboarding, steering map |
| Optional | [`mcp.json`](mcp.json) | MCP server config — server key **`q-ring`** matches tool references in steering |
| Optional | [`steering/`](steering/) | Workflow-specific guidance (same content as before; `inclusion` applies when synced to `.kiro/steering/`) |
| Optional | [`hooks/`](hooks/) | Agent hook JSON — copy into workspace `.kiro/hooks/` during onboarding |

It mirrors the q-ring [Cursor plugin](../cursor-plugin/README.md) for Kiro’s [MCP](https://kiro.dev/docs/mcp/), [steering](https://kiro.dev/docs/steering/), and [hooks](https://kiro.dev/docs/hooks/).

## Prerequisites

Install the q-ring CLI and MCP server globally:

```bash
# pnpm (recommended)
pnpm add -g @i4ctime/q-ring

# npm
npm install -g @i4ctime/q-ring

# Homebrew
brew install i4ctime/tap/qring
```

Verify the MCP server is on `PATH`:

```bash
qring-mcp --help
```

## What's Included

### MCP server (`mcp.json` at power root)

When you add this folder as a Power, Kiro loads [`mcp.json`](mcp.json) from the power root (per [Adding MCP servers](https://kiro.dev/docs/powers/create/)). It connects to the local `qring-mcp` binary over stdio so all 46 q-ring MCP tools are available — `get_secret`, `set_secret`, `scan_codebase_for_secrets`, `rotate_secret`, `health_check`, and so on.

If you use **`pnpm run plugin:sync:kiro`** instead, the same file is copied to **`.kiro/settings/mcp.json`** (Kiro’s user-level MCP location for a flattened install).

### Steering files (`steering/*.md` → `.kiro/steering/`)

Steering shapes Kiro's behavior the same way Cursor rules do. The frontmatter `inclusion` field controls when each file is loaded.

| Steering file | Inclusion | Purpose |
|---------------|-----------|---------|
| `qring-secret-hygiene.md` | `always` | Never hardcode secrets — always go through q-ring |
| `qring-workflow.md` | `always` | Use q-ring MCP tools for every secret operation |
| `qring-env-file-safety.md` | `fileMatch` (`**/.env*`) | Warn about `.env` files, suggest importing into q-ring |
| `qring-secret-ops.md` | `manual` | Agent persona — day-to-day secret operations |
| `qring-security-auditor.md` | `manual` | Agent persona — proactive monitoring & governance |
| `qring-secret-management.md` | `manual` | Skill — store/retrieve/list/inspect secrets |
| `qring-secret-scanning.md` | `manual` | Skill — scan and lint codebases for hardcoded secrets |
| `qring-secret-rotation.md` | `manual` | Skill — validate, rotate, and CI-check secrets |
| `qring-project-onboarding.md` | `manual` | Skill — create manifests, detect environments, register hooks |
| `qring-exec-with-secrets.md` | `manual` | Skill — run commands with secrets injected and redacted |
| `qring-cmd-scan-secrets.md` | `manual` | Slash-style command — scan & auto-fix |
| `qring-cmd-health-check.md` | `manual` | Slash-style command — full health report |
| `qring-cmd-rotate-expired.md` | `manual` | Slash-style command — rotate expired/stale credentials |
| `qring-cmd-setup-project.md` | `manual` | Slash-style command — initialize q-ring for a project |
| `qring-cmd-teleport-secrets.md` | `manual` | Slash-style command — encrypted cross-machine transfer |
| `qring-cmd-dashboard.md` | `manual` | Slash-style command — launch the live status dashboard |
| `qring-cmd-exec-safe.md` | `manual` | Slash-style command — exec with redaction |
| `qring-cmd-analyze.md` | `manual` | Slash-style command — usage analytics |

Manual steering files are activated by typing `#qring-secret-ops` (etc.) in the Kiro chat — Kiro will load that file into context for the conversation.

### Agent hooks (`hooks/*.kiro.hook` → `.kiro/hooks/`)

| Hook file | Trigger | Behavior |
|-----------|---------|----------|
| `qring-scan-on-save.kiro.hook` | File saved (source files) | Run `lint_files` MCP tool; warn and offer auto-fix when secrets are detected |
| `qring-env-file-edit.kiro.hook` | File saved (`.env*`) | Suggest `import_dotenv`; verify `.gitignore` covers `.env*` |
| `qring-session-init.kiro.hook` | Manual button | Run `get_project_context`; surface expired or stale secrets |

> Kiro's hook schema is still maturing. The `.kiro.hook` files in this directory are saved in the JSON format Kiro currently accepts; if Kiro fails to load them, recreate the same logic from the **Agent Hooks** UI using the prompts in each file as the hook body.

## Installation

### Recommended: Add as a Kiro Power (local path)

1. Install `@i4ctime/q-ring` globally and verify `qring-mcp --help` (see **Prerequisites** above).
2. Open Kiro → **Powers** → **Add power from Local Path**.
3. Select this **`kiro-plugin`** directory (the one containing `POWER.md` and `mcp.json`).

Test activation with phrases that match the keywords in `POWER.md` (e.g. “store this API key in q-ring”, “scan for secrets”, “rotate expired keys”). See [Testing locally](https://kiro.dev/docs/powers/create/).

### Share on GitHub

Push the `kiro-plugin/` tree to a **public** repository so others can use **Add power from GitHub** — see [Sharing your power](https://kiro.dev/docs/powers/create/).

### Alternative: Flatten into `~/.kiro` (no Power UI)

From the `q-ring` repo root:

```bash
pnpm install
pnpm run plugin:sync:kiro
```

This copies:

- `kiro-plugin/mcp.json` → `~/.kiro/settings/mcp.json` (user-level)
- `kiro-plugin/steering/` → `~/.kiro/steering/`
- `kiro-plugin/hooks/` → `~/.kiro/hooks/`

Pass a custom destination for a project-scoped flatten:

```bash
pnpm run plugin:sync:kiro -- /path/to/your/project/.kiro
```

If `settings/mcp.json` already exists, the script writes `mcp.json.qring-template` unless you pass `--force`. Merge the q-ring server block by hand or overwrite after review.

### Manual flatten (project-scoped)

```bash
mkdir -p .kiro/{settings,steering,hooks}
cp kiro-plugin/mcp.json            .kiro/settings/mcp.json
cp kiro-plugin/steering/*.md       .kiro/steering/
cp kiro-plugin/hooks/*.kiro.hook   .kiro/hooks/
```

Reload Kiro's MCP servers from the **MCP Servers** panel after copying.

## Configuration

The plugin works out of the box. For project-specific behavior, create a `.q-ring.json` manifest in your project root:

```json
{
  "env": "dev",
  "defaultEnv": "dev",
  "branchMap": {
    "main": "prod",
    "develop": "dev"
  },
  "secrets": {
    "DATABASE_URL": { "required": true, "description": "PostgreSQL connection string" },
    "API_KEY": { "required": true, "provider": "openai" }
  }
}
```

Or activate the manual steering file `#qring-cmd-setup-project` and let the agent walk you through it.

## License

AGPL-3.0-only — same as the [@i4ctime/q-ring](https://www.npmjs.com/package/@i4ctime/q-ring) npm package and [q-ring](https://github.com/I4cTime/q-ring) repository.
