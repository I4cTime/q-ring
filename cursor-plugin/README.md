# q-ring Cursor Plugin

OS keychain secrets for AI coding agents, over MCP — manage secrets, scan for leaks, rotate keys, and enforce policy directly from Cursor.

> **Looking for another editor?** See the sister packs: [`kiro-plugin/`](../kiro-plugin/README.md) for [Kiro](https://kiro.dev) and [`claude-code-plugin/`](../claude-code-plugin/README.md) for [Claude Code](https://docs.claude.com/en/docs/claude-code/overview).

## Prerequisites

Install the q-ring CLI and MCP server globally:

```bash
# npm
npm install -g @i4ctime/q-ring

# Homebrew
brew install i4ctime/tap/qring
```

Verify the MCP server is available:

```bash
qring-mcp --help
```

## What's Included

### Rules (always active)

| Rule | Purpose |
|------|---------|
| `secret-hygiene` | Never hardcode secrets — always use q-ring |
| `qring-workflow` | Use q-ring MCP tools for all secret operations |
| `env-file-safety` | Warn about `.env` files, suggest importing into q-ring |

### Skills (auto-triggered by context)

| Skill | Triggers On |
|-------|-------------|
| `secret-management` | Mentions of secrets, API keys, tokens, credentials, `.env` files |
| `secret-scanning` | Requests to scan, lint, audit, or find leaked credentials |
| `secret-rotation` | Expired keys, rotation, validation, CI checks |
| `project-onboarding` | New project setup, manifests, environment detection |

### Agents (specialized personas)

| Agent | Purpose |
|-------|---------|
| `security-auditor` | Proactive security monitoring — audit trails, anomalies, governance |
| `secret-ops` | Day-to-day secret management — store, share, organize |

### Commands (explicit invocations)

| Command | Action |
|---------|--------|
| `/qring:scan-secrets` | Scan codebase for hardcoded secrets, offer auto-fix |
| `/qring:health-check` | Full health report — decay, anomalies, audit integrity |
| `/qring:rotate-expired` | Find and rotate expired/stale credentials |
| `/qring:setup-project` | Initialize q-ring — manifest, imports, hooks |
| `/qring:teleport-secrets` | Encrypted cross-machine secret transfer |

### Hooks (automatic)

| Event | Behavior |
|-------|----------|
| `afterFileEdit` | Scan edited files for hardcoded secrets |
| `sessionStart` | Load project context and note expired secrets |

### MCP Server

The plugin connects to the `qring-mcp` server via stdio transport, providing access to all 44 q-ring MCP tools for secret management, scanning, rotation, auditing, and governance.

## Installation

Install from the Cursor marketplace, or clone the plugin directory:

From the `q-ring` repo root (after `pnpm install`):

```bash
pnpm run plugin:sync
```

This copies `cursor-plugin/` to `~/.cursor/plugins/local/my-plugin` by default. Pass a custom destination as the first argument if needed.

## Configuration

The plugin works out of the box with default settings. For project-specific configuration, create a `.q-ring.json` manifest in your project root:

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

Or run `/qring:setup-project` to create one interactively.

## License

AGPL-3.0-only — same as the [@i4ctime/q-ring](https://www.npmjs.com/package/@i4ctime/q-ring) npm package and [q-ring](https://github.com/I4cTime/q-ring) repository.
