# Quickstart: q-ring in Cursor

## 1. Install the CLI (once per machine)

```bash
pnpm add -g @i4ctime/q-ring     # or: npm i -g / brew install i4ctime/tap/qring
qring doctor                    # verify keyring backend + qring-mcp on PATH
```

## 2. Install the plugin

From a checkout of this repo:

```bash
pnpm install
pnpm run plugin:sync            # copies cursor-plugin/ to ~/.cursor/plugins/local/my-plugin
```

Restart Cursor. You get the MCP server (all 46 tools), 3 always-on rules, 8 commands, 2 agents, 5 skills, and 3 natural-language hooks.

## 3. First five minutes

```bash
qring set OPENAI_API_KEY        # value prompted, masked — never in chat or history
```

Then in Cursor chat:

| Try | What happens |
|---|---|
| "Set up q-ring for this project" | Manifest, env detection, `.env` import, hooks |
| "Scan this repo for hardcoded secrets and fix them" | `scan_codebase_for_secrets` + auto-migration to q-ring |
| "Run the integration tests — they need `DATABASE_URL`" | `exec_with_secrets`: injected env, redacted output |
| "Which of my keys are expired or about to expire?" | `health_check` / decay report |
| "Show me the q-ring dashboard" | `status_dashboard` opens the live localhost view |

The rules keep the agent from ever writing secrets into code or `.env` files; the skills trigger on secret-related requests automatically.

## Troubleshooting

MCP server not connecting, keyring errors → [troubleshooting.md](troubleshooting.md). Full plugin reference → [cursor-plugin/README.md](../cursor-plugin/README.md).
