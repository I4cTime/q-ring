# Quickstart: q-ring in Claude Code

Five minutes from zero to an agent that manages your secrets safely.

## 1. Install the CLI (once per machine)

```bash
pnpm add -g @i4ctime/q-ring     # or: npm i -g / brew install i4ctime/tap/qring
qring doctor                    # verify keyring backend + qring-mcp on PATH
```

## 2. Install the plugin

Inside Claude Code:

```
/plugin marketplace add I4cTime/q-ring
/plugin install qring@q-ring
```

That registers the MCP server (all 44 tools), 8 slash commands, 2 subagents, 6 skills, and 3 safety hooks in one step.

Prefer project-scoped files instead of a plugin? From a checkout of this repo: `pnpm run plugin:sync:claude -- /path/to/your/project`.

## 3. First five minutes

Store a key without pasting it into chat (the CLI prompts, masked):

```bash
qring set OPENAI_API_KEY        # value prompted, never in shell history or transcripts
```

Then drive everything from chat:

| Try | What happens |
|---|---|
| `/qring-setup-project` | Wizard: manifest, env detection, `.env` import, hooks |
| `/qring-scan-secrets` | Scans the codebase for hardcoded secrets, offers auto-fix |
| "Run the test suite — it needs `OPENAI_API_KEY`" | Agent uses `exec_with_secrets`: key injected, output redacted |
| "Is my Stripe key still valid?" | `validate_secret` liveness-checks it against the provider |
| `/qring-dashboard` | Live localhost dashboard (secrets health, audit log, entanglement graph) |

## 4. Guardrails you get automatically

- The **SessionStart hook** points the agent at `get_project_context` when a `.q-ring.json` exists.
- The **PreToolUse hook** asks for confirmation before shell commands that would print or commit `.env` files.
- Secrets stored with `--requires-approval` refuse agent reads until you run `qring approve KEY --for 3600 --reason "…"`.

## Troubleshooting

MCP server not showing up, keyring errors, approval confusion → [troubleshooting.md](troubleshooting.md). Full plugin reference → [claude-code-plugin/README.md](../claude-code-plugin/README.md).
