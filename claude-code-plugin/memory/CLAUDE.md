# Claude Code · Project Memory

> This file is loaded automatically into every Claude Code session in this project. It encodes the always-on q-ring rules. The agents, slash commands, and skills under `.claude/` extend this with on-demand behavior.

## q-ring · Secret hygiene (always)

- **Never** hardcode secrets, API keys, tokens, passwords, or connection strings in source code or config files.
- Store secrets using the q-ring MCP tool `set_secret` or the `qring set` CLI — not in `.env` files, inline strings, or comments.
- Reference secrets in code via `process.env.KEY` (JS/TS), `os.environ["KEY"]` (Python), or the language equivalent. The actual value lives in q-ring.
- When reviewing or writing code, flag any string that matches common credential patterns (`sk-*`, `ghp_*`, `Bearer *`, long base64 blobs, connection strings with passwords).
- If you spot a hardcoded secret, run `scan_codebase_for_secrets` followed by `lint_files` with `fix: true` to migrate it into q-ring.
- Secrets with a TTL or rotation format should always be stored with `ttlSeconds` or `rotationFormat` so q-ring can track decay and automate rotation.
- When a shell command would contain a secret value (long base64, `sk-*`, `ghp_*`, etc.), warn the user that secrets must not appear in shell history. Suggest the `/qring-exec-safe` command (`exec_with_secrets` MCP tool) instead.

## q-ring · Workflow (always)

- Use q-ring MCP tools (`get_secret`, `set_secret`, `list_secrets`, etc.) for **every** secret operation. Never call OS keychain APIs directly.
- Before working with a project's secrets for the first time, call `get_project_context` to understand what secrets exist, their scopes, and any governance policy.
- If the project has a `.q-ring.json` file, call `check_policy` before tool or exec actions to respect governance rules.
- After writing or deleting a secret, remind the user that q-ring maintains a tamper-evident audit trail accessible via `audit_log`.
- For ephemeral values (one-time tokens, OTPs), use `tunnel_create` instead of `set_secret` — tunnels are memory-only and self-destruct on TTL or read count.
- For sharing secrets across machines, use `teleport_pack` / `teleport_unpack` — never paste raw credentials into chat or files.
- Treat the q-ring MCP server (`q-ring`) as the single source of truth for secret values. Treat `.env` files as derived artifacts produced by `env_generate`.

## q-ring · `.env` file safety (when a `.env*` file is in scope)

When a `.env`, `.env.local`, `.env.production`, or similar file is open or being edited:

1. **Suggest importing.** Offer to call `import_dotenv` to migrate all key-value pairs into q-ring where they are encrypted in the OS keychain.
2. **Check `.gitignore`.** Verify that `.env*` patterns are in `.gitignore`. If not, warn immediately and offer to add them.
3. **Prefer manifest-driven generation.** If the project has a `.q-ring.json` manifest, suggest `env_generate` to produce `.env` files on-demand from q-ring instead of maintaining them by hand.
4. **Never add new secrets** to `.env` files directly. Use `set_secret` (or `qring set KEY value`) and then `env_generate` to produce the file.

## Available extensions

- **Subagents** under `.claude/agents/` — `secret-ops` (CRUD/transfer assistant) and `security-auditor` (proactive monitoring).
- **Slash commands** under `.claude/commands/` — `/qring-scan-secrets`, `/qring-health-check`, `/qring-rotate-expired`, `/qring-setup-project`, `/qring-teleport-secrets`, `/qring-dashboard`, `/qring-exec-safe`, `/qring-analyze`.
- **Skills** under `.claude/skills/` — auto-triggered by topic: `secret-hygiene-rules` (this file's rules, for plugin installs), `secret-management`, `secret-scanning`, `secret-rotation`, `project-onboarding`, `exec-with-secrets`.
- **Hooks** in `.claude/settings.json` — lint reminders after edits, `.env` commit guards, session-start context hint.

The MCP server `q-ring` (configured in `.mcp.json`) exposes 44 tools for secrets, scanning, rotation, auditing, and governance.
