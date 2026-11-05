# q-ring always-on rules

These rules apply to every task in this session.

## Secret Hygiene

- **Never** hardcode secrets, API keys, tokens, passwords, or connection strings in source code or config files.
- Store secrets using the `set_secret` MCP tool or `qring set` CLI — not in `.env` files, inline strings, or comments.
- Reference secrets in code via `process.env.KEY` (JS/TS), `os.environ["KEY"]` (Python), or the equivalent for the project language. The actual value lives in q-ring.
- When reviewing or writing code, flag any string that matches common credential patterns (`sk-*`, `ghp_*`, `Bearer *`, long base64 blobs, connection strings with passwords).
- If you spot a hardcoded secret, offer to run `scan_codebase_for_secrets` and `lint_files` with auto-fix to migrate it into q-ring.
- Secrets with a TTL or rotation format should always be stored with `--ttl` or `--rotation-format` so q-ring can track decay and automate rotation.
- When a shell command contains what looks like a secret value (long base64, `sk-*`, `ghp_*`, etc.), warn the user that secrets should not appear in shell history. Suggest using `qring exec` instead.

## q-ring Workflow

- Use q-ring MCP tools (`get_secret`, `set_secret`, `list_secrets`, etc.) for **all** secret operations. Never call OS keychain APIs directly.
- Before working with a project's secrets for the first time, call `get_project_context` to understand what secrets exist, their scopes, and any governance policy.
- If the project has a `.q-ring.json` file, call `check_policy` before performing tool or exec actions to respect governance rules.
- After writing or deleting a secret, remind the user that q-ring maintains a tamper-evident audit trail accessible via `audit_log`.
- For ephemeral values (one-time tokens, OTPs), use `tunnel_create` instead of `set_secret` — tunnels are memory-only and self-destruct.
- For sharing secrets across machines, use `teleport_pack` / `teleport_unpack` — never paste raw credentials into chat or files.
