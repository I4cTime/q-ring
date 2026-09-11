# CLI vs MCP parity

`qring` (CLI) and `qring-mcp` (MCP) share `src/core/*`, `src/services/*`, and
the same governance rules. Some workflows exist only on one surface by design.

The canonical source for tool registrations is `src/mcp/tools/*.ts`. CLI
commands live in `src/cli/commands/*.ts` and delegate to the same core modules
so both surfaces see identical policy enforcement, audit log entries, and
approval gates.

## Shared behavior

- **Agent sessions:** `qring audit:sessions` (CLI, operator view — canary
  trips included) and the MCP resources `qring://sessions` /
  `qring://sessions/{id}` (agent view — canary trips stripped, hidden when
  policy denies `audit_log`) both build on `listAgentSessions` in
  `src/core/sessions.ts`. Resources, not tools, by the standing rule; the
  tool count stays at 44.
- **Airlock policy:** `policy.wrap` (`src/core/policy.ts`) is enforced only
  by `qring mcp wrap` — the q-ring MCP server itself is governed by
  `policy.mcp`. `qring mcp approve` grants use the same HMAC-verified approval
  registry as `qring approve`, under scope `wrap` and a per-project service id.

- **List key filter:** `qring list --filter` and MCP `list_secrets` use the
  same glob rules (`src/services/list-secrets-filter.ts`): `*` → `.*`,
  `?` → `.`, other regex metacharacters escaped.
- **Version:** Both read `PACKAGE_VERSION` from `src/version.ts` (resolved from
  `package.json` next to `dist/`).
- **Policy enforcement:** Every MCP tool runs `enforceToolPolicy` before
  executing; the CLI goes through the same `checkToolPolicy`, `checkExecPolicy`,
  and `checkKeyReadPolicy` helpers in `src/core/policy.ts`. **Policy root
  differs by surface:** the MCP server pins policy resolution to its launch CWD
  (`setPolicyRoot`, called in `src/mcp/server.ts`) so an agent can't escape
  governance via a crafted `projectPath`; the CLI resolves policy from the
  caller's `projectPath`/CWD as usual.
- **SSRF protection:** All outbound HTTP (hooks, JIT providers, provider
  validation) routes through `src/utils/http-request.ts`, which re-validates the
  resolved IP at connect time via `guardedLookup`; user-configurable URLs are
  additionally pre-checked through `src/core/ssrf.ts`.

## Command ↔ tool map

| Concern            | CLI                                              | MCP                                                             |
| ------------------ | ------------------------------------------------ | --------------------------------------------------------------- |
| Secret CRUD        | `set` `get` `delete` `list` `inspect` `export` `import` | `set_secret` `get_secret` `delete_secret` `list_secrets` `inspect_secret` `export_secrets` `import_dotenv` |
| Existence check    | `has` (exit 0/1, `--quiet` for scripts)          | `has_secret`                                                    |
| Generation         | `generate`                                       | `generate_secret`                                               |
| Entanglement       | `entangle` / `disentangle`                       | `entangle_secrets` / `disentangle_secrets`                      |
| Tunnel             | `tunnel create/read/destroy/list`                | `tunnel_create` / `tunnel_read` / `tunnel_destroy` / `tunnel_list` |
| Teleport           | `teleport pack/unpack`                           | `teleport_pack` / `teleport_unpack`                             |
| Project context    | `context`                                        | `get_project_context`                                           |
| Project check      | `check`                                          | `check_project`                                                 |
| Env generation     | `env:generate`                                   | `env_generate`                                                  |
| Env detection      | `env`                                            | `detect_environment`                                            |
| Validation         | `validate` / `validate --all` / `--list-providers` | `validate_secret` / `list_providers`                            |
| CI validation      | `ci:validate`                                    | `ci_validate_secrets`                                           |
| Rotation           | `rotate`                                         | `rotate_secret`                                                 |
| Audit              | `audit` / `audit --anomalies`                    | `audit_log` / `detect_anomalies`                                |
| Audit integrity    | `audit:verify` / `audit:export`                  | `verify_audit_chain` / `export_audit`                           |
| Health             | `health`                                         | `health_check`                                                  |
| Hooks (callbacks)  | `hook add/list/remove/enable/disable/test`       | `register_hook` / `list_hooks` / `remove_hook`                  |
| Scanning           | `scan` / `lint`                                  | `scan_codebase_for_secrets` / `lint_files`                      |
| Exec               | `exec`                                           | `exec_with_secrets`                                             |
| Dashboard          | `status`                                         | `status_dashboard`                                              |
| Agent scan         | `agent`                                          | `agent_scan`                                                    |
| Agent memory       | `remember` / `recall` / `forget`                 | `agent_remember` / `agent_recall` / `agent_forget`              |
| Analysis           | `analyze`                                        | `analyze_secrets`                                               |
| Policy summary     | `policy`                                         | `get_policy_summary`                                            |

## CLI-only (no MCP tool)

| CLI                                                       | Notes                                                           |
| --------------------------------------------------------- | --------------------------------------------------------------- |
| `qring approve` / `approvals`                             | Interactive approval tokens for MCP secret reads                |
| `hook:install` / `hook:uninstall` / `hook:run`            | Git pre-commit wiring                                           |
| `qring wizard`                                            | Interactive service setup                                       |
| `hook enable` / `disable` / `test`                        | Runtime lifecycle for secret-change hooks                       |
| `qring doctor`                                            | Install self-check (keyring, audit, manifest, MCP binary)       |
| `qring completion <shell>`                                | bash/zsh/fish completion scripts generated from the CLI itself  |

## MCP-only (no CLI subcommand)

| MCP tool        | Notes                                                                            |
| --------------- | -------------------------------------------------------------------------------- |
| `check_policy`  | Programmatic policy probe — CLI surfaces the same information via `qring policy`. |

## JSON output

- **Global:** `qring --json …` (or `--json` on the subcommand) emits
  `{ "ok": true, "data": … }` for: `get`, `has`, `delete`, `list`, `inspect`,
  `import`, `audit`, `audit:verify`, `health`, `analyze`, `recall` (list
  mode), `check`, `env`, `validate` (single, `--all`, `--list-providers`),
  `rotate`, `tunnel list`, `hook list`, `approvals`, `scan`, `lint`.
  See `emitJson` in `src/cli/helpers.ts`.
- **Legacy shapes:** `qring context --json`, `qring ci:validate --json`, and
  `qring policy --json` print their payload without the `{ok, data}` envelope
  (kept for backward compatibility).

## Destructive-operation confirmations

`delete`, `forget --all`, `teleport unpack` (when it would overwrite existing
keys), `wizard` (when its generated keys already exist), and
`env:generate -o` (when the output file exists) prompt for confirmation on a
TTY. Pass `-y`/`--yes` to skip; non-interactive use without `--yes` is an
error, never a silent yes.

## Intentional differences

- **Raw secrets:** MCP tools such as `get_secret` return JSON payloads; CLI
  `qring get` defaults to JSON and uses `--raw` for the legacy single-value
  stream.

When adding a feature, update this file and the Cursor plugin skills/commands
if user-facing behavior changes.
