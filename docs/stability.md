# Stability contract (0.19 release candidate → 1.0)

0.19 is the release candidate for q-ring 1.0. This document lists the
surface that is **frozen** as of 0.19, the parts that stay **experimental**,
what semantic versioning promises from 1.0 on, how deprecations work, what
is **deprecated in 0.19**, and which versions receive fixes.

Every list here is derived from the code on `main` (0.18.0 plus the
`[Unreleased]` section of the [CHANGELOG](../CHANGELOG.md)), not from
memory: the CLI table was dumped from the live commander tree
(`createProgram()` in `src/cli/commands.ts`), the MCP table from the tool
registry built by `createMcpServer()` (`src/mcp/server.ts`), and the
environment variables from a grep of `src/` for `process.env`. If this
document and the code disagree, the code is the bug report: open an issue.

"Frozen" means: from 1.0 on, it changes only in the ways the
[semver promise](#semver-promise-from-10) allows. Until 1.0 ships, a frozen
item changes only to fix a defect found during the release candidate, and
any such change is called out in the CHANGELOG.

## Frozen as of 0.19

### CLI commands and flags

The binary is `qring` (the MCP server binary is `qring-mcp`). Global
options on the root command: `-V, --version` and `--json`.

Conventions that are part of the contract:

- **Scope flags.** `-g, --global`, `-p, --project`, `--team <id>`,
  `--org <id>` and `--project-path <path>` mean the same thing on every
  command that takes them. With no scope flag, reads resolve
  project → team → org → global (`resolveScope` in `src/core/scope.ts`).
- **`--json`.** Accepted on the root (`qring --json <command>`) and, where
  listed below, on the subcommand; both spellings are equivalent
  (`wantsJsonOutput` in `src/cli/helpers.ts`). Commands that go through
  `emitJson` print `{ "ok": true, "data": … }`. The exceptions that print a
  bare payload are listed under [Deprecated in 0.19](#deprecated-in-019)
  (`context`, `ci:validate`, `policy`) and under
  [Experimental](#experimental-not-frozen) (`push`, `setup`,
  `mcp approvals`, `agent --once`). `qring get` without `--json` prints
  `{ "key", "value" }`; `--raw` prints the bare value.
- **Confirmations.** Destructive commands (`delete`, `forget --all`,
  `teleport unpack` over existing keys, `wizard` over existing keys,
  `env:generate -o` over an existing file, `promote` over a differing
  value) ask on a TTY and refuse without `-y, --yes` when not interactive.
- **Secret values never travel in argv to child processes** (`push`, hooks,
  `exec`, `run`): they go over stdin or the child's environment. This is a
  behavioural guarantee, not just an implementation detail.

The frozen command tree (79 command paths, including group commands such as
`tunnel`, `hook`, `canary` and `mcp`). Argument and option spellings are
frozen; help text is not.

| Command | Arguments | Aliases | Options |
| --- | --- | --- | --- |
| `qring set` | `<key>` `[value]` | - | `-g, --global`<br>`-p, --project`<br>`--team <id>`<br>`--org <id>`<br>`--project-path <path>`<br>`-e, --env <env>`<br>`--ttl <seconds>`<br>`--expires <iso>`<br>`--description <desc>`<br>`--tags <tags>`<br>`--rotation-format <format>`<br>`--rotation-prefix <prefix>`<br>`--rotate-every <days>`<br>`--requires-approval`<br>`--jit-provider <provider>` |
| `qring get` | `<key>` | - | `-g, --global`<br>`-p, --project`<br>`--team <id>`<br>`--org <id>`<br>`--project-path <path>`<br>`-e, --env <env>`<br>`--raw` |
| `qring has` | `<key>` | - | `-g, --global`<br>`-p, --project`<br>`--team <id>`<br>`--org <id>`<br>`--project-path <path>`<br>`-q, --quiet` |
| `qring delete` | `<key>` | `rm` | `-g, --global`<br>`-p, --project`<br>`--project-path <path>`<br>`-y, --yes`<br>`--json` |
| `qring list` | - | `ls` | `-g, --global`<br>`-p, --project`<br>`--team <id>`<br>`--org <id>`<br>`--project-path <path>`<br>`--show-decay`<br>`-t, --tag <tag>`<br>`--expired`<br>`--stale`<br>`-f, --filter <pattern>`<br>`--json` |
| `qring inspect` | `<key>` | - | `-g, --global`<br>`-p, --project`<br>`--project-path <path>`<br>`--json` |
| `qring export` | - | - | `-f, --format <format>`<br>`-g, --global`<br>`-p, --project`<br>`--project-path <path>`<br>`-e, --env <env>`<br>`-k, --keys <keys>`<br>`-t, --tags <tags>` |
| `qring import` | `<file>` | - | `-g, --global`<br>`-p, --project`<br>`--project-path <path>`<br>`-e, --env <env>`<br>`--skip-existing`<br>`--dry-run`<br>`--json` |
| `qring context` | - | `describe` | `-g, --global`<br>`-p, --project`<br>`--project-path <path>`<br>`--json` |
| `qring check` | - | - | `--project-path <path>`<br>`--json` |
| `qring env` | - | - | `--project-path <path>`<br>`--json` |
| `qring env:generate` | - | - | `--project-path <path>`<br>`-o, --output <file>`<br>`-e, --env <env>`<br>`-y, --yes` |
| `qring wizard` | `<name>` | - | `--keys <keys>`<br>`--provider <provider>`<br>`--tags <tags>`<br>`--hook-exec <cmd>`<br>`-g, --global`<br>`-p, --project`<br>`--project-path <path>`<br>`-y, --yes` |
| `qring promote` | `<key>` | - | `--from <env>`<br>`--to <env>`<br>`-g, --global`<br>`-p, --project`<br>`--team <id>`<br>`--org <id>`<br>`--project-path <path>`<br>`-f, --force`<br>`-y, --yes` |
| `qring diff` | `<envA>` `<envB>` | - | `-k, --keys <keys>`<br>`-g, --global`<br>`-p, --project`<br>`--team <id>`<br>`--org <id>`<br>`--project-path <path>` |
| `qring generate` | - | `gen` | `-f, --format <format>`<br>`-l, --length <n>`<br>`--prefix <prefix>`<br>`-s, --save <key>`<br>`-g, --global`<br>`-p, --project`<br>`--project-path <path>` |
| `qring entangle` | `<sourceKey>` `<targetKey>` | - | `-g, --global`<br>`--source-project <path>`<br>`--target-project <path>` |
| `qring disentangle` | `<sourceKey>` `<targetKey>` | - | `-g, --global`<br>`--source-project <path>`<br>`--target-project <path>` |
| `qring tunnel` | - | - | - |
| `qring tunnel create` | `<value>` | - | `--ttl <seconds>`<br>`--max-reads <n>` |
| `qring tunnel read` | `<id>` | - | - |
| `qring tunnel destroy` | `<id>` | - | - |
| `qring tunnel list` | - | `ls` | `--json` |
| `qring teleport` | - | `tp` | - |
| `qring teleport keygen` | - | - | `--force` |
| `qring teleport identity` | - | - | - |
| `qring teleport pack` | - | - | `-k, --keys <keys>`<br>`--to <recipient...>`<br>`-g, --global`<br>`-p, --project`<br>`--project-path <path>` |
| `qring teleport unpack` | `[bundle]` | - | `-g, --global`<br>`-p, --project`<br>`--project-path <path>`<br>`--dry-run`<br>`-y, --yes` |
| `qring validate` | `[key]` | - | `-g, --global`<br>`-p, --project`<br>`--project-path <path>`<br>`--provider <name>`<br>`--all`<br>`--manifest`<br>`--list-providers`<br>`--json` |
| `qring rotate` | `<key>` | - | `-g, --global`<br>`-p, --project`<br>`--project-path <path>`<br>`--provider <name>`<br>`--json` |
| `qring rotate:due` | - | - | `-g, --global`<br>`-p, --project`<br>`--team <id>`<br>`--org <id>`<br>`--project-path <path>`<br>`--all`<br>`--json` |
| `qring ci:validate` | - | - | `-g, --global`<br>`-p, --project`<br>`--project-path <path>`<br>`--json` |
| `qring exec` | `<command...>` | - | `-g, --global`<br>`-p, --project`<br>`--project-path <path>`<br>`-e, --env <env>`<br>`-k, --keys <keys>`<br>`-t, --tags <tags>`<br>`--profile <name>` |
| `qring scan` | `[dir]` | - | `--fix`<br>`-g, --global`<br>`-p, --project`<br>`--project-path <path>`<br>`--json` |
| `qring lint` | `<files...>` | - | `--fix`<br>`-g, --global`<br>`-p, --project`<br>`--project-path <path>`<br>`--json` |
| `qring status` | - | - | `--port <port>`<br>`--no-open` |
| `qring audit` | - | - | `-k, --key <key>`<br>`-a, --action <action>`<br>`--agent <label>`<br>`-n, --limit <n>`<br>`--anomalies`<br>`--json` |
| `qring audit:verify` | - | - | `--json` |
| `qring audit:export` | - | - | `--since <date>`<br>`--until <date>`<br>`--format <fmt>`<br>`-o, --output <file>` |
| `qring audit:sessions` | - | - | `--agent <label>`<br>`--since <when>`<br>`-n, --limit <n>`<br>`-v, --verbose`<br>`--json` |
| `qring health` | - | - | `-g, --global`<br>`-p, --project`<br>`--project-path <path>`<br>`--json` |
| `qring hook:install` | - | - | `--project-path <path>` |
| `qring hook:uninstall` | - | - | `--project-path <path>` |
| `qring hook:run` | - | - | - |
| `qring hook` | - | - | - |
| `qring hook add` | - | - | `--key <key>`<br>`--key-pattern <pattern>`<br>`--tag <tag>`<br>`--scope <scope>`<br>`--action <actions>`<br>`--exec <command>`<br>`--url <url>`<br>`--signal-target <target>`<br>`--signal-name <signal>`<br>`--description <desc>` |
| `qring hook list` | - | `ls` | `--json` |
| `qring hook remove` | `<id>` | `rm` | - |
| `qring hook enable` | `<id>` | - | - |
| `qring hook disable` | `<id>` | - | - |
| `qring hook test` | `<id>` | - | - |
| `qring remember` | `<key>` `<value>` | - | - |
| `qring recall` | `[key]` | - | `--json` |
| `qring forget` | `<key>` | - | `--all`<br>`-y, --yes` |
| `qring analyze` | - | - | `-g, --global`<br>`-p, --project`<br>`--project-path <path>`<br>`--json` |
| `qring agent` | - | - | `-i, --interval <seconds>`<br>`--auto-rotate`<br>`-v, --verbose`<br>`--project-path <paths>`<br>`--once` |
| `qring approve` | `<key>` | - | `-g, --global`<br>`-p, --project`<br>`--project-path <path>`<br>`--for <seconds>`<br>`--reason <text>`<br>`--revoke`<br>`--list` |
| `qring approvals` | - | - | `--json` |
| `qring policy` | - | - | `--json` |
| `qring run` | `<command...>` | - | `--project-path <path>`<br>`-e, --env <env>`<br>`--env-file <files...>`<br>`--no-manifest`<br>`--profile <name>`<br>`--strict`<br>`--dry-run` |
| `qring push` | `<target>` | - | `-k, --keys <keys>`<br>`--project-path <path>`<br>`-e, --env <env>`<br>`--repo <owner/name>`<br>`--vercel-env <envs>`<br>`--app <name>`<br>`--service <name>`<br>`--railway-env <name>`<br>`--site <id>`<br>`--dry-run`<br>`--json` |
| `qring setup` | `<editor>` | - | `-g, --global`<br>`--project-path <path>`<br>`--force`<br>`--dry-run`<br>`--json` |
| `qring canary` | - | - | - |
| `qring canary plant` | `<key>` | - | `-f, --format <format>`<br>`--value <value>`<br>`--description <text>`<br>`--force`<br>`--push <target>`<br>`--repo <owner/name>`<br>`--vercel-env <envs>`<br>`--json`<br>`-g, --global`<br>`-p, --project`<br>`--team <id>`<br>`--org <id>`<br>`--project-path <path>` |
| `qring canary disarm` | `<key>` | - | `-g, --global`<br>`-p, --project`<br>`--team <id>`<br>`--org <id>`<br>`--project-path <path>` |
| `qring canary list` | - | `ls` | `--json`<br>`-g, --global`<br>`-p, --project`<br>`--team <id>`<br>`--org <id>`<br>`--project-path <path>` |
| `qring canary alert` | - | - | - |
| `qring canary alert add` | - | - | `--discord <url>`<br>`--slack <url>`<br>`--ntfy <url>`<br>`--url <url>`<br>`--description <text>`<br>`--json` |
| `qring canary alert list` | - | `ls` | `--json` |
| `qring canary alert remove` | `<id>` | `rm` | - |
| `qring canary alert enable` | `<id>` | - | - |
| `qring canary alert disable` | `<id>` | - | - |
| `qring canary alert test` | `[id]` | - | `--json` |
| `qring mcp` | - | - | - |
| `qring mcp wrap` | `[command...]` | - | `--url <url>`<br>`--header <name:value>`<br>`--auth-secret <KEY>`<br>`--inherit-env`<br>`--no-redact`<br>`--label <label>`<br>`--project-path <path>` |
| `qring mcp approve` | `<tool>` | - | `--for <seconds>`<br>`--reason <text>`<br>`--revoke`<br>`--project-path <path>` |
| `qring mcp approvals` | - | - | `--project-path <path>`<br>`--json` |
| `qring doctor` | - | - | `--project-path <path>`<br>`--json` |
| `qring completion` | `<shell>` | - | - |

### MCP tools: names and input schemas

`qring-mcp` registers **46 tools**. Frozen for each: the tool name, every
input parameter name, its JSON type, its enum values, whether it is
required, and its default. Required inputs below are those a caller must
send (parameters with a default are optional). The full JSON Schema of each
tool is what `tools/list` returns; `src/mcp/tools/*.ts` is the source.

| # | Tool | Required inputs | Optional inputs |
| --- | --- | --- | --- |
| 1 | `get_secret` | `key` | `scope`, `projectPath`, `env`, `teamId`, `orgId` |
| 2 | `list_secrets` | - | `scope`, `projectPath`, `tag`, `expired`, `stale`, `filter`, `teamId`, `orgId` |
| 3 | `set_secret` | `key`, `value` | `scope`, `projectPath`, `env`, `ttlSeconds`, `description`, `tags`, `rotationFormat`, `rotationPrefix`, `rotateEveryDays`, `teamId`, `orgId` |
| 4 | `delete_secret` | `key` | `scope`, `projectPath`, `teamId`, `orgId` |
| 5 | `has_secret` | `key` | `scope`, `projectPath`, `teamId`, `orgId` |
| 6 | `export_secrets` | - | `format`, `keys`, `tags`, `scope`, `projectPath`, `env`, `teamId`, `orgId` |
| 7 | `import_dotenv` | `content` | `scope`, `projectPath`, `skipExisting`, `dryRun` |
| 8 | `inspect_secret` | `key` | `scope`, `projectPath`, `teamId`, `orgId` |
| 9 | `generate_secret` | - | `format`, `length`, `prefix`, `saveAs`, `scope`, `projectPath`, `teamId`, `orgId` |
| 10 | `entangle_secrets` | `sourceKey`, `targetKey` | `sourceScope`, `targetScope`, `sourceProjectPath`, `targetProjectPath` |
| 11 | `disentangle_secrets` | `sourceKey`, `targetKey` | `sourceScope`, `targetScope`, `sourceProjectPath`, `targetProjectPath` |
| 12 | `promote_secret` | `key`, `from`, `to` | `force`, `scope`, `projectPath`, `teamId`, `orgId` |
| 13 | `diff_environments` | `envA`, `envB` | `keys`, `scope`, `projectPath`, `teamId`, `orgId` |
| 14 | `check_project` | - | `projectPath` |
| 15 | `env_generate` | - | `projectPath`, `env` |
| 16 | `detect_environment` | - | `projectPath` |
| 17 | `get_project_context` | - | `scope`, `projectPath`, `teamId`, `orgId` |
| 18 | `tunnel_create` | `value` | `ttlSeconds`, `maxReads` |
| 19 | `tunnel_read` | `id` | - |
| 20 | `tunnel_list` | - | - |
| 21 | `tunnel_destroy` | `id` | - |
| 22 | `teleport_pack` | - | `keys`, `passphrase`, `recipients`, `scope`, `projectPath`, `teamId`, `orgId` |
| 23 | `teleport_unpack` | `bundle` | `passphrase`, `scope`, `projectPath`, `teamId`, `orgId`, `dryRun` |
| 24 | `audit_log` | - | `key`, `action`, `agent`, `limit` |
| 25 | `detect_anomalies` | - | `key` |
| 26 | `health_check` | - | `scope`, `projectPath`, `teamId`, `orgId` |
| 27 | `verify_audit_chain` | - | - |
| 28 | `export_audit` | - | `since`, `until`, `format` |
| 29 | `validate_secret` | `key` | `provider`, `scope`, `projectPath`, `teamId`, `orgId` |
| 30 | `list_providers` | - | - |
| 31 | `rotate_secret` | `key` | `provider`, `scope`, `projectPath`, `teamId`, `orgId` |
| 32 | `ci_validate_secrets` | - | `scope`, `projectPath`, `teamId`, `orgId` |
| 33 | `register_hook` | `type` | `key`, `keyPattern`, `tag`, `scope`, `actions`, `command`, `url`, `signalTarget`, `signalName`, `description` |
| 34 | `list_hooks` | - | - |
| 35 | `remove_hook` | `id` | - |
| 36 | `exec_with_secrets` | `command` | `args`, `keys`, `tags`, `profile`, `scope`, `projectPath`, `teamId`, `orgId` |
| 37 | `scan_codebase_for_secrets` | `dirPath` | - |
| 38 | `lint_files` | `files` | `fix`, `scope`, `projectPath`, `teamId`, `orgId` |
| 39 | `analyze_secrets` | - | `scope`, `projectPath`, `teamId`, `orgId` |
| 40 | `status_dashboard` | - | `port` |
| 41 | `agent_scan` | - | `autoRotate`, `projectPaths` |
| 42 | `agent_remember` | `key`, `value` | - |
| 43 | `agent_recall` | - | `key` |
| 44 | `agent_forget` | `key` | - |
| 45 | `check_policy` | `action` | `toolName`, `key`, `command`, `projectPath` |
| 46 | `get_policy_summary` | - | `projectPath` |

Also frozen for tools:

- Registration order (`src/mcp/tool-registration.ts`): some clients cache it.
- Tool results that are JSON keep every field they have in 0.19; new fields
  may be added.
- Error codes that appear in tool error text, such as
  `ERR_TELEPORT_PASSPHRASE_REQUIRED`, `ERR_TELEPORT_NO_IDENTITY` and
  `ERR_TELEPORT_CORRUPT` (`src/core/teleport.ts`).

Not frozen: tool descriptions and parameter descriptions (they are tuned for
tool-selection quality), and the behaviour hints in
`src/mcp/tool-annotations.ts` (`readOnlyHint`, `destructiveHint`,
`idempotentHint`, `openWorldHint`), which may be corrected in a minor.

### MCP resource URIs

Registered in `src/mcp/resources.ts`:

| URI | Name | Content |
| --- | --- | --- |
| `qring://sessions` | `agent-sessions` | JSON `{ "sessions": [...] }`: agent session summaries for the last 7 days |
| `qring://sessions/{id}` | `agent-session` | JSON: one session's timeline |

Both are `application/json`, never contain secret values, strip canary
trips, and return nothing when `.q-ring.json` policy denies the `audit_log`
tool. Session objects keep their 0.19 fields; new fields may be added.

### `.q-ring.json` format

Top-level keys read by q-ring (`ProjectConfig` in `src/core/collapse.ts`):

| Key | Type | Meaning |
| --- | --- | --- |
| `env` | string | Force the environment for this project |
| `defaultEnv` | string | Environment when nothing else decides |
| `branchMap` | object, branch → env | Git branch mapping; `*` globs allowed |
| `secrets` | object, key → manifest entry | The secrets manifest |
| `policy` | object | Governance policy (strict schema, below) |

Manifest entry fields (`ManifestEntry`): `required`, `description`,
`format`, `prefix`, `provider`, `validationUrl`.

Environment resolution order (`collapseEnvironment`): explicit `--env` /
`env` input → `QRING_ENV` → `NODE_ENV` (`production` → `prod`,
`development` → `dev`) → `.q-ring.json` `env` → git branch through the
built-in map merged with `branchMap` → `.q-ring.json` `defaultEnv`.

The `policy` object is validated with `.strict()` at every level
(`src/core/policy.ts`); an unknown key is a `PolicyConfigError` and the
engine fails closed. The frozen schema:

| Block | Keys |
| --- | --- |
| `policy.mcp` | `allowTools`, `denyTools`, `readableKeys`, `deniedKeys`, `deniedTags` (string arrays) |
| `policy.exec` | `allowCommands`, `denyCommands` (string arrays), `maxRuntimeSeconds` (number), `allowNetwork` (boolean) |
| `policy.secrets` | `requireApprovalForTags`, `requireRotationFormatForTags` (string arrays), `maxTtlSeconds` (number) |
| `policy.wrap` | `allowTools`, `denyTools`, `approveTools` (string arrays, `*` globs), `rateLimit` (`{ maxCalls: positive int, perSeconds: positive number }`), `toolRateLimits` (tool → rate limit), `redactResults` (boolean) |

Policy for the MCP server is read from the directory the server was
launched in, never from a caller-supplied `projectPath`. That anchoring is
part of the contract.

### Ring and keyring record format

Secrets live in the OS keychain (or the encrypted file backend) as
service/account pairs (`src/core/scope.ts`, `src/core/keyring.ts`):

| Scope | Service | Account |
| --- | --- | --- |
| global | `q-ring:global` | the key name |
| project | `q-ring:project:<first 12 hex chars of sha256(project path)>` | the key name |
| team | `q-ring:team:<teamId>` | the key name |
| org | `q-ring:org:<orgId>` | the key name |

The stored password is a JSON **envelope** (`src/core/envelope.ts`):
`{ "v": 1, "value"?, "states"?, "defaultEnv"?, "meta": {...} }`, where
`states` maps environment → value (superposition) and `meta` carries
`createdAt`, `updatedAt`, `accessCount` (required) and the optional
`expiresAt`, `ttlSeconds`, `description`, `tags`, `entangled`,
`lastAccessedAt`, `ephemeral`, `rotationFormat`, `rotationPrefix`,
`rotatedAt`, `rotateEveryDays`, `provider`, `validationUrl`,
`requiresApproval`, `jitProvider`, `jitExpiresAt`, `canary`,
`canaryFormat`. Unknown `meta` fields are dropped on read. A keychain value
that is not a valid envelope is read as a plain value (`wrapLegacy`), so
entries written before the envelope format, or by other tools, stay
readable; this is kept permanently.

Other keychain entries q-ring owns:

| Service | Account | Holds |
| --- | --- | --- |
| `qring-audit-chain` | `hmac-key`, `chain-head` | Audit anchor key and head HMAC |
| `qring-memory-key` | `encryption-key` | Agent memory key |
| `q-ring-teleport` | `identity` | Teleport X25519 private key (PKCS8 DER, base64) |

Encrypted formats on disk and on the wire:

- **File backend** (`QRING_BACKEND=file`): one file,
  `qfile1:<salt>:<iv>:<tag>:<ciphertext>`, AES-256-GCM, PBKDF2 210 000
  iterations (`src/core/backend.ts`).
- **Agent memory** (`agent-memory.enc`): `<iv>:<tag>:<ct>` under the
  keyring key, or `qmem2:<salt>:<iv>:<tag>:<ct>` under
  `QRING_MEMORY_PASSPHRASE` (`src/core/memory.ts`).
- **Teleport bundles** (`src/core/teleport.ts`): base64 JSON. v1
  (passphrase): `{ v: 1, data, salt, iv, tag, createdAt, count, iter }`. v2
  (recipients): `{ v: 2, createdAt, count, ephemeral, recipients: [{ id,
  wrap, iv, tag }], iv, tag, data }`. Recipient strings are `qring1` +
  base64url of the 32-byte X25519 public key. Both versions are supported
  modes, not legacy.
- **Secret references**: `qring://project/KEY`, `qring://global/KEY`,
  `qring:///KEY` (project, then global), optional `?env=<env>`; the key
  lives in the path, never the host (`src/core/refs.ts`).
- **Audit log** (`audit.jsonl`): one JSON event per line with `timestamp`,
  `action`, `source`, `pid` and optional `key`, `scope`, `env`, `detail`,
  `prevHash`, `correlationId`, `agent` (`AuditEvent` in
  `src/core/observer.ts`). Actions: `read`, `write`, `delete`, `list`,
  `export`, `generate`, `entangle`, `tunnel`, `teleport`, `collapse`,
  `approve`, `revoke`, `policy_deny`, `rotate`, `push`, `canary`, `wrap`.
  Export formats: `jsonl`, `json`, `csv`.

New optional fields may be added to any of these in a minor; a reader of a
newer minor's data written by an older 1.x always works.

### Environment variables

Every variable q-ring reads (grep of `src/` for `process.env`):

| Variable | Effect | Where |
| --- | --- | --- |
| `QRING_BACKEND` | `keyring` (default) or `file`; anything else is an error | `src/core/backend.ts` |
| `QRING_FILE_PASSPHRASE` | Passphrase for the file backend; required when it is selected | `src/core/backend.ts` |
| `QRING_FILE_BACKEND_PATH` | File backend location (default `~/.config/q-ring/file-backend.enc`) | `src/core/backend.ts` |
| `QRING_CONFIG_DIR` | Directory for registries: hooks, entanglement, approvals, canary webhooks, memory, observer state (default `~/.config/q-ring`) | `src/utils/config-dir.ts` |
| `QRING_AUDIT_DIR` | Directory for `audit.jsonl`; also moves the lock dir unless `QRING_LOCK_DIR` is set | `src/core/observer.ts`, `src/utils/file-lock.ts` |
| `QRING_LOCK_DIR` | Directory for file locks | `src/utils/file-lock.ts` |
| `QRING_MEMORY_PASSPHRASE` | Agent memory key when no OS keyring is available | `src/core/memory.ts` |
| `QRING_ENV` | Forces the environment (second only to an explicit `--env`) | `src/core/collapse.ts` |
| `NODE_ENV` | Environment hint after `QRING_ENV` | `src/core/collapse.ts` |
| `QRING_NOTIFY` | `off`, `0` or `false` disables approval and canary desktop notifications | `src/core/notify.ts` |
| `QRING_DEBUG` | Any value: full stack traces from the CLI, traces for dropped audit writes | `src/index.ts`, `src/core/observer.ts` |
| `QRING_WRAP_TIMEOUT_MS` | Airlock ceiling for one downstream call (default 600 000) | `src/core/wrap.ts` |
| `QRING_ALLOW_PRIVATE_HOOKS` | `1` lets hooks, validation and HTTP JIT reach private and loopback addresses | `src/core/ssrf.ts` |
| `NO_COLOR` | Disables colour output | `src/utils/colors.ts` |
| `QRING_SILENCE_DEPRECATIONS` | `1` silences the one-line deprecation warnings | `src/core/deprecation.ts` |
| `Q_RING_ALLOW_PRIVATE_HOOKS` | Old spelling of `QRING_ALLOW_PRIVATE_HOOKS`; still works, deprecated, see below | `src/core/ssrf.ts` |
| `QRING_CANARY_ALERTS_PATH` | Canary webhook registry file; still works, deprecated, see below | `src/core/canary-webhooks.ts` |

Variables q-ring **sets** for children, also frozen: `QRING_HOOK_KEY`,
`QRING_HOOK_ACTION` and `QRING_HOOK_SCOPE` for shell hooks
(`src/core/hooks.ts`).

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Success |
| `1` | Any error (the central handler in `src/index.ts`, usage errors from the argument parser), and a failed check: `has` on a missing key, `diff` with drift, `doctor` with a failed check, `ci:validate` with an invalid secret, `audit:verify` on a broken chain, `hook:run` when the staged files contain secrets, `run` with a missing required secret, `push` with a failed key, and `mcp wrap` when the wrapped server exits |
| `124` | `exec` / `run`: the child exceeded the profile's runtime limit and was killed |
| `126` | `exec` / `run`: the command was blocked by the profile's network rule |
| child's code | `exec`, `run`: the child's own exit code is passed through |

`mcp wrap` exits `0` when the host disconnects or on SIGTERM/SIGINT.

`ci:validate` exits `1` on a failed secret with and without `--json`.

### Redaction token

Known secret values in `exec` / `run` output and in airlock results are
replaced with a redaction token. Both forms are frozen as of 0.19:

- `[QRING:REDACTED]`
- `[QRING:REDACTED:<KEY>]`, where `<KEY>` is the name of the q-ring key
  whose value was replaced

Tools that post-process redacted output can match both on the
`[QRING:REDACTED` prefix. Redaction is exact-match against values the ring
knows (`src/core/exec.ts`, `src/core/wrap-redact.ts`); `exec` / `run` skip
values of 5 characters or fewer.

### Known defect scheduled for 0.19

`qring exec --profile <name>` and `qring run --profile <name>` accept any
name. An unknown one (a typo such as `restrcted`) becomes an empty profile
with no restrictions instead of an error (`getProfile` in
`src/core/exec.ts`). The MCP `exec_with_secrets` tool is not affected: its
`profile` input only accepts `unrestricted`, `restricted` and `ci`. This
fails open, so it is a defect, not frozen behaviour; it is fixed before the
0.19 tag, after which an unknown profile name is an error.

## Experimental (not frozen)

These ship in 0.19 and are supported, but their surface may change in a
minor release, before or after 1.0. Each change is called out in the
CHANGELOG.

- **The airlock over HTTP.** `qring mcp wrap --url <url>` (a remote
  Streamable HTTP MCP server) with `--header <name:value>` and
  `--auth-secret <KEY>`. The stdio airlock (`qring mcp wrap -- <command>`),
  its other flags and `policy.wrap` are frozen; the remote transport is
  newer (0.17.5) and depends on a protocol transport that is still moving.
- **Integrations that drive third-party CLIs.** `qring push <target>`
  (`gh`, `vercel`, `wrangler`, `flyctl`, `railway`, `netlify`;
  `src/core/push.ts`), `qring canary plant --push`, and the `aws-sts` JIT
  provider, which runs the `aws` CLI (`src/core/provision.ts`). Frozen: the
  command names, the target names, `--keys`, `--project-path`, `--env`,
  `--dry-run`, and the guarantee that values reach the platform CLI over
  stdin (or, for Netlify, a private `0600` temp file), never argv.
  Experimental: the target-specific flags (`--repo`, `--vercel-env`,
  `--app`, `--service`, `--railway-env`, `--site`), how each platform CLI is
  invoked (they change on their own schedule), and the `--json` result.
- **Provider-native rotation.** `qring rotate`, the `rotate_secret` tool and
  `qring agent --auto-rotate` try provider-native rotation first, but no
  built-in provider implements it in 0.19 (`supportsRotation` is never set
  in `src/core/validate.ts`), so rotation always generates a new value
  locally. The command, tool and input names are frozen; the provider path,
  the locally generated format and the `provider` / `message` fields of the
  result are not.
- **Bare JSON outputs outside the envelope.** `qring setup --json`,
  `qring mcp approvals --json` and
  `qring agent --once` print a bare payload. Their shapes may change until
  they move to the `{ "ok": true, "data": … }` envelope.
- **The status dashboard's HTTP API.** `/api/status` and the SSE stream
  behind `qring status` / `status_dashboard` serve the bundled page only.
  The command, its flags and the tool are frozen; the payload is not.
- **macOS and Windows.** The CI legs for macOS and Windows (and the Node 18
  build-only leg) run with `continue-on-error` in `.github/workflows/ci.yml`.
  Linux is the tested platform; behaviour elsewhere is best effort until
  those legs block.

## Not part of the contract

- Human-readable output: wording, colours, layout, help text.
- MCP tool and parameter descriptions, and the tool annotations.
- The list of validation providers and the prefixes used to auto-detect
  them (providers are added in minors).
- How audit events are grouped into agent sessions.
- The JSON registry files under the config dir (`hooks.json`,
  `approvals.json`, `entanglement.json`, `canary-alerts.json`, observer
  state). q-ring migrates them itself; edit them through the CLI.
- Internal variables: `__QRING_HTTP_CFG` (passes config to the HTTP JIT
  child) and the `__QRING__` dashboard global.
- The modules under `dist/`. q-ring ships two binaries, not a library API.

## Semver promise from 1.0

From 1.0.0, q-ring follows [semantic versioning](https://semver.org) for
everything listed under [Frozen as of 0.19](#frozen-as-of-019).

A **patch** release (1.x.y) fixes bugs and security issues. It changes no
surface, except to make behaviour match this document.

A **minor** release (1.x.0) may add:

- new commands, subcommands, flags and aliases;
- new MCP tools, new optional tool parameters, new enum values on inputs,
  and new resource URIs (the tool count in the docs goes up);
- new optional fields in JSON outputs, tool results, envelope `meta`, audit
  events, teleport bundles and session objects;
- new audit actions, push targets, JIT providers, validation providers,
  canary formats and environment variables;
- new optional keys in `.q-ring.json`, including the `policy` blocks.
  Because the policy schema is strict, a file that uses a key added in 1.x
  needs q-ring 1.x or later; older versions fail closed on it.

Readers must tolerate what a minor may add: unknown JSON fields and unknown
audit actions. An older 1.x that rewrites an envelope drops `meta` fields it
does not know.

Only a **major** release may remove or rename a frozen command, flag, tool,
parameter, resource URI, policy key, environment variable or exit code;
make an optional input required; change the type or meaning of an existing
input or output field; change a stored format so that data written by the
previous major can no longer be read; or raise the minimum Node.js version.
Anything removed in a major was deprecated first, under the policy below.

**Node.js floor.** `engines.node` is `>=18` in 0.19. Node 18 is end of
life, so 1.0 may raise the floor to `>=20`; after 1.0, only a major raises
it.

**Security exception.** A fix for a vulnerability may tighten frozen
behaviour in any release (refuse something that used to be allowed), as
0.14.0 did for approvals and the `restricted` exec profile. Such a change
is listed under `Security` in the CHANGELOG with what to do about it.

## Deprecation policy

1. A deprecated item keeps working for **at least one minor release**
   after the release that deprecates it.
2. While deprecated, using it prints **one line to stderr, once per
   process**, starting `q-ring: deprecated:` and naming the replacement and
   the removal version (`warnDeprecated` in `src/core/deprecation.ts`).
   Warnings never go to stdout (so `--json` consumers and the MCP stdio
   stream are unaffected) and never contain a secret value. Set
   `QRING_SILENCE_DEPRECATIONS=1` to silence them.
3. Every deprecation is listed in this document under the release that
   deprecates it, and in the CHANGELOG under `Deprecated`.
4. Removal happens **only in a major release**. Items deprecated in 0.19
   may be removed in 1.0, the major that closes the 0.x line; anything
   deprecated during 1.x is removed in 2.0 at the earliest.

## Deprecated in 0.19

Each item below still works in 0.19, prints a one-line
`q-ring: deprecated: …` warning on stderr the first time it is used in a
process (silence with `QRING_SILENCE_DEPRECATIONS=1`), and is **removed in
1.0**. The CHANGELOG lists the same items under `Deprecated`.

| What | Replacement | Removed in | Warning | Evidence |
| --- | --- | --- | --- | --- |
| `qring approve <key> --list` (needs a throwaway `<key>` and duplicates a whole command) | `qring approvals` (also supports `--json`) | 1.0 | `src/cli/commands/security.ts:36` | flag at `src/cli/commands/security.ts:26`; replacement at `:90` |
| Bare `--json` output of `qring context`, `qring ci:validate` and `qring policy` | The `{ "ok": true, "data": … }` wrapper every other `--json` command uses; 1.0 switches these three to it, and the shape is unchanged until then | 1.0 | `src/cli/commands/project.ts:36`, `src/cli/commands/validation.ts:347`, `src/cli/commands/security.ts:128` | documented as "legacy shapes … kept for backward compatibility" in `docs/cli-mcp-parity.md:99` |
| Teleport v1 bundles with no `iter` field (packed before 0.12.0, PBKDF2 at 100 000 iterations) | Re-pack with current q-ring (v1 bundles record `iter`, 210 000) or use v2 recipient packs (`qring teleport pack --to`) | 1.0 | `src/core/teleport.ts:191` (on unpack) | `src/core/teleport.ts:40`; `CHANGELOG.md:557` |
| Agent memory encrypted under the machine-derived key (stores written before 0.14.0) | The OS-keyring key (the store is re-encrypted under it on first read where a keyring exists) or `QRING_MEMORY_PASSPHRASE` | 1.0 | `src/core/memory.ts:173` (on read or migration) | `src/core/memory.ts:78`; `CHANGELOG.md:416` |
| `QRING_CANARY_ALERTS_PATH` (undocumented; the test suite was its only user) | `QRING_CONFIG_DIR` (the registry is `<dir>/canary-alerts.json`) | 1.0 | `src/core/canary-webhooks.ts:67` (when set) | `src/core/canary-webhooks.ts:65` |
| `Q_RING_ALLOW_PRIVATE_HOOKS` (the only variable without the `QRING_` prefix) | `QRING_ALLOW_PRIVATE_HOOKS=1`; either name enables the override in 0.19 | 1.0 | `src/core/ssrf.ts:29` (when only the old name is set) | `privateTargetsAllowed` at `src/core/ssrf.ts:26` |

Considered and **kept** (not deprecated):

- Reading a keychain value that is not an envelope as a plain value
  (`src/core/envelope.ts:186`): zero cost, and dropping it would make old or
  externally written entries unreadable.
- Teleport v1 passphrase bundles as such: a supported mode next to v2.
- `qring get --raw`: older docs call it the "legacy" stream, but it is the
  only way to get a bare value in a script.
- `--json` on both the root and the subcommand; `promote -y` as an alias of
  `--force` (matches the `-y` convention elsewhere).
- Approvals granted before 0.14.0 and entanglement registries without a
  `version`: the former already grant nothing (`qring doctor` reports
  them), the latter are still read as is.

## Support window

| Line | Receives |
| --- | --- |
| 0.18.x and older | Nothing; upgrade to 0.19 |
| 0.19.x (release candidate) | Bug and security fixes until 1.0.0; security fixes only for 90 days after 1.0.0 |
| Latest 1.x minor | Bug and security fixes |
| Previous 1.x minor | Security fixes only, for 90 days after the next minor ships |

Before 1.0 only the latest minor is supported; the table in
[SECURITY.md](../SECURITY.md) shows the line that receives every fix and is
regenerated by `scripts/sync-versions.mjs` on each release. Report
vulnerabilities as described there.
