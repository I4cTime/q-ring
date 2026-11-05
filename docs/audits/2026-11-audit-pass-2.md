# Internal adversarial audit, pass 2 (November 2026)

Tracking issue: [#133](https://github.com/I4cTime/q-ring/issues/133).
Branch: `security/0.19-audit-pass-2`, based on `main` at `cdac34d`.
Audit date: 2026-11-04.

This is the second self-run adversarial review, after the one that shipped
in 0.14.0. It covers the surfaces added since: the MCP airlock (`qring mcp
wrap`), canary honeytokens and their alerting, teleport v2 recipient packs,
push targets, promote/diff, rotation reminders, the new introspection
resources, the file backend, `qring://` refs and `qring run`, approvals,
notify, and the policy loader. Findings were self-discovered; there is no
external reporter and no evidence of exploitation. Following the house style
of 0.13.1 and 0.14.0, each finding is fixed with a regression test and will
be disclosed in the 0.19.0 CHANGELOG `Security` section, without a GHSA or
CVE.

The CHANGELOG has never numbered audit findings. Code comments do: the
0.14.0 audit appears as A2 to A6 and B1 to B4, and the 0.16.2 canary fixes
as S2 and S8. To avoid colliding with those, this pass uses a C series:
C1 to C26, in commit order. No code comment cites these ids. C18 to C26
came from the adversarial review of PR #143 (each upheld by three of three
reviewers) and are fixed on the same branch.

Id mapping from the first draft of this report: B1 to B14 became C1 to C14
(same order); C15 to C17 were draft items N13 to N15, fixed on this branch.

## Attacker models

1. **Prompt-injected agent**: can call any MCP tool the policy allows.
2. **Malicious wrapped downstream MCP server**: behind `qring mcp wrap`.
3. **Malicious teleport bundle or recipient string**.
4. **Hostile child process** under `qring exec` / `qring run`.
5. **Local user without the keyring**: can see files and process
   arguments, not keychain contents.

For every surface the review looked for: policy bypass (glob anchoring, case,
unicode, tool-name collisions across downstream servers), path traversal and
symlink races in file writes, argv and env leakage of values, TOCTOU in
approvals and rate limits, replay or downgrade in teleport, canary identity
inference through any output or timing, SSRF in webhooks and HTTP
downstreams (redirects included), audit-chain gaps, fail-open error
handling, prototype pollution and schema laxness in JSON input, and secrets
in error messages or logs.

## How findings were verified

Every finding below has a regression test that **fails without the fix
and passes with it**: on `cdac34d` for C1 to C17, and on the commit just
before the fix for C18 to C26. Each was checked by running the test both ways (the
fix's source files reverted to the base, then restored). Where the test
demonstrates the attack itself rather than only the corrected behaviour,
the table says "attack reproduced". Items in "Examined and sound" and
"Not fixed" are from reading the code unless they say otherwise.

## Findings

| Id | Severity | Surface | Summary |
| --- | --- | --- | --- |
| C1 | Medium | exec / run | `--profile <typo>` ran with no restrictions |
| C2 | Medium | canary | `canary plant --force` kept the old secret's stats and settings, and propagated the fake value into entangled real secrets |
| C3 | High | policy | `policy.mcp.deniedTags` was never enforced |
| C4 | High | policy / MCP writes | MCP writes ignored key policy: a denied key could be overwritten |
| C5 | Medium | canary / audit | canary trips were recoverable from `prevHash` gaps in agent-facing audit views |
| C6 | Medium | canary alerts | a blocked alert delivery wrote an agent-visible `policy_deny` naming the canary |
| C7 | Medium | canary / validate | `ci_validate_secrets` read every value silently: no audit, no canary trip |
| C8 | High | hooks | MCP `register_hook` created live shell and signal hooks outside exec policy |
| C9 | Medium | exec / run / wrap / push | children inherited `QRING_FILE_PASSPHRASE` and `QRING_MEMORY_PASSPHRASE` |
| C10 | Medium | airlock | downstream error, progress and URI text bypassed result redaction |
| C11 | Medium | push | a value could inject extra variables into fly or netlify |
| C12 | High | exec | keys named `NODE_OPTIONS`, `LD_PRELOAD`, ... were injected into children |
| C13 | Low | teleport | bundle strings with control characters reached the terminal |
| C14 | Low | file backend | the store was rewritten in place; a failed write destroyed it |
| C15 | Low | airlock | tool-name globs stopped at a newline, and the rate limiter grew without bound |
| C16 | Low | hooks | an SSRF-blocked HTTP hook logged its full URL (path and query) |
| C17 | Low | environments | environment names resolved to `Object.prototype` members |
| C18 | High | exec | the C12 denylist missed whole families (`GIT_EXTERNAL_DIFF`, `MAKEFLAGS`, `PAGER`, ...) |
| C19 | High | entanglement | entanglement checks ignored `deniedTags` in both directions |
| C20 | Medium | bulk MCP writers | import_dotenv and teleport_unpack aborted halfway on a protected key |
| C21 | Medium | keyring | write paths used the policy-filtered `hasSecret` as an existence check |
| C22 | Medium | lint | lint_files --fix aborted halfway on a protected key and lost a rewrite |
| C23 | Low | agent_scan | MCP auto-rotation wrote as "agent" and ignored the MCP write policy |
| C24 | Low | canary alerts | a blocked alert delivery counted as a canary trip |
| C25 | Low | keyring | deleteSecret read each envelope twice |
| C26 | Low | keyring | a delete across scopes deleted allowed copies before refusing a denied one |

### C1: unknown exec profile ran unrestricted (Medium)

- **Surface:** `qring exec --profile`, `qring run --profile` (`src/core/exec.ts`).
- **Attack:** `qring exec --profile restriced -- python -c ...` (a typo, or
  a script that passes a name through) resolved the unknown name to
  `{ name }`, an empty profile: no deny list, no network block, no runtime
  cap. Names were looked up with a plain index, so `constructor` resolved to
  an `Object.prototype` member. The MCP tool was not affected (its `profile`
  is a zod enum).
- **Evidence:** `src/core/exec.ts:57`
  `return BUILTIN_PROFILES[name] ?? { name };`.
- **Fix:** `getProfile` looks names up by own property and throws
  `Unknown exec profile "<name>". Known profiles: unrestricted, restricted, ci`.
  The change stays inside `getProfile`, because `exec.ts` is also being
  reworked on the redaction branch.
- **Test:** `src/__tests__/core/exec-redaction.test.ts` ("getProfile rejects
  unknown profile names"), `src/__tests__/core/run.test.ts` ("refuses an
  unknown profile...", "execCommand with an unknown profile"). Attack
  reproduced: before the fix, the run test's child ran.
- **Commit:** `fix(exec): refuse an unknown exec profile instead of running unrestricted`.

### C2: forced canary plant inherited the replaced secret (Medium)

- **Surface:** `plantCanary` (`src/core/canary.ts`), `setSecret`
  (`src/core/keyring.ts`).
- **Attack:** `qring canary plant KEY --force` over a real secret went
  through `setSecret`'s metadata inheritance. The canary kept the old
  `createdAt` and `accessCount`, so `plantedAt` was wrong and `tripCount`
  was non-zero: the canary listed as **tripped right after planting**
  (`qring canary list`, `qring://canaries`). Rotation, approval, JIT and
  entanglement settings carried over too. Because the key was still
  entangled, `setSecret` then **propagated the fake canary value into every
  entangled partner**, overwriting real credentials with noise. The reverse
  also held: a real write to an entangled partner landed in the canary.
- **Evidence:** `src/core/keyring.ts:409-410` (createdAt and accessCount
  copied from `existing`), `src/core/keyring.ts:326` (all metadata
  inherited from `existing`), `src/core/keyring.ts:417` (propagation with no
  canary check), `src/core/canary.ts:189` (plant through the inheriting
  path).
- **Fix:** `setSecret` gains an internal `freshMeta` option, which
  `plantCanary` uses. Canary writes never propagate to entangled partners,
  and propagation never writes into a canary. `CANARY_FORMATS` is looked up
  by own property.
- **Test:** `src/__tests__/core/canary.test.ts`: "a forced plant over a
  real secret starts fresh...", "...never propagates the fake value into
  entangled real secrets", "a real write to an entangled partner never lands
  in a canary", "does not resolve Object.prototype members as formats".
  Attack reproduced: the partner's real value was overwritten before the fix.
- **Commit:** `fix(canary): plant over an existing secret with fresh metadata, never propagate canary values`.

### C3: `policy.mcp.deniedTags` never enforced (High)

- **Surface:** the key policy (`src/core/policy.ts`, `src/core/keyring.ts`).
- **Attack:** `deniedTags` is part of the frozen policy schema and is
  validated, but every caller of `checkKeyReadPolicy` passed `undefined` for
  the tags, so the tag rule never ran. A secret tagged `prod` under
  `"deniedTags": ["prod"]` stayed readable, listable, exportable, injectable
  (exec) and deletable over MCP.
- **Evidence:** `src/core/keyring.ts:168,296,479,552,629` (all pass
  `undefined`); the tag branch at `src/core/policy.ts:276` was unreachable.
- **Fix:** once the envelope is read, its tags are checked in `getSecret`,
  `getEnvelope`, `hasSecret`, `listSecrets` (and so export, exec and
  teleport_pack) and `deleteSecret`.
- **Test:** `src/__tests__/core/policy-denied-tags.test.ts`. Attack
  reproduced.
- **Commit:** `fix(policy): enforce policy.mcp.deniedTags on MCP reads`.

### C4: MCP writes ignored key policy (High)

- **Surface:** `setSecret` and every MCP tool that writes: `set_secret`,
  `teleport_unpack`, `import_dotenv`, `generate_secret saveAs`,
  `promote_secret`, `rotate_secret`, `lint_files --fix`.
- **Attack:** reads and deletes of a `deniedKeys` key are refused over MCP,
  but `setSecret` checked policy only for entangled propagation targets
  (the 0.14.0 A2 fix), never for the key being written. An agent could
  replace `PROD_DB_PASSWORD` directly with `set_secret`, or with
  `teleport_unpack` of a bundle it had packed itself. This is the direct
  form of the write bypass that 0.14.0 closed for entanglement.
  `lint_files --fix` also wrote with a hard-coded `source: "cli"`, so its
  writes were neither checked nor attributed to MCP in the audit log.
- **Evidence:** `src/core/keyring.ts:326` onwards (no key check before the
  write), `src/mcp/tools/secrets.ts:233`, `src/mcp/tools/teleport.ts:174`,
  `src/core/linter.ts:118`.
- **Fix:** an MCP-sourced `setSecret` checks `deniedKeys`, `readableKeys`
  and the stored secret's tags before writing. `lintFiles` takes the
  caller's source. **Behaviour change:** with a `readableKeys` allowlist,
  MCP writes are now limited to those keys as well, as deletes already were.
- **Test:** `src/__tests__/mcp/write-policy.test.ts` (set_secret,
  set_secret with env, teleport_unpack, import_dotenv, generate_secret).
  Attack reproduced.
- **Commit:** `fix(policy): hold MCP writes to key policy`.

### C5: canary trips recoverable from audit hash-chain gaps (Medium)

- **Surface:** MCP `export_audit` and the `qring://sessions/{id}` timeline.
- **Attack:** both strip canary trip events but kept every event's
  `prevHash`, the SHA-256 of the previous audit line. Once a trip line is
  removed, the next event's `prevHash` matches no exported line, so an agent
  that hashes the export learns which read tripped, and so which key is a
  canary, without touching it. Any past trip counts, including the
  operator's own test read right after planting. This undid the 0.17
  "canary trip records are operator-only" fix.
- **Evidence:** `src/core/observer.ts:456` (filter keeps `prevHash`, which is
  written at `:222`), `src/core/sessions.ts:148`.
- **Fix:** a filtered export (`excludeActions`) drops `prevHash` from every
  event, and so does the agent view of session events. The operator's
  unfiltered `qring audit:export` and `audit:verify` keep the chain.
- **Test:** `src/__tests__/core/audit-hardening.test.ts` ("export_audit
  carries no hash chain that would point at a removed trip") and
  `src/__tests__/core/sessions.test.ts`. Attack reproduced: on the base,
  the test finds exactly one orphaned `prevHash`, on the read just after the
  canary read.
- **Commit:** `fix(audit): drop hash-chain links from agent-facing audit views`.

### C6: blocked canary alert delivery named the canary (Medium)

- **Surface:** `sendOne` in `src/core/canary-webhooks.ts`.
- **Attack:** when an alert channel failed the SSRF guard, every trip wrote
  a `policy_deny` event with `key: <canary>` and the detail
  `canary alert SSRF blocked`. The guard blocks private addresses unless
  `QRING_ALLOW_PRIVATE_HOOKS=1`, so a self-hosted ntfy or webhook on the
  LAN triggers this on every trip. MCP `audit_log` hides only `canary`
  events, so an agent could list `policy_deny` events and read off canary
  names.
- **Evidence:** `src/core/canary-webhooks.ts:223`, read through
  `src/mcp/tools/audit.ts:73`.
- **Fix:** the block is logged as an operator-only `canary` event with no
  `key` field (the key is named in the detail text, so trip counters do
  not count it).
- **Test:** `src/__tests__/core/canary-webhooks.test.ts` ("refuses
  SSRF-flagged URLs and audits the block"). Attack reproduced: the
  agent-visible view named the key before the fix.
- **Commit:** `fix(canary): keep blocked alert deliveries out of agent-visible audit`.

### C7: `ci_validate_secrets` read silently (Medium)

- **Surface:** MCP `ci_validate_secrets` (`src/mcp/tools/validation.ts`).
- **Attack:** the tool read every value in scope with `silent: true`. The
  description promises a read event per key, but a silent read writes no
  audit event, bumps no access counter and trips no canary. An agent could
  run every value past its provider and see which provider-shaped keys come
  back `invalid` (the canaries) with no trace and no alert. This is the
  ring sweep that 0.16.2 closed for `export_secrets`.
- **Evidence:** `src/mcp/tools/validation.ts:143`.
- **Fix:** the reads are no longer silent. The operator's CLI
  `qring ci:validate` is unchanged.
- **Test:** `src/__tests__/mcp/ci-validate-reads.test.ts`. Attack
  reproduced (no read or canary events before the fix).
- **Commit:** `fix(validate): ci_validate_secrets reads are audited and trip canaries`.

### C8: MCP `register_hook` created live shell and signal hooks (High)

- **Surface:** MCP `register_hook` (`src/mcp/tools/hooks.ts`), with
  `executeShell` and `executeSignal` in `src/core/hooks.ts`.
- **Attack:** an agent could store a shell hook that then ran through
  `/bin/sh -c` on every matching write, with the server's full environment
  (`src/core/hooks.ts:164`), outside `policy.exec` (allow and deny lists,
  runtime cap), even when `exec_with_secrets` is denied by policy. The hook
  persists in `hooks.json`, fires on the operator's own CLI writes, and its
  stdout is copied into the audit detail, which the agent can read back.
  A signal hook could send `SIGKILL` to any process the user owns, matched
  by name.
- **Evidence:** `src/mcp/tools/hooks.ts:110` (`enabled: true`),
  `src/core/hooks.ts:164-171`.
- **Fix:** shell and signal hooks registered over MCP are stored with
  `enabled: false`. The tool result carries a `note` telling the operator to
  arm the hook with `qring hook enable <id>`. HTTP hooks (SSRF-guarded, no
  values in the body) stay enabled. **Behaviour change** for MCP clients
  that relied on immediate shell hooks.
- **Test:** `src/__tests__/mcp/register-hook.test.ts`, including that the
  hook does not run on the next write until it is enabled, and does run
  after. Attack reproduced: before the fix the hook came back enabled.
- **Commit:** `fix(hooks): shell and signal hooks registered over MCP start disabled`.

### C9: children inherited q-ring's master keys (Medium)

- **Surface:** exec and run children (`exec_with_secrets` included), a
  wrapped server under `--inherit-env`, and platform CLIs under `qring push`.
- **Attack:** on a file-backend host, `QRING_FILE_PASSPHRASE` unlocks the
  whole store and `QRING_MEMORY_PASSPHRASE` unlocks agent memory. Both sat
  in `process.env` and were copied into every child. A command run with
  `--keys ONE_KEY`, or a hostile child under `exec`, could decrypt every
  secret.
- **Evidence:** `src/core/exec.ts:196` and `src/core/run.ts:71` (full
  `process.env` copied), `src/core/exec.ts:302` (`env: envMap`),
  `src/core/wrap.ts:412`, `src/core/push.ts:251` (no `env`, so it inherits).
- **Fix:** `src/core/child-env.ts` (`withoutQringCredentials`) strips both
  variables in `spawnRedacted`, in the `--inherit-env` path and in push.
  **Behaviour change:** a child that itself calls `qring` on a file-backend
  host no longer gets the passphrase implicitly.
- **Test:** `src/__tests__/core/run.test.ts` ("exec/run children never
  inherit q-ring's master-key env vars"), `src/__tests__/core/push.test.ts`,
  `src/__tests__/core/child-env.test.ts`. Attack reproduced: the child
  printed both passphrases before the fix.
- **Commit:** `fix(exec): keep q-ring's master-key env vars out of child processes`.

### C10: airlock redaction skipped non-result text (Medium)

- **Surface:** `createAirlockServer` (`src/core/wrap.ts`). Only the
  redactor wiring changed; the engine is on the redaction branch.
- **Attack:** results were scrubbed, but text a wrapped server sends outside
  a result was not:
  - JSON-RPC error messages and error data from `tools/call`,
    `resources/read` and `prompts/get`;
  - the message of a plain downstream failure, which was also written
    verbatim into the audit log;
  - progress notification messages;
  - the resource URI recorded in the audit log (`db://...?password=`).

  A server that echoes a credential into an error (`401 for token sk-...`)
  put it in the transcript and in `audit.jsonl`.
- **Evidence:** `src/core/wrap.ts:309-311`, `:291`, `:339-340`, `:368`.
- **Fix:** all of these go through the redactor, failing closed (the text is
  withheld if the redactor throws). JSON-RPC error codes are preserved.
- **Test:** `src/__tests__/core/wrap-error-redaction.test.ts` (a stub
  downstream that throws and reports progress). Attack reproduced.
- **Commit:** `fix(wrap): redact downstream error, progress and URI text, not just results`.

### C11: push values could inject variables (Medium)

- **Surface:** `flyImportLine` and `dotenvLine` in `src/core/push.ts`.
- **Attack:** fly and netlify take `NAME=VALUE` lines. A value containing
  `"""` closed fly's triple quote early. Netlify's encoder wrote any value
  with a newline (or both quote kinds) unquoted. Either way the rest of the
  value was parsed as more variables. A value planted by an agent
  (`set_secret`) or by a teleport bundle could add `DATABASE_URL` or
  `NODE_OPTIONS` to a production app the next time the operator ran
  `qring push fly|netlify`.
- **Evidence:** `src/core/push.ts:100`, `src/core/push.ts:113`.
- **Fix:** a value with no exact encoding for the target, or a key that is
  not a plain variable name, fails that key (dry runs included) and is never
  sent.
- **Test:** `src/__tests__/core/push.test.ts` ("values that would inject
  extra variables"). Attack reproduced: the injected line reached the CLI's
  stdin or the temp file before the fix.
- **Commit:** `fix(push): refuse values that would inject extra variables into fly or netlify`.

### C12: process-control variables injected into exec children (High)

- **Surface:** `execCommand` (`src/core/exec.ts`).
- **Attack:** exec injects every secret in scope under its own name. A key
  named `NODE_OPTIONS`, `LD_PRELOAD`, `PATH`, `BASH_ENV`, `PYTHONSTARTUP`,
  `JAVA_TOOL_OPTIONS`, `GIT_SSH_COMMAND` or `npm_config_*` is not a
  credential; it is code that runs inside the child before the child's own.
  `NODE_OPTIONS=--import=data:text/javascript,...` needs no file. An agent
  that may call `set_secret` and `exec_with_secrets` could therefore run
  arbitrary code, with every injected secret, inside a command that
  `policy.exec.allowCommands` permits. A teleport bundle could do the same
  to the operator's next `qring exec`.
- **Evidence:** `src/core/exec.ts:241` (`envMap[entry.key] = val` for any
  name).
- **Fix:** keys whose names steer process start-up
  (`isProcessControlEnvName` in `src/core/child-env.ts`) are left out of
  exec children. Over MCP they are left out even when named in `keys`. The
  local operator can still inject one deliberately with `--keys NAME`; the
  CLI sweep prints a note when it skips one.
- **Test:** `src/__tests__/core/exec-env-injection.test.ts`. Attack
  reproduced: on the base an allowlisted MCP exec printed `PWNED` from a
  planted `NODE_OPTIONS`.
- **Follow-up:** the list was incomplete; C18 widens it to whole families.
- **Commit:** `fix(exec): never sweep process-control variables like NODE_OPTIONS into a child`.

### C13: teleport bundle strings with control characters (Low)

- **Surface:** `TeleportPayloadSchema` and `TeleportBundleV2Schema`
  (`src/core/teleport.ts`).
- **Attack:** anyone who knows a recipient's public string can make a v2
  bundle. Its key names and scopes are printed by `--dry-run`, the
  overwrite prompt and MCP dry runs, and its recipient ids (from the
  unauthenticated header) by the `--dry-run` preamble. ANSI escapes in a key
  name could erase preview lines and hide which keys an unpack overwrites;
  an id could fake `(you)`.
- **Evidence:** `src/core/teleport.ts:81` (`key: z.string()`), `:262`
  (`id: z.string()`), printed at `src/cli/commands/quantum.ts:399,449`.
- **Fix:** payload keys must be 1-256 printable characters, scopes 1-64,
  and recipient ids exactly 8 hex characters. Anything else is
  `ERR_TELEPORT_CORRUPT`.
- **Test:** `src/__tests__/core/teleport-v2.test.ts` ("bundle strings that
  reach the terminal").
- **Commit:** `fix(teleport): refuse control characters in bundle strings that reach the terminal`.

### C14: file-backend store rewritten in place (Low)

- **Surface:** `saveStore` (`src/core/backend.ts`).
- **Attack (availability and integrity):** the single file holding every
  secret was truncated and rewritten in place. A crash, a kill or a full
  disk mid-write destroyed the store. A concurrent reader (the MCP server
  reads without the writer's lock) could see a half-written file.
- **Evidence:** `src/core/backend.ts:151`.
- **Fix:** write to a 0600 temp file beside the store (`O_EXCL`), then
  rename it over the store. On failure the temp file is removed and the old
  store is intact.
- **Test:** `src/__tests__/core/backend-file-atomic.test.ts` (an ENOSPC
  that fails halfway through the write). Attack reproduced: before the fix,
  every secret was unreadable after the failed write.
- **Commit:** `fix(backend): write the file-backend store atomically`.

### C15: wrap globs and rate-limiter growth (Low)

- **Surface:** `matchesToolPattern` (`src/core/policy.ts`) and the
  airlock's `RateLimiter` (`src/core/wrap.ts`).
- **Attack:** a glob compiled `*` to `.*` without the dotAll flag, so a
  tool named `delete_\nrepo` slipped past a `delete_*` deny. Only a
  downstream that names its tools that way can do it, and allow lists
  already failed closed. Separately, the rate limiter kept one entry for
  every distinct tool name an agent called, real or invented, for the life
  of the session: a name spray grew memory without bound.
- **Evidence:** `src/core/policy.ts:352` (no `s` flag),
  `src/core/wrap.ts:129` (unbounded `Map`).
- **Fix:** the patterns use the `s` flag. The limiter tracks at most 1024
  names (`RATE_LIMITER_MAX_TOOLS`). When it is full, the oldest entry whose
  window has passed is evicted. If every tracked window is still live, the
  new name is refused rather than evicting one: evicting a live window
  would reset that tool's count, so a spray of 1024 names could otherwise
  lift any tool's limit.
- **Test:** `src/__tests__/core/wrap-limits.test.ts` (a newline cannot
  dodge a deny glob; the map never exceeds the cap; a name spray cannot
  reset a live tool's window). On the base the glob test fails on
  behaviour; the limiter tests fail because the limiter had no cap (and was
  not exported for testing).
- **Commit:** `fix(wrap): globs match across newlines and the rate limiter is bounded`.

### C16: hook SSRF block logged the full URL (Low)

- **Surface:** `executeHttp` (`src/core/hooks.ts`).
- **Attack:** when the SSRF guard blocked an HTTP hook, the `policy_deny`
  event carried the whole URL. Webhook paths and query strings are often
  the credential (Slack and Discord webhook paths, `?token=`), and
  `audit_log` is readable over MCP.
- **Evidence:** `src/core/hooks.ts:208`.
- **Fix:** the detail names only `scheme://host[:port]`.
- **Test:** `src/__tests__/core/hooks-ssrf-audit.test.ts`. Attack
  reproduced: the path and token were in the audit log before the fix.
- **Commit:** `fix(hooks): log only scheme and host when an HTTP hook is SSRF-blocked`.

### C17: environment names resolved to prototype members (Low)

- **Surface:** `collapseValue` (`src/core/envelope.ts`), promote and diff
  (`src/core/promote.ts`), the branch map (`src/core/collapse.ts`).
- **Attack:** environment names come from callers (MCP `env`, `--env`,
  `?env=` refs, promote and diff arguments, the current branch name) and
  indexed plain objects. `constructor`, `toString` or `valueOf` resolved to
  `Object.prototype` members: promote could copy a function into a state,
  diff reported phantom differences, collapse returned a function where a
  string was expected, and a branch named `constructor` mapped to an
  environment. No value was disclosed.
- **Evidence:** `src/core/envelope.ts:213`, `src/core/promote.ts:69,74,134`,
  `src/core/collapse.ts:222` (line numbers at `cdac34d`).
- **Fix:** lookups go through `Object.hasOwn` (`ownState` in
  `envelope.ts`); a prototype name is simply an absent environment.
- **Test:** `src/__tests__/core/env-own-property.test.ts` (collapse,
  promote, diff, and a real repository on a branch named `constructor`).
- **Commit:** `fix(env): look environment names up by own property`.

### C18: process-control denylist missed whole families (High)

- **Surface:** `isProcessControlEnvName` (`src/core/child-env.ts`), used by
  exec (C12).
- **Attack:** C12 listed a handful of loader and interpreter variables, but
  git, ssh, make, cargo, pagers and editors obey many more. A key planted
  as `GIT_EXTERNAL_DIFF`, `GIT_ASKPASS`, `GIT_PROXY_COMMAND`, `GIT_PAGER`,
  `SSH_ASKPASS`, `MAKEFLAGS`, `MAKEFILES`, `RUSTC_WRAPPER`, `CARGO_*`,
  `GLIBC_TUNABLES`, `PAGER`, `EDITOR`, `HOME` or `KUBECONFIG` still ran code
  inside an allowlisted `git diff` or `make`.
- **Fix:** whole families are denied by prefix (`GIT_`, `SSH_`, `CARGO_`,
  `RUSTC`, `RUSTFLAGS`, `MAKE`, `PYTHON`, `PERL`, `RUBY`, `JAVA`, `JDK_`,
  `NODE_`, `NPM_`, `YARN_`, `PNPM_`, `BUN_`, `DENO_`, `LD_`, `DYLD_`,
  `GCONV_`, `GLIBC_`), plus exact shell, home, config-path, pager and
  editor, compiler and Go toolchain names. Two deliberate exemptions:
  credentials inside a family (last `_` segment `TOKEN`, `KEY`, `SECRET`,
  `PASSWORD` or `PAT`, so `NPM_TOKEN`, `NODE_AUTH_TOKEN`,
  `CARGO_REGISTRY_TOKEN` and `SSH_PRIVATE_KEY` still inject; never
  `GIT_CONFIG_*`), and `NODE_ENV`. A token value cannot run code, and
  denying these would break `npm publish` and deploy keys. The CLI
  `--keys NAME` override is unchanged.
- **Not a sandbox.** The `restricted` profile and this denylist do not
  confine a child. A caller who controls the arguments of an allowed binary
  can still run code through the binary itself (`git -c core.pager=…`,
  `make -f …`, `npm run …`). The denylist closes the environment-variable
  route only. `docs/threat-model.md` now says so.
- **Test:** `src/__tests__/core/exec-env-gadgets.test.ts`: allowlisted
  `git diff --no-index` with `GIT_EXTERNAL_DIFF`, and `make -f` with
  `MAKEFILES` and with `MAKEFLAGS=--eval=$(shell …)`, plus the family
  classification. Attack reproduced: on the parent commit all three
  gadgets ran the payload and created the marker.
- **Commit:** `fix(exec): deny whole families of process-control env vars`.

### C19: entanglement ignored deniedTags (High)

- **Surface:** the MCP `entangle_secrets` gate (`src/mcp/tools/secrets.ts`)
  and the propagation loop in `setSecret` (`src/core/keyring.ts`).
- **Attack:** both checks passed `undefined` for the tags. With deniedTags
  enforced on direct reads and writes (C3, C4), entanglement was the way
  around it, in both directions:
  - **write:** an MCP write to a scratch key propagated into a tag-denied
    entangled partner;
  - **read:** a link *from* a tag-denied key to a readable one copied its
    value across on the next operator write.
- **Fix:** both checks read the envelope and pass its tags. A blocked MCP
  propagation is audited as `policy_deny` (key name only, never the value).
- **Test:** `src/__tests__/core/entanglement-tags.test.ts` (the write path:
  set_secret SCRATCH leaves PROD unchanged; the read path: the link from
  PROD is refused over MCP). Attack reproduced.
- **Commit:** `fix(entangle): judge entanglement by the stored tags as well as the key name`.

### C20: bulk MCP writers aborted halfway (Medium)

- **Surface:** `importDotenv` (`src/core/import.ts`), MCP `import_dotenv`
  and `teleport_unpack`.
- **Attack (integrity):** both called `setSecret` in a loop. After C4 the
  first protected key threw after the keys before it had been written,
  leaving a half-applied import, an error, and no list of what landed.
- **Fix:** `checkKeyWritePolicy(key, opts)` in `keyring.ts` makes the same
  decision as `setSecret`, judged against the stored secret's tags, and
  runs for every key before anything is written. Allowed keys are written;
  protected ones are skipped. `importDotenv` returns them in the additive
  `skippedByPolicy: [{ key, reason }]` field, and both tools list them as
  `Skipped (policy): KEY: reason`. A policy skip is not an error.
- **Test:** `src/__tests__/mcp/bulk-write-policy.test.ts` (importDotenv,
  the import_dotenv tool and teleport_unpack, each under deniedKeys and
  deniedTags, with the protected keys between allowed ones). Attack
  reproduced: on the parent commit, keys after the first protected one
  were never written.
- **Commit:** `fix(policy): bulk MCP writers skip protected keys instead of aborting midway`.

### C21: write paths used the policy-filtered existence check (Medium)

- **Surface:** `hasSecret` and its write-path callers (`src/core/keyring.ts`,
  `src/core/import.ts`).
- **Attack:** over MCP, `hasSecret` reports a policy-hidden key as absent,
  which is correct for has_secret, get and list. `skipExisting` used it as
  an existence check, so a hidden existing key looked absent and the import
  went on to overwrite it.
- **Fix:** a new `secretExists` returns true, decay-aware existence for write
  paths. `hasSecret` stays the visibility answer, and both comments state
  the distinction. Write paths run `checkKeyWritePolicy` first, so a
  protected key is a policy skip, never mistaken for an absent one.
- **Test:** `src/__tests__/core/secret-exists.test.ts`.
- **Commit:** `fix(keyring): write paths use true existence, not the policy-filtered view`.

### C22: lint_files --fix aborted halfway (Medium)

- **Surface:** `lintFiles` (`src/core/linter.ts`).
- **Attack (integrity):** each fix rewrote the literal, then called
  `setSecret`. A protected key threw midway: earlier files were already
  rewritten and stored, later files were never processed, and the throwing
  file's rewrite was lost.
- **Fix:** each fix runs `checkKeyWritePolicy` first. A protected key is
  reported on its result (`fixed: false`, `skipped: <reason>`) and its
  literal is left in place, since rewriting it without storing the value
  would lose it. The other fixes still run. The existing-key check uses
  `secretExists`.
- **Test:** `src/__tests__/core/linter.test.ts` ("lintFiles --fix from an
  MCP caller"): file1 fixed, file2's denied key skipped with a reason,
  file3 still processed. Attack reproduced.
- **Commit:** `fix(lint): lint_files --fix skips protected keys instead of aborting`.

### C23: agent_scan auto-rotation bypassed the MCP write policy (Low)

- **Surface:** `runHealthScan` (`src/core/agent.ts`), MCP `agent_scan`.
- **Attack:** auto-rotation wrote with `source: "agent"`, so
  `agent_scan { autoRotate: true }` from an agent overwrote any expired
  secret, protected ones included, with a generated value (breaking the
  credential). The writes were attributed to the local daemon.
- **Fix:** `runHealthScan` takes a `writeSource`, and the MCP tool passes
  `"mcp"`. Each rotation runs `checkKeyWritePolicy`; protected keys are
  never rotated and are listed in the additive `rotationSkipped` report
  field.
- **Test:** `src/__tests__/mcp/agent-scan-policy.test.ts`. Attack
  reproduced.
- **Residual:** agent_scan's warnings still name expired keys that MCP
  key policy hides (as before this pass). Listing through the MCP view
  would fix that; it is left for the 0.20 issues alongside N1 to N12.
- **Commit:** `fix(agent): agent_scan auto-rotation over MCP honours the MCP write policy`.

### C24: blocked alert delivery counted as a trip (Low)

- **Surface:** `sendOne` (`src/core/canary-webhooks.ts`) and every
  agent-facing audit filter.
- **Attack (integrity of the trip record):** C6 logged a blocked delivery
  with action `canary`. Each trip on a LAN-only channel therefore counted
  twice in trip and session counts.
- **Fix:** a new action, `canary_alert`, with the key and the detail
  `delivery blocked (scheme://host)`. Trip counts read `canary` only. A
  shared `AGENT_HIDDEN_ACTIONS` list (`canary`, `canary_alert`) drives MCP
  audit_log, export_audit and the qring://sessions resources.
- **Test:** `src/__tests__/core/canary-webhooks.test.ts`,
  `src/__tests__/core/sessions.test.ts` ("blocked canary alert
  deliveries"), `src/__tests__/core/audit-hardening.test.ts` ("audit_log
  and export_audit hide blocked canary alert deliveries").
- **Commit:** `fix(canary): record blocked alert deliveries as canary_alert, not as trips`.

### C25: deleteSecret read each envelope twice (Low)

- **Surface:** `deleteSecret` (`src/core/keyring.ts`).
- **Issue:** the deniedTags check (C3) and the canary-trip check each read
  the envelope. That is two keyring round trips, and the two checks could
  judge different copies if the secret changed in between.
- **Fix:** one read serves both.
- **Test:** `src/__tests__/core/delete-secret.test.ts` (one read of the
  key's entry).
- **Commit:** `fix(keyring): deleteSecret reads each envelope once`.

### C26: delete across scopes deleted before refusing (Low)

- **Surface:** `deleteSecret` (`src/core/keyring.ts`).
- **Attack (integrity):** with no scope, delete walks project then global
  and checked the tag policy inside the loop. An MCP delete of a key whose
  project copy is untagged and whose global copy is tagged `prod` deleted
  the project copy, then threw.
- **Fix:** every copy is read and checked first; a denial deletes nothing.
- **Test:** `src/__tests__/core/delete-secret.test.ts` ("checks policy on
  every scope's copy before deleting any of them"). Attack reproduced.
- **Commit:** `fix(keyring): a delete across scopes checks every copy before deleting any`.

## Examined and sound

These were reviewed adversarially and need no change. This is the list the
1.0 launch story can say was checked.

**MCP airlock (`wrap.ts`, `policy.wrap`)**
- **Policy failures fail closed.** Any failure to load the policy denies the
  call (the `gate()` catch). `toolAllowed` hides tools on error. An invalid
  policy stops `runWrap` before it proxies anything, because
  `wrapRedactsResults` throws. The existing test "fails closed when the
  policy file is invalid" covers this.
- **Deny wins over allow.**
- **Glob patterns are anchored and escaped.** Patterns are anchored
  `^...$`, every regex metacharacter except `*` is escaped, and allow lists
  fail closed for odd names.
- **Approvals are checked on every call.** Each `tools/call` checks
  `hasApproval`: HMAC over every field, `timingSafeEqual`, expiry, and a
  binding to `q-ring:wrap:<hash(projectPath)>`.
- **The rate limiter has no TOCTOU.** `take` is synchronous on the single
  event loop, so concurrent calls cannot race it.
- **Spawned servers get a minimal environment.** They receive the SDK's
  safe set unless `--inherit-env` is passed, which now also drops q-ring's
  master keys (C9).
- **`--auth-secret` stays out of argv.** The read is audited and the value
  never appears in argv or in the session label.
- **Tool arguments and prompt arguments are never logged.**
- **Progress tokens cannot collide.** They are remapped to the host's own
  token.

**Canary honeytokens**
- **Values carry no tell.** They are CSPRNG output with no default
  description, and `meta.canary` is not projected by any MCP tool response.
- **Bulk exports trip canaries:** `export_secrets` and `teleport_pack` do,
  and `ci_validate_secrets` does after C7.
- **Delete is a trip, and disarming is CLI-only.**
- **`qring://canaries` is dark by default.** Without
  `QRING_MCP_EXPOSE_CANARIES=1` it lists nothing, and it is also hidden when
  policy denies `audit_log`. Its alert targets show host only.
- **Webhooks are SSRF-guarded and never carry the value.** The URL is
  checked at add time (http/https only) and at send time with `checkSSRF`
  plus the connect-time `guardedLookup` rebinding guard. `node:http(s)`
  never follows redirects. The body never contains the canary value. Alerts
  are throttled; audit events are not.

**Teleport v2**
- **No key or nonce reuse:** a fresh content key per bundle and random
  96-bit IVs for both the payload and each wrap.
- **Per-recipient key wrap is bound:** X25519 with a single-use ephemeral
  key, HKDF-SHA256 salted with ephemeral‖recipient public keys, and the
  wrap AAD set to the recipient id. Swapping the ephemeral key or editing a
  wrap fails authentication; the existing tests cover this.
- **No silent downgrade.** v1 and v2 are told apart by a `z.literal`
  version. A v2 bundle never accepts a passphrase and a v1 bundle never
  uses the identity, so a v2-to-v1 substitution needs the passphrase anyway.
- **The private key never leaves the keyring.**
- **`NOT_A_RECIPIENT` reveals only the 8-hex ids already in the bundle.**
- **Unpack is gated on the CLI:** `--dry-run`, plus a confirmation before
  overwriting existing keys.

**Push, promote, diff, rotation**
- **Push never puts values in argv.** Values go over stdin, or into a 0600
  file inside a 0700 `mkdtemp` directory that is removed in `finally`
  (`O_EXCL` create). `shell: false` everywhere, and every pushed key is
  audited.
- **Promote and diff are safe.** Environment names are validated by regex,
  values are compared but never returned, and overwriting a different value
  needs `force`.
- **Rotation status is a pure function.** Unparseable dates are handled.
  `qring://rotation` is gated on `list_secrets` and lists through MCP-source
  key policy, which includes tags since C3.

**Other surfaces**
- **The policy loader fails closed.** The schema is strict at every level,
  the cache is keyed on content, and a file that is not JSON, not an object
  or unreadable fails closed. The full suite passes on the rebased base
  `cdac34d`.
- **`qring://` refs reject anything malformed.** They use their own
  grammar: the key-in-host form is rejected, keys must match
  `[A-Za-z_][A-Za-z0-9_]*`, and unknown query parameters are rejected.
- **`qring run` injects only what the project declares** (manifest and
  `.env` refs), and a missing required key is fatal.
- **Approvals are tamper-evident.** The HMAC covers every field
  (`workspace` and `sessionId` included), comparison is constant-time,
  expiry is enforced, and grants are bound to a project.
- **Notifications are inert.** `notify-send` and `osascript` get argv with
  no shell; Pango markup is escaped; AppleScript quotes are stripped.
- **The file backend fails closed.** It is explicit opt-in, uses PBKDF2 at
  210k iterations and AES-256-GCM with a fresh IV on every write, and
  refuses to run without the passphrase.
- **Audit text cannot inject into terminals.** Control characters are
  stripped from `key`, `detail`, `scope` and `env` at write time.

## Real issues not fixed here

These are real, but each needs a design decision, a change to a frozen
surface, or belongs to another branch. They are to be filed as issues for
0.20. Each has a recommendation.

### N1: the caller chooses its own exec profile (Medium)

`exec_with_secrets` takes `profile` as an input, so an agent can pass
`unrestricted` (`src/mcp/tools/tooling.ts:48`). `restricted` is the default,
not a boundary; only `policy.exec` actually binds an agent.
**Recommendation:** add a policy floor, for example `policy.exec.profile`
(or `policy.mcp.execProfile`), naming the least restrictive profile an MCP
caller may select. The tool refuses anything looser and uses the floor when
the input is omitted. It is an additive policy key, so it can ship in a
minor without touching the frozen schema's existing keys.

### N2: `policy.wrap` gates tools only (Medium)

`resources/read`, `resources/subscribe` and `prompts/get` cross the airlock
with no allow/deny, no approval and no rate limit
(`src/core/wrap.ts:253-254`). A wrapped server that exposes the same
capability as a resource (a filesystem server's `file://` reads, say)
bypasses `denyTools` entirely.
**Recommendation:** add `allowResources`/`denyResources` (URI globs, deny
wins, same matcher as tools) and `allowPrompts`/`denyPrompts`, hide denied
entries from the list calls as tools are hidden, and count every request,
not only tool calls, against `rateLimit`. All of these are additive schema
keys.

### N3: wrap approvals and policy are per project, not per server (Medium)

The approval service is `q-ring:wrap:<hash(projectPath)>`
(`src/core/wrap.ts:93`), and `policy.wrap` has one block per project. Two
airlocks in one project share grants, globs and rate-limit buckets, so
approving `run_query` on trusted server A also approves a same-named tool on
server B.
**Recommendation:** include the airlock's server identity (the `--label`,
else the downstream's `serverInfo.name`) in the approval service. Have
`qring mcp approve` take `--server <label>`, and allow
`policy.wrap.servers.<label>` blocks that override the project-wide block.
The default label keeps today's behaviour for single-airlock projects.

### N4: teleport v2 has no sender authentication (Medium)

Anyone with a published `qring1…` string can produce a bundle that unpacks
cleanly. The header fields (`count`, `createdAt`, the recipient list) are
outside the payload AAD, which is a constant (`src/core/teleport.ts:221,385`).
MCP `teleport_unpack` overwrites existing keys that policy does not protect,
with no confirmation.
**Recommendation:** for a v3 format, bind the canonical header (version,
`createdAt`, ephemeral key, sorted recipient ids) into the payload AAD, and
add an optional sender signature (an Ed25519 identity beside the X25519 one)
checked against a local known-senders list, with a loud warning for unknown
senders. In the meantime, give MCP `teleport_unpack` an additive `force`
input and refuse to overwrite existing keys without it, matching the CLI's
confirmation.

### N5: `qring run` and `qring push` trust the repository (Medium)

The manifest (`.q-ring.json` secrets) and `qring://` refs in `.env` decide
which keys are injected or pushed (`src/core/run.ts:83`). A cloned,
untrusted repository can name any global key, and its own test script
receives the value under `qring run -- npm test`.
**Recommendation:** add a direnv-style trust step. Record the SHA-256 of
the manifest and `.env` files the operator approves (`qring allow`), refuse
or prompt when they change, and print which global-scope keys a run would
pull before it pulls them for the first time.

### N6: `diff_environments` is an equality oracle (Low)

An agent can `set_secret KEY --env probe <guess>`; the handler keeps the
current value as the `default` state. Diffing `probe` against `default`
then tests the guess against an approval-gated value with no approval and
no read event (`src/core/promote.ts:139`). It matters only for low-entropy
secrets.
**Recommendation:** over MCP, report the status `approval-required` instead
of comparing any key whose `requiresApproval` has no live grant. Apply the
same gate to `promote_secret`, which can copy a gated value between states.

### N7: `verify_audit_chain` counts canary lines (Low)

MCP `verify_audit_chain` returns `totalEvents`, which includes canary trips
(`src/mcp/tools/audit.ts:195`). The difference from the event count of
`export_audit` gives the number of trips, though not which keys and only
after the fact.
**Recommendation:** give agents the verdict only (`valid`, `brokenAt` as a
position among agent-visible events), or count only agent-visible events.
`totalEvents` is a frozen JSON field, so deprecate it in 0.20 and drop it
from the MCP response in 1.x per the stability contract.

### N8: the approval HMAC key sits next to the grants (Low)

The approval key is a 0600 file, `.approval-key`, beside `approvals.json`
(`src/core/approval.ts:49`). Any same-user process, such as an agent with a
shell, can read it and forge grants. Code execution in the user session is
outside the stated threat model, so this is defence in depth.
**Recommendation:** keep the HMAC key in the OS keyring, as the audit
anchor already is, falling back to the file only on keyring-less hosts with
a one-time warning. Re-sign existing grants on first use, or have
`qring doctor` report them.

### N9: the exec tool description and the restricted deny list (Low)

The `exec_with_secrets` description tells agents to "define a custom
profile in `.q-ring.json`", but no such feature exists. The `restricted`
deny list also misses `dash`, `ksh`, `fish`, `csh`, `awk`, `lua`,
`env -S` and `busybox`.
**Recommendation:** after the redaction branch merges (it edits the same
description), drop the custom-profile sentence and extend the deny list.
Better still, deny by basename after resolving symlinks, and treat
`env`/`busybox` as wrappers whose first non-option argument is checked
again. Keep the documentation's "not a sandbox" statement.

### N10: hook commands and the JIT helper keep the full environment (Low)

Operator-armed shell hooks and the JIT HTTP helper still inherit the whole
environment, master keys included (`src/core/hooks.ts:164`,
`src/core/provision.ts`). Shell-hook stdout is copied into the audit
detail, where MCP `audit_log` can read it.
**Recommendation:** build both environments with `withoutQringCredentials`
(C9), and record only the exit status of a shell hook in the audit log, or
its stdout passed through the redactor and capped, never raw output.

### N11: `--auth-secret` over plain HTTP (Low)

`qring mcp wrap --url http://… --auth-secret KEY` sends the bearer token in
clear text to any host (`src/core/wrap.ts:400`).
**Recommendation:** refuse `--auth-secret` (and `Authorization` passed via
`--header`) unless the URL is `https:` or a loopback address, with an
explicit `--allow-insecure-auth` escape hatch that is audited.

### N12: an empty redaction set when the keyring is unavailable (Low)

If the keyring cannot be read when the airlock first builds its redaction
set, the set is empty and results pass unredacted
(`src/core/wrap-redact.ts:75`).
**Recommendation:** this belongs to the redaction branch, which is reworking
the path. The consistent choice is to fail closed when no set has ever been
built: withhold results, as that branch already does when a build throws,
and say so in the session-start banner.

## Draft CHANGELOG `Security` bullets for 0.19.0

The `[Unreleased]` section is not edited on this branch. These bullets follow
the 0.14.0 house style.

- **`policy.mcp.deniedTags` is enforced.** The tag rule was validated but
  never evaluated (every check passed no tags), so a secret carrying a
  denied tag stayed readable, listable, exportable and deletable over MCP.
- **MCP writes respect key policy.** `set_secret`, `teleport_unpack`,
  `import_dotenv`, `generate_secret --saveAs`, `promote_secret`,
  `rotate_secret` and `lint_files --fix` could overwrite a key that policy
  denies, which is the direct form of the 0.14.0 entanglement bypass. With
  a `readableKeys` allowlist, MCP writes are now limited to those keys too.
- **MCP shell and signal hooks start disabled.** `register_hook` could plant
  a persistent shell command outside exec policy. Arm a reviewed hook with
  `qring hook enable <id>`.
- **Exec never injects process-control variables.** A secret named after a
  variable that steers what a program runs turned an allowlisted command
  into arbitrary code execution: `NODE_OPTIONS`, `LD_PRELOAD`, `PATH`,
  `GIT_EXTERNAL_DIFF` inside `git diff`, `MAKEFLAGS` inside `make`, and so
  on. Whole families are now denied (`GIT_*`, `SSH_*`, `MAKE*`,
  `CARGO_*`/`RUSTC*`, interpreter, `LD_*`/`DYLD_*`, package manager), as
  are `PAGER`, `EDITOR`, `HOME`, `KUBECONFIG` and similar. These keys are
  never injected over MCP, and from the CLI only when named with `--keys`.
  Credentials inside a family (`NPM_TOKEN`, `CARGO_REGISTRY_TOKEN`, ...)
  still inject. Exec profiles are not a sandbox: a caller who controls an
  allowed binary's arguments can still run code through it.
- **Canary identity no longer leaks** through `prevHash` gaps in MCP
  `export_audit` and `qring://sessions/{id}`, through `policy_deny` events
  when an alert channel is SSRF-blocked, or through silent reads in
  `ci_validate_secrets`, which now audits each read and trips canaries.
- **`canary plant --force` starts fresh.** It no longer inherits the
  replaced secret's stats, so the canary no longer shows as tripped right
  after planting. It no longer keeps the old secret's settings, and it never
  copies the fake value into entangled real secrets.
- **q-ring's master keys stay out of child processes.**
  `QRING_FILE_PASSPHRASE` and `QRING_MEMORY_PASSPHRASE` are stripped from
  exec and run children, from `--inherit-env` wrapped servers and from push
  CLIs.
- **Airlock redaction covers errors, progress and URIs.** Downstream error
  messages and data, progress messages and audited resource URIs are now
  scrubbed like results.
- **`qring push` refuses values that would inject variables.** A fly or
  netlify value that would spill into extra `NAME=VALUE` lines is refused.
- **Unknown exec profiles are an error.** `--profile <typo>` used to run
  unrestricted.
- **Teleport bundles reject control characters** in key names, scopes and
  recipient ids.
- **The file backend writes atomically.** A failed write can no longer
  destroy the store.
- **Wrap tool-name globs match across newlines**, and the airlock's rate
  limiter tracks at most 1024 tool names.
- **SSRF-blocked hook URLs are logged as scheme and host only.**
- **Environment names are looked up by own property**, so `constructor` and
  similar names never resolve to prototype members.
- **Entanglement honours `deniedTags`** in both directions: MCP writes do
  not propagate into a tag-denied key, and `entangle_secrets` refuses links
  that touch one.
- **Bulk MCP writers no longer abort halfway.** `import_dotenv`,
  `teleport_unpack` and `lint_files --fix` check every key first, write
  the allowed ones and list the protected ones as skipped with a reason
  (`importDotenv` gains `skippedByPolicy`).
- **`agent_scan` auto-rotation over MCP honours the MCP write policy.**
  Protected keys are never rotated and are reported in `rotationSkipped`.
- **Blocked canary alert deliveries are no longer counted as trips.** They
  are recorded as `canary_alert` and hidden from agents.
- **A delete across scopes checks every copy first**, so a policy denial
  deletes nothing.
