<div align="center">
  <img src="https://raw.githubusercontent.com/I4cTime/q-ring/main/assets/social-card-optimized.jpg" alt="q-ring — never paste an API key into .env again" width="100%" />
</div>

# q-ring

**OS keychain secrets for AI coding agents, over MCP.**

[![CI](https://img.shields.io/github/actions/workflow/status/I4cTime/q-ring/ci.yml?style=flat-square&label=CI)](https://github.com/I4cTime/q-ring/actions/workflows/ci.yml)
[![NPM Version](https://img.shields.io/npm/v/@i4ctime/q-ring?style=flat-square&color=0ea5e9)](https://www.npmjs.com/package/@i4ctime/q-ring)
[![NPM Downloads](https://img.shields.io/npm/dm/@i4ctime/q-ring?style=flat-square&color=0ea5e9&label=downloads)](https://www.npmjs.com/package/@i4ctime/q-ring)
[![Docs](https://img.shields.io/badge/docs-website-0ea5e9?style=flat-square)](https://qring.i4c.studio/docs)
[![MCP Tools](https://img.shields.io/badge/MCP_tools-44-0ea5e9?style=flat-square)](https://glama.ai/mcp/servers/I4cTime/q-ring)
[![Smithery](https://img.shields.io/badge/smithery-i4ctime%2Fq--ring-0ea5e9?style=flat-square)](https://smithery.ai/servers/i4ctime/q-ring)
[![Cursor Directory](https://img.shields.io/badge/cursor_directory-q--ring-0ea5e9?style=flat-square)](https://cursor.directory/plugins/q-ring)
[![PulseMCP](https://img.shields.io/badge/pulsemcp-q--ring-0ea5e9?style=flat-square)](https://www.pulsemcp.com/servers/i4ctime-q-ring)
[![mcpservers.org](https://img.shields.io/badge/mcpservers.org-q--ring-0ea5e9?style=flat-square)](https://mcpservers.org/servers/i4ctime/q-ring)
[![License](https://img.shields.io/npm/l/@i4ctime/q-ring?style=flat-square&color=0ea5e9)](https://github.com/I4cTime/q-ring/blob/main/LICENSE)
[![Discord](https://img.shields.io/badge/discord-join%20the%20studio-5865F2?style=flat-square&logo=discord&logoColor=white)](https://discord.gg/5uEApw5uEz)
[![YouTube](https://img.shields.io/badge/youtube-%40qring__dev-FF0000?style=flat-square&logo=youtube&logoColor=white)](https://www.youtube.com/@qring_dev)
[![X](https://img.shields.io/badge/follow-%40i4c__studio-000000?style=flat-square&logo=x&logoColor=white)](https://x.com/i4c_studio)

<a href="https://glama.ai/mcp/servers/I4cTime/q-ring">
  <img src="https://glama.ai/mcp/servers/I4cTime/q-ring/badges/card.svg" alt="q-ring MCP server" width="400" />
</a>

Stop pasting API keys into plain-text `.env` files or wrestling with clunky secret managers. **q-ring** securely anchors your credentials to your OS's native vault (macOS Keychain, Linux Secret Service, Windows Credential Vault) and supercharges them with mechanics from quantum physics.

> 📖 **[View the Official Documentation](https://qring.i4c.studio/docs)** for a complete CLI reference, MCP prompt cookbooks, and architecture details.

### Why q-ring?
- **Superposition:** Store one key with multiple states (dev/staging/prod) that collapse based on context.
- **Entanglement:** Link keys across projects so rotating one automatically updates them all.
- **Tunneling:** Create ephemeral, in-memory secrets that self-destruct after a set time or read count.
- **Teleportation:** Securely pack and share AES-256-GCM encrypted secret bundles.
- **Seamless AI Integration:** 44 built-in MCP tools for native use in **Cursor**, **Kiro**, and **Claude Code**.

## 🚀 Installation

q-ring is designed to be installed globally so it's available anywhere in your terminal. Pick your favorite package manager:

```bash
# pnpm (recommended)
pnpm add -g @i4ctime/q-ring

# npm
npm install -g @i4ctime/q-ring

# yarn
yarn global add @i4ctime/q-ring

# Homebrew (macOS / Linux)
brew install i4ctime/tap/qring
```

### Docker (MCP server)

The repo ships a `Dockerfile` that builds the MCP server and exposes it through [`mcp-proxy`](https://github.com/punkpeye/mcp-proxy) — useful for hosted MCP deployments (e.g. Glama) or keeping the server off the host entirely:

```bash
git clone https://github.com/I4cTime/q-ring.git
cd q-ring
docker build -t qring-mcp .
docker run --rm -p 8080:8080 qring-mcp
```

> Note: inside a container there is no OS keychain (GNOME Keyring / macOS Keychain), so this path is for the MCP protocol surface, ephemeral use, and CI experiments — not for durable local secret storage. For day-to-day use install the CLI natively via one of the package managers above.

## ⚡ Quick Start

```bash
# 1️⃣ Store a secret (prompts securely if value is omitted)
qring set OPENAI_API_KEY sk-...

# 2️⃣ Retrieve it anytime
qring get OPENAI_API_KEY

# 3️⃣ List all keys (values are never shown)
qring list

# 4️⃣ Generate a cryptographic secret and save it
qring generate --format api-key --prefix "sk-" --save MY_KEY

# 5️⃣ Run a full health scan
qring health

# Something not working? Diagnose the install (keyring, audit, MCP wiring)
qring doctor

# Tab completion for your shell
qring completion zsh > ~/.zsh/completions/_qring   # also: bash, fish
```

## Quantum Features

### Superposition — One Key, Multiple Environments

A single secret can hold different values for dev, staging, and prod simultaneously. The correct value resolves based on your current context.

```bash
# Set environment-specific values
qring set API_KEY "sk-dev-123" --env dev
qring set API_KEY "sk-stg-456" --env staging
qring set API_KEY "sk-prod-789" --env prod

# Value resolves based on context
QRING_ENV=prod qring get API_KEY   # → sk-prod-789
QRING_ENV=dev  qring get API_KEY   # → sk-dev-123

# Inspect the quantum state
qring inspect API_KEY
```

### Wavefunction Collapse — Smart Environment Detection

q-ring auto-detects your environment without explicit flags. Resolution order:

1. `--env` flag
2. `QRING_ENV` environment variable
3. `NODE_ENV` environment variable
4. Git branch heuristics (`main`/`master` → prod, `develop` → dev)
5. `.q-ring.json` project config
6. Default environment from the secret

```bash
# See what environment q-ring detects
qring env

# Project config (.q-ring.json)
echo '{"env": "staging", "branchMap": {"release/*": "staging"}}' > .q-ring.json
```

### Quantum Decay — Secrets with TTL

Secrets can have a time-to-live. Expired secrets are blocked from reads. Stale secrets (75%+ lifetime) trigger warnings.

```bash
# Set a secret that expires in 1 hour
qring set SESSION_TOKEN "tok-..." --ttl 3600

# Set with explicit expiry
qring set CERT_KEY "..." --expires "2026-06-01T00:00:00Z"

# Health check shows decay status
qring health
```

### Observer Effect — Audit Everything

Every secret read, write, and delete is logged with a tamper-evident hash chain. Access patterns are tracked for anomaly detection.

```bash
# View audit log
qring audit
qring audit --key OPENAI_KEY --limit 50

# Detect anomalies (burst access, unusual hours, chain tampering)
qring audit --anomalies

# Verify audit chain integrity
qring audit:verify

# Export audit log
qring audit:export --format json --since 2026-03-01
qring audit:export --format csv --output audit-report.csv
```

### Quantum Noise — Secret Generation

Generate cryptographically strong secrets in common formats.

```bash
qring generate                          # API key (default)
qring generate --format password -l 32  # Strong password
qring generate --format uuid            # UUID v4
qring generate --format token           # Base64url token
qring generate --format hex -l 64       # 64-byte hex
qring generate --format api-key --prefix "sk-live-" --save STRIPE_KEY
```

### Entanglement — Linked Secrets

Link secrets across projects. When you rotate one, all entangled copies update automatically.

```bash
# Entangle two secrets
qring entangle API_KEY API_KEY_BACKUP

# Now updating API_KEY also updates API_KEY_BACKUP
qring set API_KEY "new-value"

# Unlink entangled secrets
qring disentangle API_KEY API_KEY_BACKUP
```

### Tunneling — Ephemeral Secrets

Create secrets that exist only in memory. They never touch disk. Optional TTL and max-read self-destruction.

```bash
# Create an ephemeral secret (returns tunnel ID)
qring tunnel create "temporary-token-xyz" --ttl 300 --max-reads 1

# Read it (self-destructs after this read)
qring tunnel read tun_abc123

# List active tunnels
qring tunnel list
```

### Teleportation — Encrypted Sharing

Pack secrets into AES-256-GCM encrypted bundles for secure transfer between machines. Keys are derived with PBKDF2-HMAC-SHA512 (210 000 iterations) from your passphrase; each bundle records its iteration count, so bundles produced by older versions still unpack.

```bash
# Pack secrets (prompts for passphrase)
qring teleport pack --keys "API_KEY,DB_PASS" > bundle.txt

# On another machine: unpack (prompts for passphrase)
cat bundle.txt | qring teleport unpack

# Preview without importing
qring teleport unpack <bundle> --dry-run
```

### Import — Bulk Secret Ingestion

Import secrets from `.env` files directly into q-ring. Supports standard dotenv syntax including comments, quoted values, and escape sequences. The CLI accepts either a file path or raw content; the `import_dotenv` MCP tool only accepts raw content (it never reads files from disk) so an agent can't coerce it into reading arbitrary local files.

```bash
# Import all secrets from a .env file
qring import .env

# Import to project scope, skipping existing keys
qring import .env --project --skip-existing

# Preview what would be imported
qring import .env --dry-run
```

### Selective Export

Export only the secrets you need using key names or tag filters.

```bash
# Export specific keys
qring export --keys "API_KEY,DB_PASS,REDIS_URL"

# Export by tag
qring export --tags "backend"

# Combine with format
qring export --keys "API_KEY,DB_PASS" --format json
```

### Secret Search and Filtering

Filter `qring list` output by tag, expiry state, or key pattern.

```bash
# Filter by tag
qring list --tag backend

# Show only expired secrets
qring list --expired

# Show only stale secrets (75%+ decay)
qring list --stale

# Glob pattern on key name
qring list --filter "API_*"

# Script-friendly existence check (exit 0 if present, 1 if not; decay-aware)
qring has OPENAI_API_KEY --quiet && echo "configured"
```

### Project Secret Manifest

Declare required secrets in `.q-ring.json` and validate project readiness with a single command.

```bash
# Validate project secrets against the manifest
qring check

# See which secrets are present, missing, expired, or stale
qring check --project-path /path/to/project
```

### Env File Sync

Generate a `.env` file from the project manifest, resolving each key from q-ring with environment-aware superposition collapse.

```bash
# Generate to stdout
qring env:generate

# Write to a file
qring env:generate --output .env

# Force a specific environment
qring env:generate --env staging --output .env.staging
```

### Secret References & Least-Privilege Run

A `qring://` reference is a committable pointer to a secret — it goes in your `.env` file instead of the value. `qring run` resolves references and manifest keys at spawn time, injecting **only what the project declares** (unlike `exec`, which injects the whole scope). Output is auto-redacted.

```bash
# .env — safe to commit: these are references, not values
DATABASE_URL=qring://project/DATABASE_URL
OPENAI_API_KEY=qring://global/OPENAI_API_KEY
STRIPE_KEY=qring:///STRIPE_KEY            # auto scope: project, then global
SESSION_TTL=3600                          # plain values pass through

# Run with declared secrets injected (manifest + .env refs)
qring run -- pnpm dev

# Preview what would be injected, without running
qring run --dry-run -- pnpm dev

# Pin an environment, use a specific env file, or skip the manifest
qring run --env prod --env-file .env.prod --no-manifest -- ./deploy.sh
```

The key lives in the **path**, never the host (`qring://project/KEY`, not `qring://KEY`) — URL hosts are case-insensitive, and env-var keys are not. Malformed references fail loudly instead of leaking a literal `qring://…` string into the child. A reference pinned to an environment: `qring://project/DATABASE_URL?env=prod`.

### Editor Setup

Wire the q-ring MCP server into an editor's MCP config with one command. Merges non-destructively — other servers are preserved, and an existing q-ring entry is only replaced with `--force`.

```bash
qring setup cursor          # .cursor/mcp.json (project) or --global for ~/.cursor
qring setup kiro            # .kiro/settings/mcp.json, with read-only autoApprove list
qring setup claude          # .mcp.json (project scope)

# Preview without writing
qring setup cursor --dry-run
```

### Push to Deployment Platforms

Push manifest secrets to GitHub Actions, Vercel, or Cloudflare Workers through each platform's **own authenticated CLI** (`gh` / `vercel` / `wrangler`) — q-ring never holds platform tokens, and values travel over stdin, never argv. Every push is recorded in the audit chain.

```bash
# Push the .q-ring.json manifest keys to GitHub Actions secrets
qring push github --repo you/your-app

# Push to Vercel environments
qring push vercel --vercel-env production,preview

# Push to Cloudflare Workers secrets
qring push cloudflare

# Explicit keys, preview first
qring push github --keys DATABASE_URL,API_KEY --dry-run
```

### Secret Liveness Validation

Test if a secret is actually valid with its target service. q-ring auto-detects the provider from key prefixes (`sk-` → OpenAI, `ghp_` → GitHub, etc.) or accepts an explicit provider name.

```bash
# Validate a single secret
qring validate OPENAI_API_KEY

# Force a specific provider
qring validate SOME_KEY --provider stripe

# Validate all secrets with detectable providers
qring validate --all

# Only validate manifest-declared secrets
qring validate --all --manifest

# List available providers
qring validate --list-providers
```

**Built-in providers:** OpenAI, Anthropic, OpenRouter, Google AI (Gemini), Groq, Hugging Face, ElevenLabs*, Vercel*, Stripe, GitHub, AWS (format check), Generic HTTP. Keys are only ever sent in headers, never URLs. (*no safe public prefix — select explicitly with `--provider` or the manifest `provider` field.)

Output:

```
  ✓ OPENAI_API_KEY   valid    (openai, 342ms)
  ✗ STRIPE_KEY       invalid  (stripe, 128ms) — API key has been revoked
  ⚠ AWS_ACCESS_KEY   error    (aws, 10002ms) — network timeout
  ○ DATABASE_URL     unknown  — no provider detected
```

### Hooks — Callbacks on Secret Change

Register webhooks, shell commands, or process signals that fire when secrets are created, updated, or deleted. Supports key matching, glob patterns, tag filtering, and scope constraints.

```bash
# Run a shell command when a secret changes
qring hook add --key DB_PASS --exec "docker restart app"

# POST to a webhook on any write/delete
qring hook add --key API_KEY --url "https://hooks.example.com/rotate"

# Trigger on all secrets tagged "backend"
qring hook add --tag backend --exec "pm2 restart all"

# Signal a process when DB secrets change
qring hook add --key-pattern "DB_*" --signal-target "node"

# List all hooks
qring hook list

# Remove a hook
qring hook remove <id>

# Enable/disable
qring hook enable <id>
qring hook disable <id>

# Dry-run test a hook
qring hook test <id>
```

Hooks are fire-and-forget: a failing hook never blocks secret operations. The hook registry is stored at `~/.config/q-ring/hooks.json`.

**SSRF protection:** HTTP hook URLs targeting private/loopback IP ranges (`127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`, `::1`, `fc00::/7`) are blocked by default. DNS is checked up front *and* re-validated at connect time, so a hostname can't pass the check then rebind to a private address before the socket opens. To allow hooks targeting local services (e.g. during development), set the environment variable `Q_RING_ALLOW_PRIVATE_HOOKS=1`.

### Configurable Rotation

Set a rotation format per secret so the agent auto-rotates with the correct value shape.

```bash
# Store a secret with rotation format metadata
qring set STRIPE_KEY "sk-..." --rotation-format api-key --rotation-prefix "sk-"

# Store a password with password rotation format
qring set DB_PASS "..." --rotation-format password
```

### Secure Execution & Auto-Redaction

Run commands with secrets securely injected into the environment. All known secret values are automatically redacted from stdout and stderr to prevent leaking into terminal logs or agent transcripts. Exec profiles restrict which commands may be run.

```bash
# Execute a deployment script with secrets injected
qring exec -- npm run deploy

# Inject only specific tags
qring exec --tags backend -- node server.js

# Run with a restricted profile (blocks network tools and interpreters/shells, 30s timeout)
qring exec --profile restricted -- npm test
```

### Codebase Secret Scanner

Migrating a legacy codebase? Quickly scan directories for hardcoded credentials using regex heuristics and Shannon entropy analysis.

```bash
# Scan current directory
qring scan .
```

Output:
```
  ✗ src/db/connection.js:12
    Key:     DB_PASSWORD
    Entropy: 4.23
    Context: const DB_PASSWORD = "..."
```

### Composite / Templated Secrets

Store complex connection strings that dynamically resolve other secrets. If `DB_PASS` rotates, `DB_URL` is automatically correct without manual updates.

```bash
qring set DB_USER "admin"
qring set DB_PASS "supersecret"
qring set DB_URL "postgres://{{DB_USER}}:{{DB_PASS}}@localhost/mydb"

# Resolves embedded templates automatically
qring get DB_URL 
# Output: postgres://admin:supersecret@localhost/mydb
```

### User Approvals (Zero-Trust Agent)

Protect sensitive production secrets from being read autonomously by the MCP server without explicit user approval. Each approval token is HMAC-verified, scoped, reasoned, and time-limited. The gate applies to bulk reads too — `export_secrets` and `teleport_pack` over MCP skip approval-protected keys that lack a valid grant.

```bash
# Mark a secret as requiring approval
qring set PROD_DB_URL "..." --requires-approval

# Temporarily grant MCP access for 1 hour with a reason
qring approve PROD_DB_URL --for 3600 --reason "deploying v2.0"

# List all approvals with verification status
qring approvals

# Revoke an approval
qring approve PROD_DB_URL --revoke
```

When an agent is blocked on an approval-protected key, q-ring raises a desktop notification (Linux `notify-send`, macOS `osascript`) naming the key and the exact `qring approve` command — throttled per key, disabled with `QRING_NOTIFY=off`.

### Canary Honeytokens

Plant fake credentials that look and read exactly like real ones. Anything that touches one — a compromised MCP server, an over-curious agent, exfiltrated tooling sweeping the ring — gets the fake value back with no tell, while q-ring fires a desktop alert and writes a `canary` event into the tamper-evident audit chain.

```bash
# Plant a canary shaped like a real AWS access key
qring canary plant AWS_SECRET_ACCESS_KEY --format aws

# Other shapes: github, openai, anthropic, stripe, generic
qring canary plant GHP_BACKUP_TOKEN --format github

# See what's been tripped
qring canary list
qring audit --action canary
```

Values are CSPRNG noise in the provider's real token shape (an `aws` canary matches `AKIA[A-Z0-9]{16}`) — plausible enough to be taken, never valid. Alerts are throttled to one per key per 30 seconds; the audit trail records every read.

Canaries are built to stay covert: they carry no identifying description (add an innocuous cover story with `--description` if you like), their flag never appears in MCP tool responses, and trip records are visible only from the operator's terminal — never to agents via MCP audit tools. Bulk `export` and `delete` trip them just like reads, so sweeping the ring or removing the tripwire both ring the bell. Done with one? `qring canary disarm <key>` turns it back into an ordinary secret (`qring set` over a canary warns you first — the flag deliberately survives overwrites so an agent can't launder it away).

### MCP Airlock

Run a third-party MCP server behind q-ring. The airlock sits between your agent host and the wrapped server, spawns it with a **stripped environment** (no inherited API keys — opt back in with `--inherit-env`), and records every tool call that crosses it as a `wrap` event in the audit chain, grouped per session and labeled with the calling client's identity. Tool arguments are never logged — they may contain secrets.

```json
{
  "mcpServers": {
    "some-server": {
      "command": "qring",
      "args": ["mcp", "wrap", "--", "npx", "-y", "some-mcp-server"]
    }
  }
}
```

Tools-only proxy today: `tools/list` and `tools/call` pass through verbatim (pagination, progress notifications, cancellation, and `tools/list_changed` included; long-running tools are governed by the host's own timeout, with a generous airlock ceiling configurable via `QRING_WRAP_TIMEOUT_MS`). A wrapped server's *resources and prompts* are not proxied yet — a resources-heavy server will look tools-only behind the airlock.

Be clear about what the airlock is: env stripping plus a tamper-evident record of every tool call. It is **not a sandbox** — the wrapped process still runs as your user with normal filesystem, network, and OS-keychain access, and tool descriptions/results pass through uninspected. See `docs/threat-model.md` for the honest boundary picture.

### Just-In-Time (JIT) Provisioning

Instead of storing static credentials, configure `q-ring` to dynamically generate short-lived tokens on the fly when requested (e.g. AWS STS, generic HTTP endpoints).

```bash
# Store the STS role configuration
qring set AWS_TEMP_KEYS '{"roleArn":"arn:aws:iam::123:role/AgentRole", "durationSeconds":3600}' --jit-provider aws-sts

# Resolving the secret automatically assumes the role and caches the temporary token
qring get AWS_TEMP_KEYS
```

### Project Context for AI Agents

A safe, redacted overview of the project's secrets, configuration, and state. Designed to be fed into an AI agent's system prompt without ever exposing secret values.

```bash
# Human-readable summary
qring context

# JSON output (for MCP / programmatic use)
qring context --json
```

### Secret-Aware Linter

Scan specific files for hardcoded secrets with optional auto-fix. When `--fix` is used, detected secrets are replaced with `process.env.KEY` references and stored in q-ring.

```bash
# Lint files for hardcoded secrets
qring lint src/config.ts src/db.ts

# Auto-fix: replace hardcoded values and store in q-ring
qring lint src/config.ts --fix

# Scan entire directory with auto-fix
qring scan . --fix
```

### Agent Memory

Encrypted, persistent key-value store that survives across AI agent sessions. Useful for remembering rotation history, project decisions, or context.

```bash
# Store a memory
qring remember last_rotation "Rotated STRIPE_KEY on 2026-03-21"

# Retrieve it
qring recall last_rotation

# List all memories
qring recall

# Forget
qring forget last_rotation
```

### Pre-Commit Secret Scanning

Install a git pre-commit hook that automatically blocks commits containing hardcoded secrets.

```bash
# Install the hook
qring hook:install

# Uninstall
qring hook:uninstall
```

### Secret Analytics

Analyze usage patterns and get optimization suggestions for your secrets.

```bash
qring analyze
```

Output includes most accessed secrets, unused/stale secrets, scope optimization suggestions, and rotation recommendations.

### Service Setup Wizard

Quickly set up a new service integration with secrets, manifest entries, and hooks in one command.

```bash
# Create secrets for a new Stripe integration
qring wizard stripe --keys STRIPE_KEY,STRIPE_SECRET --provider stripe --tags payment

# With a hook to restart the app on change
qring wizard myservice --hook-exec "pm2 restart app"
```

### Governance Policy

Define project-level governance rules in `.q-ring.json` to control which MCP tools can be used, which keys are accessible, and which commands can be executed. Policy is enforced at both the MCP server and keyring level.

Over MCP, policy is resolved from the directory the server was **launched** in — not from the `projectPath` a caller passes — so an agent can't sidestep restrictions by pointing at a directory with no policy. Launch the MCP server from your project root (where `.q-ring.json` lives). Edits to `.q-ring.json` are picked up automatically (the policy cache invalidates on file change), so you don't need to restart the server.

Policy files are schema-validated and **fail closed**: an invalid `policy` object (say, a typo like `denytools`) raises a `PolicyConfigError` instead of being silently ignored, so a malformed rule can never widen access.

```bash
# View the active policy
qring policy

# JSON output
qring policy --json
```

Example policy in `.q-ring.json`:

```json
{
  "policy": {
    "mcp": {
      "denyTools": ["delete_secret"],
      "deniedKeys": ["PROD_DB_PASSWORD"],
      "deniedTags": ["production"]
    },
    "exec": {
      "denyCommands": ["curl", "wget", "ssh"],
      "maxRuntimeSeconds": 30
    },
    "secrets": {
      "requireApprovalForTags": ["production"],
      "maxTtlSeconds": 86400
    }
  }
}
```

### Exec Profiles

Restrict command execution with named profiles that control allowed commands, network access, timeouts, and environment sanitization.

```bash
# Run with the "restricted" profile (blocks network tools and interpreters/shells; 30s timeout)
qring exec --profile restricted -- npm test

# Run with the "ci" profile (5min timeout, allows network)
qring exec --profile ci -- npm run deploy

# Default: unrestricted
qring exec -- echo "hello"
```

**Built-in profiles:** `unrestricted`, `restricted` (denies network tools *and* interpreters/shells — `python -c`, `node -e`, `bash` and friends can't exfiltrate injected secrets; 30s limit), `ci` (5min limit, blocks destructive commands).

### Tamper-Evident Audit

Every audit event includes a SHA-256 hash of the previous event, creating a tamper-evident chain. Since v0.14 the chain is also anchored with a keyed HMAC stored in the OS keyring, so `qring audit:verify` detects truncation and whole-file rewrites — not just in-place edits. Verify integrity and export logs in multiple formats. Events from MCP sessions are additionally stamped with the connecting client's self-reported identity (`clientInfo` name@version) — shown in `qring audit` output and filterable with `qring audit --agent <label>`. It's an audit label for "which agent did this", never an authorization boundary, since clients choose what to report.

```bash
# Verify the entire audit chain
qring audit:verify

# Export as JSON
qring audit:export --format json --since 2026-03-01

# Export as CSV
qring audit:export --format csv --output audit-report.csv
```

### Encrypted File Backend (Headless / CI)

Hosts with no OS keyring at all (headless Linux, containers, CI) can opt into an encrypted file store. Everything — secrets, the audit anchor, the agent-memory key — routes through it.

```bash
export QRING_BACKEND=file
export QRING_FILE_PASSPHRASE="a strong passphrase"   # required — no passphrase, no access
qring set CI_TOKEN
```

The store is AES-256-GCM at `~/.config/q-ring/file-backend.enc` (mode `0600`, path override via `QRING_FILE_BACKEND_PATH`), keyed by PBKDF2 from the passphrase. It is **explicit-only**: a missing OS keyring never falls back to it silently, and without the passphrase every operation fails closed — q-ring never encrypts under a machine-derivable key.

### Team & Org Scopes

Extend beyond `global` and `project` scopes with `team` and `org` scopes for shared secrets across groups. Resolution order: project → team → org → global (most specific wins).

```bash
# Store a secret in team scope
qring set SHARED_API_KEY "sk-..." --team my-team

# Store in org scope
qring set ORG_LICENSE "lic-..." --org acme-corp

# Resolution cascades: project > team > org > global
qring get API_KEY --team my-team --org acme-corp
```

### Issuer-Native Rotation

Attempt provider-native secret rotation (for providers that support it) or fall back to local generation.

```bash
# Rotate via the detected provider
qring rotate STRIPE_KEY

# Force a specific provider
qring rotate API_KEY --provider openai
```

### CI Secret Validation

Batch-validate all secrets against their providers in a CI-friendly mode. Returns a structured pass/fail report with exit code 1 on failure.

```bash
# Validate all secrets (CI mode)
qring ci:validate

# JSON output for pipeline parsing
qring ci:validate --json
```

### Agent Mode — Autonomous Monitoring

A background daemon that continuously monitors secret health, detects anomalies, and optionally auto-rotates expired secrets.

```bash
# Start the agent
qring agent --interval 60 --verbose

# With auto-rotation of expired secrets
qring agent --auto-rotate

# Single scan (for CI/cron)
qring agent --once
```

### Quantum Status Dashboard — Live Monitoring

Launch a real-time dashboard in your browser that turns the entire quantum subsystem into one glanceable page. It's a single self-contained HTML page served locally — no cloud, no config, fully offline — built as a Preact + htm app (runtime bundled and inlined). It streams updates every 5 seconds via Server-Sent Events and diffs the DOM in place, so data refreshes without re-running entrance animations and your search input, caret, and scroll position are preserved across ticks.

What you get:

- **KPI strip** — total secrets, detected environment, protected count, active approvals, hooks, 24-hour reads, and live anomaly count.
- **Health summary** — donut chart of healthy / stale / expired / no-decay secrets plus per-scope counts (global / project / team / org).
- **Environment** — wavefunction collapse details: detected env, source, branch, and any project context.
- **Manifest** — `.q-ring.json` summary with declared / required / missing / expired / stale keys.
- **Policy** — at-a-glance view of MCP, exec, and secret policies (allow/deny tools, deny keys/tags, allow/deny commands, approval & rotation requirements).
- **Secrets table** — searchable, sortable view of every secret (key, scope, env, type, decay, tags, last read), with quick chips for `expired`, `stale`, and `protected` filters. Press `/` to focus the search box.
- **Quantum cards** — decay timers, superposition states, entanglement pairs, and active quantum tunnels.
- **Approvals & hooks** — live list of valid (and tampered) approval grants and every registered hook with its match summary.
- **Agent memory** — count of encrypted memory keys persisted at `~/.config/q-ring/agent-memory.enc`.
- **Anomaly alerts** — burst reads, off-hours access, tampered audit chain, and other suspicious patterns.
- **Audit log (24h)** — filterable feed with action chips (`read`/`write`/`delete`/`export`), source chips (`cli`/`mcp`/`hook`/`agent`), and a free-text filter.

Top-bar controls let you **pause** SSE updates (handy while reading the audit feed), **refresh** on demand, or jump to the raw JSON snapshot at `/api/status`. Keyboard shortcuts: `/` focus secrets search · `P` pause · `R` refresh.

The dashboard binds to `127.0.0.1` only and **never** exposes secret values, but it does surface key names, the audit log, and approval grants — so every route is gated by a random, per-launch token. `qring status` prints (and opens) the full URL including `?token=…`; requests without the token get a `403`. Stop the server to invalidate the token.

```bash
# Open the dashboard (auto-launches your browser at http://127.0.0.1:9876/?token=…)
qring status

# Specify a custom port
qring status --port 4200

# Don't auto-open the browser (copy the printed tokenized URL yourself)
qring status --no-open
```

## MCP Server

q-ring includes a full MCP server with 44 tools for AI agent integration.

### Core Tools

| Tool | Description |
|------|-------------|
| `get_secret` | Read a secret value (collapses superposition, audits the read) |
| `list_secrets` | List keys + metadata in scope (values never exposed); filter by tag, expiry, glob |
| `set_secret` | Create or overwrite a single secret with optional TTL, per-env state, tags, rotation format |
| `delete_secret` | Permanently remove a secret value (not undoable from q-ring) |
| `has_secret` | Boolean existence check that respects decay (no audit read) |
| `export_secrets` | Render multiple secrets as `.env` or JSON for one-off export (skips approval-protected keys without a grant) |
| `import_dotenv` | Parse `.env` text and bulk-store every key/value pair (accepts raw content only — never reads files) |
| `check_project` | Compare `.q-ring.json` manifest against the keyring for missing/expired/stale keys |
| `env_generate` | Render a complete `.env` body from the project manifest, with warnings for gaps |

### Quantum Tools

| Tool | Description |
|------|-------------|
| `inspect_secret` | Show metadata for one key (states, decay, entanglement, access count) without revealing the value |
| `detect_environment` | Resolve which env slug should drive superposition collapse for the current context |
| `generate_secret` | Generate a CSPRNG-backed value in a chosen format and optionally store it |
| `entangle_secrets` | Link two keys so future writes/rotations propagate the same value |
| `disentangle_secrets` | Break the sync link between two keys (does not delete values) |

### Tunneling Tools

| Tool | Description |
|------|-------------|
| `tunnel_create` | Stash a value in process memory and return an opaque ID (never touches disk) |
| `tunnel_read` | Fetch a tunneled value by ID — may self-destruct on read |
| `tunnel_list` | Enumerate active tunnels with remaining read budget and TTL (IDs only) |
| `tunnel_destroy` | Immediately remove a tunnel from memory before its TTL/reads run out |

### Teleportation Tools

| Tool | Description |
|------|-------------|
| `teleport_pack` | Encrypt selected secrets into a passphrase-protected AES-256-GCM bundle |
| `teleport_unpack` | Decrypt a teleport bundle and import each secret (with optional dry-run) |

### Validation Tools

| Tool | Description |
|------|-------------|
| `validate_secret` | Hit the upstream service (OpenAI/Stripe/GitHub/AWS/HTTP) to confirm a single key is still live |
| `list_providers` | Enumerate built-in validation providers and their auto-detect prefixes |

### Hook Tools

| Tool | Description |
|------|-------------|
| `register_hook` | Register a shell/HTTP/signal side-effect that fires on write/delete/rotate |
| `list_hooks` | Show every registered hook with match criteria, type, and enabled flag |
| `remove_hook` | Detach a single hook by ID without touching any secrets |

### Execution & Scanning Tools

| Tool | Description |
|------|-------------|
| `exec_with_secrets` | Run a child command with secrets injected as env vars and any leaked values redacted from output |
| `scan_codebase_for_secrets` | Walk a directory tree and flag hardcoded secrets via regex + entropy heuristics |
| `lint_files` | Inspect a specific file list for hardcoded secrets with optional auto-fix to `process.env.KEY` |

### AI Agent Tools

| Tool | Description |
|------|-------------|
| `get_project_context` | Single redacted snapshot of secrets, env, manifest, hooks, and recent audit activity |
| `agent_remember` | Persist a non-secret note in encrypted agent memory across sessions |
| `agent_recall` | Read a memory value, or list every stored key when no key is supplied |
| `agent_forget` | Permanently delete a key from agent memory |
| `analyze_secrets` | Usage profile: most-accessed, stale, never-accessed, no-rotation candidates |

### Observer & Health Tools

| Tool | Description |
|------|-------------|
| `audit_log` | Query the tamper-evident audit log filtered by key, action, and limit |
| `detect_anomalies` | Surface burst-read and off-hours findings from audit history |
| `verify_audit_chain` | Recompute the audit hash chain and report the first break point if tampered |
| `export_audit` | Export audit events as jsonl, json, or csv for archival/SIEM |
| `health_check` | Read-only scope sweep: decay/stale/expired counts plus current anomalies |
| `status_dashboard` | Start a local SSE dashboard with live KPIs, secrets, hooks, and audit feed (returns a token-gated `127.0.0.1` URL) |
| `agent_scan` | Multi-project health pass with optional `autoRotate` for expired secrets |

### Governance & Policy Tools

| Tool | Description |
|------|-------------|
| `check_policy` | Dry-run a tool/key/exec action against `.q-ring.json` policy without performing it |
| `get_policy_summary` | High-level overview of policy rule counts and approval/rotation requirements |
| `rotate_secret` | Ask the upstream provider to issue a new credential and store it back in the keyring |
| `ci_validate_secrets` | Batch-validate every accessible secret in scope and return a structured pass/fail report |

### Cursor / Kiro Configuration

Add to `.cursor/mcp.json` or `.kiro/mcp.json`:

**If q-ring is installed globally** (e.g. `pnpm add -g @i4ctime/q-ring`):

```json
{
  "mcpServers": {
    "q-ring": {
      "command": "qring-mcp"
    }
  }
}
```

**If using a local clone:**

```json
{
  "mcpServers": {
    "q-ring": {
      "command": "node",
      "args": ["/path/to/q-ring/dist/mcp.js"]
    }
  }
}
```

### Claude Code Configuration

Add to `~/.claude/claude_desktop_config.json`:

**Global install:**

```json
{
  "mcpServers": {
    "q-ring": {
      "command": "qring-mcp"
    }
  }
}
```

**Local clone:**

```json
{
  "mcpServers": {
    "q-ring": {
      "command": "node",
      "args": ["/path/to/q-ring/dist/mcp.js"]
    }
  }
}
```

### VS Code Configuration

VS Code speaks MCP natively — add to `.vscode/mcp.json` (note the `servers` key, not `mcpServers`):

```json
{
  "servers": {
    "q-ring": {
      "command": "qring-mcp"
    }
  }
}
```

`qring setup` does not write this file yet — VS Code is config-only (no first-party plugin bundle).

## Editor Plugins

The q-ring repo ships three first-party editor packs — each one adds rules/steering, agents, commands, skills, hooks, and the MCP connector to its host editor.

| Plugin | Editor | Highlights |
|--------|--------|-----------|
| [`cursor-plugin/`](cursor-plugin/README.md) | [Cursor](https://cursor.com) | 3 rules, 5 skills, 2 agents, 8 slash commands, 3 hooks, MCP autoconnect |
| [`kiro-plugin/`](kiro-plugin/README.md) | [Kiro](https://kiro.dev) | Official [Power](https://kiro.dev/docs/powers/create/) layout: `POWER.md`, root `mcp.json`, `steering/`, `hooks/`; or flatten with `plugin:sync:kiro` |
| [`claude-code-plugin/`](claude-code-plugin/README.md) | [Claude Code](https://docs.claude.com/en/docs/claude-code/overview) | `CLAUDE.md` memory, project `.mcp.json`, 2 subagents, 8 slash commands, 5 skills, 3 hook scripts |

### Cursor Plugin

The **q-ring Cursor Plugin** brings quantum secret management directly into your IDE with rules, skills, agents, commands, hooks, and a built-in MCP connector.

| Component | What it does |
|-----------|-------------|
| **3 Rules** | Always-on guidance: never hardcode secrets, use q-ring for all ops, warn about `.env` files |
| **5 Skills** | Auto-triggered by context: secret management, scanning, rotation, project onboarding, exec-with-secrets |
| **2 Agents** | `security-auditor` (proactive monitoring) and `secret-ops` (day-to-day assistant) |
| **8 Commands** | `/qring:scan-secrets`, `/qring:health-check`, `/qring:rotate-expired`, `/qring:setup-project`, `/qring:teleport-secrets`, `/qring:dashboard`, `/qring:exec-safe`, `/qring:analyze` |
| **3 Hooks** | `afterFileEdit` (lint scan), `sessionStart` (project context), `beforeShellExecution` (`.env` guard) |
| **MCP Connector** | Auto-connects to `qring-mcp` via stdio — all 44 tools available |

Install from the Cursor marketplace or see [`cursor-plugin/README.md`](cursor-plugin/README.md) for manual setup.

### Kiro Plugin (Power)

The [`kiro-plugin/`](kiro-plugin/) directory is a Kiro **Power** per [Create powers](https://kiro.dev/docs/powers/create/): `POWER.md` (metadata, onboarding, steering map), root [`mcp.json`](kiro-plugin/mcp.json) (MCP server must match the server name referenced in the power), and [`steering/`](kiro-plugin/steering/) for workflows. Install from Kiro → **Powers** → **Add power from Local Path** and select `kiro-plugin`, or publish the folder on GitHub and use **Add power from GitHub**.

Always-on steering blocks hardcoded secrets and routes everything through q-ring; `manual` steering files act as agent personas (`#qring-secret-ops`, `#qring-security-auditor`), skill packs, and slash-style commands (`#qring-cmd-scan-secrets`, etc.). Optional hooks live in `hooks/` for copy into `.kiro/hooks/`.

```bash
# Alternative: flatten into ~/.kiro (settings + steering + hooks)
pnpm run plugin:sync:kiro

# Or scope to a single project
pnpm run plugin:sync:kiro -- /path/to/your/project/.kiro
```

See [`kiro-plugin/README.md`](kiro-plugin/README.md) for the full breakdown.

### Claude Code Plugin

For [Claude Code](https://docs.claude.com/en/docs/claude-code/overview), q-ring ships a `CLAUDE.md` memory file, a project-scoped `.mcp.json`, two [subagents](https://docs.claude.com/en/docs/claude-code/sub-agents) (`secret-ops`, `security-auditor`), eight [slash commands](https://docs.claude.com/en/docs/claude-code/slash-commands) (`/qring-scan-secrets`, `/qring-health-check`, …), five [skills](https://docs.claude.com/en/docs/claude-code/skills), and three [hooks](https://docs.claude.com/en/docs/claude-code/hooks) (post-edit lint reminder, pre-Bash `.env` guard, session-start context primer).

```bash
# Install into the current project ($PWD)
pnpm run plugin:sync:claude

# Install agents/commands/skills/hooks at user scope (~/.claude)
pnpm run plugin:sync:claude -- --user

# Or target a specific project
pnpm run plugin:sync:claude -- /path/to/your/project
```

Existing `CLAUDE.md`, `.mcp.json`, or `.claude/settings.json` files are never silently overwritten — the script writes a `<filename>.qring-template` next to them so you can merge by hand. Pass `--force` to overwrite.

See [`claude-code-plugin/README.md`](claude-code-plugin/README.md) for the full breakdown.

## Architecture

```
qring CLI ─────┐
               ├──▶ Core Engine ──▶ @napi-rs/keyring ──▶ OS Keyring
MCP Server ────┘       │
                       ├── Envelope (quantum metadata)
                       ├── Scope Resolver (global / project / team / org)
                       ├── Collapse (env detection + branchMap globs)
                       ├── Observer (tamper-evident audit chain)
                       ├── Policy (governance-as-code engine)
                       ├── Noise (secret generation)
                       ├── Entanglement (cross-secret linking)
                       ├── Validate (provider-based liveness + rotation)
                       ├── Hooks (shell/HTTP/signal callbacks)
                       ├── Import (.env file ingestion)
                       ├── Exec (profile-restricted injection + redaction)
                       ├── Scan (codebase entropy heuristics)
                       ├── Provision (JIT ephemeral credentials)
                       ├── Approval (HMAC-verified zero-trust tokens)
                       ├── Context (safe redacted project view)
                       ├── Linter (secret-aware code scanning)
                       ├── Memory (encrypted agent persistence)
                       ├── Tunnel (ephemeral in-memory)
                       ├── Teleport (encrypted sharing)
                       ├── Agent (autonomous monitor + rotation)
                       └── Dashboard (live status via SSE)
```

## Project Config (`.q-ring.json`)

Optional per-project configuration:

```json
{
  "env": "dev",
  "defaultEnv": "dev",
  "branchMap": {
    "main": "prod",
    "develop": "dev",
    "staging": "staging",
    "release/*": "staging",
    "feature/*": "dev"
  },
  "secrets": {
    "OPENAI_API_KEY": { "required": true, "description": "OpenAI API key", "format": "api-key", "prefix": "sk-", "provider": "openai" },
    "DATABASE_URL": { "required": true, "description": "Postgres connection string", "validationUrl": "https://api.example.com/health" },
    "SENTRY_DSN": { "required": false, "description": "Sentry error tracking" }
  },
  "policy": {
    "mcp": {
      "denyTools": ["delete_secret"],
      "deniedKeys": ["PROD_DB_PASSWORD"],
      "deniedTags": ["production"]
    },
    "exec": {
      "denyCommands": ["curl", "wget"],
      "maxRuntimeSeconds": 60
    }
  }
}
```

- **`branchMap`** supports glob patterns with `*` wildcards (e.g., `release/*` matches `release/v1.0`)
- **`secrets`** declares the project's required secrets — use `qring check` to validate, `qring env:generate` to produce a `.env` file
- **`provider`** associates a liveness validation provider with a secret (e.g., `"openai"`, `"stripe"`, `"github"`) — use `qring validate` to test
- **`validationUrl`** configures the generic HTTP provider's endpoint for custom validation
- **`policy`** defines governance rules for MCP tool gating, key access restrictions, exec allowlists, and secret lifecycle requirements

## 📚 Docs

- [Quickstart: Claude Code](docs/quickstart-claude-code.md) · [Cursor](docs/quickstart-cursor.md) · [Kiro](docs/quickstart-kiro.md)
- [Troubleshooting](docs/troubleshooting.md) — keyring backends, MCP connection, approval gate, policy pinning
- [CLI ↔ MCP parity](docs/cli-mcp-parity.md) — every command mapped to its MCP tool
- [Releasing](docs/releasing.md) — tag-driven release flow

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full guide (dev environment, conventions, files to keep in sync). The short version:

- Run **`pnpm run lint`**, **`pnpm run typecheck`**, and **`pnpm run test:ci`** before opening a PR.
- Tests or sandboxes can point the audit log elsewhere with **`QRING_AUDIT_DIR`** (directory is created if missing); default is `~/.config/q-ring/audit.jsonl`.
- Optional local pre-commit: **`qring hook:install`** (uses this package’s `precommit` hook when `qring` is on your `PATH`).
- After changing one of the editor plugins:
  - **Cursor:** `pnpm run plugin:sync` copies `cursor-plugin/` to `~/.cursor/plugins/local/my-plugin` (or pass a custom path).
  - **Kiro:** `pnpm run plugin:sync:kiro` copies `kiro-plugin/mcp.json` → `~/.kiro/settings/mcp.json`, plus `steering/` and `hooks/` (or pass a project `.kiro` path). Prefer adding `kiro-plugin/` as a [Power](https://kiro.dev/docs/powers/create/) from the Powers panel instead.
  - **Claude Code:** `pnpm run plugin:sync:claude` copies `claude-code-plugin/` into the current directory (or pass a project path; add `--user` to install at `~/.claude/`).
- See also [docs/cli-mcp-parity.md](docs/cli-mcp-parity.md).

## 🔒 Security

- **Local-first.** Core storage is your OS keychain — there is no q-ring cloud and no account. The MCP surface, audit log, and agent memory live on your machine (audit and memory files are written owner-only, `0600`).
- **Written-down threat model.** What q-ring protects, what it doesn't, and where the residual risk lives — including an honest answer to the agent-exfiltration question — in [docs/threat-model.md](docs/threat-model.md).
- **Hardened by adversarial review.** v0.14.0 shipped the results of an internal adversarial audit — policy-bypass, approval-scoping, and exec-profile findings all fixed, each with regression tests. Details are in the [CHANGELOG](CHANGELOG.md) `Security` sections (house style since 0.12.0: fix first, then disclose there).
- **Reporting a vulnerability.** Use [GitHub private vulnerability reporting](https://github.com/I4cTime/q-ring/security/advisories/new) — see [SECURITY.md](SECURITY.md) for the supported-versions table and response commitments (48-hour acknowledgement, 7-day assessment).

## 📜 License

[AGPL-3.0](LICENSE) - Free to use, modify, and share. Any derivative work or hosted service must release its source code under the same license.
