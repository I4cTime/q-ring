# q-ring threat model

This document states plainly what q-ring protects, what it does not, and
where the residual risk lives. It is written for the skeptical reader:
if a claim here does not match the code, that is a bug — report it via
[SECURITY.md](../SECURITY.md).

Telemetry and data-handling posture is covered separately in
[PRIVACY.md](../PRIVACY.md) (short version: local-first, no cloud, no
telemetry).

## Assets

- **Secret values** — API keys, tokens, passwords, connection strings,
  stored in the OS vault (macOS Keychain, Linux Secret Service, Windows
  Credential Vault) via `@napi-rs/keyring`.
- **q-ring state on disk** under `~/.config/q-ring/`: the hash-chained
  audit log (`audit.jsonl`), encrypted agent memory
  (`agent-memory.enc`), and the entanglement / approvals / hooks
  registries. Created `0600` (files) / `0700` (directory).
- **Policy and approvals** — `.q-ring.json` per-project policy and
  HMAC-signed approval grants.
- **Teleport bundles** — AES-256-GCM-encrypted secret bundles in
  transit between machines.

## Trust boundaries

```
┌─────────────────────────────── your machine ───────────────────────────────┐
│                                                                            │
│  OS keychain  ◄──►  q-ring process (CLI / MCP server)  ◄──►  MCP client    │
│  (vendor's          policy · approvals · audit ·             (Cursor,      │
│   security          redaction · TTL/decay                     Claude Code, │
│   model)                    │                                 Kiro, …)     │
│                             ▼                                              │
│                     child processes (`qring exec`)                         │
└────────────────────────────────────────────────────────────────────────────┘
```

- **The OS keychain** is trusted. q-ring inherits the vendor's security
  model (user-session unlock, per-user isolation). q-ring does not try
  to improve on it, only to avoid ever writing values outside it.
- **The q-ring process** is trusted. It holds secret values in memory
  while servicing a request. Enforcement (policy, approvals, audit)
  happens here — server-side of the MCP boundary — so a client cannot
  opt out of it.
- **The MCP client is semi-trusted and is the primary threat.** An
  agent can be steered by prompt injection, a compromised extension, or
  a malicious tool description. q-ring's job is to make the client's
  access *governed, observable, and revocable* — not to assume the
  client is well-behaved.
- **Child processes** run with whatever secrets you inject. Exec
  profiles constrain which commands run; redaction filters known values
  from captured output. Neither is a sandbox (see below).

## Attackers considered

1. **A prompt-injected or otherwise misbehaving MCP agent** trying to
   read secrets it should not, write over protected keys, or leak
   values into the transcript.
2. **Another local process running as you** reading q-ring's files or
   probing its local dashboard.
3. **Someone with the disk but not your session** (stolen laptop,
   backup, CI artifact) reading state at rest.
4. **A malicious teleport bundle** crafted to plant or overwrite keys
   on unpack.
5. **A network attacker** reachable only if you point q-ring at them —
   e.g. an SSRF attempt via a hook or validation URL.

Explicitly *not* considered: an attacker with root, or arbitrary code
execution in your user session outside q-ring. They can read the
keychain the same way q-ring does; no local tool changes that.

## Mitigations by surface

**MCP tool access (the agent boundary)**

- Secrets are exposed as *tools*, never as MCP resources — the agent
  must intend each read; keys cannot leak via a resource listing.
- Key-level allow/deny policy in `.q-ring.json`, enforced in the
  server. Since v0.14 the policy schema is strict and **fails closed**:
  a malformed policy raises an error instead of silently allowing.
- Sensitive reads can require **human approval**. Approvals are
  HMAC-signed and bound to the resolved project identity
  (`q-ring:project:<hash>`), so a grant in project A does not satisfy
  project B (v0.14).
- Bulk paths (`export_secrets`, `teleport_pack`) and entanglement
  writes go through the same key-level policy checks — entanglement
  can no longer be used as a policy-bypass write primitive (v0.14).
- TTL/decay expires access instead of letting grants persist.

**Audit**

- Every access is appended to a hash-chained JSONL log. `audit:verify`
  checks the chain against a keyed anchor — an HMAC of the head line
  under a random key held in the OS keyring, stored outside the log —
  making both rewrites and truncation tamper-evident (v0.14). Hosts
  without a keyring degrade to per-line integrity checks and say so.
- Audit entries record events *about* secrets, never secret values.
- `detect_anomalies` flags unusual access patterns over the log.

**`qring exec` / `qring run`**

- `qring run` is the least-privilege path: it injects only the keys the
  project declares (the `.q-ring.json` manifest plus `qring://` refs in
  .env files), not the whole scope. `qring://` refs are committable
  pointers — the value never appears in the file.

- Secrets are injected into the child's environment, not echoed to the
  shell. Captured stdout/stderr is piped through a redaction transform
  that masks known secret values (UTF-8-safe across chunk boundaries
  since v0.14).
- Profiles gate what may run: `restricted` denies network tools *and*
  interpreters/shells (`python`, `node`, `sh`, …), because
  `python -c '…'` is a network tool. `ci` and `unrestricted` widen
  this deliberately; custom profiles live in `.q-ring.json`.
- **This is not a sandbox.** An allowed binary can still do anything an
  allowed binary can do. Redaction is best-effort against *known*
  values — it cannot mask a secret the child re-encodes.

**At rest**

- Secret values live only in the OS vault. q-ring's own files hold
  metadata, the audit log, and encrypted agent memory — created
  `0600`/`0700`, with a best-effort tightening pass for files created
  by older versions.
- Agent memory is encrypted under a keyring-held key, else a PBKDF2 key
  from `QRING_MEMORY_PASSPHRASE`, else **writes fail closed** — there
  is no fallback to a machine-derivable key (v0.14).
- On hosts with no OS keyring (headless Linux, containers, CI), the
  opt-in file backend (`QRING_BACKEND=file`, v0.15) stores secrets in
  an AES-256-GCM file keyed by PBKDF2 from `QRING_FILE_PASSPHRASE`.
  It is explicit-only — a missing keyring never falls back to it
  silently — and fails closed without the passphrase.
- Corrupt registry files are moved aside to `<name>.corrupt-<ts>` and
  never silently overwritten.

**Ephemeral and shared secrets**

- Tunnels are in-memory only, destroyed by TTL or read count; they
  never touch disk.
- Teleport bundles are AES-256-GCM under a user-supplied passphrase;
  passphrase strength and channel choice are the user's responsibility.
  `--dry-run` shows what an unpack would write before it writes.

**Local services and outbound requests**

- The status dashboard binds to `127.0.0.1` and requires a per-launch
  random bearer token on every route — localhost binding alone is not
  treated as authentication on shared hosts.
- Hook and validation URLs are SSRF-guarded against private, loopback,
  and link-local ranges, including DNS-rebinding.
- `qring push` (v0.15) deliberately exports manifest secrets to GitHub
  Actions / Vercel / Cloudflare through each platform's own
  authenticated CLI — q-ring never holds platform tokens, values travel
  over the child's stdin (never argv, which is world-readable via
  `/proc`), and every pushed key lands in the audit chain.
- Validation providers are contacted only when you explicitly configure
  and invoke them; keys are sent in headers, never URLs.
- Otherwise the CLI and MCP server make **no network calls of their
  own** — no telemetry, no update pings.

## Where plaintext can appear

Being explicit, because this is where hand-waving usually hides:

- **In q-ring's process memory** while servicing a request.
- **In a child process's environment** during `qring exec` — that is
  the feature.
- **In the MCP transcript, if policy allows the read.** A permitted
  `get_secret` returns the value to the client; that is also the
  feature. Use policy/approvals to decide *which* keys may do this.
- **In a generated `.env`** if you run `env:generate` — deliberate,
  user-invoked, and on you to clean up.
- **In an unpacked teleport bundle** on the receiving machine.
- **On the destination platform after `qring push`** — once a value
  lands in GitHub/Vercel/Cloudflare, that platform's security model
  governs it, not q-ring's.

## The exfiltration question, answered honestly

*"If the agent can read a secret and also has a network tool, can a
prompt injection exfiltrate it?"* — **Yes, in principle.** Once a value
is returned to a client that also holds an egress channel (HTTP tool,
interpreter, even `git push`), no local secrets manager can retract it.
q-ring's position is defense-in-depth around that irreducible fact:

- make every read **intentional** (tools, not resources),
- make sensitive reads **gated** (policy, project-bound approvals),
- make all reads **observable** (tamper-evident audit, anomaly
  detection),
- make access **expiring** (TTL/decay, tunnels),
- and keep values **out of ambient context** (exec-with-redaction
  instead of pasting keys into prompts or `.env` files).

If a key must never reach an agent, deny it at the key level and use
`qring exec` so the value only ever enters a child process — the agent
sees redacted output, not the secret.

## Out of scope

- An attacker with root or with arbitrary code execution as your user.
- Guaranteeing a client never leaks a value it was *permitted* to read.
- Team sync, RBAC, and hosted audit — q-ring is per-machine by design;
  cross-machine transfer is the manual teleport flow.
- Compliance certification. The audit log is local and tamper-evident,
  not "immutable in the cloud."

## Hardening recommendations for production keys

- Deny production keys to MCP tools entirely in `.q-ring.json`; expose
  them only through `qring exec` with the `restricted` profile, or
  `qring run` so only the declared manifest is injected.
- Require approval for anything you would rotate if it leaked.
- Run `qring doctor` after upgrading — it flags pre-v0.14 approvals
  that lack a project binding.
- Verify the audit chain (`qring audit verify`) on a schedule, and keep
  `QRING_MEMORY_PASSPHRASE` set on headless/CI hosts where no OS
  keyring is available.

## History and disclosure

v0.14.0 was a hardening release from an internal adversarial audit;
every finding is documented in the [CHANGELOG](../CHANGELOG.md)
`Security` sections (house style: fix first, then disclose there).
Report new findings via [SECURITY.md](../SECURITY.md) — private
reporting, 48-hour acknowledgement.
