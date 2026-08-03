# Privacy Policy

q-ring is local-first. There is no q-ring cloud, no account, and no
telemetry.

## What q-ring stores, and where

- **Secret values** live in your operating system's native vault — macOS
  Keychain, Linux Secret Service, or Windows Credential Vault. q-ring
  never writes secret values to its own files in plaintext.
- **Metadata** (key names, scopes, tags, decay timers, entanglement
  links) and the **audit log** (hash-chained JSONL) are stored in local
  files under your user profile, created with `0600` permissions.

## What q-ring sends over the network

Nothing, by default. The CLI and MCP server make no network calls of
their own — no telemetry, no analytics beacons, no update pings.

Network requests happen only when you explicitly invoke a feature that
requires them, such as a Just-In-Time provider integration you have
configured; those requests go directly to the provider you chose, under
that provider's privacy policy.

## What AI agents can see

MCP clients (Cursor, Kiro, Claude Code, and others) access secrets only
through q-ring's MCP tools, governed by the key-level policy and approval
rules in `.q-ring.json`. `qring exec` redacts secret values from command
output, and audit entries record events about secrets — not the secret
values themselves.

## Contact

Questions: i4c.studio.dev@gmail.com — or open an issue at
https://github.com/I4cTime/q-ring/issues. Security reports: see
[SECURITY.md](SECURITY.md).
