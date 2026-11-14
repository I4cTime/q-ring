# Troubleshooting

Start with the built-in self-check — it covers the most common failures in one shot:

```bash
qring doctor          # keyring backend and storage format, audit log, manifest, policy, qring-mcp on PATH
qring doctor --json   # same, machine-readable
```

Set `QRING_DEBUG=1` to get full stack traces from any CLI error instead of the one-line message.

## Keyring backend errors (most common first-run issue)

q-ring stores secrets in the OS keychain via [`@napi-rs/keyring`](https://github.com/Brooooooklyn/keyring-node): GNOME Keyring / Secret Service on Linux, Keychain on macOS, Credential Manager on Windows.

**Symptom:** `qring set` / `get` fails with a keyring error, or `qring doctor` reports the keyring probe failed.

- **Headless Linux / SSH / CI:** there is usually no unlocked Secret Service. Install and start one:

  ```bash
  sudo apt install gnome-keyring dbus-x11        # Debian/Ubuntu
  dbus-run-session -- sh -c 'echo "" | gnome-keyring-daemon --unlock; exec your-command'
  ```

  For CI pipelines, prefer `qring exec` / `qring ci:validate` on a runner with a keyring, or inject secrets through your CI's native secret store instead of q-ring.

- **Linux desktop:** make sure the login keyring is unlocked (it usually unlocks with your session). KDE users need `ksecretservice` or GNOME Keyring installed.
- **Docker:** containers have no OS keychain — the Docker image is for the MCP protocol surface and experiments, not durable storage (see the README's Docker section).

## A secret reads back empty on Linux (passwordless GNOME keyring)

**Symptom:** `qring get KEY` fails with `Secret "KEY" (global scope): the stored value is empty, likely lost by the OS keyring. Run `qring doctor` to check the keyring, then set the secret again.` With an older q-ring the same entry reads as an empty value.

**Cause:** a GNOME keyring without a password is stored as a plain text file. The daemon writes each value raw but reads the file back with escape processing, so a q-ring entry whose stored JSON contained a backslash escape (a quote, backslash, newline or control character in the value, description or a tag) came back empty the next time the daemon reloaded its file. That is often right after the next write to the keyring, at the latest on a daemon restart or reboot. A newline escape could make the daemon reject the whole file and leave every secret in that keyring unreadable. Encrypted GNOME keyrings, KWallet, macOS Keychain, Windows Credential Manager and the file backend are not affected.

**Fix:**

1. Upgrade every q-ring install on the machine together: the global CLI, the MCP server or plugin, and anything pinned in scripts. On Linux, q-ring now stores affected entries in a backslash-free form (`{"v":1,"enc":"b64",...}`), and a version older than this fix reads that form as a plain value and returns the wrapper text instead of the secret.
2. Run `qring doctor` and read the "keyring storage format" check. It lists keys still stored in the at-risk form and keys that are already empty.
3. Read each at-risk key once with the new version (`qring get KEY`); that rewrites it in the safe form.
4. Set each empty key again with `qring set KEY`. `set` and `delete` work on an empty key, `list` still shows it, and `export` and `exec` skip it with a warning.

A passwordless keyring keeps secrets as plain text on disk, so disk encryption is what protects them. Set a keyring password if you want the keyring itself encrypted.

## MCP server not connecting (Cursor / Kiro / Claude Code)

1. `qring doctor` — confirms `qring-mcp` is on `PATH`. Editors spawn it by bare name; a shell alias is not enough.
2. Install globally so the binary lands on `PATH`: `pnpm add -g @i4ctime/q-ring` (or npm/yarn/brew).
3. GUI editors don't always inherit your shell's `PATH` (especially on macOS when launched from the Dock). If tools don't appear, set the absolute path in the MCP config:

   ```json
   { "mcpServers": { "q-ring": { "command": "/absolute/path/to/qring-mcp" } } }
   ```

   Find it with `command -v qring-mcp` (or `where qring-mcp` on Windows).
4. Approve the server when the editor prompts (Claude Code asks per-project for `.mcp.json` servers).
5. Still stuck? Run the handshake by hand — you should get a JSON `serverInfo` response:

   ```bash
   echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"probe","version":"0.0.0"}}}' | qring-mcp | head -1
   ```

## "Why can't the agent read my secret?" (approval gate)

Secrets stored with `--requires-approval` (or matching `policy.secrets.requireApprovalForTags`) refuse MCP reads until you grant a scoped, time-boxed approval:

```bash
qring approve MY_KEY --for 3600 --reason "deploying"
qring approvals        # see active grants, TTLs, and tamper status
```

The CLI itself is never gated — only MCP/agent reads are.

## "My policy is being ignored" (MCP policy root pinning)

Since 0.12.0 the MCP server resolves `.q-ring.json` **policy** from the directory it was launched in, not from the `projectPath` the agent passes (that closed a policy-escape hole). If your policy seems inactive over MCP:

- make sure the editor launches `qring-mcp` with the project as its working directory, or
- put the policy in the `.q-ring.json` at the server's launch directory.

Project-scoped *secret* resolution still follows `projectPath` — only policy is pinned.

## Audit log

- Default location: `~/.config/q-ring/audit.jsonl`. Override with `QRING_AUDIT_DIR` (created if missing) — useful for tests and sandboxes.
- `qring audit:verify` (or the dashboard's chain badge) checks the tamper-evident hash chain. A broken chain means the file was edited or partially deleted; export what you need (`qring audit:export`), then investigate before trusting the tail.

## Scripting gotchas

- Destructive commands (`delete`, `forget --all`, `teleport unpack` over existing keys, `wizard` over existing keys, `env:generate -o` over an existing file) prompt on a TTY and **error** on non-TTY stdin — pass `--yes`/`-y` in scripts.
- Machine output: `--json` works on effectively the whole read surface and emits `{ "ok": true, "data": … }` (see [cli-mcp-parity.md](cli-mcp-parity.md)).
- `qring get --raw` prints the bare value with no trailing newline — right for piping into other tools.
- `qring has KEY --quiet` is the exit-code-only existence check (decay-aware: expired secrets count as absent).

## AGPL questions

q-ring is AGPL-3.0-only. Using the CLI/MCP server as a tool in your workflow does **not** make your projects AGPL — the license applies to q-ring itself and derivative works of it. If you modify q-ring and offer it as a network service, you must publish your modifications. Not legal advice; see [LICENSE](../LICENSE).
