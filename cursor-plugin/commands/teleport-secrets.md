---
name: teleport-secrets
description: Pack secrets into an encrypted bundle or unpack a received bundle for cross-machine transfer.
---

# Teleport Secrets

Securely transfer secrets between machines using encrypted bundles.

## Usage

Invoke via `/qring:teleport-secrets`

## Workflow

Ask the user whether they want to **pack** (send) or **unpack** (receive).

### Pack (send secrets)

1. Call `list_secrets` to show available secrets.
2. Ask the user which keys to include (or use tag-based selection).
3. Ask how to lock the bundle:
   - **Recipients** (preferred, 0.18+): the user pastes one or more `qring1…` recipient strings the teammates got from `qring teleport keygen`. Call `teleport_pack` with the selected keys and `recipients`.
   - **Passphrase**: ask for a passphrase and call `teleport_pack` with `passphrase`.
4. Present the encrypted bundle string to the user for transfer (clipboard, secure channel, etc.).
5. For passphrase bundles, remind the user to share the passphrase through a separate channel. Recipient bundles need nothing else.

### Unpack (receive secrets)

1. Ask the user to paste the encrypted bundle string.
2. Call `teleport_unpack` with `dryRun: true` first: a v2 bundle reports which recipient ids it is addressed to and whether this machine's identity is one of them; a v1 bundle needs the passphrase (ask for it).
3. Call `teleport_unpack` for real (passphrase only for v1; v2 uses the identity in the user's keyring — if there is none, tell the user to run `qring teleport keygen` and have the sender re-pack to the printed recipient).
4. Report the imported secrets: count, names, and scopes.
5. Offer to verify the imports with `list_secrets`.

## Security Notes

- The bundle is AES-256-GCM encrypted — safe to transfer over untrusted channels
- Recipient bundles: only the listed recipients' keyrings can open it; never ask for or handle a private key — agents only see `qring1…` recipient strings
- Passphrase bundles: always share the passphrase through a separate, secure channel (different from the bundle)
- Bundles are one-time use by convention — re-pack for additional transfers
