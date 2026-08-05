# Releasing q-ring

Releases are tag-driven. One script stages everything; pushing the tag does the rest.

## Flow

```bash
# on develop, with a non-empty [Unreleased] section in CHANGELOG.md
pnpm run release:prepare minor      # or patch / major / an explicit x.y.z
```

`scripts/prepare-release.mjs`:

1. bumps `package.json`,
2. runs `sync-versions` (Cursor + Claude plugin manifests, marketplaces, `server.json`, `SECURITY.md`),
3. rolls the CHANGELOG's `[Unreleased]` into `[x.y.z] — YYYY-MM-DD` and leaves a fresh `[Unreleased]`,
4. runs the plugin-parity check,
5. prints the exact commit/tag/push commands.

Review the diff, merge to `main` per the usual PR flow, then tag and push:

```bash
git tag v0.13.0
git push --tags
```

## What the tag triggers

`.github/workflows/release.yml` (on `v*` tags):

1. **GitHub Release** — created idempotently, with the release notes extracted from that version's CHANGELOG section. Tagging without a matching CHANGELOG section fails the run on purpose.
2. **Publish** (`publish.yml`, dispatched on the tag ref) — npm publish with provenance (idempotent: skips if the version is already on npm), then MCP Registry publish via a pinned `mcp-publisher`.
3. **Homebrew** (`update-homebrew.yml`, dispatched on the tag ref) — waits up to 5 minutes for the version to appear on npm, regenerates the tap formula with the new tarball sha, and pushes to `I4cTime/homebrew-tap` (skips if unchanged).
4. **Smithery** (`publish.yml`, `smithery` job, `needs: publish`) — waits for npm to serve the new version, builds the cross-platform MCPB bundle (`pnpm run build:mcpb` / `scripts/build-mcpb.mjs`, which vendors the *published* npm package), attaches `qring-<version>.mcpb` to the GitHub release, publishes it to `i4ctime/q-ring` with the pinned `smithery` CLI (`SMITHERY_API_KEY` repo secret), and best-effort re-applies the listing metadata + icon (bundle publishes have reset them before). Downstream of the npm/MCP publish on purpose — a Smithery failure never blocks the critical path.

Why **dispatch** instead of events or `workflow_call` (both were tried and failed on the first v0.13.0 attempt):

- The release is created with `GITHUB_TOKEN`, and GitHub does not fire workflow triggers for events created by `GITHUB_TOKEN` — so the `release: published` triggers can't fire on this path. (They remain in place so a release created manually in the UI still publishes.)
- `workflow_call` breaks npm trusted publishing: npm validates the OIDC token's *top-level* workflow file, which is `release.yml` for a called workflow, but the trusted publisher on npmjs.com is registered for `publish.yml` — npm rejects the token with a misleading `E404`.
- Explicit `workflow_dispatch` API calls **are** allowed with `GITHUB_TOKEN` (recursion prevention only suppresses event-triggered runs), and a dispatched run has `publish.yml` as its top-level workflow, so the OIDC claim matches.

Also learned the hard way: `release.yml` must not share `publish.yml`'s concurrency group — a called/dispatched workflow's own group is what serializes publishing, and a parent holding the same group deadlocks. Every downstream step is idempotent, so overlap between the manual-release and tag-driven paths is harmless.

## Recovering from a failed release

- **npm/MCP publish failed:** fix the cause, then re-run from the Actions tab with `workflow_dispatch` on `publish.yml`, passing the tag as `ref`. The npm step skips if the version already published.
- **Homebrew failed:** re-run the `update-homebrew.yml` job — it re-derives everything from the tag and npm.
- **Smithery failed:** re-run the `smithery` job (or the whole `publish.yml` dispatch — the npm step skips when already published). Manual fallback: `pnpm run build:mcpb && smithery mcp publish dist-mcpb/qring-<ver>.mcpb -n i4ctime/q-ring`.
- **Wrong notes:** edit the GitHub Release body in the UI; nothing downstream depends on it.
