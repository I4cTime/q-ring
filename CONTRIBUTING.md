# Contributing to q-ring

Thanks for helping improve q-ring! This guide covers the dev environment, project conventions, and the release-adjacent files you must keep in sync.

## Dev environment

- **Node** ≥ 18 (CI runs 22, releases build on 24) and **pnpm** — the exact pnpm version is pinned via the `packageManager` field in `package.json` (use `corepack enable` and it resolves automatically).
- Install and build:

  ```bash
  pnpm install
  pnpm run build
  ```

- Useful scripts:

  | Script | What it does |
  |---|---|
  | `pnpm run typecheck` | `tsc --noEmit` |
  | `pnpm run lint` | ESLint over `src/`, zero warnings allowed |
  | `pnpm test` | vitest in watch mode |
  | `pnpm run test:ci` | single vitest run (what CI runs) |
  | `pnpm run build` | bundles the dashboard client, then tsup → `dist/` |
  | `pnpm run format` | prettier over `src/` and `scripts/` |

- Tests and sandboxes can point the audit log elsewhere with `QRING_AUDIT_DIR` (directory is created if missing); default is `~/.config/q-ring/audit.jsonl`.
- `QRING_DEBUG=1` makes the CLI print full stack traces instead of one-line errors.
- Optional local pre-commit: `qring hook:install` (uses this package's `precommit` hook when `qring` is on your `PATH`).

## Branches and commits

- Base your work on **`develop`**; `main` tracks releases.
- Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `chore:`, with optional scope — e.g. `fix(ci): …`), matching the existing history and the Dependabot config.
- Before opening a PR, run `pnpm run lint`, `pnpm run typecheck`, and `pnpm run test:ci` — the PR template checklist mirrors CI.

## Keep these in sync when you change behavior

- **CLI ↔ MCP parity:** [docs/cli-mcp-parity.md](docs/cli-mcp-parity.md) maps every CLI command to its MCP tool. Update it when adding, renaming, or removing either surface.
- **Editor plugins:** after changing plugin content:
  - **Skills and Claude Code rules are generated** — edit only `cursor-plugin/skills/*/SKILL.md` and `cursor-plugin/rules/*.mdc`, then run `pnpm run plugin:gen-skills` to regenerate the Claude Code skills, the Claude Code session-hook rules (`claude-code-plugin/hooks/qring-session-rules.md`) and rule files (`claude-code-plugin/rules/*.md`), and the Kiro skill steering files, and commit the output. CI (`pnpm run check:parity`) fails if they drift, if the plugins' command/agent/skill sets diverge, if doc'd MCP tool counts don't match the code, or if manifest versions are stale.
  - Cursor: `pnpm run plugin:sync` copies `cursor-plugin/` to `~/.cursor/plugins/local/my-plugin`.
  - Kiro: `pnpm run plugin:sync:kiro` copies `kiro-plugin/mcp.json`, `steering/`, and `hooks/` into `~/.kiro`.
  - Claude Code: `pnpm run plugin:sync:claude` copies the plugin into the current project (`--user` for `~/.claude`).
- **Versions:** `pnpm run sync-versions` stamps `package.json`'s version into the Cursor and Claude Code plugin manifests, `server.json`, and `SECURITY.md`. It runs automatically on `prepublishOnly`.
- **Dashboard client:** `src/core/dashboard-client.ts` is generated from `src/dashboard-client/main.js` — run `pnpm run build:dashboard` after editing the client and commit the regenerated file.
- **CHANGELOG:** add your change under `[Unreleased]` in `CHANGELOG.md` (Keep a Changelog format).

## Security issues

Do **not** open a public issue for vulnerabilities — follow [SECURITY.md](SECURITY.md).

## License

By contributing you agree your work is licensed under [AGPL-3.0-only](LICENSE), the same license as the project.
