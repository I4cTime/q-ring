---
paths:
  - "**/.env*"
---

# .env File Safety

When a `.env` file is open or being edited:

1. **Suggest importing** — offer to run `import_dotenv` to migrate all key-value pairs into q-ring where they are encrypted in the OS keychain.
2. **Check .gitignore** — verify that `.env*` patterns are in `.gitignore`. If not, warn the user immediately.
3. **Prefer manifest-driven generation** — if the project has a `.q-ring.json` manifest, suggest using `env_generate` to produce `.env` files on-demand from q-ring instead of maintaining them manually.
4. **Never add secrets** to `.env` files directly. Use `qring set KEY value` and then `qring env:generate` to produce the file.
