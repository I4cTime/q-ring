import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["src/__tests__/**/*.test.ts"],
    environment: "node",
    testTimeout: 10_000,
    setupFiles: ["src/__tests__/helpers/test-env.ts"],
    // LOAD-BEARING: the suite mutates process.env per file (HOME swaps in
    // approval tests, QRING_* everywhere), which is only safe with per-file
    // process isolation. `--pool=threads` shares process.env across files
    // and fails deterministically — do not switch pools for speed.
    pool: "forks",
  },
});
