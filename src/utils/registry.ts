import { existsSync, readFileSync, renameSync } from "node:fs";

/**
 * Load a JSON registry file, distinguishing "absent" (a normal first run) from
 * "present but corrupt" (a crash mid-write, a full disk, manual mangling).
 *
 * The previous pattern — `try { JSON.parse(...) } catch { return empty }` —
 * treated both cases identically, so a single unparseable read made the caller's
 * next save silently overwrite the file with an empty-plus-one-new-entry
 * registry, permanently destroying every entanglement link / approval grant /
 * hook the user had, with no warning.
 *
 * Here, corruption moves the file aside to `<path>.corrupt-<timestamp>` and
 * warns loudly, so the caller reinitializes from empty while the original bytes
 * survive in the backup. If the file cannot even be moved aside, we throw rather
 * than let a later save overwrite the only (recoverable) copy.
 */
export function loadJsonRegistry<T>(path: string, empty: T): T {
  if (!existsSync(path)) return empty;

  const raw = readFileSync(path, "utf8");
  try {
    return JSON.parse(raw) as T;
  } catch (err) {
    const reason = err instanceof Error ? err.message : String(err);
    const stamp = new Date().toISOString().replace(/[:.]/g, "-");
    const backup = `${path}.corrupt-${stamp}`;
    try {
      renameSync(path, backup);
    } catch {
      throw new Error(
        `q-ring: registry ${path} is corrupt (${reason}) and could not be moved ` +
          `aside — refusing to continue so a later write cannot overwrite it. ` +
          `Inspect or remove the file manually.`,
      );
    }
    console.error(
      `q-ring: WARNING — registry ${path} was corrupt (${reason}); moved it to ` +
        `${backup} and reinitialized from empty. Previous entries are preserved ` +
        `in the backup file.`,
    );
    return empty;
  }
}
