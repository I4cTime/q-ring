import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  existsSync,
  readFileSync,
  writeFileSync,
  readdirSync,
  rmSync,
  mkdirSync,
} from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { loadJsonRegistry } from "../../utils/registry.js";

const dir = join(tmpdir(), `qring-registry-corrupt-${process.pid}`);
const path = join(dir, "registry.json");

describe("loadJsonRegistry — corruption handling (B2)", () => {
  let warnSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    rmSync(dir, { recursive: true, force: true });
    mkdirSync(dir, { recursive: true });
    warnSpy = vi.spyOn(console, "error").mockImplementation(() => {});
  });

  afterEach(() => {
    warnSpy.mockRestore();
    rmSync(dir, { recursive: true, force: true });
  });

  it("returns the empty value when the file is absent (normal first run)", () => {
    expect(loadJsonRegistry(path, { pairs: [] })).toEqual({ pairs: [] });
    // must NOT create a spurious backup for an absent file
    expect(readdirSync(dir).filter((f) => f.includes(".corrupt-"))).toHaveLength(0);
  });

  it("parses a valid registry file", () => {
    writeFileSync(path, JSON.stringify({ pairs: [{ a: 1 }] }));
    expect(loadJsonRegistry(path, { pairs: [] })).toEqual({ pairs: [{ a: 1 }] });
  });

  it("on corruption: backs the file up, warns, and returns empty — never silently empties", () => {
    const corrupt = "{not valid json";
    writeFileSync(path, corrupt);

    const result = loadJsonRegistry(path, { pairs: [] as unknown[] });

    // reinitialized from empty for the caller...
    expect(result).toEqual({ pairs: [] });
    // ...loudly, not silently
    expect(warnSpy).toHaveBeenCalledOnce();
    // ...the corrupt bytes are preserved byte-identical in a .corrupt- backup
    const backups = readdirSync(dir).filter((f) => f.includes(".corrupt-"));
    expect(backups).toHaveLength(1);
    expect(readFileSync(join(dir, backups[0]), "utf8")).toBe(corrupt);
    // ...and the original path no longer holds the corrupt data (moved aside),
    // so a subsequent save cannot overwrite-and-destroy it
    expect(existsSync(path)).toBe(false);
  });
});
