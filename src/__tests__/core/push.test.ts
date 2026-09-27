import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { mkdtempSync, writeFileSync, rmSync, readFileSync, statSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

vi.mock("@napi-rs/keyring", async () => {
  const fake = await import("../helpers/fake-keyring.js");
  return { Entry: fake.FakeEntry, findCredentials: fake.findCredentials };
});

const spawnSyncMock = vi.hoisted(() => vi.fn());
vi.mock("node:child_process", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:child_process")>();
  return { ...actual, spawnSync: spawnSyncMock };
});

import { resetFakeKeyring } from "../helpers/fake-keyring.js";
import { setSecret } from "../../core/keyring.js";
import { clearCollapseCache } from "../../core/collapse.js";
import { pushSecrets, resolvePushKeys } from "../../core/push.js";

let project: string;

beforeEach(() => {
  resetFakeKeyring();
  clearCollapseCache();
  spawnSyncMock.mockReset();
  // Default: every CLI invocation (probe + push) succeeds.
  spawnSyncMock.mockReturnValue({ status: 0, stdout: "", stderr: "", error: undefined });
  project = mkdtempSync(join(tmpdir(), "qring-push-test-"));
});

afterEach(() => {
  rmSync(project, { recursive: true, force: true });
});

function writeManifest(secrets: Record<string, object>): void {
  writeFileSync(join(project, ".q-ring.json"), JSON.stringify({ secrets }));
  clearCollapseCache();
}

describe("resolvePushKeys", () => {
  it("prefers explicit keys over the manifest", () => {
    writeManifest({ FROM_MANIFEST: {} });
    expect(resolvePushKeys({ target: "github", keys: ["A", "B"], projectPath: project })).toEqual(["A", "B"]);
  });

  it("falls back to manifest keys", () => {
    writeManifest({ ONE: {}, TWO: {} });
    expect(resolvePushKeys({ target: "github", projectPath: project })).toEqual(["ONE", "TWO"]);
  });

  it("throws when there is nothing to push", () => {
    expect(() => resolvePushKeys({ target: "github", projectPath: project })).toThrow(/Nothing to push/);
  });
});

describe("pushSecrets", () => {
  it("pushes manifest keys via gh with the value on stdin, never argv", () => {
    writeManifest({ API_KEY: {} });
    setSecret("API_KEY", "secret-value-1", { scope: "project", projectPath: project, silent: true });

    const result = pushSecrets({ target: "github", projectPath: project, silent: true });

    expect(result.pushed).toEqual(["API_KEY"]);
    const pushCall = spawnSyncMock.mock.calls.find((c) => c[1]?.includes("set"));
    expect(pushCall![0]).toBe("gh");
    expect(pushCall![1]).toEqual(["secret", "set", "API_KEY"]);
    expect(pushCall![2].input).toBe("secret-value-1");
    expect(pushCall![1]).not.toContain("secret-value-1");
  });

  it("passes --repo to gh when given", () => {
    setSecret("K", "value-long", { scope: "project", projectPath: project, silent: true });
    pushSecrets({ target: "github", keys: ["K"], repo: "I4cTime/q-ring", projectPath: project, silent: true });
    const pushCall = spawnSyncMock.mock.calls.find((c) => c[1]?.includes("set"));
    expect(pushCall![1]).toEqual(["secret", "set", "K", "--repo", "I4cTime/q-ring"]);
  });

  it("vercel pushes once per environment with --force", () => {
    setSecret("K", "value-long", { scope: "project", projectPath: project, silent: true });
    pushSecrets({
      target: "vercel", keys: ["K"], vercelEnvs: ["production", "preview"],
      projectPath: project, silent: true,
    });
    const envCalls = spawnSyncMock.mock.calls.filter((c) => c[1]?.[0] === "env");
    expect(envCalls.map((c) => c[1])).toEqual([
      ["env", "add", "K", "production", "--force"],
      ["env", "add", "K", "preview", "--force"],
    ]);
  });

  it("reports missing keys without failing the push", () => {
    writeManifest({ PRESENT: {}, ABSENT: {} });
    setSecret("PRESENT", "value-long", { scope: "project", projectPath: project, silent: true });

    const result = pushSecrets({ target: "cloudflare", projectPath: project, silent: true });

    expect(result.pushed).toEqual(["PRESENT"]);
    expect(result.missing).toEqual(["ABSENT"]);
  });

  it("captures per-key CLI failures", () => {
    setSecret("BAD", "value-long", { scope: "project", projectPath: project, silent: true });
    spawnSyncMock.mockImplementation((_bin: string, args: string[]) =>
      args.includes("--version")
        ? { status: 0, stdout: "", stderr: "" }
        : { status: 1, stdout: "", stderr: "not logged in" },
    );

    const result = pushSecrets({ target: "github", keys: ["BAD"], projectPath: project, silent: true });

    expect(result.pushed).toEqual([]);
    expect(result.failed).toEqual([{ key: "BAD", error: "not logged in" }]);
  });

  it("dry run resolves keys but never invokes the platform CLI", () => {
    writeManifest({ K: {} });
    setSecret("K", "value-long", { scope: "project", projectPath: project, silent: true });

    const result = pushSecrets({ target: "github", projectPath: project, dryRun: true, silent: true });

    expect(result.pushed).toEqual(["K"]);
    expect(spawnSyncMock).not.toHaveBeenCalled();
  });

  it("errors up front when the platform CLI is absent", () => {
    setSecret("K", "value-long", { scope: "project", projectPath: project, silent: true });
    spawnSyncMock.mockReturnValue({ status: null, stdout: "", stderr: "", error: new Error("ENOENT") });

    expect(() =>
      pushSecrets({ target: "github", keys: ["K"], projectPath: project, silent: true }),
    ).toThrow(/gh.*not found/);
  });
});

/** Every non-probe spawn: [binary, argv, options]. */
function pushCalls(): [string, string[], { input?: string }][] {
  return spawnSyncMock.mock.calls.filter((c) => !c[1]?.includes("--version")) as never;
}

describe("pushSecrets — fly", () => {
  const VALUE = "fly-secret#with-hash";

  it("feeds KEY=VALUE to `flyctl secrets import` on stdin, triple-quoted, never argv", () => {
    setSecret("FLY_KEY", VALUE, { scope: "project", projectPath: project, silent: true });
    const result = pushSecrets({ target: "fly", keys: ["FLY_KEY"], projectPath: project, silent: true });

    expect(result.pushed).toEqual(["FLY_KEY"]);
    const [[bin, argv, options]] = pushCalls();
    expect(bin).toBe("flyctl");
    expect(argv).toEqual(["secrets", "import"]);
    expect(options.input).toBe(`FLY_KEY="""${VALUE}"""\n`);
    expect(JSON.stringify(argv)).not.toContain(VALUE);
  });

  it("passes --app when given", () => {
    setSecret("K", VALUE, { scope: "project", projectPath: project, silent: true });
    pushSecrets({ target: "fly", keys: ["K"], app: "my-app", projectPath: project, silent: true });
    const [[, argv]] = pushCalls();
    expect(argv).toEqual(["secrets", "import", "--app", "my-app"]);
  });

  it("dry run never invokes flyctl", () => {
    setSecret("K", VALUE, { scope: "project", projectPath: project, silent: true });
    const result = pushSecrets({ target: "fly", keys: ["K"], projectPath: project, dryRun: true, silent: true });
    expect(result.pushed).toEqual(["K"]);
    expect(spawnSyncMock).not.toHaveBeenCalled();
  });
});

describe("pushSecrets — railway", () => {
  const VALUE = "railway-secret-value";

  it("uses `railway variable set KEY --stdin` with the raw value on stdin", () => {
    setSecret("RW_KEY", VALUE, { scope: "project", projectPath: project, silent: true });
    const result = pushSecrets({ target: "railway", keys: ["RW_KEY"], projectPath: project, silent: true });

    expect(result.pushed).toEqual(["RW_KEY"]);
    const [[bin, argv, options]] = pushCalls();
    expect(bin).toBe("railway");
    expect(argv).toEqual(["variable", "set", "RW_KEY", "--stdin"]);
    expect(options.input).toBe(VALUE);
    expect(JSON.stringify(argv)).not.toContain(VALUE);
  });

  it("passes --service and --environment when given", () => {
    setSecret("K", VALUE, { scope: "project", projectPath: project, silent: true });
    pushSecrets({
      target: "railway", keys: ["K"], service: "api", railwayEnv: "staging",
      projectPath: project, silent: true,
    });
    const [[, argv]] = pushCalls();
    expect(argv).toEqual([
      "variable", "set", "K", "--stdin", "--service", "api", "--environment", "staging",
    ]);
  });

  it("dry run never invokes railway", () => {
    setSecret("K", VALUE, { scope: "project", projectPath: project, silent: true });
    const result = pushSecrets({ target: "railway", keys: ["K"], projectPath: project, dryRun: true, silent: true });
    expect(result.pushed).toEqual(["K"]);
    expect(spawnSyncMock).not.toHaveBeenCalled();
  });
});

describe("pushSecrets — netlify", () => {
  const VALUE = "netlify-secret#value";

  /** Mock that snapshots the temp file while the CLI "runs". */
  function captureImportFile(): { path?: string; content?: string; mode?: number } {
    const seen: { path?: string; content?: string; mode?: number } = {};
    spawnSyncMock.mockImplementation((_bin: string, args: string[]) => {
      if (args.includes("--version")) return { status: 0, stdout: "", stderr: "" };
      seen.path = args[1];
      seen.content = readFileSync(args[1], "utf8");
      seen.mode = statSync(args[1]).mode & 0o777;
      return { status: 0, stdout: "", stderr: "" };
    });
    return seen;
  }

  it("imports a 0600 dotenv temp file via `netlify env:import`, never the value in argv", () => {
    setSecret("NL_KEY", VALUE, { scope: "project", projectPath: project, silent: true });
    const seen = captureImportFile();

    const result = pushSecrets({ target: "netlify", keys: ["NL_KEY"], projectPath: project, silent: true });

    expect(result.pushed).toEqual(["NL_KEY"]);
    const [[bin, argv, options]] = pushCalls();
    expect(bin).toBe("netlify");
    expect(argv[0]).toBe("env:import");
    expect(argv[1]).toBe(seen.path);
    expect(argv).toHaveLength(2);
    expect(JSON.stringify(argv)).not.toContain(VALUE);
    expect(options.input).toBe("");

    expect(seen.path!.startsWith(tmpdir())).toBe(true);
    expect(seen.content).toBe(`NL_KEY='${VALUE}'\n`);
    // chmod is a no-op on Windows (mode reads back 0666) — same skip as the
    // canary registry test; the content/removal assertions still run there.
    if (process.platform !== "win32") expect(seen.mode).toBe(0o600);
    expect(existsSync(seen.path!)).toBe(false);
  });

  it("removes the temp file even when the CLI fails", () => {
    setSecret("K", VALUE, { scope: "project", projectPath: project, silent: true });
    let path = "";
    spawnSyncMock.mockImplementation((_bin: string, args: string[]) => {
      if (args.includes("--version")) return { status: 0, stdout: "", stderr: "" };
      path = args[1];
      return { status: 1, stdout: "", stderr: "not linked" };
    });

    const result = pushSecrets({ target: "netlify", keys: ["K"], projectPath: project, silent: true });

    expect(result.failed).toEqual([{ key: "K", error: "not linked" }]);
    expect(path).not.toBe("");
    expect(existsSync(path)).toBe(false);
  });

  it("double-quotes a value containing a single quote", () => {
    setSecret("K", "it's", { scope: "project", projectPath: project, silent: true });
    const seen = captureImportFile();
    pushSecrets({ target: "netlify", keys: ["K"], projectPath: project, silent: true });
    expect(seen.content).toBe(`K="it's"\n`);
  });

  it("passes --site when given", () => {
    setSecret("K", VALUE, { scope: "project", projectPath: project, silent: true });
    pushSecrets({ target: "netlify", keys: ["K"], site: "my-site", projectPath: project, silent: true });
    const [[, argv]] = pushCalls();
    expect(argv.slice(2)).toEqual(["--site", "my-site"]);
  });

  it("dry run never invokes netlify and writes no file", () => {
    setSecret("K", VALUE, { scope: "project", projectPath: project, silent: true });
    const result = pushSecrets({ target: "netlify", keys: ["K"], projectPath: project, dryRun: true, silent: true });
    expect(result.pushed).toEqual(["K"]);
    expect(spawnSyncMock).not.toHaveBeenCalled();
  });
});
