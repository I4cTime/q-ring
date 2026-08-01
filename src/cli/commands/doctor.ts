import type { Command } from "commander";
import { existsSync, readFileSync, writeFileSync, rmSync } from "node:fs";
import { join, delimiter } from "node:path";
import { homedir } from "node:os";
import { verifyAuditChain } from "../../core/observer.js";
import { getPolicySummary } from "../../core/policy.js";
import { countLegacyApprovals } from "../../core/approval.js";
import { c, SYMBOLS } from "../../utils/colors.js";
import { emitJson } from "../helpers.js";
import { PACKAGE_VERSION } from "../../version.js";

type CheckStatus = "ok" | "warn" | "fail";

interface CheckResult {
  name: string;
  status: CheckStatus;
  detail: string;
}

function auditDir(): string {
  return process.env.QRING_AUDIT_DIR ?? join(homedir(), ".config", "q-ring");
}

function checkNode(): CheckResult {
  const major = Number(process.versions.node.split(".")[0]);
  return {
    name: "node runtime",
    status: major >= 18 ? "ok" : "fail",
    detail: `v${process.versions.node}${major >= 18 ? "" : " — q-ring requires Node >= 18"}`,
  };
}

async function checkKeyringBackend(): Promise<CheckResult> {
  // Probe the OS keychain end-to-end with a dedicated service name so real
  // secrets and the audit log are never touched. This is the check that
  // fails on headless Linux without a Secret Service (gnome-keyring, etc.).
  try {
    const { Entry } = await import("@napi-rs/keyring");
    const probe = new Entry("q-ring-doctor-probe", "PROBE");
    probe.setPassword("ok");
    const read = probe.getPassword();
    probe.deletePassword();
    if (read !== "ok") {
      return {
        name: "keyring backend",
        status: "fail",
        detail: "probe round-trip returned unexpected value",
      };
    }
    return {
      name: "keyring backend",
      status: "ok",
      detail: "write/read/delete round-trip succeeded",
    };
  } catch (err) {
    return {
      name: "keyring backend",
      status: "fail",
      detail: `${err instanceof Error ? err.message : String(err)} — on headless Linux, install and unlock a Secret Service (e.g. gnome-keyring)`,
    };
  }
}

function checkAuditLog(): CheckResult {
  const dir = auditDir();
  try {
    const probeFile = join(dir, ".doctor-probe");
    writeFileSync(probeFile, "ok");
    rmSync(probeFile);
  } catch (err) {
    return {
      name: "audit log",
      status: "fail",
      detail: `${dir} not writable: ${err instanceof Error ? err.message : String(err)}`,
    };
  }

  const chain = verifyAuditChain();
  if (chain.totalEvents === 0) {
    return { name: "audit log", status: "ok", detail: `${dir} writable, no events yet` };
  }
  if (!chain.intact) {
    return {
      name: "audit log",
      status: "fail",
      detail: `hash chain BROKEN at event #${chain.brokenAt} (${chain.validEvents}/${chain.totalEvents} valid) — see qring audit:verify`,
    };
  }
  return {
    name: "audit log",
    status: "ok",
    detail: `${dir} writable, chain intact (${chain.totalEvents} events)`,
  };
}

function checkManifest(projectPath: string): CheckResult {
  const manifestPath = join(projectPath, ".q-ring.json");
  if (!existsSync(manifestPath)) {
    return {
      name: "project manifest",
      status: "warn",
      detail: `no .q-ring.json in ${projectPath} (optional — run qring wizard or /qring-setup-project)`,
    };
  }
  try {
    const config = JSON.parse(readFileSync(manifestPath, "utf8"));
    const declared = Object.keys(config.secrets ?? {}).length;
    const hasPolicy = !!config.policy;
    return {
      name: "project manifest",
      status: "ok",
      detail: `${declared} secret(s) declared${hasPolicy ? ", policy present" : ""}`,
    };
  } catch (err) {
    return {
      name: "project manifest",
      status: "fail",
      detail: `.q-ring.json is not valid JSON: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
}

function checkPolicy(): CheckResult {
  const summary = getPolicySummary();
  const active = [
    summary.hasMcpPolicy && "mcp",
    summary.hasExecPolicy && "exec",
    summary.hasSecretPolicy && "secrets",
  ].filter(Boolean);
  return {
    name: "governance policy",
    status: "ok",
    detail: active.length
      ? `active: ${active.join(", ")}`
      : "none configured (add a \"policy\" section to .q-ring.json to enable)",
  };
}

function checkLegacyApprovals(): CheckResult {
  const n = countLegacyApprovals();
  if (n === 0) {
    return {
      name: "approval bindings",
      status: "ok",
      detail: "no legacy approvals; all bound to a project/team/org identity",
    };
  }
  return {
    name: "approval bindings",
    status: "warn",
    detail: `${n} pre-v0.14 approval(s) have no project binding and will NOT grant access — re-run \`qring approve\` for each`,
  };
}

function checkMcpBinary(): CheckResult {
  const exts = process.platform === "win32" ? [".cmd", ".exe", ".bat", ""] : [""];
  for (const dir of (process.env.PATH ?? "").split(delimiter)) {
    if (!dir) continue;
    for (const ext of exts) {
      if (existsSync(join(dir, `qring-mcp${ext}`))) {
        return {
          name: "qring-mcp binary",
          status: "ok",
          detail: `found at ${join(dir, `qring-mcp${ext}`)}`,
        };
      }
    }
  }
  return {
    name: "qring-mcp binary",
    status: "warn",
    detail:
      "not on PATH — editor MCP configs that spawn `qring-mcp` will fail; install globally (pnpm add -g @i4ctime/q-ring)",
  };
}

export function registerDoctorCommand(program: Command): void {
  program
    .command("doctor")
    .description("Diagnose the q-ring installation (keyring, audit, manifest, MCP)")
    .option("--project-path <path>", "Project path (defaults to cwd)")
    .option("--json", "Output as JSON")
    .action(async (cmd) => {
      const projectPath = cmd.projectPath ?? process.cwd();

      const checks: CheckResult[] = [
        checkNode(),
        await checkKeyringBackend(),
        checkAuditLog(),
        checkManifest(projectPath),
        checkPolicy(),
        checkLegacyApprovals(),
        checkMcpBinary(),
      ];

      const failed = checks.filter((r) => r.status === "fail").length;
      const warned = checks.filter((r) => r.status === "warn").length;

      if (
        emitJson(program, cmd, {
          version: PACKAGE_VERSION,
          projectPath,
          checks,
          healthy: failed === 0,
        })
      ) {
        if (failed > 0) process.exitCode = 1;
        return;
      }

      console.log(c.bold(`\n  ${SYMBOLS.shield} qring doctor — v${PACKAGE_VERSION}\n`));

      for (const r of checks) {
        const icon =
          r.status === "ok"
            ? c.green(SYMBOLS.check)
            : r.status === "warn"
              ? c.yellow(SYMBOLS.warning)
              : c.red(SYMBOLS.cross);
        console.log(`  ${icon} ${c.bold(r.name.padEnd(18))} ${c.dim(r.detail)}`);
      }

      console.log();
      if (failed > 0) {
        console.log(`  ${c.red(`${failed} check(s) failed`)}${warned ? c.dim(`, ${warned} warning(s)`) : ""}\n`);
        process.exitCode = 1;
      } else if (warned > 0) {
        console.log(`  ${c.yellow(`${warned} warning(s)`)} ${c.dim("— everything critical is healthy")}\n`);
      } else {
        console.log(`  ${c.green("All checks passed.")}\n`);
      }
    });
}
