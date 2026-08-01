import type { Command } from "commander";
import {
  grantApproval,
  revokeApproval,
  listApprovals,
} from "../../core/approval.js";
import { serviceForScope } from "../../core/scope.js";
import { getPolicySummary } from "../../core/policy.js";
import { c, SYMBOLS } from "../../utils/colors.js";
import { wantsJsonOutput, emitJson } from "../helpers.js";
import { buildOpts } from "../options.js";

export function registerSecurityCommands(program: Command): void {
  program
    .command("approve <key>")
    .description(
      "Grant a scoped, reasoned, HMAC-verified approval token for MCP secret access",
    )
    .option("-g, --global", "Global scope")
    .option("-p, --project", "Project scope")
    .option("--project-path <path>", "Explicit project path")
    .option("--for <seconds>", "Duration of approval in seconds", parseInt, 3600)
    .option("--reason <text>", "Reason for granting approval")
    .option("--revoke", "Revoke an existing approval")
    .option("--list", "List all approvals")
    .action((key: string, cmd) => {
      const opts = buildOpts(cmd);
      const scope = opts.scope ?? "global";
      // Bind the approval to the concrete project/team/org identity, not just
      // the coarse scope label (A5) — the label "project" is identical across
      // every project, so an approval must be keyed on the resolved service.
      const service = serviceForScope(scope, opts);

      if (cmd.list) {
        const approvals = listApprovals();
        if (approvals.length === 0) {
          console.log(c.dim("  No active approvals"));
          return;
        }
        for (const a of approvals) {
          const status = a.tampered
            ? c.red("TAMPERED")
            : a.valid
              ? c.green("active")
              : c.dim("expired");
          const ttl = Math.max(
            0,
            Math.round(
              (new Date(a.expiresAt).getTime() - Date.now()) / 1000,
            ),
          );
          console.log(
            `  ${status} ${c.bold(a.key)} [${a.scope}] reason=${c.dim(a.reason)} ttl=${ttl}s granted-by=${a.grantedBy}`,
          );
        }
        return;
      }

      if (cmd.revoke) {
        const revoked = revokeApproval(key, scope, service);
        if (revoked) {
          console.log(
            `${SYMBOLS.check} ${c.yellow("revoked")} approval for ${c.bold(key)}`,
          );
        } else {
          console.log(c.dim(`  No active approval found for ${key}`));
        }
        return;
      }

      const entry = grantApproval(key, scope, service, cmd.for, {
        reason: cmd.reason ?? "manual approval",
      });
      console.log(
        `${SYMBOLS.check} ${c.green("approved")} ${c.bold(key)} for ${cmd.for}s`,
      );
      console.log(
        c.dim(
          `  id=${entry.id} reason="${entry.reason}" expires=${entry.expiresAt}`,
        ),
      );
    });

  program
    .command("approvals")
    .description("List all approval tokens with verification status")
    .option("--json", "Output as JSON")
    .action((cmd) => {
      const approvals = listApprovals();
      if (emitJson(program, cmd, { approvals })) return;
      if (approvals.length === 0) {
        console.log(c.dim("  No approvals found"));
        return;
      }

      console.log(c.bold(`\n${SYMBOLS.lock} Approval Tokens\n`));
      for (const a of approvals) {
        const status = a.tampered
          ? c.red(`${SYMBOLS.cross} TAMPERED`)
          : a.valid
            ? c.green(`${SYMBOLS.check} active`)
            : c.dim(`${SYMBOLS.warning} expired`);
        const ttl = Math.max(
          0,
          Math.round((new Date(a.expiresAt).getTime() - Date.now()) / 1000),
        );
        console.log(`  ${status} ${c.bold(a.key)} [${a.scope}]`);
        console.log(
          c.dim(`    id=${a.id} reason="${a.reason}" ttl=${ttl}s by=${a.grantedBy}`),
        );
        if (a.workspace) console.log(c.dim(`    workspace=${a.workspace}`));
      }
      console.log();
    });

  program
    .command("policy")
    .description("Show project governance policy summary")
    .option("--json", "Output as JSON")
    .action((cmd) => {
      const summary = getPolicySummary();
      if (wantsJsonOutput(program, cmd)) {
        console.log(JSON.stringify(summary, null, 2));
        return;
      }

      console.log(c.bold("\n⚖  Governance Policy\n"));

      if (
        !summary.hasMcpPolicy &&
        !summary.hasExecPolicy &&
        !summary.hasSecretPolicy
      ) {
        console.log(c.dim("  No policy configured in .q-ring.json"));
        console.log(
          c.dim('  Add a "policy" section to enable governance controls.\n'),
        );
        return;
      }

      if (summary.hasMcpPolicy) {
        console.log(c.cyan("  MCP Policy:"));
        const m = summary.details.mcp!;
        if (m.allowTools)
          console.log(c.green(`    Allow tools: ${m.allowTools.join(", ")}`));
        if (m.denyTools)
          console.log(c.red(`    Deny tools:  ${m.denyTools.join(", ")}`));
        if (m.readableKeys)
          console.log(
            c.green(`    Readable keys: ${m.readableKeys.join(", ")}`),
          );
        if (m.deniedKeys)
          console.log(c.red(`    Denied keys:   ${m.deniedKeys.join(", ")}`));
        if (m.deniedTags)
          console.log(c.red(`    Denied tags:   ${m.deniedTags.join(", ")}`));
      }

      if (summary.hasExecPolicy) {
        console.log(c.cyan("  Exec Policy:"));
        const e = summary.details.exec!;
        if (e.allowCommands)
          console.log(
            c.green(`    Allow commands:    ${e.allowCommands.join(", ")}`),
          );
        if (e.denyCommands)
          console.log(
            c.red(`    Deny commands:     ${e.denyCommands.join(", ")}`),
          );
        if (e.maxRuntimeSeconds)
          console.log(`    Max runtime:       ${e.maxRuntimeSeconds}s`);
        if (e.allowNetwork !== undefined)
          console.log(`    Allow network:     ${e.allowNetwork}`);
      }

      if (summary.hasSecretPolicy) {
        console.log(c.cyan("  Secret Lifecycle Policy:"));
        const s = summary.details.secrets!;
        if (s.requireApprovalForTags)
          console.log(
            `    Require approval for tags: ${s.requireApprovalForTags.join(", ")}`,
          );
        if (s.maxTtlSeconds) console.log(`    Max TTL: ${s.maxTtlSeconds}s`);
      }

      console.log();
    });
}
