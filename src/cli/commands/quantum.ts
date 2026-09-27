import type { Command } from "commander";
import {
  getSecret,
  setSecret,
  hasSecret,
  listSecrets,
  entangleSecrets,
  disentangleSecrets,
  type KeyringOptions,
} from "../../core/keyring.js";
import {
  generateSecret,
  estimateEntropy,
  type NoiseFormat,
} from "../../core/noise.js";
import {
  tunnelCreate,
  tunnelRead,
  tunnelDestroy,
  tunnelList,
} from "../../core/tunnel.js";
import {
  teleportPack,
  teleportPackFor,
  teleportUnpackAuto,
  inspectTeleportBundle,
  generateTeleportIdentity,
  loadTeleportIdentity,
  parseRecipient,
  type TeleportPayload,
} from "../../core/teleport.js";
import { promptSecret, confirm } from "../../utils/prompt.js";
import { c, SYMBOLS } from "../../utils/colors.js";
import { emitJson } from "../helpers.js";
import { buildOpts } from "../options.js";

export function registerQuantumCommands(program: Command): void {
  program
    .command("generate")
    .alias("gen")
    .description("Generate a cryptographic secret (quantum noise)")
    .option(
      "-f, --format <format>",
      "Format: hex, base64, alphanumeric, uuid, api-key, token, password",
      "api-key",
    )
    .option(
      "-l, --length <n>",
      "Length (bytes or chars depending on format)",
      parseInt,
    )
    .option("--prefix <prefix>", "Prefix for api-key/token format")
    .option(
      "-s, --save <key>",
      "Save the generated secret to keyring with this key",
    )
    .option("-g, --global", "Save to global scope")
    .option("-p, --project", "Save to project scope")
    .option("--project-path <path>", "Explicit project path")
    .action((cmd) => {
      const secret = generateSecret({
        format: cmd.format as NoiseFormat,
        length: cmd.length,
        prefix: cmd.prefix,
      });

      const entropy = estimateEntropy(secret);

      if (cmd.save) {
        const opts = buildOpts(cmd);
        setSecret(cmd.save, secret, opts);
        console.log(
          `${SYMBOLS.sparkle} ${c.green("generated & saved")} ${c.bold(cmd.save)} ${c.dim(`(${cmd.format}, ${entropy} bits entropy)`)}`,
        );
      } else {
        process.stdout.write(secret);
        if (process.stdout.isTTY) {
          console.log(
            `\n${c.dim(`format: ${cmd.format} | entropy: ~${entropy} bits`)}`,
          );
        }
      }
    });

  program
    .command("entangle <sourceKey> <targetKey>")
    .description("Link two secrets — rotating one updates the other")
    .option("-g, --global", "Both in global scope")
    .option("--source-project <path>", "Source project path")
    .option("--target-project <path>", "Target project path")
    .action((sourceKey: string, targetKey: string, cmd) => {
      const sourceOpts: KeyringOptions = {
        scope: cmd.sourceProject ? "project" : "global",
        projectPath: cmd.sourceProject ?? process.cwd(),
        source: "cli",
      };
      const targetOpts: KeyringOptions = {
        scope: cmd.targetProject ? "project" : "global",
        projectPath: cmd.targetProject ?? process.cwd(),
        source: "cli",
      };

      entangleSecrets(sourceKey, sourceOpts, targetKey, targetOpts);
      console.log(
        `${SYMBOLS.link} ${c.cyan("entangled")} ${c.bold(sourceKey)} ${SYMBOLS.arrow} ${c.bold(targetKey)}`,
      );
    });

  program
    .command("disentangle <sourceKey> <targetKey>")
    .description("Unlink two entangled secrets")
    .option("-g, --global", "Both in global scope")
    .option("--source-project <path>", "Source project path")
    .option("--target-project <path>", "Target project path")
    .action((sourceKey: string, targetKey: string, cmd) => {
      const sourceOpts: KeyringOptions = {
        scope: cmd.sourceProject ? "project" : "global",
        projectPath: cmd.sourceProject ?? process.cwd(),
        source: "cli",
      };
      const targetOpts: KeyringOptions = {
        scope: cmd.targetProject ? "project" : "global",
        projectPath: cmd.targetProject ?? process.cwd(),
        source: "cli",
      };

      disentangleSecrets(sourceKey, sourceOpts, targetKey, targetOpts);
      console.log(
        `${SYMBOLS.link} ${c.yellow("disentangled")} ${c.bold(sourceKey)} ${SYMBOLS.arrow} ${c.bold(targetKey)}`,
      );
    });

  // ─── Tunneling Commands ───

  const tunnel = program
    .command("tunnel")
    .description("Ephemeral in-memory secrets (quantum tunneling)");

  tunnel
    .command("create <value>")
    .description("Create a tunneled secret (returns tunnel ID)")
    .option("--ttl <seconds>", "Auto-expire after N seconds", parseInt)
    .option("--max-reads <n>", "Self-destruct after N reads", parseInt)
    .action((value: string, cmd) => {
      const id = tunnelCreate(value, {
        ttlSeconds: cmd.ttl,
        maxReads: cmd.maxReads,
      });

      console.log(`${SYMBOLS.ghost} ${c.magenta("tunneled")} ${c.bold(id)}`);

      const extras: string[] = [];
      if (cmd.ttl) extras.push(`ttl=${cmd.ttl}s`);
      if (cmd.maxReads) extras.push(`max-reads=${cmd.maxReads}`);
      if (extras.length) console.log(c.dim(`  ${extras.join(" | ")}`));
    });

  tunnel
    .command("read <id>")
    .description("Read a tunneled secret (may self-destruct)")
    .action((id: string) => {
      const value = tunnelRead(id);
      if (value === null) {
        console.error(
          c.red(`${SYMBOLS.cross} Tunnel "${id}" not found or expired`),
        );
        process.exit(1);
      }
      process.stdout.write(value);
    });

  tunnel
    .command("destroy <id>")
    .description("Destroy a tunneled secret immediately")
    .action((id: string) => {
      const destroyed = tunnelDestroy(id);
      if (destroyed) {
        console.log(`${SYMBOLS.check} ${c.green("destroyed")} ${id}`);
      } else {
        console.error(c.red(`${SYMBOLS.cross} Tunnel "${id}" not found`));
        process.exit(1);
      }
    });

  tunnel
    .command("list")
    .alias("ls")
    .description("List active tunnels")
    .option("--json", "Output as JSON")
    .action((cmd) => {
      const tunnels = tunnelList();
      if (emitJson(program, cmd, { tunnels })) return;
      if (tunnels.length === 0) {
        console.log(c.dim("No active tunnels"));
        return;
      }

      console.log(
        c.bold(`\n  ${SYMBOLS.ghost} Active tunnels (${tunnels.length})\n`),
      );
      for (const t of tunnels) {
        const parts = [c.bold(t.id)];
        parts.push(c.dim(`reads: ${t.accessCount}`));
        if (t.maxReads) parts.push(c.dim(`max: ${t.maxReads}`));
        if (t.expiresAt) {
          const remaining = Math.max(
            0,
            Math.floor((t.expiresAt - Date.now()) / 1000),
          );
          parts.push(c.dim(`expires: ${remaining}s`));
        }
        console.log(`  ${SYMBOLS.ghost} ${parts.join("  ")}`);
      }
      console.log();
    });

  // ─── Teleportation Commands ───

  const tp = program
    .command("teleport")
    .alias("tp")
    .description("Encrypted secret sharing (quantum teleportation)");

  tp.command("keygen")
    .description(
      "Create your teleport identity (X25519 keypair, private key in the OS keyring)",
    )
    .option("--force", "Replace an existing identity")
    .action((cmd) => {
      let identity: ReturnType<typeof generateTeleportIdentity>;
      try {
        identity = generateTeleportIdentity({ force: Boolean(cmd.force) });
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        console.error(c.red(`${SYMBOLS.cross} ${msg}`));
        process.exit(1);
      }
      // Always newline-terminated: `$(qring teleport identity)` strips it,
      // while `>> recipients.txt` needs it.
      console.log(identity.recipient);
      if (process.stdout.isTTY) {
        console.log(
          `${SYMBOLS.key} ${c.green("identity created")} ${c.dim(`(id ${identity.id})`)} — share the line above with anyone who should \`teleport pack --to\` you`,
        );
      }
    });

  tp.command("identity")
    .description("Print your public teleport recipient string")
    .action(() => {
      let identity: ReturnType<typeof loadTeleportIdentity>;
      try {
        identity = loadTeleportIdentity();
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        console.error(c.red(`${SYMBOLS.cross} ${msg}`));
        process.exit(1);
      }
      if (!identity) {
        console.error(
          c.red(
            `${SYMBOLS.cross} No teleport identity found — run ${c.bold("qring teleport keygen")} first`,
          ),
        );
        process.exit(1);
      }
      console.log(identity.recipient);
      if (process.stdout.isTTY) {
        console.log(c.dim(`recipient id: ${identity.id}`));
      }
    });

  tp.command("pack")
    .description("Pack secrets into an encrypted bundle")
    .option("-k, --keys <keys>", "Comma-separated key names to pack")
    .option(
      "--to <recipient...>",
      "Recipient(s) from `qring teleport identity` (repeatable or comma-separated); skips the passphrase",
    )
    .option("-g, --global", "Pack global scope")
    .option("-p, --project", "Pack project scope")
    .option("--project-path <path>", "Explicit project path")
    .action(async (cmd) => {
      const opts = buildOpts(cmd);

      // `--to a --to b` and `--to a,b` both work; validate before touching
      // any secret so a typo in a recipient never reads the keyring.
      const recipients: string[] = ((cmd.to as string[] | undefined) ?? [])
        .flatMap((r) => r.split(","))
        .map((r) => r.trim())
        .filter((r) => r.length > 0);
      for (const r of recipients) {
        try {
          parseRecipient(r);
        } catch (err) {
          const msg = err instanceof Error ? err.message : String(err);
          console.error(c.red(`${SYMBOLS.cross} Bad recipient "${r}": ${msg}`));
          process.exit(1);
        }
      }

      let passphrase: string | undefined;
      if (recipients.length === 0) {
        passphrase = await promptSecret(
          `${SYMBOLS.lock} Enter passphrase for encryption: `,
        );
        if (!passphrase) {
          console.error(c.red("Passphrase required (or pass --to <recipient>)"));
          process.exit(1);
        }
      }

      const entries = listSecrets(opts);
      let keys: string[] | undefined;
      if (cmd.keys) {
        keys = cmd.keys.split(",").map((k: string) => k.trim());
      }

      const secrets: { key: string; value: string; scope?: string }[] = [];
      for (const entry of entries) {
        if (keys && !keys.includes(entry.key)) continue;
        const value = getSecret(entry.key, { ...opts, scope: entry.scope });
        if (value !== null) {
          secrets.push({ key: entry.key, value, scope: entry.scope });
        }
      }

      if (secrets.length === 0) {
        console.error(c.red("No secrets to pack"));
        process.exit(1);
      }

      const bundle =
        recipients.length > 0
          ? teleportPackFor(secrets, recipients)
          : teleportPack(secrets, passphrase as string);
      process.stdout.write(bundle);
      if (process.stdout.isTTY) {
        const to =
          recipients.length > 0
            ? c.dim(` for ${recipients.length} recipient(s)`)
            : "";
        console.log(
          `\n${SYMBOLS.package} ${c.green("packed")} ${secrets.length} secret(s)${to}`,
        );
      }
    });

  tp.command("unpack [bundle]")
    .description("Unpack and import secrets from an encrypted bundle")
    .option("-g, --global", "Import to global scope")
    .option("-p, --project", "Import to project scope")
    .option("--project-path <path>", "Explicit project path")
    .option("--dry-run", "Show what would be imported without saving")
    .option("-y, --yes", "Overwrite existing secrets without asking")
    .action(async (bundle: string | undefined, cmd) => {
      if (!bundle) {
        const chunks: Buffer[] = [];
        for await (const chunk of process.stdin) {
          chunks.push(chunk);
        }
        bundle = Buffer.concat(chunks).toString("utf8").trim();
      }

      // Peek at the format first: v1 needs a passphrase prompt, v2 needs our
      // keyring identity and must never prompt.
      let info: ReturnType<typeof inspectTeleportBundle>;
      try {
        info = inspectTeleportBundle(bundle);
      } catch {
        console.error(
          c.red(`${SYMBOLS.cross} Failed to unpack: corrupted bundle`),
        );
        process.exit(1);
      }

      let passphrase: string | undefined;
      let identity: ReturnType<typeof loadTeleportIdentity> = null;
      if (info.v === 1) {
        passphrase = await promptSecret(
          `${SYMBOLS.lock} Enter passphrase for decryption: `,
        );
      } else {
        try {
          identity = loadTeleportIdentity();
        } catch (err) {
          const msg = err instanceof Error ? err.message : String(err);
          console.error(c.red(`${SYMBOLS.cross} ${msg}`));
          process.exit(1);
        }
        if (cmd.dryRun) {
          const mine = identity ? info.recipients.includes(identity.id) : false;
          console.log(
            `\n${SYMBOLS.package} ${c.bold("Recipient bundle")} addressed to ${info.recipients.length} recipient id(s):`,
          );
          for (const id of info.recipients) {
            const marker =
              identity && id === identity.id ? c.green(" (you)") : "";
            console.log(`  ${SYMBOLS.key} ${id}${marker}`);
          }
          if (!identity) {
            console.log(
              c.dim(
                `  no local identity — run ${c.bold("qring teleport keygen")} to create one`,
              ),
            );
          } else if (!mine) {
            console.log(
              c.dim(`  your id ${identity.id} is not among them; unpack will fail`),
            );
          }
          console.log();
        }
        if (!identity) {
          console.error(
            c.red(
              `${SYMBOLS.cross} This bundle is addressed to recipient keys and you have no teleport identity — run ${c.bold("qring teleport keygen")} first`,
            ),
          );
          process.exit(1);
        }
      }

      // Only the decrypt itself maps to "wrong passphrase" — errors from the
      // confirm/import steps below must not be swallowed by this catch.
      let payload: TeleportPayload;
      try {
        payload = teleportUnpackAuto(bundle, {
          passphrase,
          identity: identity?.privateKey,
        });
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        const reason = msg.startsWith("ERR_TELEPORT_NOT_A_RECIPIENT")
          ? `this bundle is not addressed to your identity (${identity?.id})`
          : info.v === 1
            ? "wrong passphrase or corrupted bundle"
            : "corrupted bundle or mismatched identity";
        console.error(c.red(`${SYMBOLS.cross} Failed to unpack: ${reason}`));
        process.exit(1);
      }

      if (cmd.dryRun) {
        console.log(
          `\n${SYMBOLS.package} ${c.bold("Would import")} (${payload.secrets.length} secrets):\n`,
        );
        for (const s of payload.secrets) {
          console.log(
            `  ${SYMBOLS.key} ${c.bold(s.key)} ${c.dim(`[${s.scope ?? "global"}]`)}`,
          );
        }
        return;
      }

      const opts = buildOpts(cmd);

      const existing = payload.secrets
        .map((s) => s.key)
        .filter((k) => hasSecret(k, opts));
      if (
        existing.length > 0 &&
        !(await confirm(
          `${existing.length} existing secret(s) will be overwritten: ${existing.join(", ")}. Continue?`,
          { assumeYes: cmd.yes },
        ))
      ) {
        console.error(c.dim("Aborted."));
        process.exitCode = 1;
        return;
      }

      for (const s of payload.secrets) {
        setSecret(s.key, s.value, opts);
      }

      console.log(
        `${SYMBOLS.check} ${c.green("imported")} ${payload.secrets.length} secret(s) from teleport bundle`,
      );
    });
}
