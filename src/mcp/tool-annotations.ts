import type { ToolAnnotations } from "@modelcontextprotocol/sdk/types.js";

/**
 * MCP tool annotations for every q-ring tool — the structured behavior hints
 * (MCP spec: readOnlyHint / destructiveHint / idempotentHint / openWorldHint)
 * that let hosts decide what to auto-approve and what to confirm.
 *
 * Every hint is set explicitly; nothing relies on the spec defaults. The
 * prose descriptions remain the authority on *why* — keep both in sync when a
 * tool's behavior changes. `src/__tests__/mcp/server.test.ts` asserts that
 * every registered tool has an entry here and that no entry is orphaned.
 *
 * Conventions:
 * - readOnlyHint: the tool never changes the keyring, files, hooks, memory,
 *   or running processes. Appending to the audit log does not count.
 * - destructiveHint: a non-read-only tool that overwrites, deletes, replaces
 *   a credential, edits source files, or runs arbitrary commands.
 * - idempotentHint: repeating the call with the same arguments has no further
 *   effect.
 * - openWorldHint: the tool talks to external services or runs commands that
 *   can — validation, rotation, exec, agent auto-rotate.
 */
const hints = (
  readOnlyHint: boolean,
  destructiveHint: boolean,
  idempotentHint: boolean,
  openWorldHint: boolean,
): ToolAnnotations => ({ readOnlyHint, destructiveHint, idempotentHint, openWorldHint });

const READ = hints(true, false, true, false);
const READ_OPEN = hints(true, false, true, true);

export const TOOL_ANNOTATIONS: Record<string, ToolAnnotations> = {
  // secrets
  get_secret: READ,
  list_secrets: READ,
  set_secret: hints(false, true, true, false),
  delete_secret: hints(false, true, true, false),
  has_secret: READ,
  export_secrets: READ,
  import_dotenv: hints(false, false, true, false), // existing keys are skipped, not overwritten
  inspect_secret: READ,
  generate_secret: hints(false, true, false, false), // saveAs overwrites; fresh value every call
  entangle_secrets: hints(false, false, true, false),
  disentangle_secrets: hints(false, false, true, false),
  // project
  check_project: READ,
  env_generate: READ, // renders text, never writes files
  detect_environment: READ,
  get_project_context: READ,
  // tunnels (memory-only)
  tunnel_create: hints(false, false, false, false),
  tunnel_read: hints(false, true, false, false), // may self-destruct on read
  tunnel_list: READ,
  tunnel_destroy: hints(false, true, true, false),
  // teleport
  teleport_pack: READ,
  teleport_unpack: hints(false, true, true, false), // imports may overwrite keys
  // audit / health
  audit_log: READ,
  detect_anomalies: READ,
  health_check: READ,
  verify_audit_chain: READ,
  export_audit: READ,
  // validation / rotation (network)
  validate_secret: READ_OPEN,
  list_providers: READ,
  rotate_secret: hints(false, true, false, true), // replaces the credential upstream and locally
  ci_validate_secrets: READ_OPEN,
  // hooks
  register_hook: hints(false, false, false, false),
  list_hooks: READ,
  remove_hook: hints(false, true, true, false),
  // execution / scanning
  exec_with_secrets: hints(false, true, false, true), // arbitrary command
  scan_codebase_for_secrets: READ,
  lint_files: hints(false, true, true, false), // fix:true rewrites source files
  analyze_secrets: READ,
  status_dashboard: hints(false, false, false, false), // starts a local server, new token per launch
  agent_scan: hints(false, true, false, true), // autoRotate replaces expired credentials
  // agent memory
  agent_remember: hints(false, true, true, false),
  agent_recall: READ,
  agent_forget: hints(false, true, true, false),
  // policy
  check_policy: READ,
  get_policy_summary: READ,
};

/** Look up a tool's annotations; a missing entry is a programming error. */
export function toolAnnotations(name: string): ToolAnnotations {
  const a = TOOL_ANNOTATIONS[name];
  if (!a) throw new Error(`q-ring: no tool annotations defined for "${name}"`);
  return a;
}
