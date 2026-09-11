/**
 * MCP Airlock: `qring mcp wrap -- <server command>` / `qring mcp wrap --url`.
 *
 * Runs a third-party MCP server (a child process, or a remote Streamable
 * HTTP endpoint) and re-exposes it over stdio, sitting between the agent
 * host and the wrapped server:
 *
 *   agent host ── stdio ── [q-ring airlock] ── stdio | http ── wrapped server
 *
 * What the airlock adds:
 *
 * - Environment stripping: a spawned server gets the SDK's minimal safe
 *   environment, NOT the parent env — it can't read API keys out of
 *   `process.env` unless `--inherit-env` is passed. Hygiene, not a sandbox:
 *   the child still runs unconfined as the operator's user.
 * - A tamper-evident audit trail: every tool call, resource read, and prompt
 *   fetch crossing the airlock lands in the audit chain as a "wrap" action,
 *   grouped by a per-session correlation id and stamped with the connecting
 *   client's identity label. Tool ARGUMENTS and prompt arguments are
 *   deliberately not logged — they may contain secrets.
 * - Wrap policy (`.q-ring.json` → `policy.wrap`): per-tool allow/deny globs,
 *   tools that need a live `qring mcp approve` grant, and sliding-window rate
 *   limits. Denied tools are hidden from tools/list and refused on call.
 * - Result redaction: known secret values are scrubbed from tool results,
 *   resource contents, and prompt messages before they reach the transcript
 *   (see wrap-redact.ts). Policy `wrap.redactResults: false` or
 *   `--no-redact` turns it off.
 *
 * The proxy aims to be transparent to both sides: tools, resources, and
 * prompts forward verbatim (pagination, list_changed / updated notifications,
 * subscriptions included), progress notifications are relayed under the
 * host's own progress token, downstream protocol errors stay JSON-RPC
 * errors, and tool-execution failures surface as isError results. stdout is
 * the protocol channel — all diagnostics go to stderr.
 */

import { randomUUID } from "node:crypto";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
  ToolListChangedNotificationSchema,
  ListResourcesRequestSchema,
  ListResourceTemplatesRequestSchema,
  ReadResourceRequestSchema,
  SubscribeRequestSchema,
  UnsubscribeRequestSchema,
  ResourceListChangedNotificationSchema,
  ResourceUpdatedNotificationSchema,
  ListPromptsRequestSchema,
  GetPromptRequestSchema,
  PromptListChangedNotificationSchema,
  McpError,
  type CallToolResult,
  type ServerCapabilities,
} from "@modelcontextprotocol/sdk/types.js";
import { PACKAGE_VERSION } from "../version.js";
import { logAudit, setAuditAgentLabel } from "./observer.js";
import {
  checkWrapToolPolicy,
  wrapToolRequiresApproval,
  getWrapRateLimit,
  wrapRedactsResults,
  setPolicyRoot,
  type WrapRateLimit,
} from "./policy.js";
import { hasApproval } from "./approval.js";
import { getSecret } from "./keyring.js";
import { hashProjectPath } from "../utils/hash.js";
import { createRedactor, NOOP_REDACTOR, type Redactor } from "./wrap-redact.js";

/**
 * Ceiling on a single downstream tool call. Deliberately generous: the HOST
 * owns call deadlines (its cancellation propagates through the airlock), and
 * `resetTimeoutOnProgress` keeps actively-reporting tools alive — this only
 * reaps calls that are silent for the whole window. Override with
 * QRING_WRAP_TIMEOUT_MS.
 */
const DEFAULT_DOWNSTREAM_TIMEOUT_MS = 10 * 60 * 1000;

function downstreamTimeoutMs(): number {
  const raw = Number(process.env.QRING_WRAP_TIMEOUT_MS);
  return Number.isFinite(raw) && raw > 0 ? raw : DEFAULT_DOWNSTREAM_TIMEOUT_MS;
}

/** Approval scope + service used for `qring mcp approve <tool>` grants. */
export const WRAP_APPROVAL_SCOPE = "wrap";
export function wrapApprovalService(projectPath: string): string {
  return `q-ring:wrap:${hashProjectPath(projectPath)}`;
}

export interface WrapOptions {
  /** Server command to spawn (stdio downstream). Mutually exclusive with url. */
  command?: string;
  args?: string[];
  /** Remote Streamable HTTP MCP endpoint (http downstream). */
  url?: string;
  /** Extra request headers for an http downstream, as "Name: value". */
  headers?: string[];
  /** q-ring key whose value is sent as `Authorization: Bearer …` (http). */
  authSecret?: string;
  /** Pass the full parent environment to the wrapped server (default: SDK safe env) */
  inheritEnv?: boolean;
  /** Label used in audit events (default: the wrapped command line / url) */
  label?: string;
  /** Scrub known secret values from results (default: policy, else on) */
  redact?: boolean;
  /** Project whose `.q-ring.json` policy governs the session (default: cwd) */
  projectPath?: string;
}

export interface WrapSession {
  label: string;
  correlationId: string;
}

export interface AirlockOptions {
  /** Project used for policy + approval resolution (default: cwd) */
  projectPath?: string;
  /** Result redactor (default: none — runWrap wires the real one) */
  redactor?: Redactor;
}

/** Sliding-window per-tool call counter. */
class RateLimiter {
  private readonly calls = new Map<string, number[]>();

  /** Record a call; returns false when the window is already full. */
  take(tool: string, limit: WrapRateLimit, now = Date.now()): boolean {
    const windowStart = now - limit.perSeconds * 1000;
    const recent = (this.calls.get(tool) ?? []).filter((t) => t > windowStart);
    if (recent.length >= limit.maxCalls) {
      this.calls.set(tool, recent);
      return false;
    }
    recent.push(now);
    this.calls.set(tool, recent);
    return true;
  }
}

function truncate(s: string, max = 200): string {
  return s.length > max ? `${s.slice(0, max)}…` : s;
}

/**
 * Build the airlock proxy server around an already-connected downstream
 * client. Exported separately so tests can drive it over in-memory
 * transports without spawning processes.
 */
export function createAirlockServer(
  downstream: Client,
  session: WrapSession,
  options: AirlockOptions = {},
): Server {
  const projectPath = options.projectPath ?? process.cwd();
  const redactor = options.redactor ?? NOOP_REDACTOR;
  const approvalService = wrapApprovalService(projectPath);
  const limiter = new RateLimiter();

  const downstreamInfo = downstream.getServerVersion();
  const dsCaps = downstream.getServerCapabilities() ?? {};
  const name = downstreamInfo ? `${downstreamInfo.name} (q-ring airlock)` : "q-ring-airlock";

  // Advertise exactly what the wrapped server can do — a host that sees a
  // resources capability and gets "method not found" would mark us broken.
  const capabilities: ServerCapabilities = {};
  if (dsCaps.tools) capabilities.tools = { listChanged: true };
  if (dsCaps.resources) {
    capabilities.resources = { listChanged: true, subscribe: !!dsCaps.resources.subscribe };
  }
  if (dsCaps.prompts) capabilities.prompts = { listChanged: true };

  const proxy = new Server(
    { name, version: PACKAGE_VERSION },
    {
      capabilities,
      // Servers ship usage guidance in `instructions`; hosts inject it into
      // the system prompt. Losing it would degrade the wrapped server.
      instructions: downstream.getInstructions(),
    },
  );

  // Feature synergy with per-agent identity: the agent host's clientInfo
  // from OUR initialize handshake labels every audited call. Spoofable —
  // audit metadata only, never authorization.
  proxy.oninitialized = () => {
    const info = proxy.getClientVersion();
    if (info) setAuditAgentLabel(`${info.name}@${info.version}`);
  };

  const audit = (detail: string, action: "wrap" | "policy_deny" = "wrap") =>
    logAudit({ action, source: "mcp", detail, correlationId: session.correlationId });

  const denied = (toolName: string, reason: string): CallToolResult => {
    audit(`airlock blocked "${toolName}" → ${session.label}: ${reason}`, "policy_deny");
    return {
      content: [{ type: "text", text: `airlock: policy denied: ${reason}` }],
      isError: true,
    };
  };

  /**
   * Wrap-policy gate for one tool call. Any policy load failure (an
   * unparseable `.q-ring.json`) denies — the airlock fails closed like the
   * rest of the policy engine.
   */
  const gate = (toolName: string): CallToolResult | null => {
    try {
      const decision = checkWrapToolPolicy(toolName, projectPath);
      if (!decision.allowed) return denied(toolName, decision.reason ?? "denied by policy");
      if (
        wrapToolRequiresApproval(toolName, projectPath) &&
        !hasApproval(toolName, WRAP_APPROVAL_SCOPE, approvalService)
      ) {
        return denied(
          toolName,
          `wrapped tool "${toolName}" requires operator approval — run: qring mcp approve ${toolName} --for 3600 --reason "<why>"`,
        );
      }
      const limit = getWrapRateLimit(toolName, projectPath);
      if (limit && !limiter.take(toolName, limit)) {
        return denied(
          toolName,
          `rate limit exceeded for "${toolName}" (${limit.maxCalls} calls per ${limit.perSeconds}s)`,
        );
      }
      return null;
    } catch (err) {
      return denied(toolName, err instanceof Error ? err.message : String(err));
    }
  };

  const toolAllowed = (toolName: string): boolean => {
    try {
      return checkWrapToolPolicy(toolName, projectPath).allowed;
    } catch {
      return false;
    }
  };

  // ── Tools ──────────────────────────────────────────────────────────────

  // Handlers are registered per capability: the SDK refuses a handler for a
  // capability the server does not advertise, and a host that sees no tools
  // capability never asks. A tools-less (resources/prompts-only) downstream
  // is therefore proxied honestly instead of answering an empty list.
  if (dsCaps.tools) registerToolHandlers();
  if (dsCaps.resources) registerResourceHandlers();
  if (dsCaps.prompts) registerPromptHandlers();

  return proxy;

  // ── Tools ──────────────────────────────────────────────────────────────

  function registerToolHandlers(): void {
    // A dynamic downstream (login-gated or feature-flagged tools) re-lists
    // after this notification; swallowing it would freeze the host's view.
    downstream.setNotificationHandler(ToolListChangedNotificationSchema, () => {
      void proxy.sendToolListChanged().catch(() => {});
    });

    proxy.setRequestHandler(ListToolsRequestSchema, async (request) => {
      const listed = await downstream.listTools(request.params);
      // Hide what policy would refuse anyway — an agent that never sees a
      // denied tool never wastes a turn on it (and can't enumerate the gate).
      return { ...listed, tools: listed.tools.filter((t) => toolAllowed(t.name)) };
    });

    proxy.setRequestHandler(CallToolRequestSchema, async (request, extra) => {
      const toolName = request.params.name;
      const blocked = gate(toolName);
      if (blocked) return blocked;

      audit(`tool call "${toolName}" → ${session.label}`);

      // Relay progress under the host's own token. When we pass `onprogress`,
      // the SDK swaps in its own token on the downstream request, so the
      // host's token never collides with airlock message ids.
      const hostToken = request.params._meta?.progressToken;
      const onprogress =
        hostToken !== undefined
          ? (progress: { progress: number; total?: number; message?: string }) => {
              void extra
                .sendNotification({
                  method: "notifications/progress",
                  params: { ...progress, progressToken: hostToken },
                })
                .catch(() => {});
            }
          : undefined;

      try {
        const result = (await downstream.callTool(request.params, undefined, {
          signal: extra.signal,
          timeout: downstreamTimeoutMs(),
          resetTimeoutOnProgress: true,
          onprogress,
        })) as CallToolResult;
        return redactor.result(result);
      } catch (err) {
        // Protocol errors (unknown tool, timeout, connection closed) must stay
        // JSON-RPC errors — the spec separates them from tool-execution
        // failures, and hosts use the distinction (e.g. to refresh tool lists).
        if (err instanceof McpError) throw err;
        const message = err instanceof Error ? err.message : String(err);
        audit(`tool call "${toolName}" failed: ${message}`);
        return {
          content: [{ type: "text", text: `airlock: downstream error: ${message}` }],
          isError: true,
        } satisfies CallToolResult;
      }
    });
  }

  // ── Resources ──────────────────────────────────────────────────────────

  function registerResourceHandlers(): void {
    downstream.setNotificationHandler(ResourceListChangedNotificationSchema, () => {
      void proxy.sendResourceListChanged().catch(() => {});
    });
    downstream.setNotificationHandler(ResourceUpdatedNotificationSchema, (n) => {
      void proxy.sendResourceUpdated(n.params).catch(() => {});
    });

    proxy.setRequestHandler(ListResourcesRequestSchema, (request) =>
      downstream.listResources(request.params),
    );
    proxy.setRequestHandler(ListResourceTemplatesRequestSchema, (request) =>
      downstream.listResourceTemplates(request.params),
    );
    proxy.setRequestHandler(ReadResourceRequestSchema, async (request, extra) => {
      // URIs are identifiers, not payloads — logged (bounded) so the trail
      // says what was fetched, unlike tool arguments.
      audit(`resource read ${truncate(request.params.uri)} → ${session.label}`);
      const result = await downstream.readResource(request.params, {
        signal: extra.signal,
        timeout: downstreamTimeoutMs(),
      });
      return redactor.result(result);
    });
    if (dsCaps.resources?.subscribe) {
      proxy.setRequestHandler(SubscribeRequestSchema, (request) =>
        downstream.subscribeResource(request.params),
      );
      proxy.setRequestHandler(UnsubscribeRequestSchema, (request) =>
        downstream.unsubscribeResource(request.params),
      );
    }
  }

  // ── Prompts ────────────────────────────────────────────────────────────

  function registerPromptHandlers(): void {
    downstream.setNotificationHandler(PromptListChangedNotificationSchema, () => {
      void proxy.sendPromptListChanged().catch(() => {});
    });
    proxy.setRequestHandler(ListPromptsRequestSchema, (request) =>
      downstream.listPrompts(request.params),
    );
    proxy.setRequestHandler(GetPromptRequestSchema, async (request, extra) => {
      // Prompt arguments are user content — never logged, like tool args.
      audit(`prompt get "${request.params.name}" → ${session.label}`);
      const result = await downstream.getPrompt(request.params, {
        signal: extra.signal,
        timeout: downstreamTimeoutMs(),
      });
      return redactor.result(result);
    });
  }
}

function parseHeaders(raw: string[] | undefined): Record<string, string> {
  const headers: Record<string, string> = {};
  for (const line of raw ?? []) {
    const idx = line.indexOf(":");
    if (idx <= 0) throw new Error(`--header expects "Name: value", got "${line}"`);
    headers[line.slice(0, idx).trim()] = line.slice(idx + 1).trim();
  }
  return headers;
}

/** Connect to the wrapped server: spawn it (stdio) or dial it (http). */
export async function connectDownstream(opts: WrapOptions): Promise<Client> {
  const client = new Client({ name: "q-ring-airlock", version: PACKAGE_VERSION });

  if (opts.url) {
    const headers = parseHeaders(opts.headers);
    if (opts.authSecret) {
      // An audited, non-silent read: the airlock deliberately consumed this
      // credential to reach the wrapped server.
      const value = getSecret(opts.authSecret, { projectPath: opts.projectPath, source: "cli" });
      if (value === null) {
        throw new Error(`--auth-secret: "${opts.authSecret}" not found in the keyring`);
      }
      headers.Authorization = `Bearer ${value}`;
    }
    const transport = new StreamableHTTPClientTransport(new URL(opts.url), {
      requestInit: { headers },
    });
    await client.connect(transport);
    return client;
  }

  if (!opts.command) throw new Error("wrap needs a server command or --url");

  const env = opts.inheritEnv
    ? (Object.fromEntries(Object.entries(process.env).filter(([, v]) => v !== undefined)) as Record<
        string,
        string
      >)
    : undefined; // SDK default: getDefaultEnvironment(), the minimal safe set

  const transport = new StdioClientTransport({
    command: opts.command,
    args: opts.args ?? [],
    env,
    stderr: "inherit",
  });

  await client.connect(transport);
  return client;
}

/**
 * Run the airlock until either side disconnects. Resolves with the exit code
 * the CLI should use: 0 when the host closed the session, 1 when the wrapped
 * server died underneath it. Close is awaited (bounded) before resolving so
 * the SDK's staged child shutdown (stdin end → SIGTERM → SIGKILL) actually
 * runs — otherwise `process.exit` in the CLI orphans children that ignore
 * stdin EOF.
 */
export async function runWrap(opts: WrapOptions): Promise<number> {
  const projectPath = opts.projectPath ?? process.cwd();
  // Anchor policy like the MCP server does: the operator's launch directory
  // governs the session, never anything the wrapped server or host says.
  setPolicyRoot(projectPath);

  const label = opts.label ?? opts.url ?? [opts.command, ...(opts.args ?? [])].join(" ");
  const session: WrapSession = { label, correlationId: randomUUID() };

  const downstream = await connectDownstream(opts);
  const downstreamInfo = downstream.getServerVersion();
  const caps = downstream.getServerCapabilities() ?? {};
  const surfaces = (["tools", "resources", "prompts"] as const).filter((c) => caps[c]);

  if (surfaces.length === 0) {
    await downstream.close().catch(() => {});
    throw new Error(
      `wrapped server "${downstreamInfo?.name ?? label}" exposes no tools, resources, or prompts — nothing to proxy`,
    );
  }

  const redact = opts.redact ?? wrapRedactsResults(projectPath);
  const redactor = redact ? createRedactor({ projectPath }) : NOOP_REDACTOR;
  const envNote = opts.url ? "remote (http)" : opts.inheritEnv ? "inherited" : "stripped";

  logAudit({
    action: "wrap",
    source: "cli",
    detail: `airlock session started: ${label} (env ${envNote}; ${surfaces.join("+")}; results ${redact ? "redacted" : "unredacted"})`,
    correlationId: session.correlationId,
  });
  console.error(
    `q-ring airlock: wrapping ${downstreamInfo?.name ?? label} — env ${envNote}, ${surfaces.join("/")} audited, results ${redact ? "redacted" : "NOT redacted"} (session ${session.correlationId.slice(0, 8)})`,
  );

  const proxy = createAirlockServer(downstream, session, { projectPath, redactor });
  const transport = new StdioServerTransport();

  return new Promise<number>((resolve) => {
    let settled = false;
    const finish = (code: number, reason: string) => {
      if (settled) return;
      settled = true;
      logAudit({
        action: "wrap",
        source: "cli",
        detail: `airlock session ended: ${reason}`,
        correlationId: session.correlationId,
      });
      // Bounded graceful close: give StdioClientTransport its full
      // stdin-EOF → SIGTERM → SIGKILL escalation before the CLI exits.
      const closes = Promise.allSettled([proxy.close(), downstream.close()]);
      const deadline = new Promise<void>((r) => setTimeout(r, 6000).unref());
      void Promise.race([closes, deadline]).then(() => resolve(code));
    };

    downstream.onclose = () => finish(1, "wrapped server exited");
    // Use the protocol-level callback — Protocol.connect documents that it
    // takes ownership of transport callbacks, so don't rely on pre-set
    // transport.onclose surviving an SDK upgrade.
    proxy.onclose = () => finish(0, "host disconnected");
    // Transport errors are per-message (e.g. one unparseable stdin line) —
    // SDK convention is log-and-continue, never session teardown.
    proxy.onerror = (err) => {
      console.error(`q-ring airlock: transport error: ${err.message}`);
    };
    // StdioServerTransport never watches stdin 'end' — its onclose only
    // fires on an explicit close(). A host hanging up is an EOF on stdin.
    process.stdin.on("end", () => finish(0, "host disconnected"));
    // A host that vanishes mid-write surfaces as EPIPE on stdout, not as a
    // transport close — without this handler it crashes the process.
    process.stdout.on("error", (err: NodeJS.ErrnoException) => {
      if (err.code === "EPIPE") finish(0, "host disconnected");
      else finish(1, `stdout error: ${err.message}`);
    });
    // Hosts typically stop stdio servers with SIGTERM; route it through the
    // same graceful close so the child isn't orphaned.
    process.once("SIGTERM", () => finish(0, "terminated"));
    process.once("SIGINT", () => finish(0, "interrupted"));

    proxy.connect(transport).catch((err: unknown) => {
      console.error(
        `q-ring airlock: failed to start: ${err instanceof Error ? err.message : String(err)}`,
      );
      finish(1, "startup failure");
    });
  });
}
