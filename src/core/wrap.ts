/**
 * MCP Airlock: `qring mcp wrap -- <server command>`.
 *
 * Runs a third-party MCP server as a child process and re-exposes it over
 * stdio, sitting between the agent host and the wrapped server:
 *
 *   agent host ── stdio ── [q-ring airlock] ── stdio ── wrapped server
 *
 * Tools-only proxy. What the airlock adds:
 *
 * - Environment stripping: the wrapped server is spawned with the SDK's
 *   minimal safe environment, NOT the parent env — a wrapped server can't
 *   read API keys out of `process.env` unless `--inherit-env` is passed.
 *   NOTE: this is hygiene, not a sandbox — the child still runs unconfined
 *   as the operator's user (filesystem, network, OS keyring).
 * - A tamper-evident audit trail: every tool call crossing the airlock lands
 *   in the audit chain as a "wrap" action, grouped by a per-session
 *   correlation id and stamped with the connecting client's identity label.
 *   Tool ARGUMENTS are deliberately not logged — they may contain secrets.
 *
 * The proxy aims to be transparent to both sides: tools/list and tools/call
 * forward verbatim (including pagination and tools/list_changed), progress
 * notifications are relayed under the host's own progress token, downstream
 * protocol errors stay JSON-RPC errors, and tool-execution failures surface
 * as isError results. stdout is the protocol channel — all diagnostics go
 * to stderr.
 */

import { randomUUID } from "node:crypto";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
  ToolListChangedNotificationSchema,
  McpError,
  type CallToolResult,
} from "@modelcontextprotocol/sdk/types.js";
import { PACKAGE_VERSION } from "../version.js";
import { logAudit, setAuditAgentLabel } from "./observer.js";

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

export interface WrapOptions {
  command: string;
  args?: string[];
  /** Pass the full parent environment to the wrapped server (default: SDK safe env) */
  inheritEnv?: boolean;
  /** Label used in audit events (default: the wrapped command line) */
  label?: string;
}

export interface WrapSession {
  label: string;
  correlationId: string;
}

/**
 * Build the airlock proxy server around an already-connected downstream
 * client. Exported separately so tests can drive it over in-memory
 * transports without spawning processes.
 */
export function createAirlockServer(
  downstream: Client,
  session: WrapSession,
): Server {
  const downstreamInfo = downstream.getServerVersion();
  const name = downstreamInfo
    ? `${downstreamInfo.name} (q-ring airlock)`
    : "q-ring-airlock";

  const proxy = new Server(
    { name, version: PACKAGE_VERSION },
    {
      capabilities: { tools: { listChanged: true } },
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

  // A dynamic downstream (login-gated or feature-flagged tools) re-lists
  // after this notification; swallowing it would freeze the host's view.
  downstream.setNotificationHandler(ToolListChangedNotificationSchema, () => {
    void proxy.sendToolListChanged().catch(() => {});
  });

  proxy.setRequestHandler(ListToolsRequestSchema, async (request) => {
    // Defensive: a downstream with no tools capability makes the SDK client
    // throw client-side; an empty list is the honest tools-only answer.
    if (!downstream.getServerCapabilities()?.tools) return { tools: [] };
    return downstream.listTools(request.params);
  });

  proxy.setRequestHandler(CallToolRequestSchema, async (request, extra) => {
    const toolName = request.params.name;
    logAudit({
      action: "wrap",
      source: "mcp",
      detail: `tool call "${toolName}" → ${session.label}`,
      correlationId: session.correlationId,
    });

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
      return (await downstream.callTool(request.params, undefined, {
        signal: extra.signal,
        timeout: downstreamTimeoutMs(),
        resetTimeoutOnProgress: true,
        onprogress,
      })) as CallToolResult;
    } catch (err) {
      // Protocol errors (unknown tool, timeout, connection closed) must stay
      // JSON-RPC errors — the spec separates them from tool-execution
      // failures, and hosts use the distinction (e.g. to refresh tool lists).
      if (err instanceof McpError) throw err;
      const message = err instanceof Error ? err.message : String(err);
      logAudit({
        action: "wrap",
        source: "mcp",
        detail: `tool call "${toolName}" failed: ${message}`,
        correlationId: session.correlationId,
      });
      return {
        content: [
          { type: "text", text: `airlock: downstream error: ${message}` },
        ],
        isError: true,
      } satisfies CallToolResult;
    }
  });

  return proxy;
}

/** Connect to the wrapped server by spawning it as a child process. */
export async function connectDownstream(opts: WrapOptions): Promise<Client> {
  const client = new Client({
    name: "q-ring-airlock",
    version: PACKAGE_VERSION,
  });

  const env = opts.inheritEnv
    ? (Object.fromEntries(
        Object.entries(process.env).filter(([, v]) => v !== undefined),
      ) as Record<string, string>)
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
  const label = opts.label ?? [opts.command, ...(opts.args ?? [])].join(" ");
  const session: WrapSession = { label, correlationId: randomUUID() };

  const downstream = await connectDownstream(opts);
  const downstreamInfo = downstream.getServerVersion();

  if (!downstream.getServerCapabilities()?.tools) {
    await downstream.close().catch(() => {});
    throw new Error(
      `wrapped server "${downstreamInfo?.name ?? label}" exposes no tools capability — the airlock is tools-only (resources/prompts are not proxied yet)`,
    );
  }

  logAudit({
    action: "wrap",
    source: "cli",
    detail: `airlock session started: ${label}${opts.inheritEnv ? " (env inherited)" : " (env stripped)"}`,
    correlationId: session.correlationId,
  });
  console.error(
    `q-ring airlock: wrapping ${downstreamInfo?.name ?? label} — env ${opts.inheritEnv ? "inherited" : "stripped"}, tool calls audited (session ${session.correlationId.slice(0, 8)})`,
  );

  const proxy = createAirlockServer(downstream, session);
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
