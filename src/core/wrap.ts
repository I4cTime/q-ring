/**
 * MCP Airlock: `qring mcp wrap -- <server command>`.
 *
 * Runs a third-party MCP server as a child process and re-exposes it over
 * stdio, sitting between the agent host and the wrapped server:
 *
 *   agent host ── stdio ── [q-ring airlock] ── stdio ── wrapped server
 *
 * Tools-only proxy MVP. What the airlock adds:
 *
 * - Environment stripping: the wrapped server is spawned with the SDK's
 *   minimal safe environment, NOT the parent env — a wrapped server can't
 *   read API keys out of `process.env` unless `--inherit-env` is passed.
 * - A tamper-evident audit trail: every tool call crossing the airlock lands
 *   in the audit chain as a "wrap" action, grouped by a per-session
 *   correlation id and stamped with the connecting client's identity label.
 *   Tool ARGUMENTS are deliberately not logged — they may contain secrets.
 *
 * The proxy is transparent to both sides: tools/list and tools/call are
 * forwarded verbatim, and downstream failures surface as isError results so
 * the agent sees the same failure text it would talking to the server
 * directly. stdout is the protocol channel — all diagnostics go to stderr.
 */

import { randomUUID } from "node:crypto";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
  type CallToolResult,
} from "@modelcontextprotocol/sdk/types.js";
import { PACKAGE_VERSION } from "../version.js";
import { logAudit, setAuditAgentLabel } from "./observer.js";

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
    { capabilities: { tools: {} } },
  );

  // Feature synergy with per-agent identity: the agent host's clientInfo
  // from OUR initialize handshake labels every audited call. Spoofable —
  // audit metadata only, never authorization.
  proxy.oninitialized = () => {
    const info = proxy.getClientVersion();
    if (info) setAuditAgentLabel(`${info.name}@${info.version}`);
  };

  proxy.setRequestHandler(ListToolsRequestSchema, async (request) => {
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
    try {
      return (await downstream.callTool(request.params, undefined, {
        signal: extra.signal,
      })) as CallToolResult;
    } catch (err) {
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
 * server died underneath it.
 */
export async function runWrap(opts: WrapOptions): Promise<number> {
  const label = opts.label ?? [opts.command, ...(opts.args ?? [])].join(" ");
  const session: WrapSession = { label, correlationId: randomUUID() };

  const downstream = await connectDownstream(opts);
  const downstreamInfo = downstream.getServerVersion();

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
      void proxy.close().catch(() => {});
      void downstream.close().catch(() => {});
      resolve(code);
    };

    downstream.onclose = () => finish(1, "wrapped server exited");
    transport.onclose = () => finish(0, "host disconnected");
    transport.onerror = (err) => finish(1, `transport error: ${err.message}`);
    // StdioServerTransport never watches stdin 'end' — its onclose only fires
    // on an explicit close(). A host hanging up is an EOF on our stdin.
    process.stdin.on("end", () => finish(0, "host disconnected"));
    // A host that vanishes mid-write surfaces as EPIPE on stdout, not as a
    // transport close — without this handler it crashes the process.
    process.stdout.on("error", (err: NodeJS.ErrnoException) => {
      if (err.code === "EPIPE") finish(0, "host disconnected");
      else finish(1, `stdout error: ${err.message}`);
    });

    proxy.connect(transport).catch((err: unknown) => {
      console.error(
        `q-ring airlock: failed to start: ${err instanceof Error ? err.message : String(err)}`,
      );
      finish(1, "startup failure");
    });
  });
}
