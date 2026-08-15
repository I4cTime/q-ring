import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { PACKAGE_VERSION } from "../version.js";
import { registerMcpTools } from "./tool-registration.js";
import { setPolicyRoot } from "../core/policy.js";
import { setAuditAgentLabel } from "../core/observer.js";

export function createMcpServer(): McpServer {
  // Anchor governance policy to the directory the operator launched the server
  // in. Agents pass projectPath freely, so resolving policy from it would let a
  // malicious agent escape `.q-ring.json` restrictions by pointing elsewhere.
  setPolicyRoot(process.cwd());

  const server = new McpServer({
    name: "q-ring",
    version: PACKAGE_VERSION,
  });
  registerMcpTools(server);
  // Stamp audit events with the connecting client's self-reported identity
  // (clientInfo from the initialize handshake). Label only — spoofable, so it
  // must never feed policy or approval decisions.
  server.server.oninitialized = () => {
    const info = server.server.getClientVersion();
    if (info) setAuditAgentLabel(`${info.name}@${info.version}`);
  };
  return server;
}
