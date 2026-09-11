/**
 * Canary webhook alerting.
 *
 * Desktop notifications only reach the operator when they are at that
 * machine. A canary trip is the one event worth paging on, so trips can also
 * fan out to Discord, Slack, ntfy, or any JSON endpoint. Channels live in
 * ~/.config/q-ring/canary-alerts.json (0600) and are managed with
 * `qring canary alert …`.
 *
 * Strictly best-effort and fire-and-forget: a failing channel never blocks or
 * delays the trip itself (the audit event is already written by the time we
 * get here). Every URL goes through the SSRF guard so an alert channel cannot
 * be pointed at a private service. The webhook body never carries the canary
 * VALUE — only which key tripped, from where, and by whom.
 */

import { existsSync, writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import { randomUUID } from "node:crypto";
import { loadJsonRegistry } from "../utils/registry.js";
import { httpRequest } from "../utils/http-request.js";
import { checkSSRF } from "./ssrf.js";
import { logAudit } from "./observer.js";

export type CanaryAlertType = "discord" | "slack" | "ntfy" | "generic";

export const CANARY_ALERT_TYPES: CanaryAlertType[] = ["discord", "slack", "ntfy", "generic"];

export interface CanaryAlertChannel {
  id: string;
  type: CanaryAlertType;
  url: string;
  enabled: boolean;
  createdAt: string;
  description?: string;
}

/** What a trip looks like to a channel. Never includes the secret value. */
export interface CanaryAlertEvent {
  key: string;
  scope: string;
  env?: string;
  source: string;
  agent?: string | null;
  detail: string;
  timestamp: string;
  /** Set by `qring canary alert test` so receivers can tell drills apart. */
  test?: boolean;
}

export interface CanaryAlertResult {
  channelId: string;
  type: CanaryAlertType;
  success: boolean;
  message: string;
}

interface AlertRegistry {
  channels: CanaryAlertChannel[];
}

function getRegistryPath(): string {
  const override = process.env.QRING_CANARY_ALERTS_PATH;
  if (override) return override;
  const dir = join(homedir(), ".config", "q-ring");
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true, mode: 0o700 });
  return join(dir, "canary-alerts.json");
}

function loadRegistry(): AlertRegistry {
  return loadJsonRegistry<AlertRegistry>(getRegistryPath(), { channels: [] });
}

function saveRegistry(registry: AlertRegistry): void {
  writeFileSync(getRegistryPath(), JSON.stringify(registry, null, 2), { mode: 0o600 });
}

function assertHttpUrl(url: string): void {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error(`Invalid webhook URL: ${url}`);
  }
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    throw new Error(`Webhook URL must be http(s): ${url}`);
  }
}

export function addCanaryAlert(
  entry: Pick<CanaryAlertChannel, "type" | "url" | "description">,
): CanaryAlertChannel {
  if (!CANARY_ALERT_TYPES.includes(entry.type)) {
    throw new Error(
      `Unknown alert type "${entry.type}". Available: ${CANARY_ALERT_TYPES.join(", ")}`,
    );
  }
  assertHttpUrl(entry.url);
  const registry = loadRegistry();
  const channel: CanaryAlertChannel = {
    id: randomUUID().slice(0, 8),
    type: entry.type,
    url: entry.url,
    description: entry.description,
    enabled: true,
    createdAt: new Date().toISOString(),
  };
  registry.channels.push(channel);
  saveRegistry(registry);
  return channel;
}

export function listCanaryAlerts(): CanaryAlertChannel[] {
  return loadRegistry().channels;
}

export function removeCanaryAlert(id: string): boolean {
  const registry = loadRegistry();
  const before = registry.channels.length;
  registry.channels = registry.channels.filter((c) => c.id !== id);
  if (registry.channels.length === before) return false;
  saveRegistry(registry);
  return true;
}

export function setCanaryAlertEnabled(id: string, enabled: boolean): boolean {
  const registry = loadRegistry();
  const channel = registry.channels.find((c) => c.id === id);
  if (!channel) return false;
  channel.enabled = enabled;
  saveRegistry(registry);
  return true;
}

/** Redact a webhook URL for display — the path usually IS the credential. */
export function describeAlertUrl(url: string): string {
  try {
    const u = new URL(url);
    const tail =
      u.pathname.length > 12 ? `${u.pathname.slice(0, 8)}…${u.pathname.slice(-4)}` : u.pathname;
    return `${u.protocol}//${u.host}${tail}`;
  } catch {
    return url;
  }
}

function headline(event: CanaryAlertEvent): string {
  return event.test ? "q-ring canary alert test" : "q-ring: CANARY TRIPPED";
}

function summary(event: CanaryAlertEvent): string {
  const who = event.agent ? `${event.source} (${event.agent})` : event.source;
  const where = event.env ? `${event.scope}/${event.env}` : event.scope;
  return event.test
    ? `This is a test from \`qring canary alert test\`. Trips on honeytoken "${event.key}" (${where}) would arrive here.`
    : `Honeytoken "${event.key}" (${where}) was read by ${who} at ${event.timestamp}. ${event.detail}. This credential is fake — but something reached for it. Investigate: qring audit --action canary`;
}

interface Outbound {
  body: string;
  headers: Record<string, string>;
}

/** Build the provider-specific request body. Exported for tests. */
export function buildAlertPayload(type: CanaryAlertType, event: CanaryAlertEvent): Outbound {
  const json = { "Content-Type": "application/json", "User-Agent": "q-ring-canary/1.0" };
  switch (type) {
    case "discord":
      return {
        body: JSON.stringify({ content: `🚨 **${headline(event)}**\n${summary(event)}` }),
        headers: json,
      };
    case "slack":
      return {
        body: JSON.stringify({ text: `:rotating_light: *${headline(event)}*\n${summary(event)}` }),
        headers: json,
      };
    case "ntfy":
      return {
        body: summary(event),
        headers: {
          "Content-Type": "text/plain",
          "User-Agent": "q-ring-canary/1.0",
          Title: headline(event),
          Priority: event.test ? "3" : "5",
          Tags: event.test ? "test_tube" : "rotating_light",
        },
      };
    case "generic":
      return {
        body: JSON.stringify({
          event: "canary",
          test: event.test ?? false,
          key: event.key,
          scope: event.scope,
          env: event.env,
          source: event.source,
          agent: event.agent ?? undefined,
          detail: event.detail,
          timestamp: event.timestamp,
        }),
        headers: json,
      };
  }
}

async function sendOne(
  channel: CanaryAlertChannel,
  event: CanaryAlertEvent,
): Promise<CanaryAlertResult> {
  const base = { channelId: channel.id, type: channel.type };
  const ssrfBlock = await checkSSRF(channel.url);
  if (ssrfBlock) {
    logAudit({
      action: "policy_deny",
      key: event.key,
      scope: event.scope,
      source: "hook",
      detail: `canary alert SSRF blocked: ${describeAlertUrl(channel.url)}`,
    });
    return { ...base, success: false, message: ssrfBlock };
  }
  try {
    const { body, headers } = buildAlertPayload(channel.type, event);
    const res = await httpRequest({
      url: channel.url,
      method: "POST",
      headers,
      body,
      timeoutMs: 10_000,
    });
    return {
      ...base,
      success: res.statusCode >= 200 && res.statusCode < 300,
      message: `HTTP ${res.statusCode}`,
    };
  } catch (err) {
    return { ...base, success: false, message: err instanceof Error ? err.message : "HTTP error" };
  }
}

/**
 * Send a trip to every enabled channel (or just `onlyId`). Resolves with the
 * per-channel results; never rejects. Callers on the trip path should not
 * await it.
 */
export async function sendCanaryAlerts(
  event: CanaryAlertEvent,
  onlyId?: string,
): Promise<CanaryAlertResult[]> {
  const channels = listCanaryAlerts().filter((c) => (onlyId ? c.id === onlyId : c.enabled));
  if (channels.length === 0) return [];
  const results = await Promise.allSettled(channels.map((c) => sendOne(c, event)));
  return results.map((r, i) =>
    r.status === "fulfilled"
      ? r.value
      : {
          channelId: channels[i].id,
          type: channels[i].type,
          success: false,
          message: String(r.reason),
        },
  );
}
