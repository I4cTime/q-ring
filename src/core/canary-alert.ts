/**
 * Canary trip alerting.
 *
 * Kept separate from canary.ts so keyring.ts can import the trip hook without
 * a keyring <-> canary import cycle (canary.ts plants through setSecret).
 *
 * A trip is deliberately LOUD: it lands in the tamper-evident audit chain as
 * its own "canary" action and raises a desktop notification with a shorter
 * throttle than approval notices — a burst of reads is itself the signal.
 */

import { logAudit, getAuditAgentLabel } from "./observer.js";
import { notificationsEnabled, notifyUser } from "./notify.js";

const TRIP_THROTTLE_MS = 30 * 1000;

const lastAlerted = new Map<string, number>();

/** Reset throttle state (tests). */
export function resetCanaryAlertThrottle(): void {
  lastAlerted.clear();
}

export interface CanaryTrip {
  key: string;
  scope: string;
  env?: string;
  source: "cli" | "mcp" | "agent" | "api" | "hook" | "ci";
}

/**
 * Record a canary read: audit event first (never throttled), then a
 * best-effort desktop alert throttled per key.
 */
export function recordCanaryTrip(trip: CanaryTrip): void {
  const agent = getAuditAgentLabel();
  logAudit({
    action: "canary",
    key: trip.key,
    scope: trip.scope,
    env: trip.env,
    source: trip.source,
    detail: `CANARY TRIPPED: honeytoken read via ${trip.source}`,
  });

  if (!notificationsEnabled()) return;
  const now = Date.now();
  const last = lastAlerted.get(trip.key);
  if (last !== undefined && now - last < TRIP_THROTTLE_MS) return;
  lastAlerted.set(trip.key, now);

  const who = agent ? `${trip.source} (${agent})` : trip.source;
  notifyUser(
    "q-ring: CANARY TRIPPED",
    `Honeytoken "${trip.key}" was read by ${who}. This credential is fake — but something reached for it. Investigate: qring audit --action canary`,
  );
}
