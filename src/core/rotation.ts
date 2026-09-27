/**
 * Rotation reminders: how old is a secret's VALUE, and when should it be
 * rotated next? Pure computation over envelope metadata — provider-native
 * rotation lives elsewhere (`validate.ts`, `agent.ts`).
 */

import type { SecretMetadata } from "./envelope.js";

export type RotationState = "ok" | "due-soon" | "overdue" | "unscheduled";

export interface RotationStatus {
  /** ISO timestamp the age is measured from (rotatedAt → updatedAt → createdAt) */
  lastRotatedAt: string;
  /** Whole days since the value last changed (never negative) */
  ageDays: number;
  /** Reminder interval in days, or null when no reminder is configured */
  rotateEveryDays: number | null;
  /** ISO timestamp the next rotation is due, or null when unscheduled */
  dueAt: string | null;
  /** Whole days until due (negative = days overdue), or null when unscheduled */
  daysUntilDue: number | null;
  state: RotationState;
}

const DAY_MS = 86_400_000;
/** "Due soon" opens at 20% of the interval or 7 days, whichever is smaller. */
const DUE_SOON_FRACTION = 0.2;
const DUE_SOON_MAX_DAYS = 7;

/** Days before `dueAt` at which a secret becomes "due-soon". */
export function dueSoonWindowDays(rotateEveryDays: number): number {
  return Math.min(rotateEveryDays * DUE_SOON_FRACTION, DUE_SOON_MAX_DAYS);
}

function parseMs(iso: string | undefined): number | null {
  if (!iso) return null;
  const ms = new Date(iso).getTime();
  return Number.isFinite(ms) ? ms : null;
}

export function rotationStatus(
  meta: Pick<SecretMetadata, "createdAt" | "updatedAt" | "rotatedAt" | "rotateEveryDays">,
  now: Date | number = Date.now(),
): RotationStatus {
  const nowMs = typeof now === "number" ? now : now.getTime();
  const lastRotatedAt = meta.rotatedAt ?? meta.updatedAt ?? meta.createdAt;
  // An unparseable anchor is treated as "just now" rather than exploding.
  const lastMs = parseMs(lastRotatedAt) ?? nowMs;
  const ageDays = Math.max(0, Math.floor((nowMs - lastMs) / DAY_MS));

  const every = meta.rotateEveryDays;
  if (!every || !Number.isFinite(every) || every <= 0) {
    return {
      lastRotatedAt,
      ageDays,
      rotateEveryDays: null,
      dueAt: null,
      daysUntilDue: null,
      state: "unscheduled",
    };
  }

  const dueMs = lastMs + every * DAY_MS;
  const untilMs = dueMs - nowMs;
  // ceil: 0.3 days left is still "1 day"; -12.3 days is "12 days overdue".
  const daysUntilDue = Math.ceil(untilMs / DAY_MS);

  let state: RotationState = "ok";
  if (untilMs <= 0) state = "overdue";
  else if (untilMs <= dueSoonWindowDays(every) * DAY_MS) state = "due-soon";

  return {
    lastRotatedAt,
    ageDays,
    rotateEveryDays: every,
    dueAt: new Date(dueMs).toISOString(),
    daysUntilDue,
    state,
  };
}

/** Human label: "due in 3d", "overdue 12d", "due now", or "unscheduled". */
export function describeRotation(status: RotationStatus): string {
  if (status.state === "unscheduled" || status.daysUntilDue === null) return "unscheduled";
  if (status.daysUntilDue > 0) return `due in ${status.daysUntilDue}d`;
  if (status.daysUntilDue === 0) return "due now";
  return `overdue ${-status.daysUntilDue}d`;
}

/** Sort key: most overdue first, then soonest due, then unscheduled last. */
export function compareRotationUrgency(a: RotationStatus, b: RotationStatus): number {
  const ad = a.daysUntilDue ?? Number.POSITIVE_INFINITY;
  const bd = b.daysUntilDue ?? Number.POSITIVE_INFINITY;
  return ad - bd;
}
