/**
 * Approval Notifications
 *
 * When an MCP agent is blocked on a secret that requires user approval, the
 * denial reaches the agent — but the human it is asking for is looking at a
 * different window. This module raises a best-effort desktop notification
 * (`notify-send` on Linux, `osascript` on macOS) telling the user which key
 * is waiting and what to run.
 *
 * Strictly best-effort: notification failure must never affect the deny
 * itself, and repeated agent retries are throttled per key so a retry loop
 * cannot spam the desktop. Disable entirely with QRING_NOTIFY=off.
 */

import { spawn } from "node:child_process";

const DISABLE_ENV = "QRING_NOTIFY";
const THROTTLE_MS = 5 * 60 * 1000;

// Per-key last-notified timestamps. In-memory is enough: the MCP server that
// hits approval denials is a long-lived process.
const lastNotified = new Map<string, number>();

/** Reset throttle state (tests). */
export function resetNotifyThrottle(): void {
  lastNotified.clear();
}

export function notificationsEnabled(): boolean {
  const value = process.env[DISABLE_ENV];
  return value !== "off" && value !== "0" && value !== "false";
}

/**
 * Fire a desktop notification, detached and fire-and-forget. Returns whether
 * a notifier was launched (false on unsupported platforms or errors).
 */
export function notifyUser(title: string, body: string): boolean {
  try {
    let command: string;
    let args: string[];

    if (process.platform === "linux") {
      command = "notify-send";
      // Many notification daemons render the body as Pango markup — a key
      // or agent label containing <span …> would restyle or truncate the
      // alert. Escape the markup-significant characters.
      const pango = (s: string) =>
        s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
      args = ["--app-name=q-ring", "--urgency=critical", pango(title), pango(body)];
    } else if (process.platform === "darwin") {
      command = "osascript";
      // Args are passed as argv (no shell); quotes in the payload are
      // stripped rather than escaped to keep the AppleScript literal inert.
      const clean = (s: string) => s.replace(/["\\]/g, "");
      args = ["-e", `display notification "${clean(body)}" with title "${clean(title)}"`];
    } else {
      return false;
    }

    const child = spawn(command, args, { detached: true, stdio: "ignore" });
    child.on("error", () => {
      /* notifier missing — best-effort */
    });
    child.unref();
    return true;
  } catch {
    return false;
  }
}

/**
 * Notify the user that an agent is waiting on approval for `key`.
 * Throttled to once per key per 5 minutes.
 */
export function notifyApprovalRequested(key: string, source: string): void {
  if (!notificationsEnabled()) return;

  const now = Date.now();
  const last = lastNotified.get(key);
  if (last !== undefined && now - last < THROTTLE_MS) return;
  lastNotified.set(key, now);

  notifyUser(
    "q-ring: approval requested",
    `An ${source} agent wants to read "${key}". Allow with: qring approve ${key}`,
  );
}
