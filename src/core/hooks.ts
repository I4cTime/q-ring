/**
 * Hook system: fire callbacks when secrets are created, updated, or deleted.
 * Supports shell commands, HTTP webhooks, and process signals.
 *
 * Registry stored at ~/.config/q-ring/hooks.json
 */

import { existsSync, writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import { execFile, spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { httpRequest } from "../utils/http-request.js";
import { loadJsonRegistry } from "../utils/registry.js";
import { logAudit } from "./observer.js";
import { checkSSRF } from "./ssrf.js";

export type HookType = "shell" | "http" | "signal";
export type HookAction = "write" | "delete" | "rotate";

export interface HookMatch {
  key?: string;
  keyPattern?: string;
  tag?: string;
  scope?: "global" | "project";
  action?: HookAction[];
}

export interface HookEntry {
  id: string;
  type: HookType;
  match: HookMatch;
  command?: string;
  url?: string;
  signal?: { target: string; signal?: string };
  description?: string;
  createdAt: string;
  enabled: boolean;
}

export interface HookPayload {
  action: HookAction;
  key: string;
  scope: string;
  timestamp: string;
  source: "cli" | "mcp" | "agent" | "api" | "hook" | "ci";
}

export interface HookResult {
  hookId: string;
  success: boolean;
  message: string;
}

interface HookRegistry {
  hooks: HookEntry[];
}

function getRegistryPath(): string {
  const dir = join(homedir(), ".config", "q-ring");
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
  }
  return join(dir, "hooks.json");
}

function loadRegistry(): HookRegistry {
  return loadJsonRegistry<HookRegistry>(getRegistryPath(), { hooks: [] });
}

function saveRegistry(registry: HookRegistry): void {
  writeFileSync(getRegistryPath(), JSON.stringify(registry, null, 2), {
    mode: 0o600,
  });
}

export function registerHook(
  entry: Omit<HookEntry, "id" | "createdAt">,
): HookEntry {
  const registry = loadRegistry();
  const hook: HookEntry = {
    ...entry,
    id: randomUUID().slice(0, 8),
    createdAt: new Date().toISOString(),
  };
  registry.hooks.push(hook);
  saveRegistry(registry);
  return hook;
}

export function removeHook(id: string): boolean {
  const registry = loadRegistry();
  const before = registry.hooks.length;
  registry.hooks = registry.hooks.filter((h) => h.id !== id);
  if (registry.hooks.length < before) {
    saveRegistry(registry);
    return true;
  }
  return false;
}

export function listHooks(): HookEntry[] {
  return loadRegistry().hooks;
}

export function enableHook(id: string): boolean {
  const registry = loadRegistry();
  const hook = registry.hooks.find((h) => h.id === id);
  if (!hook) return false;
  hook.enabled = true;
  saveRegistry(registry);
  return true;
}

export function disableHook(id: string): boolean {
  const registry = loadRegistry();
  const hook = registry.hooks.find((h) => h.id === id);
  if (!hook) return false;
  hook.enabled = false;
  saveRegistry(registry);
  return true;
}

function matchesHook(
  hook: HookEntry,
  payload: HookPayload,
  tags?: string[],
): boolean {
  if (!hook.enabled) return false;

  const m = hook.match;

  if (m.action?.length && !m.action.includes(payload.action)) return false;

  if (m.key && m.key !== payload.key) return false;

  if (m.keyPattern) {
    const escaped = m.keyPattern.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*");
    const regex = new RegExp("^" + escaped + "$", "i");
    if (!regex.test(payload.key)) return false;
  }

  if (m.tag && (!tags || !tags.includes(m.tag))) return false;

  if (m.scope && m.scope !== payload.scope) return false;

  return true;
}

/** pgrep -f pattern: allow only literals safe from regex/shell metacharacters. */
const SAFE_PGREP_NAME = /^[a-zA-Z0-9._:/-]{1,256}$/;

function shellRunner(): { file: string; args: string[] } {
  if (process.platform === "win32") {
    const comspec = process.env.ComSpec ?? "cmd.exe";
    return { file: comspec, args: ["/d", "/s", "/c"] };
  }
  return { file: "/bin/sh", args: ["-c"] };
}

function executeShell(command: string, payload: HookPayload): Promise<HookResult> {
  return new Promise((resolve) => {
    const env = {
      ...process.env,
      QRING_HOOK_KEY: payload.key,
      QRING_HOOK_ACTION: payload.action,
      QRING_HOOK_SCOPE: payload.scope,
    };

    const { file, args } = shellRunner();
    execFile(
      file,
      [...args, command],
      {
        timeout: 30000,
        env,
        windowsHide: true,
        maxBuffer: 4 * 1024 * 1024,
        encoding: "utf8",
      },
      (err, stdout) => {
        if (err) {
          resolve({
            hookId: "",
            success: false,
            message: `Shell error: ${err.message}`,
          });
        } else {
          resolve({
            hookId: "",
            success: true,
            message: (stdout ?? "").trim() || "OK",
          });
        }
      },
    );
  });
}

async function executeHttp(url: string, payload: HookPayload): Promise<HookResult> {
  const ssrfBlock = await checkSSRF(url);
  if (ssrfBlock) {
    logAudit({
      action: "policy_deny",
      key: payload.key,
      scope: payload.scope,
      source: payload.source,
      detail: `hook SSRF blocked: ${url}`,
    });
    return { hookId: "", success: false, message: ssrfBlock };
  }

  try {
    const body = JSON.stringify(payload);
    const res = await httpRequest({
      url,
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "User-Agent": "q-ring-hooks/1.0",
      },
      body,
      timeoutMs: 10_000,
    });
    return {
      hookId: "",
      success: res.statusCode >= 200 && res.statusCode < 300,
      message: `HTTP ${res.statusCode}`,
    };
  } catch (err) {
    return {
      hookId: "",
      success: false,
      message: err instanceof Error ? err.message : "HTTP error",
    };
  }
}

function executeSignal(
  target: string,
  signal: string = "SIGHUP",
): Promise<HookResult> {
  return new Promise((resolve) => {
    const trimmed = target.trim();
    if (/^\d+$/.test(trimmed)) {
      const pid = parseInt(trimmed, 10);
      try {
        process.kill(pid, signal as NodeJS.Signals);
        resolve({
          hookId: "",
          success: true,
          message: `Signal ${signal} sent to PID ${pid}`,
        });
      } catch (err) {
        resolve({
          hookId: "",
          success: false,
          message: `Signal error: ${err instanceof Error ? err.message : String(err)}`,
        });
      }
      return;
    }

    if (!SAFE_PGREP_NAME.test(trimmed)) {
      resolve({
        hookId: "",
        success: false,
        message:
          'Signal target must be a numeric PID, or a process name matching /^[a-zA-Z0-9._:/-]{1,256}$/ (no spaces or shell metacharacters).',
      });
      return;
    }

    const child = spawn("pgrep", ["-f", trimmed], {
      timeout: 5000,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    child.stdout.on("data", (d: Buffer) => {
      stdout += d.toString();
    });
    child.on("close", (code) => {
      if (code !== 0 || !stdout.trim()) {
        resolve({
          hookId: "",
          success: false,
          message: `Process "${trimmed}" not found`,
        });
        return;
      }
      const pids = stdout
        .trim()
        .split("\n")
        .map((p) => parseInt(p.trim(), 10))
        .filter((p) => !isNaN(p));
      let sent = 0;
      for (const p of pids) {
        try {
          process.kill(p, signal as NodeJS.Signals);
          sent++;
        } catch {
          /* ignore dead PIDs */
        }
      }
      resolve({
        hookId: "",
        success: sent > 0,
        message: `Signal ${signal} sent to ${sent} process(es)`,
      });
    });
    child.on("error", () => {
      resolve({
        hookId: "",
        success: false,
        message: `Process "${trimmed}" not found`,
      });
    });
  });
}

async function executeHook(
  hook: HookEntry,
  payload: HookPayload,
): Promise<HookResult> {
  let result: HookResult;

  switch (hook.type) {
    case "shell":
      result = hook.command
        ? await executeShell(hook.command, payload)
        : { hookId: hook.id, success: false, message: "No command specified" };
      break;
    case "http":
      result = hook.url
        ? await executeHttp(hook.url, payload)
        : { hookId: hook.id, success: false, message: "No URL specified" };
      break;
    case "signal":
      result = hook.signal
        ? await executeSignal(hook.signal.target, hook.signal.signal)
        : { hookId: hook.id, success: false, message: "No signal target specified" };
      break;
    default:
      result = { hookId: hook.id, success: false, message: `Unknown hook type: ${hook.type}` };
  }

  result.hookId = hook.id;
  return result;
}

/**
 * Fire all matching hooks for a given payload. Fire-and-forget — never blocks
 * the caller on hook failures.
 */
export async function fireHooks(
  payload: HookPayload,
  tags?: string[],
): Promise<HookResult[]> {
  const hooks = listHooks();
  const matching = hooks.filter((h) => matchesHook(h, payload, tags));

  if (matching.length === 0) return [];

  const results = await Promise.allSettled(
    matching.map((h) => executeHook(h, payload)),
  );

  const hookResults: HookResult[] = [];
  for (const r of results) {
    if (r.status === "fulfilled") {
      hookResults.push(r.value);
    } else {
      hookResults.push({
        hookId: "unknown",
        success: false,
        message: r.reason?.message ?? "Hook execution failed",
      });
    }
  }

  for (const r of hookResults) {
    try {
      logAudit({
        action: "write",
        key: payload.key,
        scope: payload.scope,
        source: payload.source,
        detail: `hook:${r.hookId} ${r.success ? "ok" : "fail"} — ${r.message}`,
      });
    } catch { /* never crash on audit logging */ }
  }

  return hookResults;
}
