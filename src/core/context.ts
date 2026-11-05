/**
 * Self-Documenting Project Context for AI Agents
 *
 * Provides a safe, redacted view of the project's secrets, configuration,
 * and state without ever exposing actual secret values.
 */

import { listSecrets } from "./keyring.js";
import { collapseEnvironment, readProjectConfig } from "./collapse.js";
import { queryAudit, AGENT_HIDDEN_ACTIONS } from "./observer.js";
import { listHooks } from "./hooks.js";
import { registry as providerRegistry } from "./validate.js";
import { registry as jitRegistry } from "./provision.js";
import type { KeyringOptions } from "./keyring.js";

export interface SecretSummary {
  key: string;
  scope: string;
  tags?: string[];
  description?: string;
  provider?: string;
  requiresApproval?: boolean;
  jitProvider?: string;
  hasStates: boolean;
  isExpired: boolean;
  isStale: boolean;
  timeRemaining: string | null;
  accessCount: number;
  lastAccessed: string | null;
  rotationFormat?: string;
}

export interface ProjectContext {
  projectPath: string;
  environment: {
    env: string;
    source: string;
  } | null;
  secrets: SecretSummary[];
  totalSecrets: number;
  expiredCount: number;
  staleCount: number;
  protectedCount: number;
  manifest: {
    declared: number;
    missing: string[];
  } | null;
  validationProviders: string[];
  jitProviders: string[];
  hooksCount: number;
  recentActions: Array<{
    action: string;
    key?: string;
    source: string;
    timestamp: string;
  }>;
}

export function getProjectContext(opts: KeyringOptions = {}): ProjectContext {
  const projectPath = opts.projectPath ?? process.cwd();
  const envResult = collapseEnvironment({ projectPath });

  const secretsList = listSecrets({
    ...opts,
    projectPath,
    silent: true,
  });

  let expiredCount = 0;
  let staleCount = 0;
  let protectedCount = 0;

  const secrets: SecretSummary[] = secretsList.map((entry) => {
    const meta = entry.envelope?.meta;
    const decay = entry.decay;

    if (decay?.isExpired) expiredCount++;
    if (decay?.isStale) staleCount++;
    if (meta?.requiresApproval) protectedCount++;

    return {
      key: entry.key,
      scope: entry.scope,
      tags: meta?.tags,
      description: meta?.description,
      provider: meta?.provider,
      requiresApproval: meta?.requiresApproval,
      jitProvider: meta?.jitProvider,
      hasStates: !!(entry.envelope?.states && Object.keys(entry.envelope.states).length > 0),
      isExpired: decay?.isExpired ?? false,
      isStale: decay?.isStale ?? false,
      timeRemaining: decay?.timeRemaining ?? null,
      accessCount: meta?.accessCount ?? 0,
      lastAccessed: meta?.lastAccessedAt ?? null,
      rotationFormat: meta?.rotationFormat,
    };
  });

  // Manifest analysis
  let manifest: ProjectContext["manifest"] = null;
  const config = readProjectConfig(projectPath);
  if (config?.secrets) {
    const declaredKeys = Object.keys(config.secrets);
    const existingKeys = new Set(secrets.map((s) => s.key));
    const missing = declaredKeys.filter((k) => !existingKeys.has(k));
    manifest = { declared: declaredKeys.length, missing };
  }

  // Recent audit activity (last 20 agent-visible events, redacted). This
  // context is served to agents (get_project_context): canary trips and
  // canary alert records would name the honeytokens.
  const recentEvents = queryAudit()
    .filter((e) => !AGENT_HIDDEN_ACTIONS.includes(e.action))
    .slice(0, 20);
  const recentActions = recentEvents.map((e) => ({
    action: e.action,
    key: e.key,
    source: e.source,
    timestamp: e.timestamp,
  }));

  return {
    projectPath,
    environment: envResult
      ? { env: envResult.env, source: envResult.source }
      : null,
    secrets,
    totalSecrets: secrets.length,
    expiredCount,
    staleCount,
    protectedCount,
    manifest,
    validationProviders: providerRegistry.listProviders().map((p) => p.name),
    jitProviders: jitRegistry.listProviders().map((p) => p.name),
    hooksCount: listHooks().length,
    recentActions,
  };
}
