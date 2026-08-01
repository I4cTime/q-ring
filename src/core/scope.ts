import { hashProjectPath } from "../utils/hash.js";

const SERVICE_PREFIX = "q-ring";

export type Scope = "global" | "project" | "team" | "org";

export interface ResolvedScope {
  scope: Scope;
  service: string;
  projectPath?: string;
  teamId?: string;
  orgId?: string;
}

export function globalService(): string {
  return `${SERVICE_PREFIX}:global`;
}

export function projectService(projectPath: string): string {
  const hash = hashProjectPath(projectPath);
  return `${SERVICE_PREFIX}:project:${hash}`;
}

export function teamService(teamId: string): string {
  return `${SERVICE_PREFIX}:team:${teamId}`;
}

export function orgService(orgId: string): string {
  return `${SERVICE_PREFIX}:org:${orgId}`;
}

export interface ScopeOpts {
  scope?: Scope;
  projectPath?: string;
  teamId?: string;
  orgId?: string;
}

/**
 * Resolution order (most specific first):
 * project → team → org → global
 *
 * When a scope is explicitly requested, only that scope is returned.
 * When no scope is specified, the full resolution chain is built so
 * project-level secrets override team, which override org, which
 * override global.
 */
export function resolveScope(opts: ScopeOpts): ResolvedScope[] {
  const { scope, projectPath, teamId, orgId } = opts;

  if (scope === "global") {
    return [{ scope: "global", service: globalService() }];
  }

  if (scope === "project") {
    if (!projectPath) throw new Error("Project path is required for project scope");
    return [{ scope: "project", service: projectService(projectPath), projectPath }];
  }

  if (scope === "team") {
    if (!teamId) throw new Error("Team ID is required for team scope");
    return [{ scope: "team", service: teamService(teamId), teamId }];
  }

  if (scope === "org") {
    if (!orgId) throw new Error("Org ID is required for org scope");
    return [{ scope: "org", service: orgService(orgId), orgId }];
  }

  const chain: ResolvedScope[] = [];

  if (projectPath) {
    chain.push({ scope: "project", service: projectService(projectPath), projectPath });
  }
  if (teamId) {
    chain.push({ scope: "team", service: teamService(teamId), teamId });
  }
  if (orgId) {
    chain.push({ scope: "org", service: orgService(orgId), orgId });
  }

  chain.push({ scope: "global", service: globalService() });
  return chain;
}

/**
 * The single service string for one specific scope, given resolution opts.
 * Unlike resolveScope (which builds the precedence chain when scope is omitted),
 * this always returns exactly one service — used to bind an approval to the
 * concrete project/team/org identity rather than the coarse scope label.
 */
export function serviceForScope(
  scope: Scope,
  opts: Omit<ScopeOpts, "scope"> = {},
): string {
  return resolveScope({ ...opts, scope })[0].service;
}

export function parseServiceName(service: string): ResolvedScope {
  if (service === globalService()) {
    return { scope: "global", service };
  }
  if (service.startsWith(`${SERVICE_PREFIX}:project:`)) {
    return { scope: "project", service };
  }
  if (service.startsWith(`${SERVICE_PREFIX}:team:`)) {
    const teamId = service.slice(`${SERVICE_PREFIX}:team:`.length);
    return { scope: "team", service, teamId };
  }
  if (service.startsWith(`${SERVICE_PREFIX}:org:`)) {
    const orgId = service.slice(`${SERVICE_PREFIX}:org:`.length);
    return { scope: "org", service, orgId };
  }
  return { scope: "global", service };
}
