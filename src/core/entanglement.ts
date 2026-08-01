/**
 * Quantum Entanglement: link secrets across projects.
 * When one entangled secret is rotated, all linked copies update.
 *
 * Entanglement is stored as metadata in the envelope. The entanglement
 * registry at ~/.config/q-ring/entanglement.json provides a reverse
 * lookup: given a secret, find all its entangled partners.
 */

import { existsSync, writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import { loadJsonRegistry } from "../utils/registry.js";

export interface EntanglementPair {
  /** Source: service/key */
  source: { service: string; key: string };
  /** Target: service/key */
  target: { service: string; key: string };
  /** When this entanglement was created */
  createdAt: string;
}

interface EntanglementRegistry {
  pairs: EntanglementPair[];
}

function getRegistryPath(): string {
  const dir = join(homedir(), ".config", "q-ring");
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
  }
  return join(dir, "entanglement.json");
}

function loadRegistry(): EntanglementRegistry {
  return loadJsonRegistry<EntanglementRegistry>(getRegistryPath(), { pairs: [] });
}

function saveRegistry(registry: EntanglementRegistry): void {
  writeFileSync(getRegistryPath(), JSON.stringify(registry, null, 2), {
    mode: 0o600,
  });
}

export function entangle(
  source: { service: string; key: string },
  target: { service: string; key: string },
): void {
  const registry = loadRegistry();

  const exists = registry.pairs.some(
    (p) =>
      p.source.service === source.service &&
      p.source.key === source.key &&
      p.target.service === target.service &&
      p.target.key === target.key,
  );

  if (!exists) {
    registry.pairs.push({
      source,
      target,
      createdAt: new Date().toISOString(),
    });
    // Bidirectional: add reverse link too
    registry.pairs.push({
      source: target,
      target: source,
      createdAt: new Date().toISOString(),
    });
    saveRegistry(registry);
  }
}

export function disentangle(
  source: { service: string; key: string },
  target: { service: string; key: string },
): void {
  const registry = loadRegistry();
  registry.pairs = registry.pairs.filter(
    (p) =>
      !(
        (p.source.service === source.service &&
          p.source.key === source.key &&
          p.target.service === target.service &&
          p.target.key === target.key) ||
        (p.source.service === target.service &&
          p.source.key === target.key &&
          p.target.service === source.service &&
          p.target.key === source.key)
      ),
  );
  saveRegistry(registry);
}

/**
 * Find all entangled partners for a given secret.
 */
export function findEntangled(
  source: { service: string; key: string },
): { service: string; key: string }[] {
  const registry = loadRegistry();
  return registry.pairs
    .filter(
      (p) =>
        p.source.service === source.service && p.source.key === source.key,
    )
    .map((p) => p.target);
}

/**
 * List all entanglement pairs.
 */
export function listEntanglements(): EntanglementPair[] {
  return loadRegistry().pairs;
}
