/**
 * Asserting on what exec INJECTED, not on what the child happens to have.
 *
 * A child inherits the runner's environment, and CI images set variables
 * these tests plant (windows-latest sets MAVEN_OPTS; GitHub images also set
 * JAVA_TOOL_OPTIONS, GOPATH, CGO_ENABLED, RUSTUP_HOME, CARGO_HOME). So each
 * planted key gets a unique sentinel value, and the child reports only the
 * names whose value is exactly that sentinel. It prints names, never
 * values, so output redaction cannot interfere.
 */
import { randomBytes } from "node:crypto";

const RUN = randomBytes(6).toString("hex");
const sentinels = new Map<string, string>();

/** The unique value to plant under `name` (stable for the test run). */
export function plantedValue(name: string): string {
  let value = sentinels.get(name);
  if (!value) {
    // The name is deliberately not part of the value.
    value = `planted-${RUN}-${sentinels.size}`;
    sentinels.set(name, value);
  }
  return value;
}

/**
 * A `node -e` script printing, as JSON, which of `names` the child received
 * with exactly the planted value, in the order given.
 */
export function printPlantedScript(names: string[]): string {
  const want = Object.fromEntries(names.map((n) => [n, plantedValue(n)]));
  return `const want = ${JSON.stringify(want)}; console.log(JSON.stringify(Object.keys(want).filter((k) => process.env[k] === want[k])))`;
}
