/**
 * Shared secret-redaction engine.
 *
 * Used by `qring exec` / `qring run` (RedactionTransform in exec.ts, a
 * streaming scrubber over child stdout/stderr, via RedactionStream) and by
 * the MCP airlock (wrap-redact.ts, scrubbing tool results via
 * RedactionSet.redact). Both build one RedactionSet from `{ name, value }`
 * entries.
 *
 * What counts as a hit, for every value longer than 5 characters:
 *
 * 1. The verbatim value.
 * 2. Encoded forms of it (#121), for values up to DERIVE_MAX_LENGTH chars:
 *    base64 standard and URL-safe at all three byte alignments (so a value
 *    embedded mid-string, as in `Authorization: Basic base64(user:pass)`,
 *    still matches; padding is ignored), lowercase and uppercase hex of the
 *    UTF-8 bytes, `encodeURIComponent`, and the JSON-string-escaped body
 *    (with and without escaped forward slashes).
 * 3. Slices of it (#122): any run of 16 or more consecutive characters of one
 *    of the value's credential-bearing parts (see sliceRegions: the userinfo
 *    of a URL, the signature of a JWT, the body lines of a PEM block, the long
 *    string values of a JSON object; an opaque value is one part), extended
 *    left and right while the text still follows it and replaced whole. Parts
 *    longer than SLICE_MAX_LENGTH chars are not sliced, and windows that are
 *    repeated-character runs (`0000000000000000`) are ignored.
 *
 * Every hit is replaced by `[QRING:REDACTED:<KEY_NAME>]` naming the keyring
 * key the value came from (#123); `[QRING:REDACTED]` when the name is unknown.
 *
 * This remains a best-effort safety net, not a guarantee: a value the child
 * transforms in other ways (encrypted, compressed, reversed, sliced shorter
 * than 16 characters) still passes through.
 */

/** Fallback replacement when the key name is unknown. */
export const REDACTED = "[QRING:REDACTED]";

/** Values this short or shorter would shred ordinary text, so they are skipped. */
export const MIN_REDACT_LENGTH = 6;

/** Shortest run of a secret's characters treated as a sliced hit. */
export const SLICE_WINDOW = 16;

/** Values longer than this get no encoded forms (verbatim and slices only). */
export const DERIVE_MAX_LENGTH = 256;

/**
 * Credential parts (see sliceRegions) longer than this are not sliced; a whole
 * opaque value counts as one part. The limit is per part, so a 2.3 KB
 * service-account JSON still slices its 64-char PEM lines and token fields,
 * while a single 5 KB opaque blob is matched verbatim only.
 */
export const SLICE_MAX_LENGTH = 1024;

/** Values longer than this are not parsed for structure: the whole value is one part. */
export const STRUCTURE_MAX_LENGTH = 64 * 1024;

/**
 * Slice windows with less variety than this are ignored, so repeated-character
 * runs (`0000000000000000`, `abababababababab`) never count as a slice: at
 * least MIN_WINDOW_DISTINCT distinct chars and MIN_WINDOW_ENTROPY bits/char
 * of Shannon entropy. Digit-only account numbers and hex tokens pass.
 */
export const MIN_WINDOW_ENTROPY = 2.0;
export const MIN_WINDOW_DISTINCT = 4;

export interface RedactionEntry {
  /** Keyring key the value came from; omitted when unknown. */
  name?: string;
  value: string;
}

export interface RedactionSetOptions {
  /**
   * Verbatim values only: no encoded forms, no slices. The fallback when a
   * full build fails, so a bad value can never leave the set empty.
   */
  verbatimOnly?: boolean;
  /**
   * false: no slice matching (no window table, no slice-derived hold-back),
   * only whole values and their encoded forms. The airlock uses this: where
   * an untrusted caller can choose text that is scrubbed and read the result
   * back, slice extension (which stops at the first mismatching char) answers
   * "is the next char of this secret X?" one char at a time.
   */
  slices?: boolean;
}

/** The replacement token for a key name (fallback when the name is unknown). */
export function redactionToken(name?: string): string {
  if (!name) return REDACTED;
  // Keep the token parseable: `]` or whitespace in a name would break it.
  const safe = name.replace(/[^A-Za-z0-9_.:-]/g, "_");
  return `[QRING:REDACTED:${safe}]`;
}

/** A matched region of a text, [start, end), to be replaced by `token`. */
export interface RedactionMatch {
  start: number;
  end: number;
  token: string;
}

/** A slice hit, with the region and alignment (pos - offset) it followed. */
interface SliceHit extends RedactionMatch {
  region: number;
  delta: number;
}

interface Pattern {
  text: string;
  token: string;
}

interface SliceRegion {
  text: string;
  token: string;
}

// ── Encoded forms ────────────────────────────────────────────────────────

/** Base64 of `bytes` as it appears when preceded by `lead` bytes (0, 1 or 2). */
function base64Core(bytes: Buffer, lead: number): string {
  const padded = Buffer.concat([Buffer.alloc(lead), bytes]);
  const b64 = padded.toString("base64").replace(/=+$/, "");
  const totalBits = padded.length * 8;
  // Drop leading chars that mix in the unknown preceding bytes and a trailing
  // char that would mix in the unknown following bytes.
  const from = Math.ceil((lead * 8) / 6);
  const to = Math.floor(totalBits / 6);
  return b64.slice(from, to);
}

/**
 * Every encoded form of a value worth matching (excluding the value itself).
 * Never throws: a form that cannot be computed (encodeURIComponent on a lone
 * UTF-16 surrogate) is skipped, the rest still apply.
 */
export function derivedForms(value: string): string[] {
  const forms = new Set<string>();
  const add = (make: () => string | string[]) => {
    try {
      const made = make();
      for (const f of Array.isArray(made) ? made : [made]) forms.add(f);
    } catch {
      // Skip just this form.
    }
  };
  const bytes = Buffer.from(value, "utf8");
  for (const lead of [0, 1, 2]) {
    add(() => {
      const core = base64Core(bytes, lead);
      return [core, core.replace(/\+/g, "-").replace(/\//g, "_")];
    });
  }
  add(() => {
    const hex = bytes.toString("hex");
    return [hex, hex.toUpperCase()];
  });
  add(() => encodeURIComponent(value));
  add(() => {
    const json = JSON.stringify(value).slice(1, -1);
    return [json, json.replace(/\//g, "\\/")];
  });
  forms.delete(value);
  return [...forms].filter((f) => f.length >= MIN_REDACT_LENGTH);
}

// ── Slice regions ────────────────────────────────────────────────────────

const JWT_RE = /^eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.([A-Za-z0-9_-]+)$/;
const URL_RE = /^[A-Za-z][A-Za-z0-9+.-]*:\/\/([^/?#\s]*)(\S*)$/;

/**
 * JSON keys whose string values may hold a credential. `cert` excludes
 * `cert_url`; any key that names a URL or URI (`token_uri`,
 * `auth_provider_x509_cert_url`) is excluded too, since those are public
 * endpoints even under a credential-sounding name.
 */
const CREDENTIAL_KEY_RE =
  /key|secret|token|password|passwd|pwd|credential|private|auth|signature|refresh|access|cert(?!_url)/i;
const URL_KEY_RE = /ur[il]$/i;
const PEM_RE = /-----BEGIN [^-\n]+-----/;

function isCredentialKey(key: string): boolean {
  return CREDENTIAL_KEY_RE.test(key) && !URL_KEY_RE.test(key);
}

/**
 * Collect slice regions from a parsed JSON node. A string is a candidate only
 * when the key it sits under names a credential (`qualifies`), or when it is
 * a PEM block whatever its key; every other string (`client_email`,
 * `project_id`, `type`, public URLs) yields nothing.
 */
function collectJsonStrings(node: unknown, out: string[], depth: number, qualifies: boolean): void {
  if (depth > 20) return;
  if (typeof node === "string") {
    if (node.length < SLICE_WINDOW) return;
    if (qualifies || PEM_RE.test(node)) out.push(...sliceRegions(node, depth + 1));
  } else if (Array.isArray(node)) {
    // Array elements inherit the array's key.
    for (const n of node) collectJsonStrings(n, out, depth + 1, qualifies);
  } else if (node && typeof node === "object") {
    for (const [k, v] of Object.entries(node as Record<string, unknown>)) {
      collectJsonStrings(v, out, depth + 1, isCredentialKey(k));
    }
  }
}

/** Regions of a value, and whether it parsed as a JSON object or array. */
function structuredRegions(value: string, depth: number): { regions: string[]; json: boolean } {
  const trimmed = value.trim();

  // JSON first: in compact JSON a PEM's newlines are the two chars `\n`, so
  // the PEM rule below would see one line, full of ':', and keep nothing.
  if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
    try {
      const parsed: unknown = JSON.parse(trimmed);
      if (parsed && typeof parsed === "object") {
        const regions: string[] = [];
        // A top-level array of strings is a list of opaque values.
        collectJsonStrings(parsed, regions, depth, Array.isArray(parsed));
        return { regions, json: true };
      }
    } catch {
      // Not JSON: try the other shapes.
    }
  }

  if (PEM_RE.test(value)) {
    // Real newlines, or the literal two-char `\n` of a PEM pasted into .env.
    const regions = value
      .split(/\r?\n|\\n/)
      .map((l) => l.trim())
      .filter((l) => l.length > 0 && !l.startsWith("-----") && !l.includes(":"));
    return { regions, json: false };
  }

  const jwt = JWT_RE.exec(trimmed);
  if (jwt) return { regions: [jwt[1]], json: false };

  const url = URL_RE.exec(trimmed);
  if (url) {
    const authority = url[1];
    const at = authority.lastIndexOf("@");
    if (at >= 0) return { regions: [authority.slice(0, at)], json: false };
    return { regions: url[2] ? [url[2]] : [], json: false };
  }

  return { regions: [value], json: false };
}

/**
 * The credential-bearing parts of a value, which are what slice matching
 * looks for. Public structure is left out so it never matches unrelated text:
 *
 * - JSON object or array: string values under credential-named keys (key,
 *   secret, token, password, private, auth, ...; not URL/URI keys), and any
 *   PEM value, each through these same rules. Nothing else: no keys, no
 *   structure, no `client_email`. A JSON value with no such string yields no
 *   regions at all (it is still matched whole, verbatim).
 * - PEM: the base64 body lines, armor and header lines removed.
 * - JWT: the signature segment only (header and payload are shared shapes).
 * - URL with userinfo: the userinfo (`user:password`) only.
 * - URL without userinfo: the path + query, scheme and host stripped.
 * - Anything else: the whole value.
 *
 * Outside JSON, never empty: when a shape yields nothing, the whole value is
 * the region.
 */
export function sliceRegions(value: string, depth = 0): string[] {
  const { regions, json } = structuredRegions(value, depth);
  if (json || regions.length > 0) return regions;
  return [value];
}

// ── Hashing ──────────────────────────────────────────────────────────────

// Polynomial hash mod 2^32: h(s) = s0*B^(L-1) + ... + s(L-1). Used rolling
// over SLICE_WINDOW chars for window lookup, and right-to-left over suffixes
// for the hold-back check. A collision can only cause an extra (verified)
// comparison or a longer hold-back, never a missed hit.
// A large odd multiplier (not 31): with a small base, short strings collide
// structurally ("s\n" and "qH" share a hash), which would hold back ordinary
// output for no reason.
const HASH_BASE = 0x9e3779b1 | 0;
const HASH_DROP = (() => {
  // HASH_BASE^(SLICE_WINDOW - 1) mod 2^32, used to remove the outgoing char.
  let p = 1;
  for (let i = 0; i < SLICE_WINDOW - 1; i++) p = Math.imul(p, HASH_BASE);
  return p;
})();

function windowHash(s: string, start: number): number {
  let h = 0;
  for (let i = start; i < start + SLICE_WINDOW; i++) {
    h = (Math.imul(h, HASH_BASE) + s.charCodeAt(i)) | 0;
  }
  return h;
}

// Membership tables are sorted Int32Arrays searched by bisection, fronted by
// a 2^20-bit filter so most misses cost one bit test. Measured building 200
// sliceable 1000-char secrets (Node 26, x86-64, cold, retained after GC): the
// Set/Map tables held about 104 MB of heap and took about 295 ms; these hold
// about 14 MB of typed arrays and take about 85 ms.
const FILTER_BITS = 20;
const FILTER_MASK = (1 << FILTER_BITS) - 1;

function filterSlot(h: number): number {
  return (h ^ (h >>> 13) ^ (h >>> 26)) & FILTER_MASK;
}

function buildFilter(hashes: Int32Array | Uint32Array): Uint32Array {
  const f = new Uint32Array(1 << (FILTER_BITS - 5));
  for (let i = 0; i < hashes.length; i++) {
    const slot = filterSlot(hashes[i]);
    f[slot >>> 5] |= 1 << (slot & 31);
  }
  return f;
}

function filterHas(f: Uint32Array, h: number): boolean {
  const slot = filterSlot(h);
  return (f[slot >>> 5] & (1 << (slot & 31))) !== 0;
}

/**
 * Indices of `hashes` (unsigned 32-bit values) in ascending hash order. Each
 * (hash, index) pair is packed into one exactly representable double
 * (2^32 * 2^21 = 2^53) so a native numeric sort does the work, with no JS
 * comparator; past 2^21 entries it falls back to a comparator sort.
 */
function sortedOrder(hashes: Uint32Array): Uint32Array {
  const count = hashes.length;
  const idx = new Uint32Array(count);
  const SHIFT = 2 ** 21;
  if (count < SHIFT) {
    const packed = new Float64Array(count);
    for (let i = 0; i < count; i++) packed[i] = hashes[i] * SHIFT + i;
    packed.sort();
    for (let k = 0; k < count; k++) idx[k] = packed[k] % SHIFT;
  } else {
    for (let i = 0; i < count; i++) idx[i] = i;
    idx.sort((x, y) => hashes[x] - hashes[y]);
  }
  return idx;
}

/** First index in sorted `arr` whose value is >= h. */
function lowerBound(arr: Int32Array | Uint32Array, h: number): number {
  let lo = 0;
  let hi = arr.length;
  while (lo < hi) {
    const mid = (lo + hi) >>> 1;
    if (arr[mid] < h) lo = mid + 1;
    else hi = mid;
  }
  return lo;
}

/**
 * Sort unsigned 32-bit values (two 16-bit LSD radix passes, linear time) and
 * drop duplicates; returns a right-sized copy.
 */
function sortUnique(arr: Uint32Array): Uint32Array {
  const n = arr.length;
  const tmp = new Uint32Array(n);
  const count = new Uint32Array(65536);
  for (let i = 0; i < n; i++) count[arr[i] & 0xffff]++;
  for (let i = 0, sum = 0; i < 65536; i++) {
    const c = count[i];
    count[i] = sum;
    sum += c;
  }
  for (let i = 0; i < n; i++) tmp[count[arr[i] & 0xffff]++] = arr[i];
  count.fill(0);
  for (let i = 0; i < n; i++) count[tmp[i] >>> 16]++;
  for (let i = 0, sum = 0; i < 65536; i++) {
    const c = count[i];
    count[i] = sum;
    sum += c;
  }
  for (let i = 0; i < n; i++) arr[count[tmp[i] >>> 16]++] = tmp[i];
  let u = 0;
  for (let i = 0; i < n; i++) {
    if (i === 0 || arr[i] !== arr[i - 1]) arr[u++] = arr[i];
  }
  return arr.slice(0, u);
}

// n * log2(n) for the counts a 16-char window can hold.
const NLOGN = Float64Array.from({ length: SLICE_WINDOW + 1 }, (_, n) =>
  n > 1 ? n * Math.log2(n) : 0,
);
// Scratch per-char counts for regionWindows (always left zeroed).
const WINDOW_COUNTS = new Uint8Array(65536);

/**
 * Call `emit(offset, hash)` for each 16-char window of `text` with enough
 * variety to be a slice (MIN_WINDOW_DISTINCT distinct chars and
 * MIN_WINDOW_ENTROPY bits/char). The hash and the char counts both roll, so
 * a region costs O(length). Shannon entropy of a window with counts n_c is
 * log2(16) - sum(n_c log2 n_c) / 16.
 */
function regionWindows(text: string, emit: (offset: number, hash: number) => void): void {
  if (text.length < SLICE_WINDOW) return;
  let distinct = 0;
  let sum = 0;
  const add = (c: number) => {
    const n = WINDOW_COUNTS[c];
    if (n === 0) distinct++;
    sum += NLOGN[n + 1] - NLOGN[n];
    WINDOW_COUNTS[c] = n + 1;
  };
  const remove = (c: number) => {
    const n = WINDOW_COUNTS[c];
    if (n === 1) distinct--;
    sum += NLOGN[n - 1] - NLOGN[n];
    WINDOW_COUNTS[c] = n - 1;
  };
  for (let i = 0; i < SLICE_WINDOW; i++) add(text.charCodeAt(i));
  let h = windowHash(text, 0);
  const maxEntropy = Math.log2(SLICE_WINDOW);
  for (let offset = 0; offset + SLICE_WINDOW <= text.length; offset++) {
    if (offset > 0) {
      const out = text.charCodeAt(offset - 1);
      const inc = text.charCodeAt(offset + SLICE_WINDOW - 1);
      remove(out);
      add(inc);
      h = (Math.imul(h - Math.imul(out, HASH_DROP), HASH_BASE) + inc) | 0;
    }
    const entropy = maxEntropy - sum / SLICE_WINDOW;
    if (distinct >= MIN_WINDOW_DISTINCT && entropy >= MIN_WINDOW_ENTROPY - 1e-9) emit(offset, h);
  }
  for (let i = text.length - SLICE_WINDOW; i < text.length; i++)
    WINDOW_COUNTS[text.charCodeAt(i)] = 0;
}

let longValueNoted = false;

/** Test hook: let the once-per-process "value too long to slice" note fire again. */
export function resetRedactionNotes(): void {
  longValueNoted = false;
}

/** Per-stream scan state: what earlier calls already examined. */
export interface ScanState {
  /** Chars at the start of the text already scanned by an earlier call. */
  from: number;
  /** Per pattern: earliest start for the next occurrence (non-overlapping). */
  next: Int32Array;
}

export class RedactionSet {
  /** Full-value patterns (verbatim and encoded), longest first. */
  private readonly patterns: Pattern[] = [];
  private readonly regions: SliceRegion[] = [];
  /** Window hashes (unsigned), sorted, with the region and offset of each (parallel). */
  private readonly winHash: Uint32Array;
  private readonly winRegion: Int32Array;
  private readonly winOffset: Int32Array;
  private readonly winFilter: Uint32Array;
  /** Sorted unique hashes of every suffix that could still grow into a hit. */
  private readonly liveHash: Uint32Array;
  private readonly liveFilter: Uint32Array;
  /** Longest full pattern. */
  readonly maxLen: number;
  /** Upper bound on how much raw text a stream may hold back. */
  readonly holdMax: number;
  /** True when at least one value has slice windows. */
  readonly slicing: boolean;

  constructor(entries: readonly RedactionEntry[], options: RedactionSetOptions = {}) {
    // One name per value: the first entry that supplies it wins (a named
    // entry beats an unnamed one).
    const byValue = new Map<string, string | undefined>();
    for (const { name, value } of entries) {
      if (typeof value !== "string" || value.length < MIN_REDACT_LENGTH) continue;
      if (!byValue.has(value) || (byValue.get(value) === undefined && name)) {
        byValue.set(value, name);
      }
    }

    const patternMap = new Map<string, string>();
    let tooLongToSlice = 0;
    for (const [value, name] of byValue) {
      const token = redactionToken(name);
      if (!patternMap.has(value)) patternMap.set(value, token);
      if (options.verbatimOnly) continue;

      if (value.length <= DERIVE_MAX_LENGTH) {
        for (const form of derivedForms(value)) {
          if (!patternMap.has(form)) patternMap.set(form, token);
        }
      }
      if (options.slices === false) continue;

      let regions: string[];
      try {
        regions = value.length > STRUCTURE_MAX_LENGTH ? [value] : sliceRegions(value);
      } catch {
        regions = [value];
      }
      for (const text of regions) {
        if (text.length > SLICE_MAX_LENGTH) tooLongToSlice++;
        else if (text.length >= SLICE_WINDOW) this.regions.push({ text, token });
      }
    }

    if (tooLongToSlice > 0 && !longValueNoted) {
      longValueNoted = true;
      // Counts only: never a value or a key name.
      process.stderr.write(
        `[QRING] redaction: ${tooLongToSlice} credential part(s) longer than ${SLICE_MAX_LENGTH} chars ` +
          `are not slice-matched (their values are still matched verbatim)\n`,
      );
    }

    for (const [text, token] of patternMap) this.patterns.push({ text, token });
    this.patterns.sort((a, b) => b.text.length - a.text.length);
    this.maxLen = this.patterns.length > 0 ? this.patterns[0].text.length : 0;
    this.holdMax = Math.max(this.maxLen, SLICE_WINDOW);

    // Windows: hashes sorted (as unsigned values) with the region and offset
    // of each in parallel arrays, sized for the worst case then trimmed.
    let maxWindows = 0;
    for (const { text } of this.regions) maxWindows += Math.max(0, text.length - SLICE_WINDOW + 1);
    const hashes = new Uint32Array(maxWindows);
    const regionOf = new Int32Array(maxWindows);
    const offsetOf = new Int32Array(maxWindows);
    let count = 0;
    this.regions.forEach(({ text }, region) => {
      regionWindows(text, (offset, h) => {
        hashes[count] = h;
        regionOf[count] = region;
        offsetOf[count] = offset;
        count++;
      });
    });
    const order = sortedOrder(hashes.subarray(0, count));
    this.winHash = new Uint32Array(count);
    this.winRegion = new Int32Array(count);
    this.winOffset = new Int32Array(count);
    for (let k = 0; k < count; k++) {
      const i = order[k];
      this.winHash[k] = hashes[i];
      this.winRegion[k] = regionOf[i];
      this.winOffset[k] = offsetOf[i];
    }
    this.winFilter = buildFilter(this.winHash);
    this.slicing = count > 0;

    // Live suffixes: every proper prefix of a full pattern, and every
    // substring shorter than a window of a slice region.
    let liveCount = 0;
    for (const { text } of this.patterns) liveCount += Math.max(0, text.length - 1);
    for (const { text } of this.regions) {
      for (let i = 0; i < text.length; i++) {
        liveCount += Math.min(SLICE_WINDOW - 1, text.length - i);
      }
    }
    const live = new Uint32Array(liveCount);
    let n = 0;
    for (const { text } of this.patterns) {
      let h = 0;
      for (let i = 0; i < text.length - 1; i++) {
        h = (Math.imul(h, HASH_BASE) + text.charCodeAt(i)) | 0;
        live[n++] = h;
      }
    }
    for (const { text } of this.regions) {
      for (let i = 0; i < text.length; i++) {
        let h = 0;
        for (let j = i; j < text.length && j < i + SLICE_WINDOW - 1; j++) {
          h = (Math.imul(h, HASH_BASE) + text.charCodeAt(j)) | 0;
          live[n++] = h;
        }
      }
    }
    this.liveHash = sortUnique(live);
    this.liveFilter = buildFilter(this.liveHash);
  }

  get empty(): boolean {
    return this.patterns.length === 0;
  }

  get patternCount(): number {
    return this.patterns.length;
  }

  /**
   * All regions of `text` to redact, sorted and non-overlapping. Overlapping
   * hits are merged into one region named after the earliest, longest hit, so
   * no character of either survives and a verbatim hit stays one token.
   *
   * With `state`, only occurrences that reach past `state.from` are searched
   * for (earlier ones were found by a previous call), and full patterns resume
   * where their last occurrence ended.
   */
  findMatches(text: string, state?: ScanState): RedactionMatch[] {
    if (this.empty || text.length === 0) return [];
    const from = state?.from ?? 0;
    const out: RedactionMatch[] = [];

    // 1. Full-value patterns (verbatim and encoded), non-overlapping per pattern.
    for (let k = 0; k < this.patterns.length; k++) {
      const { text: p, token } = this.patterns[k];
      let i = text.indexOf(p, Math.max(0, from - p.length + 1, state ? state.next[k] : 0));
      while (i !== -1) {
        out.push({ start: i, end: i + p.length, token });
        if (state) state.next[k] = i + p.length;
        i = text.indexOf(p, i + p.length);
      }
    }

    // 2. Slices, over every position (including inside full-pattern hits, so
    //    a short value nested in a longer one cannot shadow it).
    if (this.slicing && text.length >= SLICE_WINDOW) {
      this.findSlices(text, Math.max(0, from - (SLICE_WINDOW - 1)), out);
    }
    return mergeMatches(out);
  }

  private findSlices(text: string, start: number, out: RedactionMatch[]): void {
    // Every position is examined (not resuming after a hit), so a run of a
    // different secret, or another alignment of the same one, that starts
    // inside a hit is still found; mergeMatches joins the overlaps. Windows
    // that only re-find an earlier hit (same region, same alignment, still
    // inside it) are skipped, which keeps a long hit linear.
    const last = text.length - SLICE_WINDOW;
    if (start > last) return;
    let h = windowHash(text, start);
    const active: SliceHit[] = [];
    for (let i = start; i <= last; i++) {
      if (i > start) {
        h =
          (Math.imul(h - Math.imul(text.charCodeAt(i - 1), HASH_DROP), HASH_BASE) +
            text.charCodeAt(i + SLICE_WINDOW - 1)) |
          0;
      }
      if (!filterHas(this.winFilter, h)) continue;
      for (let a = active.length - 1; a >= 0; a--) {
        if (active[a].end <= i) active.splice(a, 1);
      }
      const hit = this.extend(text, i, h >>> 0, active);
      if (hit) {
        out.push({ start: hit.start, end: hit.end, token: hit.token });
        active.push(hit);
      }
    }
  }

  /**
   * Longest run around a window (hash `h`) at `pos` that still follows a
   * region, ignoring alignments an `active` hit already covers.
   */
  private extend(text: string, pos: number, h: number, active: SliceHit[]): SliceHit | null {
    let best: SliceHit | null = null;
    for (
      let k = lowerBound(this.winHash, h);
      k < this.winHash.length && this.winHash[k] === h;
      k++
    ) {
      const offset = this.winOffset[k];
      const region = this.winRegion[k];
      const delta = pos - offset;
      if (active.some((a) => a.region === region && a.delta === delta)) continue;
      const { text: value, token } = this.regions[region];
      // Verify (the hash can collide).
      let ok = true;
      for (let k = 0; k < SLICE_WINDOW; k++) {
        if (text.charCodeAt(pos + k) !== value.charCodeAt(offset + k)) {
          ok = false;
          break;
        }
      }
      if (!ok) continue;
      let left = 0;
      while (
        pos - left > 0 &&
        offset - left > 0 &&
        text.charCodeAt(pos - left - 1) === value.charCodeAt(offset - left - 1)
      ) {
        left++;
      }
      let right = SLICE_WINDOW;
      while (
        pos + right < text.length &&
        offset + right < value.length &&
        text.charCodeAt(pos + right) === value.charCodeAt(offset + right)
      ) {
        right++;
      }
      const start = pos - left;
      const end = pos + right;
      if (!best || end - start > best.end - best.start) best = { start, end, token, region, delta };
    }
    return best;
  }

  /**
   * Start of the longest suffix of `text` (no earlier than `bound`) that could
   * still become a hit once more text arrives: a proper prefix of a full
   * pattern, or a substring shorter than a window of a slice region. Returns
   * text.length when no suffix is live. One right-to-left pass of hashes.
   */
  liveStart(text: string, bound: number): number {
    let best = text.length;
    let h = 0;
    let pow = 1;
    for (let p = text.length - 1; p >= bound; p--) {
      h = (h + Math.imul(text.charCodeAt(p), pow)) | 0;
      pow = Math.imul(pow, HASH_BASE);
      if (filterHas(this.liveFilter, h)) {
        const k = lowerBound(this.liveHash, h >>> 0);
        if (k < this.liveHash.length && this.liveHash[k] === h >>> 0) best = p;
      }
    }
    return best;
  }

  /** Redact a complete text in one pass. */
  redact(text: string): string {
    return applyMatches(text, this.findMatches(text));
  }
}

/**
 * Streaming redaction over a sequence of text chunks. Emits everything that
 * can no longer be part of a hit and holds back the rest raw:
 *
 * - only the longest suffix that could still grow into a hit is held
 *   (RedactionSet.liveStart), so ordinary output flushes at once;
 * - a hit that crosses the hold-back point or reaches the end of the text is
 *   held whole (it may still grow), and remembered so it is not searched for
 *   again;
 * - the held text never exceeds holdMax chars: a region that starts before
 *   that bound is emitted as a token up to the bound and its remainder is
 *   carried as an already-redacted region, so even an endless run of a
 *   repeating secret streams out in bounded memory.
 *
 * There is deliberately no idle flush: emitting held raw text on a timer
 * could print a half-received secret.
 */
export class RedactionStream {
  private pending = "";
  private carried: RedactionMatch[] = [];
  private readonly state: ScanState;

  constructor(private readonly set: RedactionSet) {
    this.state = { from: 0, next: new Int32Array(set.patternCount) };
  }

  /** Length of the raw text currently held back. */
  get held(): number {
    return this.pending.length;
  }

  write(chunk: string): string {
    if (!chunk) return "";
    const text = this.pending + chunk;
    this.state.from = this.pending.length;
    const matches = mergeMatches([...this.carried, ...this.set.findMatches(text, this.state)]);

    const n = text.length;
    const bound = Math.max(0, n - this.set.holdMax);
    let cut = this.set.liveStart(text, bound);
    const emitted: RedactionMatch[] = [];
    const carried: RedactionMatch[] = [];

    for (const m of matches) {
      if (m.start < cut && (m.end > cut || m.end === n)) {
        if (m.start >= bound) {
          cut = m.start;
          carried.push(m);
        } else {
          // Cap: redact up to the bound now, carry the rest as redacted.
          cut = bound;
          emitted.push({ start: m.start, end: bound, token: m.token });
          carried.push({ start: bound, end: m.end, token: m.token });
        }
      } else if (m.end <= cut) {
        emitted.push(m);
      } else {
        carried.push(m);
      }
    }

    this.pending = text.slice(cut);
    this.carried = carried
      .filter((m) => m.end > cut)
      .map((m) => ({ start: m.start - cut, end: m.end - cut, token: m.token }));
    for (let k = 0; k < this.state.next.length; k++) {
      this.state.next[k] = Math.max(0, this.state.next[k] - cut);
    }
    return applyMatches(text.slice(0, cut), emitted);
  }

  /** Flush everything held, with an optional last chunk. */
  end(chunk = ""): string {
    const text = this.pending + chunk;
    this.state.from = this.pending.length;
    const matches = mergeMatches([...this.carried, ...this.set.findMatches(text, this.state)]);
    this.pending = "";
    this.carried = [];
    return applyMatches(text, matches);
  }
}

/** Sort by start (longest first on ties) and merge overlapping regions. */
function mergeMatches(matches: RedactionMatch[]): RedactionMatch[] {
  if (matches.length <= 1) return matches;
  matches.sort((a, b) => a.start - b.start || b.end - a.end);
  const out: RedactionMatch[] = [{ ...matches[0] }];
  for (let i = 1; i < matches.length; i++) {
    const cur = out[out.length - 1];
    const m = matches[i];
    if (m.start < cur.end) {
      if (m.end > cur.end) cur.end = m.end;
    } else {
      out.push({ ...m });
    }
  }
  return out;
}

function applyMatches(text: string, matches: RedactionMatch[]): string {
  if (matches.length === 0) return text;
  let out = "";
  let pos = 0;
  for (const m of matches) {
    out += text.slice(pos, m.start) + m.token;
    pos = m.end;
  }
  return out + text.slice(pos);
}
