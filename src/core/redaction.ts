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
 * 3. Slices of it (#122), for values up to SLICE_MAX_LENGTH chars: any run of
 *    16 or more consecutive characters of the value's credential-bearing part
 *    (see sliceRegions: the userinfo of a URL, the signature of a JWT, the body
 *    of a PEM block, the long string values of a JSON object), extended left
 *    and right while the text still follows it and replaced whole. Windows
 *    with under 3 bits/char of entropy (`0000000000000000`) are ignored.
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

/** Values longer than this are not sliced (verbatim, plus encoded if short enough). */
export const SLICE_MAX_LENGTH = 1024;

/** Slice windows below this Shannon entropy (bits per char) are ignored. */
export const MIN_WINDOW_ENTROPY = 3.0;

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

interface Pattern {
  text: string;
  token: string;
}

interface SliceRegion {
  text: string;
  token: string;
}

interface WindowRef {
  region: number;
  offset: number;
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

function collectJsonStrings(node: unknown, out: string[], depth: number): void {
  if (depth > 20) return;
  if (typeof node === "string") {
    if (node.length >= SLICE_WINDOW) out.push(...sliceRegions(node, depth + 1));
  } else if (Array.isArray(node)) {
    for (const n of node) collectJsonStrings(n, out, depth + 1);
  } else if (node && typeof node === "object") {
    for (const v of Object.values(node as Record<string, unknown>)) {
      collectJsonStrings(v, out, depth + 1);
    }
  }
}

/**
 * The credential-bearing parts of a value, which are what slice matching
 * looks for. Public structure is left out so it never matches unrelated text:
 *
 * - URL with userinfo: the userinfo (`user:password`) only.
 * - URL without userinfo: the path + query, scheme and host stripped.
 * - JWT: the signature segment only (header and payload are shared shapes).
 * - PEM: the base64 body lines, armor and header lines removed.
 * - JSON object: its string values of 16+ chars, recursively (not keys).
 * - Anything else: the whole value.
 */
export function sliceRegions(value: string, depth = 0): string[] {
  const trimmed = value.trim();

  if (/-----BEGIN [^-\n]+-----/.test(value)) {
    return value
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter((l) => l.length > 0 && !l.startsWith("-----") && !l.includes(":"));
  }

  const jwt = JWT_RE.exec(trimmed);
  if (jwt) return [jwt[1]];

  const url = URL_RE.exec(trimmed);
  if (url) {
    const authority = url[1];
    const at = authority.lastIndexOf("@");
    if (at >= 0) return [authority.slice(0, at)];
    return url[2] ? [url[2]] : [];
  }

  if (trimmed.startsWith("{")) {
    try {
      const parsed: unknown = JSON.parse(trimmed);
      if (parsed && typeof parsed === "object") {
        const out: string[] = [];
        collectJsonStrings(parsed, out, depth);
        return out;
      }
    } catch {
      // Not JSON: fall through to the whole value.
    }
  }

  return [value];
}

/** Shannon entropy, bits per char, of s[start, start + len). */
function entropy(s: string, start: number, len: number): number {
  const counts = new Map<number, number>();
  for (let i = start; i < start + len; i++) {
    const c = s.charCodeAt(i);
    counts.set(c, (counts.get(c) ?? 0) + 1);
  }
  let h = 0;
  for (const n of counts.values()) {
    const p = n / len;
    h -= p * Math.log2(p);
  }
  return h;
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
  private readonly windows = new Map<number, WindowRef[]>();
  /** Hashes of every suffix that could still grow into a hit (see liveStart). */
  private readonly live = new Set<number>();
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

      if (value.length > SLICE_MAX_LENGTH) {
        tooLongToSlice++;
        continue;
      }
      let regions: string[];
      try {
        regions = sliceRegions(value);
      } catch {
        regions = [value];
      }
      for (const text of regions) {
        if (text.length >= SLICE_WINDOW) this.regions.push({ text, token });
      }
    }

    if (tooLongToSlice > 0 && !longValueNoted) {
      longValueNoted = true;
      // Counts only: never a value or a key name.
      process.stderr.write(
        `[QRING] redaction: ${tooLongToSlice} secret value(s) longer than ${SLICE_MAX_LENGTH} chars ` +
          `are matched verbatim only (no slice matching)\n`,
      );
    }

    for (const [text, token] of patternMap) this.patterns.push({ text, token });
    this.patterns.sort((a, b) => b.text.length - a.text.length);
    this.maxLen = this.patterns.length > 0 ? this.patterns[0].text.length : 0;
    this.holdMax = Math.max(this.maxLen, SLICE_WINDOW);

    this.regions.forEach(({ text }, region) => {
      for (let offset = 0; offset + SLICE_WINDOW <= text.length; offset++) {
        if (entropy(text, offset, SLICE_WINDOW) < MIN_WINDOW_ENTROPY) continue;
        const h = windowHash(text, offset);
        const refs = this.windows.get(h);
        if (refs) refs.push({ region, offset });
        else this.windows.set(h, [{ region, offset }]);
      }
    });
    this.slicing = this.windows.size > 0;

    // Live suffixes: every proper prefix of a full pattern, and every
    // substring shorter than a window of a slice region.
    for (const { text } of this.patterns) {
      let h = 0;
      for (let i = 0; i < text.length - 1; i++) {
        h = (Math.imul(h, HASH_BASE) + text.charCodeAt(i)) | 0;
        this.live.add(h);
      }
    }
    for (const { text } of this.regions) {
      for (let i = 0; i < text.length; i++) {
        let h = 0;
        for (let j = i; j < text.length && j < i + SLICE_WINDOW - 1; j++) {
          h = (Math.imul(h, HASH_BASE) + text.charCodeAt(j)) | 0;
          this.live.add(h);
        }
      }
    }
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
    let i = start;
    let h = 0;
    // Position h was computed for. h is rolled forward only from i - 1; -2 can
    // never equal i - 1, so it forces a fresh hash (start, after a jump).
    let hashAt = -2;
    const last = text.length - SLICE_WINDOW;

    while (i <= last) {
      if (hashAt === i - 1) {
        h =
          (Math.imul(h - Math.imul(text.charCodeAt(i - 1), HASH_DROP), HASH_BASE) +
            text.charCodeAt(i + SLICE_WINDOW - 1)) |
          0;
      } else {
        h = windowHash(text, i);
      }
      hashAt = i;

      const refs = this.windows.get(h);
      const hit = refs ? this.extend(text, i, refs) : null;
      if (hit) {
        out.push(hit);
        i = hit.end;
        hashAt = -2;
      } else {
        i++;
      }
    }
  }

  /** Longest run around a window hit at `pos` that still follows a region. */
  private extend(text: string, pos: number, refs: WindowRef[]): RedactionMatch | null {
    let best: RedactionMatch | null = null;
    for (const { region, offset } of refs) {
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
      if (!best || end - start > best.end - best.start) best = { start, end, token };
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
      if (this.live.has(h)) best = p;
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
