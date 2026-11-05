/**
 * Shared secret-redaction engine.
 *
 * Used by `qring exec` / `qring run` (RedactionTransform in exec.ts, a
 * streaming scrubber over child stdout/stderr) and by the MCP airlock
 * (wrap-redact.ts, scrubbing tool results). Both build one RedactionSet from
 * `{ name, value }` entries and ask it for matches.
 *
 * What counts as a hit, for every value longer than 5 characters:
 *
 * 1. The verbatim value.
 * 2. Encoded forms of it (#121): base64 standard and URL-safe at all three
 *    byte alignments (so a value embedded mid-string, as in
 *    `Authorization: Basic base64(user:pass)`, still matches; padding is
 *    ignored), lowercase and uppercase hex of the UTF-8 bytes,
 *    `encodeURIComponent`, and the JSON-string-escaped body (with and without
 *    escaped forward slashes).
 * 3. Slices of it (#122): any run of 16 or more consecutive characters of the
 *    raw value. A hit is extended left and right while the text still follows
 *    the value, and the whole run is replaced.
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

/** Above this many 16-char windows across all values, slice matching is skipped. */
export const MAX_SLICE_WINDOWS = 5000;

export interface RedactionEntry {
  /** Keyring key the value came from; omitted when unknown. */
  name?: string;
  value: string;
}

/** The replacement token for a key name (fallback when the name is unknown). */
export function redactionToken(name?: string): string {
  if (!name) return REDACTED;
  // Keep the token parseable: `]` or whitespace in a name would break it.
  const safe = name.replace(/[^A-Za-z0-9_.:-]/g, "_");
  return `[QRING:REDACTED:${safe}]`;
}

interface Pattern {
  text: string;
  token: string;
}

interface SliceSecret {
  value: string;
  token: string;
}

interface WindowRef {
  secret: number;
  offset: number;
}

/** A matched region of a text, [start, end), to be replaced by `token`. */
export interface RedactionMatch {
  start: number;
  end: number;
  token: string;
}

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

/** Every encoded form of a value worth matching (excluding the value itself). */
export function derivedForms(value: string): string[] {
  const bytes = Buffer.from(value, "utf8");
  const forms = new Set<string>();
  for (const lead of [0, 1, 2]) {
    const core = base64Core(bytes, lead);
    forms.add(core);
    forms.add(core.replace(/\+/g, "-").replace(/\//g, "_"));
  }
  const hex = bytes.toString("hex");
  forms.add(hex);
  forms.add(hex.toUpperCase());
  forms.add(encodeURIComponent(value));
  const json = JSON.stringify(value).slice(1, -1);
  forms.add(json);
  forms.add(json.replace(/\//g, "\\/"));
  forms.delete(value);
  return [...forms].filter((f) => f.length >= MIN_REDACT_LENGTH);
}

// Polynomial rolling hash over SLICE_WINDOW UTF-16 code units, mod 2^32.
const HASH_BASE = 31;
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

let sliceCapWarned = false;

/** Test hook: let the once-per-process slice-cap warning fire again. */
export function resetSliceCapWarning(): void {
  sliceCapWarned = false;
}

export class RedactionSet {
  /** Full-value patterns (verbatim and encoded), longest first. */
  private readonly patterns: Pattern[];
  private readonly sliceSecrets: SliceSecret[];
  private readonly windows = new Map<number, WindowRef[]>();
  /** Longest full pattern: the streaming tail must hold maxLen - 1 chars. */
  readonly maxLen: number;
  /** False when there was nothing to slice or the window cap tripped. */
  readonly slicing: boolean;

  constructor(entries: readonly RedactionEntry[]) {
    // One name per value: the first entry that supplies it wins.
    const byValue = new Map<string, string | undefined>();
    for (const { name, value } of entries) {
      if (typeof value !== "string" || value.length < MIN_REDACT_LENGTH) continue;
      if (!byValue.has(value) || (byValue.get(value) === undefined && name)) {
        byValue.set(value, name);
      }
    }

    const patternMap = new Map<string, string>();
    const sliceSecrets: SliceSecret[] = [];
    let windowCount = 0;
    for (const [value, name] of byValue) {
      const token = redactionToken(name);
      if (!patternMap.has(value)) patternMap.set(value, token);
      for (const form of derivedForms(value)) {
        if (!patternMap.has(form)) patternMap.set(form, token);
      }
      if (value.length > SLICE_WINDOW) {
        sliceSecrets.push({ value, token });
        windowCount += value.length - SLICE_WINDOW + 1;
      }
    }

    this.patterns = [...patternMap].map(([text, token]) => ({ text, token }));
    this.patterns.sort((a, b) => b.text.length - a.text.length);
    this.maxLen = this.patterns.length > 0 ? this.patterns[0].text.length : 0;

    const capped = windowCount > MAX_SLICE_WINDOWS;
    this.sliceSecrets = capped ? [] : sliceSecrets;
    if (capped) {
      if (!sliceCapWarned) {
        sliceCapWarned = true;
        // Counts only: never a value or a key name.
        process.stderr.write(
          `[QRING] redaction: ${windowCount} secret slice windows exceed the cap of ${MAX_SLICE_WINDOWS}; ` +
            `sliced-secret matching is off (verbatim and encoded values are still redacted)\n`,
        );
      }
    }

    this.sliceSecrets.forEach(({ value }, secret) => {
      for (let offset = 0; offset + SLICE_WINDOW <= value.length; offset++) {
        const h = windowHash(value, offset);
        const refs = this.windows.get(h);
        if (refs) refs.push({ secret, offset });
        else this.windows.set(h, [{ secret, offset }]);
      }
    });
    this.slicing = this.windows.size > 0;
  }

  get empty(): boolean {
    return this.patterns.length === 0;
  }

  /**
   * All regions of `text` to redact, sorted and non-overlapping. Overlapping
   * hits are merged into one region (named after the earliest, longest hit)
   * so no character of either survives.
   */
  findMatches(text: string): RedactionMatch[] {
    if (this.empty || text.length === 0) return [];

    // 1. Full-value patterns (verbatim and encoded).
    const full: RedactionMatch[] = [];
    for (const { text: p, token } of this.patterns) {
      let i = text.indexOf(p);
      while (i !== -1) {
        full.push({ start: i, end: i + p.length, token });
        i = text.indexOf(p, i + 1);
      }
    }
    const merged = mergeMatches(full);

    // 2. Slices, skipping regions a full pattern already covers so a verbatim
    //    hit stays one replacement.
    if (!this.slicing || text.length < SLICE_WINDOW) return merged;
    const slices = this.findSlices(text, merged);
    return slices.length === 0 ? merged : mergeMatches([...merged, ...slices]);
  }

  private findSlices(text: string, covered: RedactionMatch[]): RedactionMatch[] {
    const out: RedactionMatch[] = [];
    let ci = 0; // next covered region at or after i
    let i = 0;
    let h = 0;
    // Position h was computed for. h is rolled forward only from i - 1; -2 can
    // never equal i - 1, so it forces a fresh hash (start, after a jump).
    let hashAt = -2;
    const last = text.length - SLICE_WINDOW;

    while (i <= last) {
      while (ci < covered.length && covered[ci].end <= i) ci++;
      if (ci < covered.length && covered[ci].start <= i) {
        i = covered[ci].end;
        hashAt = -2;
        continue;
      }

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
    return out;
  }

  /** Longest run around a window hit at `pos` that still follows a secret. */
  private extend(text: string, pos: number, refs: WindowRef[]): RedactionMatch | null {
    let best: RedactionMatch | null = null;
    for (const { secret, offset } of refs) {
      const { value, token } = this.sliceSecrets[secret];
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

  /** Redact a complete text in one pass. */
  redact(text: string): string {
    return applyMatches(text, this.findMatches(text));
  }

  /**
   * Streaming step: redact what is safe to emit from `text` and return the
   * raw (unredacted) remainder to prepend to the next chunk. The remainder is
   * the last maxLen - 1 characters, so any value that might complete in the
   * next chunk is still whole when it is matched; a hit that straddles the cut
   * is complete and emitted whole. With `final`, everything is emitted.
   */
  redactStream(text: string, final: boolean): { emit: string; keep: string } {
    const matches = this.findMatches(text);
    if (final) return { emit: applyMatches(text, matches), keep: "" };

    let cut = Math.max(0, text.length - Math.max(this.maxLen - 1, 0));
    for (const m of matches) {
      if (m.start >= cut) break;
      if (m.end <= cut) continue;
      // Straddles the cut. A hit touching the end of the text could still
      // grow (a slice), so hold it back whole; otherwise emit it whole.
      cut = m.end >= text.length ? m.start : m.end;
      break;
    }
    const emitted = matches.filter((m) => m.end <= cut);
    return { emit: applyMatches(text.slice(0, cut), emitted), keep: text.slice(cut) };
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
