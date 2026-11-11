// KBOX-54: the one forms library for both scanners (the relay's response scanner and the share-file writer).
// A port to TypeScript of devbox's admin-match `cores` and `forms` (admin-secrets-spec section 3), plus the stripped view and a
// streaming matcher that reports how many raw bytes may already be released. It never logs, throws with, or returns any part
// of a value in an error: a refusal is one of the fixed codes of FormsFailure.
import { Buffer } from 'node:buffer';

export type FormName =
  | 'raw'
  | 'b64-0'
  | 'b64-1'
  | 'b64-2'
  | 'b64url-0'
  | 'b64url-1'
  | 'b64url-2'
  | 'hex'
  | 'HEX'
  | 'percent'
  | 'json'
  | 'json-slash'
  | 'u-lower'
  | 'u-upper';

/** `written`: the core as stored. `decoded`: a URL password percent-decoded, when that differs. */
export type CoreKind = 'written' | 'decoded';

export interface Form {
  readonly name: FormName;
  readonly core: CoreKind;
  readonly bytes: Uint8Array;
}

/**
 * `empty`: no value or no core. `short-core`: a core under 2 UTF-8 bytes, which has no base64 interior at alignment 1 and
 * would match nearly anything. `nul`: a NUL byte, which the stripped view uses as its separator.
 */
export type FormsFailure = 'empty' | 'short-core' | 'nul';
export type FormsResult = { readonly ok: true; readonly forms: readonly Form[] } | { readonly ok: false; readonly code: FormsFailure };

export interface ValueOptions {
  /** A prefix declared for this value's shape (the value's core is what follows it), besides the known ones. */
  readonly prefix?: string;
}

/** A copy found: `index` is the position in the array given to `createMatcher`; `start` and `end` are raw offsets, `end` exclusive. */
export interface Match {
  readonly index: number;
  readonly name: FormName;
  readonly start: number;
  readonly end: number;
}

/** `releasable`: raw bytes [0, releasable) of everything fed so far can no longer belong to a copy that is not yet reported. */
export interface Progress {
  readonly matches: readonly Match[];
  readonly releasable: number;
}

export interface Matcher {
  /** Feeds the next raw bytes. */
  feed(chunk: Uint8Array): Progress;
  /** A clean end of stream: what was held back is scanned and released. A cut stream is never ended, so its tail stays held. */
  end(): Progress;
}

/** `bytes[i]` is a kept raw byte or the separator (NUL); `offsets[i]` is its raw offset (a separator: the start of its run). */
export interface StrippedView {
  readonly bytes: Uint8Array;
  readonly offsets: readonly number[];
}

// ---------------------------------------------------------------- cores

const KNOWN_PREFIXES: readonly string[] = ['sb_secret_', 'GOCSPX-'];
const BASE64URL_PART = /^[A-Za-z0-9_-]+$/;
const URL_SCHEME = /^[A-Za-z][A-Za-z0-9+.-]*:\/\//;
const PERCENT_RUN = /(?:%[0-9A-Fa-f]{2})+/g;
const utf8 = new TextEncoder();

function isJwtHeader(part: string): boolean {
  if (part.length % 4 === 1) return false;
  try {
    const parsed: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.from(part, 'base64url')));
    return typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed) && Object.hasOwn(parsed, 'alg');
  } catch {
    return false;
  }
}

/** The signature of a JWT (three base64url segments, the first a JSON object with `alg`), else undefined. */
function jwtSignature(value: string): string | undefined {
  const parts = value.split('.');
  const [header, , signature] = parts;
  if (parts.length !== 3 || header === undefined || signature === undefined) return undefined;
  return parts.every((p) => BASE64URL_PART.test(p)) && isJwtHeader(header) ? signature : undefined;
}

/** The password of a URL with userinfo, as written, else undefined. */
function urlPassword(value: string): string | undefined {
  const scheme = URL_SCHEME.exec(value);
  if (scheme === null) return undefined;
  const netloc = value.slice(scheme[0].length).split(/[/?#]/, 1)[0] ?? '';
  const userinfo = netloc.slice(0, Math.max(0, netloc.lastIndexOf('@')));
  const colon = userinfo.indexOf(':');
  return colon < 0 ? undefined : userinfo.slice(colon + 1);
}

const unquote = (s: string): string => s.replace(PERCENT_RUN, (run) => new TextDecoder().decode(Buffer.from(run.replaceAll('%', ''), 'hex')));

/**
 * The secret part of a value: a JWT's signature; what follows a declared or known prefix; a URL's password as written and, when
 * different, percent-decoded; else the whole value. Every form is per character or byte, so an encoded core is a substring of the
 * encoded whole.
 */
export function coresOf(value: string, options: ValueOptions = {}): readonly string[] {
  const signature = jwtSignature(value);
  if (signature !== undefined) return [signature];
  const declared = options.prefix === undefined || options.prefix === '' ? [] : [options.prefix];
  for (const prefix of [...declared, ...KNOWN_PREFIXES]) {
    if (value.startsWith(prefix)) return [value.slice(prefix.length)];
  }
  const password = urlPassword(value);
  if (password === undefined) return [value];
  const decoded = unquote(password);
  return decoded === password ? [password] : [password, decoded];
}

// ---------------------------------------------------------------- forms

const MIN_CORE_BYTES = 2;
const SAFE_SETS: readonly string[] = ['', '/', "!*'()"]; // quote(safe=''), quote()'s default safe='/', encodeURIComponent
const UNRESERVED = /^[A-Za-z0-9_.~-]$/;

function base64Interior(core: Uint8Array, alignment: number, url: boolean): Uint8Array {
  const padded = new Uint8Array(alignment + core.length);
  padded.set(core, alignment);
  const encoded = Buffer.from(padded).toString(url ? 'base64url' : 'base64');
  return utf8.encode(encoded.slice(Math.ceil((8 * alignment) / 6), Math.floor((8 * (alignment + core.length)) / 6)));
}

function percentEncode(core: Uint8Array, safe: string): string {
  let out = '';
  for (const byte of core) {
    const char = String.fromCharCode(byte);
    out += byte < 0x80 && (UNRESERVED.test(char) || safe.includes(char)) ? char : `%${byte.toString(16).toUpperCase().padStart(2, '0')}`;
  }
  return out;
}

const unicodeEscape = (unit: number, upper: boolean): string => {
  const hex = unit.toString(16).padStart(4, '0');
  return `\\u${upper ? hex.toUpperCase() : hex}`;
};

const SHORT_JSON_ESCAPES: ReadonlyMap<string, string> = new Map([
  ['"', '\\"'],
  ['\\', '\\\\'],
  ['\b', '\\b'],
  ['\f', '\\f'],
  ['\n', '\\n'],
  ['\r', '\\r'],
  ['\t', '\\t'],
]);

/** The body of a JSON string the way `json.dumps` writes it: everything outside space to tilde is `\uXXXX`, lower-case. */
function jsonBody(core: string): string {
  let out = '';
  for (let i = 0; i < core.length; i += 1) {
    const char = core.charAt(i);
    const unit = core.charCodeAt(i);
    out += SHORT_JSON_ESCAPES.get(char) ?? (unit < 0x20 || unit > 0x7e ? unicodeEscape(unit, false) : char);
  }
  return out;
}

const everyCharEscaped = (core: string, upper: boolean): string =>
  Array.from({ length: core.length }, (_, i) => unicodeEscape(core.charCodeAt(i), upper)).join('');

function formsOfCore(core: string, kind: CoreKind, shared: boolean): Form[] {
  const bytes = utf8.encode(core);
  const form = (name: FormName, body: Uint8Array | string): Form => ({ name, core: kind, bytes: typeof body === 'string' ? utf8.encode(body) : body });
  const out: Form[] = [
    form('raw', bytes),
    form('b64-0', base64Interior(bytes, 0, false)),
    form('b64-1', base64Interior(bytes, 1, false)),
    form('b64-2', base64Interior(bytes, 2, false)),
    form('b64url-0', base64Interior(bytes, 0, true)),
    form('b64url-1', base64Interior(bytes, 1, true)),
    form('b64url-2', base64Interior(bytes, 2, true)),
  ];
  if (shared) return out;
  const hex = Buffer.from(bytes).toString('hex');
  out.push(form('hex', hex), form('HEX', hex.toUpperCase()));
  const percents: string[] = [];
  for (const safe of SAFE_SETS) {
    const upper = percentEncode(bytes, safe);
    for (const spelled of [upper, upper.replace(/%[0-9A-F]{2}/g, (m) => m.toLowerCase())]) {
      if (spelled !== core && !percents.includes(spelled)) percents.push(spelled);
    }
  }
  for (const spelled of percents) out.push(form('percent', spelled));
  const json = jsonBody(core);
  if (json !== core) out.push(form('json', json));
  if (json.includes('/')) out.push(form('json-slash', json.replaceAll('/', '\\/')));
  out.push(form('u-lower', everyCharEscaped(core, false)), form('u-upper', everyCharEscaped(core, true)));
  return out;
}

function formsOfValue(value: string, options: ValueOptions, shared: boolean): FormsResult {
  const cores = coresOf(value, options);
  for (const core of cores) {
    if (core === '') return { ok: false, code: 'empty' };
    if (core.includes('\u0000')) return { ok: false, code: 'nul' };
    if (utf8.encode(core).length < MIN_CORE_BYTES) return { ok: false, code: 'short-core' };
  }
  return { ok: true, forms: cores.flatMap((core, i) => formsOfCore(core, i === 0 ? 'written' : 'decoded', shared)) };
}

/** Every form of every core of the value: for the relay's response scanner. */
export const scanForms = (value: string, options: ValueOptions = {}): FormsResult => formsOfValue(value, options, false);

/** Raw plus the six base64 interiors of every core: for the share file. Hex, percent and `\u` forms are never shared. */
export const shareForms = (value: string, options: ValueOptions = {}): FormsResult => formsOfValue(value, options, true);

// ---------------------------------------------------------------- the stripped view

const BACKSLASH = 0x5c;
const CR = 0x0d;
const LF = 0x0a;
const SEPARATOR = 0x00;
/** A run of removed bytes longer than this is kept as one separator: `\` CR LF is 3 bytes, plus one byte of indentation. */
const LONGEST_JOINABLE_RUN = 4;
const isBlank = (byte: number): boolean => byte === 0x20 || (byte >= 0x09 && byte <= 0x0d);

function elementAt<T>(items: ArrayLike<T>, i: number): T {
  const item = items[i];
  if (item === undefined) throw new RangeError('index outside the buffer');
  return item;
}
const byteAt = (bytes: Uint8Array, i: number): number => elementAt(bytes, i);

/** What one push of the scanner produced; `offsets` are raw offsets from the start of the stream. */
interface Scanned {
  readonly bytes: Uint8Array;
  readonly offsets: Float64Array;
  /** Index in `bytes` of the last separator, or -1. */
  readonly lastSeparator: number;
}

interface StripScanner {
  push(data: Uint8Array, final: boolean): Scanned;
  /** Raw offset of the first byte not yet classified (a backslash, maybe with a CR, waiting for what follows), or -1. */
  pendingFrom(): number;
}

/**
 * Removes whitespace and the `\`-newline pattern, a run at a time: a run of at most 4 removed bytes vanishes, a longer one
 * becomes ONE separator byte (so no copy spans it and a whitespace flood is never held). A backslash is removed only when a
 * line break follows, which may arrive in the next chunk, so it stays pending until then.
 */
function createStripScanner(): StripScanner {
  let pending: Uint8Array = new Uint8Array(0);
  let position = 0;
  let runLength = 0;
  let runStart = 0;
  const push = (data: Uint8Array, final: boolean): Scanned => {
    const joined = pending.length === 0 ? data : Buffer.concat([pending, data]);
    const base = position;
    const bytes = new Uint8Array(joined.length);
    const offsets = new Float64Array(joined.length);
    let count = 0;
    let lastSeparator = -1;
    let k = 0;
    for (; k < joined.length; k += 1) {
      const byte = byteAt(joined, k);
      let removed = isBlank(byte);
      if (byte === BACKSLASH) {
        if (k + 1 >= joined.length && !final) break;
        const next = k + 1 < joined.length ? byteAt(joined, k + 1) : -1;
        if (next === CR && k + 2 >= joined.length && !final) break;
        removed = next === LF || (next === CR && k + 2 < joined.length && byteAt(joined, k + 2) === LF);
      }
      if (removed) {
        if (runLength === 0) runStart = base + k;
        runLength += 1;
        if (runLength === LONGEST_JOINABLE_RUN + 1) {
          bytes[count] = SEPARATOR;
          offsets[count] = runStart;
          lastSeparator = count;
          count += 1;
        }
      } else {
        runLength = 0;
        bytes[count] = byte;
        offsets[count] = base + k;
        count += 1;
      }
    }
    pending = Uint8Array.from(joined.subarray(k));
    position = base + k;
    return { bytes: bytes.subarray(0, count), offsets: offsets.subarray(0, count), lastSeparator };
  };
  return { push, pendingFrom: () => (pending.length === 0 ? -1 : position) };
}

/** The stripped view of a whole buffer, with the map from each stripped byte back to its raw offset. */
export function strippedView(raw: Uint8Array): StrippedView {
  const scanned = createStripScanner().push(raw, true);
  return { bytes: Uint8Array.from(scanned.bytes), offsets: Array.from(scanned.offsets) };
}

// ---------------------------------------------------------------- the streaming matcher

/**
 * Finds every form in the raw bytes and in the stripped view, across chunk boundaries, once each. The release point holds back
 * the last (longest form - 1) stripped characters since the last separator, and every raw byte from the raw offset of the first
 * of them on (the removed bytes between and after them included); the raw view holds back its own last (longest form - 1) raw
 * bytes, which is what keeps a copy that holds whitespace itself. Nothing before a separator can join a copy, so a whitespace
 * flood holds back a constant number of bytes.
 */
export function createMatcher(forms: readonly Form[]): Matcher {
  if (forms.some((f) => f.bytes.length === 0)) throw new RangeError('a form must not be empty');
  const needles = forms.map((f) => Buffer.from(f.bytes));
  const hold = Math.max(0, ...needles.map((n) => n.length - 1));
  const scanner = createStripScanner();
  let rawTail: Buffer = Buffer.alloc(0);
  let retained: Buffer = Buffer.alloc(0);
  let retainedOffsets: readonly number[] = [];
  let consumed = 0;
  let ended = false;
  const reported = new Map<string, number>();

  /** Every occurrence of every form in `window` that ends after `already` bytes, reported once, with raw offsets from `rawRange`. */
  const collect = (window: Buffer, already: number, rawRange: (start: number, end: number) => readonly [number, number], found: Match[]): void => {
    needles.forEach((needle, index) => {
      for (let at = window.indexOf(needle, Math.max(0, already - needle.length + 1)); at >= 0; at = window.indexOf(needle, at + 1)) {
        const [start, end] = rawRange(at, at + needle.length);
        const key = `${index}:${start}:${end}`;
        if (reported.has(key)) continue;
        reported.set(key, start);
        found.push({ index, name: elementAt(forms, index).name, start, end });
      }
    });
  };

  const step = (chunk: Uint8Array, final: boolean): Progress => {
    const found: Match[] = [];
    const rawWindow = Buffer.concat([rawTail, chunk]);
    const rawBase = consumed - rawTail.length;
    collect(rawWindow, rawTail.length, (start, end) => [rawBase + start, rawBase + end], found);
    consumed += chunk.length;
    rawTail = Buffer.from(rawWindow.subarray(Math.max(0, rawWindow.length - hold)));

    const scanned = scanner.push(chunk, final);
    const window = Buffer.concat([retained, scanned.bytes]);
    const offsetOf = (i: number): number => (i < retained.length ? elementAt(retainedOffsets, i) : elementAt(scanned.offsets, i - retained.length));
    collect(window, retained.length, (start, end) => [offsetOf(start), offsetOf(end - 1) + 1], found);
    const lastSeparator = scanned.lastSeparator < 0 ? -1 : retained.length + scanned.lastSeparator;
    const keep = Math.min(hold, window.length - (lastSeparator + 1));
    retainedOffsets = Array.from({ length: keep }, (_, i) => offsetOf(window.length - keep + i));
    retained = Buffer.from(window.subarray(window.length - keep));

    let releasable = final ? consumed : Math.min(consumed, consumed - rawTail.length);
    const firstHeld = retainedOffsets[0];
    if (!final && firstHeld !== undefined) releasable = Math.min(releasable, firstHeld);
    const pendingFrom = scanner.pendingFrom();
    if (!final && pendingFrom >= 0) releasable = Math.min(releasable, pendingFrom);
    for (const [key, start] of reported) if (start < releasable) reported.delete(key);
    return { matches: found.sort((a, b) => a.start - b.start || a.index - b.index), releasable };
  };

  return {
    feed(chunk) {
      if (ended) throw new RangeError('the matcher has ended');
      return step(chunk, false);
    },
    end() {
      if (ended) throw new RangeError('the matcher has ended');
      ended = true;
      return step(new Uint8Array(0), true);
    },
  };
}
