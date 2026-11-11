// KBOX-14: the streaming response scanner. A response's allowed headers and body are one stream; it is matched against the
// forms of every value the box holds (the KBOX-54 matcher, whose hold-back is counted in the stripped view) and against the
// credential shapes of src/data/credential-shapes.json, found in the same stripped view. A byte is released only when it can
// no longer belong to a match. The scanner never quotes what it saw: a hit is a fixed reason.
import { SEPARATOR, createMatcher, createStripScanner } from './forms.ts';
import type { Form } from './forms.ts';
import type { Parsed } from './schemas.ts';

export interface PrefixShape {
  readonly prefix: Uint8Array;
  readonly min: number;
  /** `alphabet[c]` for each ASCII code. */
  readonly alphabet: readonly boolean[];
}

export interface CredentialShapes {
  readonly prefixes: readonly PrefixShape[];
  /** Each listed member name as it opens a JSON member: `"name"`. */
  readonly members: readonly Uint8Array[];
  readonly pemLabelMax: number;
  readonly jwtHeaderMax: number;
}

export type HitReason = 'value' | 'credential';
export type ScanStep = { readonly kind: 'progress'; readonly releasable: number } | { readonly kind: 'hit'; readonly reason: HitReason };

export interface ResponseScanner {
  feed(chunk: Uint8Array): ScanStep;
  /** A clean end of stream: what is held is decided and, when nothing hits, released. A cut stream is never ended. */
  end(): ScanStep;
  /** The most raw bytes ever held back at once. */
  heldHighWater(): number;
}

// ---------------------------------------------------------------- the data file

const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const intIn = (v: unknown, min: number, max: number): v is number => typeof v === 'number' && Number.isInteger(v) && v >= min && v <= max;
const ALPHABET_TEXT = /^\[(?:[A-Za-z0-9_.~+/=]|[A-Za-z0-9]-[A-Za-z0-9]|-)+\]$/;
const PREFIX_TEXT = /^[\x21-\x7e]{1,32}$/;
const MEMBER_TEXT = /^[A-Za-z0-9_-]{1,64}$/;
const ascii = (text: string): Uint8Array => Uint8Array.from(text, (c) => c.charCodeAt(0));

function alphabetOf(text: unknown): readonly boolean[] | undefined {
  if (typeof text !== 'string' || !ALPHABET_TEXT.test(text)) return undefined;
  const test = new RegExp(`^${text}$`);
  return Array.from({ length: 128 }, (_, c) => test.test(String.fromCharCode(c)));
}

const onlyKeys = (v: Record<string, unknown>, keys: readonly string[]): boolean => Object.keys(v).every((k) => keys.includes(k));

/** Parses the shapes data at the edge; a refusal names nothing of the input. */
export function parseCredentialShapes(raw: unknown): Parsed<CredentialShapes> {
  const refused = { ok: false } as const;
  if (!isRecord(raw) || !onlyKeys(raw, ['default_min', 'default_alphabet', 'prefixes', 'members', 'pem_label_max', 'jwt_header_max'])) return refused;
  const { default_min: defaultMin, prefixes, members, pem_label_max: pemLabelMax, jwt_header_max: jwtHeaderMax } = raw;
  const defaultAlphabet = alphabetOf(raw['default_alphabet']);
  if (!intIn(defaultMin, 1, 256) || defaultAlphabet === undefined || !intIn(pemLabelMax, 1, 256) || !intIn(jwtHeaderMax, 1, 4096)) return refused;
  if (!Array.isArray(prefixes) || !Array.isArray(members)) return refused;
  const shapes: PrefixShape[] = [];
  for (const entry of prefixes) {
    if (!isRecord(entry) || !onlyKeys(entry, ['prefix', 'min', 'alphabet', 'note']) || typeof entry['prefix'] !== 'string' || !PREFIX_TEXT.test(entry['prefix'])) return refused;
    const min = entry['min'] ?? defaultMin;
    const alphabet = entry['alphabet'] === undefined ? defaultAlphabet : alphabetOf(entry['alphabet']);
    if (!intIn(min, 1, 256) || alphabet === undefined) return refused;
    shapes.push({ prefix: ascii(entry['prefix']), min, alphabet });
  }
  if (!members.every((m): m is string => typeof m === 'string' && MEMBER_TEXT.test(m))) return refused;
  return { ok: true, value: { prefixes: shapes, members: members.map((m) => ascii(`"${m}"`)), pemLabelMax, jwtHeaderMax } };
}

// ---------------------------------------------------------------- credential candidates in the stripped view

type Decision = 'none' | 'miss' | 'hit' | 'more';

const CR = 0x0d;
const LF = 0x0a;
const BACKSLASH = 0x5c;
/** A removed blank that is not part of a line break ends a candidate: prose like `ask- the` is never joined into one word. */
const isSoftBlank = (b: number): boolean => b === 0x20 || b === 0x09 || b === 0x0b || b === 0x0c;
const QUOTE = 0x22;
const COLON = 0x3a;
const DOT = 0x2e;
const DASH = 0x2d;
const JWT_OPEN = ascii('eyJ');
const PEM_OPEN = ascii('-----BEGIN');
const PEM_CLOSE = ascii('-----');
const PEM_SUFFIX = 'PRIVATEKEY';
const isBase64Url = (b: number): boolean => (b >= 0x41 && b <= 0x5a) || (b >= 0x61 && b <= 0x7a) || (b >= 0x30 && b <= 0x39) || b === DASH || b === 0x5f;
const isUpper = (b: number): boolean => b >= 0x41 && b <= 0x5a;

function headerHasAlg(header: readonly number[]): boolean {
  const text = Buffer.from(Buffer.from(header).toString('latin1'), 'base64url').toString('utf8');
  try {
    const value: unknown = JSON.parse(text);
    return isRecord(value) && Object.hasOwn(value, 'alg');
  } catch {
    return false;
  }
}

interface ShapeScanner {
  push(chunk: Uint8Array, final: boolean): ScanStep;
}

function createShapeScanner(shapes: CredentialShapes): ShapeScanner {
  const strip = createStripScanner();
  const firstBytes = new Set<number>([...shapes.prefixes.map((p) => p.prefix[0] ?? -1), JWT_OPEN[0] ?? -1, PEM_OPEN[0] ?? -1, QUOTE]);
  // The retained stripped view: from the first undecided byte on. `soft[i]`: a soft blank was removed just before byte i.
  let bytes: number[] = [];
  let offsets: number[] = [];
  let soft: number[] = [];
  let softPending = false;
  let consumed = 0;
  let carry: Uint8Array = new Uint8Array(0);

  return {
    push(chunk, final) {
      const walkBase = strip.pendingFrom() >= 0 ? strip.pendingFrom() : consumed;
      const walk = carry.length === 0 ? chunk : Buffer.concat([carry, chunk]);
      const scanned = strip.push(chunk, final);
      consumed += chunk.length;
      const walkEnd = strip.pendingFrom() >= 0 ? strip.pendingFrom() : consumed;
      let e = 0;
      // A separator whose run began in an earlier push carries an offset before this walk.
      for (; e < scanned.bytes.length && (scanned.offsets[e] ?? 0) < walkBase; e += 1) {
        bytes.push(SEPARATOR);
        offsets.push(scanned.offsets[e] ?? 0);
        soft.push(0);
      }
      for (let x = walkBase; x < walkEnd; x += 1) {
        const raw = walk[x - walkBase] ?? 0;
        if (e < scanned.bytes.length && scanned.offsets[e] === x) {
          bytes.push(scanned.bytes[e] ?? 0);
          offsets.push(x);
          soft.push(softPending ? 1 : 0);
          softPending = scanned.bytes[e] === SEPARATOR && isSoftBlank(raw);
          e += 1;
        } else if (isSoftBlank(raw)) {
          softPending = true;
        } else if (raw !== CR && raw !== LF && raw !== BACKSLASH) {
          throw new RangeError('the stripped view and the raw walk disagree');
        }
      }
      if (e !== scanned.bytes.length) throw new RangeError('the stripped view and the raw walk disagree');
      carry = Uint8Array.from(walk.subarray(walkEnd - walkBase));

      const length = bytes.length;
      /** At the end of what is here: decided by a clean end or a soft blank already seen, else wait for more. */
      const edge = (blankEnds: boolean): Decision => (final || (blankEnds && softPending) ? 'miss' : 'more');
      const opens = (i: number, text: Uint8Array, blanksInside: boolean): Decision | 'open' => {
        for (let j = 0; j < text.length; j += 1) {
          const k = i + j;
          if (k >= length) return edge(!blanksInside) === 'miss' ? 'none' : 'more';
          if (bytes[k] !== text[j] || (j > 0 && !blanksInside && soft[k] === 1)) return 'none';
        }
        return 'open';
      };
      const prefixAt = (i: number, shape: PrefixShape): Decision => {
        const opened = opens(i, shape.prefix, false);
        if (opened !== 'open') return opened;
        let count = 0;
        for (let k = i + shape.prefix.length; ; k += 1) {
          if (k >= length) return edge(true);
          const b = bytes[k] ?? 0;
          if (soft[k] === 1 || b >= 128 || shape.alphabet[b] !== true) return 'miss';
          count += 1;
          if (count >= shape.min) return 'hit';
        }
      };
      const jwtAt = (i: number): Decision => {
        const opened = opens(i, JWT_OPEN, false);
        if (opened !== 'open') return opened;
        for (let k = i; ; k += 1) {
          if (k - i > shapes.jwtHeaderMax) return 'miss';
          if (k >= length) return edge(true);
          const b = bytes[k] ?? 0;
          if (k > i && soft[k] === 1) return 'miss';
          if (b === DOT) return headerHasAlg(bytes.slice(i, k)) ? 'hit' : 'miss';
          if (!isBase64Url(b)) return 'miss';
        }
      };
      const memberAt = (i: number, name: Uint8Array): Decision => {
        const opened = opens(i, name, false);
        if (opened !== 'open') return opened;
        const expect = [COLON, QUOTE];
        for (let k = i + name.length, step = 0; ; k += 1, step += 1) {
          if (k >= length) return edge(false);
          const b = bytes[k] ?? 0;
          if (step < expect.length) {
            if (b !== expect[step]) return 'miss';
          } else {
            return b === QUOTE ? 'miss' : 'hit';
          }
        }
      };
      const pemAt = (i: number): Decision => {
        const opened = opens(i, PEM_OPEN, false);
        if (opened !== 'open') return opened;
        let label = '';
        for (let k = i + PEM_OPEN.length; ; k += 1) {
          if (k >= length) return edge(false);
          const b = bytes[k] ?? 0;
          if (b === DASH) {
            const closed = opens(k, PEM_CLOSE, false);
            if (closed === 'open') return label.endsWith(PEM_SUFFIX) ? 'hit' : 'miss';
            return closed === 'more' ? 'more' : 'miss';
          }
          if (!isUpper(b) || label.length >= shapes.pemLabelMax) return 'miss';
          label += String.fromCharCode(b);
        }
      };
      const decideAt = (i: number): Decision => {
        if (!firstBytes.has(bytes[i] ?? -1)) return 'none';
        const decisions = [...shapes.prefixes.map((p) => prefixAt(i, p)), jwtAt(i), pemAt(i), ...shapes.members.map((m) => memberAt(i, m))];
        if (decisions.includes('hit')) return 'hit';
        return decisions.includes('more') ? 'more' : 'miss';
      };

      let firstHeld = -1;
      for (let i = 0; i < length; i += 1) {
        const decision = decideAt(i);
        if (decision === 'hit') return { kind: 'hit', reason: 'credential' };
        if (decision === 'more' && firstHeld < 0) firstHeld = i;
      }
      const releasable = firstHeld < 0 ? walkEnd : Math.min(walkEnd, offsets[firstHeld] ?? walkEnd);
      const keep = firstHeld < 0 ? length : firstHeld;
      bytes = bytes.slice(keep);
      offsets = offsets.slice(keep);
      soft = soft.slice(keep);
      return { kind: 'progress', releasable };
    },
  };
}

// ---------------------------------------------------------------- the response scanner

export function createResponseScanner(forms: readonly Form[], shapes: CredentialShapes): ResponseScanner {
  const values = createMatcher(forms);
  const credentials = createShapeScanner(shapes);
  let consumed = 0;
  let highWater = 0;
  let stopped = false;

  const step = (chunk: Uint8Array, final: boolean): ScanStep => {
    if (stopped) throw new RangeError('the scanner has stopped');
    consumed += chunk.length;
    const progress = final ? values.end() : values.feed(chunk);
    const shaped = credentials.push(chunk, final);
    if (progress.matches.length > 0 || shaped.kind === 'hit') {
      stopped = true;
      return { kind: 'hit', reason: progress.matches.length > 0 ? 'value' : 'credential' };
    }
    const releasable = Math.min(progress.releasable, shaped.releasable);
    highWater = Math.max(highWater, consumed - releasable);
    if (final) stopped = true;
    return { kind: 'progress', releasable };
  };

  return {
    feed: (chunk) => step(chunk, false),
    end: () => step(new Uint8Array(0), true),
    heldHighWater: () => highWater,
  };
}
