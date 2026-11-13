// A reference reader of the share file, format v4 (KBOX-33, revision 4), written from the spec text alone. It imports nothing from
// src/: writer and reader do not share a mistake. It SAMPLES: windowed entries are matched by hashing only the view offsets that are
// multiples of `scan_stride` (one grid over the whole view), never every position, so a file that leaves a window out is caught (a
// matcher that steps by one cannot see thinned windows; that is how v3 passed its own tests). It fails closed: a file it cannot
// verify, read in full, or that is older than one it has already seen gives a refusal and no findings.
import { createHash, createHmac, createPublicKey, verify } from 'node:crypto';

export type Refusal = 'bad_envelope' | 'bad_signature' | 'bad_body' | 'rolled_back';

export interface Finding {
  readonly project: string;
  readonly name: string;
  readonly gen: number;
  readonly retired: boolean;
  readonly form: string;
  /** Offset in the raw bytes scanned where the form starts: the hit position minus `j`, carried through the view. */
  readonly start: number;
}

export interface OpenShare {
  readonly version: number;
  scan(content: Uint8Array): Finding[];
}

export type OpenResult = { readonly ok: true; readonly share: OpenShare } | { readonly ok: false; readonly code: Refusal };

export interface OpenOptions {
  /** The highest version already seen: a file below it is a rollback and is refused. */
  readonly lastVersion?: number;
}

export const WINDOW = 24;
export const SLOTS = 320;
export const SCAN_STRIDE = 9;
const DIGEST_BYTES = 32;
const SLOT_BYTES = SLOTS * DIGEST_BYTES;
const FORMS = ['raw', 'b64s0', 'b64s1', 'b64s2', 'b64u0', 'b64u1', 'b64u2'];
const HEADER_MEMBERS = ['v', 'version', 'issued_at', 'salt_b64', 'set_id', 'window', 'slots', 'scan_stride'];
const SPKI_ED25519 = Buffer.from('302a300506032b6570032100', 'hex');

/** Where one window digest sits: the entry's index and the slot `j`, the window's offset in the form. */
export interface Slot {
  readonly entry: number;
  readonly j: number;
}
/** Window digest (lower-case hex) to every slot holding it. */
export type SlotTable = ReadonlyMap<string, readonly Slot[]>;
/** A window of the view whose digest is in the table; `at` is the window's offset in the view. */
export interface Hit extends Slot {
  readonly at: number;
}

/** SHA-256(salt ‖ window) as lower-case hex: the window digest of format v4. */
export const windowSha256 = (salt: Uint8Array) => (window: Uint8Array): string => createHash('sha256').update(salt).update(window).digest('hex');

/**
 * The sampling core: hashes the windows at view offsets 0, 9, 18, ... only, and looks each up. `digest` is a parameter so a test can
 * count the calls and run the same sampler over another table (the v3 control).
 */
export function sampledHits(view: Uint8Array, table: SlotTable, digest: (window: Uint8Array) => string): Hit[] {
  const hits: Hit[] = [];
  for (let at = 0; at + WINDOW <= view.length; at += SCAN_STRIDE) {
    for (const slot of table.get(digest(view.subarray(at, at + WINDOW))) ?? []) hits.push({ ...slot, at });
  }
  return hits;
}

/** The view bytes and, for each, its offset in the raw bytes. */
interface View {
  readonly bytes: Buffer;
  readonly offsets: readonly number[];
}

const isBlank = (b: number): boolean => b === 0x20 || (b >= 0x09 && b <= 0x0d);

/**
 * The line-joined view windowed entries are matched in: every backslash-newline removed (joining its two lines), then each line's
 * leading and trailing whitespace stripped and the lines joined. Whitespace inside a line stays (the stated limit: a copy split by
 * spaces into pieces under 32 characters is not found).
 */
export function lineJoinedView(raw: Uint8Array): View {
  const kept: number[] = [];
  const offsets: number[] = [];
  let line: number[] = [];
  const flush = (): void => {
    let from = 0;
    let to = line.length;
    while (from < to && isBlank(raw[line[from] ?? 0] ?? 0)) from += 1;
    while (to > from && isBlank(raw[line[to - 1] ?? 0] ?? 0)) to -= 1;
    for (const i of line.slice(from, to)) {
      kept.push(raw[i] ?? 0);
      offsets.push(i);
    }
    line = [];
  };
  for (let i = 0; i < raw.length; i += 1) {
    const b = raw[i] ?? 0;
    if (b === 0x5c && raw[i + 1] === 0x0a) {
      i += 1;
      continue;
    }
    if (b === 0x5c && raw[i + 1] === 0x0d && raw[i + 2] === 0x0a) {
      i += 2;
      continue;
    }
    if (b === 0x0a) flush();
    else line.push(i);
  }
  flush();
  return { bytes: Buffer.from(kept), offsets };
}

/** The view anchored entries are also matched in: every whitespace byte and every backslash before a line break removed. */
function strippedView(raw: Uint8Array): View {
  const kept: number[] = [];
  const offsets: number[] = [];
  for (let i = 0; i < raw.length; i += 1) {
    const b = raw[i] ?? 0;
    const next = raw[i + 1];
    if (isBlank(b) || (b === 0x5c && (next === 0x0a || next === 0x0d))) continue;
    kept.push(b);
    offsets.push(i);
  }
  return { bytes: Buffer.from(kept), offsets };
}

const rawView = (raw: Uint8Array): View => ({ bytes: Buffer.from(raw), offsets: Array.from({ length: raw.length }, (_, i) => i) });

interface Windowed {
  readonly tier: 'windowed';
  readonly slots: Buffer;
}
interface Anchored {
  readonly tier: 'anchored';
  readonly anchor: string;
  readonly len: number;
  readonly digest: string;
}
type Entry = { readonly project: string; readonly name: string; readonly gen: number; readonly retired: boolean; readonly form: string } & (Windowed | Anchored);

const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const sameMembers = (value: Record<string, unknown>, names: readonly string[]): boolean => Object.keys(value).join() === names.join();

/** Canonical base64 of exactly `length` bytes, or undefined. */
function exactBase64(text: unknown, length: number): Buffer | undefined {
  if (typeof text !== 'string') return undefined;
  const bytes = Buffer.from(text, 'base64');
  return bytes.length === length && bytes.toString('base64') === text ? bytes : undefined;
}

function parseEntry(raw: unknown): Entry | undefined {
  if (!isRecord(raw)) return undefined;
  const { project, name, gen, retired, tier, form } = raw;
  if (typeof project !== 'string' || typeof name !== 'string' || typeof gen !== 'number' || typeof retired !== 'boolean' || typeof form !== 'string') return undefined;
  if (!FORMS.includes(form)) return undefined;
  const base = { project, name, gen, retired, form };
  if (tier === 'windowed') {
    const slots = exactBase64(raw['probes_b64'], SLOT_BYTES);
    return slots !== undefined && sameMembers(raw, ['project', 'name', 'gen', 'retired', 'tier', 'form', 'probes_b64']) ? { ...base, tier, slots } : undefined;
  }
  const { anchor, len, digest } = raw;
  if (tier !== 'anchored' || typeof anchor !== 'string' || typeof len !== 'number' || typeof digest !== 'string') return undefined;
  return sameMembers(raw, ['project', 'name', 'gen', 'retired', 'tier', 'form', 'anchor', 'len', 'digest']) ? { ...base, tier, anchor, len, digest } : undefined;
}

/** Characters of a base64 form between the end of the anchor and the first character fixed by core bytes alone: 0 or 1. */
function gapAfterAnchor(form: string, anchorLength: number): number {
  const first = form === 'raw' ? 0 : [0, 2, 3][Number(form.slice(-1))] ?? 0;
  return form === 'raw' || (first + anchorLength) % 4 === 0 ? 0 : 1;
}

/** Every slot of every windowed entry, by digest. */
function slotTable(entries: readonly Entry[]): Map<string, Slot[]> {
  const table = new Map<string, Slot[]>();
  for (const [entry, e] of entries.entries()) {
    if (e.tier !== 'windowed') continue;
    for (let j = 0; j < SLOTS; j += 1) {
      const d = e.slots.subarray(j * DIGEST_BYTES, (j + 1) * DIGEST_BYTES).toString('hex');
      table.set(d, [...(table.get(d) ?? []), { entry, j }]);
    }
  }
  return table;
}

/** The raw offset of view position `start`, or, when the form starts before the view (a fragment), the hit's raw offset minus `j`. */
function rawStart(view: View, hit: Hit): number {
  return view.offsets[hit.at - hit.j] ?? (view.offsets[hit.at] ?? hit.at) - hit.j;
}

export function openShare(envelope: Uint8Array, publicKeyRawB64: string, options: OpenOptions = {}): OpenResult {
  const refuse = (code: Refusal): OpenResult => ({ ok: false, code });
  let outer: unknown;
  try {
    outer = JSON.parse(Buffer.from(envelope).toString('utf8'));
  } catch {
    return refuse('bad_envelope');
  }
  if (!isRecord(outer) || !sameMembers(outer, ['format', 'v', 'body_b64', 'sig_b64']) || outer['format'] !== 'kbox-share' || outer['v'] !== 4) return refuse('bad_envelope');
  const { body_b64: bodyB64, sig_b64: sigB64 } = outer;
  if (typeof bodyB64 !== 'string' || typeof sigB64 !== 'string') return refuse('bad_envelope');
  const bodyBytes = Buffer.from(bodyB64, 'base64');
  const key = createPublicKey({ key: Buffer.concat([SPKI_ED25519, Buffer.from(publicKeyRawB64, 'base64')]), format: 'der', type: 'spki' });
  if (!verify(null, bodyBytes, key, Buffer.from(sigB64, 'base64'))) return refuse('bad_signature');
  let body: unknown;
  try {
    body = JSON.parse(bodyBytes.toString('utf8'));
  } catch {
    return refuse('bad_body');
  }
  if (!isRecord(body) || !sameMembers(body, ['header', 'entries', 'coverage'])) return refuse('bad_body');
  const { header, entries: rawEntries } = body;
  if (!isRecord(header) || !sameMembers(header, HEADER_MEMBERS) || !Array.isArray(rawEntries) || !Array.isArray(body['coverage'])) return refuse('bad_body');
  if (header['v'] !== 4 || header['window'] !== WINDOW || header['slots'] !== SLOTS || header['scan_stride'] !== SCAN_STRIDE) return refuse('bad_body');
  const { version } = header;
  const salt = exactBase64(header['salt_b64'], 32);
  if (typeof version !== 'number' || salt === undefined) return refuse('bad_body');
  const parsed = rawEntries.map(parseEntry);
  const entries = parsed.filter((e): e is Entry => e !== undefined);
  if (entries.length !== parsed.length) return refuse('bad_body');
  if (options.lastVersion !== undefined && version < options.lastVersion) return refuse('rolled_back');
  const table = slotTable(entries);
  const digest = windowSha256(salt);
  const mac = (bytes: Uint8Array): string => createHmac('sha256', salt).update(bytes).digest('hex');

  const scan = (content: Uint8Array): Finding[] => {
    const found = new Map<string, Finding>();
    const report = (index: number, start: number): void => {
      const entry = entries[index];
      if (entry === undefined) return;
      found.set(`${index}:${start}`, { project: entry.project, name: entry.name, gen: entry.gen, retired: entry.retired, form: entry.form, start });
    };
    const joined = lineJoinedView(content);
    for (const hit of sampledHits(joined.bytes, table, digest)) report(hit.entry, rawStart(joined, hit));
    for (const view of [rawView(content), strippedView(content)]) {
      for (const [index, entry] of entries.entries()) {
        if (entry.tier !== 'anchored') continue;
        const anchor = Buffer.from(entry.anchor, 'latin1');
        for (let at = view.bytes.indexOf(anchor); at >= 0; at = view.bytes.indexOf(anchor, at + 1)) {
          const runAt = at + anchor.length + gapAfterAnchor(entry.form, anchor.length);
          const run = view.bytes.subarray(runAt, runAt + entry.len);
          if (run.length === entry.len && mac(run) === entry.digest) report(index, view.offsets[at] ?? at);
        }
      }
    }
    return [...found.values()].sort((a, b) => a.start - b.start || a.name.localeCompare(b.name) || a.form.localeCompare(b.form));
  };
  return { ok: true, share: { version, scan } };
}
