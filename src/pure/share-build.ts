// KBOX-33: the share file, format v4, built from a store of admin and master key values: what the workstation's leak scanner reads.
// The body is JSON {header, entries, coverage}; the envelope {format, v, body_b64, sig_b64} carries an Ed25519 signature over the
// exact decoded body bytes. Read this before changing anything: the file is public, so what it shows is the whole contract.
//
//  - A windowed entry (a random core of 32 to 256 characters) has seven entries, one per form, each with `probes_b64`: exactly 320
//    slots of 32 bytes. Slot j holds SHA-256(salt ‖ form[j:j+24]) for EVERY window of the form (j + 24 <= its length), so a matcher
//    may hash only the input positions at multiples of `scan_stride` (9) and still meet every copy of at least 32 characters. Every
//    other slot is 32 random bytes (a decoy, the same shape), so the slot count and the size of the file do not depend on the key's
//    length, and no `len` member exists on a windowed entry. A window lies wholly inside the core: never a prefix, a JWT header or
//    a payload.
//  - An anchored entry (a core of at least 72 bits behind a public prefix of 4 or more characters) is `anchor`, the characters of
//    the prefix as the form spells them, then `digest`, the HMAC of the `len` characters that core bytes alone fix. Between the two
//    a base64 form has 0 or 1 characters that mix prefix and core bits and are skipped: 1 unless (alignment + prefix bytes) is a
//    multiple of 3. `len` and the prefix are the only value-derived text in the file (KBOX-2's declared exception).
//  - Window slots and `digest` are keyed by this version's salt; the salt is new for every version.
import { createHash, createHmac } from 'node:crypto';
import type { Coverage } from '../ports/meta.ts';
import type { Random } from '../ports/random.ts';
import type { KeyShape } from '../ports/types.ts';
import { assess } from './coverage.ts';
import type { Origin } from './coverage.ts';
import { base64Interior, shareForms } from './forms.ts';
import type { FormName } from './forms.ts';

export const SHARE_FORMAT = 'kbox-share';
export const SHARE_V = 4;
/** The characters a window digest covers. */
export const WINDOW = 24;
/** Window slots per windowed entry, in every file: the largest windowed form (342 characters) has 319 windows. */
export const SLOTS = 320;
/** The largest input stride at which a matcher still meets a window of every windowed copy: a 32-character core has 9 window starts. */
export const SCAN_STRIDE = 9;
const SLOT_BYTES = 32;
const SALT_BYTES = 32;

export type ShareFormName = 'raw' | 'b64s0' | 'b64s1' | 'b64s2' | 'b64u0' | 'b64u1' | 'b64u2';

interface FormSpec {
  readonly name: ShareFormName;
  readonly source: FormName;
  /** The byte offset (mod 3) the core, or for an anchored entry the whole value, starts at. */
  readonly alignment: 0 | 1 | 2;
  readonly url: boolean;
}

/** The closed list, in file order: raw, then the standard and the url interiors at alignments 0 to 2. */
const FORMS: readonly FormSpec[] = [
  { name: 'raw', source: 'raw', alignment: 0, url: false },
  { name: 'b64s0', source: 'b64-0', alignment: 0, url: false },
  { name: 'b64s1', source: 'b64-1', alignment: 1, url: false },
  { name: 'b64s2', source: 'b64-2', alignment: 2, url: false },
  { name: 'b64u0', source: 'b64url-0', alignment: 0, url: true },
  { name: 'b64u1', source: 'b64url-1', alignment: 1, url: true },
  { name: 'b64u2', source: 'b64url-2', alignment: 2, url: true },
];

export interface ShareKey {
  readonly project: string;
  readonly name: string;
  readonly gen: number;
  readonly retired: boolean;
  /** The adapter's shape; none: not watched. */
  readonly shape: KeyShape | undefined;
  readonly origin: Origin;
  readonly value: string;
}

export interface BuildInput {
  readonly version: number;
  /** Milliseconds since the Unix epoch. */
  readonly issuedAt: number;
  readonly random: Random;
  readonly keys: readonly ShareKey[];
}

export interface WindowedEntry {
  readonly project: string;
  readonly name: string;
  readonly gen: number;
  readonly retired: boolean;
  readonly tier: 'windowed';
  readonly form: ShareFormName;
  /** Base64 of exactly SLOTS × 32 bytes: the window slots. */
  readonly probes_b64: string;
}
export interface AnchoredEntry {
  readonly project: string;
  readonly name: string;
  readonly gen: number;
  readonly retired: boolean;
  readonly tier: 'anchored';
  readonly form: ShareFormName;
  readonly anchor: string;
  readonly len: number;
  readonly digest: string;
}
export interface CoverageItem {
  readonly project: string;
  readonly name: string;
  readonly gen: number;
  readonly tier: Coverage;
}
export interface ShareBody {
  readonly header: {
    readonly v: typeof SHARE_V;
    readonly version: number;
    readonly issued_at: number;
    readonly salt_b64: string;
    readonly set_id: string;
    readonly window: typeof WINDOW;
    readonly slots: typeof SLOTS;
    readonly scan_stride: typeof SCAN_STRIDE;
  };
  readonly entries: readonly (WindowedEntry | AnchoredEntry)[];
  readonly coverage: readonly CoverageItem[];
}

export interface Built {
  readonly body: ShareBody;
  /** The exact bytes that are signed. */
  readonly bytes: Uint8Array;
  /** Equal for two builds exactly when a reader would see the same generations at the same tiers (what makes a new version). */
  readonly contentKey: string;
}

/** HMAC-SHA256 of `bytes` under `salt`, as lower-case hex: an anchored entry's `digest` (the name predates v4's SHA-256 windows). */
export const windowDigest = (salt: Uint8Array, bytes: Uint8Array): string => createHmac('sha256', salt).update(bytes).digest('hex');

/** SHA-256(salt ‖ window): a window slot. The salt is public, so a keyed MAC would add nothing over the salt prefix. */
export const windowProbe = (salt: Uint8Array, bytes: Uint8Array): Buffer => createHash('sha256').update(salt).update(bytes).digest();

const hex = (bytes: Uint8Array): string => Buffer.from(bytes).toString('hex');
const compare = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);
const utf8 = new TextEncoder();
const latin1 = (bytes: Uint8Array): string => Buffer.from(bytes).toString('latin1');

const order = (a: ShareKey, b: ShareKey): number => compare(a.project, b.project) || compare(a.name, b.name) || a.gen - b.gen || Number(a.retired) - Number(b.retired);

type Plan = { readonly tier: 'none' } | { readonly tier: 'windowed'; readonly forms: ReadonlyMap<FormName, Uint8Array> } | { readonly tier: 'anchored'; readonly prefix: string; readonly core: string };

/** The tier of a key from its shape and value, with what the entries need; a value the forms library refuses is not watched. */
function plan(key: ShareKey): Plan {
  if (key.shape === undefined) return { tier: 'none' };
  const assessed = assess({ shape: key.shape, value: key.value, origin: key.origin });
  if (assessed.tier === 'none') return { tier: 'none' };
  const result = shareForms(key.value, assessed.prefix === '' ? {} : { prefix: assessed.prefix });
  if (!result.ok) return { tier: 'none' };
  if (assessed.tier === 'anchored') return { tier: 'anchored', prefix: assessed.prefix, core: assessed.core };
  return { tier: 'windowed', forms: new Map(result.forms.filter((f) => f.core === 'written').map((f) => [f.name, f.bytes])) };
}

function anchoredEntry(key: ShareKey, prefix: string, core: string, spec: FormSpec, salt: Uint8Array): AnchoredEntry {
  const prefixBytes = utf8.encode(prefix);
  const coreBytes = utf8.encode(core);
  const base = { project: key.project, name: key.name, gen: key.gen, retired: key.retired, tier: 'anchored', form: spec.name } as const;
  if (spec.name === 'raw') return { ...base, anchor: prefix, len: coreBytes.length, digest: windowDigest(salt, coreBytes) };
  const run = base64Interior(coreBytes, (spec.alignment + prefixBytes.length) % 3, spec.url);
  if (run.length === 0) throw new RangeError('an anchored core has no characters of its own in a form');
  return { ...base, anchor: latin1(base64Interior(prefixBytes, spec.alignment, spec.url)), len: run.length, digest: windowDigest(salt, run) };
}

/**
 * The SLOTS window slots of one windowed entry: slot j is the probe of form[j:j+24] for every window of the form, every other slot 32
 * random bytes. A window whose digest is already in the file (the standard and the url interior are the same text when a window holds
 * no `+`, `/`, `-` or `_`) becomes a decoy: two equal digests would show a reader which slots hold a real window, and so how long the
 * key is. The scanner still finds the copy through the first of the two. A form with more windows than slots is refused.
 */
export function windowedSlots(form: Uint8Array, salt: Uint8Array, random: Random, used: Set<string>): Uint8Array {
  if (form.length - WINDOW + 1 > SLOTS) throw new RangeError('a windowed form has more windows than the file has slots');
  const slots = new Uint8Array(SLOTS * SLOT_BYTES);
  for (let j = 0; j < SLOTS; j += 1) {
    const real = j + WINDOW <= form.length ? windowProbe(salt, form.subarray(j, j + WINDOW)) : undefined;
    const slot = real !== undefined && !used.has(hex(real)) ? real : random.bytes(SLOT_BYTES);
    if (slot.length !== SLOT_BYTES) throw new RangeError('a random draw is not the size asked for');
    used.add(hex(slot));
    slots.set(slot, j * SLOT_BYTES);
  }
  return slots;
}

export function buildShare(input: BuildInput): Built {
  const keys = [...input.keys].sort(order);
  for (const [i, key] of keys.entries()) {
    const before = keys[i - 1];
    if (before !== undefined && order(before, key) === 0) throw new RangeError('a share file holds one entry per project, name, generation and retirement');
  }
  const salt = input.random.bytes(SALT_BYTES);
  const entries: (WindowedEntry | AnchoredEntry)[] = [];
  const coverage: CoverageItem[] = [];
  // Every slot digest written so far, as hex: no digest appears twice in a file.
  const usedSlots = new Set<string>();
  for (const key of keys) {
    const planned = plan(key);
    coverage.push({ project: key.project, name: key.name, gen: key.gen, tier: planned.tier });
    const identity = { project: key.project, name: key.name, gen: key.gen, retired: key.retired };
    if (planned.tier === 'windowed') {
      for (const spec of FORMS) {
        const form = planned.forms.get(spec.source);
        if (form === undefined) throw new RangeError('a windowed key is missing a form');
        const slots = windowedSlots(form, salt, input.random, usedSlots);
        entries.push({ ...identity, tier: 'windowed', form: spec.name, probes_b64: Buffer.from(slots).toString('base64') });
      }
    } else if (planned.tier === 'anchored') {
      for (const spec of FORMS) entries.push(anchoredEntry(key, planned.prefix, planned.core, spec, salt));
    }
  }
  const setId = createHash('sha256').update(JSON.stringify(keys.map((k) => [k.project, k.name, k.gen, k.retired]))).digest('hex');
  const body: ShareBody = {
    header: { v: SHARE_V, version: input.version, issued_at: input.issuedAt, salt_b64: Buffer.from(salt).toString('base64'), set_id: setId, window: WINDOW, slots: SLOTS, scan_stride: SCAN_STRIDE },
    entries,
    coverage,
  };
  return { body, bytes: utf8.encode(JSON.stringify(body)), contentKey: `${setId}:${JSON.stringify(coverage)}` };
}

/** The envelope as written: compact JSON, the signature over the exact bytes `bodyBytes`. */
export function sealEnvelope(bodyBytes: Uint8Array, signature: Uint8Array): Uint8Array {
  return utf8.encode(JSON.stringify({ format: SHARE_FORMAT, v: SHARE_V, body_b64: Buffer.from(bodyBytes).toString('base64'), sig_b64: Buffer.from(signature).toString('base64') }));
}

/** What the writer needs of a file already on disk: its version, what it covered, and the signed bytes with their signature. */
export interface FileSummary {
  readonly version: number;
  readonly contentKey: string;
  readonly body: Uint8Array;
  readonly signature: Uint8Array;
}

type Json = { readonly ok: true; readonly value: unknown } | { readonly ok: false };

const parseJson = (text: string): Json => {
  try {
    return { ok: true, value: JSON.parse(text) };
  } catch {
    return { ok: false };
  }
};

const member = (value: unknown, name: string): unknown => (typeof value === 'object' && value !== null && name in value ? (value as Record<string, unknown>)[name] : undefined);

/** The summary of a share envelope, or undefined for anything that is not one. The signature is NOT checked here. */
export function summaryOf(envelope: Uint8Array): FileSummary | undefined {
  const outer = parseJson(Buffer.from(envelope).toString('utf8'));
  const bodyB64 = outer.ok ? member(outer.value, 'body_b64') : undefined;
  const sigB64 = outer.ok ? member(outer.value, 'sig_b64') : undefined;
  if (typeof bodyB64 !== 'string' || typeof sigB64 !== 'string') return undefined;
  const bodyBytes = Buffer.from(bodyB64, 'base64');
  const body = parseJson(bodyBytes.toString('utf8'));
  const header = body.ok ? member(body.value, 'header') : undefined;
  const version = member(header, 'version');
  const setId = member(header, 'set_id');
  if (!body.ok || typeof version !== 'number' || !Number.isSafeInteger(version) || typeof setId !== 'string') return undefined;
  return { version, contentKey: `${setId}:${JSON.stringify(member(body.value, 'coverage'))}`, body: bodyBytes, signature: Buffer.from(sigB64, 'base64') };
}
