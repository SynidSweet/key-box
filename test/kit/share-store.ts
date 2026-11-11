// Synthetic stores for the share-file tests (KBOX-33, KBOX-18): fake keys of chosen length and shape, copies of them planted in
// documents the way a leak makes them (raw, base64 at each alignment, wrapped), decoys that are NOT copies, and a signer.
import { createPrivateKey, createPublicKey, sign } from 'node:crypto';
import type { KeyShape } from '../../src/ports/types.ts';
import type { Origin } from '../../src/pure/coverage.ts';
import type { SeededRandom } from './random.ts';

export const ALPHABET_CHARS = {
  hex: '0123456789abcdef',
  base62: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789',
  base64: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/',
  base64url: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_',
} as const;

export interface FakeKey {
  readonly project: string;
  readonly name: string;
  readonly gen: number;
  readonly retired: boolean;
  readonly shape: KeyShape;
  readonly origin: Origin;
  /** The whole value: prefix and core, or a JWT. */
  readonly value: string;
  /** The part of the value no window may leak: for a JWT the signature, else what follows the prefix. */
  readonly core: string;
}

export const randomCore = (rng: SeededRandom, alphabet: keyof typeof ALPHABET_CHARS, length: number): string =>
  Array.from({ length }, () => ALPHABET_CHARS[alphabet][rng.int(ALPHABET_CHARS[alphabet].length)]).join('');

export interface FakeKeyOptions {
  readonly project?: string;
  readonly gen?: number;
  readonly retired?: boolean;
  readonly alphabet?: keyof typeof ALPHABET_CHARS;
  readonly prefix?: string | null;
  readonly origin?: Origin;
  readonly random?: boolean;
}

/** A key whose shape accepts exactly this core length. */
export function fakeKey(rng: SeededRandom, name: string, coreLength: number, options: FakeKeyOptions = {}): FakeKey {
  const alphabet = options.alphabet ?? 'base62';
  const prefix = options.prefix === undefined ? null : options.prefix;
  const core = randomCore(rng, alphabet, coreLength);
  return {
    project: options.project ?? 'proj',
    name,
    gen: options.gen ?? 1,
    retired: options.retired ?? false,
    shape: { prefix, alphabet, coreLength: { min: coreLength, max: coreLength }, random: options.random ?? true },
    origin: options.origin ?? 'pasted',
    value: `${prefix ?? ''}${core}`,
    core,
  };
}

/** A JWT (HS256) with a random signature of 43 characters; the header and payload are public. */
export function fakeJwt(rng: SeededRandom, name: string, options: FakeKeyOptions = {}): FakeKey {
  // `typ` first: the gate's secret scan flags the `{"alg"` header base64 followed by a long run, and these values are fake.
  const header = Buffer.from('{"typ":"JWT","alg":"HS256"}').toString('base64url');
  const payload = Buffer.from('{"iss":"supabase","role":"service_role"}').toString('base64url');
  const core = randomCore(rng, 'base64url', 43);
  return {
    project: options.project ?? 'proj',
    name,
    gen: options.gen ?? 1,
    retired: options.retired ?? false,
    shape: { prefix: null, alphabet: 'base64url', coreLength: { min: 43, max: 43 }, random: true },
    origin: options.origin ?? 'pasted',
    value: `${header}.${payload}.${core}`,
    core,
  };
}

// ---------------------------------------------------------------- planting a copy

/** The copy inside text, so a raw scan sees it. */
export const rawDocument = (value: string): Uint8Array => Buffer.from(`token=${value}\nnext line\n`, 'utf8');

export interface Wrap {
  readonly columns: number;
  readonly lineBreak: '\n' | '\r\n';
}

/** Base64 (standard or url) of a document that carries the value at byte offset `alignment` mod 3, optionally wrapped. */
export function base64Document(value: string, alignment: 0 | 1 | 2, url: boolean, wrap?: Wrap): Uint8Array {
  const document = Buffer.concat([Buffer.alloc(3 + alignment, 0x2d), Buffer.from(value, 'utf8'), Buffer.from(';end', 'utf8')]);
  const encoded = document.toString(url ? 'base64url' : 'base64');
  if (wrap === undefined) return Buffer.from(encoded, 'utf8');
  const lines: string[] = [];
  for (let i = 0; i < encoded.length; i += wrap.columns) lines.push(encoded.slice(i, i + wrap.columns));
  return Buffer.from(lines.join(wrap.lineBreak), 'utf8');
}

// ---------------------------------------------------------------- decoys

const flip = (char: string, mask: number): string => String.fromCharCode(char.charCodeAt(0) ^ mask);

/**
 * A value that is not a copy: the core differs at interior bytes only (index 2, 7, 12, ... up to the third from last), so that every
 * 24-character window of every form has at least one changed byte, and the first and last two bytes stay as they are.
 * A decoy that changes only the first or last byte is still found: base64 interiors at some alignment do not hold those bytes' bits.
 */
export function interiorDecoy(key: FakeKey): string {
  const chars = [...key.core];
  for (let i = 2; i < chars.length - 2; i += 5) chars[i] = flip(chars[i] ?? 'a', 0x01);
  return key.value.slice(0, key.value.length - key.core.length) + chars.join('');
}

/** The same core with only its first and last byte changed (bit 6 of the first, bit 0 of the last). */
export function edgeOnlyDecoy(key: FakeKey): string {
  const chars = [...key.core];
  chars[0] = flip(chars[0] ?? 'a', 0x40);
  chars[chars.length - 1] = flip(chars[chars.length - 1] ?? 'a', 0x01);
  return key.value.slice(0, key.value.length - key.core.length) + chars.join('');
}

// ---------------------------------------------------------------- signing

export interface TestSigner {
  readonly publicKeyRawB64: string;
  sign(body: Uint8Array): Uint8Array;
}

const PKCS8_ED25519_SEED = Buffer.from('302e020100300506032b657004220420', 'hex');

export function signerFromSeed(seed: Uint8Array): TestSigner {
  const privateKey = createPrivateKey({ key: Buffer.concat([PKCS8_ED25519_SEED, Buffer.from(seed)]), format: 'der', type: 'pkcs8' });
  const spki = createPublicKey(privateKey).export({ format: 'der', type: 'spki' });
  return { publicKeyRawB64: Buffer.from(spki.subarray(spki.length - 32)).toString('base64'), sign: (body) => sign(null, Buffer.from(body), privateKey) };
}
