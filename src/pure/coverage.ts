// KBOX-18: the watch tier of a key, from the adapter's shape and the value itself. Windowed: a random core of 32 to 256
// characters over an alphabet of at least 16 symbols (every 24-character window of every shared form then holds at least 72
// bits). Anchored: a random core of at least 72 bits behind a fixed public prefix of at least 4 characters. Everything else is
// not watched. The 72 bits are counted over each digested run itself, in every shared form and alignment (KBOX-2), not over the
// whole core. Eligibility comes from the strict shape check or from box generation, never from a pasted value's length.
import type { Coverage } from '../ports/meta.ts';
import type { Alphabet, KeyShape } from '../ports/types.ts';
import { base64InteriorSpan, coresOf } from './forms.ts';

export const WINDOWED_MIN_CORE = 32;
export const WINDOWED_MAX_CORE = 256;
export const WINDOWED_MIN_ALPHABET = 16;
export const ANCHORED_MIN_BITS = 72;
export const ANCHORED_MIN_PREFIX = 4;

const SYMBOLS: Readonly<Record<Alphabet, string>> = {
  hex: '0123456789abcdef',
  base62: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789',
  base64: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/',
  base64url: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_',
};

export const ALPHABET_SIZE: Readonly<Record<Alphabet, number>> = { hex: SYMBOLS.hex.length, base62: SYMBOLS.base62.length, base64: SYMBOLS.base64.length, base64url: SYMBOLS.base64url.length };

/** The spellings a core of the alphabet may use: hex keys come in either case. */
const spellings = (alphabet: Alphabet): readonly string[] => (alphabet === 'hex' ? [SYMBOLS.hex, SYMBOLS.hex.toUpperCase()] : [SYMBOLS[alphabet]]);

const ALPHABET_CHARS: Readonly<Record<Alphabet, RegExp>> = {
  hex: /^[0-9a-fA-F]+$/,
  base62: /^[A-Za-z0-9]+$/,
  base64: /^[A-Za-z0-9+/]+$/,
  base64url: /^[A-Za-z0-9_-]+$/,
};

/** The numbers a tier is decided on. */
export interface TierParts {
  readonly prefixLength: number;
  readonly alphabetSize: number;
  readonly coreLength: number;
  readonly random: boolean;
}

export function tierOfParts(p: TierParts): Coverage {
  if (!p.random) return 'none';
  if (p.coreLength >= WINDOWED_MIN_CORE && p.coreLength <= WINDOWED_MAX_CORE && p.alphabetSize >= WINDOWED_MIN_ALPHABET) return 'windowed';
  if (p.prefixLength >= ANCHORED_MIN_PREFIX && p.coreLength * Math.log2(p.alphabetSize) >= ANCHORED_MIN_BITS) return 'anchored';
  return 'none';
}

/** Bits of a symbol's byte at bit positions `lo` to `hi` (exclusive, 0 = the top bit): log2 of how many values they take over the symbols. */
function fieldBits(symbols: string, lo: number, hi: number): number {
  const mask = 2 ** (hi - lo) - 1;
  return Math.log2(new Set([...symbols].map((c) => (c.charCodeAt(0) >> (8 - hi)) & mask)).size);
}

/** The bits a run holds when it covers bits `startBit` to `endBit` of a core whose every byte is one symbol drawn at random. */
function coveredBits(symbols: string, startBit: number, endBit: number): number {
  let bits = 0;
  for (let byte = Math.floor(startBit / 8); byte * 8 < endBit; byte += 1) {
    const lo = Math.max(startBit - byte * 8, 0);
    const hi = Math.min(endBit - byte * 8, 8);
    bits += lo === 0 && hi === 8 ? Math.log2(symbols.length) : fieldBits(symbols, lo, hi);
  }
  return bits;
}

/**
 * The fewest random bits any digested run of an anchored core holds: the core itself in the raw form, and the base64 characters
 * that core bytes alone fix at each of the three alignments (the standard and the url-safe form spell the same bits).
 */
export function anchoredRunBits(alphabet: Alphabet, coreLength: number): number {
  const spans = [0, 1, 2].map((alignment) => base64InteriorSpan(coreLength, alignment));
  return Math.min(...spellings(alphabet).flatMap((symbols) => [coveredBits(symbols, 0, 8 * coreLength), ...spans.map((span) => coveredBits(symbols, span.startBit, span.endBit))]));
}

/** `generated`: the box made the value (an UNVERIFIED length range can only move a tier). `pasted`: it must fit the shape's core range. */
export type Origin = 'generated' | 'pasted';

export interface AssessInput {
  readonly shape: KeyShape;
  readonly value: string;
  readonly origin: Origin;
}

/** `prefix` is the public prefix declared by the shape ('' for none); `core` is what follows it, or a JWT's signature. */
export type Assessment = { readonly tier: 'none' } | { readonly tier: 'windowed' | 'anchored'; readonly prefix: string; readonly core: string };

const NONE: Assessment = { tier: 'none' };

/**
 * The one core of a value that fits the shape, or undefined. A shape with no prefix takes the whole value or a JWT's signature,
 * and nothing else (a URL's password, or a value that begins with a prefix the shape does not declare, has no tier).
 */
function coreFitting(shape: KeyShape, value: string): string | undefined {
  const cores = coresOf(value, shape.prefix === null ? {} : { prefix: shape.prefix });
  const [core] = cores;
  if (cores.length !== 1 || core === undefined || core === '') return undefined;
  if (shape.prefix !== null) return value.startsWith(shape.prefix) && core === value.slice(shape.prefix.length) ? core : undefined;
  return core === value || value.endsWith(`.${core}`) ? core : undefined;
}

export function assess(input: AssessInput): Assessment {
  const { shape, value, origin } = input;
  if (!shape.random) return NONE;
  const core = coreFitting(shape, value);
  if (core === undefined || !ALPHABET_CHARS[shape.alphabet].test(core)) return NONE;
  if (origin === 'pasted' && (core.length < shape.coreLength.min || core.length > shape.coreLength.max)) return NONE;
  const prefix = shape.prefix ?? '';
  const tier = tierOfParts({ prefixLength: prefix.length, alphabetSize: ALPHABET_SIZE[shape.alphabet], coreLength: core.length, random: true });
  if (tier === 'none') return NONE;
  if (tier === 'anchored' && anchoredRunBits(shape.alphabet, core.length) < ANCHORED_MIN_BITS) return NONE;
  return { tier, prefix, core };
}
