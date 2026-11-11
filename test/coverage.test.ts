// KBOX-18: key formats and watch coverage. The tier of a key comes from the adapter's strict shape check or from box generation,
// never from a pasted value's length. Boundaries, the named formats, the oracle-free properties.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { KeyShape } from '../src/ports/types.ts';
import { ALPHABET_SIZE, assess, tierOfParts } from '../src/pure/coverage.ts';
import type { Origin, TierParts } from '../src/pure/coverage.ts';
import { checkProperty, seedFor } from './kit/index.ts';

const seed = seedFor(process.env);

const parts = (over: Partial<TierParts> = {}): TierParts => ({ prefixLength: 0, alphabetSize: 62, coreLength: 40, random: true, ...over });

const ALPHABETS = {
  hex: '0123456789abcdef',
  base62: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789',
  base64: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/',
  base64url: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_',
} as const;

/** A core of exactly `length` characters of the alphabet, cycling through it so every character class shows. */
const coreOf = (alphabet: keyof typeof ALPHABETS, length: number): string => Array.from({ length }, (_, i) => ALPHABETS[alphabet][(i * 7 + 3) % ALPHABETS[alphabet].length]).join('');

const shape = (over: Partial<KeyShape> = {}): KeyShape => ({ prefix: null, alphabet: 'base62', coreLength: { min: 20, max: 300 }, random: true, ...over });

const tierOf = (s: KeyShape, value: string, origin: Origin = 'pasted'): string => assess({ shape: s, value, origin }).tier;

// ---------------------------------------------------------------- the thresholds, one at a time

test('KBOX-18 a core of 31 characters is not windowed and 32 is; 256 is windowed and 257 is not', () => {
  assert.equal(tierOfParts(parts({ coreLength: 31 })), 'none');
  assert.equal(tierOfParts(parts({ coreLength: 32 })), 'windowed');
  assert.equal(tierOfParts(parts({ coreLength: 256 })), 'windowed');
  assert.equal(tierOfParts(parts({ coreLength: 257 })), 'none');
});

test('KBOX-18 a core over 256 characters is anchored when it qualifies there, else none', () => {
  assert.equal(tierOfParts(parts({ coreLength: 257, prefixLength: 4 })), 'anchored');
  assert.equal(tierOfParts(parts({ coreLength: 257, prefixLength: 3 })), 'none');
});

test('KBOX-18 an alphabet of 15 symbols is not windowed and 16 is', () => {
  assert.equal(tierOfParts(parts({ alphabetSize: 15 })), 'none');
  assert.equal(tierOfParts(parts({ alphabetSize: 16 })), 'windowed');
  assert.equal(tierOfParts(parts({ alphabetSize: 15, prefixLength: 4 })), 'anchored', 'a 15-symbol core of 40 characters is 156 bits: anchored behind a prefix');
});

test('KBOX-18 anchored needs a core of at least 72 bits: 71.45 bits is none, 72 is anchored', () => {
  // 62 symbols: 12 characters are 71.45 bits, 13 are 77.4. 64 symbols: 12 characters are exactly 72 bits.
  assert.equal(tierOfParts(parts({ alphabetSize: 62, coreLength: 12, prefixLength: 4 })), 'none');
  assert.equal(tierOfParts(parts({ alphabetSize: 62, coreLength: 13, prefixLength: 4 })), 'anchored');
  assert.equal(tierOfParts(parts({ alphabetSize: 64, coreLength: 11, prefixLength: 4 })), 'none');
  assert.equal(tierOfParts(parts({ alphabetSize: 64, coreLength: 12, prefixLength: 4 })), 'anchored');
  assert.equal(tierOfParts(parts({ alphabetSize: 16, coreLength: 17, prefixLength: 4 })), 'none', '68 bits');
  assert.equal(tierOfParts(parts({ alphabetSize: 16, coreLength: 18, prefixLength: 4 })), 'anchored', '72 bits');
});

test('KBOX-18 anchored needs a public prefix of at least 4 characters: 3 is none, 4 is anchored', () => {
  assert.equal(tierOfParts(parts({ coreLength: 28, prefixLength: 3 })), 'none');
  assert.equal(tierOfParts(parts({ coreLength: 28, prefixLength: 4 })), 'anchored');
  assert.equal(tierOfParts(parts({ coreLength: 28, prefixLength: 0 })), 'none');
});

test('KBOX-18 a core that is not random is none whatever its length, prefix and alphabet', () => {
  for (const coreLength of [8, 28, 32, 64, 256, 300]) assert.equal(tierOfParts(parts({ coreLength, prefixLength: 7, random: false })), 'none');
});

test('KBOX-18 the alphabet sizes of the four named alphabets', () => {
  assert.deepEqual(ALPHABET_SIZE, { hex: 16, base62: 62, base64: 64, base64url: 64 });
});

// ---------------------------------------------------------------- the real values and the strict shape check

test('KBOX-18 a 28-character GOCSPX- core is anchored, with the prefix and that core', () => {
  const core = coreOf('base64url', 28);
  const a = assess({ shape: shape({ prefix: 'GOCSPX-', alphabet: 'base64url', coreLength: { min: 28, max: 28 } }), value: `GOCSPX-${core}`, origin: 'pasted' });
  assert.deepEqual(a, { tier: 'anchored', prefix: 'GOCSPX-', core });
});

test('KBOX-18 a JWT signature of 43 characters (HS256) is windowed', () => {
  const header = Buffer.from('{"alg":"HS256","typ":"JWT"}').toString('base64url');
  const payload = Buffer.from('{"sub":"1"}').toString('base64url');
  const signature = coreOf('base64url', 43);
  const a = assess({ shape: shape({ alphabet: 'base64url', coreLength: { min: 43, max: 43 } }), value: `${header}.${payload}.${signature}`, origin: 'pasted' });
  assert.equal(a.tier, 'windowed');
  assert.equal(a.tier === 'windowed' ? a.core : '', signature, 'the core is the signature, so no window touches the header or the payload');
});

test('KBOX-18 a prefixed windowed key has the prefix outside its core', () => {
  const core = coreOf('base62', 40);
  const a = assess({ shape: shape({ prefix: 'sb_secret_', coreLength: { min: 40, max: 40 } }), value: `sb_secret_${core}`, origin: 'pasted' });
  assert.deepEqual(a, { tier: 'windowed', prefix: 'sb_secret_', core });
});

test('KBOX-18 the tier of each format the spec names, with a synthetic value of the stated length', () => {
  const table: readonly { readonly label: string; readonly shape: KeyShape; readonly core: number; readonly tier: string }[] = [
    { label: 'Vercel vcp_ at 24 (anchored: 24 x 5.95 = 143 bits)', shape: shape({ prefix: 'vcp_', coreLength: { min: 24, max: 64 } }), core: 24, tier: 'anchored' },
    { label: 'Vercel vcp_ at 32', shape: shape({ prefix: 'vcp_', coreLength: { min: 24, max: 64 } }), core: 32, tier: 'windowed' },
    { label: 'Supabase sb_secret_ at 40', shape: shape({ prefix: 'sb_secret_', coreLength: { min: 20, max: 80 } }), core: 40, tier: 'windowed' },
    { label: 'Supabase sb_secret_ at 22', shape: shape({ prefix: 'sb_secret_', coreLength: { min: 20, max: 80 } }), core: 22, tier: 'anchored' },
    { label: 'a hex key of 64', shape: shape({ alphabet: 'hex', coreLength: { min: 32, max: 64 } }), core: 64, tier: 'windowed' },
    { label: 'a hex key of 16 with no prefix (64 bits, no prefix)', shape: shape({ alphabet: 'hex', coreLength: { min: 16, max: 64 } }), core: 16, tier: 'none' },
    { label: 'a base64 key of 300 behind a 5-character prefix', shape: shape({ prefix: 'sk-xx', alphabet: 'base64', coreLength: { min: 20, max: 400 } }), core: 300, tier: 'anchored' },
  ];
  for (const row of table) {
    const prefix = row.shape.prefix ?? '';
    const alphabet = row.shape.alphabet;
    assert.equal(tierOf(row.shape, prefix + coreOf(alphabet, row.core)), row.tier, row.label);
  }
});

test('KBOX-18 a long human-chosen paste that fails the shape check is none', () => {
  const s = shape({ prefix: 'sk-', alphabet: 'base62', coreLength: { min: 40, max: 60 } });
  const long = `sk-${coreOf('base62', 60)}`;
  assert.equal(tierOf(s, long), 'windowed', 'control: the same shape accepts a value that fits it');
  assert.equal(tierOf(s, `sk-${coreOf('base62', 61)}`), 'none', 'one over the shape\'s longest core');
  assert.equal(tierOf(s, `sk-${coreOf('base62', 39)}`), 'none', 'one under the shape\'s shortest core');
  assert.equal(tierOf(s, `sk-correct horse battery staple ${coreOf('base62', 40)}`), 'none', 'a character outside the alphabet');
  assert.equal(tierOf(s, coreOf('base62', 60)), 'none', 'the prefix is missing');
  assert.equal(tierOf(shape({ coreLength: { min: 8, max: 300 } }), 'Tr0ub4dor&3-and-a-long-human-passphrase-of-many-words-here'), 'none');
});

test('KBOX-18 a pasted value that fits a shape of a non-random format is none however long it is', () => {
  assert.equal(tierOf(shape({ random: false }), coreOf('base62', 100)), 'none');
  assert.equal(tierOf(shape({ random: false }), coreOf('base62', 100), 'generated'), 'none');
});

test('KBOX-18 box generation counts the measured length, a pasted value counts only inside the shape\'s core range', () => {
  const s = shape({ prefix: 'abcd', coreLength: { min: 40, max: 50 } });
  const value = `abcd${coreOf('base62', 100)}`;
  assert.equal(tierOf(s, value, 'pasted'), 'none', 'a pasted 100-character core is outside 40 to 50');
  assert.equal(tierOf(s, value, 'generated'), 'windowed', 'a generated one is measured: an UNVERIFIED range can only move a tier');
  assert.equal(tierOf(s, `abcd${coreOf('base62', 20)}`, 'generated'), 'anchored');
  assert.equal(tierOf(s, `abcd${coreOf('base62', 20)}$`, 'generated'), 'none', 'a generated value still has to be made of the alphabet');
});

test('KBOX-18 a value that is not UTF-8 text, empty, or a URL with a password has no tier', () => {
  const s = shape({ coreLength: { min: 1, max: 300 } });
  assert.equal(tierOf(s, ''), 'none');
  assert.equal(tierOf(s, 'x'), 'none', 'one character is under the forms library\'s minimum core');
  assert.equal(tierOf(s, `postgres://user:${coreOf('base62', 40)}@db.example.com/postgres`), 'none');
});

// ---------------------------------------------------------------- properties

test(`KBOX-18 property: for every shape, the tier steps up with core length to windowed and above 256 only ever drops to anchored or none (seed ${seed})`, () => {
  const rank = { none: 0, anchored: 1, windowed: 2 } as const;
  checkProperty(seed, 60, (rng) => {
    const base = parts({ prefixLength: rng.int(9), alphabetSize: [2, 8, 15, 16, 32, 62, 64][rng.int(7)] ?? 64 });
    let previous = -1;
    for (let coreLength = 1; coreLength <= 256; coreLength += 1) {
      const tier = tierOfParts({ ...base, coreLength });
      assert.ok(rank[tier] >= previous, `the tier fell from rank ${previous} to ${tier} at ${coreLength}`);
      previous = rank[tier];
    }
    for (let coreLength = 257; coreLength <= 400; coreLength += 7) {
      const tier = tierOfParts({ ...base, coreLength });
      assert.notEqual(tier, 'windowed', `${coreLength} characters are never windowed`);
      assert.equal(tier, base.prefixLength >= 4 ? 'anchored' : 'none');
    }
  });
});

test(`KBOX-18 property: the tier depends on the measured core, never on the pasted value's total length (seed ${seed})`, () => {
  checkProperty(seed, 40, (rng) => {
    const s = shape({ prefix: 'abcd', coreLength: { min: 30, max: 60 } });
    const length = 32 + rng.int(29);
    const core = coreOf('base62', length);
    const plain = assess({ shape: s, value: `abcd${core}`, origin: 'pasted' });
    assert.equal(plain.tier, 'windowed');
    for (const tail of ['', ' ', '\n', '!'.repeat(rng.int(200) + 1)]) {
      const longer = assess({ shape: s, value: `abcd${core}${tail}`, origin: 'pasted' }).tier;
      assert.equal(longer, tail === '' ? 'windowed' : 'none', 'a value that no longer fits the shape is none, however long');
    }
  });
});
