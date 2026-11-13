// KBOX-33 revision 4: the share file, format v4. Every 24-character window of each form sits in one of 320 fixed slots per windowed
// entry, as SHA-256(salt ‖ window), padded with random decoys, so a matcher may hash only one input position in `scan_stride` and
// still meet every copy. The oracle is a reference matcher that SAMPLES (test/kit/sampling-matcher.ts): it never steps by one, so a
// file that thins its windows (v3) fails here. Forms are computed in this file from the base64 definition, not by src/pure/forms.ts.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import type { Random } from '../src/ports/random.ts';
import { buildShare, sealEnvelope, windowedSlots } from '../src/pure/share-build.ts';
import { seedFor, seededRandom } from './kit/index.ts';
import type { SeededRandom } from './kit/index.ts';
import { SCAN_STRIDE, WINDOW, openShare, sampledHits, windowSha256 } from './kit/sampling-matcher.ts';
import type { Finding, Slot } from './kit/sampling-matcher.ts';
import { GOLDEN, GOLDEN_SIGNING_SEED_HEX, goldenKeys, toShareKey } from './kit/share-golden.ts';
import { fakeKey, randomCore, signerFromSeed } from './kit/share-store.ts';
import type { FakeKey } from './kit/share-store.ts';

const seed = seedFor(process.env);
const SLOTS = 320;
const SLOT_BYTES = 32;
const FORM_NAMES = ['raw', 'b64s0', 'b64s1', 'b64s2', 'b64u0', 'b64u1', 'b64u2'] as const;
type FormName = (typeof FORM_NAMES)[number];

// ---------------------------------------------------------------- building and reading a file

interface WindowedEntry {
  readonly name: string;
  readonly tier: string;
  readonly form: string;
  readonly probes_b64?: string;
  readonly digest?: string;
}
interface Body {
  readonly header: Record<string, unknown>;
  readonly entries: readonly WindowedEntry[];
}
interface File {
  readonly envelope: Uint8Array;
  readonly bodyBytes: Buffer;
  readonly body: Body;
  readonly publicKey: string;
  readonly salt: Buffer;
}

function fileOver(keys: readonly FakeKey[], random: Random): File {
  const signer = signerFromSeed(Buffer.from(GOLDEN_SIGNING_SEED_HEX, 'hex'));
  const built = buildShare({ version: 1, issuedAt: GOLDEN.issuedAt, random, keys: keys.map(toShareKey) });
  const envelope = sealEnvelope(built.bytes, signer.sign(built.bytes));
  const outer = JSON.parse(Buffer.from(envelope).toString('utf8')) as { body_b64: string };
  const bodyBytes = Buffer.from(outer.body_b64, 'base64');
  const body = JSON.parse(bodyBytes.toString('utf8')) as Body;
  return { envelope, bodyBytes, body, publicKey: signer.publicKeyRawB64, salt: Buffer.from(String(body.header['salt_b64']), 'base64') };
}

/** A Random whose first draw is `salt` (buildShare draws the salt first; each test asserts the header shows it), then `rest`. */
function saltFirst(salt: Uint8Array, rest: SeededRandom): Random {
  let first = true;
  return {
    bytes(n) {
      if (!first) return rest.bytes(n);
      first = false;
      if (n !== salt.length) throw new RangeError(`the first draw is the ${salt.length}-byte salt, not ${n} bytes`);
      return Uint8Array.from(salt);
    },
  };
}

/** The 320 slots of an entry, each 32 bytes, as hex. */
function slotsOf(entry: WindowedEntry | undefined): string[] {
  if (entry?.probes_b64 === undefined) throw new RangeError('not a windowed entry');
  const bytes = Buffer.from(entry.probes_b64, 'base64');
  return Array.from({ length: bytes.length / SLOT_BYTES }, (_, j) => bytes.subarray(j * SLOT_BYTES, (j + 1) * SLOT_BYTES).toString('hex'));
}

/** The seven forms of a prefix-less core, from the base64 definition: the characters fixed by core bytes alone at alignment a. */
function formsOf(core: string): Record<FormName, string> {
  const interior = (a: 0 | 1 | 2, url: boolean): string =>
    Buffer.concat([Buffer.alloc(a), Buffer.from(core)])
      .toString(url ? 'base64url' : 'base64')
      .slice(Math.ceil((8 * a) / 6), Math.floor((8 * (a + core.length)) / 6));
  return { raw: core, b64s0: interior(0, false), b64s1: interior(1, false), b64s2: interior(2, false), b64u0: interior(0, true), b64u1: interior(1, true), b64u2: interior(2, true) };
}

const filler = (rng: SeededRandom, length: number): string => randomCore(rng, 'base64', length);

/**
 * `text[s, s + length)` between fillers of `before` and `after` characters, the filler characters next to it chosen unlike the form's
 * own neighbours, so random filler never extends the fragment by a character (which would add a window).
 */
function plantFragment(rng: SeededRandom, text: string, s: number, length: number, before: number, after: number): Buffer {
  const unlike = (char: string | undefined): string => {
    for (;;) {
      const drawn = filler(rng, 1);
      if (drawn !== char) return drawn;
    }
  };
  return Buffer.from(filler(rng, before - 1) + unlike(text[s - 1]) + text.slice(s, s + length) + unlike(text[s + length]) + filler(rng, after - 1));
}

function opened(file: File): (content: Uint8Array) => Finding[] {
  const result = openShare(file.envelope, file.publicKey);
  assert.ok(result.ok, `the sampling matcher opens the file: ${result.ok ? '' : result.code}`);
  return result.share.scan;
}

const startsOf = (found: readonly Finding[], name: string): number[] => [...new Set(found.filter((f) => f.name === name).map((f) => f.start))];

// ---------------------------------------------------------------- 1. the sampling contract

test(`KBOX-33 sampling contract: a matcher hashing only offsets at multiples of scan_stride finds every form of a 32- and a 256-character core planted at 9 consecutive offsets exactly once, at its start, while the same sampler over the v3 layout finds 1 of 9 (seed ${seed})`, () => {
  const rng = seededRandom(seed);
  for (const length of [32, 256]) {
    const key = fakeKey(rng, `CORE_${length}`, length);
    const file = fileOver([key], seededRandom(rng.int(1e6)));
    const scan = opened(file);
    const digest = windowSha256(file.salt);
    for (const [form, text] of Object.entries(formsOf(key.core))) {
      // The v3 control: windows only at j = 0, 9, 18, ... (what v3 published), read by the same sampler.
      const v3 = new Map<string, Slot[]>();
      for (let j = 0; j + WINDOW <= text.length; j += SCAN_STRIDE) v3.set(digest(Buffer.from(text.slice(j, j + WINDOW))), [{ entry: 0, j }]);
      let v3Found = 0;
      for (let k = 0; k < SCAN_STRIDE; k += 1) {
        const at = 100 + k;
        const content = Buffer.from(filler(rng, at) + text + filler(rng, 50));
        assert.deepEqual(startsOf(scan(content), key.name), [at], `${length}-character core, ${form} planted at ${at}: found once, at its start`);
        let calls = 0;
        const counted = (window: Uint8Array): string => {
          calls += 1;
          return digest(window);
        };
        if (sampledHits(content, v3, counted).some((hit) => hit.at - hit.j === at)) v3Found += 1;
        assert.ok(calls <= Math.ceil(content.length / SCAN_STRIDE), `the sampler hashed ${calls} windows of ${content.length} bytes: it must not step by one`);
      }
      assert.equal(v3Found, 1, `${length}-character core, ${form}: the v3 layout under a sampling matcher is found at exactly 1 of 9 offsets`);
    }
  }
});

// ---------------------------------------------------------------- 2. fragments

test(`KBOX-33 a 32-character fragment of any form, cut at any offset of the form and planted at any offset mod 9, is found at the form's start (seed ${seed})`, () => {
  const rng = seededRandom(seed + 1);
  const key = fakeKey(rng, 'LONG', 256);
  const scan = opened(fileOver([key], seededRandom(rng.int(1e6))));
  for (const [form, text] of Object.entries(formsOf(key.core))) {
    for (let s = 0; s + 32 <= text.length; s += 1) {
      for (let r = 0; r < SCAN_STRIDE; r += 1) {
        const before = SCAN_STRIDE + r;
        const content = Buffer.from(filler(rng, before) + text.slice(s, s + 32) + filler(rng, 10));
        assert.ok(startsOf(scan(content), key.name).includes(before - s), `${form}: fragment at ${s}, planted at ${before}`);
      }
    }
  }
});

test(`KBOX-33 stated limit: a fragment of L = 24 to 31 characters planted at 9 consecutive offsets is found at exactly L - 23 of them (seed ${seed})`, () => {
  const rng = seededRandom(seed + 2);
  const key = fakeKey(rng, 'LIMIT', 64);
  const scan = opened(fileOver([key], seededRandom(rng.int(1e6))));
  for (const [form, text] of Object.entries(formsOf(key.core))) {
    for (let length = 24; length <= 31; length += 1) {
      const s = rng.int(text.length - length + 1);
      let found = 0;
      for (let k = 0; k < SCAN_STRIDE; k += 1) {
        const before = 20 + k;
        if (startsOf(scan(plantFragment(rng, text, s, length, before, 10)), key.name).includes(before - s)) found += 1;
      }
      assert.equal(found, length - 23, `${form}: a ${length}-character fragment`);
    }
  }
});

// ---------------------------------------------------------------- 3. constant shape

const shapeOf = (v: unknown): unknown => {
  if (typeof v === 'string') return `s${v.length}`;
  if (typeof v === 'number') return `n${String(v).length}`;
  if (typeof v === 'boolean' || v === null) return v;
  if (Array.isArray(v)) return v.map(shapeOf);
  return Object.fromEntries(Object.entries(v as Record<string, unknown>).map(([k, x]) => [k, shapeOf(x)]));
};

test('KBOX-33 constant shape: for cores of 32, 64 and 256 characters every windowed probes_b64 is exactly 10,240 bytes, bodies and envelopes are the same size, and the closed schema has no len, probes or stride', () => {
  const files = [32, 64, 256].map((length) => fileOver([fakeKey(seededRandom(length), 'KEY', length)], seededRandom(5)));
  for (const file of files) {
    assert.equal((JSON.parse(Buffer.from(file.envelope).toString('utf8')) as { v: unknown }).v, 4, 'envelope v');
    assert.deepEqual(Object.keys(file.body), ['header', 'entries', 'coverage']);
    assert.deepEqual(Object.keys(file.body.header), ['v', 'version', 'issued_at', 'salt_b64', 'set_id', 'window', 'slots', 'scan_stride']);
    assert.deepEqual([file.body.header['v'], file.body.header['window'], file.body.header['slots'], file.body.header['scan_stride']], [4, 24, 320, 9]);
    assert.deepEqual(file.body.entries.map((e) => e.form), [...FORM_NAMES]);
    for (const entry of file.body.entries) {
      assert.deepEqual(Object.keys(entry), ['project', 'name', 'gen', 'retired', 'tier', 'form', 'probes_b64']);
      assert.equal(Buffer.from(String(entry.probes_b64), 'base64').length, SLOTS * SLOT_BYTES, `${entry.form}: 320 slots of 32 bytes`);
    }
    const text = file.bodyBytes.toString('utf8');
    for (const member of ['len', 'probes', 'stride']) assert.ok(!text.includes(`"${member}"`), `no ${member} member`);
  }
  const first = files[0];
  assert.ok(first !== undefined);
  for (const file of files) {
    assert.deepEqual(shapeOf(file.body), shapeOf(first.body), 'identical shape');
    assert.equal(file.bodyBytes.length, first.bodyBytes.length, 'identical body size');
    assert.equal(file.envelope.length, first.envelope.length, 'identical envelope size');
  }
});

// ---------------------------------------------------------------- 4. known answer

interface KnownAnswer {
  readonly salt_hex: string;
  readonly value: string;
  readonly forms: Readonly<Record<'raw' | 'b64s1' | 'b64u2', { readonly text: string; readonly slots: readonly string[] }>>;
}

test('KBOX-33 known answer: slot j is SHA-256(salt ‖ form[j:j+24]) for a fixed salt and value, against a vector made independently with Python hashlib', () => {
  const vector = JSON.parse(readFileSync(new URL('./fixtures/share-v4/known-answer.json', import.meta.url), 'utf8')) as KnownAnswer;
  const salt = Buffer.from(vector.salt_hex, 'hex');
  const key: FakeKey = { ...fakeKey(seededRandom(1), 'KNOWN', vector.value.length), value: vector.value, core: vector.value };
  const file = fileOver([key], saltFirst(salt, seededRandom(2)));
  assert.equal(file.salt.toString('hex'), vector.salt_hex, 'the file is salted with the vector\'s salt');
  const slots = (form: FormName): string[] => slotsOf(file.body.entries[FORM_NAMES.indexOf(form)]);
  for (const form of ['raw', 'b64s1'] as const) {
    const expected = vector.forms[form].slots;
    assert.deepEqual(slots(form).slice(0, expected.length), expected, `${form}: every window, in order`);
    assert.ok(slots(form).slice(expected.length).every((d) => !expected.includes(d)), `${form}: the slots past the last window are decoys`);
  }
  // The url form at alignment 2 holds no - or _, so each of its windows is the standard form's: the standard entry keeps the digest
  // and the url entry's slots are all decoys (no digest twice in a file).
  const url = vector.forms.b64u2;
  assert.ok(!/[-_]/.test(url.text), 'control: the vector\'s b64u2 text has no url-only character');
  assert.deepEqual(slots('b64s2').slice(0, url.slots.length), url.slots, 'b64s2 holds the windows of the shared text');
  assert.ok(slots('b64u2').every((d) => !url.slots.includes(d)), 'b64u2 holds only decoys');
});

// ---------------------------------------------------------------- 5. no digest twice

test(`KBOX-33 no 32-byte window slot appears twice in a file, even where the standard and url forms are the same text (seed ${seed})`, () => {
  const rng = seededRandom(seed + 3);
  const letters = Array.from({ length: 64 }, () => 'abcdefghijklmnopqrstuvwxyz'[rng.int(26)]).join('');
  const lower: FakeKey = { ...fakeKey(rng, 'LOWER', 64), value: letters, core: letters };
  const file = fileOver([...goldenKeys(), lower, fakeKey(rng, 'SHORT', 32)], seededRandom(rng.int(1e6)));
  const forms = formsOf(letters);
  assert.equal(forms.b64s0, forms.b64u0, 'control: a lower-case core has the same standard and url text at alignment 0');
  // Window slots only: an anchored key's standard and url digests may be equal, KBOX-2's declared one-bit exception.
  const digests = file.body.entries.flatMap((e) => (e.tier === 'windowed' ? slotsOf(e) : []));
  assert.ok(digests.length > 7 * SLOTS * 3, 'the file holds several windowed generations');
  assert.equal(new Set(digests).size, digests.length);
});

// ---------------------------------------------------------------- 6. decoys are fresh

test(`KBOX-33 decoy slots differ between two builds with the same salt and different randomness, while every real window slot is equal (seed ${seed})`, () => {
  const rng = seededRandom(seed + 4);
  const key = fakeKey(rng, 'DECOYS', 32);
  const salt = Buffer.from(rng.bytes(32));
  const [a, b] = [fileOver([key], saltFirst(salt, seededRandom(rng.int(1e6)))), fileOver([key], saltFirst(salt, seededRandom(rng.int(1e6))))];
  assert.equal(a.salt.toString('hex'), salt.toString('hex'));
  assert.equal(b.salt.toString('hex'), salt.toString('hex'));
  const digest = windowSha256(salt);
  const forms = formsOf(key.core);
  let decoys = 0;
  for (const [index, form] of FORM_NAMES.entries()) {
    const text = forms[form];
    const [left, right] = [slotsOf(a.body.entries[index]), slotsOf(b.body.entries[index])];
    for (let j = 0; j < SLOTS; j += 1) {
      const real = j + WINDOW <= text.length && left[j] === digest(Buffer.from(text.slice(j, j + WINDOW)));
      if (real) assert.equal(right[j], left[j], `${form} slot ${j}: a real window is the same under the same salt`);
      else {
        decoys += 1;
        assert.notEqual(right[j], left[j], `${form} slot ${j}: a decoy is drawn fresh`);
      }
    }
  }
  assert.ok(decoys >= 7 * SLOTS - 7 * 20, `${decoys} decoys: a 32-character core fills at most 19 slots of a form`);
});

// ---------------------------------------------------------------- the slot bound

test('KBOX-33 a form of 343 characters (320 windows) fills every slot, and one of 344 (321 windows) is refused with a RangeError', () => {
  const rng = seededRandom(seed + 5);
  const form = (length: number): Uint8Array => Buffer.from(randomCore(rng, 'base62', length));
  const salt = rng.bytes(32);
  const full = windowedSlots(form(343), salt, rng, new Set());
  assert.equal(full.length, SLOTS * SLOT_BYTES);
  assert.throws(() => windowedSlots(form(344), salt, rng, new Set()), RangeError);
});

test('KBOX-33 a random draw shorter than a slot is refused, never written as a decoy whose zero tail would mark it as one', () => {
  const rng = seededRandom(seed + 6);
  const short: Random = { bytes: (n) => rng.bytes(n - 1) };
  assert.throws(() => windowedSlots(Buffer.from(randomCore(rng, 'base62', 32)), rng.bytes(32), short, new Set()), RangeError);
});
