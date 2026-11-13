// KBOX-33 revision 4: the share file, format v4. Every 24-character window of each form sits in one of 320 fixed slots per windowed
// entry, as SHA-256(salt ‖ window), padded with random decoys, so a matcher may hash only one input position in `scan_stride` and
// still meet every copy. The oracle is a reference matcher that SAMPLES (test/kit/reference-matcher.ts): it never steps by one, so a
// file that thins its windows (v3) fails here. Forms are computed in this file from the base64 definition, not by src/pure/forms.ts.
import assert from 'node:assert/strict';
import { createPublicKey, verify } from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';
import { test } from 'node:test';
import type { Random } from '../src/ports/random.ts';
import { buildShare, sealEnvelope, windowedSlots } from '../src/pure/share-build.ts';
import { checkProperty, seedFor, seededRandom } from './kit/index.ts';
import type { SeededRandom } from './kit/index.ts';
import { SCAN_STRIDE, WINDOW, openShare, sampledHits, windowSha256 } from './kit/reference-matcher.ts';
import type { Finding, Slot } from './kit/reference-matcher.ts';
import { GOLDEN, GOLDEN_SIGNING_SEED_HEX, buildGolden, expectedFindings, goldenKeys, plantedDocuments, toShareKey } from './kit/share-golden.ts';
import { fakeKey, randomCore, signerFromSeed } from './kit/share-store.ts';
import type { FakeKey } from './kit/share-store.ts';

const seed = seedFor(process.env);
const SLOTS = 320;
const SLOT_BYTES = 32;
const FORM_NAMES = ['raw', 'b64s0', 'b64s1', 'b64s2', 'b64u0', 'b64u1', 'b64u2'] as const;
type FormName = (typeof FORM_NAMES)[number];

// ---------------------------------------------------------------- building and reading a file

interface WindowedEntry {
  readonly project: string;
  readonly name: string;
  readonly gen: number;
  readonly retired: boolean;
  readonly anchor?: string;
  readonly len?: number;
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

function fileOver(keys: readonly FakeKey[], random: Random, version = 1): File {
  const signer = signerFromSeed(Buffer.from(GOLDEN_SIGNING_SEED_HEX, 'hex'));
  const built = buildShare({ version, issuedAt: GOLDEN.issuedAt, random, keys: keys.map(toShareKey) });
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

test(`KBOX-33 decoy slots differ between two builds with the same salt and different randomness, while every real window slot is equal, and no byte of a decoy is fixed (seed ${seed})`, () => {
  const rng = seededRandom(seed + 4);
  const key = fakeKey(rng, 'DECOYS', 32);
  const salt = Buffer.from(rng.bytes(32));
  const [a, b] = [fileOver([key], saltFirst(salt, seededRandom(rng.int(1e6)))), fileOver([key], saltFirst(salt, seededRandom(rng.int(1e6))))];
  assert.equal(a.salt.toString('hex'), salt.toString('hex'));
  assert.equal(b.salt.toString('hex'), salt.toString('hex'));
  const digest = windowSha256(salt);
  const forms = formsOf(key.core);
  const decoys: Buffer[] = [];
  for (const [index, form] of FORM_NAMES.entries()) {
    const text = forms[form];
    const [left, right] = [slotsOf(a.body.entries[index]), slotsOf(b.body.entries[index])];
    for (let j = 0; j < SLOTS; j += 1) {
      const real = j + WINDOW <= text.length && left[j] === digest(Buffer.from(text.slice(j, j + WINDOW)));
      if (real) assert.equal(right[j], left[j], `${form} slot ${j}: a real window is the same under the same salt`);
      else {
        decoys.push(Buffer.from(String(left[j]), 'hex'));
        assert.notEqual(right[j], left[j], `${form} slot ${j}: a decoy is drawn fresh`);
      }
    }
  }
  assert.ok(decoys.length >= 7 * SLOTS - 7 * 20, `${decoys.length} decoys: a 32-character core fills at most 19 slots of a form`);
  // A digest is uniform in every byte; a decoy with a fixed byte (a zero tail from a short draw, a constant marker) would tell a
  // reader which slots are decoys, and so the key's length.
  for (let i = 0; i < SLOT_BYTES; i += 1) assert.ok(new Set(decoys.map((d) => d[i])).size > 1, `byte ${i} is the same in every decoy`);
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

// ---------------------------------------------------------------- the v4 pins of what v3 pinned (S-795 retirement titles)

const FIXTURES = new URL('./fixtures/share-v4/', import.meta.url);
const fixture = (name: string): Buffer => readFileSync(new URL(name, FIXTURES));
const decodedBody = (envelope: Uint8Array): Buffer => Buffer.from((JSON.parse(Buffer.from(envelope).toString('utf8')) as { body_b64: string }).body_b64, 'base64');
const outerOf = (envelope: Uint8Array): Record<string, unknown> => JSON.parse(Buffer.from(envelope).toString('utf8')) as Record<string, unknown>;
const bodyOf = (envelope: Uint8Array): Body => JSON.parse(decodedBody(envelope).toString('utf8')) as Body;
const WATCHED = goldenKeys().filter((k) => k.name !== 'SUPABASE_DB_PASSWORD');
/** A file over keys with the golden signer, a seeded random and a version. */
const goldenFile = (keys: readonly FakeKey[], randomSeed = 5, version = 1): File => fileOver(keys, seededRandom(randomSeed), version);
const slotSet = (body: Body): Set<string> => new Set(body.entries.flatMap((e) => (e.tier === 'windowed' ? slotsOf(e) : [])));

test('KBOX-33 v4: the golden file is exactly what the box writes over the golden store (the cross-repo fixture, share-v4 corpus)', () => {
  const store = JSON.parse(fixture('store.json').toString('utf8')) as { keys: { value: string }[] };
  const golden = buildGolden();
  assert.deepEqual(store.keys.map((k) => k.value), goldenKeys().map((k) => k.value), 'store.json holds the values the golden file was made over');
  assert.equal(Buffer.compare(fixture('share.json'), Buffer.from(golden.envelope)), 0, 'share.json is byte for byte the written envelope');
  assert.equal(Buffer.compare(fixture('body.json'), Buffer.from(golden.body)), 0, 'body.json is byte for byte the signed body');
  assert.equal(Buffer.compare(decodedBody(fixture('share.json')), fixture('body.json')), 0, 'the signature covers the exact decoded body_b64');
  const planted = readdirSync(new URL('planted/', FIXTURES)).filter((f) => f !== 'expected.json');
  assert.deepEqual(planted.sort(), Object.keys(plantedDocuments()).sort());
  for (const [file, content] of Object.entries(plantedDocuments())) assert.equal(Buffer.compare(fixture(`planted/${file}`), Buffer.from(content)), 0, file);
  assert.deepEqual(JSON.parse(fixture('planted/expected.json').toString('utf8')), expectedFindings());
});

test('KBOX-33 v4: the envelope is {format, v, body_b64, sig_b64} in that order with v 4, the signature Ed25519 over the decoded body bytes', () => {
  const golden = buildGolden();
  const outer = outerOf(golden.envelope);
  assert.deepEqual(Object.keys(outer), ['format', 'v', 'body_b64', 'sig_b64']);
  assert.equal(outer['format'], 'kbox-share');
  assert.equal(outer['v'], 4);
  assert.equal(Buffer.from(String(outer['sig_b64']), 'base64').length, 64);
  assert.equal(Buffer.from(String(outer['body_b64']), 'base64').toString('base64'), outer['body_b64'], 'canonical base64, so the signed bytes are the decoded ones');
  assert.equal(golden.envelope[golden.envelope.length - 1], 0x7d, 'the envelope is one compact JSON object, no trailing newline');
  assert.ok(verify(null, decodedBody(golden.envelope), createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(golden.signer.publicKeyRawB64, 'base64')]), format: 'der', type: 'spki' }), Buffer.from(String(outer['sig_b64']), 'base64')));
});

test('KBOX-33 v4: the header is {v, version, issued_at, salt_b64, set_id, window, slots, scan_stride} with 24, 320 and 9, a 32-byte salt and no baseline', () => {
  const body = bodyOf(buildGolden().envelope);
  assert.deepEqual(Object.keys(body), ['header', 'entries', 'coverage']);
  assert.deepEqual(Object.keys(body.header), ['v', 'version', 'issued_at', 'salt_b64', 'set_id', 'window', 'slots', 'scan_stride']);
  assert.equal(body.header['v'], 4);
  assert.equal(body.header['version'], GOLDEN.version);
  assert.equal(body.header['issued_at'], GOLDEN.issuedAt);
  assert.deepEqual([body.header['window'], body.header['slots'], body.header['scan_stride']], [24, 320, 9]);
  assert.equal(Buffer.from(String(body.header['salt_b64']), 'base64').length, 32);
  assert.ok(!('baseline' in body.header));
});

test('KBOX-33 v4: the salt is new for every version: two files over the same store share no salt, no slot and no digest', () => {
  const a = goldenFile(goldenKeys(), 1, 1).body;
  const b = goldenFile(goldenKeys(), 2, 2).body;
  assert.notEqual(a.header['salt_b64'], b.header['salt_b64']);
  const slotsA = slotSet(a);
  assert.ok(slotsA.size > 0);
  assert.ok([...slotSet(b)].every((d) => !slotsA.has(d)));
  const digests = new Set(a.entries.map((e) => e.digest).filter((d) => d !== undefined));
  assert.ok(digests.size > 0, 'control: the golden store has anchored entries');
  assert.ok(b.entries.every((e) => e.digest === undefined || !digests.has(e.digest)));
});

test('KBOX-33 v4: entries: seven per generation named by form, windowed entries carry probes_b64 and no length, anchored ones the closed seven members', () => {
  const body = bodyOf(buildGolden().envelope);
  assert.equal(body.entries.length, 7 * WATCHED.length, 'one entry per form per watched generation, none for the not-watched key');
  for (const key of WATCHED) {
    const mine = body.entries.filter((e) => e.project === key.project && e.name === key.name && e.gen === key.gen);
    assert.deepEqual(mine.map((e) => e.form), [...FORM_NAMES], `${key.name} gen ${key.gen}`);
    assert.ok(mine.every((e) => e.retired === key.retired));
  }
  assert.ok(body.entries.some((e) => e.tier === 'windowed') && body.entries.some((e) => e.tier === 'anchored'), 'control: both tiers');
  for (const entry of body.entries) {
    if (entry.tier === 'windowed') assert.deepEqual(Object.keys(entry), ['project', 'name', 'gen', 'retired', 'tier', 'form', 'probes_b64']);
    else assert.deepEqual(Object.keys(entry), ['project', 'name', 'gen', 'retired', 'tier', 'form', 'anchor', 'len', 'digest']);
  }
});

test('KBOX-33 v4: form names are the closed seven and never form text; an entry is its index', () => {
  const body = bodyOf(buildGolden().envelope);
  const text = decodedBody(buildGolden().envelope).toString('utf8');
  for (const key of goldenKeys()) assert.ok(!text.includes(key.core.slice(0, 8)), 'no form text');
  assert.ok(body.entries.every((e) => (FORM_NAMES as readonly string[]).includes(e.form)));
  assert.ok(!text.includes('"entry"'), 'a slot names no entry: its entry is where it sits');
  assert.ok(body.entries.every((e) => e.tier !== 'windowed' || e.probes_b64 !== undefined));
});

test('KBOX-33 v4: a 28-character GOCSPX- core gets an anchored entry per form and no windowed slots, and the anchor is the prefix as that form spells it', () => {
  const key = fakeKey(seededRandom(3), 'GOOGLE_CLIENT_SECRET', 28, { prefix: 'GOCSPX-', alphabet: 'base64url' });
  const { body } = goldenFile([key]);
  assert.equal(body.entries.length, 7);
  assert.ok(body.entries.every((e) => e.tier === 'anchored' && e.probes_b64 === undefined), 'no windowed slots');
  for (const [i, entry] of body.entries.entries()) {
    const alignment = entry.form === 'raw' ? 0 : Number(entry.form.slice(-1));
    if (entry.form === 'raw') {
      assert.equal(entry.anchor, 'GOCSPX-');
      assert.equal(entry.len, 28);
      continue;
    }
    // The prefix as it reads inside a base64 text where the value starts at byte offset `alignment` mod 3.
    const whole = Buffer.concat([Buffer.alloc(alignment), Buffer.from(key.value)]).toString(entry.form.startsWith('b64u') ? 'base64url' : 'base64');
    assert.equal(entry.anchor, whole.slice(Math.ceil((8 * alignment) / 6), Math.floor((8 * (alignment + 7)) / 6)), `entry ${i} ${entry.form}`);
    assert.ok(!entry.anchor?.includes(key.core.slice(0, 4)));
  }
});

test('KBOX-33 v4: no slot is the digest of ANY 24-character window that touches a prefix or a JWT header or payload, in any form at any offset', () => {
  const file = goldenFile(goldenKeys());
  const slots = slotSet(file.body);
  const digest = windowSha256(file.salt);
  const withPublicPart = goldenKeys().filter((k) => k.value !== k.core);
  assert.ok(withPublicPart.length >= 4, 'sb_secret_, GOCSPX-, vcp_ and the JWT');
  assert.equal(file.body.entries.filter((e) => e.name === 'SUPABASE_SERVICE_KEY' && e.tier === 'windowed').length, 7, 'control: the sb_secret_ key is windowed, so its slots are in the set checked');
  for (const key of withPublicPart) {
    const publicChars = key.value.length - key.core.length;
    const texts: { readonly text: string; readonly firstCoreChar: number }[] = [{ text: key.value, firstCoreChar: publicChars }];
    for (const a of [0, 1, 2]) {
      const whole = Buffer.concat([Buffer.alloc(a), Buffer.from(key.value)]);
      for (const kind of ['base64', 'base64url'] as const) texts.push({ text: whole.toString(kind), firstCoreChar: Math.ceil((8 * (a + publicChars)) / 6) });
    }
    for (const { text, firstCoreChar } of texts) {
      for (let i = 0; i < firstCoreChar && i + WINDOW <= text.length; i += 1) assert.ok(!slots.has(digest(Buffer.from(text.slice(i, i + WINDOW), 'latin1'))), `${key.name}: a window at ${i} of a form touches the public part`);
    }
  }
});

function lengthStore(rng: SeededRandom, windowed: readonly number[], anchored: readonly number[]): FakeKey[] {
  return [
    ...windowed.map((length, i) => fakeKey(rng, `WINDOWED_KEY_${i}`, length, { alphabet: i % 2 === 0 ? 'base62' : 'hex', prefix: i % 3 === 0 ? 'sb_secret_' : null })),
    ...anchored.map((length, i) => fakeKey(rng, `ANCHORED_KEY_${i}`, length, { prefix: 'vcp_' })),
  ];
}

test(`KBOX-33 v4 property: stores of keys of different lengths with the same count per tier give files of identical size and shape (seed ${seed})`, () => {
  checkProperty(seed, 25, (rng) => {
    const windowedCount = 1 + rng.int(3);
    const anchoredCount = rng.int(3);
    const draw = (): { windowed: number[]; anchored: number[] } => ({
      windowed: Array.from({ length: windowedCount }, () => 32 + rng.int(225)),
      anchored: Array.from({ length: anchoredCount }, () => 20 + rng.int(12)),
    });
    const a = draw();
    const b = draw();
    const left = goldenFile(lengthStore(seededRandom(rng.int(1e6)), a.windowed, a.anchored), 5);
    const right = goldenFile(lengthStore(seededRandom(rng.int(1e6)), b.windowed, b.anchored), 6);
    assert.deepEqual(shapeOf(left.body), shapeOf(right.body), 'same shape');
    assert.equal(left.envelope.length, right.envelope.length, `same size for windowed ${a.windowed} against ${b.windowed}`);
    assert.equal(left.bodyBytes.length, right.bodyBytes.length);
  });
});

test(`KBOX-33 v4 property: a windowed key of any eligible length fills the same 320 slots, and its windows are the only slots that depend on it (seed ${seed})`, () => {
  checkProperty(seed, 20, (rng) => {
    const length = 32 + rng.int(225);
    const key = fakeKey(rng, 'K', length, { alphabet: (['base62', 'hex', 'base64url'] as const)[rng.int(3)] ?? 'base62' });
    const file = goldenFile([key], rng.int(1e6));
    assert.equal(file.body.entries.length, 7);
    const digest = windowSha256(file.salt);
    for (const [index, name] of FORM_NAMES.entries()) {
      const forms = formsOf(key.core);
      const text = forms[name];
      // A url form whose text equals its standard sibling's keeps no window: the digest is held once, by the standard entry.
      const sharedWithStandard = name.startsWith('b64u') && text === forms[`b64s${name.slice(-1)}` as FormName];
      const windows = sharedWithStandard ? [] : Array.from({ length: Math.max(0, text.length - WINDOW + 1) }, (_, j) => digest(Buffer.from(text.slice(j, j + WINDOW))));
      const slots = slotsOf(file.body.entries[index]);
      assert.equal(slots.length, SLOTS, `${name}: 320 slots whatever the length`);
      // Slot j is window j where there is one; every other slot is the digest of no window of the key (a fresh decoy).
      assert.deepEqual(slots.slice(0, windows.length), windows, `${name}: the windows in order`);
      assert.ok(slots.slice(windows.length).every((d) => !windows.includes(d)), `${name}: the rest depends on no window`);
    }
    // And the copy is found: the slots cover every eligible length.
    const scan = opened(file);
    assert.ok(scan(Buffer.from(key.core)).length > 0, 'raw copy found');
    assert.ok(scan(Buffer.from(Buffer.from(key.core).toString('base64'))).length > 0, 'base64 copy found');
  });
});

test('KBOX-33 v4: the reader fails closed on a file older than one it has seen, a wrong format (v 3 included), or a body that breaks the layout', () => {
  const golden = buildGolden();
  const key = golden.signer.publicKeyRawB64;
  const refusal = (r: ReturnType<typeof openShare>): string => (r.ok ? 'opened' : r.code);
  assert.equal(refusal(openShare(golden.envelope, key, { lastVersion: GOLDEN.version })), 'opened', 'the same version is not a rollback');
  assert.equal(refusal(openShare(golden.envelope, key, { lastVersion: GOLDEN.version + 1 })), 'rolled_back');
  assert.equal(refusal(openShare(Buffer.from('{"format":"kbox-share","v":2}'), key)), 'bad_envelope');
  assert.equal(refusal(openShare(Buffer.from('not json'), key)), 'bad_envelope');
  const body = bodyOf(golden.envelope);
  const resign = (changed: unknown, v = 4): Uint8Array => {
    const bytes = Buffer.from(JSON.stringify(changed));
    return Buffer.from(JSON.stringify({ format: 'kbox-share', v, body_b64: bytes.toString('base64'), sig_b64: Buffer.from(golden.signer.sign(bytes)).toString('base64') }));
  };
  assert.equal(refusal(openShare(resign(body), key)), 'opened', 'control: a re-signed untouched body opens');
  assert.equal(refusal(openShare(resign(body, 3), key)), 'bad_envelope', 'a validly signed v 3 envelope');
  const first = body.entries.findIndex((e) => e.tier === 'windowed');
  assert.ok(first >= 0);
  const withEntry = (change: (e: WindowedEntry) => unknown): unknown => ({ ...body, entries: body.entries.map((e, i) => (i === first ? change(e) : e)) });
  assert.equal(refusal(openShare(resign(withEntry((e) => ({ ...e, probes_b64: String(e.probes_b64).slice(0, -44) }))), key)), 'bad_body', 'a windowed entry with 319 slots');
  assert.equal(refusal(openShare(resign(withEntry((e) => ({ ...e, len: 40 }))), key)), 'bad_body', 'a len on a windowed entry');
  assert.equal(refusal(openShare(resign({ ...body, header: { ...body.header, scan_stride: 8 } }), key)), 'bad_body', 'scan_stride 8');
  assert.equal(refusal(openShare(resign({ ...body, header: { ...body.header, baseline: {} } }), key)), 'bad_body', 'a baseline member');
  assert.equal(refusal(openShare(resign({ ...body, probes: [] }), key)), 'bad_body', 'a v3 top-level probes member');
});

test('KBOX-33 v4: the golden file opens with the stored public key and finds each planted copy of its own key and nothing else (share-v4 corpus)', () => {
  const store = JSON.parse(fixture('store.json').toString('utf8')) as { public_key_ed25519_b64: string };
  const result = openShare(fixture('share.json'), store.public_key_ed25519_b64);
  assert.ok(result.ok);
  assert.equal(result.share.version, GOLDEN.version);
  const expected = JSON.parse(fixture('planted/expected.json').toString('utf8')) as Record<string, string[]>;
  const watched = new Map(goldenKeys().filter((k) => k.shape.random).map((k) => [`${k.name}.${k.gen}`.toLowerCase(), `${k.project}/${k.name}/${k.gen}`]));
  for (const [file, keys] of Object.entries(expected)) {
    const found = [...new Set(result.share.scan(fixture(`planted/${file}`)).map((f) => `${f.project}/${f.name}/${f.gen}`))];
    assert.deepEqual(found, keys, file);
    const owner = watched.get(file.split('.').slice(0, 2).join('.'));
    const isCopy = !file.includes('.decoy.') && owner !== undefined;
    assert.deepEqual(keys, isCopy ? [owner] : [], isCopy ? `${file} holds a copy of exactly one key` : `${file} holds no copy`);
  }
});

test('KBOX-33 v4: a new version has a new salt: a slot of one version is in no other', () => {
  const store = [fakeKey(seededRandom(11), 'OPENAI_ADMIN_KEY', 64, { alphabet: 'hex' })];
  const next = [...store, fakeKey(seededRandom(12), 'OPENAI_ADMIN_KEY', 64, { alphabet: 'hex', gen: 2 })];
  const [a, b] = [goldenFile(store, 21, 1), goldenFile(next, 22, 2)];
  assert.notEqual(a.body.header['salt_b64'], b.body.header['salt_b64']);
  const old = slotSet(a.body);
  assert.equal(old.size, 7 * SLOTS, 'control: the first version holds its own slots');
  assert.ok([...slotSet(b.body)].every((d) => !old.has(d)));
});
