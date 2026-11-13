// KBOX-33 and KBOX-18: the share file, format v3. The layout byte by byte (a golden fixture devbox's matcher is built against), a
// reference matcher written from devbox's spec finding every planted copy and nothing else, and the two things S-128 forbids: a
// file that lets someone confirm a guessed weak secret, and a file whose size or shape tells a reader a key's length.
import assert from 'node:assert/strict';
import { createHash, createHmac } from 'node:crypto';
import { test } from 'node:test';
import { buildShare, sealEnvelope, windowDigest } from '../src/pure/share-build.ts';
import { findDerived } from './kit/derived-forms.ts';
import { seedFor, seededRandom } from './kit/index.ts';
import { GOLDEN, GOLDEN_SIGNING_SEED_HEX, buildGolden, goldenKeys, toShareKey } from './kit/share-golden.ts';
import { openShare } from './kit/reference-matcher.ts';
import type { Finding } from './kit/reference-matcher.ts';
import { base64Document, edgeOnlyDecoy, fakeJwt, fakeKey, interiorDecoy, rawDocument, signerFromSeed } from './kit/share-store.ts';
import type { FakeKey } from './kit/share-store.ts';

const seed = seedFor(process.env);

// ---------------------------------------------------------------- reading a file back, loosely typed on purpose

interface Entry {
  readonly project: string;
  readonly name: string;
  readonly gen: number;
  readonly retired: boolean;
  readonly tier: string;
  readonly form: string;
  readonly anchor?: string;
  readonly len?: number;
  readonly digest?: string;
}
interface Body {
  readonly header: Record<string, unknown>;
  readonly entries: readonly Entry[];
  readonly probes: readonly { readonly entry: number; readonly j: number; readonly d: string }[];
  readonly coverage: readonly { readonly project: string; readonly name: string; readonly gen: number; readonly tier: string }[];
}
const bodyOf = (envelope: Uint8Array): Body => {
  const outer = JSON.parse(Buffer.from(envelope).toString('utf8')) as { body_b64: string };
  return JSON.parse(Buffer.from(outer.body_b64, 'base64').toString('utf8')) as Body;
};
const decodedBody = (envelope: Uint8Array): Buffer => Buffer.from((JSON.parse(Buffer.from(envelope).toString('utf8')) as { body_b64: string }).body_b64, 'base64');

function at<T>(items: readonly T[], i: number): T {
  const item = items[i];
  if (item === undefined) throw new RangeError(`no element ${i} of ${items.length}`);
  return item;
}

/** Builds and signs a file over keys with a seeded random, as the box does. */
function fileOver(keys: readonly FakeKey[], randomSeed = 5, version = 1): { envelope: Uint8Array; publicKey: string } {
  const signer = signerFromSeed(Buffer.from(GOLDEN_SIGNING_SEED_HEX, 'hex'));
  const built = buildShare({ version, issuedAt: GOLDEN.issuedAt, random: seededRandom(randomSeed), keys: keys.map(toShareKey) });
  return { envelope: sealEnvelope(built.bytes, signer.sign(built.bytes)), publicKey: signer.publicKeyRawB64 };
}

const findingsIn = (keys: readonly FakeKey[], content: Uint8Array): Finding[] => {
  const { envelope, publicKey } = fileOver(keys);
  const opened = openShare(envelope, publicKey);
  assert.ok(opened.ok, 'the reference matcher opens the file');
  return opened.share.scan(content);
};
const namesOf = (found: readonly Finding[]): string[] => [...new Set(found.map((f) => `${f.name}/${f.gen}`))].sort();

// ---------------------------------------------------------------- the layout, byte by byte

test('KBOX-33 set_id is the SHA-256 hex of the sorted (project, name, gen, retired) list, every generation of every admin and master key', () => {
  const keys = goldenKeys();
  const cmp = (a: unknown, b: unknown): number => (String(a) < String(b) ? -1 : String(a) > String(b) ? 1 : 0);
  const sorted = keys.map((k) => [k.project, k.name, k.gen, k.retired]).sort((a, b) => cmp(a[0], b[0]) || cmp(a[1], b[1]) || Number(a[2]) - Number(b[2]));
  const expected = createHash('sha256').update(JSON.stringify(sorted)).digest('hex');
  assert.equal(bodyOf(buildGolden().envelope).header['set_id'], expected);
  const shuffled = [...keys].reverse();
  assert.equal(bodyOf(fileOver(shuffled).envelope).header['set_id'], expected, 'the order the keys arrive in does not matter');
});

test('KBOX-33 coverage lists every admin and master generation with its tier, so "not watched" is explicit', () => {
  const body = bodyOf(buildGolden().envelope);
  assert.deepEqual(
    body.coverage.map((c) => `${c.name}/${c.gen}/${c.tier}`).sort(),
    ['GOOGLE_CLIENT_SECRET/1/anchored', 'OPENAI_ADMIN_KEY/1/windowed', 'OPENAI_ADMIN_KEY/2/windowed', 'SUPABASE_DB_PASSWORD/1/none', 'SUPABASE_JWT/1/windowed', 'SUPABASE_SERVICE_KEY/1/windowed', 'VERCEL_TOKEN/1/anchored'],
  );
  assert.ok(body.coverage.every((c) => Object.keys(c).join() === 'project,name,gen,tier'));
});

test('KBOX-33 a long human-chosen paste that fails the shape check has no entry and no probe, only a none coverage item', () => {
  const body = bodyOf(buildGolden().envelope);
  assert.ok(!body.entries.some((e) => e.name === 'SUPABASE_DB_PASSWORD'));
  assert.deepEqual(body.coverage.filter((c) => c.name === 'SUPABASE_DB_PASSWORD'), [{ project: 'shop', name: 'SUPABASE_DB_PASSWORD', gen: 1, tier: 'none' }]);
  const password = goldenKeys().find((k) => k.name === 'SUPABASE_DB_PASSWORD');
  assert.ok(password !== undefined);
  assert.deepEqual(findingsIn(goldenKeys(), rawDocument(password.value)), [], 'a copy of it is not found: it is never fingerprinted');
});

test('KBOX-33 an anchored digest is the HMAC of the characters after the anchor that core bytes alone fix, and len is their count', () => {
  const key = fakeKey(seededRandom(4), 'VERCEL_TOKEN', 30, { prefix: 'vcp_' });
  const body = bodyOf(fileOver([key]).envelope);
  const salt = Buffer.from(String(body.header['salt_b64']), 'base64');
  for (const entry of body.entries) {
    const alignment = entry.form === 'raw' ? 0 : Number(entry.form.slice(-1));
    const whole = Buffer.concat([Buffer.alloc(alignment), Buffer.from(key.value)]);
    const text = entry.form === 'raw' ? key.value : whole.toString(entry.form.startsWith('b64u') ? 'base64url' : 'base64');
    // Bits 8*(alignment + 4) onward belong to the core; the first whole character at or after that bit is where the run starts.
    const runFrom = entry.form === 'raw' ? 4 : Math.ceil((8 * (alignment + 4)) / 6);
    const runTo = entry.form === 'raw' ? key.value.length : Math.floor((8 * (alignment + 4 + 30)) / 6);
    const run = text.slice(runFrom, runTo);
    assert.equal(entry.len, run.length, entry.form);
    assert.equal(entry.digest, createHmac('sha256', salt).update(run).digest('hex'), entry.form);
  }
});

// ---------------------------------------------------------------- the reference matcher: found, and nothing else

const WATCHED_GOLDEN = goldenKeys().filter((k) => k.name !== 'SUPABASE_DB_PASSWORD');

test('KBOX-33 the reference matcher finds a planted raw copy and a base64 copy at each of the six alignments, of every watched key', () => {
  for (const key of WATCHED_GOLDEN) {
    const label = `${key.name} gen ${key.gen}`;
    const documents = [
      ['raw', rawDocument(key.value)],
      ...([0, 1, 2] as const).flatMap((a) => [
        [`b64 std ${a}`, base64Document(key.value, a, false)] as const,
        [`b64 url ${a}`, base64Document(key.value, a, true)] as const,
      ]),
    ] as const;
    for (const [how, content] of documents) assert.deepEqual(namesOf(findingsIn(WATCHED_GOLDEN, content)), [`${key.name}/${key.gen}`], `${label}: ${how}`);
  }
});

test('KBOX-33 a copy wrapped at 64 or 76 columns, with LF or CRLF, is found in the stripped view and nowhere else', () => {
  for (const key of WATCHED_GOLDEN) {
    for (const columns of [64, 76]) {
      for (const lineBreak of ['\n', '\r\n'] as const) {
        for (const a of [0, 1, 2] as const) {
          const content = base64Document(key.value, a, a === 1, { columns, lineBreak });
          assert.deepEqual(namesOf(findingsIn(WATCHED_GOLDEN, content)), [`${key.name}/${key.gen}`], `${key.name} ${columns} ${a}`);
        }
      }
    }
  }
});

test('KBOX-33 a copy is reported at the offset it sits at (raw form: the core), once', () => {
  const key = at(WATCHED_GOLDEN, 0);
  const content = rawDocument(key.value);
  const found = findingsIn(WATCHED_GOLDEN, content).filter((f) => f.form === 'raw');
  assert.equal(found.length, 1);
  assert.equal(at(found, 0).start, Buffer.from(content).indexOf(key.core));
});

test('KBOX-33 an interior decoy, unrelated text, another key\'s value and a value\'s public parts alone are found in no form', () => {
  const rng = seededRandom(seed);
  const stranger = fakeKey(rng, 'STRANGER', 48, { prefix: 'sb_secret_' });
  const jwt = WATCHED_GOLDEN.find((k) => k.name === 'SUPABASE_JWT');
  assert.ok(jwt !== undefined);
  for (const key of WATCHED_GOLDEN) {
    const decoy = interiorDecoy(key);
    assert.notEqual(decoy, key.value);
    for (const content of [rawDocument(decoy), ...([0, 1, 2] as const).flatMap((a) => [base64Document(decoy, a, false), base64Document(decoy, a, true)])]) {
      assert.deepEqual(findingsIn(WATCHED_GOLDEN, content), [], `${key.name}: a decoy`);
    }
    const prefix = key.value.slice(0, key.value.length - key.core.length);
    if (prefix !== '') assert.deepEqual(findingsIn(WATCHED_GOLDEN, rawDocument(prefix + stranger.core)), [], `${key.name}: the prefix with another core`);
  }
  assert.deepEqual(findingsIn(WATCHED_GOLDEN, rawDocument(stranger.value)), []);
  const publicParts = jwt.value.slice(0, jwt.value.length - jwt.core.length);
  assert.deepEqual(findingsIn(WATCHED_GOLDEN, rawDocument(publicParts + stranger.core.slice(0, 43))), [], 'the JWT header and payload with another signature');
  assert.deepEqual(findingsIn(WATCHED_GOLDEN, Buffer.from('plain text '.repeat(500))), []);
});

test('KBOX-33 a prefix-cut anchored copy is not found: the limit of the anchored tier, documented', () => {
  const key = WATCHED_GOLDEN.find((k) => k.name === 'GOOGLE_CLIENT_SECRET');
  assert.ok(key !== undefined);
  assert.deepEqual(namesOf(findingsIn(WATCHED_GOLDEN, rawDocument(key.value))), ['GOOGLE_CLIENT_SECRET/1'], 'control: the whole value is found');
  assert.deepEqual(findingsIn(WATCHED_GOLDEN, rawDocument(key.core)), [], 'the core alone is not');
  for (const a of [0, 1, 2] as const) assert.deepEqual(findingsIn(WATCHED_GOLDEN, base64Document(key.core, a, false)), [], `base64 alignment ${a}`);
});

test('KBOX-33 a retired generation is found and reported as retired', () => {
  const retired = WATCHED_GOLDEN.find((k) => k.retired);
  assert.ok(retired !== undefined);
  const found = findingsIn(WATCHED_GOLDEN, rawDocument(retired.value));
  assert.ok(found.length > 0 && found.every((f) => f.retired && f.gen === 2));
});

test('KBOX-33 no window covers a prefix or a JWT header: the public part of a value, with the right core cut away, never matches', () => {
  const rng = seededRandom(seed + 1);
  for (const key of WATCHED_GOLDEN.filter((k) => k.value !== k.core && k.shape.prefix !== 'GOCSPX-' && k.shape.prefix !== 'vcp_')) {
    const publicPart = key.value.slice(0, key.value.length - key.core.length);
    const filler = fakeKey(rng, 'F', Math.max(key.core.length, 32), { alphabet: key.shape.alphabet }).core;
    for (const content of [rawDocument(publicPart + filler), base64Document(publicPart + filler, 1, false), base64Document(publicPart + filler, 2, true)]) {
      assert.deepEqual(findingsIn(WATCHED_GOLDEN, content), [], `${key.name}`);
    }
  }
});

// ---------------------------------------------------------------- the carry-over from forms: decoys differ at interior bytes

test('KBOX-33 a decoy that differs from a core only in its first or last byte is still found (so decoys here differ at interior bytes)', () => {
  const long = WATCHED_GOLDEN.filter((k) => k.core.length >= 36);
  assert.ok(long.length >= 4);
  for (const key of long) {
    const edge = edgeOnlyDecoy(key);
    assert.notEqual(edge, key.value);
    const found = findingsIn(WATCHED_GOLDEN, rawDocument(edge));
    assert.ok(found.length > 0, `${key.name}: a 24-character window sits wholly inside the unchanged bytes`);
  }
});

test('KBOX-33 an interior decoy changes no byte of a core\'s first two or last two and changes every 24-character window of it', () => {
  for (const key of WATCHED_GOLDEN) {
    const decoyCore = interiorDecoy(key).slice(key.value.length - key.core.length);
    const n = key.core.length;
    for (const i of [0, 1, n - 2, n - 1]) assert.equal(decoyCore[i], key.core[i], `${key.name}: edge byte ${i}`);
    for (let w = 0; w + 24 <= n; w += 1) assert.notEqual(decoyCore.slice(w, w + 24), key.core.slice(w, w + 24), `${key.name}: window ${w}`);
    let changed = 0;
    for (let i = 0; i < n; i += 1) if (decoyCore[i] !== key.core[i]) changed += 1;
    assert.ok(changed >= Math.floor((n - 4) / 5), `${key.name}: ${changed} changed bytes`);
  }
});

// ---------------------------------------------------------------- S-128: lengths

const shapeOf = (v: unknown): unknown => {
  if (typeof v === 'string') return `s${v.length}`;
  if (typeof v === 'number') return `n${String(v).length}`;
  if (typeof v === 'boolean' || v === null) return v;
  if (Array.isArray(v)) return v.map(shapeOf);
  return Object.fromEntries(Object.entries(v as Record<string, unknown>).map(([k, x]) => [k, shapeOf(x)]));
};

function lengthStore(rng: ReturnType<typeof seededRandom>, windowed: readonly number[], anchored: readonly number[]): FakeKey[] {
  return [
    ...windowed.map((length, i) => fakeKey(rng, `WINDOWED_KEY_${i}`, length, { alphabet: i % 2 === 0 ? 'base62' : 'hex', prefix: i % 3 === 0 ? 'sb_secret_' : null })),
    ...anchored.map((length, i) => fakeKey(rng, `ANCHORED_KEY_${i}`, length, { prefix: 'vcp_' })),
  ];
}

test('KBOX-33 anchored lengths are the declared exception: len changes with the core, and nothing else about the file does', () => {
  const sizes = [20, 25, 30].map((length) => bodyOf(fileOver(lengthStore(seededRandom(length), [], [length])).envelope));
  const lens = sizes.map((b) => b.entries.map((e) => e.len));
  assert.notDeepEqual(lens[0], lens[1]);
  assert.deepEqual(sizes.map((b) => shapeOf(b)), [shapeOf(at(sizes, 0)), shapeOf(at(sizes, 0)), shapeOf(at(sizes, 0))]);
});

// ---------------------------------------------------------------- KBOX-2: no value, prefix or length

test('KBOX-2 the share file holds no value, no prefix and no length of a windowed key', () => {
  const rng = seededRandom(seed + 2);
  const keys = [
    fakeKey(rng, 'WINDOWED_PREFIXED', 40, { prefix: 'sb_secret_' }),
    fakeKey(rng, 'WINDOWED_HEX', 64, { alphabet: 'hex' }),
    fakeKey(rng, 'WINDOWED_LONG', 211, { alphabet: 'base64url', prefix: 'tok_zzz_' }),
    fakeJwt(rng, 'WINDOWED_JWT'),
  ];
  const { envelope } = fileOver(keys);
  const surfaces = { envelope, body: decodedBody(envelope) };
  for (const key of keys) {
    const bytes = Buffer.from(key.value);
    assert.deepEqual(findDerived(bytes, key.name, surfaces), [], `${key.name}: no piece, digest or length`);
    const needles = [key.value, key.core, key.core.slice(0, 12), key.core.slice(-12), key.core.slice(12, 24), Buffer.from(key.core).toString('base64').slice(8, 20), Buffer.from(key.core).toString('hex').slice(0, 16)];
    for (const needle of needles) assert.ok(!surfaces.body.includes(needle) && !Buffer.from(envelope).includes(needle), `${key.name}: ${needle.slice(0, 2)}.. is in the file`);
    const publicPart = key.value.slice(0, key.value.length - key.core.length);
    if (publicPart !== '') assert.ok(!surfaces.body.includes(publicPart), `${key.name}: the prefix is in the file`);
  }
  const body = bodyOf(envelope);
  const text = surfaces.body.toString('utf8');
  assert.ok(!/"len"/.test(text) && !/"anchor"/.test(text), 'no len or anchor member anywhere');
  for (const key of keys) for (const n of [key.value.length, key.core.length]) assert.ok(!new RegExp(`"[a-z_]+":${n}[,}]`).test(text.replace(/"j":\d+/g, '')), `${key.name}: the number ${n}`);
  assert.equal(body.entries.length, 28);
});

test('KBOX-2 for an anchored key only the declared prefix (as each form spells it) and len are in the file: not one core byte', () => {
  const rng = seededRandom(seed + 3);
  const key = fakeKey(rng, 'ANCHORED', 28, { prefix: 'GOCSPX-', alphabet: 'base64url' });
  const { envelope } = fileOver([key]);
  const text = decodedBody(envelope).toString('utf8');
  for (let from = 0; from + 8 <= key.core.length; from += 1) {
    for (const form of [key.core, Buffer.from(key.core).toString('base64'), Buffer.from(key.core).toString('base64url'), Buffer.from(key.core).toString('hex')]) {
      assert.ok(!text.includes(form.slice(from, from + 8)), `core bytes at ${from}`);
    }
  }
  const anchors = bodyOf(envelope).entries.map((e) => e.anchor);
  assert.equal(anchors[0], 'GOCSPX-');
  assert.ok(anchors.every((a) => a !== undefined && a.length >= 5 && a.length <= 12));
});

// ---------------------------------------------------------------- fail closed, known answers

test('KBOX-33 the signature fails on one flipped body byte, and the reader refuses before parsing', () => {
  const golden = buildGolden();
  const outer = JSON.parse(Buffer.from(golden.envelope).toString('utf8')) as Record<string, string>;
  const body = Buffer.from(String(outer['body_b64']), 'base64');
  for (const index of [0, 10, Math.floor(body.length / 2), body.length - 1]) {
    const flipped = Buffer.from(body);
    flipped[index] = (flipped[index] ?? 0) ^ 0x01;
    const tampered = Buffer.from(JSON.stringify({ ...outer, body_b64: flipped.toString('base64') }));
    const opened = openShare(tampered, golden.signer.publicKeyRawB64);
    assert.deepEqual(opened.ok ? 'opened' : opened.code, 'bad_signature', `byte ${index}`);
  }
  assert.deepEqual(openShare(golden.envelope, signerFromSeed(Buffer.alloc(32, 7)).publicKeyRawB64).ok, false, 'another key');
});

test('KBOX-33 known answers: HMAC-SHA256 (RFC 4231 case 2) through the window digest, and the golden signature is Ed25519 (RFC 8032 test 1 key)', () => {
  assert.equal(windowDigest(Buffer.from('Jefe'), Buffer.from('what do ya want for nothing?')), '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843');
  assert.equal(buildGolden().signer.publicKeyRawB64, Buffer.from('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a', 'hex').toString('base64'));
  const empty = signerFromSeed(Buffer.from(GOLDEN_SIGNING_SEED_HEX, 'hex')).sign(new Uint8Array(0));
  assert.equal(
    Buffer.from(empty).toString('hex'),
    'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b',
  );
});

test('KBOX-33 a store holding the same generation twice is refused, not written with two meanings', () => {
  const key = fakeKey(seededRandom(1), 'K', 40);
  assert.throws(() => fileOver([key, key]), RangeError);
});
