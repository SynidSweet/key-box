// KBOX-33 and KBOX-18: the share file, format v3. The layout byte by byte (a golden fixture devbox's matcher is built against), a
// reference matcher written from devbox's spec finding every planted copy and nothing else, and the two things S-128 forbids: a
// file that lets someone confirm a guessed weak secret, and a file whose size or shape tells a reader a key's length.
import assert from 'node:assert/strict';
import { createHash, createHmac } from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';
import { test } from 'node:test';
import { buildShare, sealEnvelope, windowDigest } from '../src/pure/share-build.ts';
import { findDerived } from './kit/derived-forms.ts';
import { checkProperty, seedFor, seededRandom } from './kit/index.ts';
import { GOLDEN, GOLDEN_SIGNING_SEED_HEX, buildGolden, expectedFindings, goldenKeys, plantedDocuments, toShareKey } from './kit/share-golden.ts';
import { openShare } from './kit/reference-matcher.ts';
import type { Finding } from './kit/reference-matcher.ts';
import { base64Document, edgeOnlyDecoy, fakeJwt, fakeKey, interiorDecoy, rawDocument, signerFromSeed } from './kit/share-store.ts';
import type { FakeKey } from './kit/share-store.ts';

const seed = seedFor(process.env);
const FIXTURES = new URL('./fixtures/share-v3/', import.meta.url);
const fixture = (name: string): Buffer => readFileSync(new URL(name, FIXTURES));

const FORM_NAMES = ['raw', 'b64s0', 'b64s1', 'b64s2', 'b64u0', 'b64u1', 'b64u2'];

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

test('KBOX-33 the golden file is exactly what the box writes over the golden store (the cross-repo fixture)', () => {
  const store = JSON.parse(fixture('store.json').toString('utf8')) as { keys: { project: string; name: string; gen: number; retired: boolean; value: string }[] };
  const golden = buildGolden();
  assert.deepEqual(
    store.keys.map((k) => k.value),
    goldenKeys().map((k) => k.value),
    'store.json holds the values the golden file was made over',
  );
  assert.equal(Buffer.compare(fixture('share.json'), Buffer.from(golden.envelope)), 0, 'share.json is byte for byte the written envelope');
  assert.equal(Buffer.compare(fixture('body.json'), Buffer.from(golden.body)), 0, 'body.json is byte for byte the signed body');
  assert.equal(Buffer.compare(decodedBody(fixture('share.json')), fixture('body.json')), 0, 'the signature covers the exact decoded body_b64');
  const planted = readdirSync(new URL('planted/', FIXTURES)).filter((f) => f !== 'expected.json');
  assert.deepEqual(planted.sort(), Object.keys(plantedDocuments()).sort());
  for (const [file, content] of Object.entries(plantedDocuments())) assert.equal(Buffer.compare(fixture(`planted/${file}`), Buffer.from(content)), 0, file);
  assert.deepEqual(JSON.parse(fixture('planted/expected.json').toString('utf8')), expectedFindings());
});

test('KBOX-33 the golden file opens with the stored public key and finds each planted copy of its own key and nothing else', () => {
  const store = JSON.parse(fixture('store.json').toString('utf8')) as { public_key_ed25519_b64: string };
  const opened = openShare(fixture('share.json'), store.public_key_ed25519_b64);
  assert.ok(opened.ok);
  assert.equal(opened.share.version, GOLDEN.version);
  const expected = JSON.parse(fixture('planted/expected.json').toString('utf8')) as Record<string, string[]>;
  const watched = new Map(goldenKeys().filter((k) => k.shape.random).map((k) => [`${k.name}.${k.gen}`.toLowerCase(), `${k.project}/${k.name}/${k.gen}`]));
  for (const [file, keys] of Object.entries(expected)) {
    const hits: Finding[] = opened.share.scan(fixture(`planted/${file}`));
    const found: string[] = [...new Set(hits.map((f) => `${f.project}/${f.name}/${f.gen}`))];
    assert.deepEqual(found, keys, file);
    const owner = watched.get(file.split('.').slice(0, 2).join('.'));
    const isCopy = !file.includes('.decoy.') && owner !== undefined;
    assert.deepEqual(keys, isCopy ? [owner] : [], isCopy ? `${file} holds a copy of exactly one key` : `${file} holds no copy`);
  }
});

test('KBOX-33 the envelope is {format, v, body_b64, sig_b64} in that order, the signature is Ed25519 over the decoded body bytes', () => {
  const golden = buildGolden();
  const outer = JSON.parse(Buffer.from(golden.envelope).toString('utf8')) as Record<string, unknown>;
  assert.deepEqual(Object.keys(outer), ['format', 'v', 'body_b64', 'sig_b64']);
  assert.equal(outer['format'], 'kbox-share');
  assert.equal(outer['v'], 3);
  assert.equal(Buffer.from(String(outer['sig_b64']), 'base64').length, 64);
  assert.equal(Buffer.from(String(outer['body_b64']), 'base64').toString('base64'), outer['body_b64'], 'canonical base64, so the signed bytes are the decoded ones');
  assert.equal(golden.envelope[golden.envelope.length - 1], 0x7d, 'the envelope is one compact JSON object, no trailing newline');
});

test('KBOX-33 the header is {v, version, issued_at, salt_b64, set_id, stride} with stride 9, a 32-byte salt and no baseline', () => {
  const body = bodyOf(buildGolden().envelope);
  assert.deepEqual(Object.keys(body), ['header', 'entries', 'probes', 'coverage']);
  assert.deepEqual(Object.keys(body.header), ['v', 'version', 'issued_at', 'salt_b64', 'set_id', 'stride']);
  assert.equal(body.header['v'], 3);
  assert.equal(body.header['version'], GOLDEN.version);
  assert.equal(body.header['issued_at'], GOLDEN.issuedAt);
  assert.equal(body.header['stride'], 9);
  assert.equal(Buffer.from(String(body.header['salt_b64']), 'base64').length, 32);
  assert.ok(!('baseline' in body.header));
});

test('KBOX-33 set_id is the SHA-256 hex of the sorted (project, name, gen, retired) list, every generation of every admin and master key', () => {
  const keys = goldenKeys();
  const cmp = (a: unknown, b: unknown): number => (String(a) < String(b) ? -1 : String(a) > String(b) ? 1 : 0);
  const sorted = keys.map((k) => [k.project, k.name, k.gen, k.retired]).sort((a, b) => cmp(a[0], b[0]) || cmp(a[1], b[1]) || Number(a[2]) - Number(b[2]));
  const expected = createHash('sha256').update(JSON.stringify(sorted)).digest('hex');
  assert.equal(bodyOf(buildGolden().envelope).header['set_id'], expected);
  const shuffled = [...keys].reverse();
  assert.equal(bodyOf(fileOver(shuffled).envelope).header['set_id'], expected, 'the order the keys arrive in does not matter');
});

test('KBOX-33 the salt is new for every version: two files over the same store share no salt, no probe and no digest', () => {
  const a = bodyOf(fileOver(goldenKeys(), 1, 1).envelope);
  const b = bodyOf(fileOver(goldenKeys(), 2, 2).envelope);
  assert.notEqual(a.header['salt_b64'], b.header['salt_b64']);
  const ds = new Set(a.probes.map((p) => p.d));
  assert.ok(b.probes.every((p) => !ds.has(p.d)));
  const digests = new Set(a.entries.map((e) => e.digest).filter((d) => d !== undefined));
  assert.ok(b.entries.every((e) => e.digest === undefined || !digests.has(e.digest)));
});

test('KBOX-33 entries: seven per generation named by form, windowed entries carry no length and no digest, anchored ones the closed seven members', () => {
  const body = bodyOf(buildGolden().envelope);
  const watched = goldenKeys().filter((k) => k.name !== 'SUPABASE_DB_PASSWORD');
  assert.equal(body.entries.length, 7 * watched.length, 'one entry per form per watched generation, none for the not-watched key');
  for (const key of watched) {
    const mine = body.entries.filter((e) => e.project === key.project && e.name === key.name && e.gen === key.gen);
    assert.deepEqual(mine.map((e) => e.form), FORM_NAMES, `${key.name} gen ${key.gen}`);
    assert.ok(mine.every((e) => e.retired === key.retired));
  }
  for (const entry of body.entries) {
    assert.ok(FORM_NAMES.includes(entry.form));
    if (entry.tier === 'windowed') assert.deepEqual(Object.keys(entry), ['project', 'name', 'gen', 'retired', 'tier', 'form']);
    else assert.deepEqual(Object.keys(entry), ['project', 'name', 'gen', 'retired', 'tier', 'form', 'anchor', 'len', 'digest']);
  }
});

test('KBOX-33 probes: every windowed entry has exactly 40, with j = 0, 9, ... 351 and a 64-hex d, whatever the key', () => {
  const body = bodyOf(buildGolden().envelope);
  const windowed = body.entries.flatMap((e, i) => (e.tier === 'windowed' ? [i] : []));
  assert.ok(windowed.length >= 21, 'the golden store has three windowed generations at least');
  for (const index of windowed) {
    const mine = body.probes.filter((p) => p.entry === index);
    assert.deepEqual(mine.map((p) => p.j), Array.from({ length: 40 }, (_, i) => i * 9));
    assert.ok(mine.every((p) => /^[0-9a-f]{64}$/.test(p.d)));
    assert.ok(mine.every((p) => Object.keys(p).join() === 'entry,j,d'));
  }
  assert.equal(body.probes.length, 40 * windowed.length, 'no probe belongs to an anchored entry');
  assert.equal(new Set(body.probes.map((p) => p.d)).size, body.probes.length, 'no two probes are equal');
});

test('KBOX-33 no two probes are equal even when the standard and url interiors are the same text, or equal digests would show which slots are real', () => {
  const rng = seededRandom(77);
  const letters = Array.from({ length: 64 }, () => 'abcdefghijklmnopqrstuvwxyz'[rng.int(26)]).join('');
  const key: FakeKey = { ...fakeKey(rng, 'LOWER', 64), value: letters, core: letters };
  const { envelope, publicKey } = fileOver([key]);
  const body = bodyOf(envelope);
  const salt = Buffer.from(String(body.header['salt_b64']), 'base64');
  const std = Buffer.from(letters).toString('base64');
  assert.equal(std.replace(/=+$/, ''), Buffer.from(letters).toString('base64url'), 'control: a lower-case core has the same standard and url text at alignment 0');
  const mac = (text: string): string => createHmac('sha256', salt).update(text).digest('hex');
  assert.equal(body.probes.length, 280);
  assert.equal(new Set(body.probes.map((p) => p.d)).size, 280, 'every digest in the file is different');
  const real = body.probes.filter((p) => p.entry === 1 && p.d === mac(std.slice(p.j, p.j + 24)));
  assert.ok(real.length > 0, 'the standard form keeps its windows');
  assert.ok(!body.probes.some((p) => p.entry === 4 && p.d === mac(std.slice(p.j, p.j + 24))), 'the url form\'s copy of the same window is a decoy');
  const opened = openShare(envelope, publicKey);
  assert.ok(opened.ok);
  for (const content of [base64Document(letters, 0, true), base64Document(letters, 0, false)]) assert.ok(opened.share.scan(content).length > 0, 'a url or a standard copy is still found');
});

test('KBOX-33 a real probe is the HMAC-SHA256 of a 24-character window of a form, a decoy is not the digest of anything of the key', () => {
  const key = fakeKey(seededRandom(9), 'K', 40, { alphabet: 'hex' });
  const body = bodyOf(fileOver([key]).envelope);
  const salt = Buffer.from(String(body.header['salt_b64']), 'base64');
  const raw = body.probes.filter((p) => p.entry === 0);
  const mac = (text: string): string => createHmac('sha256', salt).update(text).digest('hex');
  assert.deepEqual(
    raw.slice(0, 2).map((p) => p.d),
    [mac(key.core.slice(0, 24)), mac(key.core.slice(9, 33))],
    'j = 0 and 9 are windows of the 40-character raw form',
  );
  const everyWindow = new Set(Array.from({ length: 17 }, (_, i) => mac(key.core.slice(i, i + 24))));
  assert.ok(raw.slice(2).every((p) => !everyWindow.has(p.d)), 'j = 18 on would run past the end of the form: those slots are decoys, the digest of no window of the key');
  assert.equal(raw.length, 40);
});

test('KBOX-33 form names are the closed seven and never form text; an entry is its index and a probe names it', () => {
  const body = bodyOf(buildGolden().envelope);
  const text = decodedBody(buildGolden().envelope).toString('utf8');
  for (const key of goldenKeys()) assert.ok(!text.includes(key.core.slice(0, 8)), 'no form text');
  assert.ok(body.probes.every((p) => Number.isInteger(p.entry) && p.entry >= 0 && p.entry < body.entries.length));
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

test('KBOX-33 a 28-character GOCSPX- core gets an anchored entry per form and no window, and the anchor is the prefix as that form spells it', () => {
  const key = fakeKey(seededRandom(3), 'GOOGLE_CLIENT_SECRET', 28, { prefix: 'GOCSPX-', alphabet: 'base64url' });
  const body = bodyOf(fileOver([key]).envelope);
  assert.equal(body.entries.length, 7);
  assert.ok(body.entries.every((e) => e.tier === 'anchored'));
  assert.deepEqual(body.probes, [], 'no windows');
  for (const [i, entry] of body.entries.entries()) {
    const url = entry.form.startsWith('b64u');
    const alignment = entry.form === 'raw' ? 0 : Number(entry.form.slice(-1));
    if (entry.form === 'raw') {
      assert.equal(entry.anchor, 'GOCSPX-');
      assert.equal(entry.len, 28);
      continue;
    }
    // The prefix as it reads inside a base64 text where the value starts at byte offset `alignment` mod 3.
    const whole = Buffer.concat([Buffer.alloc(alignment), Buffer.from(key.value)]).toString(url ? 'base64url' : 'base64');
    const first = Math.ceil((8 * alignment) / 6);
    const last = Math.floor((8 * (alignment + 7)) / 6);
    assert.equal(entry.anchor, whole.slice(first, last), `entry ${i} ${entry.form}`);
    assert.ok(!entry.anchor?.includes(key.core.slice(0, 4)));
  }
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

test('KBOX-33 no probe is the digest of ANY 24-character window that touches a prefix or a JWT header or payload, in any form at any offset', () => {
  const { envelope } = fileOver(goldenKeys());
  const body = bodyOf(envelope);
  const salt = Buffer.from(String(body.header['salt_b64']), 'base64');
  const probed = new Set(body.probes.map((p) => p.d));
  const mac = (text: string): string => createHmac('sha256', salt).update(text, 'latin1').digest('hex');
  const withPublicPart = goldenKeys().filter((k) => k.value !== k.core);
  assert.ok(withPublicPart.length >= 4, 'sb_secret_, GOCSPX-, vcp_ and the JWT');
  for (const key of withPublicPart) {
    const publicChars = key.value.length - key.core.length;
    const texts: { readonly text: string; readonly firstCoreChar: number }[] = [{ text: key.value, firstCoreChar: publicChars }];
    for (const a of [0, 1, 2]) {
      const whole = Buffer.concat([Buffer.alloc(a), Buffer.from(key.value)]);
      for (const kind of ['base64', 'base64url'] as const) texts.push({ text: whole.toString(kind), firstCoreChar: Math.ceil((8 * (a + publicChars)) / 6) });
    }
    for (const { text, firstCoreChar } of texts) {
      for (let i = 0; i < firstCoreChar && i + 24 <= text.length; i += 1) assert.ok(!probed.has(mac(text.slice(i, i + 24))), `${key.name}: a window at ${i} of a form touches the public part`);
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

test('KBOX-33 two stores that differ only in windowed key length (32, 64 and 256 characters) give the same entries, the same j set and bodies of the same size, with no len', () => {
  const stores = [32, 64, 256].map((length) => lengthStore(seededRandom(length), [length], []));
  const files = stores.map((keys) => fileOver(keys).envelope);
  const bodies = files.map(bodyOf);
  for (const body of bodies) {
    assert.equal(body.entries.length, 7);
    assert.equal(body.probes.length, 280);
    assert.ok(body.entries.every((e) => !('len' in e) && !('digest' in e) && !('anchor' in e)));
    assert.deepEqual([...new Set(body.probes.map((p) => p.j))], Array.from({ length: 40 }, (_, i) => i * 9));
  }
  assert.deepEqual(bodies.map((b) => shapeOf(b)), [shapeOf(at(bodies, 0)), shapeOf(at(bodies, 0)), shapeOf(at(bodies, 0))], 'identical shape');
  assert.deepEqual(files.map((f) => f.length), [at(files, 0).length, at(files, 0).length, at(files, 0).length], 'identical size');
  assert.deepEqual(files.map((f) => decodedBody(f).length), [decodedBody(at(files, 0)).length, decodedBody(at(files, 0)).length, decodedBody(at(files, 0)).length]);
});

test(`KBOX-33 property: stores of keys of different lengths with the same count per tier give files of identical size and shape (seed ${seed})`, () => {
  checkProperty(seed, 25, (rng) => {
    const windowedCount = 1 + rng.int(3);
    const anchoredCount = rng.int(3);
    const draw = (): { windowed: number[]; anchored: number[] } => ({
      windowed: Array.from({ length: windowedCount }, () => 32 + rng.int(225)),
      anchored: Array.from({ length: anchoredCount }, () => 20 + rng.int(12)),
    });
    const a = draw();
    const b = draw();
    const left = fileOver(lengthStore(seededRandom(rng.int(1e6)), a.windowed, a.anchored), 5);
    const right = fileOver(lengthStore(seededRandom(rng.int(1e6)), b.windowed, b.anchored), 6);
    const [bodyA, bodyB] = [bodyOf(left.envelope), bodyOf(right.envelope)];
    assert.deepEqual(shapeOf(bodyA), shapeOf(bodyB), 'same shape');
    assert.equal(left.envelope.length, right.envelope.length, `same size for windowed ${a.windowed} against ${b.windowed}`);
    assert.equal(decodedBody(left.envelope).length, decodedBody(right.envelope).length);
    assert.deepEqual(
      bodyA.probes.map((p) => [p.entry, p.j]),
      bodyB.probes.map((p) => [p.entry, p.j]),
      'same probes by entry and j: which slots hold a window is not visible',
    );
  });
});

test(`KBOX-33 property: a windowed key of any eligible length has the same probe count and j set, and its windows are the only slots that depend on it (seed ${seed})`, () => {
  checkProperty(seed, 20, (rng) => {
    const length = 32 + rng.int(225);
    const key = fakeKey(rng, 'K', length, { alphabet: ['base62', 'hex', 'base64url'][rng.int(3)] as 'base62' | 'hex' | 'base64url' });
    const body = bodyOf(fileOver([key], rng.int(1e6)).envelope);
    assert.equal(body.entries.length, 7);
    assert.equal(body.probes.length, 280);
    for (let e = 0; e < 7; e += 1) assert.deepEqual(body.probes.filter((p) => p.entry === e).map((p) => p.j), Array.from({ length: 40 }, (_, i) => i * 9));
    // The reference matcher still finds the copy: the probes cover every eligible length.
    const opened = openShare(fileOver([key], 8).envelope, signerFromSeed(Buffer.from(GOLDEN_SIGNING_SEED_HEX, 'hex')).publicKeyRawB64);
    assert.ok(opened.ok);
    assert.ok(opened.share.scan(base64Document(key.value, 1, false)).length > 0);
    assert.ok(opened.share.scan(rawDocument(key.value)).length > 0);
  });
});

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

test('KBOX-33 the reader fails closed on a file older than one it has seen, a wrong format, or a body that breaks the layout', () => {
  const golden = buildGolden();
  const refusal = (r: ReturnType<typeof openShare>): string => (r.ok ? 'opened' : r.code);
  assert.equal(refusal(openShare(golden.envelope, golden.signer.publicKeyRawB64, { lastVersion: GOLDEN.version })), 'opened', 'the same version is not a rollback');
  assert.equal(refusal(openShare(golden.envelope, golden.signer.publicKeyRawB64, { lastVersion: GOLDEN.version + 1 })), 'rolled_back');
  assert.equal(refusal(openShare(Buffer.from('{"format":"kbox-share","v":2}'), golden.signer.publicKeyRawB64)), 'bad_envelope');
  assert.equal(refusal(openShare(Buffer.from('not json'), golden.signer.publicKeyRawB64)), 'bad_envelope');
  const body = bodyOf(golden.envelope);
  const resign = (changed: unknown): Uint8Array => {
    const bytes = Buffer.from(JSON.stringify(changed));
    return Buffer.from(JSON.stringify({ format: 'kbox-share', v: 3, body_b64: bytes.toString('base64'), sig_b64: Buffer.from(golden.signer.sign(bytes)).toString('base64') }));
  };
  assert.equal(refusal(openShare(resign({ ...body, probes: body.probes.slice(1) }), golden.signer.publicKeyRawB64)), 'bad_body', 'a windowed entry with 39 probes');
  assert.equal(refusal(openShare(resign({ ...body, header: { ...body.header, stride: 8 } }), golden.signer.publicKeyRawB64)), 'bad_body', 'stride 8');
  assert.equal(refusal(openShare(resign({ ...body, header: { ...body.header, baseline: {} } }), golden.signer.publicKeyRawB64)), 'bad_body', 'a baseline member');
  const firstWindowed = body.entries.findIndex((e) => e.tier === 'windowed');
  assert.ok(firstWindowed >= 0);
  assert.equal(refusal(openShare(resign({ ...body, entries: body.entries.map((e, i) => (i === firstWindowed ? { ...e, len: 40 } : e)) }), golden.signer.publicKeyRawB64)), 'bad_body', 'a len on a windowed entry');
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
