// The golden share file (KBOX-33): a synthetic store of fake values, the file the box writes over it, and documents with planted
// copies. The files under test/fixtures/share-v4/ are what this builds; devbox's v4 reader (admin-match) runs them too. Run with
// `write <dir>` it (re)writes them; run with no arguments (as `node --test` does to every file under test/) it does nothing.
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { buildShare, sealEnvelope } from '../../src/pure/share-build.ts';
import type { ShareKey } from '../../src/pure/share-build.ts';
import { openShare } from './reference-matcher.ts';
import { seededRandom } from './random.ts';
import { base64Document, fakeJwt, fakeKey, interiorDecoy, rawDocument, signerFromSeed } from './share-store.ts';
import type { FakeKey, TestSigner } from './share-store.ts';

/** RFC 8032 section 7.1 test 1's seed: a published vector, never a box key. */
export const GOLDEN_SIGNING_SEED_HEX = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60';
export const GOLDEN = { keySeed: 20261111, randomSeed: 33, version: 7, issuedAt: 1_700_000_000_000 } as const;

export function goldenKeys(): FakeKey[] {
  const rng = seededRandom(GOLDEN.keySeed);
  return [
    fakeKey(rng, 'SUPABASE_SERVICE_KEY', 40, { project: 'shop', prefix: 'sb_secret_' }),
    fakeKey(rng, 'OPENAI_ADMIN_KEY', 64, { project: 'shop', alphabet: 'hex' }),
    fakeKey(rng, 'OPENAI_ADMIN_KEY', 64, { project: 'shop', alphabet: 'hex', gen: 2, retired: true }),
    fakeJwt(rng, 'SUPABASE_JWT', { project: 'shop' }),
    fakeKey(rng, 'GOOGLE_CLIENT_SECRET', 28, { project: 'shop', prefix: 'GOCSPX-', alphabet: 'base64url' }),
    fakeKey(rng, 'VERCEL_TOKEN', 24, { project: 'site', prefix: 'vcp_' }),
    { ...fakeKey(rng, 'SUPABASE_DB_PASSWORD', 60, { project: 'shop' }), shape: { prefix: null, alphabet: 'base62', coreLength: { min: 8, max: 40 }, random: false } },
  ];
}

export const toShareKey = (k: FakeKey): ShareKey => ({ project: k.project, name: k.name, gen: k.gen, retired: k.retired, shape: k.shape, origin: k.origin, value: k.value });

export interface Golden {
  readonly signer: TestSigner;
  readonly envelope: Uint8Array;
  readonly body: Uint8Array;
}

export function buildGolden(keys: readonly FakeKey[] = goldenKeys()): Golden {
  const signer = signerFromSeed(Buffer.from(GOLDEN_SIGNING_SEED_HEX, 'hex'));
  const built = buildShare({ version: GOLDEN.version, issuedAt: GOLDEN.issuedAt, random: seededRandom(GOLDEN.randomSeed), keys: keys.map(toShareKey) });
  return { signer, envelope: sealEnvelope(built.bytes, signer.sign(built.bytes)), body: built.bytes };
}

/** File name to content: one copy of one key each, then documents with no copy at all. */
export function plantedDocuments(keys: readonly FakeKey[] = goldenKeys()): Record<string, Uint8Array> {
  const docs: Record<string, Uint8Array> = {};
  for (const key of keys) {
    const slug = `${key.name}.${key.gen}`.toLowerCase();
    docs[`${slug}.raw.txt`] = rawDocument(key.value);
    for (const a of [0, 1, 2] as const) {
      docs[`${slug}.b64s${a}.txt`] = base64Document(key.value, a, false);
      docs[`${slug}.b64u${a}.txt`] = base64Document(key.value, a, true);
    }
    docs[`${slug}.b64s1.wrap64.txt`] = base64Document(key.value, 1, false, { columns: 64, lineBreak: '\r\n' });
    docs[`${slug}.b64u2.wrap76.txt`] = base64Document(key.value, 2, true, { columns: 76, lineBreak: '\r\n' });
    docs[`${slug}.decoy.txt`] = rawDocument(interiorDecoy(key));
  }
  docs['nothing.txt'] = Buffer.from('no key here, only text that looks like a log line: build 4412 passed in 31 s\n');
  return docs;
}

/** What the reference matcher finds in each planted document, by key: the cross-repo expectation. */
export function expectedFindings(keys: readonly FakeKey[] = goldenKeys()): Record<string, string[]> {
  const golden = buildGolden(keys);
  const opened = openShare(golden.envelope, golden.signer.publicKeyRawB64);
  if (!opened.ok) throw new Error(`the golden file does not open: ${opened.code}`);
  return Object.fromEntries(
    Object.entries(plantedDocuments(keys)).map(([file, content]) => [
      file,
      [...new Set(opened.share.scan(content).map((f) => `${f.project}/${f.name}/${f.gen}`))],
    ]),
  );
}

const [mode, dir] = process.argv.slice(2);
if (mode === 'write' && dir !== undefined) {
  const keys = goldenKeys();
  const golden = buildGolden(keys);
  mkdirSync(join(dir, 'planted'), { recursive: true });
  const store = {
    note: 'synthetic: fake values, never a real key; the signing seed is the RFC 8032 test 1 vector',
    signing_seed_hex: GOLDEN_SIGNING_SEED_HEX,
    public_key_ed25519_b64: golden.signer.publicKeyRawB64,
    random_seed: GOLDEN.randomSeed,
    version: GOLDEN.version,
    issued_at: GOLDEN.issuedAt,
    keys: keys.map((k) => ({ project: k.project, name: k.name, gen: k.gen, retired: k.retired, origin: k.origin, shape: k.shape, value: k.value })),
  };
  writeFileSync(join(dir, 'store.json'), `${JSON.stringify(store, null, 2)}\n`);
  writeFileSync(join(dir, 'share.json'), golden.envelope);
  writeFileSync(join(dir, 'body.json'), golden.body);
  for (const [file, content] of Object.entries(plantedDocuments(keys))) writeFileSync(join(dir, 'planted', file), content);
  writeFileSync(join(dir, 'planted', 'expected.json'), `${JSON.stringify(expectedFindings(keys), null, 2)}\n`);
}
