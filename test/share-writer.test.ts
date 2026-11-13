// KBOX-33: the share writer. It runs at start and on every key.changed of an admin or master key, signs with a key of its own kept in
// the vault, writes the file durably, and announces the version only afterwards; GET /api/share fails closed when the file is stale.
import assert from 'node:assert/strict';
import { createPublicKey, verify } from 'node:crypto';
import { existsSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import type { KeyRow } from '../src/ports/meta.ts';
import type { ShareSource } from '../src/ports/share.ts';
import { WriteRefused } from '../src/pure/errors.ts';
import { buildShare, sealEnvelope, summaryOf } from '../src/pure/share-build.ts';
import { shareSigner } from '../src/shell/share-writer.ts';
import { GOLDEN_SIGNING_SEED_HEX, toShareKey } from './kit/share-golden.ts';
import { openShare } from './kit/reference-matcher.ts';
import { base64Document, fakeKey, rawDocument, signerFromSeed } from './kit/share-store.ts';
import type { FakeKey } from './kit/share-store.ts';
import { FakeClock, TimedClock, drive, seededRandom, startNode, tempDir, waitUntil } from './kit/index.ts';
import { hashToken, newToken } from '../src/pure/tokens.ts';
import { openCore } from '../src/shell/core.ts';
import { shareWorld } from './support/share-world.ts';
import type { ShareWorld } from './support/share-world.ts';

const rng = seededRandom(404);
const windowed = (name: string, gen = 1, over: { retired?: boolean } = {}): FakeKey => fakeKey(rng, name, 48, { project: 'shop', gen, ...over });

const row = (name: string, gen: number, keyClass: KeyRow['class'] = 'admin'): KeyRow => ({
  keyref: `openai/${name.toLowerCase()}`,
  platform: 'openai',
  name,
  projects: ['shop'],
  class: keyClass,
  status: 'works',
  gen_current: gen,
  schedule: { rotate_every_days: 30, grace_hours: 24, next_due_at: null, expires_at: null },
  coverage: null,
  last_use_at: null,
});

const shareVersions = (w: ShareWorld): number[] => w.core.events.after(0).filter((e) => e.kind === 'share.version').map((e) => Number(e.data['version']));
const fileOf = (w: ShareWorld): Buffer => readFileSync(join(w.shareDir, 'share.json'));
const publicKeyOf = (w: ShareWorld): string => {
  const key = w.core.meta.snapshot().box.share_public_key_ed25519_b64;
  assert.ok(key !== null, 'the box shows its share public key');
  return key;
};

// ---------------------------------------------------------------- the first start

test('KBOX-33 at start the writer writes version 1, signed by a key the box shows in GET /api/meta, and announces it once', async (t) => {
  const w = await shareWorld(t, { store: [windowed('OPENAI_ADMIN_KEY')] });
  assert.deepEqual(shareVersions(w), [1]);
  const box = w.core.meta.snapshot().box;
  assert.equal(box.share_version, 1);
  const opened = openShare(fileOf(w), publicKeyOf(w));
  assert.ok(opened.ok, 'the file verifies with the public key the box shows');
  assert.equal(opened.share.version, 1);
  const meta = await w.core.call('/api/meta', { token: w.core.enrol('mc', 'control') });
  assert.equal((meta.json() as { box: { share_public_key_ed25519_b64: string } }).box.share_public_key_ed25519_b64, publicKeyOf(w));
});

test('KBOX-33 first start generates the signing key once as a master value in the vault; a restart reuses it', async (t) => {
  const w = await shareWorld(t, { store: [windowed('OPENAI_ADMIN_KEY')] });
  const keyFile = join(w.core.stateDir, 'vault', 'keybox', 'share-signing', '1');
  assert.ok(existsSync(keyFile), 'the signing key is a vault generation');
  assert.equal(statSync(keyFile).mode & 0o777, 0o600);
  const before = readFileSync(keyFile);
  const publicKey = publicKeyOf(w);
  const second = await shareWorld(t, { stateDir: w.core.stateDir, store: w.store });
  assert.equal(publicKeyOf(second), publicKey, 'the public half is the same after a restart');
  assert.equal(Buffer.compare(readFileSync(keyFile), before), 0, 'the key was not generated again');
  assert.deepEqual(readdirSync(join(w.core.stateDir, 'vault', 'keybox', 'share-signing')), ['1']);
});

test('KBOX-33 the signing key is never in the share file, the audit log, an event or the metadata', async (t) => {
  const w = await shareWorld(t, { store: [windowed('OPENAI_ADMIN_KEY')] });
  const seed = readFileSync(join(w.core.stateDir, 'vault', 'keybox', 'share-signing', '1'));
  const surfaces = [fileOf(w).toString('latin1'), JSON.stringify(w.core.events.after(0)), JSON.stringify(w.core.audit.read(0).entries), JSON.stringify(w.core.meta.snapshot())];
  for (const surface of surfaces) for (const needle of [seed.toString('hex'), seed.toString('base64'), seed.toString('base64url'), seed.toString('latin1')]) assert.ok(!surface.includes(needle));
});

test('KBOX-33 known answers: the signer is Ed25519 over the exact bytes (RFC 8032 test 1 key and empty message)', () => {
  const signer = shareSigner(Buffer.from(GOLDEN_SIGNING_SEED_HEX, 'hex'));
  assert.equal(signer.publicKeyB64, Buffer.from('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a', 'hex').toString('base64'));
  assert.equal(
    Buffer.from(signer.sign(new Uint8Array(0))).toString('hex'),
    'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b',
  );
  const spki = Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(signer.publicKeyB64, 'base64')]);
  const message = Buffer.from('a body');
  assert.ok(verify(null, message, createPublicKey({ key: spki, format: 'der', type: 'spki' }), signer.sign(message)));
  assert.ok(!verify(null, Buffer.from('a bodz'), createPublicKey({ key: spki, format: 'der', type: 'spki' }), signer.sign(message)));
});

// ---------------------------------------------------------------- a new version when a generation, retirement or tier changes

test('KBOX-33 a key.changed after a generation change, a retirement and a tier change each gives a new version and exactly one share.version', async (t) => {
  const first = windowed('OPENAI_ADMIN_KEY', 1);
  const w = await shareWorld(t, { store: [first] });
  w.core.meta.putKey(row('OPENAI_ADMIN_KEY', 1));
  await w.writer.idle();
  assert.deepEqual(shareVersions(w), [1], 'the first key.changed changed nothing the file shows beyond what start wrote');

  w.store.push(windowed('OPENAI_ADMIN_KEY', 2));
  w.core.meta.putKey(row('OPENAI_ADMIN_KEY', 2));
  await w.writer.idle();
  assert.deepEqual(shareVersions(w), [1, 2], 'a generation change');

  w.store[0] = { ...first, retired: true };
  w.core.meta.putKey(row('OPENAI_ADMIN_KEY', 2));
  await w.writer.idle();
  assert.deepEqual(shareVersions(w), [1, 2, 3], 'a retirement');

  const second = fakeKey(rng, 'OPENAI_ADMIN_KEY', 20, { project: 'shop', gen: 2 });
  w.store[1] = { ...second, shape: { ...second.shape, random: false } };
  w.core.meta.putKey(row('OPENAI_ADMIN_KEY', 2));
  await w.writer.idle();
  assert.deepEqual(shareVersions(w), [1, 2, 3, 4], 'a coverage tier change');

  const summary = summaryOf(fileOf(w));
  assert.equal(summary?.version, 4);
  assert.equal(w.core.meta.snapshot().box.share_version, 4);
  const opened = openShare(fileOf(w), publicKeyOf(w), { lastVersion: 4 });
  assert.ok(opened.ok);
  assert.deepEqual(opened.share.scan(rawDocument(second.value)), [], 'the key that became not-watched is no longer found');
  assert.ok(opened.share.scan(rawDocument(first.value)).every((f) => f.retired), 'the retired generation is still found, as retired');
});

test('KBOX-33 a key.changed that changes nothing the file shows writes no new version; an ordinary key reads nothing', async (t) => {
  const w = await shareWorld(t, { store: [windowed('OPENAI_ADMIN_KEY')] });
  const reads = w.reads();
  w.core.meta.putKey(row('OPENAI_ADMIN_KEY', 1));
  await w.writer.idle();
  assert.equal(w.reads(), reads + 1, 'an admin key.changed is looked at');
  assert.deepEqual(shareVersions(w), [1], 'and shows the same file, so there is no new version');
  w.core.meta.putKey(row('SOME_ORDINARY_KEY', 1, 'ordinary'));
  await w.writer.idle();
  assert.equal(w.reads(), reads + 1, 'an ordinary key is not in the file: its key.changed reads nothing');
  assert.deepEqual(shareVersions(w), [1]);
});

test('KBOX-33 the master class counts like admin', async (t) => {
  const w = await shareWorld(t, { store: [windowed('GOOGLE_MASTER')] });
  w.store.push(windowed('GOOGLE_MASTER', 2));
  w.core.meta.putKey(row('GOOGLE_MASTER', 2, 'master'));
  await w.writer.idle();
  assert.deepEqual(shareVersions(w), [1, 2]);
});

// ---------------------------------------------------------------- durable before announced, and versions that only rise

test('KBOX-33 the version is announced only after the file is durable, never before: the file already holds it when the event is written', async (t) => {
  const seen: { version: number; onDisk: number | undefined }[] = [];
  let dir = '';
  const w = await shareWorld(t, {
    store: [windowed('OPENAI_ADMIN_KEY')],
    noStart: true,
    meta: (real) => ({
      ...real,
      snapshot: () => real.snapshot(),
      shareState: () => real.shareState(),
      setSharePublicKey: (key) => real.setSharePublicKey(key),
      announceShare: (version) => {
        const file = join(dir, 'share.json');
        seen.push({ version, onDisk: existsSync(file) ? summaryOf(readFileSync(file))?.version : undefined });
        real.announceShare(version);
      },
    }),
  });
  dir = w.shareDir;
  await w.writer.start();
  w.store.push(windowed('OPENAI_ADMIN_KEY', 2));
  w.core.meta.putKey(row('OPENAI_ADMIN_KEY', 2));
  await w.writer.idle();
  assert.deepEqual(seen, [{ version: 1, onDisk: 1 }, { version: 2, onDisk: 2 }]);
});

test('KBOX-33 a crash between write and announce: the restart announces the durable file and the next version is higher, none repeated or lower', async (t) => {
  let crash = true;
  const first = await shareWorld(t, {
    store: [windowed('OPENAI_ADMIN_KEY')],
    noStart: true,
    meta: (real) => ({
      ...real,
      announceShare: (version) => {
        if (crash) throw new Error('crash before the announce');
        real.announceShare(version);
      },
    }),
  });
  await assert.rejects(first.writer.start());
  assert.equal(summaryOf(fileOf(first))?.version, 1, 'the file is durable');
  assert.deepEqual(shareVersions(first), [], 'and nothing was announced');
  assert.equal(first.core.meta.snapshot().box.share_version, 0);
  crash = false;
  first.writer.stop();

  const second = await shareWorld(t, { stateDir: first.core.stateDir, store: first.store });
  assert.deepEqual(shareVersions(second), [1], 'the restart announces the file that is already served, not a lower or a repeated version');
  second.store.push(windowed('OPENAI_ADMIN_KEY', 2));
  second.core.meta.putKey(row('OPENAI_ADMIN_KEY', 2));
  await second.writer.idle();
  assert.deepEqual(shareVersions(second), [1, 2]);
  const versions = shareVersions(second);
  assert.deepEqual(versions, [...versions].sort((a, b) => a - b));
});

test('KBOX-33 a share file already on disk that this box did not sign (a restored or foreign one) is never trusted: the new version is above its version', async (t) => {
  const old = await shareWorld(t, { store: [windowed('OPENAI_ADMIN_KEY')] });
  for (let gen = 2; gen <= 4; gen += 1) {
    old.store.push(windowed('OPENAI_ADMIN_KEY', gen));
    old.core.meta.putKey(row('OPENAI_ADMIN_KEY', gen));
    await old.writer.idle();
  }
  assert.deepEqual(shareVersions(old), [1, 2, 3, 4]);
  old.writer.stop();
  // A fresh database (share_version 0) and a fresh vault (another signing key) beside the share directory that holds version 4.
  const restored = await shareWorld(t, { store: old.store, shareDir: old.shareDir, seed: 99 });
  assert.deepEqual(shareVersions(restored), [5], 'above the file already out there, whatever the database says');
  assert.equal(summaryOf(fileOf(restored))?.version, 5);
  assert.ok(openShare(fileOf(restored), publicKeyOf(restored), { lastVersion: 4 }).ok, 'the new file is signed by this box\'s key and is not a rollback for a reader that saw version 4');
});

test('KBOX-33 a share file on disk that cannot be read is replaced by a new version, never served', async (t) => {
  const w = await shareWorld(t, { store: [windowed('OPENAI_ADMIN_KEY')] });
  w.writer.stop();
  writeFileSync(join(w.shareDir, 'share.json'), '{"torn":');
  const again = await shareWorld(t, { stateDir: w.core.stateDir, store: w.store });
  assert.ok(openShare(fileOf(again), publicKeyOf(again)).ok);
  assert.equal(summaryOf(fileOf(again))?.version, 2);
});

test('KBOX-33 the write leaves one file and no temporary one, readable by the group of the box and not writable by it', async (t) => {
  const w = await shareWorld(t, { store: [windowed('OPENAI_ADMIN_KEY')] });
  w.store.push(windowed('OPENAI_ADMIN_KEY', 2));
  w.core.meta.putKey(row('OPENAI_ADMIN_KEY', 2));
  await w.writer.idle();
  assert.deepEqual(readdirSync(w.shareDir), ['share.json']);
  assert.equal(statSync(join(w.shareDir, 'share.json')).mode & 0o777, 0o644);
});

// ---------------------------------------------------------------- the route, and failing closed

test('KBOX-33 GET /api/share (scope control) returns the current envelope byte for byte with KB-Share-Version', async (t) => {
  const w = await shareWorld(t, { store: [windowed('OPENAI_ADMIN_KEY')] });
  const control = w.core.enrol('mc', 'control');
  const reply = await w.core.call('/api/share', { token: control });
  assert.equal(reply.status, 200);
  assert.equal(reply.headers['kb-share-version'], '1');
  assert.match(String(reply.headers['content-type']), /^application\/json/);
  assert.equal(Buffer.compare(Buffer.from(reply.body), fileOf(w)), 0);
  w.store.push(windowed('OPENAI_ADMIN_KEY', 2));
  w.core.meta.putKey(row('OPENAI_ADMIN_KEY', 2));
  await w.writer.idle();
  const next = await w.core.call('/api/share', { token: control });
  assert.equal(next.headers['kb-share-version'], '2');
});

test('KBOX-33 GET /api/share is refused to a relay token and to a call with no token', async (t) => {
  const w = await shareWorld(t, { store: [windowed('OPENAI_ADMIN_KEY')] });
  assert.equal((await w.core.call('/api/share', { token: w.core.enrol('relay', 'relay') })).status, 403);
  assert.equal((await w.core.call('/api/share')).status, 401);
});

test('KBOX-33 when the store cannot be read after a key change the share file is stale and GET /api/share says so (503) until it is refreshed', async (t) => {
  const w = await shareWorld(t, { store: [windowed('OPENAI_ADMIN_KEY')] });
  const control = w.core.enrol('mc', 'control');
  w.store.push(windowed('OPENAI_ADMIN_KEY', 2));
  w.failNextReads(1);
  w.core.meta.putKey(row('OPENAI_ADMIN_KEY', 2));
  await w.writer.idle();
  assert.deepEqual(w.failures(), ['refresh_failed'], 'one audit row with a fixed code, no text of the failure');
  const stale = await w.core.call('/api/share', { token: control });
  assert.equal(stale.status, 503);
  assert.deepEqual((stale.json() as { error: { code: string; detail: { code: string } } }).error.detail, { code: 'share_stale' });
  assert.deepEqual(shareVersions(w), [1], 'no new version was announced');
  w.core.meta.putKey(row('OPENAI_ADMIN_KEY', 2));
  await w.writer.idle();
  const fresh = await w.core.call('/api/share', { token: control });
  assert.equal(fresh.status, 200);
  assert.equal(fresh.headers['kb-share-version'], '2');
});

test('KBOX-33 before the first file exists GET /api/share is 503, not an empty file', async (t) => {
  const w = await shareWorld(t, { store: [], noStart: true });
  const reply = await w.core.call('/api/share', { token: w.core.enrol('mc', 'control') });
  assert.equal(reply.status, 503);
});

test('KBOX-33 a failing first start rejects with a fixed error that names no value', async (t) => {
  const w = await shareWorld(t, { store: [windowed('OPENAI_ADMIN_KEY')], noStart: true });
  w.failNextReads(1);
  await assert.rejects(w.writer.start(), (error: unknown) => error instanceof Error && !error.message.includes(w.store[0]?.core ?? 'x'));
});

// ---------------------------------------------------------------- the metadata port

test('KBOX-33 the box cannot announce a version that is not higher than the last, and writes nothing when it refuses', async (t) => {
  const w = await shareWorld(t, { store: [windowed('OPENAI_ADMIN_KEY')] });
  const events = w.core.events.head();
  assert.throws(() => w.core.meta.announceShare(1), WriteRefused);
  assert.throws(() => w.core.meta.announceShare(0), WriteRefused);
  assert.equal(w.core.events.head(), events);
  assert.equal(w.core.meta.shareState().version, 1);
});

test('KBOX-33 the share public key is set once: a different key later is refused', async (t) => {
  const w = await shareWorld(t, { store: [] });
  const key = publicKeyOf(w);
  w.core.meta.setSharePublicKey(key);
  assert.throws(() => w.core.meta.setSharePublicKey(Buffer.alloc(32, 1).toString('base64')), WriteRefused);
  assert.throws(() => w.core.meta.setSharePublicKey('not base64 of 32 bytes'), WriteRefused);
  assert.equal(publicKeyOf(w), key);
});

test('KBOX-33 a copy of a watched value is found by the reference matcher through the route, a new generation after a change', async (t) => {
  const first = windowed('OPENAI_ADMIN_KEY', 1);
  const w = await shareWorld(t, { store: [first] });
  const control = w.core.enrol('mc', 'control');
  const read = async (): Promise<ReturnType<typeof openShare>> => openShare(Buffer.from((await w.core.call('/api/share', { token: control })).body), publicKeyOf(w));
  const before = await read();
  assert.ok(before.ok);
  assert.ok(before.share.scan(base64Document(first.value, 2, true)).length > 0);
  const second = windowed('OPENAI_ADMIN_KEY', 2);
  assert.deepEqual(before.share.scan(rawDocument(second.value)), [], 'a value the file does not yet know is not found');
  w.store.push(second);
  w.core.meta.putKey(row('OPENAI_ADMIN_KEY', 2));
  await w.writer.idle();
  const after = await read();
  assert.ok(after.ok);
  assert.ok(after.share.scan(rawDocument(second.value)).length > 0);
});

// ---------------------------------------------------------------- the real process

test('KBOX-33 the running core writes the first share file at start and serves it with the public key GET /api/meta shows', async (t) => {
  const dir = await tempDir(t);
  const stateDir = join(dir, 'state');
  const socket = join(dir, 'http.sock');
  const random = seededRandom(5);
  const token = newToken(random);
  const parts = openCore({ stateDir, clock: new FakeClock(1_000), scheduler: new TimedClock(1_000), random });
  parts.meta.addMachine({ label: 'mc', scope: 'control', tokenSha256: hashToken(token), enrolledAt: 1_000 });
  parts.close();
  const core = startNode(t, [new URL('../src/main-core.ts', import.meta.url).pathname], dir, { KB_STATE_DIR: stateDir, KB_SOCKET: socket });
  await core.ready('keybox core listening');
  const driver = drive(socket);
  const call = (path: string) => driver.request({ path, headers: { 'x-kb-client-ip': '203.0.113.9', authorization: `Bearer ${token}` } });
  const meta = (await call('/api/meta')).json() as { box: { share_version: number; share_public_key_ed25519_b64: string } };
  assert.equal(meta.box.share_version, 1);
  const served = await call('/api/share');
  assert.equal(served.status, 200, served.body);
  assert.equal(served.headers['kb-share-version'], '1');
  const opened = openShare(Buffer.from(served.body), meta.box.share_public_key_ed25519_b64);
  assert.ok(opened.ok, 'the file the real process wrote verifies with its published key');
  assert.equal(opened.share.version, 1);
  const exit = await core.stop();
  assert.equal(exit.status, 0, exit.stderr);
  assert.equal(statSync(join(stateDir, 'share', 'share.json')).mode & 0o777, 0o644);
});

// ---------------------------------------------------------------- fail closed while a newer refresh is queued

/** A store whose reads are held until the test lets them go; each read sees the store as it was when the read began. */
function heldSource(store: readonly FakeKey[]): { readonly source: ShareSource; held(): number; letGo(): void; hold(): void } {
  const waiting: { release: () => void }[] = [];
  let holding = false;
  return {
    source: {
      keys: async () => {
        const seen = store.map(toShareKey);
        if (holding) await new Promise<void>((resolve) => waiting.push({ release: resolve }));
        return seen;
      },
    },
    held: () => waiting.length,
    letGo: () => void waiting.shift()?.release(),
    hold: () => void (holding = true),
  };
}

test('KBOX-33 with two changes in flight GET /api/share stays 503 until the file holds the newest generation (the finishing refresh read the store before the second change)', async (t) => {
  const store = [windowed('OPENAI_ADMIN_KEY', 1)];
  const gate = heldSource(store);
  const w = await shareWorld(t, { noStart: true, source: () => gate.source });
  await w.writer.start();
  gate.hold();
  store.push(windowed('OPENAI_ADMIN_KEY', 2));
  w.core.meta.putKey(row('OPENAI_ADMIN_KEY', 2));
  await waitUntil(() => gate.held() === 1, 'the first refresh to read the store');
  const newest = windowed('OPENAI_ADMIN_KEY', 3);
  store.push(newest);
  w.core.meta.putKey(row('OPENAI_ADMIN_KEY', 3));
  gate.letGo();
  await waitUntil(() => gate.held() === 1 && summaryOf(fileOf(w))?.version === 2, 'the first refresh to finish and the second to start reading');
  assert.throws(() => w.writer.serve(), { code: 'unavailable', detail: { code: 'share_stale' } }, 'version 2 lacks generation 3, so it is not served');
  gate.letGo();
  await w.writer.idle();
  assert.equal(w.writer.serve().version, 3);
  const opened = openShare(fileOf(w), publicKeyOf(w), { lastVersion: 2 });
  assert.ok(opened.ok);
  assert.ok(opened.share.scan(rawDocument(newest.value)).length > 0, 'the newest generation is in the file that is served');
});

// ---------------------------------------------------------------- a failed refresh tries again

const RETRY_DELAYS_MS = [10_000, 20_000, 40_000, 80_000, 160_000, 320_000, 600_000, 600_000, 600_000];

test('KBOX-33 a failed refresh tries again after 10 s, then 20 s, doubling to 10 minutes between tries, on the injected scheduler; GET /api/share is 503 until one works', async (t) => {
  const w = await shareWorld(t, { store: [windowed('OPENAI_ADMIN_KEY')] });
  w.store.push(windowed('OPENAI_ADMIN_KEY', 2));
  w.failNextReads(RETRY_DELAYS_MS.length);
  w.core.meta.putKey(row('OPENAI_ADMIN_KEY', 2));
  await w.writer.idle();
  assert.deepEqual(w.failures(), ['refresh_failed']);
  for (const [i, delay] of RETRY_DELAYS_MS.entries()) {
    const reads = w.reads();
    w.core.clock.advance(delay - 1);
    await w.writer.idle();
    assert.equal(w.reads(), reads, `no try before ${delay} ms (try ${i + 2})`);
    assert.throws(() => w.writer.serve(), { code: 'unavailable' }, 'still 503 while it fails');
    w.core.clock.advance(1);
    await w.writer.idle();
    assert.equal(w.reads(), reads + 1, `a try at ${delay} ms after the last`);
  }
  assert.equal(w.failures().length, RETRY_DELAYS_MS.length, 'every failed try is reported, none is dropped');
  assert.equal(w.writer.serve().version, 2, 'the first try that reads the store gives the new file');
  const reads = w.reads();
  w.core.clock.advance(3_600_000);
  await w.writer.idle();
  assert.equal(w.reads(), reads, 'no more tries once it worked');
});

test('KBOX-33 a retry keeps going after many failures: the delay stays at 10 minutes and the writer never gives up', async (t) => {
  const w = await shareWorld(t, { store: [windowed('OPENAI_ADMIN_KEY')] });
  w.store.push(windowed('OPENAI_ADMIN_KEY', 2));
  w.failNextReads(40);
  w.core.meta.putKey(row('OPENAI_ADMIN_KEY', 2));
  await w.writer.idle();
  for (let i = 0; i < 40; i += 1) {
    w.core.clock.advance(600_000);
    await w.writer.idle();
  }
  assert.equal(w.writer.serve().version, 2, 'the 41st try reads the store and writes the file');
});

test('KBOX-33 stopping the writer cancels a retry that is waiting', async (t) => {
  const w = await shareWorld(t, { store: [windowed('OPENAI_ADMIN_KEY')] });
  w.store.push(windowed('OPENAI_ADMIN_KEY', 2));
  w.failNextReads(1);
  w.core.meta.putKey(row('OPENAI_ADMIN_KEY', 2));
  await w.writer.idle();
  assert.equal(w.core.clock.pendingTimers > 0, true, 'control: a retry is waiting');
  const reads = w.reads();
  w.writer.stop();
  w.core.clock.advance(600_000);
  await w.writer.idle();
  assert.equal(w.reads(), reads);
});

// ---------------------------------------------------------------- what an old file on disk may do

test('KBOX-33 a file this box signed whose version is below the announced one is never reused: a new version is written even when it shows the same keys', async (t) => {
  const w = await shareWorld(t, { store: [windowed('OPENAI_ADMIN_KEY')] });
  w.writer.stop();
  const old = fileOf(w);
  w.core.meta.announceShare(5);
  const again = await shareWorld(t, { stateDir: w.core.stateDir, store: w.store });
  assert.notEqual(Buffer.compare(fileOf(again), old), 0, 'the version 1 file was replaced');
  assert.equal(summaryOf(fileOf(again))?.version, 6);
  assert.equal(again.writer.serve().version, 6);
  assert.equal(again.core.meta.snapshot().box.share_version, 6);
});

test('KBOX-33 a foreign file on disk with the highest safe version is ignored: the writer is not wedged, writes announced + 1 and serves it', async (t) => {
  const dir = await tempDir(t);
  const foreign = signerFromSeed(Buffer.alloc(32, 7));
  const built = buildShare({ version: Number.MAX_SAFE_INTEGER, issuedAt: 1, random: seededRandom(3), keys: [toShareKey(windowed('OPENAI_ADMIN_KEY'))] });
  writeFileSync(join(dir, 'share.json'), sealEnvelope(built.bytes, foreign.sign(built.bytes)));
  const w = await shareWorld(t, { store: [windowed('OPENAI_ADMIN_KEY')], shareDir: dir });
  assert.equal(w.writer.serve().version, 1, 'announced (0) + 1: the unusable version is ignored, as for an unreadable file');
  assert.equal(w.core.meta.snapshot().box.share_version, 1);
  assert.ok(openShare(fileOf(w), publicKeyOf(w)).ok, 'signed by this box');
  w.store.push(windowed('OPENAI_ADMIN_KEY', 2));
  w.core.meta.putKey(row('OPENAI_ADMIN_KEY', 2));
  await w.writer.idle();
  assert.equal(w.writer.serve().version, 2);
});
