// KBOX-19, KBOX-30: metadata changes and their events are one transaction; the snapshot matches its cursor; tokens are hashes.
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { test } from 'node:test';
import type { TestContext } from 'node:test';
import type { KeyRow, MetaSnapshot } from '../src/ports/meta.ts';
import { WriteRefused } from '../src/pure/errors.ts';
import { openMetaDatabase } from '../src/shell/db.ts';
import { createEventHub, createEventLog } from '../src/shell/events.ts';
import { createMetaStore } from '../src/shell/meta.ts';
import { FakeClock, checkProperty, seedFor, seededRandom, spawnNode, tempDir } from './kit/index.ts';

const seed = seedFor(process.env);
const HASH_A = 'a'.repeat(64);

async function world(t: TestContext) {
  const dir = await tempDir(t);
  const path = join(dir, 'meta.db');
  const db = openMetaDatabase(path, seededRandom(seed));
  t.after(() => db.close());
  const clock = new FakeClock(9000);
  const hub = createEventHub();
  const store = createMetaStore(db, clock, hub);
  return { dir, path, db, clock, hub, store, log: createEventLog(db, clock, hub) };
}

const keyRow = (over: Partial<KeyRow> = {}): KeyRow => ({
  keyref: 'openai/master',
  platform: 'openai',
  name: 'OPENAI_ADMIN_KEY',
  projects: ['shop', 'blog'],
  class: 'admin',
  status: 'works',
  gen_current: 1,
  schedule: { rotate_every_days: 30, grace_hours: 24, next_due_at: 123456, expires_at: null },
  coverage: null,
  last_use_at: null,
  ...over,
});

test('KBOX-19 a key row, a destination row and a grant row each make the next event key.changed, and the snapshot shows them at that cursor', async (t) => {
  const { store, log } = await world(t);
  store.putKey(keyRow());
  assert.deepEqual(log.after(0).map((e) => [e.seq, e.kind, e.data]), [[1, 'key.changed', { keyref: 'openai/master' }]]);
  assert.equal(store.snapshot().cursor, 1);
  assert.equal(store.snapshot().keys[0]?.gen_current, 1);

  store.putDestination('openai/master', { kind: 'vercel-env', target: 'prj_123', readable_by: 'runtime' });
  assert.deepEqual(log.after(1).map((e) => [e.seq, e.kind]), [[2, 'key.changed']]);
  assert.deepEqual(store.snapshot().keys[0]?.destinations, [{ kind: 'vercel-env', target: 'prj_123', readable_by: 'runtime' }]);

  store.addMachine({ label: 'laptop-1', scope: 'relay', tokenSha256: HASH_A, enrolledAt: 5 });
  store.putGrant('openai/master', 'laptop-1');
  assert.deepEqual(log.after(2).map((e) => [e.seq, e.kind, e.data]), [[3, 'machine.changed', { label: 'laptop-1', change: 'enrolled' }], [4, 'key.changed', { keyref: 'openai/master' }]]);
  const snapshot = store.snapshot();
  assert.deepEqual(snapshot.keys[0]?.grants, [{ machine: 'laptop-1' }]);
  assert.equal(snapshot.cursor, 4);

  store.putKey(keyRow({ status: 'rotating', gen_current: 2, coverage: 'windowed', last_use_at: 77 }));
  const changed = store.snapshot().keys[0];
  assert.deepEqual([changed?.status, changed?.gen_current, changed?.coverage, changed?.last_use_at], ['rotating', 2, 'windowed', 77]);
  assert.equal(store.snapshot().cursor, 5);
  assert.equal(store.snapshot().keys.length, 1);
});

test('KBOX-30 the snapshot has the shape of the spec: a key, a machine without its token hash, an approval, the box and the cursor', async (t) => {
  const { store } = await world(t);
  store.putKey(keyRow({ projects: ['a', 'b'] }));
  store.addMachine({ label: 'm1', scope: 'control', tokenSha256: HASH_A, enrolledAt: 11 });
  store.putApproval({ approval_id: 'ap_1', kind: 'key_rotate', title: 'Rotate a key', slot: 'admin-1', opened_at: 20, expires_at: 30 });
  const snapshot: MetaSnapshot = store.snapshot();
  assert.deepEqual(snapshot.machines, [{ label: 'm1', scope: 'control', enrolled_at: 11, revoked: false, last_network: null }]);
  assert.deepEqual(snapshot.approvals, [{ approval_id: 'ap_1', kind: 'key_rotate', title: 'Rotate a key', slot: 'admin-1', opened_at: 20, expires_at: 30 }]);
  assert.deepEqual(Object.keys(snapshot.box).sort(), ['epoch', 'oidc_issuer', 'release', 'share_public_key_ed25519_b64', 'share_version']);
  assert.match(snapshot.box.epoch, /^[0-9a-f]{8}$/);
  assert.deepEqual(snapshot.keys[0], {
    keyref: 'openai/master',
    platform: 'openai',
    name: 'OPENAI_ADMIN_KEY',
    projects: ['a', 'b'],
    class: 'admin',
    status: 'works',
    gen_current: 1,
    destinations: [],
    schedule: { rotate_every_days: 30, grace_hours: 24, next_due_at: 123456, expires_at: null },
    grants: [],
    allow_rules: [],
    coverage: null,
    last_use_at: null,
  });
  assert.equal(JSON.stringify(snapshot).includes(HASH_A), false, 'a token hash is never in the snapshot');
});

test('KBOX-5 metadata text that is not a name, and a class or status outside the closed lists, is refused and writes neither row nor event', async (t) => {
  const { store, log } = await world(t);
  const bad: Partial<KeyRow>[] = [
    { keyref: 'has space' },
    { keyref: '' },
    { name: 'x'.repeat(200) },
    { platform: 'Open AI' },
    { projects: ['fine', 'not fine'] },
    { class: 'superuser' as KeyRow['class'] },
    { status: 'sleeping' as KeyRow['status'] },
    { coverage: 'full' as KeyRow['coverage'] },
    { gen_current: 0 },
    { gen_current: 1.5 },
    { schedule: { rotate_every_days: -1, grace_hours: 1, next_due_at: null, expires_at: null } },
  ];
  for (const over of bad) assert.throws(() => store.putKey(keyRow(over)), Error, JSON.stringify(over));
  assert.throws(() => store.addMachine({ label: 'no spaces allowed', scope: 'relay', tokenSha256: HASH_A, enrolledAt: 1 }), WriteRefused);
  assert.throws(() => store.addMachine({ label: 'ok', scope: 'relay', tokenSha256: 'not-a-hash', enrolledAt: 1 }), WriteRefused);
  assert.throws(() => store.putGrant('missing/key', 'ok'), Error);
  assert.deepEqual(store.snapshot().keys, []);
  assert.deepEqual(store.snapshot().machines, []);
  assert.equal(log.head(), 0);
});

test('KBOX-2 property: random byte strings offered as any text of a metadata write are refused and no row or event appears', async (t) => {
  const { store, log } = await world(t);
  store.putKey(keyRow());
  checkProperty(seed, 100, (rng) => {
    const text = Buffer.from(rng.bytes(24 + rng.int(40))).toString('latin1');
    for (const over of [{ keyref: text }, { name: text }, { platform: text }, { projects: [text] }]) assert.throws(() => store.putKey(keyRow(over)), WriteRefused);
    assert.throws(() => store.putDestination('openai/master', { kind: text, target: 'x', readable_by: 'api' }), WriteRefused);
    assert.throws(() => store.putDestination('openai/master', { kind: 'vercel-env', target: text, readable_by: 'api' }), WriteRefused);
    assert.throws(() => store.addMachine({ label: text, scope: 'relay', tokenSha256: HASH_A, enrolledAt: 1 }), WriteRefused);
    assert.throws(() => store.putApproval({ approval_id: 'ap', kind: 'k', title: text, slot: 's', opened_at: 1, expires_at: 2 }), WriteRefused);
  });
  assert.equal(log.head(), 1, 'only the one valid putKey wrote an event');
});

test('KBOX-10 tokens() lists every enrolled hash with its scope, and revoking flips the flag and writes machine.changed', async (t) => {
  const { store, log } = await world(t);
  store.addMachine({ label: 'a', scope: 'control', tokenSha256: HASH_A, enrolledAt: 1 });
  store.addMachine({ label: 'b', scope: 'relay', tokenSha256: 'b'.repeat(64), enrolledAt: 2 });
  assert.deepEqual(store.tokens(), [
    { label: 'a', scope: 'control', tokenSha256: HASH_A, revoked: false },
    { label: 'b', scope: 'relay', tokenSha256: 'b'.repeat(64), revoked: false },
  ]);
  store.revokeMachine('b');
  assert.equal(store.tokens()[1]?.revoked, true);
  assert.deepEqual(log.after(2).map((e) => [e.kind, e.data]), [['machine.changed', { label: 'b', change: 'revoked' }]]);
  assert.throws(() => store.revokeMachine('nobody'), Error);
  assert.equal(store.snapshot().machines[1]?.revoked, true);
  assert.throws(() => store.addMachine({ label: 'c', scope: 'relay', tokenSha256: HASH_A, enrolledAt: 3 }), Error, 'two machines never share a token hash');
});

test('KBOX-43 the first use of a token from a new network writes one token.new_network event; the same network again writes none', async (t) => {
  const { store, log } = await world(t);
  store.addMachine({ label: 'a', scope: 'control', tokenSha256: HASH_A, enrolledAt: 1 });
  const before = log.head();
  store.recordUse('a', '203.0.113.0/24');
  store.recordUse('a', '203.0.113.0/24');
  assert.deepEqual(log.after(before).map((e) => [e.kind, e.data]), [['token.new_network', { label: 'a', network: '203.0.113.0/24' }]]);
  assert.equal(store.snapshot().machines[0]?.last_network, '203.0.113.0/24');
  store.recordUse('a', '2001:db8:1::/48');
  assert.deepEqual(log.after(before + 1).map((e) => e.data), [{ label: 'a', network: '2001:db8:1::/48' }]);
  assert.throws(() => store.recordUse('nobody', '203.0.113.0/24'), Error);
  assert.throws(() => store.recordUse('a', 'not a network'), WriteRefused);
});

test('KBOX-30 a snapshot taken while another process writes is consistent with its cursor, and replaying the later events reaches the final state', async (t) => {
  const { dir, path, store, log } = await world(t);
  const writes = 3000;
  const writer = new URL('./kit/db-writer.ts', import.meta.url).pathname;
  const child = spawnNode([writer, 'meta', path, 'openai/master', String(writes)], dir);
  let exited = false;
  void child.then(() => (exited = true));
  const cursors = new Set<number>();
  let taken = 0;
  while (!exited || taken < 5) {
    const snapshot = store.snapshot();
    const gen = snapshot.keys[0]?.gen_current ?? 0;
    assert.equal(gen, snapshot.cursor, 'the key shows exactly the writes the cursor says were made');
    cursors.add(snapshot.cursor);
    taken += 1;
    await new Promise((resolve) => setImmediate(resolve));
  }
  const run = await child;
  assert.equal(run.status, 0, run.stderr);
  assert.ok(cursors.size >= 2, `the snapshots must overlap the writer, saw cursors ${[...cursors].join(',')}`);
  const final = store.snapshot();
  assert.equal(final.cursor, writes);
  for (const cursor of [...cursors]) {
    const replayed = (cursor === 0 ? 0 : cursor) + log.after(cursor).length;
    assert.equal(replayed, final.keys[0]?.gen_current, 'a snapshot plus the events after its cursor is the final state');
  }
});
