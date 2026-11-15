// M1 (design 3.8): the work one operation does, counted not timed, so a change that doubles it is caught before release. The estimate on
// the Pi is these counts times kb-bench's measured unit costs. The counts are pinned as measured on the code of this commit: each test
// catches a change that adds a verify, a hash or a commit to the operation.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { DatabaseSync } from 'node:sqlite';
import { seededRandom } from '../kit/index.ts';
import { toShareKey } from '../kit/share-golden.ts';
import { fakeKey } from '../kit/share-store.ts';
import { approveWorld } from '../support/approve-world.ts';
import { relayWorld } from '../support/relay-world.ts';
import { PER_OPERATION } from '../../src/pure/bench.ts';
import { buildShare } from '../../src/pure/share-build.ts';
import { counting } from './counters.ts';

// Pinned as measured: PER_OPERATION (src/pure/bench.ts) must equal these, and the judge multiplies PER_OPERATION.
const APPROVAL_COMMITS = 6;
const RELAY_COMMITS = 5;

test('M1 per approval: two ES256 verifies (the design says two), six SQLite commits (one durable write transaction each), seven SHA-256 calls', async (t) => {
  const w = await approveWorld(t);
  const proposed = w.propose({ kind: 'demote', keyref: 'k1' }, 'ctl-1');
  const item = (await w.queue()).find((q) => q.approval_id === proposed.approval_id);
  assert.ok(item);
  const proof = w.proofFor(item);
  let status = 0;
  const counts = await counting(async () => void (status = (await w.decide(item.approval_id, 'approve', proof)).status));
  assert.equal(status, 200);
  assert.deepEqual(counts, { sha256: 7, es256: 2, ed25519: 0, commits: APPROVAL_COMMITS });
  assert.deepEqual({ commits: counts.commits, es256: counts.es256 }, PER_OPERATION.approval, 'the judge multiplies PER_OPERATION: it follows the code');
});

test('M1 per relay call: one SHA-256 (the token check), no signature verify, five SQLite commits', async (t) => {
  const w = await relayWorld(t);
  let status = 0;
  const counts = await counting(async () => void (status = (await w.call('/r/adminkey1/v1/models')).status));
  assert.equal(status, 200);
  assert.deepEqual(counts, { sha256: 1, es256: 0, ed25519: 0, commits: RELAY_COMMITS });
  assert.deepEqual({ commits: counts.commits, sha256: counts.sha256 }, PER_OPERATION.relay);
});

test('M1 per share build of 50 windowed keys: 13,351 SHA-256 calls, no commit, no verify', async () => {
  const rng = seededRandom(5);
  const keys = Array.from({ length: 50 }, (_, i) => toShareKey(fakeKey(rng, `K${i}`, 48, { project: 'shop' })));
  const counts = await counting(() => void buildShare({ version: 1, issuedAt: 1, random: seededRandom(3), keys }));
  assert.deepEqual(counts, { sha256: 13351, es256: 0, ed25519: 0, commits: 0 });
  assert.deepEqual({ sha256: counts.sha256 }, PER_OPERATION.share);
});

test('M1 counters leave the real crypto and sqlite in place when the counted work throws', async () => {
  const before = [(await import('node:crypto')).createHash, (await import('node:crypto')).verify];
  await assert.rejects(counting(() => Promise.reject(new Error('boom'))), /boom/);
  const after = [(await import('node:crypto')).createHash, (await import('node:crypto')).verify];
  assert.deepEqual(after, before);
});

test('M1 commits: an autocommit write is one commit, an explicit transaction of two writes is one, a read is none, and a statement prepared before counting is still seen', async () => {
  const db = new DatabaseSync(':memory:');
  db.exec('CREATE TABLE t (n INTEGER)');
  const insert = db.prepare('INSERT INTO t (n) VALUES (?)');
  const select = db.prepare('SELECT n FROM t');
  const autocommit = await counting(() => void insert.run(1));
  const explicit = await counting(() => {
    db.exec('BEGIN IMMEDIATE');
    insert.run(2);
    insert.run(3);
    db.exec('COMMIT');
  });
  const read = await counting(() => void select.all());
  const execWrite = await counting(() => void db.exec('DELETE FROM t'));
  db.close();
  assert.deepEqual([autocommit.commits, explicit.commits, read.commits, execWrite.commits], [1, 1, 0, 1]);
});
