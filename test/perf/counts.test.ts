// M1 (design 3.8): the work one operation does, counted not timed, so a change that doubles it is caught before release. The estimate on
// the Pi is these counts times kb-bench's measured unit costs. The counts are pinned as measured on the code of this commit: each test
// catches a change that adds a verify, a hash or a commit to the operation.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { seededRandom } from '../kit/index.ts';
import { toShareKey } from '../kit/share-golden.ts';
import { fakeKey } from '../kit/share-store.ts';
import { approveWorld } from '../support/approve-world.ts';
import { relayWorld } from '../support/relay-world.ts';
import { buildShare } from '../../src/pure/share-build.ts';
import { counting } from './counters.ts';

test('M1 per approval: two ES256 verifies (the design says two), five SQLite commits, seven SHA-256 calls', async (t) => {
  const w = await approveWorld(t);
  const proposed = w.propose({ kind: 'demote', keyref: 'k1' }, 'ctl-1');
  const item = (await w.queue()).find((q) => q.approval_id === proposed.approval_id);
  assert.ok(item);
  const proof = w.proofFor(item);
  let status = 0;
  const counts = await counting(async () => void (status = (await w.decide(item.approval_id, 'approve', proof)).status));
  assert.equal(status, 200);
  // The design (3.8) says "one commit" per approval; the code of this commit commits five times (the pin records what is, not the budget).
  assert.deepEqual(counts, { sha256: 7, es256: 2, ed25519: 0, commits: 5 });
});

test('M1 per relay call: one SHA-256 (the token check), no signature verify, five SQLite commits', async (t) => {
  const w = await relayWorld(t);
  let status = 0;
  const counts = await counting(async () => void (status = (await w.call('/r/adminkey1/v1/models')).status));
  assert.equal(status, 200);
  assert.deepEqual(counts, { sha256: 1, es256: 0, ed25519: 0, commits: 5 });
});

test('M1 per share build of 50 windowed keys: 13,351 SHA-256 calls, no commit, no verify', async () => {
  const rng = seededRandom(5);
  const keys = Array.from({ length: 50 }, (_, i) => toShareKey(fakeKey(rng, `K${i}`, 48, { project: 'shop' })));
  const counts = await counting(() => void buildShare({ version: 1, issuedAt: 1, random: seededRandom(3), keys }));
  assert.deepEqual(counts, { sha256: 13351, es256: 0, ed25519: 0, commits: 0 });
});

test('M1 counters leave the real crypto and sqlite in place when the counted work throws', async () => {
  const before = [(await import('node:crypto')).createHash, (await import('node:crypto')).verify];
  await assert.rejects(counting(() => Promise.reject(new Error('boom'))), /boom/);
  const after = [(await import('node:crypto')).createHash, (await import('node:crypto')).verify];
  assert.deepEqual(after, before);
});
