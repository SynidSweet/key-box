// KBOX-51 step 10 as amended (revoke-proof, 2026-11-13): the proof watch is the one exit from `grace` for a rotated generation. It ends each
// lingering generation again where the box can, asks the key's proven revoked evidence (KBOX-62), and retires it only after two proven
// verdicts at least 60 s apart, the second with no end call. The world is the deletion world (test/support/delete-world.ts): proven
// evidence 401 unless `unproven`; a revoked id answers 401, a live one 200, and `answer` replaces every status.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { TestContext } from 'node:test';
import type { Issuer } from '../src/ports/issuer.ts';
import type { BoxMadeKey } from '../src/ports/platform.ts';
import { PROOF_GAP_MS } from '../src/shell/proof-watch.ts';
import { bytesOf, settle, waitUntil } from './kit/index.ts';
import { DAY, HOUR, deleteWorld } from './support/delete-world.ts';
import type { DeleteWorld, DeleteWorldOptions } from './support/delete-world.ts';

const KEYREF = 'fake/shop/FAKE_KEY';
const status = (w: DeleteWorld, keyref: string, gen: number): string | undefined => w.rotation.store.gen(keyref, gen)?.status;
const revokes = (w: DeleteWorld): readonly string[] => w.platform.calls.filter((c) => c.startsWith('revoke'));
const asked = (w: DeleteWorld): number => w.platform.calls.filter((c) => c.startsWith('status')).length;
const text = async (w: DeleteWorld, keyref: string, gen: number): Promise<string> => Buffer.from(await bytesOf(w.parts.vault.lend(keyref, gen))).toString('utf8');

/** A key rotated to the end (run done): gen 2 current, gen 1 lingering in grace, its id already revoked at the platform (it answers 401). */
async function lingering(w: DeleteWorld, keyref = KEYREF): Promise<void> {
  if (w.rotation.store.key(keyref) === undefined) await w.addKey(keyref === KEYREF ? {} : { keyref, name: keyref.split('/').at(-1) ?? 'K' });
  w.rotation.orchestrator.start({ keyref, origin: 'owner' });
  await w.rotation.orchestrator.idle();
  await w.pass(24 * HOUR, HOUR);
  assert.equal(w.rotation.store.activeRunOf(keyref), undefined, 'the run is done');
}

async function world(t: TestContext, options: DeleteWorldOptions = {}): Promise<DeleteWorld> {
  const w = await deleteWorld(t, options);
  await lingering(w);
  assert.equal(status(w, KEYREF, 1), 'grace');
  return w;
}

/** One sweep, its first half run: the end calls and first verdicts made, and the sweep waiting on its gap (or finished). */
async function firstHalf(w: DeleteWorld): Promise<Promise<void>> {
  const sweep = w.rotation.watch.run();
  await w.rotation.watch.idle();
  return sweep;
}

test('KBOX-51 the proof watch retires a lingering generation after two proven verdicts 60 s apart, the second with no end call: retired, its value file deleted, one key.revoked', async (t) => {
  const w = await world(t);
  const value = await text(w, KEYREF, 1);
  const from = w.platform.calls.length;
  const sweep = await firstHalf(w);
  assert.equal(status(w, KEYREF, 1), 'grace', 'one verdict retires nothing');
  w.clock.advance(PROOF_GAP_MS - 1);
  await settle();
  assert.equal(status(w, KEYREF, 1), 'grace', '1 ms before the gap ends');
  w.clock.advance(1);
  await sweep;
  assert.deepEqual(w.platform.calls.slice(from).map((c) => c.replace(/ with .*/, '')), ['revoke pk-1', `status ${value}`, `status ${value}`]);
  assert.equal(status(w, KEYREF, 1), 'retired');
  assert.throws(() => w.parts.vault.lend(KEYREF, 1), 'its value file is deleted');
  assert.equal(w.audits('key.revoked').length, 1);
});

test('KBOX-51 a verdict proven once and then refused (401 then 200) leaves the generation grace with its value; the next sweep starts again from the end call', async (t) => {
  const w = await world(t);
  const sweep = await firstHalf(w);
  w.platform.answer = 200;
  w.clock.advance(PROOF_GAP_MS);
  await sweep;
  assert.equal(status(w, KEYREF, 1), 'grace');
  assert.ok((await text(w, KEYREF, 1)).length > 0);
  w.platform.answer = undefined;
  const ended = revokes(w).length;
  await firstHalf(w);
  assert.equal(revokes(w).length, ended + 1, 'ended again');
});

test('KBOX-51 a 403, a 404, a network error and a 200 never retire, and the sweep does not wait', async (t) => {
  const w = await world(t);
  for (const answer of [403, 404, 'throw', 200] as const) {
    w.platform.answer = answer;
    await w.rotation.watch.run();
    assert.equal(status(w, KEYREF, 1), 'grace', String(answer));
  }
  assert.deepEqual(w.audits('key.revoked'), []);
});

test('KBOX-51 with no proven evidence a generation is ended again each sweep, never asked, and stays grace after 30 daily sweeps', async (t) => {
  const w = await world(t, { unproven: true });
  const ended = revokes(w).length;
  const before = asked(w);
  for (let day = 1; day <= 30; day += 1) {
    w.clock.advance(DAY);
    await w.rotation.watch.run();
    assert.equal(revokes(w).length, ended + day);
  }
  assert.equal(asked(w), before, 'no evidence to ask');
  assert.equal(status(w, KEYREF, 1), 'grace');
});

test('KBOX-51 a generation the owner ends gets no end call, and with no platform key id it is proven by the verifier path only: retired with its value held, never once the value is gone', async (t) => {
  for (const valueGone of [false, true]) {
    const w = await deleteWorld(t);
    const { keyref, value } = await w.addPasted('PASTED_KEY');
    const next = w.platform.value();
    w.platform.pasted.add(next);
    w.rotation.orchestrator.start({ keyref, origin: 'paste', value: Buffer.from(next) });
    await w.rotation.orchestrator.idle();
    w.platform.pasted.delete(value);
    await w.pass(25 * HOUR, HOUR);
    assert.equal(w.rotation.store.activeRunOf(keyref), undefined);
    assert.equal(w.rotation.store.gen(keyref, 1)?.platformKeyId, null);
    if (valueGone) w.parts.vault.retire(keyref, 1);
    const ended = revokes(w).length;
    const from = asked(w);
    const sweep = await firstHalf(w);
    w.clock.advance(PROOF_GAP_MS);
    await sweep;
    assert.equal(revokes(w).length, ended, 'the owner ends it: no call');
    assert.equal(asked(w) - from, valueGone ? 0 : 2);
    assert.equal(status(w, keyref, 1), valueGone ? 'grace' : 'retired');
  }
});

test('KBOX-51 the watch skips the old and the new generation of an active run, in grace and at step 10', async (t) => {
  const w = await world(t);
  w.rotation.orchestrator.start({ keyref: KEYREF, origin: 'owner' });
  await w.rotation.orchestrator.idle();
  assert.equal(w.rotation.store.activeRunOf(KEYREF)?.state, 'grace');
  let from = revokes(w).length;
  await firstHalf(w);
  assert.deepEqual(revokes(w).slice(from).map((c) => c.split(' ')[1]), ['pk-1'], 'gen 2 (the run\'s old) and gen 3 (its new) are the run\'s');
  w.platform.answer = 200;
  await w.pass(24 * HOUR, HOUR);
  assert.equal(w.rotation.store.activeRunOf(KEYREF)?.state, 'revoking');
  from = revokes(w).length;
  await w.rotation.watch.run();
  assert.deepEqual(revokes(w).slice(from).map((c) => c.split(' ')[1]), ['pk-1']);
});

test('KBOX-62 the watch skips a key with an open deletion, and a deletion opened during the 60 s wait leaves the generation unretired by the watch', async (t) => {
  const w = await world(t);
  const sweep = await firstHalf(w);
  w.clock.advance(PROOF_GAP_MS / 2);
  await w.approveDelete(KEYREF);
  const revokedBefore = w.audits('key.revoked').length;
  w.clock.advance(PROOF_GAP_MS / 2);
  await sweep;
  assert.equal(status(w, KEYREF, 1), 'grace', 'the deletion owns it now');
  assert.equal(w.audits('key.revoked').length, revokedBefore);
  const from = w.platform.calls.length;
  await w.rotation.watch.run();
  assert.deepEqual(w.platform.calls.slice(from), [], 'no call for a key being deleted');
});

test('KBOX-55 the watch skips a box-made key', async (t) => {
  const box: BoxMadeKey = { name: 'BOX_KEY', shape: { prefix: 'bk-', alphabet: 'base64url', coreLength: { min: 43, max: 43 }, random: true }, publishLeadMs: 0, generate: () => new Uint8Array(32), check: () => Promise.resolve('ok'), prove: () => Promise.resolve('ok') };
  const w = await deleteWorld(t, { boxKey: box });
  const keyref = 'fake/p/BOX_KEY';
  w.parts.meta.putKey({ keyref, platform: 'fake', name: 'BOX_KEY', projects: [], class: 'master', status: 'works', gen_current: 2, schedule: { rotate_every_days: 90, grace_hours: 24, next_due_at: null, expires_at: null }, coverage: null, last_use_at: null });
  w.rotation.store.putKeyInfo(keyref, { scopeItems: ['master'], location: {}, rotatedAt: w.clock.now(), markAdmin: false });
  for (const g of [1, 2] as const) {
    w.parts.vault.put(keyref, g, Buffer.from(w.platform.value()));
    w.rotation.store.putGen({ keyref, gen: g, status: g === 1 ? 'grace' : 'current', platformKeyId: null, location: {} });
  }
  const from = w.platform.calls.length;
  await w.rotation.watch.run();
  assert.deepEqual(w.platform.calls.slice(from), []);
  assert.equal(status(w, keyref, 1), 'grace');
});

test('KBOX-57 a key with no master gets no call that sweep and stays grace; with the master back the next sweep goes ahead', async (t) => {
  const w = await world(t);
  const master = await text(w, w.masters.fake, 1);
  w.parts.vault.retire(w.masters.fake, 1);
  const from = w.platform.calls.length;
  await w.rotation.watch.run();
  assert.deepEqual(w.platform.calls.slice(from), []);
  assert.equal(status(w, KEYREF, 1), 'grace');
  w.parts.vault.put(w.masters.fake, 1, Buffer.from(master));
  const sweep = await firstHalf(w);
  w.clock.advance(PROOF_GAP_MS);
  await sweep;
  assert.equal(status(w, KEYREF, 1), 'retired');
});

test('KBOX-51 a stop during the 60 s wait retires nothing and does not throw; after a restart the watch starts again from the end call and the first verdict', async (t) => {
  const w = await world(t);
  const sweep = await firstHalf(w);
  w.rotation.watch.stop();
  await sweep;
  w.clock.advance(PROOF_GAP_MS);
  await settle();
  assert.equal(status(w, KEYREF, 1), 'grace');
  await w.restart();
  const ended = revokes(w).length;
  const again = await firstHalf(w);
  assert.equal(revokes(w).length, ended + 1);
  w.clock.advance(PROOF_GAP_MS);
  await again;
  assert.equal(status(w, KEYREF, 1), 'retired');
});

test('KBOX-51 a generation whose retire throws audits one rotation.drive_failed watch_failed and the other generations still settle', async (t) => {
  const w = await world(t);
  const other = 'fake/shop/OTHER_KEY';
  await lingering(w, other);
  w.parts.db.exec(`CREATE TRIGGER refuse_retire BEFORE UPDATE ON rotation_gens WHEN NEW.keyref = '${KEYREF}' AND NEW.status = 'retired' BEGIN SELECT RAISE(ABORT, 'refused'); END`);
  const sweep = await firstHalf(w);
  w.clock.advance(PROOF_GAP_MS);
  await sweep;
  assert.deepEqual(w.audits('rotation.drive_failed').map((a) => [a.ref, a.detail]), [[KEYREF, { run_id: 'watch', code: 'watch_failed' }]]);
  assert.equal(status(w, KEYREF, 1), 'grace');
  assert.equal(status(w, other, 1), 'retired');
});

test('KBOX-51 KBOX-62 a master key\'s two lingering generations are ended and proven with the master\'s current value', async (t) => {
  const w = await deleteWorld(t);
  const master = w.masters.fake;
  for (let i = 0; i < 2; i += 1) {
    w.rotation.orchestrator.start({ keyref: master, origin: 'owner' });
    await w.rotation.orchestrator.idle();
    await w.pass(2 * HOUR, HOUR);
  }
  assert.deepEqual(w.rotation.store.gens(master).map((g) => g.status), ['grace', 'grace', 'current']);
  const current = await text(w, master, 3);
  const from = revokes(w).length;
  const sweep = await firstHalf(w);
  w.clock.advance(PROOF_GAP_MS);
  await sweep;
  assert.deepEqual(revokes(w).slice(from).map((c) => c.split(' with ')[1]), [current, current]);
  assert.deepEqual(w.rotation.store.gens(master).map((g) => g.status), ['retired', 'retired', 'current']);
});

test('KBOX-51 rotation.run() sweeps after the start-up reconcile and again after each daily reconcile, never before', async (t) => {
  const w = await world(t, { unproven: true });
  const ended = revokes(w).length;
  const stop = w.rotation.run();
  t.after(stop);
  await w.rotation.idle();
  assert.equal(revokes(w).length, ended + 1, 'one sweep at start');
  w.clock.advance(DAY - 1);
  await w.rotation.idle();
  assert.equal(revokes(w).length, ended + 1);
  w.clock.advance(1);
  await w.rotation.idle();
  assert.equal(revokes(w).length, ended + 2, 'one sweep after the daily reconcile');
});

test('KBOX-51 ruling 4: a watch whose platform call never answers never holds back the next daily reconcile, and its sweep is not doubled', async (t) => {
  const w = await world(t, { unproven: true });
  const hung = new Promise<never>(() => undefined);
  let ends = 0;
  Object.assign(w.platform.issuer, {
    revoke: (): ReturnType<Issuer['revoke']> => {
      ends += 1;
      return hung;
    },
  });
  const orphans = (): number => w.events('box.notice').filter((n) => n['code'] === 'orphan_key').length;
  w.platform.extra.push({ platformKeyId: 'pk-stray-1', name: 'kbox_stray_1' });
  const stop = w.rotation.run();
  t.after(stop);
  await waitUntil(() => orphans() === 1 && ends === 1, 'the start-up reconcile, then the sweep');
  w.platform.extra.push({ platformKeyId: 'pk-stray-2', name: 'kbox_stray_2' });
  w.clock.advance(DAY);
  await waitUntil(() => orphans() === 2, 'the daily reconcile');
  await settle();
  assert.equal(ends, 1, 'the hung sweep is still the one sweep');
  assert.equal(status(w, KEYREF, 1), 'grace');
});

test('KBOX-51 ruling 6: retireProven re-reads the generation in its transaction: a current, already retired, run-owned or deleting generation is left as it is', async (t) => {
  const w = await world(t, { unproven: true });
  const store = w.rotation.store;
  assert.equal(store.retireProven(KEYREF, 2), false, 'current');
  w.rotation.orchestrator.start({ keyref: KEYREF, origin: 'owner' });
  await w.rotation.orchestrator.idle();
  assert.equal(store.retireProven(KEYREF, 2), false, 'the run\'s old generation');
  assert.equal(status(w, KEYREF, 2), 'grace');
  const proven = await deleteWorld(t);
  await lingering(proven);
  proven.platform.answer = 200;
  await proven.approveDelete(KEYREF);
  assert.equal(proven.rotation.store.retireProven(KEYREF, 1), false, 'an open deletion');
  assert.equal(store.retireProven(KEYREF, 1), true, 'lingering: retired');
  assert.equal(store.retireProven(KEYREF, 1), false, 'already retired');
  assert.equal(status(w, KEYREF, 1), 'retired');
});
