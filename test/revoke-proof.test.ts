// KBOX-51 step 10 and KBOX-17 as amended by revoke-proof (2026-11-13): the platform's ordinary word (the verifier's mapping, a listing) ends a
// run but marks nothing dead. Only the proof watch, a deletion and a box-made key's revoke retire a generation; until then it stays `grace`,
// its value kept and watched. The world is the deletion world (test/support/delete-world.ts): its verifier answers HTTP statuses, its entry
// declares proven revoked evidence (401) unless `unproven`, and its verifier's mapping reads every status but 200 as rejected.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { TestContext } from 'node:test';
import type { Verifier } from '../src/ports/issuer.ts';
import { ApiError } from '../src/pure/errors.ts';
import { checkRetireWriters } from './arch/retire-writers.ts';
import { REPO_ROOT, materialise } from './arch/fixture.ts';
import { bytesOf } from './kit/index.ts';
import { DAY, HOUR, MINUTE, deleteWorld } from './support/delete-world.ts';
import type { DeleteWorld } from './support/delete-world.ts';
import { rotationWorld } from './support/rotation-world.ts';

const KEYREF = 'fake/shop/FAKE_KEY';
const gen = (w: DeleteWorld, n: number): string | undefined => w.rotation.store.gen(KEYREF, n)?.status;
/** The state of the key's latest rotation run (the create run, opened at the same instant, left out). */
const lastRun = (w: DeleteWorld): string | undefined => w.rotation.store.runs().filter((r) => r.keyref === KEYREF && r.origin !== 'create').at(-1)?.state;
const completed = (w: DeleteWorld): number => w.audits('rotation.completed').filter((a) => (a.detail as { gen: number }).gen > 1).length;
const holds = async (w: DeleteWorld, n: number): Promise<boolean> => (await bytesOf(w.parts.vault.lend(KEYREF, n))).length > 0;
const oldUnproven = (w: DeleteWorld): number | undefined => w.parts.meta.controlSnapshot().keys.find((k) => k.keyref === KEYREF)?.old_unproven;

/** A key rotated up to its grace wait (gen 2 current, gen 1 grace, the run waiting); then the platform answers `status` and the grace ends. */
async function stepTen(t: TestContext, status: number | 'throw' | undefined, options: { unproven?: boolean } = {}): Promise<DeleteWorld> {
  const w = await deleteWorld(t, options);
  await w.addKey();
  w.rotation.orchestrator.start({ keyref: KEYREF, origin: 'owner' });
  await w.rotation.orchestrator.idle();
  assert.equal(gen(w, 1), 'grace');
  w.platform.answer = status;
  await w.pass(24 * HOUR, HOUR);
  return w;
}

for (const status of [403, 401, 404]) {
  test(`KBOX-51 step 10: the verifier's mapping reading ${status} as rejected, with no proven evidence, ends the run and leaves gen 1 grace with its value kept and no key.revoked`, async (t) => {
    const w = await stepTen(t, status, { unproven: true });
    assert.equal(lastRun(w), 'done');
    assert.equal(completed(w), 1);
    assert.equal(gen(w, 1), 'grace', 'the platform\'s word marks nothing dead');
    assert.equal(await holds(w, 1), true, 'the vault still holds gen 1');
    assert.deepEqual(w.audits('key.revoked'), []);
  });
}

test('KBOX-51 KBOX-17 step 10: an old value the platform still takes (200) or a platform that cannot be reached keeps the run at step 10 with one notice and gen 1 grace', async (t) => {
  for (const status of [200, 'throw'] as const) {
    const w = await stepTen(t, status, { unproven: true });
    assert.equal(w.rotation.store.activeRunOf(KEYREF)?.state, 'revoking', `${status}: the run waits at step 10`);
    await w.pass(10 * MINUTE);
    assert.ok((w.rotation.store.activeRunOf(KEYREF)?.attempts ?? 0) >= 3, `${status}: retried`);
    assert.equal(w.events('rotation.old_key_still_on').length, 1);
    assert.equal(gen(w, 1), 'grace');
    assert.equal(completed(w), 0);
  }
});

test('KBOX-51 step 10: proven revoked evidence ends the run where the verifier\'s mapping does not say rejected, and still retires nothing', async (t) => {
  const w = await deleteWorld(t);
  await w.addKey();
  w.rotation.orchestrator.start({ keyref: KEYREF, origin: 'owner' });
  await w.rotation.orchestrator.idle();
  // The mapping says the platform could not be reached; the answer status (401) is proven to mean revoked.
  Object.assign(w.platform.verifier, { verify: (): ReturnType<Verifier['verify']> => Promise.resolve('unreachable') });
  await w.pass(24 * HOUR, HOUR);
  assert.equal(lastRun(w), 'done');
  assert.equal(gen(w, 1), 'grace');
  assert.deepEqual(w.audits('key.revoked'), []);
});

test('KBOX-51 step 10: a proven 401 still leaves gen 1 grace: step 10 never retires, only the proof watch does', async (t) => {
  const w = await stepTen(t, undefined);
  assert.equal(lastRun(w), 'done');
  assert.ok(w.platform.calls.some((c) => c.startsWith('revoke pk-1')), 'the old key was ended');
  assert.equal(gen(w, 1), 'grace');
  assert.equal(await holds(w, 1), true);
  assert.deepEqual(w.audits('key.revoked'), []);
});

test('KBOX-17 a rollback of a new key the platform issued leaves it grace with its value kept once the platform refuses it; control: one the platform still takes keeps the rollback retrying', async (t) => {
  const w = await rotationWorld(t);
  const keyref = await w.seedKey();
  w.destinations.redeployer.failNext();
  w.orch.start({ keyref, origin: 'owner' });
  await w.settle();
  assert.equal(w.store.runs().at(-1)?.state, 'failed');
  assert.equal(w.store.gen(keyref, 2)?.status, 'grace', 'issued, ended, not proven dead');
  assert.equal((await w.valueOf(keyref, 2)).length > 0, true, 'the vault still holds gen 2');
  assert.equal(w.store.gen(keyref, 1)?.status, 'current');

  const control = await rotationWorld(t);
  const other = await control.seedKey();
  control.destinations.redeployer.failNext();
  control.faults.revoke404 = true;
  control.orch.start({ keyref: other, origin: 'owner' });
  await control.orch.idle();
  control.clock.advance(MINUTE);
  await control.orch.idle();
  assert.equal(control.store.runs().at(-1)?.state, 'rolling_back', 'the platform still takes the new key: the rollback retries');
  assert.equal(control.store.gen(other, 2)?.status, 'pending');
});

test('KBOX-17 control: a rollback of a value the platform never issued (overlap:false, no platform key id) still marks it failed and deletes its value', async (t) => {
  const w = await rotationWorld(t, { overlap: false });
  const keyref = await w.seedKey();
  w.destinations.redeployer.failNext();
  w.orch.start({ keyref, origin: 'owner' });
  await w.settle();
  assert.equal(w.store.runs().at(-1)?.state, 'failed');
  assert.equal(w.store.gen(keyref, 2)?.status, 'failed');
  assert.throws(() => w.parts.vault.lend(keyref, 2), 'its value is deleted');
});

test('KBOX-51 KBOX-62 a key whose old generation stays grace rotates again when due; then a delete answers cannot_confirm with no proven evidence, and with it ends both grace generations', async (t) => {
  for (const unproven of [true, false]) {
    const w = await stepTen(t, undefined, { unproven });
    assert.equal(lastRun(w), 'done');
    w.clock.advance(91 * DAY);
    w.rotation.tick();
    await w.rotation.orchestrator.idle();
    assert.equal(w.rotation.store.runs().filter((r) => r.keyref === KEYREF && r.origin === 'schedule').length, 1, 'the tick opened the next run');
    await w.pass(25 * HOUR, HOUR);
    assert.equal(lastRun(w), 'done');
    assert.deepEqual([gen(w, 1), gen(w, 2), gen(w, 3)], ['grace', 'grace', 'current']);
    if (unproven) {
      assert.throws(() => w.rotation.deletion.precheck({ kind: 'delete_key', keyref: KEYREF }), (e: unknown) => e instanceof ApiError && e.detail !== undefined && 'code' in e.detail && e.detail.code === 'cannot_confirm');
      continue;
    }
    const before = w.platform.calls.filter((c) => c.startsWith('revoke')).length;
    await w.approveDelete(KEYREF);
    const ended = w.platform.calls.filter((c) => c.startsWith('revoke')).slice(before);
    assert.deepEqual(ended.map((c) => c.split(' ')[1]), ['pk-1', 'pk-2'], 'the batch is both grace generations, ascending');
  }
});

test('KBOX-30 old_unproven counts the generations that are not current, whose run has ended and that are not proven ended: 0 during the run\'s grace, 1 after step 10, 2 after the next rotation', async (t) => {
  const w = await deleteWorld(t, { unproven: true });
  await w.addKey();
  assert.equal(oldUnproven(w), 0);
  w.rotation.orchestrator.start({ keyref: KEYREF, origin: 'owner' });
  await w.rotation.orchestrator.idle();
  assert.equal(oldUnproven(w), 0, 'gen 1 belongs to the running rotation');
  await w.pass(24 * HOUR, HOUR);
  assert.equal(oldUnproven(w), 1);
  w.rotation.orchestrator.start({ keyref: KEYREF, origin: 'owner' });
  await w.pass(25 * HOUR, HOUR);
  assert.equal(oldUnproven(w), 2);
  assert.equal('old_unproven' in (w.parts.meta.snapshot().keys[0] ?? {}), false, 'only GET /api/meta\'s snapshot carries it');
});

test('KBOX-30 KBOX-17 old_unproven counts a failed run\'s issued new key, which stays grace', async (t) => {
  const w = await rotationWorld(t);
  const keyref = await w.seedKey();
  w.destinations.redeployer.failNext();
  w.orch.start({ keyref, origin: 'owner' });
  await w.settle();
  assert.equal(w.parts.meta.controlSnapshot().keys.find((k) => k.keyref === keyref)?.old_unproven, 1);
});

// ------------------------------------------------------------------------------------------------ structural: who may retire (KBOX-51)

test('KBOX-51 KBOX-62 the repo\'s own tree sets a generation retired only in the proof watch, the deletion and the box-made revoke', async () => {
  assert.deepEqual(await checkRetireWriters(REPO_ROOT), []);
});

const ORCH = 'src/shell/orchestrator.ts';
test('KBOX-51 negative controls: a retire in revokeOld or in any other function, a retiring SQL write or a retireProven call elsewhere, and vault.retire in revokeOld are each refused', async (t) => {
  const planted: Record<string, Record<string, string>> = {
    'setGenStatus retired in revokeOld': { [ORCH]: "async function revokeOld(run) {\n  store.setGenStatus(run.keyref, run.genOld, 'retired');\n}\n" },
    'setGenStatus retired in rollBack': { [ORCH]: "async function rollBack(run) {\n  store.setGenStatus(run.keyref, run.genNew, 'retired');\n}\n" },
    'setGenStatus retired in another file': { 'src/shell/reconcile.ts': "export const f = (store) => store.setGenStatus('k', 1, 'retired');\n" },
    'vault.retire in revokeOld': { [ORCH]: 'async function revokeOld(run) {\n  deps.vault.retire(run.keyref, run.genOld);\n}\n' },
    'a retiring SQL write elsewhere': { 'src/shell/paste.ts': "export const sql = \"UPDATE rotation_gens SET status = 'retired' WHERE keyref = ?\";\n" },
    'retireProven outside the watch': { 'src/shell/delete-run.ts': "export const f = (store) => store.retireProven('k', 1);\n" },
  };
  for (const [name, files] of Object.entries(planted)) {
    const found = await checkRetireWriters(await materialise(t, files));
    assert.deepEqual(found.map((v) => v.code), ['retire-writer'], name);
  }
  const allowed = {
    [ORCH]: "async function boxRevoke(run) {\n  deps.vault.retire(run.keyref, run.genOld);\n  store.setGenStatus(run.keyref, run.genOld, 'retired');\n}\nasync function revokeOld(run) {\n  store.setGenStatus(run.keyref, run.genOld, 'grace');\n}\n",
    'src/shell/proof-watch.ts': "export const f = (store) => store.retireProven('k', 1);\n",
    'src/shell/deletion-store.ts': "export const sql = \"UPDATE rotation_gens SET status = 'retired' WHERE keyref = ?\";\n",
    'src/shell/rotation-store.ts': "export const sql = \"UPDATE rotation_gens SET status = 'retired' WHERE keyref = ?\";\n",
  };
  assert.deepEqual(await checkRetireWriters(await materialise(t, allowed)), [], 'control: the allowed writers pass');
});
