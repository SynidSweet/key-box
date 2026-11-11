// KBOX-51 and KBOX-17: the rotation state machine, intent first, reconcile by list, and a failure that keeps the old key.
// Real meta.db and file vault, a TimedClock, a fake platform and recording destinations behind the ports; faults are planted in the ports.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { TestContext } from 'node:test';
import { bytesOf } from './kit/index.ts';
import { ApiError } from '../src/pure/errors.ts';
import { HOUR, MINUTE, rotationWorld } from './support/rotation-world.ts';
import type { RotationWorld, WorldOptions } from './support/rotation-world.ts';

const NAME = 'OPENAI_KEY';
const TARGETS = ['app-a', 'app-b'] as const;
const heldBy = (w: RotationWorld): (string | undefined)[] => TARGETS.map((t) => w.destinations.a.heldAt(t, NAME));
const genOf = (w: RotationWorld, keyref: string, gen: number) => w.store.gen(keyref, gen);
const everySurface = (w: RotationWorld): string => JSON.stringify([w.parts.events.after(0), w.parts.audit.read(0).entries, w.push.sent]);
const asText = (b: Uint8Array): string => Buffer.from(b).toString('utf8');

async function seeded(t: TestContext, options: WorldOptions = {}): Promise<{ w: RotationWorld; keyref: string; oldValue: string; oldId: string }> {
  const w = await rotationWorld(t, options);
  const keyref = await w.seedKey();
  const oldId = genOf(w, keyref, 1)?.platformKeyId ?? '';
  return { w, keyref, oldValue: await w.valueOf(keyref, 1), oldId };
}

test('KBOX-51 a rotation runs create, store, verify, push, redeploy, check, then waits out the grace and revokes, in that order', async (t) => {
  const { w, keyref, oldValue, oldId } = await seeded(t);
  w.trace.length = 0;
  w.orch.start({ keyref, origin: 'owner' });
  await w.orch.idle();
  assert.deepEqual(w.trace, ['issue', 'verify', 'push:app-a', 'push:app-b', 'redeploy:app-a', 'redeploy:app-b', 'verify'], 'nothing is revoked while the grace runs');
  assert.equal(w.store.activeRunOf(keyref)?.state, 'grace');
  assert.equal(genOf(w, keyref, 2)?.status, 'current');
  assert.equal(genOf(w, keyref, 1)?.status, 'grace');
  const newValue = await w.valueOf(keyref, 2);
  assert.deepEqual(heldBy(w), [newValue, newValue]);
  assert.ok((await w.live()).includes(oldId), 'the old key still works during the grace');
  w.clock.advance(24 * HOUR - 1);
  await w.orch.idle();
  assert.equal(genOf(w, keyref, 1)?.status, 'grace', 'one millisecond before revokeAt nothing is revoked');
  w.clock.advance(1);
  await w.orch.idle();
  assert.equal(genOf(w, keyref, 1)?.status, 'retired');
  assert.deepEqual(await w.live(), [genOf(w, keyref, 2)?.platformKeyId]);
  assert.throws(() => w.parts.vault.lend(keyref, 1), 'the old value is never lent again');
  assert.equal(oldValue.length > 0, true);
});

test('KBOX-51 the intent row is written before the platform is called, and carries kbox_<ref>_g<N>_<run8>', async (t) => {
  const { w, keyref } = await seeded(t);
  const run = w.orch.start({ keyref, origin: 'owner' });
  assert.match(run.intentName, /^kbox_[a-z0-9_]+_g2_[0-9a-f]{8}$/);
  assert.equal(run.state, 'issuing');
  await w.orch.idle();
  assert.ok(w.trace.includes('issue'), 'the fake platform refuses to create when the intent row is missing, so this run passing proves the order');
  const listed = await w.platform.lister.list(w.platform.master());
  assert.ok(listed.some((k) => k.name === run.intentName), 'the platform key carries the intent name');
});

test('KBOX-51 a second run for the same key is refused, in the database and not only in the code', async (t) => {
  const { w, keyref } = await seeded(t);
  w.orch.start({ keyref, origin: 'owner' });
  assert.throws(() => w.orch.start({ keyref, origin: 'agent' }), (e: unknown) => e instanceof ApiError && e.code === 'conflict');
  assert.throws(
    () => w.store.openRun({ runId: 'run_ffffffffffffffff', keyref, state: 'issuing', genOld: 1, genNew: 9, intentName: 'kbox_x_g9_ffffffff', origin: 'owner' }),
    (e: unknown) => e instanceof ApiError && e.code === 'conflict',
  );
  await w.orch.idle();
});

// --- a crash after each step resumes from the persisted step ----------------------------------------------------------------

const AFTER = ['issued', 'issuing', 'verifying', 'pushing', 'redeploying', 'checking', 'promoting', 'grace', 'revoking'] as const;

for (const point of AFTER) {
  test(`KBOX-51 a crash after "${point}" resumes and finishes: the new key current everywhere, the old one revoked and confirmed, nothing stray on the platform`, async (t) => {
    const { w, keyref } = await seeded(t);
    w.checkpoints.arm(point);
    w.orch.start({ keyref, origin: 'owner' });
    await w.orch.idle();
    if (point === 'grace' || point === 'revoking') {
      w.clock.advance(24 * HOUR);
      await w.orch.idle();
    }
    assert.equal(w.checkpoints.seen.at(-1), point, 'the process died at the armed point');
    w.checkpoints.crashAt = undefined;
    w.build();
    await w.orch.resume();
    await w.reconciler.run();
    await w.settle();
    assert.equal(w.store.activeRuns().length, 0);
    assert.equal(w.store.gens(keyref).find((g) => g.status === 'current')?.gen, 2);
    assert.equal(genOf(w, keyref, 1)?.status, 'retired');
    const value = await w.valueOf(keyref, 2);
    assert.deepEqual(heldBy(w), [value, value]);
    assert.deepEqual(await w.live(), [genOf(w, keyref, 2)?.platformKeyId], 'exactly the new key is live: no orphan, the old one revoked');
    assert.equal(w.events('rotation.failed').length, 0);
    assert.equal(w.parts.meta.snapshot().keys.find((k) => k.keyref === keyref)?.status, 'works');
  });
}

test('KBOX-51 a crash between creating the key and storing it leaves an orphan that reconcile finds by listing, revokes, confirms and logs; the run goes again under a new run id', async (t) => {
  const { w, keyref } = await seeded(t);
  w.checkpoints.arm('issued');
  const first = w.orch.start({ keyref, origin: 'owner' });
  await w.orch.idle();
  assert.equal((await w.live()).length, 2, 'the platform holds the orphan beside the old key');
  assert.equal(w.store.gens(keyref).length, 1, 'no generation was stored');
  w.checkpoints.crashAt = undefined;
  w.build();
  await w.orch.resume();
  assert.equal((await w.live()).length, 2, 'resume does not touch an issuing run');
  await w.reconciler.run();
  assert.equal(w.store.run(first.runId)?.state, 'abandoned');
  const audit = w.parts.audit.read(0).entries.filter((e) => e.action === 'rotation.orphan_revoked');
  assert.equal(audit.length, 1, 'the audit log records the orphan');
  const again = w.store.runs().find((r) => r.runId !== first.runId && r.keyref === keyref && r.state !== 'abandoned' && r.genNew === 2);
  assert.ok(again && again.intentName !== first.intentName, 'a new run id, so a new intent name');
  await w.settle();
  assert.deepEqual(await w.live(), [genOf(w, keyref, 2)?.platformKeyId]);
});

test('KBOX-51 a daily reconcile between issue and store revokes nothing: the run holds the lease', async (t) => {
  const { w, keyref } = await seeded(t);
  let during: string[] | undefined;
  w.checkpoints.hook = async (point) => {
    if (point !== 'issued') return;
    await w.reconciler.run();
    during = await w.live();
  };
  w.orch.start({ keyref, origin: 'owner' });
  await w.orch.idle();
  assert.equal(during?.length, 2, 'the key just issued is still on the platform after the reconcile');
  await w.settle();
  assert.equal(w.store.gens(keyref).find((g) => g.status === 'current')?.gen, 2);
  assert.equal(w.events('rotation.failed').length, 0);
});

test('KBOX-51 a key named kbox_ that matches no intent and no generation raises one notice and is not revoked, and the second reconcile raises none', async (t) => {
  const { w } = await seeded(t);
  const stray = await w.platform.issuer.issue({ scope: {} }, 'kbox_stranger_g1_deadbeef', w.platform.master());
  const before = (await w.live()).length;
  await w.reconciler.run();
  await w.reconciler.run();
  assert.equal((await w.live()).length, before);
  assert.ok((await w.live()).includes(stray.platformKeyId));
  const notices = w.events('box.notice');
  assert.equal(notices.length, 1);
  assert.deepEqual([notices[0]?.data['code'], notices[0]?.data['text']], ['orphan_key', 'orphan key found']);
});

test('KBOX-51 a push repeated after a crash updates its receipt and makes no second object', async (t) => {
  const { w, keyref } = await seeded(t);
  w.checkpoints.arm('receipt', 1);
  w.orch.start({ keyref, origin: 'owner' });
  await w.orch.idle();
  const objectsBefore = w.destinations.a.objects();
  const versionBefore = w.destinations.a.versionAt('app-a', NAME);
  w.checkpoints.crashAt = undefined;
  w.build();
  await w.orch.resume();
  await w.settle();
  assert.equal(w.destinations.a.objects(), objectsBefore, 'no second object');
  assert.equal(w.destinations.a.versionAt('app-a', NAME), versionBefore, 'the first destination keeps the object its receipt names');
  const receipts = w.store.receipts(w.store.runs().filter((r) => r.genNew === 2).at(-1)?.runId ?? '');
  assert.deepEqual(receipts.map((r) => [r.target, r.pushed, r.version !== null]), [['app-a', true, true], ['app-b', true, true]]);
});

// --- step 10: a 404 is not proof --------------------------------------------------------------------------------------------

test('KBOX-51 a revoke that answers 404 while the verifier still accepts the old value leaves it in grace, retried, one notice; then the verifier rejecting gives retired', async (t) => {
  const { w, keyref, oldId } = await seeded(t);
  w.faults.revoke404 = true;
  w.orch.start({ keyref, origin: 'owner' });
  await w.orch.idle();
  w.clock.advance(24 * HOUR);
  await w.orch.idle();
  assert.equal(genOf(w, keyref, 1)?.status, 'grace', 'not retired: the platform still accepts it');
  assert.equal(w.store.activeRunOf(keyref)?.attempts, 1);
  assert.equal(w.events('rotation.old_key_still_on').length, 1);
  w.clock.advance(MINUTE);
  await w.orch.idle();
  assert.equal(w.store.activeRunOf(keyref)?.attempts, 2, 'retried');
  assert.equal(w.events('rotation.old_key_still_on').length, 1, 'still one notice');
  w.faults.revoke404 = false;
  w.clock.advance(2 * MINUTE);
  await w.orch.idle();
  assert.equal(genOf(w, keyref, 1)?.status, 'retired');
  assert.ok(!(await w.live()).includes(oldId));
  assert.equal(w.events('rotation.old_key_still_on').length, 1);
});

test('KBOX-17 the revoke retry waits 1 minute, then 2, doubling; it does not run early', async (t) => {
  const { w, keyref } = await seeded(t);
  w.faults.revoke404 = true;
  w.orch.start({ keyref, origin: 'owner' });
  await w.orch.idle();
  w.clock.advance(24 * HOUR);
  await w.orch.idle();
  const attempts = (): number | undefined => w.store.activeRunOf(keyref)?.attempts;
  assert.equal(attempts(), 1);
  w.clock.advance(MINUTE - 1);
  await w.orch.idle();
  assert.equal(attempts(), 1, 'one millisecond early');
  w.clock.advance(1);
  await w.orch.idle();
  assert.equal(attempts(), 2);
  w.clock.advance(2 * MINUTE - 1);
  await w.orch.idle();
  assert.equal(attempts(), 2);
  w.clock.advance(1);
  await w.orch.idle();
  assert.equal(attempts(), 3);
});

test('KBOX-51 with no verifier call, a lister that still shows the id (in another region than the one recorded) leaves the old key in grace; a lister that shows it absent gives retired', async (t) => {
  const { w, keyref, oldId } = await seeded(t, { verifier: false });
  assert.equal(w.store.keyInfo(keyref)?.location.region, 'eu');
  w.faults.revoke404 = true;
  w.orch.start({ keyref, origin: 'owner' });
  await w.orch.idle();
  w.clock.advance(24 * HOUR);
  await w.orch.idle();
  assert.equal(genOf(w, keyref, 1)?.status, 'grace');
  assert.ok((await w.live()).includes(oldId));
  w.faults.revoke404 = false;
  w.clock.advance(MINUTE);
  await w.orch.idle();
  assert.equal(genOf(w, keyref, 1)?.status, 'retired');
  assert.ok(!(await w.live()).includes(oldId));
});

// --- overlap: false -----------------------------------------------------------------------------------------------------------

test('KBOX-51 overlap:false follows its order: set the new value, push, redeploy at once, check, revoke with no grace wait', async (t) => {
  const { w, keyref } = await seeded(t, { overlap: false });
  w.trace.length = 0;
  w.orch.start({ keyref, origin: 'owner' });
  await w.orch.idle();
  assert.deepEqual(w.trace, ['issue', 'verify', 'push:app-a', 'push:app-b', 'redeploy:app-a', 'redeploy:app-b', 'verify', 'revoke', 'verify']);
  assert.equal(w.store.activeRuns().length, 0, 'done at once: no clock was advanced');
  assert.equal(genOf(w, keyref, 1)?.status, 'retired');
});

test('KBOX-17 overlap:false rollback sets the old value back in every destination that was changed', async (t) => {
  const { w, keyref, oldValue } = await seeded(t, { overlap: false });
  w.destinations.redeployer.failNext();
  w.orch.start({ keyref, origin: 'owner' });
  await w.settle();
  assert.deepEqual(heldBy(w), [oldValue, oldValue]);
  assert.equal(w.store.runs().at(-1)?.state, 'failed');
});

// --- failure keeps the old key -------------------------------------------------------------------------------------------------

type Fault = readonly [step: string, plant: (w: RotationWorld) => void, failedStep: string, reason: string];
const FAULTS: readonly Fault[] = [
  ['3 create', (w) => void (w.faults.issue = true), 'issuing', 'issue_failed'],
  ['4 store', (w) => void (w.faults.vaultPut = true), 'issuing', 'store_failed'],
  ['5 verify the new key', (w) => void (w.faults.verifyAt = 1), 'verifying', 'verify_rejected'],
  ['6 push', (w) => w.destinations.a.refuse('app-b'), 'pushing', 'push_failed'],
  ['7 redeploy', (w) => w.destinations.redeployer.failNext(), 'redeploying', 'redeploy_failed'],
  ['8 check', (w) => void (w.faults.verifyAt = 2), 'checking', 'check_rejected'],
];

for (const klass of ['ordinary', 'admin'] as const) {
  for (const [step, plant, failedStep, reason] of FAULTS) {
    test(`KBOX-17 a fault at step ${step} (${klass} key) leaves the old key current in every destination, the new one revoked, and exactly one notice`, async (t) => {
      const w = await rotationWorld(t, { klass });
      const keyref = await w.seedKey();
      const oldValue = await w.valueOf(keyref, 1);
      const oldId = genOf(w, keyref, 1)?.platformKeyId ?? '';
      plant(w);
      w.orch.start({ keyref, origin: 'owner' });
      await w.settle();
      assert.deepEqual(heldBy(w), [oldValue, oldValue], 'the old value is in every destination');
      assert.deepEqual(await w.live(), [oldId], 'the new key is revoked; the old one still works');
      assert.equal(await w.platform.verifier.verify(w.parts.vault.lend(keyref, 1), { platform: 'fake' }), 'ok');
      const failed = w.events('rotation.failed');
      assert.equal(failed.length, 1, 'exactly one notice event');
      assert.deepEqual([failed[0]?.data['step'], failed[0]?.data['reason_code'], failed[0]?.data['old_key_works']], [failedStep, reason, true]);
      assert.equal(w.push.sent.filter((p) => p.kind === 'rotation_failed').length, klass === 'admin' ? 1 : 0, 'a Web Push for admin keys only');
      assert.equal(w.store.runs().at(-1)?.state, 'failed');
      assert.equal(w.store.gens(keyref).find((g) => g.gen === 1)?.status, 'current');
      assert.notEqual(w.store.gens(keyref).find((g) => g.gen === 2)?.status ?? 'failed', 'current');
      assert.equal(w.parts.meta.snapshot().keys.find((k) => k.keyref === keyref)?.gen_current, 1);
      assert.equal(w.parts.meta.snapshot().keys.find((k) => k.keyref === keyref)?.status, 'failed');
    });
  }
}

test('KBOX-17 a destination that refuses the re-push keeps the run failed with a second notice naming that destination; the new key stays unrevoked while it is the one that destination holds', async (t) => {
  const { w, keyref } = await seeded(t);
  w.destinations.redeployer.failNext();
  w.destinations.a.refuseAfter('app-a', 1);
  w.orch.start({ keyref, origin: 'owner' });
  await w.orch.idle();
  const failed = w.events('rotation.failed');
  assert.equal(failed.length, 2);
  assert.deepEqual(failed.map((e) => e.data['step']), ['redeploying', 'rollback_vercel_env']);
  assert.equal(w.store.activeRunOf(keyref)?.state, 'rolling_back');
  assert.equal((await w.live()).length, 2, 'the new key is not revoked while app-a still holds it');
  const newValue = await w.valueOf(keyref, 2);
  assert.equal(w.destinations.a.heldAt('app-a', NAME), newValue);
  w.destinations.a.allow('app-a');
  w.clock.advance(MINUTE);
  await w.orch.idle();
  assert.equal(w.events('rotation.failed').length, 2, 'the retry makes no further notice');
  const oldValue = await w.valueOf(keyref, 1);
  assert.deepEqual(heldBy(w), [oldValue, oldValue]);
  assert.equal((await w.live()).length, 1);
  assert.equal(w.store.runs().at(-1)?.state, 'failed');
});

test('KBOX-16 a destination whose properties turned api-readable since the key was added is refused at push for an admin key: the old key stays everywhere', async (t) => {
  const w = await rotationWorld(t, { klass: 'admin' });
  const keyref = await w.seedKey();
  const oldValue = await w.valueOf(keyref, 1);
  w.destinations.a.setRuntime(false);
  w.orch.start({ keyref, origin: 'owner' });
  await w.settle();
  const failed = w.events('rotation.failed');
  assert.deepEqual([failed.length, failed[0]?.data['step'], failed[0]?.data['reason_code']], [1, 'pushing', 'destination_not_allowed']);
  assert.deepEqual(heldBy(w), [oldValue, oldValue], 'nothing was pushed');
  assert.equal((await w.live()).length, 1);
});

test('KBOX-16 the same api-readable destination is accepted for an ordinary key', async (t) => {
  const w = await rotationWorld(t);
  const keyref = await w.seedKey();
  w.destinations.a.setRuntime(false);
  w.orch.start({ keyref, origin: 'owner' });
  await w.settle();
  assert.equal(w.events('rotation.failed').length, 0);
  assert.equal(genOf(w, keyref, 2)?.status, 'current');
});

test('KBOX-2 the new key value is absent from every event, audit row and push of a failed rotation', async (t) => {
  const { w, keyref } = await seeded(t, { klass: 'admin' });
  w.destinations.redeployer.failNext();
  let fresh = '';
  w.checkpoints.hook = async (point) => {
    if (point === 'issuing') fresh = await w.valueOf(keyref, 2);
  };
  w.orch.start({ keyref, origin: 'owner' });
  await w.settle();
  assert.match(fresh, /^fk-[0-9a-f]{32}$/, 'the new value was captured while it was stored');
  const old = asText(await bytesOf(w.parts.vault.lend(keyref, 1)));
  const surfaces = everySurface(w);
  for (const value of [fresh, old]) {
    for (const form of [value, Buffer.from(value).toString('base64'), Buffer.from(value).toString('hex')]) assert.equal(surfaces.includes(form), false);
  }
  assert.ok(surfaces.includes('rotation_failed') && surfaces.includes('rotation.failed'), 'the surfaces are not empty: the notice is there, by name');
});

test('KBOX-51 a key that does not exist is not_found and opens no run', async (t) => {
  const w = await rotationWorld(t);
  assert.throws(() => w.orch.start({ keyref: 'fake/none/X', origin: 'owner' }), (e: unknown) => e instanceof ApiError && e.code === 'not_found');
  assert.equal(w.store.runs().length, 0);
});
