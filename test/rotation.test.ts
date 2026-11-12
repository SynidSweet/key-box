// KBOX-51 and KBOX-17: the rotation state machine, intent first, reconcile by list, and a failure that keeps the old key.
// Real meta.db and file vault, a TimedClock, a fake platform and recording destinations behind the ports; faults are planted in the ports.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { TestContext } from 'node:test';
import { bytesOf, lent, seededRandom } from './kit/index.ts';
import { FakePlatformWorld } from './fakes/platform.ts';
import { newKeyOf } from '../src/shell/new-key.ts';
import type { PlatformSource } from '../src/shell/rotation-ports.ts';
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
  const stray = await w.platform.issuer.issue({ scope: {}, at: {} }, 'kbox_stranger_g1_deadbeef', w.platform.master());
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
  assert.deepEqual(w.trace, ['set', 'verify', 'push:app-a', 'push:app-b', 'redeploy:app-a', 'redeploy:app-b', 'verify', 'verify']);
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
      assert.equal(await w.platform.verifier.verify(w.parts.vault.lend(keyref, 1), { platform: 'fake', at: {} }), 'ok');
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

// --- a push whose outcome is unknown (review B1) -----------------------------------------------------------------------------

test('KBOX-17 a push that changed the destination and then threw is rolled back there too: the intent receipt names it, and the new key is revoked only after the old value is back', async (t) => {
  const { w, keyref, oldValue, oldId } = await seeded(t);
  w.destinations.a.applyThenThrow('app-b');
  w.orch.start({ keyref, origin: 'owner' });
  await w.settle();
  assert.deepEqual(heldBy(w), [oldValue, oldValue], 'app-b, whose push applied and then threw, holds the old value again');
  assert.deepEqual(await w.live(), [oldId], 'the new key is revoked; the old one still works');
  assert.equal(w.events('rotation.failed').length, 1);
  assert.equal(w.store.runs().at(-1)?.state, 'failed');
});

test('KBOX-17 a crash between a push and its receipt leaves an intent receipt: a later rollback puts the old value back there before the new key is revoked', async (t) => {
  const { w, keyref, oldValue, oldId } = await seeded(t);
  w.checkpoints.arm('pushed', 1);
  w.orch.start({ keyref, origin: 'owner' });
  await w.orch.idle();
  assert.equal(w.checkpoints.seen.at(-1), 'pushed', 'the process died after the first push and before its receipt');
  const newValue = await w.valueOf(keyref, 2);
  assert.equal(w.destinations.a.heldAt('app-a', NAME), newValue, 'app-a holds the new value');
  w.checkpoints.crashAt = undefined;
  w.destinations.a.refuse('app-a');
  w.build();
  await w.orch.resume();
  assert.equal(w.destinations.a.heldAt('app-a', NAME), newValue, 'the push after the restart was refused, so app-a still holds the new value');
  assert.equal((await w.live()).length, 2, 'the new key is not revoked while app-a may hold it');
  w.destinations.a.allow('app-a');
  await w.settle(MINUTE);
  assert.deepEqual(heldBy(w), [oldValue, oldValue]);
  assert.deepEqual(await w.live(), [oldId]);
  assert.equal(w.store.runs().at(-1)?.state, 'failed');
});

// --- an intent before every redeploy, set and remove (review N1) -----------------------------------------------------------------

/** The value the code deployed at each target runs: a revoked key there is an app that breaks. */
const runningAt = (w: RotationWorld): (string | undefined)[] => TARGETS.map((t) => w.destinations.redeployer.runningAt(t, NAME));
/** What happened at one target, and the revokes, in order (KBOX-17: re-push, redeploy where redeployed, then revoke the new key). */
const callsAt = (w: RotationWorld, target: string): string[] => w.trace.filter((x) => x.endsWith(`:${target}`) || x === 'revoke');

test('KBOX-17 a redeploy that started and then threw is undone: the rollback redeploys the old value there before the new key is revoked', async (t) => {
  const { w, keyref, oldValue, oldId } = await seeded(t);
  w.destinations.redeployer.startThenThrow('app-b');
  w.trace.length = 0;
  w.orch.start({ keyref, origin: 'owner' });
  await w.settle();
  assert.deepEqual(runningAt(w), [oldValue, oldValue], 'app-b, whose deploy of the new value started, runs the old value again');
  assert.deepEqual(callsAt(w, 'app-b'), ['push:app-b', 'redeploy:app-b', 'push:app-b', 'redeploy:app-b', 'revoke'], 'the new key was revoked only after app-b was redeployed with the old value');
  assert.deepEqual(await w.live(), [oldId]);
  assert.equal(w.events('rotation.failed').length, 1);
  assert.equal(w.store.runs().at(-1)?.state, 'failed');
});

test('KBOX-17 a crash between a redeploy and its receipt leaves a redeploy intent: a later rollback redeploys the old value there before the new key is revoked', async (t) => {
  const { w, keyref, oldValue, oldId } = await seeded(t);
  w.checkpoints.arm('redeployed', 1);
  w.orch.start({ keyref, origin: 'owner' });
  await w.orch.idle();
  assert.equal(w.checkpoints.seen.at(-1), 'redeployed', 'the process died after the first redeploy started and before its result was written');
  const newValue = await w.valueOf(keyref, 2);
  assert.equal(w.destinations.redeployer.runningAt('app-a', NAME), newValue, 'app-a runs the new value');
  w.checkpoints.crashAt = undefined;
  w.destinations.redeployer.refuseNext('app-a');
  w.trace.length = 0;
  w.build();
  await w.orch.resume();
  await w.settle(MINUTE);
  assert.deepEqual(runningAt(w), [oldValue, oldValue], 'app-a, whose redeploy after the restart was refused, was redeployed with the old value by the rollback');
  assert.deepEqual(callsAt(w, 'app-a'), ['push:app-a', 'redeploy:app-a', 'revoke'], 'the rollback re-pushed and redeployed app-a, then revoked the new key');
  assert.deepEqual(await w.live(), [oldId]);
  assert.equal(w.events('rotation.failed').length, 1);
  assert.equal(w.store.runs().at(-1)?.state, 'failed');
});

test('KBOX-17 the new key is not revoked while a destination whose deploy of it started may still run it: a rollback redeploy that fails holds the revoke until it goes through', async (t) => {
  const { w, keyref, oldValue, oldId } = await seeded(t);
  w.destinations.redeployer.startThenThrow('app-b');
  w.destinations.redeployer.failAt('app-b');
  w.orch.start({ keyref, origin: 'owner' });
  await w.orch.idle();
  const newValue = await w.valueOf(keyref, 2);
  assert.equal(w.destinations.redeployer.runningAt('app-b', NAME), newValue, 'app-b runs the new value: its rollback deploy failed');
  assert.equal(w.store.activeRunOf(keyref)?.state, 'rolling_back');
  assert.equal((await w.live()).length, 2, 'the new key is not revoked while app-b runs it');
  assert.deepEqual(w.events('rotation.failed').map((e) => e.data['step']), ['redeploying', 'rollback_vercel_env'], 'the failure and one card named for app-b');
  w.destinations.redeployer.allow('app-b');
  w.clock.advance(MINUTE);
  await w.orch.idle();
  assert.deepEqual(runningAt(w), [oldValue, oldValue]);
  assert.deepEqual(await w.live(), [oldId]);
  assert.equal(w.events('rotation.failed').length, 2, 'the retry files no further card');
  assert.equal(w.store.runs().at(-1)?.state, 'failed');
});

test('KBOX-17 overlap:false: a set that took the new value and then threw is undone, the platform takes the old value again', async (t) => {
  const { w, keyref, oldValue } = await seeded(t, { overlap: false });
  w.faults.setThenThrow = true;
  w.orch.start({ keyref, origin: 'owner' });
  await w.settle();
  assert.equal(await platformTakes(w, oldValue), 'ok', 'the platform, which holds one credential, takes the old value again');
  assert.deepEqual(w.trace.filter((x) => x === 'set'), ['set', 'set'], 'the new value set, then the old one set back');
  assert.deepEqual(heldBy(w), [oldValue, oldValue]);
  assert.equal(w.events('rotation.failed').length, 1);
  assert.deepEqual([w.store.runs().at(-1)?.state, genOf(w, keyref, 2)?.status, genOf(w, keyref, 1)?.status], ['failed', 'failed', 'current']);
});

test('KBOX-17 overlap:false: a crash between the set and its receipt leaves the set intent: a later failure sets the old value back at the platform', async (t) => {
  const { w, keyref, oldValue } = await seeded(t, { overlap: false });
  w.checkpoints.arm('taken', 1);
  w.orch.start({ keyref, origin: 'owner' });
  await w.orch.idle();
  assert.equal(w.checkpoints.seen.at(-1), 'taken', 'the process died after the platform took the new value and before its receipt');
  assert.equal(await platformTakes(w, oldValue), 'rejected', 'the platform holds only the new value');
  w.checkpoints.crashAt = undefined;
  w.destinations.a.refuse('app-a');
  w.build();
  await w.orch.resume();
  await w.settle(MINUTE);
  assert.equal(await platformTakes(w, oldValue), 'ok', 'the rollback set the old value back');
  assert.deepEqual(heldBy(w), [oldValue, oldValue]);
  assert.equal(w.events('rotation.failed').length, 1);
  assert.equal(w.store.runs().at(-1)?.state, 'failed');
});

test('KBOX-17 a create run whose removal took the value away and then threw tries again, and revokes the new key only once the removal answers', async (t) => {
  const w = await rotationWorld(t);
  w.destinations.a.refuse('app-b');
  w.destinations.a.removeThenThrow('app-a');
  const key = w.newKey();
  await w.orch.create(key);
  assert.equal(w.destinations.a.heldAt('app-a', NAME), undefined, 'the removal took the value away');
  assert.equal(w.store.activeRunOf(key.keyref)?.state, 'rolling_back', 'an answer that failed proves nothing: the run holds');
  assert.equal((await w.live()).length, 1, 'the new key is not revoked on an unanswered removal');
  w.clock.advance(MINUTE);
  await w.orch.idle();
  assert.deepEqual(await w.live(), [], 'the removal answered, so the new key is revoked');
  assert.equal(w.store.runs().at(-1)?.state, 'failed');
  assert.deepEqual(w.events('rotation.failed').map((e) => e.data['reason_code']), ['push_failed', 'remove_refused']);
});

test('KBOX-17 a create run that crashed between a removal and its result removes again on resume, then revokes the new key: one card', async (t) => {
  const w = await rotationWorld(t);
  w.destinations.a.refuse('app-b');
  w.checkpoints.arm('removed', 1);
  const key = w.newKey();
  await w.orch.create(key);
  assert.equal(w.checkpoints.seen.at(-1), 'removed', 'the process died after the removal and before the run went on');
  assert.equal((await w.live()).length, 1, 'the new key is still live');
  w.checkpoints.crashAt = undefined;
  w.trace.length = 0;
  w.build();
  await w.orch.resume();
  assert.deepEqual(callsAt(w, 'app-a'), ['remove:app-a', 'revoke'], 'removed again before the revoke');
  assert.deepEqual(await w.live(), []);
  assert.equal(w.destinations.a.heldAt('app-a', NAME), undefined);
  assert.equal(w.events('rotation.failed').length, 1);
  assert.equal(w.store.runs().at(-1)?.state, 'failed');
});

// --- deliveries to the workstation (review B2, M4) -----------------------------------------------------------------------------

const WORKSTATION = { kind: 'workstation', target: 'workstation', readable_by: 'api' } as const;
const deliveredGens = (w: RotationWorld): { rows: number[]; events: unknown[] } => ({
  rows: w.store.deliveries().map((d) => d.gen),
  events: w.events('delivery.ready').map((e) => e.data['gen']),
});

test('KBOX-34 a rotation that fails after its push offers no delivery of the new generation: no delivery row and no delivery.ready event for it', async (t) => {
  const w = await rotationWorld(t);
  const keyref = await w.seedKey({ destinations: [...w.newKey().destinations, WORKSTATION] });
  assert.deepEqual(deliveredGens(w), { rows: [1], events: [1] }, 'the first generation was offered once it was promoted');
  w.faults.verifyAt = 2;
  w.orch.start({ keyref, origin: 'owner' });
  await w.settle();
  assert.equal(w.store.runs().at(-1)?.state, 'failed');
  assert.deepEqual(deliveredGens(w), { rows: [1], events: [1] }, 'nothing of generation 2 was ever offered');
});

test('KBOX-34 a successful rotation offers the new generation to the workstation once it is promoted', async (t) => {
  const w = await rotationWorld(t);
  const keyref = await w.seedKey({ destinations: [...w.newKey().destinations, WORKSTATION] });
  let atCheck: { rows: number[]; events: unknown[] } | undefined;
  w.checkpoints.hook = async (point) => {
    if (point === 'checking') atCheck = deliveredGens(w);
  };
  w.orch.start({ keyref, origin: 'owner' });
  await w.settle();
  assert.deepEqual(atCheck, { rows: [1], events: [1] }, 'not offered before the check passed');
  assert.deepEqual(deliveredGens(w), { rows: [1, 2], events: [1, 2] });
});

test('KBOX-16 KBOX-34 an admin key with a workstation destination gets no delivery row and no delivery.ready event', async (t) => {
  const w = await rotationWorld(t, { klass: 'admin' });
  await w.seedKey({ destinations: [WORKSTATION] });
  assert.deepEqual(deliveredGens(w), { rows: [], events: [] });
});

// --- a failed first generation (review B3): there is no old key to keep --------------------------------------------------------

const claimsOldKeyWorks = (w: RotationWorld): boolean =>
  w.events('rotation.failed').some((e) => e.data['old_key_works'] === true) || w.push.sent.some((p) => /old key/i.test(p.title));

for (const klass of ['ordinary', 'admin'] as const) {
  test(`KBOX-17 a create run (${klass} key) whose second push fails removes the value from every destination that may hold it, revokes and confirms the new key, ends failed, and claims no old key works`, async (t) => {
    const w = await rotationWorld(t, { klass });
    w.destinations.a.refuse('app-b');
    const key = w.newKey();
    const created = await w.orch.create(key);
    assert.equal(created.status, 'failed');
    assert.equal(w.store.activeRuns().length, 0, 'the run ended without waiting on a clock');
    assert.equal(w.store.runs().at(-1)?.state, 'failed');
    assert.deepEqual(heldBy(w), [undefined, undefined], 'no destination holds the value of the failed key');
    assert.deepEqual(await w.live(), [], 'the new key is revoked and nothing else was made');
    assert.equal(claimsOldKeyWorks(w), false, 'no notice says an old key works: there is none');
    assert.equal(w.push.sent.filter((p) => p.kind === 'rotation_failed').length, klass === 'admin' ? 1 : 0, 'one Web Push for an admin key');
  });
}

test('KBOX-17 a create run whose removal is refused keeps the new key unrevoked while that destination holds it, sends one more notice named for it, and retries', async (t) => {
  const w = await rotationWorld(t, { klass: 'admin' });
  w.destinations.a.refuse('app-b');
  w.destinations.a.refuseRemove('app-a');
  const created = await w.orch.create(w.newKey());
  assert.equal(created.status, 'failed');
  const newValue = w.destinations.a.heldAt('app-a', NAME);
  assert.ok(newValue !== undefined, 'app-a still holds the new value');
  assert.equal((await w.live()).length, 1, 'the new key is not revoked while app-a holds it');
  const pushes = w.push.sent.filter((p) => p.kind === 'rotation_failed');
  assert.equal(pushes.length, 2);
  assert.match(pushes[1]?.title ?? '', /app-a/, 'the second notice names the destination');
  assert.equal(claimsOldKeyWorks(w), false);
  w.clock.advance(MINUTE);
  await w.orch.idle();
  assert.equal((await w.live()).length, 1, 'still refused: still held');
  assert.equal(w.push.sent.filter((p) => p.kind === 'rotation_failed').length, 2, 'the retry sends no further notice');
  w.destinations.a.allow('app-a');
  await w.settle(2 * MINUTE);
  assert.deepEqual(heldBy(w), [undefined, undefined]);
  assert.deepEqual(await w.live(), []);
  assert.equal(w.store.runs().at(-1)?.state, 'failed');
});

// --- a crash after the generation is stored and before the step is persisted (review M1) ------------------------------------------

test('KBOX-51 a crash between storing the new generation and persisting the step is continued, not restarted: exactly one platform key is left, the tracked one', async (t) => {
  const { w, keyref } = await seeded(t);
  w.checkpoints.arm('stored');
  const first = w.orch.start({ keyref, origin: 'owner' });
  await w.orch.idle();
  assert.equal(w.checkpoints.seen.at(-1), 'stored');
  assert.equal(w.store.run(first.runId)?.state, 'issuing', 'the run row still says issuing');
  assert.equal(genOf(w, keyref, 2)?.status, 'pending', 'and generation 2 is stored');
  w.checkpoints.crashAt = undefined;
  w.build();
  await w.orch.resume();
  await w.reconciler.run();
  await w.settle();
  assert.deepEqual(w.store.runs().filter((r) => r.origin !== 'create').map((r) => [r.runId, r.state]), [[first.runId, 'done']], 'the same run finished; none was opened beside it');
  assert.deepEqual(await w.live(), [genOf(w, keyref, 2)?.platformKeyId], 'exactly one platform key: generation 2, tracked');
  assert.equal(w.store.gens(keyref).find((g) => g.status === 'current')?.gen, 2);
});

test('KBOX-51 reconcile alone (no resume) continues an issuing run that holds a stored generation instead of restarting it', async (t) => {
  const { w, keyref } = await seeded(t);
  w.checkpoints.arm('stored');
  const first = w.orch.start({ keyref, origin: 'owner' });
  await w.orch.idle();
  w.checkpoints.crashAt = undefined;
  w.build();
  await w.reconciler.run();
  await w.settle();
  assert.equal(w.store.run(first.runId)?.state, 'done');
  assert.equal(w.store.runs().filter((r) => r.state === 'abandoned').length, 0, 'nothing was abandoned');
  assert.deepEqual(await w.live(), [genOf(w, keyref, 2)?.platformKeyId]);
});

// --- the one notice is persisted before it is sent (review m1) -----------------------------------------------------------------

test('KBOX-17 a failed run records that its notice went out before it sends it, so a crash in between never gives a second card', async (t) => {
  const { w, keyref } = await seeded(t);
  const recordedAtSend: (boolean | undefined)[] = [];
  w.appending = (kind) => {
    if (kind === 'rotation.failed') recordedAtSend.push(w.store.activeRunOf(keyref)?.failedNotified);
  };
  w.faults.verifyAt = 1;
  w.orch.start({ keyref, origin: 'owner' });
  await w.settle();
  assert.deepEqual(recordedAtSend, [true]);
});

// --- a throw outside a guarded step is never silent (review M2) --------------------------------------------------------------------

/** A write the database itself refuses (an I/O error stand-in), planted as a trigger on the real meta.db and taken away by the returned function. */
function refuseWrite(w: RotationWorld, table: 'rotation_runs' | 'rotation_gens', when: string): () => void {
  const name = `refuse_${table}`;
  w.parts.db.exec(`CREATE TRIGGER ${name} BEFORE UPDATE ON ${table} WHEN ${when} BEGIN SELECT RAISE(ABORT, 'disk I/O error'); END`);
  return () => w.parts.db.exec(`DROP TRIGGER ${name}`);
}
const stillOn = (w: RotationWorld): number => w.events('rotation.old_key_still_on').length;
const failedCards = (w: RotationWorld): number => w.events('rotation.failed').length;

test('KBOX-17 a master key that cannot be lent at push files the run\'s one failure card and keeps a retry: once it can be lent, the rollback ends with the old key everywhere', async (t) => {
  const { w, keyref, oldValue, oldId } = await seeded(t);
  w.checkpoints.hook = async (point) => {
    if (point === 'verifying') w.faults.master = true;
  };
  w.orch.start({ keyref, origin: 'owner' });
  await w.orch.idle();
  w.checkpoints.hook = undefined;
  assert.equal(failedCards(w), 1, 'one card at once');
  assert.equal(w.store.activeRunOf(keyref)?.state, 'rolling_back');
  assert.equal(w.orch.isLeased(keyref), false, 'the lease is not left behind');
  w.clock.advance(MINUTE);
  await w.orch.idle();
  assert.equal(failedCards(w), 1, 'a retry that throws again sends no second card');
  w.faults.master = false;
  await w.settle(2 * MINUTE);
  assert.equal(w.store.runs().at(-1)?.state, 'failed');
  assert.deepEqual(heldBy(w), [oldValue, oldValue]);
  assert.deepEqual(await w.live(), [oldId]);
  assert.equal(failedCards(w), 1);
});

test('KBOX-17 a run whose step write the database refuses files the one failure card and rolls back', async (t) => {
  const { w, keyref, oldValue, oldId } = await seeded(t);
  const restore = refuseWrite(w, 'rotation_runs', "NEW.state = 'checking'");
  w.orch.start({ keyref, origin: 'owner' });
  await w.orch.idle();
  restore();
  await w.settle(MINUTE);
  assert.equal(failedCards(w), 1);
  assert.equal(w.store.runs().at(-1)?.state, 'failed');
  assert.deepEqual(heldBy(w), [oldValue, oldValue]);
  assert.deepEqual(await w.live(), [oldId]);
});

test('KBOX-17 a store write refused at promote keeps the old key on, sends one old_key_still_on notice and retries until it goes through', async (t) => {
  const { w, keyref } = await seeded(t);
  const restore = refuseWrite(w, 'rotation_gens', "NEW.status = 'grace'");
  w.orch.start({ keyref, origin: 'owner' });
  await w.orch.idle();
  assert.equal(w.store.activeRunOf(keyref)?.state, 'promoting');
  assert.equal(stillOn(w), 1);
  assert.equal(failedCards(w), 0, 'nothing is rolled back after the check passed');
  w.clock.advance(MINUTE);
  await w.orch.idle();
  assert.equal(stillOn(w), 1, 'one notice, however many retries');
  restore();
  await w.settle(2 * MINUTE + 24 * HOUR);
  assert.equal(w.store.activeRuns().length, 0);
  assert.equal(genOf(w, keyref, 1)?.status, 'retired');
  assert.equal(genOf(w, keyref, 2)?.status, 'current');
});

test('KBOX-17 a master key that cannot be lent at revoke keeps the old key in grace, sends one old_key_still_on notice and retries', async (t) => {
  const { w, keyref, oldId } = await seeded(t);
  w.orch.start({ keyref, origin: 'owner' });
  await w.orch.idle();
  w.faults.master = true;
  w.clock.advance(24 * HOUR);
  await w.orch.idle();
  assert.equal(genOf(w, keyref, 1)?.status, 'grace');
  assert.equal(stillOn(w), 1);
  w.clock.advance(MINUTE);
  await w.orch.idle();
  assert.equal(stillOn(w), 1);
  w.faults.master = false;
  await w.settle(2 * MINUTE);
  assert.equal(genOf(w, keyref, 1)?.status, 'retired');
  assert.ok(!(await w.live()).includes(oldId));
});

test('KBOX-17 a master key that cannot be lent during the rollback sends no second card and retries the rollback until it ends', async (t) => {
  const { w, keyref, oldValue, oldId } = await seeded(t);
  w.faults.verifyAt = 2;
  w.checkpoints.hook = async (point) => {
    if (point === 'redeploying') w.faults.master = true;
  };
  w.orch.start({ keyref, origin: 'owner' });
  await w.orch.idle();
  w.checkpoints.hook = undefined;
  assert.equal(w.store.activeRunOf(keyref)?.state, 'rolling_back');
  assert.equal(failedCards(w), 1);
  w.faults.master = false;
  await w.settle(MINUTE);
  assert.equal(failedCards(w), 1);
  assert.equal(w.store.runs().at(-1)?.state, 'failed');
  assert.deepEqual(heldBy(w), [oldValue, oldValue]);
  assert.deepEqual(await w.live(), [oldId]);
});

// --- the lister confirms only by a complete listing of the recorded location (review M3) ------------------------------------------

test('KBOX-51 with no verifier call, a lister that answers for another region than the one recorded does not confirm the revoke, even with the key gone; a listing of the right region does', async (t) => {
  const { w, keyref, oldId } = await seeded(t, { verifier: false });
  w.faults.listerAt = { region: 'us' };
  w.orch.start({ keyref, origin: 'owner' });
  await w.orch.idle();
  w.clock.advance(24 * HOUR);
  await w.orch.idle();
  assert.ok(!(await w.live()).includes(oldId), 'the platform did revoke it');
  assert.equal(genOf(w, keyref, 1)?.status, 'grace', 'but a listing of another region proves nothing');
  w.faults.listerAt = undefined;
  w.faults.listingIncomplete = true;
  w.clock.advance(MINUTE);
  await w.orch.idle();
  assert.equal(genOf(w, keyref, 1)?.status, 'grace', 'nor does an incomplete listing of the right region');
  w.faults.listingIncomplete = false;
  w.clock.advance(2 * MINUTE);
  await w.orch.idle();
  assert.equal(genOf(w, keyref, 1)?.status, 'retired');
});

// --- overlap:false: the platform takes a value the box chose (review M5) -----------------------------------------------------------

const platformTakes = async (w: RotationWorld, value: string): Promise<string> =>
  w.platform.verifier.verify(lent(Buffer.from(value), 'probe:1'), { platform: 'fake', at: {} });

test('KBOX-51 overlap:false sets a value the box chose at the platform, which stops taking the old one, then pushes and redeploys at once and needs no revoke', async (t) => {
  const { w, keyref, oldValue } = await seeded(t, { overlap: false });
  w.trace.length = 0;
  w.orch.start({ keyref, origin: 'owner' });
  await w.orch.idle();
  assert.deepEqual(w.trace, ['set', 'verify', 'push:app-a', 'push:app-b', 'redeploy:app-a', 'redeploy:app-b', 'verify', 'verify']);
  assert.equal(w.store.activeRuns().length, 0, 'done at once: no clock was advanced');
  const newValue = await w.valueOf(keyref, 2);
  assert.deepEqual([await platformTakes(w, newValue), await platformTakes(w, oldValue)], ['ok', 'rejected']);
  assert.deepEqual(heldBy(w), [newValue, newValue]);
  assert.equal(genOf(w, keyref, 1)?.status, 'retired', 'confirmed dead by the verifier rejecting it');
});

test('KBOX-17 overlap:false rollback sets the old value back at the platform, which had stopped taking it, and in every destination', async (t) => {
  const { w, keyref, oldValue } = await seeded(t, { overlap: false });
  let oldTakenAfterPush: string | undefined;
  w.checkpoints.hook = async (point) => {
    if (point === 'pushing') oldTakenAfterPush = await platformTakes(w, oldValue);
  };
  w.destinations.redeployer.failNext();
  w.orch.start({ keyref, origin: 'owner' });
  await w.settle();
  assert.equal(oldTakenAfterPush, 'rejected', 'the platform really stopped taking the old value once the new one was set');
  assert.deepEqual(heldBy(w), [oldValue, oldValue]);
  assert.equal(await platformTakes(w, oldValue), 'ok', 'the platform takes the old value again');
  assert.equal(w.store.runs().at(-1)?.state, 'failed');
  assert.equal(genOf(w, keyref, 2)?.status, 'failed');
  assert.equal(genOf(w, keyref, 1)?.status, 'current');
});

test('KBOX-51 an overlap:false platform that cannot take a chosen value is refused at configuration with overlap_needs_set', () => {
  const caps = (set: 'api' | 'none') => ({ ...new FakePlatformWorld(seededRandom(3)).issuer.capabilities(), overlap: false, set });
  const sourceWith = (set: 'api' | 'none'): PlatformSource => ({
    platform: () => ({
      issuer: { platform: 'fake', capabilities: () => caps(set), issue: () => Promise.reject(new Error('unused')), revoke: () => Promise.resolve('absent' as const), ...(set === 'api' ? { set: () => Promise.resolve() } : {}) },
    }),
    destination: () => undefined,
    master: () => new FakePlatformWorld(seededRandom(3)).master(),
  });
  const action = { kind: 'add_key', platform: 'fake', name: 'DB_PASSWORD', projects: ['shop'], scope: { items: ['read'] } } as const;
  assert.throws(() => newKeyOf(action, sourceWith('none')), (e: unknown) => e instanceof ApiError && e.code === 'rejected' && JSON.stringify(e.detail) === JSON.stringify({ code: 'overlap_needs_set' }));
  assert.equal(newKeyOf(action, sourceWith('api')).keyref, 'fake/shop/DB_PASSWORD');
});

test('KBOX-51 a run on an overlap:false platform that cannot take a chosen value fails before any platform call', async (t) => {
  const { w, keyref } = await seeded(t, { overlap: false, settable: false });
  const before = await w.live();
  w.trace.length = 0;
  w.orch.start({ keyref, origin: 'owner' });
  await w.settle();
  const run = w.store.runs().at(-1);
  assert.deepEqual([run?.state, run?.reasonCode], ['failed', 'overlap_needs_set']);
  assert.deepEqual(w.trace, [], 'nothing was issued, set or pushed');
  assert.deepEqual(await w.live(), before, 'the platform still holds the one credential it held');
});

// --- three push outcomes (applied, refused, unknown) ---------------------------------------------------------------------------

const receiptStates = (w: RotationWorld): (string | boolean)[][] => w.store.receipts(w.store.runs().at(-1)?.runId ?? '').map((r) => [r.target, r.pushed]);

test('KBOX-17 a push the destination refused leaves a refused receipt that holds nothing: the rollback does not touch it and the new key is revoked', async (t) => {
  const { w, keyref, oldValue, oldId } = await seeded(t);
  w.destinations.a.refuse('app-b');
  w.trace.length = 0;
  w.orch.start({ keyref, origin: 'owner' });
  await w.settle();
  assert.deepEqual(receiptStates(w), [['app-a', true], ['app-b', 'refused']]);
  assert.deepEqual(w.trace.filter((x) => x.endsWith(':app-b')), [], 'nothing was pushed to or removed from app-b, in the run or in its rollback');
  assert.deepEqual(heldBy(w), [oldValue, oldValue]);
  assert.deepEqual(await w.live(), [oldId]);
  assert.equal(w.events('rotation.failed').length, 1);
});

test('KBOX-17 a push that timed out leaves a maybe receipt: the rollback puts the old value there, and only then is the new key revoked', async (t) => {
  const { w, keyref, oldValue, oldId } = await seeded(t);
  w.destinations.a.timeOut('app-b');
  w.trace.length = 0;
  w.orch.start({ keyref, origin: 'owner' });
  await w.settle();
  assert.deepEqual(receiptStates(w), [['app-a', true], ['app-b', 'maybe']]);
  assert.deepEqual(w.trace.filter((x) => x === 'push:app-b'), ['push:app-b'], 'the rollback pushed the old value to app-b');
  assert.deepEqual(heldBy(w), [oldValue, oldValue]);
  assert.deepEqual(await w.live(), [oldId]);
});

// --- a failed create run files a card for every class (no old generation) ------------------------------------------------------

for (const klass of ['ordinary', 'admin'] as const) {
  test(`KBOX-17 a failed create run (${klass} key) files exactly one rotation.failed card, and it says the old key does not work because there is none`, async (t) => {
    const w = await rotationWorld(t, { klass });
    w.destinations.a.refuse('app-b');
    await w.orch.create(w.newKey());
    const failed = w.events('rotation.failed');
    assert.equal(failed.length, 1);
    assert.deepEqual([failed[0]?.data['step'], failed[0]?.data['reason_code'], failed[0]?.data['old_key_works']], ['pushing', 'push_failed', false]);
    assert.equal(w.push.sent.filter((p) => p.kind === 'rotation_failed').length, klass === 'admin' ? 1 : 0, 'a Web Push for admin and master keys');
  });
}

// --- an overlap:false key is never created by a create run ---------------------------------------------------------------------

test('KBOX-51 a create run on an overlap:false platform is refused with overlap_needs_paste before any row or platform call; a key added by paste is then rotated', async (t) => {
  const w = await rotationWorld(t, { overlap: false });
  const key = w.newKey();
  await assert.rejects(
    () => w.orch.create(key),
    (e: unknown) => e instanceof ApiError && e.code === 'rejected' && JSON.stringify(e.detail) === JSON.stringify({ code: 'overlap_needs_paste' }),
  );
  assert.equal(w.store.key(key.keyref), undefined, 'no key row was written');
  assert.deepEqual(w.trace, [], 'the platform was not called');
  const keyref = await w.seedKey();
  assert.equal(w.store.key(keyref)?.status, 'works', 'added by paste');
  w.orch.start({ keyref, origin: 'owner' });
  await w.settle();
  assert.equal(genOf(w, keyref, 2)?.status, 'current', 'rotated by a run that sets a value the box chose');
});

// --- reconcile treats absence only from a complete listing --------------------------------------------------------------------

test('KBOX-51 reconcile restarts an issuing run whose intent key is not on the platform only on a complete listing: an incomplete one keeps the run open and retries', async (t) => {
  const { w, keyref, oldId } = await seeded(t);
  w.checkpoints.arm('issued');
  const first = w.orch.start({ keyref, origin: 'owner' });
  await w.orch.idle();
  const strayId = (await w.live()).find((id) => id !== oldId) ?? '';
  await w.platform.issuer.revoke(strayId, w.platform.master());
  w.checkpoints.crashAt = undefined;
  w.build();
  w.faults.listingIncomplete = true;
  await w.reconciler.run();
  assert.equal(w.store.run(first.runId)?.state, 'issuing', 'one page of several proves nothing: the run stays open');
  assert.equal(w.store.runs().filter((r) => r.keyref === keyref).length, 2, 'no second run was opened');
  w.faults.listingIncomplete = false;
  await w.reconciler.run();
  assert.equal(w.store.run(first.runId)?.state, 'abandoned', 'a complete listing without the intent key lets the run go again');
});

test('KBOX-51 an orphan that reconcile cannot confirm gone from a complete listing keeps its run open: nothing restarts while the platform may still hold the key', async (t) => {
  const { w, keyref } = await seeded(t);
  w.checkpoints.arm('issued');
  const first = w.orch.start({ keyref, origin: 'owner' });
  await w.orch.idle();
  w.checkpoints.crashAt = undefined;
  w.build();
  w.faults.listingIncomplete = true;
  await w.reconciler.run();
  assert.equal(w.store.run(first.runId)?.state, 'issuing', 'the revoke could not be confirmed from one page of several');
  assert.equal(w.store.runs().filter((r) => r.keyref === keyref).length, 2, 'no second run');
  w.faults.listingIncomplete = false;
  await w.reconciler.run();
  assert.equal(w.store.run(first.runId)?.state, 'abandoned');
  assert.equal(w.parts.audit.read(0).entries.filter((e) => e.action === 'rotation.restarted').length, 1);
  await w.settle();
  assert.deepEqual(await w.live(), [genOf(w, keyref, 2)?.platformKeyId], 'the orphan is gone and the new run made the one key');
});

test('KBOX-51 stopping the orchestrator cancels the timer of a run waiting out its grace: the process can end, and the run does not go on after the stop', async (t) => {
  const { w, keyref } = await seeded(t);
  assert.equal(w.clock.pendingTimers, 0);
  w.orch.start({ keyref, origin: 'owner' });
  await w.orch.idle();
  assert.ok(w.clock.pendingTimers > 0, 'the grace wait holds a timer');
  w.orch.stop();
  assert.equal(w.clock.pendingTimers, 0, 'no timer is left');
  w.clock.advance(25 * HOUR);
  await w.orch.idle();
  assert.equal(genOf(w, keyref, 1)?.status, 'grace', 'the stopped orchestrator revoked nothing');
  assert.equal(w.clock.pendingTimers, 0, 'and set no new timer');
});

// --- a master the box cannot choose is refused, once per run (review N5) ---------------------------------------------------------

test('KBOX-17 KBOX-51 a run whose platform master is ambiguous files exactly one card naming master_ambiguous, keeps the old key, and retries without another card', async (t) => {
  const { w, keyref, oldValue, oldId } = await seeded(t);
  w.faults.masterAmbiguous = true;
  w.orch.start({ keyref, origin: 'owner' });
  await w.orch.idle();
  w.clock.advance(3 * HOUR);
  await w.orch.idle();
  const failed = w.events('rotation.failed');
  assert.deepEqual(failed.map((e) => [e.data['step'], e.data['reason_code'], e.data['old_key_works']]), [['issuing', 'master_ambiguous', true]], 'one card, retries included');
  w.faults.masterAmbiguous = false;
  await w.settle(HOUR);
  assert.equal(w.store.runs().at(-1)?.state, 'failed');
  assert.deepEqual(heldBy(w), [oldValue, oldValue]);
  assert.deepEqual(await w.live(), [oldId], 'nothing was issued without a master');
  assert.equal(w.events('rotation.failed').length, 1);
});

// --- an overlap:false run needs a current generation to set back (review N6) -----------------------------------------------------

test('KBOX-17 KBOX-51 an overlap:false key with no current generation (its paste create failed) is refused a run with no_current_generation: no row, nothing set at the platform', async (t) => {
  const w = await rotationWorld(t, { overlap: false });
  w.destinations.a.refuse('app-b');
  const keyref = await w.seedKey();
  assert.equal(w.store.gens(keyref).some((g) => g.status === 'current'), false, 'the create failed: no generation is current');
  const runs = w.store.runs().length;
  w.trace.length = 0;
  assert.throws(
    () => w.orch.start({ keyref, origin: 'owner' }),
    (e: unknown) => e instanceof ApiError && e.code === 'rejected' && JSON.stringify(e.detail) === JSON.stringify({ code: 'no_current_generation' }),
  );
  await w.orch.idle();
  assert.equal(w.store.runs().length, runs, 'no run was opened');
  assert.deepEqual(w.trace, [], 'the platform was not asked to take a value');
});

// --- old_key_works states the fact at notice time (review N7, spec rotation.failed) -----------------------------------------------

const cards = (w: RotationWorld): unknown[][] => w.events('rotation.failed').map((e) => [e.data['step'], e.data['reason_code'], e.data['old_key_works']]);

test('KBOX-17 overlap:false: while the platform does not take the old value back, every card says old_key_works false; once it does, the run ends with the old key working', async (t) => {
  const { w, keyref, oldValue } = await seeded(t, { overlap: false, klass: 'admin' });
  w.checkpoints.hook = (point) => {
    if (point === 'issuing') w.platform.setReachable(false);
    return Promise.resolve();
  };
  w.orch.start({ keyref, origin: 'owner' });
  await w.orch.idle();
  w.checkpoints.hook = undefined;
  assert.deepEqual(cards(w), [
    ['verifying', 'verify_unreachable', false],
    ['rollback_platform_set', 'repush_refused', false],
  ]);
  assert.equal(w.push.sent.some((p) => /old key still works/i.test(p.title)), false, 'no push claims the old key works');
  w.platform.setReachable(true);
  w.clock.advance(MINUTE);
  await w.orch.idle();
  assert.equal(await platformTakes(w, oldValue), 'ok');
  assert.equal(w.store.runs().at(-1)?.state, 'failed');
  assert.equal(cards(w).length, 2, 'the retry files no further card');
});

test('KBOX-17 overlap:false: a destination that refuses the re-push after the platform took the old value back gets its card with old_key_works true', async (t) => {
  const { w, keyref } = await seeded(t, { overlap: false });
  w.destinations.a.refuse('app-b');
  w.destinations.a.refuseAfter('app-a', 1);
  w.orch.start({ keyref, origin: 'owner' });
  await w.orch.idle();
  assert.deepEqual(cards(w), [
    ['pushing', 'push_failed', false],
    ['rollback_vercel_env', 'repush_refused', true],
  ], 'the first card went out before the platform took the old value back; the second after');
});

// --- a run reconcile cannot settle files one card, once (review N8) ---------------------------------------------------------------

/** An `issuing` run left by a crash between issue and store, whose stray key was removed: only a listing can settle it. */
async function unsettled(t: TestContext): Promise<{ w: RotationWorld; keyref: string; runId: string }> {
  const { w, keyref, oldId } = await seeded(t);
  w.checkpoints.arm('issued');
  const first = w.orch.start({ keyref, origin: 'owner' });
  await w.orch.idle();
  await w.platform.issuer.revoke((await w.live()).find((id) => id !== oldId) ?? '', w.platform.master());
  w.checkpoints.crashAt = undefined;
  w.build();
  return { w, keyref, runId: first.runId };
}

for (const [why, plant] of [
  ['an incomplete listing', (w: RotationWorld) => void (w.faults.listingIncomplete = true)],
  ['a listing that never matches the recorded region', (w: RotationWorld) => void (w.faults.listerAt = { region: 'us' })],
] as const) {
  test(`KBOX-51 KBOX-17 a run that reconcile cannot settle (${why}) files exactly one card the first time, with reconcile_unsettled, and never again`, async (t) => {
    const { w, runId } = await unsettled(t);
    plant(w);
    await w.reconciler.run();
    assert.equal(w.store.run(runId)?.state, 'issuing', 'nothing is restarted while the platform may hold the key');
    assert.deepEqual(cards(w), [['issuing', 'reconcile_unsettled', true]]);
    await w.reconciler.run();
    await w.reconciler.run();
    assert.equal(cards(w).length, 1, 'later reconciles file no second card');
  });
}

test('KBOX-51 a run that reconcile settles at once files no card', async (t) => {
  const { w, runId } = await unsettled(t);
  await w.reconciler.run();
  assert.equal(w.store.run(runId)?.state, 'abandoned');
  assert.deepEqual(cards(w), []);
});

// ---------------------------------------------------------------- S2 ports: the class goes to every push, the master to every ready

for (const klass of ['ordinary', 'admin', 'master'] as const) {
  test(`KBOX-36 the rotation of a ${klass} key hands its class to every push, forward and in a rollback re-push`, async (t) => {
    const { w, keyref } = await seeded(t, { klass, overlap: false });
    w.destinations.redeployer.failNext();
    w.orch.start({ keyref, origin: 'owner' });
    await w.settle();
    const pushed = w.destinations.a.pushed();
    assert.ok(pushed.length > TARGETS.length, 'the two forward pushes and at least one re-push of the old value in the rollback');
    assert.deepEqual([...new Set(pushed.map((p) => p.klass))], [klass]);
  });
}

test('KBOX-4 KBOX-51 the rotation hands the master to every ready, forward and in a rollback redeploy, so a fresh redeployer can resume', async (t) => {
  const { w, keyref } = await seeded(t, { overlap: false });
  w.destinations.redeployer.failNext();
  w.orch.start({ keyref, origin: 'owner' });
  await w.settle();
  const masters = w.destinations.redeployer.readyMasters();
  assert.ok(masters.length >= 2, `ready was called ${masters.length} times`);
  const expected = Buffer.from(await bytesOf(w.platform.master())).toString('utf8');
  for (const m of masters) assert.equal(Buffer.from(await bytesOf(m)).toString('utf8'), expected);
});

// --- placement (KBOX-57) -----------------------------------------------------------------------------------------------------------

const rowsOfKey = (w: RotationWorld, keyref: string): string =>
  JSON.stringify([w.parts.db.prepare('SELECT * FROM keys WHERE keyref = ?').all(keyref), w.parts.db.prepare('SELECT * FROM rotation_keys WHERE keyref = ?').all(keyref)]);

test('KBOX-57 the issuer is handed the key\'s stored location, and the verifier the generation\'s, on a create and on every rotation', async (t) => {
  const { w, keyref } = await seeded(t);
  w.orch.start({ keyref, origin: 'owner' });
  await w.settle();
  assert.deepEqual(w.seenAt.issue, [{ region: 'eu' }, { region: 'eu' }]);
  assert.ok(w.seenAt.verify.length >= 3);
  assert.ok(w.seenAt.verify.every((at) => at.region === 'eu' && at.project === undefined), JSON.stringify(w.seenAt.verify));
});

for (const [name, answer] of [
  ['another region', { region: 'us' }],
  ['the stored region and a project the stored location lacks', { region: 'eu', project: 'p1' }],
  ['no region where the stored location names one', {}],
] as const) {
  test(`KBOX-57 KBOX-17 an issuer answering ${name} fails the run at step 3 with location_mismatch: the new key is revoked, one notice, nothing stored`, async (t) => {
    const { w, keyref, oldValue } = await seeded(t);
    w.faults.answerAt = answer;
    w.orch.start({ keyref, origin: 'owner' });
    await w.settle();
    const run = w.store.runs().at(-1);
    assert.deepEqual([run?.state, run?.failedStep, run?.reasonCode], ['failed', 'issuing', 'location_mismatch']);
    assert.equal((await w.live()).length, 1, 'only the old key is live: the misplaced one was revoked');
    assert.equal(genOf(w, keyref, 2), undefined, 'the misplaced key was never stored as a generation');
    assert.equal(w.events('rotation.failed').length, 1);
    assert.deepEqual(heldBy(w), [oldValue, oldValue]);
  });
}

test('KBOX-57 a misplaced new key is confirmed dead at the location the platform answered, not the stored one', async (t) => {
  const { w, keyref } = await seeded(t, { verifier: false });
  w.faults.answerAt = { region: 'us' };
  w.faults.revoke404 = true;
  w.seenAt.listAt.length = 0;
  w.orch.start({ keyref, origin: 'owner' });
  await w.orch.idle();
  assert.equal(w.store.activeRunOf(keyref)?.state, 'rolling_back', 'a listing of the answered region still shows it: not dead');
  assert.deepEqual(w.seenAt.listAt, [{ region: 'us' }]);
  // As for a key that could not be stored: the retry has no platform key id of its own, and the misplaced key is reconcile's orphan, found
  // by its intent name and confirmed dead at the location the listing gives it.
  w.faults.revoke404 = false;
  await w.settle();
  await w.reconciler.run();
  assert.equal((await w.live()).length, 1, 'only the old key is live');
  assert.deepEqual(w.seenAt.listAt.filter((at) => at.region !== 'us'), [], 'no listing of the stored region was taken for proof');
});

test('KBOX-57 an answer naming the stored location is no mismatch, and an answer naming no place is no claim: both runs complete', async (t) => {
  const { w, keyref } = await seeded(t);
  w.faults.answerAt = { region: 'eu' };
  w.orch.start({ keyref, origin: 'owner' });
  await w.settle();
  assert.equal(w.store.runs().at(-1)?.state, 'done');
  assert.deepEqual(genOf(w, keyref, 2)?.location, { region: 'eu' });
  w.faults.answerAt = undefined;
  w.orch.start({ keyref, origin: 'owner' });
  await w.settle();
  assert.equal(w.store.runs().at(-1)?.state, 'done');
  assert.deepEqual(genOf(w, keyref, 3)?.location, { region: 'eu' }, 'no place in the answer: the stored one is recorded');
});

test('KBOX-57 putKeyInfo refuses another location for a stored key with location_immutable and changes nothing; the same location is kept', async (t) => {
  const { w, keyref } = await seeded(t);
  const before = rowsOfKey(w, keyref);
  const info = w.store.keyInfo(keyref);
  assert.ok(info);
  for (const location of [{ region: 'us' }, {}, { region: 'eu', project: 'p1' }]) {
    assert.throws(() => w.store.putKeyInfo(keyref, { ...info, location, rotatedAt: info.rotatedAt + 1 }), (e: unknown) => e instanceof ApiError && JSON.stringify(e.detail) === JSON.stringify({ code: 'location_immutable' }), JSON.stringify(location));
  }
  assert.equal(rowsOfKey(w, keyref), before);
  w.store.putKeyInfo(keyref, { ...info, rotatedAt: info.rotatedAt + 1 });
  assert.equal(w.store.keyInfo(keyref)?.rotatedAt, info.rotatedAt + 1);
});

test('KBOX-57 create refuses a keyref that exists with key_exists before its first write: no run, no issue', async (t) => {
  const { w, keyref } = await seeded(t);
  const before = rowsOfKey(w, keyref);
  const issued = w.seenAt.issue.length;
  await assert.rejects(() => w.orch.create(w.newKey({ location: { region: 'us' }, class: 'ordinary' })), (e: unknown) => e instanceof ApiError && e.code === 'conflict' && JSON.stringify(e.detail) === JSON.stringify({ code: 'key_exists' }));
  assert.equal(rowsOfKey(w, keyref), before);
  assert.equal(w.store.runs().length, 1, 'only the seed run');
  assert.equal(w.seenAt.issue.length, issued);
});

test('KBOX-57 a run is refused before it starts when the stored location fails the entry\'s current declaration, with the check\'s code', async (t) => {
  // The entry now requires a project of ordinary keys; the key was stored without one.
  const strict = { region: { pattern: /[a-z]{2,16}/, requiredFor: [] }, project: { pattern: /p[0-9]/, requiredFor: ['ordinary' as const] } };
  const w = await rotationWorld(t, { source: (real) => ({ ...real, platform: (id) => ({ ...real.platform(id), location: strict }) }) });
  const keyref = 'fake/shop/OLD';
  w.parts.meta.putKey({ keyref, platform: 'fake', name: 'OLD', projects: ['shop'], class: 'ordinary', status: 'works', gen_current: 1, schedule: { rotate_every_days: 90, grace_hours: 1, next_due_at: null, expires_at: null }, coverage: null, last_use_at: null });
  w.store.putKeyInfo(keyref, { scopeItems: ['read'], location: { region: 'eu' }, rotatedAt: 1, markAdmin: false });
  for (const value of [undefined, Buffer.from('fk-pasted')]) {
    assert.throws(
      () => w.orch.start({ keyref, origin: 'owner', ...(value === undefined ? {} : { value }) }),
      (e: unknown) => e instanceof ApiError && e.code === 'rejected' && JSON.stringify(e.detail) === JSON.stringify({ code: 'location_missing' }),
    );
  }
  assert.equal(w.store.runs().length, 0);
  assert.deepEqual(w.seenAt.issue, []);
});
