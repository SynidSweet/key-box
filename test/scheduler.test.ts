// KBOX-52: when a key is due. A schedule, never a cap: at most one admin or master rotation falls due per day, and no due date is
// ever later than the unstaggered one.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { checkProperty, seedFor } from './kit/index.ts';
import { PASTE_PLATFORM, pasteValue, routesWorld } from './support/routes-world.ts';
import type { RoutesWorld } from './support/routes-world.ts';
import type { SeededRandom } from './kit/index.ts';
import type { KeyClass } from '../src/ports/types.ts';
import { dueDates, unstaggeredDue } from '../src/pure/scheduler.ts';
import type { SchedKey } from '../src/pure/scheduler.ts';

const DAY = 24 * 3600_000;
const HOUR = 3600_000;
const key = (keyref: string, klass: KeyClass, over: Partial<SchedKey> = {}): SchedKey => ({
  keyref,
  class: klass,
  rotateEveryDays: 90,
  graceHours: 24,
  lastRotatedAt: 0,
  expiresAt: null,
  manual: false,
  ...over,
});

test('KBOX-52 the unstaggered due date is the schedule: the last rotation plus rotateEvery', () => {
  assert.equal(unstaggeredDue(key('k', 'ordinary', { lastRotatedAt: 5 * DAY, rotateEveryDays: 30 })), 35 * DAY);
});

test('KBOX-52 an expiry earlier than the schedule wins: due at expiresAt minus grace minus one day', () => {
  const k = key('k', 'ordinary', { expiresAt: 40 * DAY, graceHours: 24, rotateEveryDays: 90 });
  assert.equal(unstaggeredDue(k), 40 * DAY - 24 * HOUR - DAY);
});

test('KBOX-52 an expiry later than the schedule changes nothing', () => {
  assert.equal(unstaggeredDue(key('k', 'ordinary', { expiresAt: 900 * DAY })), 90 * DAY);
});

test('KBOX-52 two admin keys due the same day: one moves a day earlier, an ordinary key is never moved', () => {
  const due = dueDates([key('a', 'admin'), key('b', 'admin'), key('c', 'ordinary'), key('d', 'master')]);
  const days = ['a', 'b', 'd'].map((r) => Math.floor((due.get(r) ?? Number.NaN) / DAY));
  assert.equal(new Set(days).size, 3);
  assert.equal(due.get('c'), 90 * DAY);
  for (const r of ['a', 'b', 'd']) assert.ok((due.get(r) ?? Infinity) <= 90 * DAY);
});

test('KBOX-52 a manual rotation is never delayed: it is due at once, whatever the schedule', () => {
  const due = dueDates([key('a', 'admin', { manual: true }), key('b', 'admin')], 10 * DAY);
  assert.equal(due.get('a'), 10 * DAY);
  assert.equal(due.get('b'), 90 * DAY);
});

test('KBOX-52 property: at most one admin or master rotation per day, every due date no later than the unstaggered one', () => {
  const seed = seedFor(process.env);
  checkProperty(seed, 200, (rng: SeededRandom) => {
    const keys: SchedKey[] = Array.from({ length: 1 + rng.int(12) }, (_, i) =>
      key(`k${i}`, (['ordinary', 'admin', 'master'] as const)[rng.int(3)] ?? 'ordinary', {
        lastRotatedAt: rng.int(60) * DAY + rng.int(DAY),
        rotateEveryDays: 1 + rng.int(120),
        graceHours: rng.int(72),
        expiresAt: rng.int(2) === 0 ? null : rng.int(200) * DAY,
      }),
    );
    const due = dueDates(keys);
    const privileged = new Set<number>();
    for (const k of keys) {
      const d = due.get(k.keyref);
      assert.ok(d !== undefined && d <= unstaggeredDue(k), `${k.keyref} is due no later than unstaggered`);
      if (k.class === 'ordinary') continue;
      const day = Math.floor(d / DAY);
      assert.ok(!privileged.has(day), `two privileged keys due on day ${day}`);
      privileged.add(day);
    }
  });
});

// --- the tick: what opens when a key is due ---------------------------------------------------------------------------------

const KEYREF = 'fake/shop/OPENAI_KEY';
const addAdminKey = async (w: RoutesWorld, platform = 'fake'): Promise<void> => {
  if (platform === 'fake') {
    const execute = w.rotation.executors.add_key;
    assert.ok(execute);
    await execute({ approvalId: 'apr_x', revision: 1, action: { kind: 'add_key', platform, name: 'OPENAI_KEY', projects: ['shop'], scope: { items: ['admin'] } }, requester: { kind: 'box' }, proof: undefined });
    return;
  }
  const opened = await w.api('/api/keys', { json: { platform, name: 'OPENAI_KEY', projects: ['shop'], scope: { items: ['admin'] } } });
  const task = (opened.json() as { paste_task_id: string }).paste_task_id;
  const cookie = await w.view();
  const view = (await w.call(`/p/${task}`, { cookie })).json() as { paste_id: string; digest_b64: string; nonce_b64: string };
  const value = pasteValue('3'.repeat(32));
  w.accepted.add(value);
  const stored = await w.call(`/p/${task}`, { cookie, json: { value, proof: w.pasteProof(view) } });
  assert.equal(stored.status, 201, stored.body);
};
const rotatePushes = (w: RoutesWorld) => w.push.sent.filter((p) => p.kind === 'rotate_key');

test('KBOX-52 an ordinary key that is due starts a run of its own at the tick, and one that is not yet due does not', async (t) => {
  const w = await routesWorld(t);
  await w.api('/api/keys', { json: { platform: 'fake', name: 'OPENAI_KEY', projects: ['shop'], scope: { items: ['read'] }, rotate_every_days: 30 } });
  w.clock.advance(30 * DAY - 1);
  w.rotation.tick();
  assert.equal(w.rotation.store.activeRunOf(KEYREF), undefined);
  w.clock.advance(1);
  w.rotation.tick();
  assert.equal(w.rotation.store.activeRunOf(KEYREF)?.origin, 'schedule');
  await w.rotation.orchestrator.idle();
});

test('KBOX-52 a due admin key opens exactly one approval, with the old key still working, and a second tick opens none', async (t) => {
  const w = await routesWorld(t);
  await addAdminKey(w);
  w.clock.advance(91 * DAY);
  w.rotation.tick();
  const first = await w.queue();
  assert.deepEqual(first.map((q) => [q.kind, q.revision]), [['rotate_key', 1]]);
  assert.equal(rotatePushes(w).length, 1);
  assert.equal(w.rotation.store.activeRunOf(KEYREF), undefined, 'nothing runs before the phone approves');
  assert.equal(w.parts.meta.snapshot().keys.find((k) => k.keyref === KEYREF)?.status, 'awaiting_approval');
  w.rotation.tick();
  w.rotation.tick();
  assert.deepEqual((await w.queue()).map((q) => [q.kind, q.revision]), [['rotate_key', 1]], 'no second approval and no new revision that would void the assertion');
  assert.equal(rotatePushes(w).length, 1);
  assert.equal((await w.platform.lister.list(w.platform.master())).length, 1, 'the old key keeps working while it waits');
});

test('KBOX-52 a due admin key on a paste-source platform opens exactly one paste task, and a second tick opens none', async (t) => {
  const w = await routesWorld(t);
  await addAdminKey(w, PASTE_PLATFORM);
  w.clock.advance(91 * DAY);
  w.rotation.tick();
  w.rotation.tick();
  const listed = await w.call('/app/pastes', { cookie: await w.view() });
  assert.equal((listed.json() as { pastes: unknown[] }).pastes.length, 1);
  assert.equal(w.parts.meta.snapshot().keys.find((k) => k.keyref === `${PASTE_PLATFORM}/shop/OPENAI_KEY`)?.status, 'awaiting_paste');
});

test('KBOX-52 a denied or expired approval puts the key back to works at the next tick, and a failed run is not tried again for a day', async (t) => {
  const w = await routesWorld(t);
  await addAdminKey(w);
  w.clock.advance(91 * DAY);
  w.rotation.tick();
  const expiring = w.parts.meta.snapshot().approvals.map((a) => a.approval_id);
  w.clock.advance(15 * DAY);
  w.rotation.tick();
  const reopened = w.parts.meta.snapshot().approvals.map((a) => a.approval_id);
  assert.equal(reopened.length, 1, 'the box opens a new approval after the old one expired');
  assert.notDeepEqual(reopened, expiring);
  const ordinary = await routesWorld(t);
  await ordinary.api('/api/keys', { json: { platform: 'fake', name: 'OPENAI_KEY', projects: ['shop'], scope: { items: ['read'] }, destinations: [{ kind: 'vercel_env', target: 'app-a' }], rotate_every_days: 1 } });
  ordinary.destination.refuse('app-a');
  ordinary.clock.advance(DAY);
  ordinary.rotation.tick();
  await ordinary.rotation.orchestrator.idle();
  assert.equal(ordinary.parts.events.after(0).filter((e) => e.kind === 'rotation.failed').length, 1);
  ordinary.clock.advance(23 * 3600_000);
  ordinary.rotation.tick();
  await ordinary.rotation.orchestrator.idle();
  assert.equal(ordinary.parts.events.after(0).filter((e) => e.kind === 'rotation.failed').length, 1, 'no second try within a day');
  ordinary.clock.advance(3600_000);
  ordinary.rotation.tick();
  await ordinary.rotation.orchestrator.idle();
  assert.equal(ordinary.parts.events.after(0).filter((e) => e.kind === 'rotation.failed').length, 2, 'tried again after a day');
});

test('KBOX-52 after a failed run the next run starts no sooner than 24 hours after the failure itself, not 24 hours after the run opened', async (t) => {
  let stopAt: string | undefined;
  const w = await routesWorld(t, {
    checkpoint: (point) => {
      if (point !== stopAt) return;
      stopAt = undefined;
      throw new Error('the process stopped here');
    },
  });
  await w.api('/api/keys', { json: { platform: 'fake', name: 'OPENAI_KEY', projects: ['shop'], scope: { items: ['read'] }, destinations: [{ kind: 'vercel_env', target: 'app-a' }], rotate_every_days: 1 } });
  stopAt = 'verifying';
  w.clock.advance(DAY);
  w.rotation.tick();
  await w.rotation.orchestrator.idle();
  assert.equal(w.rotation.store.activeRunOf(KEYREF)?.state, 'pushing', 'the run stopped after its verify step');
  w.clock.advance(20 * HOUR);
  w.destination.applyThenThrow('app-a');
  await w.rotation.orchestrator.resume();
  const failed = (): number => w.parts.events.after(0).filter((e) => e.kind === 'rotation.failed').length;
  assert.equal(failed(), 1, 'the run failed 20 hours after it opened');
  assert.equal(w.rotation.store.activeRunOf(KEYREF), undefined);
  const runs = (): number => w.rotation.store.runs().length;
  const before = runs();
  w.clock.advance(24 * HOUR - 1);
  w.rotation.tick();
  await w.rotation.orchestrator.idle();
  assert.equal(runs(), before, 'one millisecond short of 24 hours after the failure: nothing starts');
  w.clock.advance(1);
  w.rotation.tick();
  await w.rotation.orchestrator.idle();
  assert.equal(runs(), before + 1, '24 hours after the failure the key goes again');
});

test('KBOX-34 KBOX-52 an ordinary key on a paste-source platform is never run as an api run: a due tick opens nothing and files no failure, and a rotation request is rejected', async (t) => {
  const w = await routesWorld(t);
  const keyref = `${PASTE_PLATFORM}/shop/PLAIN_KEY`;
  const value = pasteValue('4'.repeat(32));
  w.accepted.add(value);
  const made = await w.rotation.orchestrator.create(
    { keyref, platform: PASTE_PLATFORM, name: 'PLAIN_KEY', projects: ['shop'], scopeItems: ['read'], class: 'ordinary', destinations: [], rotateEveryDays: 1, graceHours: 1, location: {}, markAdmin: false },
    Uint8Array.from(Buffer.from(value)),
  );
  assert.equal(made.status, 'works');
  w.clock.advance(2 * DAY);
  w.rotation.tick();
  await w.rotation.orchestrator.idle();
  assert.deepEqual(w.rotation.store.runs().map((r) => r.origin), ['create'], 'the tick started no run');
  assert.equal(w.parts.events.after(0).filter((e) => e.kind === 'rotation.failed').length, 0);
  const asked = await w.api('/api/rotations', { json: { keyref } });
  assert.deepEqual([asked.status, (asked.json() as { error?: { detail?: { code?: string } } }).error?.detail?.code], [422, 'no_issuer']);
  assert.deepEqual(w.rotation.store.runs().map((r) => r.origin), ['create']);
});

test('KBOX-52 KBOX-51 run() ticks at start and every hour after, resumes a run waiting out its grace, and its stop cancels the tick, the reconcile and the grace timer', async (t) => {
  const w = await routesWorld(t);
  await w.api('/api/keys', { json: { platform: 'fake', name: 'OPENAI_KEY', projects: ['shop'], scope: { items: ['read'] }, rotate_every_days: 30 } });
  assert.equal(w.clock.pendingTimers, 0);
  const stop = await w.rotation.run();
  assert.equal(w.rotation.store.activeRunOf(KEYREF), undefined, 'not due at start');
  w.clock.advance(30 * DAY);
  assert.equal(w.rotation.store.activeRunOf(KEYREF)?.origin, 'schedule', 'the hourly tick found the key due');
  await w.rotation.orchestrator.idle();
  assert.equal(w.rotation.store.activeRunOf(KEYREF)?.state, 'grace');
  assert.ok(w.clock.pendingTimers >= 3, 'the tick, the reconcile and the grace wait each hold a timer');
  stop();
  assert.equal(w.clock.pendingTimers, 0, 'nothing is left to keep the process alive');
  w.clock.advance(2 * DAY);
  await w.rotation.orchestrator.idle();
  assert.equal(w.rotation.store.activeRunOf(KEYREF)?.state, 'grace', 'a stopped rotation does no more');
});

// --- a failed tick never stops the schedule or reaches the timer (review N2) -------------------------------------------------------

/** The audit rows that say a part of the schedule failed and the loop went on: the subject and the fixed code. */
const scheduleFaults = (w: RoutesWorld): string[][] =>
  w.parts.audit
    .read(0)
    .entries.filter((e) => e.action === 'rotation.drive_failed')
    .map((e) => [e.ref, String(e.detail['code'])]);

const failingOnce = (): { arm(): void; fire(): void } => {
  let armed = false;
  return {
    arm: () => void (armed = true),
    fire: () => {
      if (!armed) return;
      armed = false;
      throw new Error('database is locked');
    },
  };
};

test('KBOX-52 a sweep that throws at an hourly tick is audited and the schedule goes on: later ticks run and a due key still opens its run', async (t) => {
  const sweep = failingOnce();
  let sweeps = 0;
  const w = await routesWorld(t, {
    approvals: (real) => ({
      propose: (input) => real.propose(input),
      sweep: () => {
        sweep.fire();
        sweeps += 1;
        return real.sweep();
      },
    }),
  });
  await w.api('/api/keys', { json: { platform: 'fake', name: 'OPENAI_KEY', projects: ['shop'], scope: { items: ['read'] }, rotate_every_days: 30 } });
  const stop = w.rotation.run();
  t.after(stop);
  await w.rotation.idle();
  sweep.arm();
  w.clock.advance(HOUR);
  const after = sweeps;
  w.clock.advance(30 * DAY);
  assert.ok(sweeps > after, 'the ticks after the failed one swept again');
  assert.equal(w.rotation.store.activeRunOf(KEYREF)?.origin, 'schedule', 'the due key opened its run');
  assert.deepEqual(scheduleFaults(w), [['tick', 'tick_failed']]);
  await w.rotation.orchestrator.idle();
});

test('KBOX-52 a sweep that throws at the start-up tick does not stop the start: the hourly tick is armed and a due key opens its run', async (t) => {
  const sweep = failingOnce();
  const w = await routesWorld(t, { approvals: (real) => ({ propose: (input) => real.propose(input), sweep: () => (sweep.fire(), real.sweep()) }) });
  await w.api('/api/keys', { json: { platform: 'fake', name: 'OPENAI_KEY', projects: ['shop'], scope: { items: ['read'] }, rotate_every_days: 30 } });
  sweep.arm();
  const stop = w.rotation.run();
  t.after(stop);
  await w.rotation.idle();
  assert.deepEqual(scheduleFaults(w), [['tick', 'tick_failed']], 'the start-up tick failed, audited');
  w.clock.advance(30 * DAY);
  assert.equal(w.rotation.store.activeRunOf(KEYREF)?.origin, 'schedule');
  await w.rotation.orchestrator.idle();
});

test('KBOX-51 a reconcile that throws at start does not stop the start: it is audited and the start-up tick still runs', async (t) => {
  const lookup = failingOnce();
  const w = await routesWorld(t, { source: (real) => ({ ...real, platform: (id) => (lookup.fire(), real.platform(id)) }) });
  await w.api('/api/keys', { json: { platform: 'fake', name: 'OPENAI_KEY', projects: ['shop'], scope: { items: ['read'] }, rotate_every_days: 30 } });
  w.clock.advance(30 * DAY);
  lookup.arm();
  const stop = w.rotation.run();
  t.after(stop);
  await w.rotation.idle();
  assert.deepEqual(scheduleFaults(w), [['reconcile', 'reconcile_failed']]);
  assert.equal(w.rotation.store.activeRunOf(KEYREF)?.origin, 'schedule', 'the start-up tick found the key due');
  await w.rotation.orchestrator.idle();
});

test('KBOX-52 the tick is guarded per key: an approval that cannot be proposed for one due key is audited with its key, and the other due key still opens its run', async (t) => {
  const w = await routesWorld(t, {
    approvals: (real) => ({
      propose: (input) => {
        if (input.action.kind === 'rotate_key') throw new Error('database is locked');
        return real.propose(input);
      },
      sweep: () => real.sweep(),
    }),
  });
  const execute = w.rotation.executors.add_key;
  assert.ok(execute);
  await execute({ approvalId: 'apr_x', revision: 1, action: { kind: 'add_key', platform: 'fake', name: 'ADMIN_KEY', projects: ['shop'], scope: { items: ['admin'] } }, requester: { kind: 'box' }, proof: undefined });
  await w.api('/api/keys', { json: { platform: 'fake', name: 'OPENAI_KEY', projects: ['shop'], scope: { items: ['read'] }, rotate_every_days: 30 } });
  w.clock.advance(91 * DAY);
  w.rotation.tick();
  assert.deepEqual(scheduleFaults(w), [['fake/shop/ADMIN_KEY', 'tick_failed']], 'the key that failed, named, with a fixed code');
  assert.equal(w.rotation.store.activeRunOf(KEYREF)?.origin, 'schedule', 'the key after it in the tick still opened its run');
  await w.rotation.orchestrator.idle();
});

// --- a refused or expired scheduled request is waited out (KBOX-52 revision 2026-11-12) -----------------------------------------

const REFUSAL_WAIT = 7 * DAY;
const EXPIRY_WAIT = DAY;
/** How many rotation requests (approvals, or paste tasks) the box has ever opened, whatever became of them. */
const countOf = (w: RoutesWorld, table: 'approvals' | 'paste_tasks'): number =>
  (w.parts.db.prepare(table === 'approvals' ? "SELECT count(*) AS n FROM approvals WHERE kind = 'rotate_key'" : "SELECT count(*) AS n FROM paste_tasks WHERE json_extract(action_json, '$.kind') = 'rotate_key'").get() as { n: number }).n;
/** Ticks every hour for `span` milliseconds (a multiple of an hour), the way the schedule does. */
const hourlyTicks = (w: RoutesWorld, span: number): void => {
  for (let spent = 0; spent < span; spent += HOUR) {
    w.clock.advance(HOUR);
    w.rotation.tick();
  }
};
const denyTheRequest = async (w: RoutesWorld): Promise<void> => {
  const [item] = await w.queue();
  assert.ok(item);
  assert.equal((await w.decide(item.approval_id, 'deny', w.proofFor(item, undefined, undefined, 'deny'))).status, 200);
};

test('KBOX-52 a due admin key whose approval is refused gets no new approval from any tick for 7 days and exactly one at the first tick after', async (t) => {
  const w = await routesWorld(t);
  await addAdminKey(w);
  w.clock.advance(91 * DAY);
  w.rotation.tick();
  await denyTheRequest(w);
  assert.equal(countOf(w, 'approvals'), 1);
  hourlyTicks(w, REFUSAL_WAIT - HOUR);
  w.clock.advance(HOUR - 1);
  w.rotation.tick();
  assert.equal(countOf(w, 'approvals'), 1, 'one millisecond short of 7 days after the refusal: no new approval');
  w.clock.advance(1);
  w.rotation.tick();
  assert.equal(countOf(w, 'approvals'), 2, 'the first tick 7 days after the refusal asks again');
  w.rotation.tick();
  assert.equal(countOf(w, 'approvals'), 2, 'and only once');
});

test('KBOX-52 a due admin key whose approval expires unanswered gets none for 24 hours after the expiry and exactly one at the first tick after', async (t) => {
  const w = await routesWorld(t);
  await addAdminKey(w);
  w.clock.advance(91 * DAY);
  w.rotation.tick();
  w.clock.advance(15 * DAY);
  w.rotation.tick();
  assert.equal(countOf(w, 'approvals'), 1, 'the tick that expires the request does not ask again in the same breath');
  hourlyTicks(w, EXPIRY_WAIT - HOUR);
  w.clock.advance(HOUR - 1);
  w.rotation.tick();
  assert.equal(countOf(w, 'approvals'), 1, 'one millisecond short of 24 hours after the expiry: no new approval');
  w.clock.advance(1);
  w.rotation.tick();
  assert.equal(countOf(w, 'approvals'), 2, 'the first tick 24 hours after the expiry asks again');
  w.rotation.tick();
  assert.equal(countOf(w, 'approvals'), 2);
});

test('KBOX-52 a manual rotation right after a refusal starts at once, and the scheduler stays quiet meanwhile', async (t) => {
  const w = await routesWorld(t);
  await addAdminKey(w);
  w.clock.advance(91 * DAY);
  w.rotation.tick();
  await denyTheRequest(w);
  const manual = await w.api('/api/rotations', { json: { keyref: KEYREF } });
  assert.equal(manual.status, 202, manual.body);
  assert.equal(countOf(w, 'approvals'), 2, 'the manual request is proposed at once');
  const [item] = await w.queue();
  assert.ok(item);
  await w.decide(item.approval_id, 'deny', w.proofFor(item, undefined, undefined, 'deny'));
  hourlyTicks(w, REFUSAL_WAIT - HOUR);
  assert.equal(countOf(w, 'approvals'), 2, 'the scheduler adds nothing while the first refusal is within its 7 days');
});

test('KBOX-52 a due admin key on a paste-source platform whose task expires gets no new task for 24 hours after the expiry and one after', async (t) => {
  const w = await routesWorld(t);
  await addAdminKey(w, PASTE_PLATFORM);
  w.clock.advance(91 * DAY);
  w.rotation.tick();
  assert.equal(countOf(w, 'paste_tasks'), 1);
  const expiresAt = (w.parts.db.prepare("SELECT expires_at AS at FROM paste_tasks WHERE json_extract(action_json, '$.kind') = 'rotate_key'").get() as { at: number }).at;
  w.clock.advance(expiresAt - w.clock.now());
  w.rotation.tick();
  assert.equal(countOf(w, 'paste_tasks'), 1, 'at the expiry no new task');
  hourlyTicks(w, EXPIRY_WAIT - HOUR);
  w.clock.advance(HOUR - 1);
  w.rotation.tick();
  assert.equal(countOf(w, 'paste_tasks'), 1, 'one millisecond short of 24 hours after the expiry: no new task');
  w.clock.advance(1);
  w.rotation.tick();
  assert.equal(countOf(w, 'paste_tasks'), 2, 'the first tick 24 hours after the expiry opens a new task');
});
