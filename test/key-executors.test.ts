// KBOX-60: the frame every approval executor shares (F1 the executor checks again, F2 the proposal check, F3 a cut-off approval is
// recorded and never run again) and the two kinds this unit builds, set_schedule and demote.
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { test } from 'node:test';
import type { TestContext } from 'node:test';
import type { KeyRow } from '../src/ports/meta.ts';
import type { BoxMadeKey } from '../src/ports/platform.ts';
import type { KeyClass, KeyShape, Scope } from '../src/ports/types.ts';
import type { Action, ActionKind } from '../src/pure/actions.ts';
import { ApiError } from '../src/pure/errors.ts';
import { openApproveCore } from '../src/shell/approve-core.ts';
import type { ExecuteResult, Executor, StoredApproval } from '../src/shell/approvals.ts';
import { refuseBoxKeyAction } from '../src/shell/box-keys.ts';
import { createKeyActions } from '../src/shell/key-executors.ts';
import type { KeyActions } from '../src/shell/key-executors.ts';
import { createMetaShareSource } from '../src/shell/share-source.ts';
import { createShareWriter } from '../src/shell/share-writer.ts';
import { fakeEntry, issuerWith, sourceOf } from './fakes/platform-entry.ts';
import { openShare } from './kit/reference-matcher.ts';
import { seededRandom, tempDir } from './kit/index.ts';
import { DOMAIN, WORDLIST, approveWorld } from './support/approve-world.ts';
import { HOUR, rotationWorld } from './support/rotation-world.ts';
import type { RotationWorld } from './support/rotation-world.ts';
import { routesWorld } from './support/routes-world.ts';

const DAY = 24 * HOUR;
const KEYREF = 'fake/shop/FAKE_KEY';
const BOX_REF = 'fake/p/BOX_KEY';
const BOX_SHAPE: KeyShape = { prefix: 'bk-', alphabet: 'base64url', coreLength: { min: 43, max: 43 }, random: true };
const BOX_KEY: BoxMadeKey = {
  name: 'BOX_KEY',
  shape: BOX_SHAPE,
  publishLeadMs: 0,
  generate: () => new Uint8Array(32),
  check: () => Promise.resolve('ok'),
  prove: () => Promise.resolve('ok'),
};

/** The classes the tests' scopes have: an `admin` or `master` item names it, anything else is ordinary. */
const byItems = (scope: Scope): KeyClass => {
  const items = Array.isArray(scope['items']) ? scope['items'] : [];
  return items.includes('master') ? 'master' : items.includes('admin') ? 'admin' : 'ordinary';
};

const approval = (action: Action): StoredApproval => ({ approvalId: 'apr_AAAAAAAAAAAAAAAA', revision: 1, action, requester: { kind: 'box' }, proof: undefined });

interface World {
  readonly w: RotationWorld;
  readonly actions: KeyActions;
  readonly registry: ReturnType<typeof registryOf>;
  /** A key row and its rotation record: the class it is stored with, the scope it was made with, and the owner's mark. */
  put(keyref: string, over?: { class?: KeyClass; items?: readonly string[]; mark?: boolean; every?: number; grace?: number }): void;
  key(keyref: string): NonNullable<ReturnType<RotationWorld['parts']['meta']['snapshot']>['keys'][number]>;
  run(action: Action): Promise<ExecuteResult>;
  changed(): readonly string[];
}

const registryOf = (w: RotationWorld) => [fakeEntry(w.platform, { issuer: issuerWith(w.platform.issuer, { classify: byItems }), boxKey: BOX_KEY })];

async function world(t: TestContext): Promise<World> {
  const w = await rotationWorld(t);
  const registry = registryOf(w);
  const actions = createKeyActions({ registry, source: sourceOf(registry), store: w.store, audit: w.parts.audit, clock: w.clock });
  const keyOf: World['key'] = (keyref) => {
    const found = w.parts.meta.snapshot().keys.find((k) => k.keyref === keyref);
    assert.ok(found, `${keyref} is stored`);
    return found;
  };
  return {
    w,
    actions,
    registry,
    put(keyref, over = {}) {
      const row: KeyRow = {
        keyref,
        platform: 'fake',
        name: keyref.split('/')[2] ?? 'K',
        projects: ['shop'],
        class: over.class ?? 'admin',
        status: 'works',
        gen_current: 1,
        schedule: { rotate_every_days: over.every ?? 90, grace_hours: over.grace ?? 24, next_due_at: 5, expires_at: null },
        coverage: null,
        last_use_at: null,
      };
      w.parts.meta.putKey(row);
      w.store.putKeyInfo(keyref, { scopeItems: over.items ?? ['read'], location: {}, rotatedAt: w.clock.now(), markAdmin: over.mark ?? false });
    },
    key: keyOf,
    run: (action) => {
      const executor = action.kind === 'set_schedule' ? actions.executors.set_schedule : actions.executors.demote;
      return executor(approval(action));
    },
    changed: () => w.events('key.changed').map((e) => String(e.data['keyref'])),
  };
}

const schedule = (keyref: string, days: number, grace: number): Action => ({ kind: 'set_schedule', keyref, rotate_every_days: days, grace_hours: grace });
const demote = (keyref: string): Action => ({ kind: 'demote', keyref });
const rejects = (code: string) => (e: unknown): boolean => e instanceof ApiError && e.code === 'rejected' && e.detail !== undefined && 'code' in e.detail && e.detail.code === code;
const conflicts = (code: string) => (e: unknown): boolean => e instanceof ApiError && e.code === 'conflict' && e.detail !== undefined && 'code' in e.detail && e.detail.code === code;

const openRun = (x: World, keyref: string): void => {
  x.w.store.openRun({ runId: 'run_open_1', keyref, state: 'pushing', genOld: 1, genNew: 2, intentName: 'kbox-test-intent', origin: 'owner' });
};

// ------------------------------------------------------------------------------------------------------ F1, F2: unknown key

test('KBOX-60 an unknown key is rejected (unknown_key) at proposal and failed (unknown_key) at execution, for set_schedule and for demote, and nothing is written', async (t) => {
  const x = await world(t);
  const head = x.w.parts.events.head();
  for (const action of [schedule('fake/shop/NOPE', 30, 2), demote('fake/shop/NOPE')]) {
    assert.throws(() => x.actions.precheck(action), rejects('unknown_key'), `${action.kind} at proposal`);
    assert.deepEqual(await x.run(action), { result: 'failed', reason: 'unknown_key' }, `${action.kind} at execution`);
  }
  assert.equal(x.w.parts.events.head(), head, 'no event');
  assert.deepEqual(x.w.parts.audit.read(0).entries, [], 'no audit row');
});

// ------------------------------------------------------------------------------------------------------ KBOX-55 at both places

test('KBOX-60 KBOX-55 a box key demote is box_made at proposal, and forced past the proposal check it is failed (box_made) at execution with the class unchanged', async (t) => {
  const x = await world(t);
  x.put(BOX_REF, { class: 'master', items: [], mark: true });
  assert.throws(() => refuseBoxKeyAction(x.registry, demote(BOX_REF)), rejects('box_made'), 'the proposal chain refuses it');
  assert.deepEqual(await x.run(demote(BOX_REF)), { result: 'failed', reason: 'box_made' });
  assert.equal(x.key(BOX_REF).class, 'master');
  assert.equal(x.w.store.keyInfo(BOX_REF)?.markAdmin, true, 'the mark is untouched');
});

test('KBOX-60 KBOX-55 a box key set_schedule with grace 0 is failed (box_made) at execution and writes nothing; with a grace it is written', async (t) => {
  const x = await world(t);
  x.put(BOX_REF, { class: 'master', items: [], every: 90, grace: 1 });
  assert.deepEqual(await x.run(schedule(BOX_REF, 30, 0)), { result: 'failed', reason: 'box_made' });
  assert.deepEqual(x.key(BOX_REF).schedule, { rotate_every_days: 90, grace_hours: 1, next_due_at: 5, expires_at: null });
  assert.deepEqual(await x.run(schedule(BOX_REF, 30, 2)), { result: 'done' });
  assert.deepEqual([x.key(BOX_REF).schedule.rotate_every_days, x.key(BOX_REF).schedule.grace_hours], [30, 2]);
});

// ------------------------------------------------------------------------------------------------------ set_schedule

test('KBOX-60 set_schedule writes rotate_every_days and grace_hours of the key row, one key.changed and one key.schedule_set row, and leaves next_due_at and the class alone', async (t) => {
  const x = await world(t);
  x.put(KEYREF, { every: 90, grace: 24 });
  const head = x.w.parts.events.head();
  assert.doesNotThrow(() => x.actions.precheck(schedule(KEYREF, 7, 0)));
  assert.deepEqual(await x.run(schedule(KEYREF, 7, 0)), { result: 'done' });
  assert.deepEqual(x.key(KEYREF).schedule, { rotate_every_days: 7, grace_hours: 0, next_due_at: 5, expires_at: null });
  assert.equal(x.key(KEYREF).class, 'admin');
  assert.deepEqual(x.w.parts.events.after(head).map((e) => [e.kind, e.data]), [['key.changed', { keyref: KEYREF }]], 'one event, nothing else');
  const rows = x.w.parts.audit.read(0).entries.filter((r) => r.action === 'key.schedule_set');
  assert.deepEqual(rows.map((r) => [r.ref, r.detail]), [[KEYREF, { rotate_every_days: 7, grace_hours: 0 }]]);
});

test('KBOX-60 set_schedule is allowed while a run is open', async (t) => {
  const x = await world(t);
  x.put(KEYREF);
  openRun(x, KEYREF);
  assert.doesNotThrow(() => x.actions.precheck(schedule(KEYREF, 30, 5)));
  assert.deepEqual(await x.run(schedule(KEYREF, 30, 5)), { result: 'done' });
});

test('KBOX-60 the scheduler\'s next tick uses the new schedule: a key not due for 90 days is due after 2 days once set to 1 day, and not before', async (t) => {
  const w = await routesWorld(t);
  const keyref = 'fake/shop/OPENAI_KEY';
  await w.api('/api/keys', { json: { platform: 'fake', name: 'OPENAI_KEY', projects: ['shop'], scope: { items: ['read'] }, rotate_every_days: 90 } });
  await w.rotation.orchestrator.idle();
  w.clock.advance(2 * DAY);
  await w.rotation.orchestrator.idle();
  const registry = [fakeEntry(w.platform, { issuer: issuerWith(w.platform.issuer, { classify: byItems }) })];
  const actions = createKeyActions({ registry, source: sourceOf(registry), store: w.rotation.store, audit: w.parts.audit, clock: w.clock });
  const runs = (): number => w.rotation.store.runs().length;
  const before = runs();
  w.rotation.tick();
  await w.rotation.orchestrator.idle();
  assert.equal(runs(), before, 'control: on the 90-day schedule nothing is due after 2 days');
  assert.deepEqual(await actions.executors.set_schedule(approval(schedule(keyref, 1, 24))), { result: 'done' });
  w.rotation.tick();
  await w.rotation.orchestrator.idle();
  assert.equal(runs(), before + 1, 'on the 1-day schedule the key is due');
  assert.equal(w.rotation.store.runs().at(-1)?.origin, 'schedule');
});

test('KBOX-60 a run that has not promoted takes the new grace at promote (revoke_at = promote time + the new grace)', async (t) => {
  const x = await world(t);
  const { w } = x;
  const keyref = await w.seedKey({ graceHours: 24, class: 'admin', scopeItems: ['admin'] });
  w.checkpoints.hook = async (point) => {
    if (point !== 'checking') return;
    w.checkpoints.hook = undefined;
    assert.deepEqual(await x.run(schedule(keyref, 90, 2)), { result: 'done' });
  };
  w.orch.start({ keyref, origin: 'approval' });
  await w.orch.idle();
  const run = w.store.activeRunOf(keyref);
  assert.ok(run?.waitUntil !== null && run?.waitUntil !== undefined, 'the run waits out its grace');
  assert.equal(run.waitUntil - w.clock.now(), 2 * HOUR, 'the grace is the one set before promote, not the 24 hours the key had');
});

// ------------------------------------------------------------------------------------------------------ demote

test('KBOX-60 demote of a marked admin key to ordinary: the mark and the grants go, the allow rules stay, one key.changed and one key.demoted {from, to}', async (t) => {
  const x = await world(t);
  x.put(KEYREF, { class: 'admin', items: ['read'], mark: true });
  x.w.parts.meta.putGrant(KEYREF, 'ws-1');
  x.w.parts.meta.putAllowRule(KEYREF, 'rule_a');
  const head = x.w.parts.events.head();
  assert.doesNotThrow(() => x.actions.precheck(demote(KEYREF)));
  assert.deepEqual(await x.run(demote(KEYREF)), { result: 'done' });
  const key = x.key(KEYREF);
  assert.equal(key.class, 'ordinary');
  assert.deepEqual(key.grants, [], 'fail closed: raised again later, a key gets no relay use back without a grant');
  assert.deepEqual(key.allow_rules, ['rule_a'], 'an empty set would mean the whole profile, so the rules are kept');
  assert.equal(x.w.store.keyInfo(KEYREF)?.markAdmin, false);
  assert.deepEqual(x.w.parts.events.after(head).map((e) => [e.kind, e.data]), [['key.changed', { keyref: KEYREF }]]);
  assert.deepEqual(x.w.parts.audit.read(0).entries.filter((r) => r.action === 'key.demoted').map((r) => [r.ref, r.detail]), [[KEYREF, { from: 'admin', to: 'ordinary' }]]);
});

test('KBOX-60 demote never goes below what the scope makes the key: a master whose scope now classes admin falls to admin and keeps its grants', async (t) => {
  const x = await world(t);
  x.put(KEYREF, { class: 'master', items: ['admin'], mark: true });
  x.w.parts.meta.putGrant(KEYREF, 'ws-1');
  assert.deepEqual(await x.run(demote(KEYREF)), { result: 'done' });
  assert.equal(x.key(KEYREF).class, 'admin');
  assert.deepEqual(x.key(KEYREF).grants, [{ machine: 'ws-1' }]);
  assert.deepEqual(x.actions.pageFacts(demote(KEYREF)), {}, 'after the demote there is nothing left to describe');
});

test('KBOX-60 demote has nothing_to_lower when the class without the mark equals the key\'s class: an unmarked key, a marked key whose scope keeps it, an ordinary key', async (t) => {
  const x = await world(t);
  const cases: [string, Parameters<World['put']>[1]][] = [
    ['fake/shop/UNMARKED', { class: 'admin', items: ['admin'] }],
    ['fake/shop/MARKED_BUT_ADMIN_SCOPE', { class: 'admin', items: ['admin'], mark: true }],
    ['fake/shop/ORDINARY', { class: 'ordinary', items: ['read'] }],
  ];
  for (const [keyref, over] of cases) {
    x.put(keyref, over);
    const before = x.key(keyref);
    assert.throws(() => x.actions.precheck(demote(keyref)), rejects('nothing_to_lower'), `${keyref} at proposal`);
    assert.deepEqual(await x.run(demote(keyref)), { result: 'failed', reason: 'nothing_to_lower' }, `${keyref} at execution`);
    assert.deepEqual(x.key(keyref), before, `${keyref} is untouched`);
    assert.equal(x.w.store.keyInfo(keyref)?.markAdmin, over?.mark ?? false, 'the mark is untouched');
  }
});

test('KBOX-60 demote with a run open is conflict (run_exists) at proposal and failed (run_open) at execution, and nothing changes; once the run ends it goes through', async (t) => {
  const x = await world(t);
  x.put(KEYREF, { class: 'admin', items: ['read'], mark: true });
  x.w.parts.meta.putGrant(KEYREF, 'ws-1');
  openRun(x, KEYREF);
  assert.throws(() => x.actions.precheck(demote(KEYREF)), conflicts('run_exists'));
  assert.deepEqual(await x.run(demote(KEYREF)), { result: 'failed', reason: 'run_open' });
  assert.equal(x.key(KEYREF).class, 'admin');
  assert.deepEqual(x.key(KEYREF).grants, [{ machine: 'ws-1' }]);
  assert.equal(x.w.store.keyInfo(KEYREF)?.markAdmin, true);
  x.w.store.update('run_open_1', { state: 'failed', reasonCode: 'test', failedStep: 'pushing', failedAt: x.w.clock.now() });
  assert.deepEqual(await x.run(demote(KEYREF)), { result: 'done' });
});

test('KBOX-60 the page is told where a demote lands, and whether a zero-grace set_schedule leaves apps on a runtime destination', async (t) => {
  const x = await world(t);
  x.put(KEYREF, { class: 'admin', items: ['read'], mark: true });
  x.put('fake/shop/NO_DEST', { class: 'admin' });
  assert.deepEqual(x.actions.pageFacts(demote(KEYREF)), { fallsTo: 'ordinary' });
  assert.deepEqual(x.actions.pageFacts(schedule(KEYREF, 30, 0)), {});
  x.w.parts.meta.putDestination(KEYREF, { kind: 'vercel_env', target: 'app-a', readable_by: 'runtime' });
  assert.deepEqual(x.actions.pageFacts(schedule(KEYREF, 30, 0)), { runtimeDestination: true });
  assert.deepEqual(x.actions.pageFacts(schedule('fake/shop/NO_DEST', 30, 0)), {});
  assert.deepEqual(x.actions.pageFacts({ kind: 'rotate_key', keyref: KEYREF }), {}, 'no other kind has facts');
});

// ------------------------------------------------------------------------------------------------------ the share file (writer level)

const FAKE_SHAPE: KeyShape = { prefix: 'fk-', alphabet: 'hex', coreLength: { min: 32, max: 32 }, random: true };

test('KBOX-60 KBOX-33 after a demote to ordinary the share file no longer lists the key, version + 1, exactly one share.version', async (t) => {
  const x = await world(t);
  const { w } = x;
  const keyref = await w.seedKey({ class: 'admin', scopeItems: ['read'], markAdmin: true });
  const writer = createShareWriter({
    dir: join(await tempDir(t), 'share'),
    meta: w.parts.meta,
    signingKey: w.parts.share.signingKey,
    source: createMetaShareSource({ meta: w.parts.meta, values: w.parts.share.values, shapeOf: (platform) => (platform === 'fake' ? FAKE_SHAPE : undefined), generations: (k: string) => w.store.gens(k) }),
    events: w.parts.events,
    hub: w.parts.hub,
    clock: w.clock,
    scheduler: w.clock,
    random: seededRandom(31),
    audit: w.parts.audit,
  });
  t.after(() => writer.stop());
  await writer.start();
  const names = (): string[] => {
    const publicKey = w.parts.meta.shareState().publicKeyB64;
    assert.ok(publicKey !== null);
    assert.ok(openShare(writer.serve().bytes, publicKey).ok, 'the file verifies');
    const envelope = JSON.parse(Buffer.from(writer.serve().bytes).toString('utf8')) as { body_b64: string };
    return (JSON.parse(Buffer.from(envelope.body_b64, 'base64').toString('utf8')) as { coverage: { name: string }[] }).coverage.map((c) => c.name);
  };
  assert.deepEqual(names(), ['OPENAI_KEY'], 'control: the admin key is in the file');
  const before = writer.serve().version;
  const heard = w.parts.events.head();

  assert.deepEqual(await x.run(demote(keyref)), { result: 'done' });
  await writer.idle();

  assert.deepEqual(names(), [], 'the key is gone from the file');
  assert.equal(writer.serve().version, before + 1);
  assert.deepEqual(w.parts.events.after(heard).filter((e) => e.kind === 'share.version').map((e) => e.data), [{ version: before + 1 }]);
});

// ------------------------------------------------------------------------------------------------------ F3

/** One valid action of each kind, each on its own key so no two share a slot. */
const FIXTURES: Readonly<Record<ActionKind, Action>> = {
  add_key: { kind: 'add_key', platform: 'fake', name: 'A_KEY', projects: ['shop'], scope: { items: ['admin'] } },
  delete_key: { kind: 'delete_key', keyref: 'fake/shop/K1' },
  rotate_key: { kind: 'rotate_key', keyref: 'fake/shop/K2' },
  demote: { kind: 'demote', keyref: 'fake/shop/K3' },
  grant: { kind: 'grant', keyref: 'fake/shop/K4', machine: 'ws-1' },
  revoke_grant: { kind: 'revoke_grant', keyref: 'fake/shop/K5', machine: 'ws-1' },
  add_destination: { kind: 'add_destination', keyref: 'fake/shop/K6', destination: { kind: 'workstation', target: '' } },
  remove_destination: { kind: 'remove_destination', keyref: 'fake/shop/K7', destination: { kind: 'workstation', target: '' } },
  set_allow_rules: { kind: 'set_allow_rules', keyref: 'fake/shop/K8', rules: [] },
  set_schedule: { kind: 'set_schedule', keyref: 'fake/shop/K9', rotate_every_days: 30, grace_hours: 24 },
  vercel_set_domain: { kind: 'vercel_set_domain', project: 'shop', op: 'add', domain: 'shop.example.com' },
  vercel_set_team_setting: { kind: 'vercel_set_team_setting', setting: 'x', value: 'y' },
  approver_add: { kind: 'approver_add', cose_sha256: 'e'.repeat(64), device_sha256: 'f'.repeat(64) },
  approver_remove: { kind: 'approver_remove', approver_id: 'ap-AAAAAAAAAAAA' },
  install_update: { kind: 'install_update', install: 'a'.repeat(64), commit: 'b'.repeat(40), base: 'c'.repeat(64) },
  enrol: { kind: 'enrol', label: 'laptop', token_sha256: 'd'.repeat(64), address: '198.51.100.7' },
};

/** The same stores and the same wiring a second time: core started again after the process died. */
function reopened(w: Awaited<ReturnType<typeof approveWorld>>, executors: Partial<Record<ActionKind, Executor>>) {
  return openApproveCore({ parts: w.parts, approverStore: w.priv, trust: w.trust, push: w.push, clock: w.clock, random: seededRandom(77), domain: DOMAIN, wordlist: WORDLIST, vet: () => 'ok', executors });
}

const notices = (w: Awaited<ReturnType<typeof approveWorld>>): readonly { code?: unknown; text?: unknown; title?: unknown }[] =>
  w.parts.events.after(0).filter((e) => e.kind === 'box.notice').map((e) => e.data);

test('KBOX-60 F3 a crash after the approval committed (the executor died): at the next start the row is failed/interrupted with one notice, and the executor is not called again', async (t) => {
  let calls = 0;
  const dying: Executor = () => {
    calls += 1;
    throw new Error('the process died here');
  };
  const w = await approveWorld(t, { executors: { set_schedule: dying } });
  const proposed = w.propose(FIXTURES.set_schedule);
  const item = (await w.queue()).find((q) => q.approval_id === proposed.approval_id);
  assert.ok(item);
  await w.decide(item.approval_id, 'approve', w.proofFor(item));
  assert.equal(calls, 1);
  assert.deepEqual(w.core.approvals.waiting('set_schedule').map((a) => a.approvalId), [proposed.approval_id], 'stuck: approved, no result');

  const again: Executor = () => {
    calls += 1;
    return Promise.resolve({ result: 'done' });
  };
  const restarted = reopened(w, { set_schedule: again });
  assert.equal(calls, 1, 'the executor was not called again');
  assert.deepEqual(restarted.approvals.waiting('set_schedule'), [], 'no longer waiting');
  const executed = w.parts.events.after(0).filter((e) => e.kind === 'approval.executed');
  assert.deepEqual(executed.map((e) => e.data), [{ approval_id: proposed.approval_id, result: 'failed', reason_code: 'interrupted' }]);
  assert.deepEqual(notices(w), [{ code: 'approval_interrupted', text: 'approval interrupted' }]);
  assert.deepEqual(
    w.parts.audit.read(0).entries.filter((r) => r.action === 'approval.executed').map((r) => [r.ref, r.detail]),
    [[proposed.approval_id, { result: 'failed', reason_code: 'interrupted' }]],
  );

  reopened(w, { set_schedule: again });
  assert.equal(notices(w).length, 1, 'a second start records and notices nothing more');
  assert.equal(calls, 1);
});

test('KBOX-60 F3 a row decided but never executed is not touched while it is pending or already has a result', async (t) => {
  const w = await approveWorld(t);
  const pending = w.propose(FIXTURES.set_schedule);
  const done = w.propose(FIXTURES.demote);
  w.parts.db.prepare("UPDATE approvals SET status = 'approved', decided_at = ?, result = 'done', result_code = 'ok' WHERE approval_id = ?").run(w.clock.now(), done.approval_id);
  reopened(w, {});
  assert.deepEqual(notices(w), []);
  assert.deepEqual(w.core.approvals.pending('set_schedule').map((a) => a.approvalId), [pending.approval_id]);
  assert.deepEqual(w.parts.events.after(0).filter((e) => e.kind === 'approval.executed'), []);
});
