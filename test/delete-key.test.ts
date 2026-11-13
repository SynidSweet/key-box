// KBOX-62 (S-816): an approved delete_key ends the key at its platform (or asks the owner to), waits until proven evidence says it stopped
// working, twice and at least a minute apart, then erases the box's copy; it never erases early and never gives up. The world is the approval
// half with the rotation unit beside it over a platform whose verifier answers HTTP statuses (test/support/delete-world.ts).
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { test } from 'node:test';
import type { BoxMadeKey } from '../src/ports/platform.ts';
import type { Action } from '../src/pure/actions.ts';
import { ApiError } from '../src/pure/errors.ts';
import type { StoredApproval } from '../src/shell/approvals.ts';
import { openMetaDatabase } from '../src/shell/db.ts';
import { ERASED_TABLES, KEPT_TABLES } from '../src/shell/deletion-store.ts';
import { PROOF_GAP_MS } from '../src/shell/proof-watch.ts';
import type { Point } from '../src/shell/rotation-ports.ts';
import { createMetaShareSource } from '../src/shell/share-source.ts';
import { createShareWriter } from '../src/shell/share-writer.ts';
import { REGISTRY } from '../src/platforms/registry.ts';
import { readTextIfPresent } from './arch/tree.ts';
import { seededRandom, tempDir } from './kit/index.ts';
import { DAY, Died, HOUR, MINUTE, PASTED, deleteWorld } from './support/delete-world.ts';
import type { DeleteWorld } from './support/delete-world.ts';
import { fileURLToPath } from 'node:url';
import type { DatabaseSync } from 'node:sqlite';

const KEYREF = 'fake/shop/FAKE_KEY';
const del = (keyref: string): Action => ({ kind: 'delete_key', keyref });
const approval = (keyref: string, id = 'apr_AAAAAAAAAAAAAAAA'): StoredApproval => ({ approvalId: id, revision: 1, action: del(keyref), requester: { kind: 'box' }, proof: undefined });

/** The refusal a proposal check threw, as `answer/code`; `ok` when it passed. */
function refusal(check: () => void): string {
  try {
    check();
    return 'ok';
  } catch (error) {
    if (!(error instanceof ApiError)) throw error;
    return `${error.code}/${error.detail !== undefined && 'code' in error.detail ? error.detail.code : ''}`;
  }
}

interface LedgerRow {
  readonly run_id: string;
  readonly notified: number;
  readonly dead_seen_at: number | null;
  readonly confirmed_at: number | null;
  readonly outcome: string | null;
}
const ledger = (w: DeleteWorld, approvalId: string): LedgerRow | undefined => w.parts.db.prepare('SELECT * FROM key_deletions WHERE approval_id = ?').get(approvalId) as LedgerRow | undefined;
const count = (w: DeleteWorld, sql: string, ...params: string[]): number => (w.parts.db.prepare(sql).get(...params) as { n: number }).n;
const stored = (w: DeleteWorld, keyref: string): boolean => w.rotation.store.key(keyref) !== undefined;
const notices = (w: DeleteWorld): readonly unknown[] => w.events('box.notice').filter((n) => n['code'] === 'delete_waiting');
const pushes = (w: DeleteWorld): readonly string[] => w.push.sent.filter((m) => m.kind === 'delete_waiting').map((m) => m.title);
const revokes = (w: DeleteWorld): readonly string[] => w.platform.calls.filter((c) => c.startsWith('revoke'));

/** A rotation of the key run to its grace wait: gen 2 current, gen 1 grace, the run waiting. */
async function inGrace(w: DeleteWorld, keyref: string): Promise<string> {
  const run = w.rotation.orchestrator.start({ keyref, origin: 'owner' });
  await w.rotation.orchestrator.idle();
  assert.equal(w.rotation.store.run(run.runId)?.state, 'grace');
  return run.runId;
}

// ------------------------------------------------------------------------------------------------------ the proposal check (F2)

test('KBOX-62 the proposal check answers unknown_key, unknown_platform, key_deleting, run_exists, master_in_use, no_master and master_ambiguous, and allows a key in grace', async (t) => {
  const w = await deleteWorld(t);
  const check = (keyref: string): string => refusal(() => w.rotation.deletion.precheck(del(keyref)));
  await w.addKey();
  assert.equal(check('fake/shop/NOPE'), 'rejected/unknown_key');
  w.parts.meta.putKey({ keyref: 'gone/shop/K', platform: 'gone', name: 'K', projects: ['shop'], class: 'ordinary', status: 'works', gen_current: 1, schedule: { rotate_every_days: 90, grace_hours: 1, next_due_at: null, expires_at: null }, coverage: null, last_use_at: null });
  assert.equal(check('gone/shop/K'), 'rejected/unknown_platform');
  assert.equal(check(w.masters.fake), 'rejected/master_in_use', 'the master serves FAKE_KEY');
  assert.equal(check(KEYREF), 'ok');

  const busy = await w.addKey({ keyref: 'fake/shop/BUSY', name: 'BUSY' });
  w.rotation.store.openRun({ runId: 'run_0000000000000001', keyref: busy, state: 'pushing', genOld: 1, genNew: 2, intentName: 'kbox_x', origin: 'owner' });
  assert.equal(check(busy), 'conflict/run_exists', 'a run before promote');
  const graced = await w.addKey({ keyref: 'fake/shop/GRACED', name: 'GRACED' });
  await inGrace(w, graced);
  assert.equal(check(graced), 'ok', 'a run in grace is superseded, not refused');

  await w.approveDelete(KEYREF);
  assert.equal(check(KEYREF), 'rejected/key_deleting');

  w.parts.vault.retire(w.masters.fake, 1);
  assert.equal(check(graced), 'rejected/no_master', 'the only master can no longer be lent');
  w.parts.vault.put(w.masters.fake, 1, Buffer.from(w.platform.value()));
  w.parts.meta.putKey({ keyref: 'fake/other/MASTER2', platform: 'fake', name: 'MASTER2', projects: ['other'], class: 'master', status: 'works', gen_current: 1, schedule: { rotate_every_days: 90, grace_hours: 1, next_due_at: null, expires_at: null }, coverage: null, last_use_at: null });
  w.rotation.store.putKeyInfo('fake/other/MASTER2', { scopeItems: ['master'], location: {}, rotatedAt: w.clock.now(), markAdmin: false });
  w.parts.vault.put('fake/other/MASTER2', 1, Buffer.from(w.platform.value()));
  assert.equal(check(graced), 'rejected/master_ambiguous');
});

test('KBOX-62 a box-made key is refused box_made at proposal and, with the proposal check bypassed, at execution', async (t) => {
  const box: BoxMadeKey = { name: 'BOX_KEY', shape: { prefix: 'bk-', alphabet: 'base64url', coreLength: { min: 43, max: 43 }, random: true }, publishLeadMs: 0, generate: () => new Uint8Array(32), check: () => Promise.resolve('ok'), prove: () => Promise.resolve('ok') };
  const w = await deleteWorld(t, { boxKey: box });
  const keyref = 'fake/p/BOX_KEY';
  w.parts.meta.putKey({ keyref, platform: 'fake', name: 'BOX_KEY', projects: [], class: 'master', status: 'works', gen_current: 1, schedule: { rotate_every_days: 90, grace_hours: 24, next_due_at: null, expires_at: null }, coverage: null, last_use_at: null });
  assert.equal(refusal(() => w.rotation.deletion.precheck(del(keyref))), 'rejected/box_made');
  assert.deepEqual(await w.rotation.deletion.executor(approval(keyref)), { result: 'failed', reason: 'box_made' });
});

test('KBOX-62 ruling 1: cannot_confirm refuses a delete before any approval opens when the evidence probe is unverified, and the same key is accepted once it is proven', async (t) => {
  const unproven = await deleteWorld(t, { unproven: true });
  await unproven.addKey();
  assert.equal(refusal(() => unproven.rotation.deletion.precheck(del(KEYREF))), 'rejected/cannot_confirm');
  assert.deepEqual(await unproven.rotation.deletion.executor(approval(KEYREF)), { result: 'failed', reason: 'cannot_confirm' }, 'and again at execution');
  assert.equal(stored(unproven, KEYREF), true);
  const proven = await deleteWorld(t);
  await proven.addKey();
  assert.equal(refusal(() => proven.rotation.deletion.precheck(del(KEYREF))), 'ok');
});

test('KBOX-62 every other kind naming a key being deleted is refused key_deleting at proposal, and a rotation is a conflict', async (t) => {
  const w = await deleteWorld(t);
  await w.addKey();
  await w.approveDelete(KEYREF);
  const actions: readonly Action[] = [
    { kind: 'grant', keyref: KEYREF, machine: 'ws-1' },
    { kind: 'set_schedule', keyref: KEYREF, rotate_every_days: 30, grace_hours: 1 },
    { kind: 'add_destination', keyref: KEYREF, destination: { kind: 'workstation', target: '' } },
    { kind: 'rotate_key', keyref: KEYREF },
  ];
  for (const action of actions) assert.equal(refusal(() => w.rotation.deletion.precheck(action)), 'rejected/key_deleting', action.kind);
  assert.throws(() => w.rotation.orchestrator.start({ keyref: KEYREF, origin: 'agent' }), (e) => e instanceof ApiError && e.code === 'conflict');
});

// ------------------------------------------------------------------------------------------------------ the execution check (F1)

test('KBOX-62 execution checks again: unknown_key, run_open for a run before promote, and master_in_use for a dependant added after the proposal', async (t) => {
  const w = await deleteWorld(t);
  assert.deepEqual(await w.rotation.deletion.executor(approval('fake/shop/NOPE')), { result: 'failed', reason: 'unknown_key' });
  const busy = await w.addKey({ keyref: 'fake/shop/BUSY', name: 'BUSY' });
  w.rotation.store.openRun({ runId: 'run_0000000000000002', keyref: busy, state: 'checking', genOld: 1, genNew: 2, intentName: 'kbox_y', origin: 'owner' });
  assert.deepEqual(await w.rotation.deletion.executor(approval(busy)), { result: 'failed', reason: 'run_open' });
  // BUSY was added after a proposal to delete the master would have passed: the master now serves it.
  assert.deepEqual(await w.rotation.deletion.executor(approval(w.masters.fake)), { result: 'failed', reason: 'master_in_use' });
  assert.equal(count(w, 'SELECT count(*) AS n FROM key_deletions'), 0, 'nothing opened');
});

test('KBOX-62 execution refuses run_open while this process works on the key run in revoking (leased), and opens nothing', async (t) => {
  const hook: { at: ((point: Point) => Promise<void>) | undefined } = { at: undefined };
  const w = await deleteWorld(t, { checkpoint: (point) => hook.at?.(point) });
  await w.addKey();
  await inGrace(w, KEYREF);
  let during: unknown;
  hook.at = async (point) => {
    if (point !== 'grace') return;
    hook.at = undefined;
    during = await w.rotation.deletion.executor(approval(KEYREF));
  };
  await w.pass(25 * HOUR, HOUR);
  assert.deepEqual(during, { result: 'failed', reason: 'run_open' });
  assert.equal(stored(w, KEYREF), true);
});

// ------------------------------------------------------------------------------------------------------ opening

test('KBOX-62 opening is one transaction: the run (gen_old 0, origin delete, revoking, intent not kbox_), the ledger, grants and deliveries gone, one key.changed; other approvals and a paste task naming the key expire; the approval waits with no result', async (t) => {
  const w = await deleteWorld(t);
  await w.addKey();
  w.parts.meta.putGrant(KEYREF, 'ws-1');
  w.rotation.store.putDelivery({ deliveryId: 'dlv_x_0', keyref: KEYREF, project: 'shop', name: 'FAKE_KEY', gen: 1, createdAt: w.clock.now() });
  const other = w.propose({ kind: 'set_schedule', keyref: KEYREF, rotate_every_days: 30, grace_hours: 1 });
  const paste = w.rotation.paste.open({ action: { kind: 'rotate_key', keyref: KEYREF }, requester: { kind: 'box' } });
  w.platform.answer = 200;
  const changedBefore = w.events('key.changed').length;
  const id = await w.approveDelete(KEYREF);

  const run = w.rotation.store.activeRunOf(KEYREF);
  assert.ok(run);
  assert.deepEqual([run.genOld, run.origin, run.state, run.intentName.startsWith('kbox_')], [0, 'delete', 'revoking', false]);
  assert.equal(ledger(w, id)?.run_id, run.runId);
  assert.equal(count(w, 'SELECT count(*) AS n FROM grants WHERE keyref = ?', KEYREF), 0);
  assert.equal(count(w, 'SELECT count(*) AS n FROM deliveries WHERE keyref = ?', KEYREF), 0);
  assert.equal(w.events('key.changed').length - changedBefore, 1, 'one key.changed for the open');
  assert.equal(w.resultOf(other.approval_id).status, 'expired');
  assert.ok(w.events('approval.decided').some((e) => e['approval_id'] === other.approval_id && e['decision'] === 'expired'));
  assert.ok(w.audits('approval.decided').some((a) => a.ref === other.approval_id));
  assert.equal(w.rotation.paste.hasPending(paste.slot), false, 'the paste task expired');
  assert.equal((w.parts.db.prepare('SELECT status FROM paste_tasks WHERE paste_id = ?').get(paste.paste_id) as { status: string }).status, 'expired');
  assert.deepEqual(w.resultOf(id), { status: 'approved', result: null, code: null });
  assert.deepEqual(w.audits('key.delete_started').map((a) => a.detail), [{ run_id: run.runId, live_gens: 1 }]);
});

test('KBOX-62 ruling 6: putKey refuses a keyref with an open deletion (no resurrecting upsert)', async (t) => {
  const w = await deleteWorld(t);
  await w.addKey();
  w.platform.answer = 200;
  await w.approveDelete(KEYREF);
  const row = w.parts.meta.snapshot().keys.find((k) => k.keyref === KEYREF);
  assert.ok(row);
  assert.throws(() => w.parts.meta.putKey({ ...row, status: 'works' }), (e) => e instanceof ApiError && e.code === 'conflict' && e.detail !== undefined && 'code' in e.detail && e.detail.code === 'key_deleting');
});

// ------------------------------------------------------------------------------------------------------ the box path

test('KBOX-62 two dead verdicts at least a minute apart erase the key; the second pass sends no revoke; nothing is erased before', async (t) => {
  const w = await deleteWorld(t);
  await w.addKey();
  const id = await w.approveDelete(KEYREF);
  assert.equal(revokes(w).length, 1, 'ended once');
  assert.notEqual(ledger(w, id)?.dead_seen_at, null, 'the first verdict is stored');
  assert.equal(stored(w, KEYREF), true, 'not erased on one verdict');
  await w.pass(59_000, 1000);
  assert.equal(stored(w, KEYREF), true, 'not before the minute');
  await w.pass(1000, 1000);
  assert.equal(stored(w, KEYREF), false, 'erased after the second verdict');
  assert.equal(revokes(w).length, 1, 'the confirmation pass sent no second revoke');
  assert.deepEqual(w.resultOf(id), { status: 'approved', result: 'done', code: 'ok' });
  assert.equal(ledger(w, id)?.outcome, 'erased');
  assert.equal(w.audits('key.revoked').filter((a) => a.ref === KEYREF).length, 1);
  assert.deepEqual(w.audits('key.deleted').map((a) => a.detail), [{ run_id: ledger(w, id)?.run_id, platform: 'fake', gens: 1, destinations: 0 }]);
});

test('KBOX-62 dead, then alive, then dead, then dead: the erase comes only after the second consecutive dead pair', async (t) => {
  const w = await deleteWorld(t);
  await w.addKey();
  await w.approveDelete(KEYREF);
  w.platform.answer = 200;
  await w.pass(MINUTE);
  assert.equal(stored(w, KEYREF), true, 'an alive second verdict resets');
  w.platform.answer = undefined;
  await w.pass(MINUTE);
  assert.equal(stored(w, KEYREF), true, 'one dead verdict after the reset is not enough');
  await w.pass(MINUTE);
  assert.equal(stored(w, KEYREF), false);
});

test('KBOX-62 ruling 1: a 403, a 404 and a network error never confirm a delete, though the key is gone at the platform; only the proven 401 does', async (t) => {
  const w = await deleteWorld(t);
  await w.addKey();
  for (const answer of [403, 404, 'throw'] as const) w.platform.answer = answer;
  w.platform.answer = 403;
  const id = await w.approveDelete(KEYREF);
  await w.pass(3 * MINUTE);
  w.platform.answer = 404;
  await w.pass(8 * MINUTE);
  w.platform.answer = 'throw';
  await w.pass(16 * MINUTE);
  assert.equal(stored(w, KEYREF), true, 'never erased on an unproven answer');
  assert.equal(ledger(w, id)?.dead_seen_at, null);
  w.platform.answer = undefined;
  await w.pass(2 * HOUR);
  assert.equal(stored(w, KEYREF), false, 'the proven answer erases it');
});

test('KBOX-62 the platform down at the end: the key and its vault stay, one notice, one push B naming the key, one key.delete_unconfirmed, retries at 1, 2, 4 … 60, 60 minutes, and no second notice after a restart', async (t) => {
  const w = await deleteWorld(t);
  await w.addKey();
  w.platform.down = true;
  const id = await w.approveDelete(KEYREF);
  const runId = ledger(w, id)?.run_id ?? '';
  const attempts = (): number => w.rotation.store.run(runId)?.attempts ?? -1;
  assert.equal(attempts(), 1);
  for (const [i, minutes] of [1, 2, 4, 8, 16, 32, 60, 60].entries()) {
    await w.pass(minutes * MINUTE - 1000, 1000);
    assert.equal(attempts(), i + 1, `no retry before ${minutes} min`);
    await w.pass(1000, 1000);
    assert.equal(attempts(), i + 2, `retry after ${minutes} min`);
  }
  await w.restart();
  await w.pass(2 * HOUR, MINUTE);
  assert.equal(stored(w, KEYREF), true);
  assert.equal(w.parts.vault.generations(KEYREF).length, 1, 'the value is still in the vault');
  assert.equal(notices(w).length, 1);
  assert.deepEqual(pushes(w), ['The box could not end the key FAKE_KEY on fake yet. End it there if you can; the box keeps checking.']);
  assert.deepEqual(w.audits('key.delete_unconfirmed').map((a) => a.detail), [{ run_id: runId, ender: 'issuer' }]);
  assert.deepEqual(w.resultOf(id).result, null);
});

test('KBOX-62 the platform down at the confirmation (the revoke went through): the key stays with one notice and one push B', async (t) => {
  const w = await deleteWorld(t);
  await w.addKey();
  w.platform.answer = 'throw';
  await w.approveDelete(KEYREF);
  await w.pass(3 * HOUR, 5 * MINUTE);
  assert.equal(stored(w, KEYREF), true);
  assert.equal(notices(w).length, 1);
  assert.equal(pushes(w).length, 1);
});

test('KBOX-62 a key that still works is not erased after 30 days, and is checked hourly at the cap', async (t) => {
  const w = await deleteWorld(t);
  await w.addKey();
  w.platform.answer = 200;
  const id = await w.approveDelete(KEYREF);
  await w.pass(30 * DAY, HOUR);
  assert.equal(stored(w, KEYREF), true);
  assert.equal(w.resultOf(id).result, null);
  const statuses = w.platform.calls.filter((c) => c.startsWith('status')).length;
  await w.pass(5 * HOUR, HOUR);
  assert.equal(w.platform.calls.filter((c) => c.startsWith('status')).length - statuses, 5, 'one check an hour');
});

test('KBOX-62 a revoke answering absent (a 404) while the key still works is not proof: not erased', async (t) => {
  const w = await deleteWorld(t);
  await w.addKey();
  const id = w.rotation.store.gens(KEYREF)[0]?.platformKeyId ?? '';
  const value = w.platform.live.get(id) ?? '';
  w.platform.live.delete(id);
  w.platform.pasted.add(value);
  await w.approveDelete(KEYREF);
  await w.pass(2 * HOUR, 5 * MINUTE);
  assert.ok(revokes(w).length > 0, 'the revoke was sent and answered absent');
  assert.equal(stored(w, KEYREF), true);
});

// ------------------------------------------------------------------------------------------------------ the owner path

test('KBOX-62 owner path: one notice and push A naming the key and its platform (no value), no platform end call; erased once the evidence says revoked twice', async (t) => {
  const w = await deleteWorld(t);
  const { keyref, value } = await w.addPasted('PASTE_KEY');
  const id = await w.approveDelete(keyref);
  assert.deepEqual(revokes(w), [], 'nobody but the owner can end it');
  assert.deepEqual(pushes(w), ['End the key PASTE_KEY on pasted; the box erases its copy once it stops working.']);
  assert.ok(!pushes(w).some((p) => p.includes(value) || p.includes(value.slice(0, 8))), 'no value or prefix');
  assert.equal(notices(w).length, 1);
  await w.pass(10 * MINUTE);
  assert.equal(stored(w, keyref), true, 'still works: not erased');
  w.platform.pasted.delete(value);
  await w.pass(2 * HOUR, MINUTE);
  assert.equal(stored(w, keyref), false);
  assert.equal(w.resultOf(id).result, 'done');
  assert.equal(notices(w).length, 1, 'still one notice');
  assert.equal(pushes(w).length, 1, 'push B never followed push A');
});

test('KBOX-62 an owner who never ends it: hourly checks, one notice, the approval approved with no result, and GET /api/meta shows deleting', async (t) => {
  const w = await deleteWorld(t);
  const { keyref } = await w.addPasted('PASTE_KEY');
  const id = await w.approveDelete(keyref);
  await w.pass(3 * DAY, HOUR);
  assert.equal(notices(w).length, 1);
  assert.deepEqual(w.resultOf(id), { status: 'approved', result: null, code: null });
  const control = w.token('mc', 'control');
  const meta = JSON.parse((await w.call('/api/meta', { token: control })).body) as { keys: { keyref: string; status: string }[] };
  assert.equal(meta.keys.find((k) => k.keyref === keyref)?.status, 'deleting');
  assert.equal(meta.keys.find((k) => k.keyref === w.masters.pasted)?.status, 'works', 'control: another key keeps its stored status');
});

// ------------------------------------------------------------------------------------------------------ masters and order

test('KBOX-62 a master in grace is deleted in strict order: its grace generation is revoked with its current value first, then the current one with itself', async (t) => {
  const w = await deleteWorld(t);
  const master = w.masters.fake;
  await inGrace(w, master);
  const [gen1, gen2] = w.rotation.store.gens(master);
  assert.ok(gen1 !== undefined && gen2 !== undefined);
  const current = w.platform.live.get(gen2.platformKeyId ?? '') ?? '';
  await w.approveDelete(master);
  assert.deepEqual(revokes(w), [`revoke ${gen1.platformKeyId} with ${current}`], 'only the grace generation is ended first');
  await w.pass(MINUTE);
  await w.pass(2 * MINUTE);
  assert.deepEqual(revokes(w), [`revoke ${gen1.platformKeyId} with ${current}`, `revoke ${gen2.platformKeyId} with ${current}`]);
  assert.equal(stored(w, master), false);
});

test('KBOX-62 a deleting master is no candidate: the platform has no master for a key at its location while it waits', async (t) => {
  const w = await deleteWorld(t);
  w.platform.answer = 200;
  await w.approveDelete(w.masters.fake);
  assert.deepEqual(w.source.master('fake', { region: 'eu' }, ['read']), { ok: false, code: 'no_master' });
  assert.equal(w.source.masters('fake').length, 0);
});

test('KBOX-62 ruling 3: a grace generation that cannot be confirmed leaves the current generation un-ended', async (t) => {
  const w = await deleteWorld(t);
  await w.addKey();
  await inGrace(w, KEYREF);
  const [gen1, gen2] = w.rotation.store.gens(KEYREF);
  assert.ok(gen1 !== undefined && gen2 !== undefined);
  w.platform.pasted.add(w.platform.live.get(gen1.platformKeyId ?? '') ?? '');
  await w.approveDelete(KEYREF);
  await w.pass(6 * HOUR, 5 * MINUTE);
  assert.ok(!revokes(w).some((r) => r.startsWith(`revoke ${gen2.platformKeyId} `)), 'the current generation was never ended');
  assert.equal(w.rotation.store.gen(KEYREF, 2)?.status, 'current');
  assert.equal(stored(w, KEYREF), true);
});

test('KBOX-62 a delete during a rotation grace supersedes the unleased run (audited), ends and erases both generations, and the rotation timer firing later changes nothing', async (t) => {
  const w = await deleteWorld(t);
  await w.addKey();
  const rotationRun = await inGrace(w, KEYREF);
  const id = await w.approveDelete(KEYREF);
  assert.equal(w.rotation.store.run(rotationRun)?.state, 'abandoned');
  assert.deepEqual(w.audits('key.delete_started').map((a) => a.detail), [{ run_id: ledger(w, id)?.run_id, live_gens: 2, superseded_run: rotationRun }]);
  await w.pass(10 * MINUTE);
  assert.equal(stored(w, KEYREF), false);
  assert.equal(revokes(w).length, 2);
  const audited = w.parts.audit.read(0).entries.length;
  await w.pass(25 * HOUR, HOUR);
  assert.equal(w.parts.audit.read(0).entries.length, audited, 'the rotation timer did nothing');
});

// ------------------------------------------------------------------------------------------------------ restarts and crashes

test('KBOX-62 ruling 2: a restart 10 s after the first dead verdict does not erase before the minute has passed', async (t) => {
  const w = await deleteWorld(t);
  await w.addKey();
  await w.approveDelete(KEYREF);
  await w.pass(10_000, 1000);
  await w.restart();
  assert.equal(stored(w, KEYREF), true, 'resume waited');
  await w.pass(49_000, 1000);
  assert.equal(stored(w, KEYREF), true, 'not before 60 s');
  await w.pass(1000, 1000);
  assert.equal(stored(w, KEYREF), false);
});

test('KBOX-62 a crash before open (approved, executor never ran): settle records failed/interrupted with one notice and opens nothing', async (t) => {
  const w = await deleteWorld(t);
  await w.addKey();
  const proposed = w.propose(del(KEYREF));
  w.parts.db.prepare("UPDATE approvals SET status = 'approved', decided_at = ? WHERE approval_id = ?").run(w.clock.now(), proposed.approval_id);
  await w.restart();
  assert.deepEqual(w.resultOf(proposed.approval_id), { status: 'approved', result: 'failed', code: 'interrupted' });
  assert.equal(w.events('box.notice').filter((n) => n['code'] === 'approval_interrupted').length, 1);
  assert.equal(ledger(w, proposed.approval_id), undefined);
  assert.equal(stored(w, KEYREF), true);
  await w.restart();
  assert.equal(w.events('box.notice').filter((n) => n['code'] === 'approval_interrupted').length, 1, 'a second start adds nothing');
});

for (const point of ['delete_opened', 'delete_end_called', 'delete_dead_seen', 'delete_confirmed'] as const) {
  test(`KBOX-62 a crash at ${point}: the next start resumes the deletion to the erase, and the approval is done only after it`, async (t) => {
    const w = await deleteWorld(t);
    await w.addKey();
    w.arm(point);
    const proposed = w.propose(del(KEYREF));
    const item = (await w.queue()).find((q) => q.approval_id === proposed.approval_id);
    assert.ok(item);
    await w.decide(item.approval_id, 'approve', w.proofFor(item));
    await w.pass(MINUTE);
    assert.ok(w.seen.includes(point), `the process died at ${point}`);
    assert.equal(w.resultOf(proposed.approval_id).result, null);
    const calls = w.platform.calls.length;
    await w.restart();
    if (point === 'delete_confirmed') assert.equal(w.platform.calls.length, calls, 'after the confirmed write, no further revoke or verify');
    await w.pass(5 * MINUTE);
    assert.equal(stored(w, KEYREF), false);
    assert.equal(w.resultOf(proposed.approval_id).result, 'done');
    assert.equal(revokes(w).length <= 2, true);
  });
}

test('KBOX-62 a crash after the vault loop: the next start completes the erase and the files are gone', async (t) => {
  const w = await deleteWorld(t);
  await w.addKey();
  w.arm('delete_vault_retired');
  const id = await w.approveDelete(KEYREF);
  await w.pass(MINUTE);
  assert.equal(stored(w, KEYREF), true, 'died before the erase transaction');
  assert.deepEqual(w.parts.vault.generations(KEYREF), []);
  await w.restart();
  assert.equal(stored(w, KEYREF), false);
  assert.equal(w.resultOf(id).result, 'done');
});

test('KBOX-62 a crash after the erase transaction: settle records the approval done with no notice', async (t) => {
  const w = await deleteWorld(t);
  await w.addKey();
  w.arm('delete_erased');
  const id = await w.approveDelete(KEYREF);
  await w.pass(MINUTE);
  assert.equal(stored(w, KEYREF), false);
  assert.equal(w.resultOf(id).result, null);
  const before = w.events('box.notice').length;
  await w.restart();
  assert.deepEqual(w.resultOf(id), { status: 'approved', result: 'done', code: 'ok' });
  assert.equal(w.events('box.notice').length, before);
});

test('KBOX-62 the release before ended the run (rollback): settle closes the ledger abandoned, keeps the key, and interrupts the approval once', async (t) => {
  const w = await deleteWorld(t);
  await w.addKey();
  w.platform.answer = 200;
  const id = await w.approveDelete(KEYREF);
  const runId = ledger(w, id)?.run_id ?? '';
  w.parts.db.prepare("UPDATE rotation_runs SET state = 'done' WHERE run_id = ?").run(runId);
  await w.restart();
  assert.equal(ledger(w, id)?.outcome, 'abandoned');
  assert.equal(stored(w, KEYREF), true);
  assert.deepEqual(w.resultOf(id), { status: 'approved', result: 'failed', code: 'interrupted' });
  assert.equal(w.events('box.notice').filter((n) => n['code'] === 'approval_interrupted').length, 1);
});

test('KBOX-62 ruling 6: when the release before already recorded the approval interrupted, settle still closes the ledger and sends no second notice', async (t) => {
  const w = await deleteWorld(t);
  await w.addKey();
  w.platform.answer = 200;
  const id = await w.approveDelete(KEYREF);
  const runId = ledger(w, id)?.run_id ?? '';
  w.parts.db.prepare("UPDATE rotation_runs SET state = 'done' WHERE run_id = ?").run(runId);
  w.parts.db.prepare("UPDATE approvals SET result = 'failed', result_code = 'interrupted' WHERE approval_id = ?").run(id);
  await w.restart();
  assert.equal(ledger(w, id)?.outcome, 'abandoned');
  assert.equal(w.events('box.notice').filter((n) => n['code'] === 'approval_interrupted').length, 0);
});

test('KBOX-62 ruling 6: a deletion step that throws sends the run its one step-failure notice and is tried again', async (t) => {
  const w = await deleteWorld(t);
  await w.addKey();
  w.platform.answer = 200;
  const id = await w.approveDelete(KEYREF);
  const runId = ledger(w, id)?.run_id ?? '';
  assert.deepEqual(w.events('rotation.old_key_still_on'), [], 'control: an unconfirmed step is no throw');
  w.flags.masterThrows = true;
  await w.pass(MINUTE);
  assert.deepEqual(w.events('rotation.old_key_still_on'), [{ run_id: runId, keyref: KEYREF, gen: 1 }]);
  w.flags.masterThrows = false;
  w.platform.answer = undefined;
  await w.pass(10 * MINUTE);
  assert.equal(stored(w, KEYREF), false, 'the retry went through');
  assert.equal(w.events('rotation.old_key_still_on').length, 1);
});

// ------------------------------------------------------------------------------------------------------ the erase

test('KBOX-62 a key re-added under the same keyref after the erase starts at generation 1', async (t) => {
  const w = await deleteWorld(t);
  await w.addKey();
  await w.approveDelete(KEYREF);
  await w.pass(MINUTE);
  assert.equal(stored(w, KEYREF), false);
  await w.addKey();
  assert.deepEqual(w.rotation.store.gens(KEYREF).map((g) => g.gen), [1]);
});

test('KBOX-62 a generation written between the vault loop and the erase transaction has its file deleted too', async (t) => {
  const hook: { at: ((point: Point) => Promise<void>) | undefined } = { at: undefined };
  const w = await deleteWorld(t, { checkpoint: (point) => hook.at?.(point) });
  await w.addKey();
  hook.at = (point) => {
    if (point === 'delete_vault_retired') {
      w.parts.vault.put(KEYREF, 7, Buffer.from(w.platform.value()));
      w.rotation.store.putGen({ keyref: KEYREF, gen: 7, status: 'pending', platformKeyId: null, location: {} });
    }
    return Promise.resolve();
  };
  await w.approveDelete(KEYREF);
  await w.pass(MINUTE);
  assert.equal(stored(w, KEYREF), false);
  assert.deepEqual(w.parts.vault.generations(KEYREF), []);
});

/** The tables of a meta.db with a foreign key to `keys` or a `keyref` column that are neither erased nor kept. */
function unlisted(db: DatabaseSync): readonly string[] {
  const tables = (db.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'").all() as { name: string }[]).map((r) => r.name);
  const named = tables.filter(
    (name) =>
      (db.prepare(`PRAGMA foreign_key_list(${JSON.stringify(name)})`).all() as { table: string }[]).some((f) => f.table === 'keys') ||
      (db.prepare(`PRAGMA table_info(${JSON.stringify(name)})`).all() as { name: string }[]).some((c) => c.name === 'keyref'),
  );
  return named.filter((name) => !(ERASED_TABLES as readonly string[]).includes(name) && !(KEPT_TABLES as readonly string[]).includes(name));
}

test('KBOX-62 every meta.db table that names a key is erased or kept, and a table added with a foreign key to keys is caught', async (t) => {
  const db = openMetaDatabase(join(await tempDir(t), 'meta.db'), seededRandom(3));
  t.after(() => db.close());
  assert.deepEqual(unlisted(db), []);
  db.exec('CREATE TABLE later_table (owner TEXT REFERENCES keys (keyref))');
  assert.deepEqual(unlisted(db), ['later_table']);
});

// ------------------------------------------------------------------------------------------------------ the schedule (KBOX-52)

test('KBOX-52 KBOX-62 a due key with a pending delete_key is held back by the tick: no run opens', async (t) => {
  const w = await deleteWorld(t);
  await w.addKey({ rotateEveryDays: 1 });
  w.propose(del(KEYREF));
  w.clock.advance(2 * DAY);
  w.rotation.tick();
  assert.equal(w.rotation.store.activeRunOf(KEYREF), undefined);
  await w.addKey({ keyref: 'fake/shop/DUE', name: 'DUE', rotateEveryDays: 1 });
  w.clock.advance(DAY);
  w.rotation.tick();
  assert.equal(w.rotation.store.activeRunOf('fake/shop/DUE')?.origin, 'schedule', 'control: a due key without one starts its run');
  await w.rotation.orchestrator.idle();
});

test('KBOX-52 KBOX-62 a key being deleted takes no staggering day: an admin key due the same day keeps its own day', async (t) => {
  const w = await deleteWorld(t);
  const admin = { scopeItems: ['admin'], class: 'admin' as const, rotateEveryDays: 30 };
  const a = await w.addKey({ ...admin, keyref: 'fake/shop/A_KEY', name: 'A_KEY' });
  const b = await w.addKey({ ...admin, keyref: 'fake/shop/B_KEY', name: 'B_KEY' });
  w.platform.answer = 200;
  await w.approveDelete(a);
  const rotations = (): number => (w.parts.db.prepare("SELECT count(*) AS n FROM approvals WHERE json_extract(action_json, '$.kind') = 'rotate_key' AND json_extract(action_json, '$.keyref') = ?").get(b) as { n: number }).n;
  w.clock.advance(29 * DAY + HOUR);
  w.rotation.tick();
  assert.equal(rotations(), 0, 'B is not moved a day earlier for A');
  w.clock.advance(DAY);
  w.rotation.tick();
  assert.equal(rotations(), 1, 'B opens on its own day');
  assert.equal(w.rotation.store.activeRunOf(a)?.origin, 'delete', 'A is still being deleted, and opened nothing');
});

// ------------------------------------------------------------------------------------------------------ the share file

test('KBOX-62 KBOX-33 the share file keeps an admin key while it is deleted and drops it after the erase, with a new version', async (t) => {
  const w = await deleteWorld(t);
  const keyref = await w.addKey({ keyref: 'fake/shop/ADMIN_KEY', name: 'ADMIN_KEY', scopeItems: ['admin'], class: 'admin' });
  const writer = createShareWriter({
    dir: join(await tempDir(t), 'share'),
    meta: w.parts.meta,
    signingKey: w.parts.share.signingKey,
    source: createMetaShareSource({ meta: w.parts.meta, values: w.parts.share.values, shapeOf: (platform) => (platform === 'fake' ? { prefix: 'fk-', alphabet: 'hex', coreLength: { min: 32, max: 32 }, random: true } : undefined), generations: (k: string) => w.rotation.store.gens(k) }),
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
    const envelope = JSON.parse(Buffer.from(writer.serve().bytes).toString('utf8')) as { body_b64: string };
    return (JSON.parse(Buffer.from(envelope.body_b64, 'base64').toString('utf8')) as { coverage: { name: string }[] }).coverage.map((c) => c.name);
  };
  assert.ok(names().includes('ADMIN_KEY'), 'control: listed before');
  w.platform.answer = 200;
  await w.approveDelete(keyref);
  await w.pass(5 * MINUTE);
  await writer.idle();
  assert.ok(names().includes('ADMIN_KEY'), 'still listed while the deletion waits');
  const during = writer.serve().version;
  w.platform.answer = undefined;
  await w.pass(10 * MINUTE);
  await writer.idle();
  assert.equal(stored(w, keyref), false);
  assert.ok(!names().includes('ADMIN_KEY'), 'gone after the erase');
  assert.ok(writer.serve().version > during);
});

// ------------------------------------------------------------------------------------------------------ evidence declarations

test('KBOX-62 KBOX-42 every probe a registry entry names as revoked evidence has a row in its probe report, so a misspelt probe never counts as proven', async () => {
  const root = fileURLToPath(new URL('..', import.meta.url));
  for (const entry of REGISTRY) {
    const report = (await readTextIfPresent(root, `docs/probes/${entry.id}.md`)) ?? '';
    for (const probe of [entry.revokedEvidence?.verifier?.probe, entry.revokedEvidence?.lister?.probe].filter((p): p is string => p !== undefined)) {
      assert.ok(report.split('\n').some((line) => line.startsWith(`| \`${probe}\``)), `${entry.id}: ${probe}`);
    }
  }
});

// --- re-pin of the retired erase test (revoke-proof, S-795 unit retire-revoke) ----------------------------------------------------------

const TABLES_NAMING_KEYREF = (db: DatabaseSync): readonly string[] =>
  (db.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name").all() as { name: string }[])
    .map((r) => r.name)
    .filter((name) => (db.prepare(`PRAGMA table_info(${JSON.stringify(name)})`).all() as { name: string }[]).some((c) => c.name === 'keyref'));

test('KBOX-62 after the erase no row names the key outside the ledger, no vault file of it is left (a file with no row included), its dead ids are in orphan_notices, and a reconcile listing them raises nothing (the hand-off generation retired by the proof watch)', async (t) => {
  const w = await deleteWorld(t);
  await w.addKey();
  await w.addKey({ keyref: 'fake/shop/OTHER', name: 'OTHER' });
  await inGrace(w, KEYREF);
  await w.pass(25 * HOUR, HOUR);
  const sweep = w.rotation.watch.run();
  await w.rotation.watch.idle();
  w.clock.advance(PROOF_GAP_MS);
  await sweep;
  assert.equal(w.rotation.store.gen(KEYREF, 1)?.status, 'retired', 'a hand-off generation the proof watch retired (KBOX-51 step 10 as amended)');
  await inGrace(w, KEYREF);
  w.parts.meta.putGrant(KEYREF, 'ws-1');
  w.parts.meta.putAllowRule(KEYREF, 'models-list');
  w.parts.meta.putDestination(KEYREF, { kind: 'workstation', target: 'workstation', readable_by: 'api' });
  w.parts.vault.put(KEYREF, 9, Buffer.from(w.platform.value()));
  const ids = w.rotation.store.gens(KEYREF).map((g) => g.platformKeyId);
  const ended = revokes(w).length;
  const id = await w.approveDelete(KEYREF);
  await w.pass(5 * MINUTE);
  assert.equal(stored(w, KEYREF), false);
  for (const table of TABLES_NAMING_KEYREF(w.parts.db)) {
    const n = (w.parts.db.prepare(`SELECT count(*) AS n FROM ${table} WHERE keyref = ?`).get(KEYREF) as { n: number }).n;
    assert.equal(n, table === 'key_deletions' ? 1 : 0, table);
  }
  assert.equal(count(w, 'SELECT count(*) AS n FROM rotation_receipts r LEFT JOIN rotation_runs u ON u.run_id = r.run_id WHERE u.run_id IS NULL'), 0);
  assert.deepEqual(w.parts.vault.generations(KEYREF), [], 'every file, the one with no generation row included');
  for (const gen of [1, 2, 9]) assert.throws(() => w.parts.vault.lend(KEYREF, gen));
  for (const pk of ids) assert.equal(w.rotation.store.firstOrphanNotice(pk ?? ''), false, `${pk} is in orphan_notices`);
  assert.deepEqual(w.audits('key.deleted').map((a) => a.detail), [{ run_id: ledger(w, id)?.run_id, platform: 'fake', gens: 3, destinations: 1 }]);
  assert.equal(revokes(w).length - ended, 2, 'the two live generations were ended, the retired one not');

  w.platform.extra.push({ platformKeyId: ids[0] ?? '', name: 'kbox_deleted', disabled: true }, { platformKeyId: 'pk-stranger', name: 'kbox_stranger' });
  await w.rotation.reconciler.run();
  assert.equal(w.events('box.notice').filter((n) => n['code'] === 'orphan_key').length, 1, 'only the never-known kbox_ key raises one');
});
