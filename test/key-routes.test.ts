// KBOX-34, KBOX-15, KBOX-19: the routes that issue keys, rotate them, hand over retired values and deliver ordinary keys.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { bytesOf, canary } from './kit/index.ts';
import { ApiError } from '../src/pure/errors.ts';
import { PASTE_PLATFORM, routesWorld } from './support/routes-world.ts';
import type { RoutesWorld } from './support/routes-world.ts';
import type { LocationProver } from '../src/ports/issuer.ts';
import type { KeyLocation } from '../src/ports/types.ts';
import type { PlatformSource } from '../src/shell/rotation-ports.ts';
import { issuerWith } from './fakes/platform-entry.ts';

const HOUR = 3600_000;
const KEYREF = 'fake/shop/OPENAI_KEY';
const body = (over: object = {}): object => ({ platform: 'fake', name: 'OPENAI_KEY', projects: ['shop'], scope: { items: ['read'] }, ...over });
const members = (reply: { json(): unknown }): string[] => Object.keys(reply.json() as object).sort();
const errorOf = (reply: { json(): unknown }): { code: string; detail?: { code?: string } } => (reply.json() as { error: { code: string; detail?: { code?: string } } }).error;

async function ordinaryWithDestinations(w: RoutesWorld) {
  return w.api('/api/keys', { json: body({ destinations: [{ kind: 'vercel_env', target: 'app-a' }, { kind: 'workstation', target: '' }], label: 'ws-1' }) });
}

test('KBOX-34 an ordinary key is created at once: 201 with keyref, class and status; it is pushed, shown in the metadata and granted to the label', async (t) => {
  const w = await routesWorld(t);
  const reply = await ordinaryWithDestinations(w);
  assert.equal(reply.status, 201, reply.body);
  assert.deepEqual(members(reply), ['class', 'keyref', 'status']);
  assert.deepEqual(reply.json(), { keyref: KEYREF, class: 'ordinary', status: 'works' });
  const key = w.parts.meta.snapshot().keys.find((k) => k.keyref === KEYREF);
  assert.deepEqual([key?.class, key?.status, key?.gen_current], ['ordinary', 'works', 1]);
  assert.deepEqual(key?.destinations.map((d) => [d.kind, d.target, d.readable_by]), [['vercel_env', 'app-a', 'runtime'], ['workstation', 'workstation', 'api']]);
  assert.equal(key?.schedule.grace_hours, 24, 'a runtime destination makes the default grace 24 h');
  assert.deepEqual(key?.grants, [{ machine: 'ws-1' }]);
  assert.equal(w.destination.heldAt('app-a', 'OPENAI_KEY'), Buffer.from(await bytesOf(w.parts.vault.lend(KEYREF, 1))).toString('utf8'));
  assert.ok(w.parts.events.after(0).some((e) => e.kind === 'key.changed' && e.data['keyref'] === KEYREF), 'a route-level key.changed (KBOX-19)');
  assert.equal(w.push.sent.filter((p) => p.kind !== 'new_network').length, 0, 'an ordinary key asks nobody');
});

test('KBOX-34 an ordinary key with only the workstation destination has a 1 h default grace', async (t) => {
  const w = await routesWorld(t);
  await w.api('/api/keys', { json: body({ destinations: [{ kind: 'workstation', target: '' }] }) });
  assert.equal(w.parts.meta.snapshot().keys.find((k) => k.keyref === KEYREF)?.schedule.grace_hours, 1);
});

test('KBOX-15 an ordinary request whose scope the adapter classes admin gets an admin key and an approval, and nothing is issued before it', async (t) => {
  const w = await routesWorld(t);
  const reply = await w.api('/api/keys', { json: body({ scope: { items: ['admin'] } }) });
  assert.equal(reply.status, 202);
  assert.deepEqual(members(reply), ['approval_id', 'class', 'keyref']);
  const answer = reply.json() as { class: string; approval_id: string };
  assert.equal(answer.class, 'admin');
  assert.equal((await w.platform.lister.list(w.platform.master())).length, 0, 'nothing issued');
  assert.equal(w.rotation.store.key(KEYREF), undefined);
  const queue = await w.queue();
  assert.deepEqual(queue.map((q) => [q.approval_id, q.kind]), [[answer.approval_id, 'add_key']]);
});

test('KBOX-15 an approved add_key issues the admin key, as admin, with the class never below the adapter classification', async (t) => {
  const w = await routesWorld(t);
  const execute = w.rotation.executors.add_key;
  assert.ok(execute);
  const action = { kind: 'add_key', platform: 'fake', name: 'OPENAI_KEY', projects: ['shop'], scope: { items: ['admin'] } } as const;
  assert.deepEqual(await execute({ approvalId: 'apr_x', revision: 1, action, requester: { kind: 'box' }, proof: undefined }), { result: 'done' });
  assert.equal(w.parts.meta.snapshot().keys.find((k) => k.keyref === KEYREF)?.class, 'admin');
  assert.equal((await w.platform.lister.list(w.platform.master())).length, 1);
  assert.deepEqual(await execute({ approvalId: 'apr_x', revision: 1, action, requester: { kind: 'box' }, proof: undefined }), { result: 'failed', reason: 'key_exists' });
});

test('KBOX-15 a master scope is never issued through POST /api/keys: a paste task, nothing issued, no approval', async (t) => {
  // Retitled: the title still said "refused" after U6's flip; as of the KBOX-34 ruling the answer is a paste task (202), the body is unchanged.
  const w = await routesWorld(t);
  const reply = await w.api('/api/keys', { json: body({ scope: { items: ['master'] } }) });
  // KBOX-34 (shared-2 U6): a master result opens a paste task (202) instead of the former `master_not_issuable`; still nothing is issued.
  assert.equal(reply.status, 202, reply.body);
  assert.deepEqual([(reply.json() as { class: string }).class, typeof (reply.json() as { paste_task_id: unknown }).paste_task_id], ['master', 'string']);
  assert.equal((await w.platform.lister.list(w.platform.master())).length, 0);
  assert.equal((await w.queue()).length, 0);
});

test('KBOX-34 an ordinary key on a paste-source platform is rejected (no_issuer); an admin one opens a paste task with no link in the answer', async (t) => {
  const w = await routesWorld(t);
  const ordinary = await w.api('/api/keys', { json: body({ platform: PASTE_PLATFORM, name: 'ANTHROPIC_KEY' }) });
  assert.equal(ordinary.status, 422);
  assert.equal(errorOf(ordinary).detail?.code, 'no_issuer');
  const admin = await w.api('/api/keys', { json: body({ platform: PASTE_PLATFORM, name: 'ANTHROPIC_KEY', scope: { items: ['admin'] } }) });
  assert.equal(admin.status, 202);
  assert.deepEqual(members(admin), ['class', 'keyref', 'paste_task_id']);
  assert.equal(admin.body.includes('http'), false);
});

test('KBOX-34 a request is refused with bad_request for each wrong member and nothing is created', async (t) => {
  const w = await routesWorld(t);
  const bad: readonly object[] = [
    body({ extra: 1 }),
    body({ name: 'lower' }),
    body({ name: '1KEY' }),
    body({ projects: [] }),
    body({ projects: 'shop' }),
    body({ scope: { items: [], more: [] } }),
    body({ destinations: [{ kind: 'carrier_pigeon', target: 'x' }] }),
    body({ destinations: 'app-a' }),
    body({ rotate_every_days: 0 }),
    body({ rotate_every_days: 1.5 }),
    { platform: 'fake' },
  ];
  for (const json of bad) assert.equal((await w.api('/api/keys', { json })).status, 400, JSON.stringify(json));
  assert.equal((await w.api('/api/keys', { json: body({ platform: 'unknown' }) })).status, 422);
  assert.equal((await w.api('/api/keys', { json: body({ destinations: [{ kind: 'gcp_secret', target: 'x' }] }) })).status, 422, 'a destination kind with no adapter');
  assert.equal(w.rotation.store.keys().length, 0);
});

test('KBOX-34 a key that exists is a conflict, and admin options on the key request are refused: they are approvals of their own', async (t) => {
  const w = await routesWorld(t);
  assert.equal((await w.api('/api/keys', { json: body() })).status, 201);
  assert.equal((await w.api('/api/keys', { json: body() })).status, 409);
  const admin = await w.api('/api/keys', { json: body({ name: 'ADMIN_KEY', scope: { items: ['admin'] }, rotate_every_days: 30 }) });
  assert.equal(admin.status, 422);
  assert.equal(errorOf(admin).detail?.code, 'use_approvals_for_options');
});

// --- rotations -----------------------------------------------------------------------------------------------------------

test('KBOX-34 POST /api/rotations: an ordinary key starts a run (201 run_id), a second is a conflict, an unknown key is not_found', async (t) => {
  const w = await routesWorld(t);
  await w.api('/api/keys', { json: body() });
  const reply = await w.api('/api/rotations', { json: { keyref: KEYREF } });
  assert.equal(reply.status, 201);
  assert.deepEqual(members(reply), ['run_id']);
  assert.equal(w.rotation.store.activeRunOf(KEYREF)?.runId, (reply.json() as { run_id: string }).run_id);
  assert.equal((await w.api('/api/rotations', { json: { keyref: KEYREF } })).status, 409);
  assert.equal((await w.api('/api/rotations', { json: { keyref: 'fake/none/X' } })).status, 404);
  assert.equal((await w.api('/api/rotations', { json: { keyref: KEYREF, extra: 1 } })).status, 400);
  await w.rotation.orchestrator.idle();
});

test('KBOX-34 and KBOX-7 POST /api/rotations for an admin key opens a rotate_key approval (202 approval_id), starts nothing, and an approved one starts the run', async (t) => {
  const w = await routesWorld(t);
  const execute = w.rotation.executors.add_key;
  assert.ok(execute);
  await execute({ approvalId: 'apr_x', revision: 1, action: { kind: 'add_key', platform: 'fake', name: 'OPENAI_KEY', projects: ['shop'], scope: { items: ['admin'] } }, requester: { kind: 'box' }, proof: undefined });
  const reply = await w.api('/api/rotations', { json: { keyref: KEYREF } });
  assert.equal(reply.status, 202);
  assert.deepEqual(members(reply), ['approval_id']);
  assert.equal(w.rotation.store.activeRunOf(KEYREF), undefined, 'nothing runs before the phone approves');
  assert.equal(w.parts.meta.snapshot().keys.find((k) => k.keyref === KEYREF)?.status, 'awaiting_approval');
  assert.deepEqual((await w.queue()).map((q) => q.kind), ['rotate_key']);
  const run = w.rotation.executors.rotate_key;
  assert.ok(run);
  const action = { kind: 'rotate_key', keyref: KEYREF } as const;
  assert.deepEqual(await run({ approvalId: 'apr_y', revision: 1, action, requester: { kind: 'box' }, proof: undefined }), { result: 'done' });
  assert.equal(w.rotation.store.activeRunOf(KEYREF)?.origin, 'approval');
  assert.deepEqual(await run({ approvalId: 'apr_y', revision: 1, action, requester: { kind: 'box' }, proof: undefined }), { result: 'failed', reason: 'run_exists' });
  assert.deepEqual(await run({ approvalId: 'apr_y', revision: 1, action: { kind: 'rotate_key', keyref: 'fake/none/X' }, requester: { kind: 'box' }, proof: undefined }), { result: 'failed', reason: 'unknown_key' });
  await w.rotation.orchestrator.idle();
});

test('KBOX-12 an approval alone cannot rotate a paste-source key: the executor says a paste is required', async (t) => {
  const w = await routesWorld(t);
  const run = w.rotation.executors.rotate_key;
  assert.ok(run);
  w.parts.meta.putKey({ keyref: 'p/k/K', platform: PASTE_PLATFORM, name: 'K', projects: ['k'], class: 'admin', status: 'works', gen_current: 1, schedule: { rotate_every_days: 90, grace_hours: 1, next_due_at: null, expires_at: null }, coverage: null, last_use_at: null });
  assert.deepEqual(await run({ approvalId: 'apr_y', revision: 1, action: { kind: 'rotate_key', keyref: 'p/k/K' }, requester: { kind: 'box' }, proof: undefined }), { result: 'failed', reason: 'paste_required' });
});

// --- deliveries ------------------------------------------------------------------------------------------------------------

test('KBOX-34 a delivery is listed, its value is the vault bytes every time until the ack, and it is gone after', async (t) => {
  const w = await routesWorld(t);
  await ordinaryWithDestinations(w);
  const list = await w.api('/api/deliveries');
  assert.equal(list.status, 200);
  const deliveries = (list.json() as { deliveries: { delivery_id: string; keyref: string; project: string; name: string; gen: number }[] }).deliveries;
  assert.equal(deliveries.length, 1);
  assert.deepEqual(Object.keys(deliveries[0] ?? {}).sort(), ['delivery_id', 'gen', 'keyref', 'name', 'project']);
  assert.deepEqual([deliveries[0]?.keyref, deliveries[0]?.project, deliveries[0]?.name, deliveries[0]?.gen], [KEYREF, 'shop', 'OPENAI_KEY', 1]);
  const id = deliveries[0]?.delivery_id ?? '';
  const first = await w.api(`/api/deliveries/${id}/value`);
  const second = await w.api(`/api/deliveries/${id}/value`);
  assert.equal(first.status, 200);
  assert.equal(first.headers['content-type'], 'application/octet-stream');
  assert.equal(first.body, Buffer.from(await bytesOf(w.parts.vault.lend(KEYREF, 1))).toString('utf8'));
  assert.equal(second.body, first.body, 'the retried delivery returns identical bytes');
  assert.ok(w.parts.events.after(0).some((e) => e.kind === 'delivery.ready' && e.data['delivery_id'] === id));
  assert.equal((await w.api(`/api/deliveries/${id}/ack`, { method: 'POST' })).status, 200);
  assert.equal((await w.api(`/api/deliveries/${id}/value`)).status, 404, 'refused after the ack');
  assert.deepEqual(((await w.api('/api/deliveries')).json() as { deliveries: unknown[] }).deliveries, []);
  assert.equal((await w.api('/api/deliveries/dlv_unknown/ack', { method: 'POST' })).status, 404);
  assert.equal((await w.api('/api/deliveries/dlv_unknown/value')).status, 404);
});

test('KBOX-34 the delivery value route refuses a key that is not ordinary with 403', async (t) => {
  const w = await routesWorld(t);
  const execute = w.rotation.executors.add_key;
  assert.ok(execute);
  await execute({ approvalId: 'apr_x', revision: 1, action: { kind: 'add_key', platform: 'fake', name: 'OPENAI_KEY', projects: ['shop'], scope: { items: ['admin'] } }, requester: { kind: 'box' }, proof: undefined });
  w.rotation.store.putDelivery({ deliveryId: 'dlv_planted', keyref: KEYREF, project: 'shop', name: 'OPENAI_KEY', gen: 1, createdAt: w.clock.now() });
  assert.equal((await w.api('/api/deliveries/dlv_planted/value')).status, 403);
});

test('KBOX-34 a delivery nobody acknowledged past the key grace raises one notice, and never stalls the run', async (t) => {
  const w = await routesWorld(t);
  await ordinaryWithDestinations(w);
  w.clock.advance(24 * HOUR - 1);
  w.rotation.tick();
  assert.equal(w.parts.events.after(0).filter((e) => e.kind === 'box.notice').length, 0);
  w.clock.advance(1);
  w.rotation.tick();
  w.rotation.tick();
  const notices = w.parts.events.after(0).filter((e) => e.kind === 'box.notice');
  assert.equal(notices.length, 1);
  assert.deepEqual([notices[0]?.data['code'], notices[0]?.data['text']], ['delivery_unacked', 'delivery unacknowledged']);
});

// --- retired -----------------------------------------------------------------------------------------------------------------

const retiredPath = (name = 'OLD_KEY') => `/api/retired?platform=fake&project=shop&name=${name}`;

test('KBOX-34 and KBOX-2 a retired value passing the shape check is stored retired, never lent, in no response, and writes key.changed', async (t) => {
  const w = await routesWorld(t);
  const c = canary(16);
  const value = `fk-${Buffer.from(c.bytes).toString('hex')}`;
  const reply = await w.api(retiredPath(), { bytes: Buffer.from(value) });
  assert.equal(reply.status, 201, reply.body);
  assert.deepEqual(members(reply), ['coverage', 'gen', 'keyref']);
  assert.deepEqual([(reply.json() as { keyref: string }).keyref, (reply.json() as { gen: number }).gen], ['fake/shop/OLD_KEY', 1]);
  assert.throws(() => w.parts.vault.lend('fake/shop/OLD_KEY', 1), 'lend refuses a retired generation');
  assert.equal(w.rotation.store.gen('fake/shop/OLD_KEY', 1)?.status, 'retired');
  assert.ok(w.parts.events.after(0).some((e) => e.kind === 'key.changed' && e.data['keyref'] === 'fake/shop/OLD_KEY'));
  c.assertAbsent({ response: reply.body, events: JSON.stringify(w.parts.events.after(0)), audit: JSON.stringify(w.parts.audit.read(0).entries), meta: JSON.stringify(w.parts.meta.snapshot()), journal: w.journal.join('\n') });
});

test('KBOX-34 a retired value failing the shape check is stored uncovered (coverage none)', async (t) => {
  const w = await routesWorld(t);
  const reply = await w.api(retiredPath(), { bytes: Buffer.from('not-a-key-shape') });
  assert.equal(reply.status, 201);
  assert.equal((reply.json() as { coverage: string }).coverage, 'none');
});

test('KBOX-34 a retired body of 64 KiB is accepted and 64 KiB + 1 is too_large; a JSON content type is refused', async (t) => {
  const w = await routesWorld(t);
  assert.equal((await w.api(retiredPath(), { bytes: Buffer.alloc(64 * 1024, 0x61) })).status, 201);
  const big = await w.api(retiredPath('OTHER_KEY'), { bytes: Buffer.alloc(64 * 1024 + 1, 0x61) });
  assert.equal(big.status, 413);
  assert.equal(errorOf(big).code, 'too_large');
  assert.equal((await w.api(retiredPath('THIRD_KEY'), { bytes: Buffer.from('x'), contentType: 'application/json' })).status, 415);
  assert.equal((await w.api('/api/retired?platform=fake&project=shop', { bytes: Buffer.from('x') })).status, 400, 'the name is required');
});

for (const items of [['read'], ['admin']]) {
  test(`KBOX-51 POST /api/keys for a ${items.join('')} key on an overlap:false platform is refused with overlap_needs_paste: no key row, no approval`, async (t) => {
    const w = await routesWorld(t, { overlap: false });
    const reply = await w.api('/api/keys', { json: body({ scope: { items } }) });
    assert.equal(reply.status, 422, reply.body);
    assert.deepEqual([errorOf(reply).code, errorOf(reply).detail?.code], ['rejected', 'overlap_needs_paste']);
    assert.equal(w.parts.meta.snapshot().keys.length, 0);
    assert.deepEqual(await w.queue(), []);
  });
}

test('KBOX-51 an approved add_key on an overlap:false platform fails with overlap_needs_paste and writes no key', async (t) => {
  const w = await routesWorld(t, { overlap: false });
  const execute = w.rotation.executors.add_key;
  assert.ok(execute);
  const action = { kind: 'add_key', platform: 'fake', name: 'OPENAI_KEY', projects: ['shop'], scope: { items: ['admin'] } } as const;
  assert.deepEqual(await execute({ approvalId: 'apr_x', revision: 1, action, requester: { kind: 'box' }, proof: undefined }), { result: 'failed', reason: 'overlap_needs_paste' });
  assert.equal(w.parts.meta.snapshot().keys.length, 0);
});

test('KBOX-34 KBOX-40 a retired value for a paste-only platform (no issuer) is stored retired with the entry\'s class and its stated shape', async (t) => {
  const w = await routesWorld(t, { pasteOnly: true });
  const path = (name: string): string => `/api/retired?platform=pasteco&project=shop&name=${name}`;
  const fits = await w.api(path('OLD_KEY'), { bytes: Buffer.from(`pk-${'ab'.repeat(16)}`) });
  assert.equal(fits.status, 201, fits.body);
  assert.deepEqual(fits.json(), { keyref: 'pasteco/shop/OLD_KEY', gen: 1, coverage: null });
  assert.equal(w.rotation.store.gen('pasteco/shop/OLD_KEY', 1)?.status, 'retired');
  assert.equal(w.parts.meta.snapshot().keys.find((k) => k.keyref === 'pasteco/shop/OLD_KEY')?.class, 'ordinary');
  const misses = await w.api(path('OTHER_KEY'), { bytes: Buffer.from('not-a-key-shape') });
  assert.equal((misses.json() as { coverage: string }).coverage, 'none');
  assert.equal((await w.api('/api/retired?platform=nobody&project=shop&name=X_KEY', { bytes: Buffer.from('x') })).status, 422);
});

// --- placement (KBOX-57) and the class floor (KBOX-15) ---------------------------------------------------------------------------

const REF = 'abcdefghijabcdefghij';
const OTHER_REF = 'zzzzzzzzzzzzzzzzzzzz';
/** A fixture entry declaring `project` (a 20-letter ref, required of ordinary and admin keys), on both the api and the paste platform. */
const PROJECT_ENTRY = { project: { pattern: /[a-z]{20}/, requiredFor: ['ordinary', 'admin'] } } as const;
const rowsOf = (w: RoutesWorld, keyref: string): string =>
  JSON.stringify([w.parts.db.prepare('SELECT * FROM keys WHERE keyref = ?').all(keyref), w.parts.db.prepare('SELECT * FROM rotation_keys WHERE keyref = ?').all(keyref)]);
const opened = (w: RoutesWorld): number =>
  (w.parts.db.prepare('SELECT (SELECT count(*) FROM approvals) + (SELECT count(*) FROM paste_tasks) AS n').get() as { n: number }).n;

test('KBOX-57 POST /api/keys refuses each placement fault with its code at proposal, opening, issuing and writing nothing', async (t) => {
  const w = await routesWorld(t, { location: PROJECT_ENTRY });
  const cases: readonly [string, object][] = [
    ['location_field_unknown', body({ location: { region: 'us', project: REF } })],
    ['location_bad_value', body({ location: { project: 'short' } })],
    ['location_bad_value', body({ location: { project: `${REF}x` } })],
    ['location_missing', body()],
    ['location_missing', body({ platform: PASTE_PLATFORM, name: 'ANTHROPIC_KEY', scope: { items: ['admin'] } })],
    ['location_in_scope', body({ scope: { items: ['read', `project:${REF}`] }, location: { project: REF } })],
  ];
  for (const [code, json] of cases) {
    const reply = await w.api('/api/keys', { json });
    assert.equal(reply.status, 422, `${code}: ${reply.body}`);
    assert.deepEqual([errorOf(reply).code, errorOf(reply).detail?.code], ['rejected', code], JSON.stringify(json));
  }
  assert.equal((await w.api('/api/keys', { json: body({ location: {} }) })).status, 400, 'an empty location object is bad_request');
  assert.equal(w.parts.meta.snapshot().keys.length, 0);
  assert.equal(opened(w), 0);
  assert.deepEqual(w.issuedAt, []);
});

test('KBOX-57 an ordinary key is made at the location of the request and stores it; the issuer is handed exactly that location', async (t) => {
  const w = await routesWorld(t, { location: PROJECT_ENTRY });
  const reply = await w.api('/api/keys', { json: body({ location: { project: REF } }) });
  assert.equal(reply.status, 201, reply.body);
  assert.deepEqual(w.issuedAt, [{ project: REF }]);
  assert.deepEqual(w.rotation.store.keyInfo(KEYREF)?.location, { project: REF });
  assert.deepEqual(w.rotation.store.gen(KEYREF, 1)?.location, { project: REF }, 'the generation records the stored location when the answer names none');
});

test('KBOX-57 negative control: a key whose projects look like a valid location is never placed by them', async (t) => {
  const w = await routesWorld(t, { location: PROJECT_ENTRY });
  const missing = await w.api('/api/keys', { json: body({ projects: [REF] }) });
  assert.deepEqual([missing.status, errorOf(missing).detail?.code], [422, 'location_missing'], 'projects are no location');
  const placed = await w.api('/api/keys', { json: body({ projects: [REF], location: { project: OTHER_REF } }) });
  assert.equal(placed.status, 201, placed.body);
  assert.deepEqual(w.issuedAt, [{ project: OTHER_REF }]);
  assert.deepEqual(w.rotation.store.keyInfo(`fake/${REF}/OPENAI_KEY`)?.location, { project: OTHER_REF });
});

test('KBOX-15 a fixture entry classing master without a location and ordinary with one classes the key master: no issuer call, nothing made', async (t) => {
  const w = await routesWorld(t, { location: PROJECT_ENTRY, classifyAt: (_scope, at) => (at.project === undefined ? 'master' : 'ordinary') });
  const reply = await w.api('/api/keys', { json: body({ location: { project: REF } }) });
  // The master answer is a paste task (KBOX-34, shared-2 U6; it was `master_not_issuable`); the floor is what this pins: the class is master.
  assert.equal(reply.status, 202, reply.body);
  assert.deepEqual([(reply.json() as { class: string }).class, typeof (reply.json() as { paste_task_id: unknown }).paste_task_id], ['master', 'string']);
  assert.deepEqual(w.issuedAt, []);
  assert.equal(w.parts.meta.snapshot().keys.length, 0);
});

test('KBOX-15 a fixture entry classing admin only with a location classes the key admin: an approval, no issue before it', async (t) => {
  const w = await routesWorld(t, { location: PROJECT_ENTRY, classifyAt: (_scope, at) => (at.project === undefined ? 'ordinary' : 'admin') });
  const reply = await w.api('/api/keys', { json: body({ location: { project: REF } }) });
  assert.equal(reply.status, 202, reply.body);
  assert.equal((reply.json() as { class: string }).class, 'admin');
  assert.deepEqual(w.issuedAt, []);
  assert.deepEqual((await w.queue()).map((q) => q.kind), ['add_key']);
});

test('KBOX-57 POST /api/keys for a keyref that exists, at another location and a lower class, is key_exists on every branch and leaves its rows as they were', async (t) => {
  const w = await routesWorld(t, { location: PROJECT_ENTRY });
  const seed = (keyref: string, platform: string, name: string): void => {
    w.parts.meta.putKey({ keyref, platform, name, projects: ['shop'], class: 'master', status: 'works', gen_current: 1, schedule: { rotate_every_days: 90, grace_hours: 1, next_due_at: null, expires_at: null }, coverage: null, last_use_at: null });
    w.rotation.store.putKeyInfo(keyref, { scopeItems: ['master'], location: { project: REF }, rotatedAt: 1, markAdmin: false });
  };
  seed(KEYREF, 'fake', 'OPENAI_KEY');
  seed(`${PASTE_PLATFORM}/shop/ANTHROPIC_KEY`, PASTE_PLATFORM, 'ANTHROPIC_KEY');
  const before = [rowsOf(w, KEYREF), rowsOf(w, `${PASTE_PLATFORM}/shop/ANTHROPIC_KEY`)];
  const at = { location: { project: OTHER_REF } };
  const branches: readonly [string, object][] = [
    ['issued at once', body({ ...at })],
    ['an approval', body({ ...at, scope: { items: ['admin'] } })],
    ['a master', body({ ...at, scope: { items: ['master'] } })],
    ['a paste task', body({ ...at, platform: PASTE_PLATFORM, name: 'ANTHROPIC_KEY', scope: { items: ['admin'] } })],
    ['no issuer', body({ ...at, platform: PASTE_PLATFORM, name: 'ANTHROPIC_KEY' })],
  ];
  for (const [branch, json] of branches) {
    const reply = await w.api('/api/keys', { json });
    assert.deepEqual([reply.status, errorOf(reply).code, errorOf(reply).detail?.code], [409, 'conflict', 'key_exists'], branch);
  }
  assert.deepEqual([rowsOf(w, KEYREF), rowsOf(w, `${PASTE_PLATFORM}/shop/ANTHROPIC_KEY`)], before);
  assert.equal(opened(w), 0);
  assert.deepEqual(w.issuedAt, []);
});

test('KBOX-57 a retired-value record on a location-requiring entry is refused rotation (location_missing): no run, no approval', async (t) => {
  const w = await routesWorld(t, { location: PROJECT_ENTRY });
  assert.equal((await w.api(retiredPath(), { bytes: Buffer.from(`fk-${'ab'.repeat(16)}`) })).status, 201);
  const reply = await w.api('/api/rotations', { json: { keyref: 'fake/shop/OLD_KEY' } });
  assert.deepEqual([reply.status, errorOf(reply).code, errorOf(reply).detail?.code], [422, 'rejected', 'location_missing']);
  assert.equal(w.rotation.store.activeRunOf('fake/shop/OLD_KEY'), undefined);
  assert.equal(opened(w), 0);
  assert.throws(() => w.rotation.orchestrator.start({ keyref: 'fake/shop/OLD_KEY', origin: 'owner' }), (e: unknown) => e instanceof ApiError && JSON.stringify(e.detail) === JSON.stringify({ code: 'location_missing' }));
  assert.equal(w.rotation.store.runs().length, 0);
});

test('KBOX-57 an admin key whose stored location the entry now refuses is refused rotation at the route: no approval, its status unchanged', async (t) => {
  // The entry gains a project field after the key was made, so the key's stored (empty) location is now missing one an admin key needs.
  const strict = { on: false };
  const w = await routesWorld(t, {
    source: (real) => ({ ...real, platform: (id) => { const kit = real.platform(id); return kit === undefined || !strict.on ? kit : { ...kit, location: PROJECT_ENTRY }; } }),
  });
  const execute = w.rotation.executors.add_key;
  assert.ok(execute);
  await execute({ approvalId: 'apr_x', revision: 1, action: { kind: 'add_key', platform: 'fake', name: 'OPENAI_KEY', projects: ['shop'], scope: { items: ['admin'] } }, requester: { kind: 'box' }, proof: undefined });
  const status = w.parts.meta.snapshot().keys.find((k) => k.keyref === KEYREF)?.status;
  strict.on = true;
  const reply = await w.api('/api/rotations', { json: { keyref: KEYREF } });
  assert.equal(reply.status, 422, reply.body);
  assert.deepEqual([reply.status, errorOf(reply).code, errorOf(reply).detail?.code], [422, 'rejected', 'location_missing']);
  assert.equal(opened(w), 0);
  assert.equal(w.parts.meta.snapshot().keys.find((k) => k.keyref === KEYREF)?.status, status);
});

test('KBOX-57 the schedule skips a due key whose stored location the entry refuses: no run and no request, on this tick or the next', async (t) => {
  const w = await routesWorld(t, { location: PROJECT_ENTRY });
  assert.equal((await w.api(retiredPath(), { bytes: Buffer.from(`fk-${'ab'.repeat(16)}`) })).status, 201);
  // A current generation that falls due: the record above holds only a retired one.
  w.rotation.store.putGen({ keyref: 'fake/shop/OLD_KEY', gen: 2, status: 'current', platformKeyId: null, location: {} });
  w.clock.advance(91 * 24 * HOUR);
  w.rotation.tick();
  w.rotation.tick();
  assert.equal(w.rotation.store.runs().length, 0);
  assert.equal(opened(w), 0);
  const refused = w.parts.audit.read(0).entries.filter((e) => e.action === 'rotation.refused');
  assert.deepEqual(refused.map((e) => [e.ref, e.detail['code']]), [['fake/shop/OLD_KEY', 'location_missing']], 'one record per key and code');
});

test('KBOX-57 the schedule\'s skip of a due key whose stored location the entry refuses sends exactly one box.notice "rotation skipped" naming the code across ticks, and starts no run', async (t) => {
  const w = await routesWorld(t, { location: PROJECT_ENTRY });
  assert.equal((await w.api(retiredPath(), { bytes: Buffer.from(`fk-${'ab'.repeat(16)}`) })).status, 201);
  w.rotation.store.putGen({ keyref: 'fake/shop/OLD_KEY', gen: 2, status: 'current', platformKeyId: null, location: {} });
  w.clock.advance(91 * 24 * HOUR);
  w.rotation.tick();
  w.rotation.tick();
  w.rotation.tick();
  const notices = w.parts.events.after(0).filter((e) => e.kind === 'box.notice' && e.data['text'] === 'rotation skipped');
  assert.deepEqual(notices.map((e) => e.data['code']), ['location_missing'], 'one notice per key and code');
  assert.equal(w.rotation.store.runs().length, 0);
});

// --- the master at proposal and the host proof (KBOX-57) --------------------------------------------------------------------------

/** A fixture entry whose `project` names an upstream host (Supabase-like): a 20-letter ref, required of ordinary and admin keys. */
const HOST_ENTRY = { project: { pattern: /[a-z]{20}/, requiredFor: ['ordinary', 'admin'], namesHost: true } } as const;
const allRows = (w: RoutesWorld): string => JSON.stringify([w.parts.db.prepare('SELECT * FROM keys').all(), w.parts.db.prepare('SELECT * FROM rotation_keys').all()]);
const answering = (result: ReturnType<PlatformSource['master']>) => (real: PlatformSource): PlatformSource => ({ ...real, master: () => result });
const issuedCount = async (w: RoutesWorld): Promise<number> => (await w.platform.lister.list(w.platform.master())).length;

test('KBOX-57 where a proposal needs the master (a key the issuer makes by run), none is rejected no_master and two master_ambiguous: nothing proposed, opened, issued or written', async (t) => {
  for (const code of ['no_master', 'master_ambiguous'] as const) {
    const w = await routesWorld(t, { source: answering({ ok: false, code }) });
    const before = allRows(w);
    for (const json of [body(), body({ scope: { items: ['admin'] } })]) {
      const reply = await w.api('/api/keys', { json });
      assert.deepEqual([reply.status, errorOf(reply).code, errorOf(reply).detail?.code], [422, 'rejected', code], `${code}: ${reply.body}`);
    }
    assert.equal(allRows(w), before, 'the keys and rotation_keys rows are byte-identical');
    assert.equal(opened(w), 0, 'no approval and no paste task');
    assert.deepEqual(w.issuedAt, [], 'the issuer was never called');
    assert.equal(await issuedCount(w), 0);
    // Positive control: a paste platform without a prover needs no master, so the same answer opens its paste task.
    const paste = await w.api('/api/keys', { json: body({ platform: PASTE_PLATFORM, name: 'ANTHROPIC_KEY', scope: { items: ['admin'] } }) });
    assert.equal(paste.status, 202, paste.body);
  }
});

test('KBOX-57 an entry with a locationProver needs the master even for a paste key: none is rejected no_master before the prover is asked', async (t) => {
  const asked: KeyLocation[] = [];
  const prover: LocationProver = { prove: (at) => { asked.push(at); return Promise.resolve('seen'); } };
  const w = await routesWorld(t, { location: HOST_ENTRY, locationProver: prover, source: answering({ ok: false, code: 'no_master' }) });
  const before = allRows(w);
  const reply = await w.api('/api/keys', { json: body({ platform: PASTE_PLATFORM, name: 'ANTHROPIC_KEY', scope: { items: ['admin'] }, location: { project: REF } }) });
  assert.deepEqual([reply.status, errorOf(reply).detail?.code], [422, 'no_master'], reply.body);
  assert.deepEqual(asked, []);
  assert.equal(allRows(w), before);
  assert.equal(opened(w), 0);
});

test('KBOX-57 a host-naming location is proven with the chosen master before the proposal: unseen is rejected location_unknown, a prover that throws is unavailable, and neither writes or opens anything', async (t) => {
  const answer: { now: 'seen' | 'unseen' | 'throws' } = { now: 'unseen' };
  const asked: { readonly at: KeyLocation; readonly master: string }[] = [];
  const prover: LocationProver = {
    prove: async (at, master) => {
      asked.push({ at, master: Buffer.from(await bytesOf(master)).toString('utf8') });
      if (answer.now === 'throws') throw new Error('platform answered 500');
      return answer.now;
    },
  };
  const masterAsks: unknown[] = [];
  const w = await routesWorld(t, {
    location: HOST_ENTRY,
    locationProver: prover,
    source: (real) => ({ ...real, master: (platform, at, items) => { masterAsks.push([platform, at, items]); return real.master(platform, at, items); } }),
  });
  const located = { location: { project: REF } };
  const requests = [body(located), body({ ...located, scope: { items: ['admin'] } }), body({ ...located, platform: PASTE_PLATFORM, name: 'ANTHROPIC_KEY', scope: { items: ['admin'] } })];
  const before = allRows(w);
  for (const [now, status, code] of [['unseen', 422, 'location_unknown'], ['throws', 503, undefined]] as const) {
    answer.now = now;
    for (const json of requests) {
      const reply = await w.api('/api/keys', { json });
      assert.deepEqual([reply.status, errorOf(reply).detail?.code], [status, code], `${now}: ${reply.body}`);
    }
  }
  assert.equal(allRows(w), before, 'the keys and rotation_keys rows are byte-identical');
  assert.equal(opened(w), 0, 'no approval and no paste task');
  assert.deepEqual(w.issuedAt, []);
  const masterText = Buffer.from(w.platform.masterBytes).toString('utf8');
  assert.deepEqual(new Set(asked.map((a) => JSON.stringify(a))), new Set([JSON.stringify({ at: { project: REF }, master: masterText })]), 'every proof asked about the key\'s place with the chosen master');
  assert.deepEqual(masterAsks[0], ['fake', { project: REF }, ['read']], 'the master was chosen by the key\'s platform, location and scope items');
  answer.now = 'seen';
  const created = await w.api('/api/keys', { json: requests[0] });
  assert.equal(created.status, 201, created.body);
  assert.deepEqual(w.issuedAt, [{ project: REF }], 'the issuer made the key at the proven place');
  assert.equal((await w.api('/api/keys', { json: requests[2] })).status, 202, 'a proven paste key opens its paste task');
});

// --- master results and master rotations (KBOX-34, KBOX-57) --------------------------------------------------------------------------

const withoutVerifier = (real: PlatformSource): PlatformSource => ({
  ...real,
  platform: (id) => {
    const kit = real.platform(id);
    if (kit === undefined) return undefined;
    const { verifier, ...rest } = kit;
    void verifier;
    return rest;
  },
});
const MASTER = ['master'];
const pasteMaster = { platform: PASTE_PLATFORM, name: 'ANTHROPIC_KEY', scope: { items: MASTER } };

test('KBOX-34 a master result on an issuer platform, and on a paste platform, opens a paste task: class master, no issuer call, no approval', async (t) => {
  const w = await routesWorld(t);
  for (const json of [body({ scope: { items: MASTER } }), body(pasteMaster)]) {
    const reply = await w.api('/api/keys', { json });
    assert.equal(reply.status, 202, reply.body);
    assert.deepEqual(members(reply), ['class', 'keyref', 'paste_task_id']);
    assert.equal((reply.json() as { class: string }).class, 'master');
  }
  assert.deepEqual(w.issuedAt, [], 'no issuer call');
  assert.equal((await w.queue()).length, 0, 'no approval');
});

// As of the KBOX-58 L3 ruling an admin paste task on an entry with no verifier is refused at proposal too (no paste of it could ever settle).
test('KBOX-34 a master result on an entry with no verifier is rejected no_verifier: nothing opened, issued or written; an admin result on it is rejected too', async (t) => {
  const w = await routesWorld(t, { source: withoutVerifier });
  const before = allRows(w);
  for (const json of [body({ scope: { items: MASTER } }), body(pasteMaster)]) {
    const reply = await w.api('/api/keys', { json });
    assert.deepEqual([reply.status, errorOf(reply).code, errorOf(reply).detail?.code], [422, 'rejected', 'no_verifier'], reply.body);
  }
  assert.equal(allRows(w), before);
  assert.equal(opened(w), 0);
  assert.deepEqual(w.issuedAt, []);
  const admin = await w.api('/api/keys', { json: body({ platform: PASTE_PLATFORM, name: 'ANTHROPIC_KEY', scope: { items: ['admin'] } }) });
  // As of the KBOX-58 L3 ruling (was: 202, "only a master needs the verifier"):
  assert.deepEqual([admin.status, errorOf(admin).code, errorOf(admin).detail?.code], [422, 'rejected', 'no_verifier'], admin.body);
  assert.equal(opened(w), 0);
});

test('KBOX-34 a master result is a paste task even where the proposal-time master is missing: no master is needed to enter the first one', async (t) => {
  const w = await routesWorld(t, { source: answering({ ok: false, code: 'no_master' }) });
  const reply = await w.api('/api/keys', { json: body({ scope: { items: MASTER } }) });
  assert.equal(reply.status, 202, reply.body);
});

/** A key of `fake` made by the add_key executor (a run), stored with these scope items. */
async function storedFake(w: RoutesWorld, items: readonly string[]): Promise<void> {
  const execute = w.rotation.executors.add_key;
  assert.ok(execute);
  const action = { kind: 'add_key', platform: 'fake', name: 'OPENAI_KEY', projects: ['shop'], scope: { items } } as const;
  assert.deepEqual(await execute({ approvalId: 'apr_x', revision: 1, action, requester: { kind: 'box' }, proof: undefined }), { result: 'done' });
}
const selfRotating = (real: PlatformSource): PlatformSource => ({
  ...real,
  platform: (id) => {
    const kit = real.platform(id);
    return kit?.issuer === undefined ? kit : { ...kit, issuer: issuerWith(kit.issuer, { selfRotate: true }) };
  },
});
const statusOf = (w: RoutesWorld): string | undefined => w.parts.meta.snapshot().keys.find((k) => k.keyref === KEYREF)?.status;

test('KBOX-34 POST /api/rotations for a master key on an issuer that is not selfRotate opens a paste task, never an approval or a run; an approval alone cannot rotate it', async (t) => {
  const w = await routesWorld(t);
  await storedFake(w, MASTER);
  const reply = await w.api('/api/rotations', { json: { keyref: KEYREF } });
  assert.equal(reply.status, 202, reply.body);
  assert.deepEqual(members(reply), ['paste_task_id']);
  assert.equal(statusOf(w), 'awaiting_paste');
  assert.equal((await w.queue()).length, 0);
  assert.equal(w.rotation.store.activeRunOf(KEYREF), undefined);
  const run = w.rotation.executors.rotate_key;
  assert.ok(run);
  assert.deepEqual(await run({ approvalId: 'apr_y', revision: 1, action: { kind: 'rotate_key', keyref: KEYREF }, requester: { kind: 'box' }, proof: undefined }), { result: 'failed', reason: 'paste_required' });
});

test('KBOX-34 POST /api/rotations for a master key on a selfRotate issuer opens a rotate_key approval', async (t) => {
  const w = await routesWorld(t, { source: selfRotating });
  await storedFake(w, MASTER);
  const reply = await w.api('/api/rotations', { json: { keyref: KEYREF } });
  assert.equal(reply.status, 202, reply.body);
  assert.deepEqual(members(reply), ['approval_id']);
  assert.deepEqual((await w.queue()).map((q) => q.kind), ['rotate_key']);
});

/** A master answer a test can change: undefined lets the world's own master through. */
const swappable = (box: { result: ReturnType<PlatformSource['master']> | undefined }) => (real: PlatformSource): PlatformSource => ({ ...real, master: (p, at, items) => box.result ?? real.master(p, at, items) });

test('KBOX-57 POST /api/rotations asks the master first where the issuer makes the rotation by run: none is rejected no_master and two master_ambiguous, nothing opened', async (t) => {
  const box: { result: ReturnType<PlatformSource['master']> | undefined } = { result: undefined };
  for (const items of [['admin'], MASTER]) {
    for (const code of ['no_master', 'master_ambiguous'] as const) {
      box.result = undefined;
      const w = await routesWorld(t, { source: (real) => selfRotating(swappable(box)(real)) });
      await storedFake(w, items);
      const status = statusOf(w);
      box.result = { ok: false, code };
      const reply = await w.api('/api/rotations', { json: { keyref: KEYREF } });
      assert.deepEqual([reply.status, errorOf(reply).code, errorOf(reply).detail?.code], [422, 'rejected', code], `${items.join()} ${code}: ${reply.body}`);
      assert.equal(opened(w), 0, 'no approval and no paste task');
      assert.equal(statusOf(w), status, 'the status is unchanged');
    }
  }
});

test('KBOX-57 KBOX-34 a rotation made by paste needs no master: a master key on an issuer that is not selfRotate opens its paste task though the platform has none', async (t) => {
  const box: { result: ReturnType<PlatformSource['master']> | undefined } = { result: undefined };
  const w = await routesWorld(t, { source: swappable(box) });
  await storedFake(w, MASTER);
  box.result = { ok: false, code: 'no_master' };
  const paste = await w.api('/api/rotations', { json: { keyref: KEYREF } });
  assert.equal(paste.status, 202, paste.body);
  assert.deepEqual(members(paste), ['paste_task_id']);
});

test('KBOX-57 the schedule asks the master before it opens a request: a due admin key with none, or two, is skipped with one box.notice "rotation skipped" per key and code, and nothing is opened', async (t) => {
  const box: { result: ReturnType<PlatformSource['master']> | undefined } = { result: undefined };
  const w = await routesWorld(t, { source: swappable(box) });
  await storedFake(w, ['admin']);
  w.clock.advance(91 * 24 * HOUR);
  box.result = { ok: false, code: 'no_master' };
  w.rotation.tick();
  w.rotation.tick();
  box.result = { ok: false, code: 'master_ambiguous' };
  w.rotation.tick();
  w.rotation.tick();
  assert.equal(opened(w), 0);
  assert.equal(w.rotation.store.runs().length, 1, 'only the key\'s own first run');
  const notices = w.parts.events.after(0).filter((e) => e.kind === 'box.notice' && e.data['text'] === 'rotation skipped');
  assert.deepEqual(notices.map((e) => e.data['code']), ['no_master', 'master_ambiguous'], 'one notice per code');
  const refused = w.parts.audit.read(0).entries.filter((e) => e.action === 'rotation.refused');
  assert.deepEqual(refused.map((e) => [e.ref, e.detail['code']]), [[KEYREF, 'no_master'], [KEYREF, 'master_ambiguous']]);
  box.result = undefined;
  w.rotation.tick();
  assert.deepEqual((await w.queue()).map((q) => q.kind), ['rotate_key'], 'positive control: with a master the same key opens its approval');
});

test('KBOX-34 the schedule opens a paste task, not an approval, for a due master key on an issuer that is not selfRotate, with no master needed', async (t) => {
  const box: { result: ReturnType<PlatformSource['master']> | undefined } = { result: undefined };
  const w = await routesWorld(t, { source: swappable(box) });
  await storedFake(w, MASTER);
  w.clock.advance(91 * 24 * HOUR);
  box.result = { ok: false, code: 'no_master' };
  w.rotation.tick();
  assert.equal(opened(w), 1);
  assert.equal((await w.queue()).length, 0, 'not an approval');
  assert.equal(statusOf(w), 'awaiting_paste');
  assert.deepEqual(w.parts.events.after(0).filter((e) => e.kind === 'box.notice'), []);
});

test('KBOX-57 KBOX-34 POST /api/retired for a keyref that exists records the new generation at the key\'s stored location, not an empty one', async (t) => {
  const w = await routesWorld(t, { location: PROJECT_ENTRY });
  assert.equal((await w.api('/api/keys', { json: body({ projects: [REF], location: { project: REF } }) })).status, 201);
  const ref = `fake/${REF}/OPENAI_KEY`;
  assert.deepEqual(w.rotation.store.keyInfo(ref)?.location, { project: REF });
  const reply = await w.api(`/api/retired?platform=fake&project=${REF}&name=OPENAI_KEY`, { bytes: Buffer.from(`fk-${'cd'.repeat(16)}`) });
  assert.equal(reply.status, 201, reply.body);
  const added = w.rotation.store.gens(ref).at(-1);
  assert.deepEqual([added?.status, added?.location], ['retired', { project: REF }]);
  assert.deepEqual(w.rotation.store.keyInfo(ref)?.location, { project: REF }, 'the key\'s own record is unchanged');
});
