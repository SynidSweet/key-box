// KBOX-34, KBOX-15, KBOX-19: the routes that issue keys, rotate them, hand over retired values and deliver ordinary keys.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { bytesOf, canary } from './kit/index.ts';
import { ApiError } from '../src/pure/errors.ts';
import { PASTE_PLATFORM, routesWorld } from './support/routes-world.ts';
import type { RoutesWorld } from './support/routes-world.ts';

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

test('KBOX-15 a master scope is never issuable through POST /api/keys: refused, nothing issued, no approval', async (t) => {
  const w = await routesWorld(t);
  const reply = await w.api('/api/keys', { json: body({ scope: { items: ['master'] } }) });
  assert.equal(reply.status, 422);
  assert.deepEqual([errorOf(reply).code, errorOf(reply).detail?.code], ['rejected', 'master_not_issuable']);
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
  assert.equal(reply.status, 422, reply.body);
  // The master answer is `master_not_issuable` until the unit that turns it into a paste task (shared-2 U6); the floor is what this pins.
  assert.equal(errorOf(reply).detail?.code, 'master_not_issuable');
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
