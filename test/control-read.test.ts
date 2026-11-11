// KBOX-30: the control read routes, GET /api/meta, GET /api/audit and GET /api/events shapes; KBOX-19 and KBOX-5 at route level.
import assert from 'node:assert/strict';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import type { TestContext } from 'node:test';
import { hashToken } from '../src/pure/tokens.ts';
import { openPrivateDatabase } from '../src/shell/private-db.ts';
import { canary, startCore } from './kit/index.ts';
import type { RunningCore } from './kit/index.ts';

/** The member set of an object is exactly `keys`: a new member fails the test that pins the response. */
const exactKeys = (value: unknown, keys: readonly string[], what: string): void => {
  assert.ok(typeof value === 'object' && value !== null && !Array.isArray(value), `${what} is an object`);
  assert.deepEqual(Object.keys(value).sort(), [...keys].sort(), what);
};

async function populated(t: TestContext): Promise<{ box: RunningCore; control: string; relay: string }> {
  const box = await startCore(t);
  const control = box.enrol('ctl-1', 'control');
  const relay = box.enrol('rly-1', 'relay');
  box.meta.putKey({
    keyref: 'openai/master',
    platform: 'openai',
    name: 'OPENAI_ADMIN_KEY',
    projects: ['shop'],
    class: 'admin',
    status: 'awaiting_approval',
    gen_current: 2,
    schedule: { rotate_every_days: 30, grace_hours: 24, next_due_at: 5000, expires_at: 9000 },
    coverage: 'windowed',
    last_use_at: 4000,
  });
  box.meta.putDestination('openai/master', { kind: 'vercel-env', target: 'prj_1', readable_by: 'runtime' });
  box.meta.putGrant('openai/master', 'rly-1');
  box.meta.putApproval({ approval_id: 'ap_1', kind: 'key_rotate', title: 'Rotate the OpenAI admin key', slot: 'admin-1', opened_at: 100, expires_at: 200 });
  // The first call from a network writes token.new_network; make it now so the tests below see only their own events.
  assert.equal((await box.call('/api/meta', { token: control })).status, 200);
  return { box, control, relay };
}

test('KBOX-30 GET /api/meta has exactly the members of the spec at every level', async (t) => {
  const { box, control } = await populated(t);
  const reply = await box.call('/api/meta', { token: control });
  assert.equal(reply.status, 200);
  const body = reply.json() as Record<string, unknown>;
  exactKeys(body, ['cursor', 'box', 'keys', 'machines', 'approvals'], 'meta');
  exactKeys(body['box'], ['release', 'share_version', 'share_public_key_ed25519_b64', 'oidc_issuer', 'epoch'], 'box');
  const keys = body['keys'] as Record<string, unknown>[];
  assert.equal(keys.length, 1);
  exactKeys(keys[0], ['keyref', 'platform', 'name', 'projects', 'class', 'status', 'gen_current', 'destinations', 'schedule', 'grants', 'allow_rules', 'coverage', 'last_use_at'], 'key');
  exactKeys((keys[0]?.['destinations'] as unknown[])[0], ['kind', 'target', 'readable_by'], 'destination');
  exactKeys(keys[0]?.['schedule'], ['rotate_every_days', 'grace_hours', 'next_due_at', 'expires_at'], 'schedule');
  exactKeys((keys[0]?.['grants'] as unknown[])[0], ['machine'], 'grant');
  const machines = body['machines'] as unknown[];
  assert.equal(machines.length, 2);
  for (const m of machines) exactKeys(m, ['label', 'scope', 'enrolled_at', 'revoked', 'last_network'], 'machine');
  const approvals = body['approvals'] as unknown[];
  exactKeys(approvals[0], ['approval_id', 'kind', 'title', 'slot', 'opened_at', 'expires_at'], 'approval');
  assert.deepEqual(keys[0]?.['projects'], ['shop']);
  assert.equal(keys[0]?.['class'], 'admin');
  assert.equal(keys[0]?.['coverage'], 'windowed');
  assert.match((body['box'] as { epoch: string }).epoch, /^[0-9a-f]{8}$/);
  assert.equal(body['cursor'], box.events.head());
});

test('KBOX-30 GET /api/audit returns {entries, cursor, more} of the rows after since, at most limit', async (t) => {
  const { box, control } = await populated(t);
  for (let i = 0; i < 4; i += 1) await box.call('/api/meta', { token: control });
  const all = (await box.call('/api/audit', { token: control })).json() as { entries: { seq: number }[]; cursor: number; more: boolean };
  exactKeys(all, ['entries', 'cursor', 'more'], 'audit');
  for (const entry of all.entries) exactKeys(entry, ['seq', 'at', 'actor', 'action', 'ref', 'detail', 'prev_hash', 'hash'], 'audit entry');
  assert.deepEqual(all.entries.map((e) => e.seq), [1, 2, 3, 4, 5]);
  assert.deepEqual([all.cursor, all.more], [5, false]);
  const page = (await box.call('/api/audit?since=1&limit=2', { token: control })).json() as typeof all;
  assert.deepEqual(page.entries.map((e) => e.seq), [2, 3]);
  assert.deepEqual([page.cursor, page.more], [3, true]);
  const rest = (await box.call(`/api/audit?since=${page.cursor}&limit=2`, { token: control })).json() as typeof all;
  assert.deepEqual(rest.entries.map((e) => e.seq).slice(0, 2), [4, 5]);
  const empty = (await box.call('/api/audit?since=999', { token: control })).json() as typeof all;
  assert.deepEqual(empty, { entries: [], cursor: 999, more: false });
  for (const query of ['limit=0', 'since=-1', 'since=a', 'limit=1.5', 'extra=1']) assert.equal((await box.call(`/api/audit?${query}`, { token: control })).status, 400, query);
});

test('KBOX-30 GET /api/events returns {events, cursor} with {seq, at, kind, data} per event', async (t) => {
  const { box, control } = await populated(t);
  const reply = (await box.call('/api/events?since=0', { token: control })).json() as { events: Record<string, unknown>[]; cursor: number };
  exactKeys(reply, ['events', 'cursor'], 'events');
  assert.equal(reply.events.length, box.events.head());
  for (const event of reply.events) exactKeys(event, ['seq', 'at', 'kind', 'data'], 'event');
  assert.equal(reply.cursor, box.events.head());
  assert.deepEqual(reply.events.map((e) => e['kind']), ['machine.changed', 'machine.changed', 'key.changed', 'key.changed', 'key.changed', 'token.new_network']);
  assert.equal(reply.events[0]?.['at'], 1_000_000);
});

test('KBOX-30 a revoked token and a relay-scope token are refused on every control read route', async (t) => {
  const { box, relay } = await populated(t);
  const revoked = box.enrol('old-1', 'control');
  box.meta.revokeMachine('old-1');
  for (const path of ['/api/meta', '/api/audit', '/api/events?since=0']) {
    assert.equal((await box.call(path, { token: relay })).status, 403, path);
    assert.equal((await box.call(path, { token: revoked })).status, 401, path);
    assert.equal((await box.call(path)).status, 401, path);
  }
});

test('KBOX-19 after a key, a destination and a grant change the next event is key.changed and GET /api/meta shows the change; the export has no private.db content', async (t) => {
  const { box, control } = await populated(t);
  const c = canary();
  const priv = openPrivateDatabase(join(box.stateDir, 'private.db'));
  t.after(() => priv.close());
  priv.addPushSubscription({ endpoint: `https://push.example/${Buffer.from(c.bytes).toString('base64url')}`, p256dh: Buffer.from(c.bytes).toString('base64'), auth: Buffer.from(c.bytes).toString('hex') });
  priv.addApprover({ approverId: 'owner-1', credentialId: Buffer.from(c.bytes).toString('base64url'), publicKey: Buffer.from(c.bytes).toString('latin1') });

  const head = box.events.head();
  box.meta.putKey({ keyref: 'openai/master', platform: 'openai', name: 'OPENAI_ADMIN_KEY', projects: ['shop'], class: 'admin', status: 'works', gen_current: 3, schedule: { rotate_every_days: 30, grace_hours: 24, next_due_at: null, expires_at: null }, coverage: 'anchored', last_use_at: null });
  const afterKey = (await box.call(`/api/events?since=${head}`, { token: control })).json() as { events: { kind: string; data: unknown }[] };
  assert.deepEqual(afterKey.events.map((e) => [e.kind, e.data]), [['key.changed', { keyref: 'openai/master' }]]);
  box.meta.putDestination('openai/master', { kind: 'google-secret-manager', target: 'projects/p/secrets/s', readable_by: 'api' });
  box.meta.putGrant('openai/master', 'ctl-1');
  const afterRest = (await box.call(`/api/events?since=${head + 1}`, { token: control })).json() as typeof afterKey;
  assert.deepEqual(afterRest.events.map((e) => e.kind), ['key.changed', 'key.changed']);
  const meta = (await box.call('/api/meta', { token: control })).json() as { cursor: number; keys: { gen_current: number; coverage: string; destinations: { kind: string }[]; grants: { machine: string }[] }[] };
  assert.equal(meta.keys[0]?.gen_current, 3);
  assert.equal(meta.keys[0]?.coverage, 'anchored');
  assert.deepEqual(meta.keys[0]?.destinations.map((d) => d.kind), ['google-secret-manager', 'vercel-env']);
  assert.deepEqual(meta.keys[0]?.grants.map((g) => g.machine), ['ctl-1', 'rly-1']);
  assert.equal(meta.cursor, head + 3);

  const bodies: string[] = [];
  for (const path of ['/api/meta', '/api/audit', '/api/events?since=0', '/api/nothing']) bodies.push((await box.call(path, { token: control })).body);
  c.assertAbsent({ responses: bodies.join('\n') });
});

test('KBOX-10 a token and its hash are in no response of the control routes', async (t) => {
  const { box, control } = await populated(t);
  const bodies: string[] = [];
  for (const path of ['/api/meta', '/api/audit', '/api/events?since=0']) bodies.push((await box.call(path, { token: control })).body);
  const all = bodies.join('\n');
  assert.equal(all.includes(control), false);
  assert.equal(all.includes(control.slice(4)), false);
  assert.equal(all.includes(hashToken(control)), false);
});

// --- KBOX-1: GET /api/bootstrap-facts ----------------------------------------------------------------------------------

const FACTS = '{"directories":[{"path":"/snap/oracle-cloud-agent","names":["plugins"]}],"found":{"paths":[],"processes":[]}}\n';

test('KBOX-1 GET /api/bootstrap-facts serves the facts file byte for byte as JSON to a control token, and refuses a relay token, a revoked token and no token', async (t) => {
  const { box, control, relay } = await populated(t);
  writeFileSync(join(box.stateDir, 'bootstrap-facts.json'), FACTS);
  const reply = await box.call('/api/bootstrap-facts', { token: control });
  assert.equal(reply.status, 200);
  assert.match(reply.headers['content-type'] ?? '', /^application\/json/);
  assert.equal(reply.body, FACTS);
  const revoked = box.enrol('old-2', 'control');
  box.meta.revokeMachine('old-2');
  assert.equal((await box.call('/api/bootstrap-facts', { token: relay })).status, 403);
  assert.equal((await box.call('/api/bootstrap-facts', { token: revoked })).status, 401);
  assert.equal((await box.call('/api/bootstrap-facts')).status, 401);
});

test('KBOX-1 GET /api/bootstrap-facts with no facts file answers 404 not_found with a closed detail, and a file that is not JSON answers 503, never 500', async (t) => {
  const { box, control } = await populated(t);
  const missing = await box.call('/api/bootstrap-facts', { token: control });
  assert.equal(missing.status, 404);
  assert.deepEqual(missing.json(), { error: { code: 'not_found', message: 'There is nothing here.', detail: { code: 'no_bootstrap_facts' } } });
  writeFileSync(join(box.stateDir, 'bootstrap-facts.json'), '{ half a file');
  const broken = await box.call('/api/bootstrap-facts', { token: control });
  assert.equal(broken.status, 503);
  assert.deepEqual((broken.json() as { error: { detail: unknown } }).error.detail, { code: 'bootstrap_facts_unreadable' });
});

test('KBOX-1 GET /api/bootstrap-facts takes no query and only GET', async (t) => {
  const { box, control } = await populated(t);
  writeFileSync(join(box.stateDir, 'bootstrap-facts.json'), FACTS);
  assert.equal((await box.call('/api/bootstrap-facts?x=1', { token: control })).status, 400);
  assert.ok([404, 405].includes((await box.call('/api/bootstrap-facts', { token: control, method: 'POST', json: true, body: '{}' })).status));
});
