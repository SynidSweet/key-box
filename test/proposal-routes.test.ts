// KBOX-53: the proposal and enrol routes and the closed action kinds; the phone routes refuse a bearer token and every
// state-changing one refuses the view cookie alone; the approver-add registration code. KBOX-19: an executed grant or
// destination approval writes key.changed and shows in GET /api/meta.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import { softApprover } from './kit/approver.ts';
import type { SoftApprover } from './kit/approver.ts';
import { seededRandom } from './kit/index.ts';
import { RP, WORDLIST, approveWorld, challenges, registerAt, wire } from './support/approve-world.ts';
import type { World } from './support/approve-world.ts';
import { parseAction } from '../src/pure/actions.ts';

const MINUTE = 60_000;
const DAY = 24 * 60 * MINUTE;
const sha = (s: string): string => createHash('sha256').update(s).digest('hex');
const rng = seededRandom(5301);
const freshToken = (): string => `kbt_${Buffer.from(rng.bytes(32)).toString('base64url')}`;
const H64 = 'ab'.repeat(32);

type Json = Record<string, unknown>;

/** One valid action per kind POST /api/proposals takes, each on its own key so no two share a slot. */
const VALID: readonly Json[] = [
  { kind: 'delete_key', keyref: 'k-delete' },
  { kind: 'rotate_key', keyref: 'k-rotate' },
  { kind: 'grant', keyref: 'k-grant', machine: 'ws-1' },
  { kind: 'revoke_grant', keyref: 'k-revoke', machine: 'ws-1' },
  { kind: 'add_destination', keyref: 'k-adddest', destination: { kind: 'vercel_env', target: 'prj_1', environments: ['production', 'preview'] } },
  { kind: 'remove_destination', keyref: 'k-rmdest', destination: { kind: 'workstation', target: '' } },
  { kind: 'set_allow_rules', keyref: 'k-rules', rules: [{ op: 'fs_doc', params: { project: 'p1', database: 'd' } }] },
  { kind: 'set_schedule', keyref: 'k-sched', rotate_every_days: 30, grace_hours: 24 },
  { kind: 'demote', keyref: 'k-demote' },
  { kind: 'vercel_set_domain', project: 'shop', op: 'move', domain: 'shop.example.com', to_project: 'shop-2' },
  { kind: 'vercel_set_team_setting', setting: 'sensitiveEnvironmentVariablePolicy', value: 'on' },
  // FORCED-FLIP: approver_add is box-originated (KBOX-7), so no token proposes it; its refusal is pinned below.
];

/** Members that may be left out. */
const OPTIONAL = new Set(['environments', 'to_project']);

/** Each way one member can be wrong: the wrong type, a value no pattern takes, or missing when it is required. */
function wrongVariants(action: Json): [string, Json][] {
  const out: [string, Json][] = [[`${String(action['kind'])} with an unknown member`, { ...action, extra: 'x' }]];
  for (const member of Object.keys(action).filter((k) => k !== 'kind')) {
    const name = `${String(action['kind'])}.${member}`;
    const wrong: [string, unknown][] =
      typeof action[member] === 'number'
        ? [['as text', '30'], ['a fraction', 1.5], ['below the range', -1], ['above the range', 1e9]]
        : [['a number', 7], ['an array', ['x']], ['a text no pattern takes', 'a\nb'.repeat(150)]];
    for (const [how, value] of wrong) out.push([`${name} ${how}`, { ...action, [member]: value }]);
    if (!OPTIONAL.has(member)) {
      const { [member]: _gone, ...rest } = action;
      void _gone;
      out.push([`${name} missing`, rest]);
    }
  }
  return out;
}

const propose = (w: World, token: string, action: unknown, reason?: unknown) => w.call('/api/proposals', { token, json: reason === undefined ? { action } : { action, reason } });

test('KBOX-53 every proposal kind is accepted with valid members and answers exactly {approval_id, status, slot, revision, replaced}', async (t) => {
  const w = await approveWorld(t);
  const token = w.token('ctl-1', 'control');
  const second = await w.addApprover();
  for (const action of VALID) {
    const reply = await propose(w, token, action, { agent: 'claude', text: 'tidy up' });
    assert.equal(reply.status, 201, `${String(action['kind'])}: ${reply.body}`);
    const body = reply.json() as Json;
    assert.deepEqual(Object.keys(body).sort(), ['approval_id', 'replaced', 'revision', 'slot', 'status'], String(action['kind']));
    assert.match(String(body['approval_id']), /^apr_[A-Za-z0-9_-]{16}$/);
    assert.equal(body['status'], 'pending');
    assert.equal(body['replaced'], false);
    assert.equal(typeof body['revision'], 'number');
    assert.equal(typeof body['slot'], 'string');
  }
  assert.equal((await propose(w, token, { kind: 'approver_remove', approver_id: second.approverId })).status, 201);
});

test('KBOX-7 approver_add is box-originated: a control token proposing one, with any key hashes, is bad_request and nothing is proposed', async (t) => {
  const w = await approveWorld(t);
  const token = w.token('ctl-1', 'control');
  const reply = await propose(w, token, { kind: 'approver_add', cose_sha256: 'e'.repeat(64), device_sha256: 'f'.repeat(64) }, { agent: 'claude', text: 'add my phone' });
  assert.equal(reply.status, 400, reply.body);
  assert.deepEqual(await w.queue(), []);
});

test('KBOX-53 each member of each kind is refused when wrong, missing or joined by an unknown member, and nothing is proposed', async (t) => {
  const w = await approveWorld(t);
  const token = w.token('ctl-1', 'control');
  const cases = [...VALID, { kind: 'approver_remove', approver_id: 'ap-AAAAAAAAAA' }].flatMap(wrongVariants);
  assert.ok(cases.length > 60, `cases: ${cases.length}`);
  for (const [name, action] of cases) assert.equal((await propose(w, token, action)).status, 400, name);
  assert.equal((await w.queue()).length, 0);
});

test('KBOX-53 the destination and rules shapes: each accepted form, and each member wrong', async (t) => {
  const w = await approveWorld(t);
  const token = w.token('ctl-1', 'control');
  const dest = (destination: unknown) => ({ kind: 'add_destination', keyref: 'k', destination });
  for (const d of [{ kind: 'gcp_secret', target: 'projects/p/secrets/s' }, { kind: 'supabase_secret', target: 'proj_x' }, { kind: 'workstation', target: '' }, { kind: 'vercel_env', target: 'prj_1', environments: ['development'] }]) {
    assert.equal(parseAction(dest(d)).ok, true, JSON.stringify(d));
  }
  const badDestinations: [string, unknown][] = [
    ['kind outside the list', { kind: 'ftp', target: 'x' }],
    ['workstation with a target', { kind: 'workstation', target: 'laptop' }],
    ['vercel_env without a target', { kind: 'vercel_env', target: '' }],
    ['an unknown environment', { kind: 'vercel_env', target: 'prj', environments: ['staging'] }],
    ['an empty environments list', { kind: 'vercel_env', target: 'prj', environments: [] }],
    ['a repeated environment', { kind: 'vercel_env', target: 'prj', environments: ['preview', 'preview'] }],
    ['an unknown member', { kind: 'vercel_env', target: 'prj', team: 't' }],
    ['not an object', 'vercel_env:prj'],
  ];
  for (const [name, d] of badDestinations) assert.equal((await propose(w, token, dest(d))).status, 400, name);
  const rules = (r: unknown) => ({ kind: 'set_allow_rules', keyref: 'k', rules: r });
  assert.equal(parseAction(rules([])).ok, true, 'an empty rule list');
  const badRules: [string, unknown][] = [
    ['op not a name', [{ op: 'Fs Doc', params: {} }]],
    ['a param that is not text', [{ op: 'fs_doc', params: { project: 1 } }]],
    ['a param name outside the pattern', [{ op: 'fs_doc', params: { 'Project-Id': 'p' } }]],
    ['an unknown member of a rule', [{ op: 'fs_doc', params: {}, note: 'x' }]],
    ['a rule without params', [{ op: 'fs_doc' }]],
    ['not a list', { op: 'fs_doc', params: {} }],
  ];
  for (const [name, r] of badRules) assert.equal((await propose(w, token, rules(r))).status, 400, name);
});

test('KBOX-53 the add_key scope shape is {items:[text]} with each item [A-Za-z0-9_.:/-]{1,128}', () => {
  const addKey = (scope: unknown) => ({ kind: 'add_key', platform: 'openai', name: 'OPENAI_API_KEY', projects: ['shop'], scope });
  assert.equal(parseAction(addKey({ items: ['model.request', 'files:read'] })).ok, true);
  assert.equal(parseAction(addKey({ items: [] })).ok, true);
  assert.equal(parseAction(addKey({ items: ['x'.repeat(128)] })).ok, true);
  for (const [name, scope] of [
    ['an item of 129', { items: ['x'.repeat(129)] }],
    ['an empty item', { items: [''] }],
    ['a space', { items: ['a b'] }],
    ['a number item', { items: [1] }],
    ['an unknown member', { items: [], extra: 1 }],
    ['a bare list', ['a']],
  ] as const) {
    assert.equal(parseAction(addKey(scope)).ok, false, name);
  }
});

test('KBOX-53 add_key, install_update, enrol and a kind outside the list are refused on /api/proposals', async (t) => {
  const w = await approveWorld(t);
  const token = w.token('ctl-1', 'control');
  const refused: Json[] = [
    { kind: 'add_key', platform: 'openai', name: 'OPENAI_API_KEY', projects: ['shop'], scope: { items: [] } },
    { kind: 'install_update', install: H64, commit: 'ab'.repeat(20), base: H64 },
    { kind: 'enrol', label: 'laptop', token_sha256: H64, address: '198.51.100.1' },
    { kind: 'drop_table' },
  ];
  for (const action of refused) {
    assert.equal(parseAction(action).ok, action['kind'] !== 'drop_table', `control: ${String(action['kind'])} is a well-formed action elsewhere`);
    assert.equal((await propose(w, token, action)).status, 400, String(action['kind']));
  }
});

test('KBOX-53 removing the last approver is rejected (422)', async (t) => {
  const w = await approveWorld(t);
  const reply = await propose(w, w.token('ctl-1', 'control'), { kind: 'approver_remove', approver_id: w.ownerId });
  assert.equal(reply.status, 422, reply.body);
});

test('KBOX-53 the three enrol cases: control in its window (201 with the share key), control without one (403), relay (202, one proposal per source address)', async (t) => {
  const w = await approveWorld(t);
  const n = await w.nonce('op');
  const op = { kind: 'enrol_window_open', label: 'mc' } as const;
  assert.equal((await w.call('/app/op', { json: { op, proof: wire(n, w.owner.prove(challenges.op(op, n), RP)) } })).status, 200);
  const active = await w.call('/api/enrol', { json: { token_sha256: sha(freshToken()), label: 'mc', scope: 'control' } });
  assert.equal(active.status, 201, active.body);
  const body = active.json() as Json;
  assert.deepEqual(Object.keys(body).sort(), ['share_public_key_ed25519_b64', 'status']);
  assert.equal(body['status'], 'active');
  assert.equal(body['share_public_key_ed25519_b64'], w.parts.meta.snapshot().box.share_public_key_ed25519_b64);
  assert.equal((await w.call('/api/enrol', { json: { token_sha256: sha(freshToken()), label: 'mc-2', scope: 'control' } })).status, 403);
  const enrolRelay = (label: string, ip: string) => w.call('/api/enrol', { ip, json: { token_sha256: sha(freshToken()), label, scope: 'relay' } });
  const first = await enrolRelay('laptop', '198.51.100.7');
  assert.equal(first.status, 202);
  assert.deepEqual(first.json(), { status: 'pending' });
  assert.equal((await enrolRelay('laptop-b', '198.51.100.7')).status, 202);
  assert.equal((await enrolRelay('desk', '203.0.113.50')).status, 202);
  const enrols = (await w.queue()).filter((q) => q.kind === 'enrol');
  assert.equal(enrols.length, 2, 'the second enrol from the same address replaced the first');
  assert.ok(enrols.some((q) => q.lines.some((l) => l.startsWith('enrol laptop-b for relay'))));
  assert.equal(enrols.some((q) => q.lines.some((l) => l.startsWith('enrol laptop for relay'))), false);
});

test('KBOX-53 an enrol body is closed: a hash not 64 lower hex, a bad label, an unknown scope or member is refused; a label in use is a conflict', async (t) => {
  const w = await approveWorld(t);
  w.token('taken', 'relay');
  const enrol = (body: Json) => w.call('/api/enrol', { json: body });
  const good = { token_sha256: H64, label: 'laptop', scope: 'relay' };
  for (const [name, body] of [
    ['63 hex', { ...good, token_sha256: H64.slice(1) }],
    ['65 hex', { ...good, token_sha256: `${H64}a` }],
    ['upper-case hex', { ...good, token_sha256: H64.toUpperCase() }],
    ['not hex', { ...good, token_sha256: 'zz'.repeat(32) }],
    ['a label with upper case', { ...good, label: 'Laptop' }],
    ['a label of 33', { ...good, label: 'a'.repeat(33) }],
    ['scope admin', { ...good, scope: 'admin' }],
    ['an unknown member', { ...good, address: '1.2.3.4' }],
  ] as const) {
    assert.equal((await enrol(body)).status, 400, name);
  }
  for (const sha of [H64.slice(1), H64.toUpperCase(), `${H64}0`]) assert.equal((await w.call(`/api/enrol/${sha}`)).status, 400, sha);
  assert.equal((await enrol({ ...good, label: 'taken' })).status, 409);
});

test('KBOX-53 the enrol status route answers {status} and nothing else: pending, approved, denied, expired; unknown is 404', async (t) => {
  const w = await approveWorld(t);
  const status = async (token: string) => {
    const reply = await w.call(`/api/enrol/${sha(token)}`);
    assert.equal(reply.status, 200, reply.body);
    const body = reply.json() as Json;
    assert.deepEqual(Object.keys(body), ['status']);
    return body['status'];
  };
  const tokens = [freshToken(), freshToken(), freshToken()] as const;
  const ips = ['198.51.100.1', '198.51.100.2', '198.51.100.3'];
  for (const [i, token] of tokens.entries()) assert.equal((await w.call('/api/enrol', { ip: ips[i] ?? '', json: { token_sha256: sha(token), label: `m-${i}`, scope: 'relay' } })).status, 202);
  assert.equal(await status(tokens[0]), 'pending');
  const items = (await w.queue()).filter((q) => q.kind === 'enrol');
  const itemOf = (label: string) => items.find((q) => q.lines.some((l) => l.startsWith(`enrol ${label} `)));
  const a = itemOf('m-0');
  const b = itemOf('m-1');
  assert.ok(a && b);
  assert.equal((await w.decide(a.approval_id, 'approve', w.proofFor(a))).status, 200);
  assert.equal((await w.decide(b.approval_id, 'deny', w.proofFor(b))).status, 200);
  assert.equal(await status(tokens[0]), 'approved');
  assert.equal(await status(tokens[1]), 'denied');
  w.clock.advance(14 * DAY + 1);
  w.core.approvals.sweep();
  assert.equal(await status(tokens[2]), 'expired');
  assert.equal((await w.call(`/api/enrol/${sha(freshToken())}`)).status, 404);
});

const PHONE_ROUTES: readonly [method: 'GET' | 'POST', path: string][] = [
  ['GET', '/'], ['GET', '/app.js'], ['GET', '/webauthn-client.js'], ['GET', '/sw.js'], ['GET', '/manifest.webmanifest'], ['GET', '/setup.js'], ['GET', '/recover.js'], ['GET', '/register.js'], ['GET', '/app.css'],
  ['GET', '/setup'], ['GET', '/recover'], ['GET', '/app/nonce?purpose=view'], ['GET', '/app/push-key'], ['GET', '/healthz'], ['GET', '/app/queue'],
  ['POST', '/setup'], ['POST', '/recover'], ['POST', '/recover/register'], ['POST', '/app/view'], ['POST', '/app/propose-approver-add'], ['POST', '/app/approve/apr_AAAAAAAAAAAAAAAA'], ['POST', '/app/deny/apr_AAAAAAAAAAAAAAAA'], ['POST', '/app/op'],
];

test('KBOX-53 KBOX-10 every phone route refuses a bearer token, a control token included', async (t) => {
  const w = await approveWorld(t, { noSetup: true });
  const token = w.token('ctl-1', 'control');
  for (const [method, path] of PHONE_ROUTES) {
    const reply = await w.call(path, method === 'POST' ? { token, json: {} } : { token });
    assert.equal(reply.status, 403, `${method} ${path}: ${reply.body}`);
  }
});

test('KBOX-53 KBOX-9 every state-changing phone route refuses the view cookie alone and changes nothing', async (t) => {
  const w = await approveWorld(t);
  const opened = w.propose({ kind: 'grant', keyref: 'openai/admin', machine: 'ws-1' });
  const cookie = await w.view();
  const before = JSON.stringify(await w.queue());
  for (const path of ['/setup', '/recover', '/recover/register', '/app/view', `/app/approve/${opened.approval_id}`, `/app/deny/${opened.approval_id}`, '/app/op']) {
    for (const json of [{}, { proof: {} }]) {
      const reply = await w.call(path, { cookie, json });
      assert.ok(reply.status === 400 || reply.status === 404, `${path} ${JSON.stringify(json)}: ${reply.status}`);
    }
  }
  const after = (await w.queue()).map((q) => ({ ...q, nonce_b64: '' }));
  assert.deepEqual(after, (JSON.parse(before) as typeof after).map((q) => ({ ...q, nonce_b64: '' })));
  assert.deepEqual(w.core.approvers.ids(), [w.ownerId]);
});

// FORCED-FLIP: as of the spec revision 4 the registration code is asked for from a view session, before any proposal; the
// new phone registers with it first and the box then proposes the approver_add naming its keys.
async function approvedAddCode(w: World): Promise<string> {
  const opened = await w.call('/app/propose-approver-add', { method: 'POST', cookie: await w.view() });
  assert.equal(opened.status, 201, opened.body);
  // FORCED-FLIP: as of the spec revision 4 this route answers the code itself; no approval is opened or approved for it.
  const code = (opened.json() as { registration_code?: string }).registration_code;
  assert.match(code ?? '', /^[a-z]+( [a-z]+){11}$/, 'twelve words');
  return code ?? '';
}

/** Approves the box's pending approver_add (the one the last registration opened). */
async function approvePendingAdd(w: World): Promise<void> {
  const item = (await w.queue()).find((q) => q.kind === 'approver_add');
  assert.ok(item);
  const reply = await w.decide(item.approval_id, 'approve', w.proofFor(item));
  assert.equal(reply.status, 200, reply.body);
}

test('KBOX-53 the approver-add registration code is valid at 10 minutes and once; refused at 10 minutes plus 1 ms and on second use', async (t) => {
  const w = await approveWorld(t);
  const code = await approvedAddCode(w);
  w.clock.advance(10 * MINUTE);
  assert.equal((await registerAt(w, '/recover/register', code, softApprover())).status, 201);
  assert.equal((await registerAt(w, '/recover/register', code, softApprover())).status, 403, 'second use');
  await approvePendingAdd(w);
  const late = await approvedAddCode(w);
  w.clock.advance(10 * MINUTE + 1);
  assert.equal((await registerAt(w, '/recover/register', late, softApprover())).status, 403, '10 minutes plus 1 ms');
  assert.equal(w.core.approvers.ids().length, 2);
});

/** The fingerprint as the spec states it, written here independently: 6 words over SHA-256(SHA-256(cose) ‖ SHA-256(device)). */
function fingerprintOf(cose: Uint8Array, device: Uint8Array): string {
  const digest = createHash('sha256').update(createHash('sha256').update(cose).digest()).update(createHash('sha256').update(device).digest()).digest();
  let bits = 0n;
  for (const b of digest.subarray(0, 9)) bits = (bits << 8n) | BigInt(b); // 72 bits, of which the first 66 are the words
  bits >>= 6n;
  return [5, 4, 3, 2, 1, 0].map((i) => WORDLIST[Number((bits >> BigInt(11 * i)) & 0x7ffn)]).join(' ');
}

test('KBOX-53 the fingerprint the new phone shows is the one its approver_add page shows beside "Compare with the new phone", and it changes with either key', async (t) => {
  const w = await approveWorld(t);
  const a = softApprover();
  const b = softApprover();
  /** Registers a new phone whose passkey is `passkeyOf`'s and whose device key is `deviceOf`'s; the fingerprint it is shown. */
  const register = async (passkeyOf: SoftApprover, deviceOf: SoftApprover): Promise<string> => {
    const code = await approvedAddCode(w);
    const n = await w.nonce('register');
    const challenge = challenges.register(n);
    const parts = { ...passkeyOf.prove(challenge, RP), deviceSignature: deviceOf.deviceSign(challenge) };
    const approver = { credential_id: Buffer.from(passkeyOf.credentialId).toString('base64url'), cose_key: Buffer.from(passkeyOf.coseKey).toString('base64url'), device_public_key: Buffer.from(deviceOf.devicePublicKey).toString('base64url') };
    const reply = await w.call('/recover/register', { json: { code, approver, proof: wire(n, parts), phrase: 'blue kettle' } });
    assert.equal(reply.status, 201, reply.body);
    const shown = (reply.json() as { fingerprint: string }).fingerprint;
    const page = (await w.queue()).find((q) => q.kind === 'approver_add');
    assert.ok(page);
    assert.ok(page.lines.includes(`Compare with the new phone: ${shown}`), `the approving page shows the same words: ${page.lines.join(' | ')}`);
    return shown;
  };
  const both = await register(a, a);
  assert.equal(both, fingerprintOf(a.coseKey, a.devicePublicKey), 'the words are the spec\'s, over the keys registered');
  assert.match(both, /^[a-z]+( [a-z]+){5}$/, 'six words');
  const otherDevice = await register(a, b);
  const otherPasskey = await register(b, a);
  assert.notEqual(otherDevice, both, 'another device key, another fingerprint');
  assert.notEqual(otherPasskey, both, 'another passkey, another fingerprint');
  assert.notEqual(otherPasskey, otherDevice);
});

test('KBOX-53 a pending device (registered, its approver_add not yet approved) is refused at every approval and view route', async (t) => {
  const w = await approveWorld(t);
  const pending = softApprover();
  assert.equal((await registerAt(w, '/recover/register', await approvedAddCode(w), pending)).status, 201);
  const item = (await w.queue()).find((q) => q.kind === 'approver_add');
  assert.ok(item);
  const n = await w.nonce('view');
  assert.equal((await w.call('/app/view', { json: { proof: wire(n, pending.prove(challenges.view(n), RP)) } })).status, 403, 'view');
  for (const decision of ['approve', 'deny'] as const) {
    const reply = await w.call(`/app/${decision}/${item.approval_id}`, { json: { proof: w.proofFor(item, pending, undefined, decision) } });
    assert.equal(reply.status, 403, `${decision} of its own approver_add`);
  }
  const other = w.propose({ kind: 'grant', keyref: 'openai/admin', machine: 'ws-1' });
  const grant = (await w.queue()).find((q) => q.approval_id === other.approval_id);
  assert.ok(grant);
  assert.equal((await w.call(`/app/approve/${grant.approval_id}`, { json: { proof: w.proofFor(grant, pending) } })).status, 403, 'approve of another approval');
  const op = { kind: 'token_revoke', label: 'ctl-1' };
  const n2 = await w.nonce('op');
  assert.equal((await w.call('/app/op', { json: { op, proof: wire(n2, pending.prove(challenges.op(op, n2), RP)) } })).status, 403, 'signed operation');
  assert.deepEqual(w.core.approvers.ids(), [w.ownerId], 'trusted by nothing');

  const fresh = (await w.queue()).find((q) => q.kind === 'approver_add');
  assert.ok(fresh);
  assert.equal(((await w.decide(fresh.approval_id, 'approve', w.proofFor(fresh))).json() as { result: string }).result, 'done', 'control: the owner approves it');
  const n3 = await w.nonce('view');
  assert.equal((await w.call('/app/view', { json: { proof: wire(n3, pending.prove(challenges.view(n3), RP)) } })).status, 200, 'control: once approved it opens a view');
});

test('KBOX-19 an executed grant and an executed destination approval each write key.changed for the key and show in GET /api/meta', async (t) => {
  const w = await approveWorld(t);
  const control = w.token('ctl-1', 'control');
  w.parts.meta.putKey({ keyref: 'openai/admin', platform: 'openai', name: 'OPENAI_ADMIN_KEY', projects: ['shop'], class: 'admin', status: 'works', gen_current: 1, schedule: { rotate_every_days: 30, grace_hours: 24, next_due_at: null, expires_at: null }, coverage: 'anchored', last_use_at: null });
  w.token('ws-1', 'relay');
  for (const action of [{ kind: 'grant', keyref: 'openai/admin', machine: 'ws-1' }, { kind: 'add_destination', keyref: 'openai/admin', destination: { kind: 'gcp_secret', target: 'projects/p/secrets/s' } }]) {
    const head = w.parts.events.head();
    const proposed = (await propose(w, control, action)).json() as { approval_id: string };
    const item = (await w.queue()).find((q) => q.approval_id === proposed.approval_id);
    assert.ok(item);
    const reply = await w.decide(item.approval_id, 'approve', w.proofFor(item));
    assert.equal((reply.json() as { result: string }).result, 'done', reply.body);
    const changed = w.parts.events.after(head).filter((e) => e.kind === 'key.changed');
    assert.deepEqual(changed.map((e) => e.data), [{ keyref: 'openai/admin' }], action.kind);
  }
  const meta = (await w.call('/api/meta', { token: control })).json() as { keys: { keyref: string; grants: { machine: string }[]; destinations: { kind: string; target: string }[] }[] };
  const key = meta.keys.find((k) => k.keyref === 'openai/admin');
  assert.ok(key);
  assert.deepEqual(key.grants.map((g) => g.machine), ['ws-1']);
  assert.ok(key.destinations.some((d) => d.target === 'projects/p/secrets/s'));
});

test('KBOX-53 the approver-add registration code is shown to the approving phone only: absent from the databases, WAL, journal, audit and events', async (t) => {
  const w = await approveWorld(t);
  const code = await approvedAddCode(w);
  assert.equal((await registerAt(w, '/recover/register', code, softApprover())).status, 201);
  const surfaces: [string, string][] = readdirSync(w.stateDir).map((f) => [f, readFileSync(join(w.stateDir, f)).toString('latin1')]);
  surfaces.push(['journal', w.journal.join('\n')], ['audit', JSON.stringify(w.parts.audit.read(0).entries)], ['events', JSON.stringify(w.parts.events.after(0))], ['push', JSON.stringify(w.push.sent)]);
  const head = code.split(' ').slice(0, 3).join(' ');
  for (const [name, body] of surfaces) assert.equal(body.includes(code) || body.includes(head), false, `code in ${name}`);
});
