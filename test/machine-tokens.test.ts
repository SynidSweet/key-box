// KBOX-11: machine tokens. The first control enrol rides a 10-minute window the owner opens by a signed operation; relay
// enrols are proposals whose words carry the label and the address seen; revocation is a signed operation; nothing is pinned
// to an address; the first use from a new network sends one push.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import type { TestContext } from 'node:test';
import { seededRandom } from './kit/index.ts';
import type { Quirks, SoftApprover } from './kit/approver.ts';
import { RP, approveWorld, challenges, wire } from './support/approve-world.ts';
import type { World } from './support/approve-world.ts';
import { route } from '../src/shell/http.ts';

const MINUTE = 60_000;
const sha = (s: string): string => createHash('sha256').update(s).digest('hex');
const rng = seededRandom(1101);
const freshToken = (): string => `kbt_${Buffer.from(rng.bytes(32)).toString('base64url')}`;

/** A relay-scope probe route: the core serves no /r/* itself, so this stands in for "a route a relay token may call". */
const relayProbe = route({ method: 'GET', path: '/api/test/relay', surface: 'api', scope: 'relay', handle: ({ actor }) => ({ json: { actor } }) });

const world = (t: TestContext) => approveWorld(t, { routes: [relayProbe] });

interface OpOptions {
  readonly approver?: SoftApprover;
  /** The label the proof is signed for, when it differs from the one sent. */
  readonly signedLabel?: string;
  readonly quirks?: Quirks;
  readonly noDevice?: boolean;
  readonly cookie?: string;
  readonly reuse?: Uint8Array;
}

async function op(w: World, kind: 'enrol_window_open' | 'token_revoke', label: string, o: OpOptions = {}) {
  const n = o.reuse ?? (await w.nonce('op'));
  const signed = { kind, label: o.signedLabel ?? label };
  const proof = wire(n, (o.approver ?? w.owner).prove(challenges.op(signed, n), RP, o.quirks));
  return {
    nonce: n,
    reply: await w.call('/app/op', { json: { op: { kind, label }, proof: o.noDevice === true ? { ...proof, device_signature: '' } : proof }, ...(o.cookie === undefined ? {} : { cookie: o.cookie }) }),
  };
}

const enrol = (w: World, token: string, label: string, scope: 'control' | 'relay', headers: Record<string, string> = {}) =>
  w.call('/api/enrol', { json: { token_sha256: sha(token), label, scope }, headers });

test('KBOX-11 a relay token is refused on /api control routes and a control token is refused on /r/*', async (t) => {
  const w = await world(t);
  const relay = w.token('rly-1', 'relay');
  const control = w.token('ctl-2', 'control');
  assert.equal((await w.call('/api/meta', { token: relay })).status, 403);
  assert.equal((await w.call('/api/proposals', { token: relay, json: { action: { kind: 'revoke_grant', keyref: 'openai/admin', machine: 'ws-1' } } })).status, 403);
  assert.equal((await w.call('/api/test/relay', { token: control })).status, 403, 'a relay-scope route refuses a control token');
  const onRelayPath = await w.call('/r/openai/v1/models', { token: control });
  assert.equal(onRelayPath.status, 403, onRelayPath.body);
  assert.equal((await w.call('/api/test/relay', { token: relay })).status, 200, 'control: the relay token works on its own surface');
});

test('KBOX-11 a control enrol with no window is refused and enrols nothing', async (t) => {
  const w = await world(t);
  const token = freshToken();
  assert.equal((await enrol(w, token, 'mc', 'control')).status, 403);
  assert.equal((await w.call('/api/meta', { token })).status, 401);
});

test('KBOX-11 the window takes a control enrol at 10 minutes, refuses one at 10 minutes plus 1 ms, and takes one enrol only', async (t) => {
  const w = await world(t);
  assert.equal((await op(w, 'enrol_window_open', 'mc')).reply.status, 200);
  w.clock.advance(10 * MINUTE);
  const first = freshToken();
  const accepted = await enrol(w, first, 'mc', 'control');
  assert.equal(accepted.status, 201, accepted.body);
  assert.equal((await w.call('/api/meta', { token: first })).status, 200);
  assert.equal((await op(w, 'token_revoke', 'mc')).reply.status, 200);
  const again = await enrol(w, freshToken(), 'mc', 'control');
  assert.equal(again.status, 403, `the window took its one enrol, even for its own label once that token is revoked: ${again.body}`);

  assert.equal((await op(w, 'enrol_window_open', 'mc3')).reply.status, 200);
  w.clock.advance(10 * MINUTE + 1);
  assert.equal((await enrol(w, freshToken(), 'mc3', 'control')).status, 403, 'the window is shut at 10 minutes plus 1 ms');
});

test('KBOX-11 a window opened for label X refuses a control enrol labelled Y and stays open for X', async (t) => {
  const w = await world(t);
  assert.equal((await op(w, 'enrol_window_open', 'mc')).reply.status, 200);
  assert.equal((await enrol(w, freshToken(), 'other', 'control')).status, 403);
  assert.equal((await enrol(w, freshToken(), 'mc', 'control')).status, 201);
});

test('KBOX-11 the view cookie alone cannot open the window or revoke a token, nor can a proof without the device signature', async (t) => {
  const w = await world(t);
  const control = w.token('ctl-2', 'control');
  const cookie = await w.view();
  assert.equal((await w.call('/app/op', { cookie, json: { op: { kind: 'enrol_window_open', label: 'mc' } } })).status, 400, 'no proof: refused by shape');
  assert.equal((await w.call('/app/op', { cookie, json: { op: { kind: 'token_revoke', label: 'ctl-2' } } })).status, 400);
  assert.equal((await op(w, 'enrol_window_open', 'mc', { cookie, noDevice: true })).reply.status, 403);
  assert.equal((await op(w, 'token_revoke', 'ctl-2', { cookie, noDevice: true })).reply.status, 403);
  assert.equal((await op(w, 'token_revoke', 'ctl-2', { quirks: { flags: 0x01 } })).reply.status, 403, 'user verification clear');
  assert.equal((await enrol(w, freshToken(), 'mc', 'control')).status, 403, 'no window was opened');
  assert.equal((await w.call('/api/meta', { token: control })).status, 200, 'the token still works');
});

test('KBOX-11 a revoke signed for label A cannot revoke label B, and a spent nonce cannot sign a second operation', async (t) => {
  const w = await world(t);
  const a = w.token('ctl-a', 'control');
  const b = w.token('ctl-b', 'control');
  assert.equal((await op(w, 'token_revoke', 'ctl-b', { signedLabel: 'ctl-a' })).reply.status, 403);
  assert.equal((await w.call('/api/meta', { token: b })).status, 200);
  const done = await op(w, 'token_revoke', 'ctl-a');
  assert.equal(done.reply.status, 200);
  assert.equal((await op(w, 'token_revoke', 'ctl-b', { reuse: done.nonce })).reply.status, 403, 'replayed nonce');
  assert.equal((await w.call('/api/meta', { token: b })).status, 200);
  assert.equal((await w.call('/api/meta', { token: a })).status, 401);
});

test('KBOX-11 a relay enrol from any address makes a proposal whose words carry the label and the address seen; X-Forwarded-For is ignored', async (t) => {
  const w = await world(t);
  const reply = await enrol(w, freshToken(), 'laptop', 'relay', { 'x-kb-client-ip': '198.51.100.23', 'x-forwarded-for': '192.0.2.99' });
  assert.equal(reply.status, 202, reply.body);
  assert.deepEqual(reply.json(), { status: 'pending' });
  const item = (await w.queue()).find((q) => q.kind === 'enrol');
  assert.ok(item);
  assert.ok(item.lines.includes('enrol laptop for relay (request seen from 198.51.100.23; the label and the address are not checked)'), item.lines.join('\n'));
  assert.equal(JSON.stringify(item).includes('192.0.2.99'), false);
});

test('KBOX-11 no address registry or pin exists: the machine record and the token record carry no address member', async (t) => {
  const w = await world(t);
  w.token('rly-1', 'relay');
  const machine = w.parts.meta.snapshot().machines.find((m) => m.label === 'rly-1');
  assert.ok(machine);
  assert.deepEqual(Object.keys(machine).sort(), ['enrolled_at', 'label', 'last_network', 'revoked', 'scope']);
  const record = w.core.tokens.tokenStore.tokens().find((r) => r.label === 'rly-1');
  assert.ok(record);
  assert.deepEqual(Object.keys(record).sort(), ['label', 'revoked', 'scope', 'tokenSha256']);
});

test('KBOX-11 an approved relay token works from two addresses on two networks', async (t) => {
  const w = await world(t);
  const token = freshToken();
  assert.equal((await enrol(w, token, 'laptop', 'relay', { 'x-kb-client-ip': '198.51.100.23' })).status, 202);
  const item = (await w.queue()).find((q) => q.kind === 'enrol');
  assert.ok(item);
  assert.equal((await w.decide(item.approval_id, 'approve', w.proofFor(item))).status, 200);
  assert.equal((await w.call('/api/test/relay', { token, ip: '198.51.100.23' })).status, 200);
  assert.equal((await w.call('/api/test/relay', { token, ip: '203.0.113.200' })).status, 200);
  assert.equal((await w.call(`/api/enrol/${sha(token)}`)).status, 200);
});

test('KBOX-11 the first use from a new network sends exactly one push naming the token; a second use from it sends none', async (t) => {
  const w = await world(t);
  const relay = w.token('rly-1', 'relay');
  const pushes = (): number => w.push.sent.filter((m) => m.kind === 'new_network').length;
  await w.call('/api/test/relay', { token: relay, ip: '198.51.100.23' });
  assert.equal(pushes(), 1);
  assert.ok(w.push.sent.at(-1)?.title.includes('rly-1'));
  await w.call('/api/test/relay', { token: relay, ip: '198.51.100.24' });
  assert.equal(pushes(), 1, 'the same /24 is the same network');
  await w.call('/api/test/relay', { token: relay, ip: '203.0.113.5' });
  assert.equal(pushes(), 2, 'another network sends one more');
});

test('KBOX-11 a revocation takes effect on the next request and opens no approval', async (t) => {
  const w = await world(t);
  const relay = w.token('rly-1', 'relay');
  assert.equal((await w.call('/api/test/relay', { token: relay })).status, 200);
  const before = (await w.queue()).length;
  assert.equal((await op(w, 'token_revoke', 'rly-1')).reply.status, 200);
  assert.equal((await w.call('/api/test/relay', { token: relay })).status, 401);
  assert.equal((await w.queue()).length, before);
});
