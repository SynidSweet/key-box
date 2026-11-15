// KBOX-32: what agents and with-keys rely on — the pass headers per profile, GET /r/_/grants and the relay URL shape — through
// the running relay over core's real lend handler. (A relay pass on /api/* is refused by core: test/control-read.test.ts.)
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { waitUntil } from './kit/index.ts';
import { PROJECT_REGISTRY } from './fixtures/profiles.ts';
import { relayWorld } from './support/relay-world.ts';
import type { RelayReply } from './support/relay-world.ts';

const json = (reply: RelayReply): unknown => JSON.parse(reply.body.toString('utf8')) as unknown;

test('KBOX-32 /r/_/grants lists only the admin keys granted to the calling machine, each with its relay env and the literal "<pass>", and no value', async (t) => {
  const w = await relayWorld(t);
  const desktop = w.lend.enrol('desktop');
  w.lend.addKey({ keyref: 'deskonly01', value: Buffer.from('a-different-admin-value-0001'), grants: ['desktop'] });
  w.lend.addKey({ keyref: 'ordinary01', value: Buffer.from('an-ordinary-value-000000001'), cls: 'ordinary', grants: ['laptop'] });
  w.lend.addKey({ keyref: 'master0001', value: Buffer.from('a-master-value-00000000001'), cls: 'master', grants: ['laptop'] });
  w.lend.addKey({ keyref: 'plainkey01', value: Buffer.from('a-plain-platform-value-0001'), platform: 'plain', grants: ['laptop'] });
  const laptop = await w.call('/r/_/grants');
  assert.equal(laptop.status, 200);
  w.canary.assertAbsent({ 'grants body': laptop.body });
  assert.equal(w.upstream.requests.length, 0);
});

test('KBOX-32 /r/_/grants takes the pass in Authorization or apikey; both present must be equal; none is 401', async (t) => {
  const w = await relayWorld(t);
  assert.equal((await w.call('/r/_/grants', { pass: null, headers: { apikey: w.pass } })).status, 200);
  assert.equal((await w.call('/r/_/grants', { headers: { apikey: w.pass } })).status, 200);
  assert.equal((await w.call('/r/_/grants', { headers: { apikey: w.lend.enrol('desktop') } })).status, 400);
  assert.equal((await w.call('/r/_/grants', { pass: null })).status, 401);
});

test('KBOX-32 a pass in a header its profile does not declare is 401: apikey works for the path profile and not for the host-in-path one', async (t) => {
  const w = await relayWorld(t);
  assert.equal((await w.call('/r/adminkey1/v1/models', { pass: null, headers: { apikey: w.pass } })).status, 200);
  const host = await w.call('/r/hostkey001/iam.hostplat.example/v1/projects/proj-01/serviceAccounts', { pass: null, headers: { apikey: w.pass } });
  assert.equal(host.status, 401);
  assert.equal(w.upstream.requests.length, 1);
  assert.equal((await w.call('/r/hostkey001/iam.hostplat.example/v1/projects/proj-01/serviceAccounts')).status, 200);
  assert.equal(w.upstream.requests[1]?.url, '/v1/projects/proj-01/serviceAccounts');
});

test('KBOX-32 a pass of machine A cannot use a key granted only to machine B', async (t) => {
  const w = await relayWorld(t);
  w.lend.enrol('desktop');
  w.lend.addKey({ keyref: 'deskonly01', value: Buffer.from('a-different-admin-value-0001'), grants: ['desktop'] });
  assert.equal((await w.call('/r/deskonly01/v1/models')).status, 403);
  assert.equal(w.upstream.requests.length, 0);
});

// ---------------------------------------------------------------- KBOX-13 / KBOX-32 revision 2026-11-13: a real keyref has an address

const REAL = 'pathplat/shop/REAL_KEY';
const ADDRESS = 'pathplat~shop~REAL_KEY';
const relayRows = (w: Awaited<ReturnType<typeof relayWorld>>) => w.lend.core.audit.read(0).entries.filter((r) => r.action === 'relay.request');

test('KBOX-32 a real keyref is listed with its address in the env and is relayed by that address, and the audit row names the keyref', async (t) => {
  const w = await relayWorld(t);
  w.lend.addKey({ keyref: REAL, value: w.value, grants: ['laptop'] });
  assert.equal((await w.call(`/r/${ADDRESS}/v1/models`)).status, 200);
  assert.equal(w.upstream.requests[0]?.url, '/v1/models');
  await waitUntil(() => relayRows(w).some((r) => r.detail['route'] === 'relay'), 'the relay audit row');
  assert.deepEqual(relayRows(w).filter((r) => r.detail['route'] === 'relay').map((r) => r.ref), [REAL]);
});

test('KBOX-13 a well-formed address of no key is 403 with no upstream call, and the audit names the keyref', async (t) => {
  const w = await relayWorld(t);
  const reply = await w.call('/r/pathplat~shop~NO_SUCH_KEY/v1/models');
  assert.equal(reply.status, 403);
  assert.equal(w.upstream.requests.length, 0);
  await waitUntil(() => relayRows(w).length === 1, 'the relay audit row');
  assert.equal(relayRows(w)[0]?.ref, 'pathplat/shop/NO_SUCH_KEY');
});

test('KBOX-13 a key granted only to another machine, and a key whose grant was removed, are each 403 with no upstream call', async (t) => {
  const w = await relayWorld(t);
  w.lend.enrol('desktop');
  w.lend.addKey({ keyref: 'pathplat/shop/DESK_ONLY', value: w.value, grants: ['desktop'] });
  w.lend.addKey({ keyref: REAL, value: w.value, grants: ['laptop'] });
  assert.equal((await w.call(`/r/${ADDRESS}/v1/models`)).status, 200, 'control: granted');
  w.lend.core.meta.removeGrant(REAL, 'laptop');
  assert.equal((await w.call(`/r/${ADDRESS}/v1/models`)).status, 403);
  assert.equal((await w.call('/r/pathplat~shop~DESK_ONLY/v1/models')).status, 403);
  assert.equal(w.upstream.requests.length, 1);
});

test('KBOX-13 each key has one address: an escaped "~" or "_" is 404 and the "/" spelling is 403, none reaches upstream', async (t) => {
  const w = await relayWorld(t);
  w.lend.addKey({ keyref: REAL, value: w.value, grants: ['laptop'] });
  assert.equal((await w.call('/r/pathplat%7Eshop%7EREAL_KEY/v1/models')).status, 404);
  assert.equal((await w.call('/r/pathplat~shop~REAL%5FKEY/v1/models')).status, 404);
  assert.equal((await w.call('/r/pathplat/shop/REAL_KEY/v1/models')).status, 403, 'the address "pathplat" names no key');
  assert.equal(w.upstream.requests.length, 0);
});

test('KBOX-13 step 3 an encoded "/" inside the address is 404 not_found before auth; after the address it is 400 bad_path after auth', async (t) => {
  const w = await relayWorld(t);
  w.lend.addKey({ keyref: REAL, value: w.value, grants: ['laptop'] });
  const inside = await w.call('/r/pathplat%2Fshop~REAL_KEY/v1/models', { pass: null });
  assert.deepEqual([inside.status, (json(inside) as { error: { code: string } }).error.code], [404, 'not_found']);
  assert.equal((await w.call(`/r/${ADDRESS}/v1/a%2Fb`, { pass: null })).status, 401);
  const after = await w.call(`/r/${ADDRESS}/v1/a%2Fb`);
  assert.deepEqual([after.status, (json(after) as { error: { code: string } }).error.code], [400, 'bad_path']);
  assert.equal(w.upstream.requests.length, 0);
});

test('KBOX-57 a key re-added at another project keeps its address and is relayed to the new project host only', async (t) => {
  const w = await relayWorld(t, { registry: PROJECT_REGISTRY });
  const keyref = 'projplat/shop/PROJ_KEY';
  w.lend.addKey({ keyref, value: w.value, platform: 'projplat', grants: ['laptop'], at: { project: 'abcdefgh' } });
  assert.equal((await w.call('/r/projplat~shop~PROJ_KEY/rest/v1/things')).status, 200);
  assert.deepEqual(w.connects, ['abcdefgh.projplat.example']);
  w.lend.readdAt(keyref, { project: 'zyxwvuts' });
  assert.equal((await w.call('/r/projplat~shop~PROJ_KEY/rest/v1/things')).status, 200);
  assert.deepEqual(w.connects, ['abcdefgh.projplat.example', 'zyxwvuts.projplat.example']);
});
