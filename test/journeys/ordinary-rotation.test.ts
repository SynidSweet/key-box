// J3 (in one process): a full rotation of an ordinary key with a delivery and its ack, through the machine API only. The real two-process
// journey needs the platform registry that the adapter units build; this one runs the same routes, store and orchestrator on the core's socket.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { bytesOf } from '../kit/index.ts';
import { routesWorld } from '../support/routes-world.ts';

const HOUR = 3600_000;
const KEYREF = 'fake/shop/OPENAI_KEY';

test('J3 KBOX-34 an ordinary key is made, delivered and acknowledged, rotated on request, and its old value is retired a day later', async (t) => {
  const w = await routesWorld(t);
  const made = await w.api('/api/keys', { json: { platform: 'fake', name: 'OPENAI_KEY', projects: ['shop'], scope: { items: ['read'] }, destinations: [{ kind: 'vercel_env', target: 'app-a' }, { kind: 'workstation', target: '' }] } });
  assert.equal(made.status, 201, made.body);
  const first = ((await w.api('/api/deliveries')).json() as { deliveries: { delivery_id: string }[] }).deliveries;
  assert.equal(first.length, 1);
  const oldValue = (await w.api(`/api/deliveries/${first[0]?.delivery_id}/value`)).body;
  assert.equal((await w.api(`/api/deliveries/${first[0]?.delivery_id}/ack`, { method: 'POST' })).status, 200);

  const run = await w.api('/api/rotations', { json: { keyref: KEYREF } });
  assert.equal(run.status, 201);
  await w.rotation.orchestrator.idle();
  const second = ((await w.api('/api/deliveries')).json() as { deliveries: { delivery_id: string; gen: number }[] }).deliveries;
  assert.deepEqual(second.map((d) => d.gen), [2], 'the new generation is on offer for the workstation');
  const newValue = (await w.api(`/api/deliveries/${second[0]?.delivery_id}/value`)).body;
  assert.notEqual(newValue, oldValue);
  assert.equal(w.destination.heldAt('app-a', 'OPENAI_KEY'), newValue, 'the runtime destination holds the new key');
  assert.equal(Buffer.from(await bytesOf(w.parts.vault.lend(KEYREF, 2))).toString('utf8'), newValue);

  w.clock.advance(24 * HOUR);
  await w.rotation.orchestrator.idle();
  assert.equal(w.rotation.store.gen(KEYREF, 1)?.status, 'retired');
  assert.deepEqual((await w.platform.lister.list(w.platform.master())).map((k) => k.name.startsWith('kbox_')), [true], 'only the new key is on the platform');
  assert.equal((await w.api(`/api/deliveries/${second[0]?.delivery_id}/ack`, { method: 'POST' })).status, 200);
  const meta = (await w.api('/api/meta')).json() as { keys: { keyref: string; status: string; gen_current: number }[] };
  assert.deepEqual(meta.keys.map((k) => [k.keyref, k.status, k.gen_current]), [[KEYREF, 'works', 2]]);
  const events = (await w.api('/api/events?since=0')).json() as { events: { kind: string }[] };
  assert.equal(events.events.some((e) => e.kind === 'rotation.failed'), false);
});
