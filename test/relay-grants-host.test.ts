import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { waitUntil } from './kit/index.ts';
import { PROJECT_REGISTRY } from './fixtures/profiles.ts';
import { relayWorld } from './support/relay-world.ts';
import type { RelayReply } from './support/relay-world.ts';

const RELAY = 'https://box.example';

const json = (reply: RelayReply): unknown => JSON.parse(reply.body.toString('utf8')) as unknown;

test('KBOX-32 /r/_/grants lists only the admin keys granted to the calling machine, each with its relay env and the literal "<pass>", and no value at https://box.example', async (t) => {
  const w = await relayWorld(t);
  const desktop = w.lend.enrol('desktop');
  w.lend.addKey({ keyref: 'deskonly01', value: Buffer.from('a-different-admin-value-0001'), grants: ['desktop'] });
  w.lend.addKey({ keyref: 'ordinary01', value: Buffer.from('an-ordinary-value-000000001'), cls: 'ordinary', grants: ['laptop'] });
  w.lend.addKey({ keyref: 'master0001', value: Buffer.from('a-master-value-00000000001'), cls: 'master', grants: ['laptop'] });
  w.lend.addKey({ keyref: 'plainkey01', value: Buffer.from('a-plain-platform-value-0001'), platform: 'plain', grants: ['laptop'] });
  const laptop = await w.call('/r/_/grants');
  assert.equal(laptop.status, 200);
  assert.deepEqual(json(laptop), {
    machine: 'laptop',
    grants: [
      { keyref: 'adminkey1', platform: 'pathplat', name: 'KEY_ADMINKEY1', projects: ['shop'], env: { PATHPLAT_BASE_URL: `${RELAY}/r/adminkey1/v1`, PATHPLAT_API_KEY: '<pass>' } },
      { keyref: 'hostkey001', platform: 'hostplat', name: 'KEY_HOSTKEY001', projects: ['shop'], env: { KBOX_GOOGLE_RELAY_URL: `${RELAY}/r/hostkey001` } },
    ],
  });
  w.canary.assertAbsent({ 'grants body': laptop.body });
  const other = await w.call('/r/_/grants', { pass: desktop });
  assert.deepEqual(json(other), { machine: 'desktop', grants: [{ keyref: 'deskonly01', platform: 'pathplat', name: 'KEY_DESKONLY01', projects: ['shop'], env: { PATHPLAT_BASE_URL: `${RELAY}/r/deskonly01/v1`, PATHPLAT_API_KEY: '<pass>' } }] });
  assert.equal(w.upstream.requests.length, 0);
});

interface SdkFixture {
  readonly method: string;
  readonly path: string;
  readonly headers: Readonly<Record<string, string>>;
}

test('KBOX-32 the OpenAI SDK request shape under the granted base URL reaches models-list, with its SDK headers dropped (fixture hand-written, UNVERIFIED) at https://box.example', async (t) => {
  const w = await relayWorld(t);
  const fixture = JSON.parse(readFileSync(new URL('./fixtures/openai-sdk-request.json', import.meta.url), 'utf8')) as SdkFixture;
  const listed = json(await w.call('/r/_/grants')) as { grants: { keyref: string; env: Record<string, string> }[] };
  const base = listed.grants.find((g) => g.keyref === 'adminkey1')?.env['PATHPLAT_BASE_URL'] ?? '';
  assert.ok(base.startsWith(RELAY));
  const headers = Object.fromEntries(Object.entries(fixture.headers).map(([k, v]) => [k, v.replace('<pass>', w.pass)]));
  const reply = await w.call(`${base.slice(RELAY.length)}${fixture.path}`, { method: fixture.method, headers });
  assert.equal(reply.status, 200);
  assert.deepEqual([w.upstream.requests[0]?.url, Object.keys(w.upstream.requests[0]?.headers ?? {}).filter((h) => h.startsWith('x-stainless') || h === 'user-agent')], ['/v1/models', []]);
  await waitUntil(() => w.lend.core.audit.read(0).entries.some((r) => r.action === 'relay.request' && r.detail['rule_id'] === 'models-list'), 'the models-list row');
});

