// J2, the relayed call (KBOX-3, KBOX-13, KBOX-14, KBOX-45): core and kb-relay as separate processes on their own sockets,
// joined only by the lend socket. The first test runs the real entry points (main-core.ts, main-relay.ts) with the empty
// v1 registry; the second runs the same modules over the test profiles and a loopback upstream: a granted call, a refused
// call and a withheld response, read back from core's audit log and events after both processes stop.
import assert from 'node:assert/strict';
import { mkdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import type { TestContext } from 'node:test';
import { openCore } from '../../src/shell/core.ts';
import type { CoreParts } from '../../src/shell/core.ts';
import { relayErrorBody } from '../../src/pure/relay-errors.ts';
import { TimedClock, canary, drive, seededRandom, startNode, tempDir } from '../kit/index.ts';
import { seedKey, seedPass } from '../support/lend-world.ts';
import { startUpstream } from '../support/relay-world.ts';

const MAIN_CORE = new URL('../../src/main-core.ts', import.meta.url).pathname;
const MAIN_RELAY = new URL('../../src/main-relay.ts', import.meta.url).pathname;
const PROCESSES = new URL('./relay-processes.ts', import.meta.url).pathname;

interface Box {
  readonly dir: string;
  readonly stateDir: string;
  readonly lendSocket: string;
  readonly relaySocket: string;
  readonly pass: string;
  readonly value: Uint8Array;
  readonly canary: ReturnType<typeof canary>;
}

/** A state directory holding the machine `laptop` (relay pass) and the admin key `adminkey1` of the path profile, granted to it. */
async function seededBox(t: TestContext): Promise<Box> {
  const dir = await tempDir(t);
  const stateDir = join(dir, 'state');
  mkdirSync(stateDir, { recursive: true });
  const clock = new TimedClock(1_000_000);
  const c = canary();
  const value = Buffer.from(Buffer.from(c.bytes).toString('hex'));
  const core = openCore({ stateDir, clock, scheduler: clock, random: seededRandom(3) });
  const pass = seedPass(core, 'laptop', 'relay', seededRandom(4), clock.now());
  seedKey(core, { keyref: 'adminkey1', value, grants: ['laptop'] });
  core.close();
  return { dir, stateDir, lendSocket: join(dir, 'lend.sock'), relaySocket: join(dir, 'relay.sock'), pass, value, canary: c };
}

/** Core's records once its process has stopped. */
function afterwards(box: Box): { readonly core: CoreParts; readonly close: () => void } {
  const clock = new TimedClock(2_000_000);
  const core = openCore({ stateDir: box.stateDir, clock, scheduler: clock, random: seededRandom(5) });
  return { core, close: () => core.close() };
}

const call = (box: Box, path: string, method = 'GET') =>
  drive(box.relaySocket).request({ path, method, headers: { authorization: `Bearer ${box.pass}`, 'x-kb-client-ip': '203.0.113.9' } });

test('J2 the real entry points: core makes the lend socket 0660, kb-relay serves /r/* through it, and with no relay profile registered nothing is lent', async (t) => {
  const box = await seededBox(t);
  const core = startNode(t, [MAIN_CORE], box.dir, { KB_STATE_DIR: box.stateDir, KB_SOCKET: join(box.dir, 'http.sock'), KB_LEND_SOCKET: box.lendSocket });
  await core.ready('keybox core listening');
  assert.equal(statSync(box.lendSocket).mode & 0o777, 0o660);
  const relay = startNode(t, [MAIN_RELAY], box.dir, { KB_RELAY_SOCKET: box.relaySocket, KB_LEND_SOCKET: box.lendSocket, KB_DOMAIN: 'box.example' });
  await relay.ready('keybox relay listening');
  const grants = await call(box, '/r/_/grants');
  assert.deepEqual([grants.status, JSON.parse(grants.body)], [200, { machine: 'laptop', grants: [] }]);
  const used = await call(box, '/r/adminkey1/v1/models');
  assert.deepEqual([used.status, used.body], [403, relayErrorBody('forbidden')]);
  const relayExit = await relay.stop();
  const coreExit = await core.stop();
  assert.deepEqual([relayExit.status, coreExit.status], [0, 0], `${relayExit.stderr}${coreExit.stderr}`);
  box.canary.assertAbsent({ 'relay stderr': relayExit.stderr, 'relay stdout': relayExit.stdout, 'core stderr': coreExit.stderr, grants: grants.body, used: used.body });
});

test('J2 a granted call is relayed with the lent value, a mustDeny call is refused with no upstream call, and a response carrying the value is withheld', async (t) => {
  const box = await seededBox(t);
  const upstream = await startUpstream(t);
  const core = startNode(t, [PROCESSES, 'core', box.stateDir, box.lendSocket], box.dir, {});
  await core.ready('listening');
  const relay = startNode(t, [PROCESSES, 'relay', box.relaySocket, box.lendSocket, String(upstream.port)], box.dir, {});
  await relay.ready('listening');

  const granted = await call(box, '/r/adminkey1/v1/models');
  assert.deepEqual([granted.status, granted.body], [200, '{"ok":true}']);
  assert.deepEqual([upstream.requests[0]?.url, upstream.requests[0]?.headers['authorization']], ['/v1/models', `Bearer ${Buffer.from(box.value).toString()}`]);
  const refused = await call(box, '/r/adminkey1/v1/organization/admin_api_keys', 'POST');
  assert.deepEqual([refused.status, upstream.requests.length], [403, 1]);
  upstream.respond((_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(`{"echo":"${Buffer.from(box.value).toString()}"}`);
  });
  const withheld = await call(box, '/r/adminkey1/v1/models');
  assert.deepEqual([withheld.status, withheld.body], [502, relayErrorBody('withheld')]);

  const relayExit = await relay.stop();
  const coreExit = await core.stop();
  assert.deepEqual([relayExit.status, coreExit.status], [0, 0], `${relayExit.stderr}${coreExit.stderr}`);
  box.canary.assertAbsent({ 'relay stderr': relayExit.stderr, 'core stderr': coreExit.stderr, refused: refused.body, withheld: withheld.body });
  const records = afterwards(box);
  t.after(records.close);
  const rows = records.core.audit.read(0).entries.filter((r) => r.action === 'relay.request');
  assert.deepEqual(
    rows.map((r) => [r.actor, r.ref, r.detail['status'], r.detail['rule_id'], r.detail['code']]),
    [
      ['laptop', 'adminkey1', 200, 'models-list', undefined],
      ['laptop', 'adminkey1', 403, undefined, 'forbidden'],
      ['laptop', 'adminkey1', 502, 'models-list', 'withheld'],
    ],
  );
  assert.deepEqual(records.core.events.after(0).filter((e) => e.kind === 'box.notice').map((e) => e.data['code']), ['credential_withheld']);
});
