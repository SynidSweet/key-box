// The core process wired as the service wires it, started in this process on a TimedClock (src/main-core.ts `startCore`): the route
// table holds the rotation routes, a rotation on a fresh box does not stop core, and stopping core leaves no timer of its own.
import assert from 'node:assert/strict';
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import type { TestContext } from 'node:test';
import type { KeyRow } from '../src/ports/meta.ts';
import { hashToken, newToken } from '../src/pure/tokens.ts';
import { startCore } from '../src/main-core.ts';
import type { StartedCore } from '../src/main-core.ts';
import { openCore } from '../src/shell/core.ts';
import { createRotationStore } from '../src/shell/rotation-store.ts';
import { TimedClock, drive, seededRandom, tempDir } from './kit/index.ts';

const DAY = 24 * 3600_000;

interface World {
  readonly core: StartedCore;
  readonly clock: TimedClock;
  readonly journal: string[];
  readonly token: string;
  call(path: string, body?: unknown): Promise<{ status: number; body: string }>;
}

interface Options {
  readonly domain?: string;
  /** Written to the state directory before core starts. */
  readonly seed?: (state: { readonly meta: ReturnType<typeof openCore>['meta']; readonly clock: TimedClock; readonly rotation: ReturnType<typeof createRotationStore> }) => void;
}

/** Starts core in this process over a fresh state directory, with a control token enrolled before the start. */
async function started(t: TestContext, options: Options = {}): Promise<World> {
  const dir = await tempDir(t);
  const stateDir = join(dir, 'state');
  const socket = join(dir, 'http.sock');
  mkdirSync(join(dir, 'results'));
  const clock = new TimedClock(1_700_000_000_000);
  const random = seededRandom(9);
  const token = newToken(random);
  const prepared = openCore({ stateDir, clock, scheduler: clock, random });
  prepared.meta.addMachine({ label: 'mc', scope: 'control', tokenSha256: hashToken(token), enrolledAt: clock.now() });
  options.seed?.({ meta: prepared.meta, clock, rotation: createRotationStore(prepared.db, clock, prepared.hub) });
  prepared.close();
  const journal: string[] = [];
  const env: Record<string, string> = { KB_STATE_DIR: stateDir, KB_SOCKET: socket, KB_INSTALL_RESULTS: join(dir, 'results'), KB_CURRENT: join(dir, 'current'), ...(options.domain === undefined ? {} : { KB_DOMAIN: options.domain }) };
  const core = await startCore(env, { clock, scheduler: clock, random, journal: (code) => void journal.push(code) });
  t.after(() => core.stop());
  const driver = drive(socket);
  const call = async (path: string, body?: unknown): Promise<{ status: number; body: string }> => {
    const reply = await driver.request({
      path,
      method: body === undefined ? 'GET' : 'POST',
      headers: { 'x-kb-client-ip': '203.0.113.9', authorization: `Bearer ${token}`, ...(body === undefined ? {} : { 'content-type': 'application/json' }) },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    return { status: reply.status, body: reply.body };
  };
  return { core, clock, journal, token, call };
}

const adminRow = (keyref: string): KeyRow => ({
  keyref,
  platform: 'google',
  name: 'GOOGLE_ADMIN_KEY',
  projects: ['shop'],
  class: 'admin',
  status: 'works',
  gen_current: 1,
  schedule: { rotate_every_days: 1, grace_hours: 24, next_due_at: null, expires_at: null },
  coverage: null,
  last_use_at: null,
});

test('KBOX-12 KBOX-34 KBOX-51 core\'s route table holds the key, rotation, retired-value, delivery and paste routes next to the approval and share routes', async (t) => {
  const w = await started(t, { domain: 'box.example' });
  const table = w.core.routes.map((r) => `${r.method} ${r.path}`);
  for (const route of ['POST /api/keys', 'POST /api/rotations', 'POST /api/retired', 'GET /api/deliveries', 'POST /api/deliveries/:id/ack', 'GET /p/:id', 'GET /app/pastes', 'POST /api/proposals', 'GET /api/share']) {
    assert.ok(table.includes(route), `${route} is in the table`);
  }
  assert.equal(new Set(table).size, table.length, 'no route is listed twice');
});

test('KBOX-1 without KB_DOMAIN there is no approval half, so no key or rotation route either', async (t) => {
  const w = await started(t);
  const table = w.core.routes.map((r) => `${r.method} ${r.path}`);
  assert.equal(table.includes('POST /api/rotations'), false);
  assert.equal(table.includes('POST /api/keys'), false);
  assert.ok(table.includes('GET /api/share'));
});

test('KBOX-51 a rotation started on a fresh box does not stop core: no platform is registered, so the request is refused with a status and the box keeps answering', async (t) => {
  const w = await started(t, { domain: 'box.example' });
  const refused = await w.call('/api/keys', { platform: 'google', name: 'GOOGLE_KEY', projects: ['shop'], scope: { items: ['read'] }, destinations: [] });
  assert.ok(refused.status >= 400 && refused.status < 500, `a contract-shaped refusal, got ${refused.status} ${refused.body}`);
  const unknown = await w.call('/api/rotations', { keyref: 'google/shop/NOPE' });
  assert.equal(unknown.status, 404);
  assert.equal((await w.call('/api/meta')).status, 200);
});

test('KBOX-52 the scheduler tick runs at start: an admin key that is due opens one rotate_key approval, and an adapter-less platform does not crash the tick', async (t) => {
  const keyref = 'google/shop/GOOGLE_ADMIN_KEY';
  const w = await started(t, {
    domain: 'box.example',
    seed: ({ meta, clock, rotation }) => {
      meta.putKey(adminRow(keyref));
      rotation.putKeyInfo(keyref, { scopeItems: ['admin'], location: {}, rotatedAt: clock.now() - 30 * DAY, markAdmin: false });
      rotation.putGen({ keyref, gen: 1, status: 'current', platformKeyId: null, location: {} });
    },
  });
  const snapshot = async (): Promise<{ keys: { keyref: string; status: string }[]; approvals: { kind: string }[] }> =>
    JSON.parse((await w.call('/api/meta')).body) as { keys: { keyref: string; status: string }[]; approvals: { kind: string }[] };
  const opened = async (): Promise<number> => (await snapshot()).approvals.filter((a) => a.kind === 'rotate_key').length;
  assert.equal(await opened(), 1, 'the due key opened its approval');
  assert.equal((await snapshot()).keys.find((k) => k.keyref === keyref)?.status, 'awaiting_approval');
  w.clock.advance(DAY);
  assert.equal(await opened(), 1, 'a later tick opens none');
});

test('KBOX-51 stopping core cancels every timer it set, rotation\'s hourly tick and daily reconcile included, and a stopped core answers nothing', async (t) => {
  const w = await started(t, { domain: 'box.example' });
  assert.ok(w.clock.pendingTimers > 0, 'a running core holds timers');
  await w.core.stop();
  assert.equal(w.clock.pendingTimers, 0, 'no timer is left');
  await assert.rejects(w.call('/api/meta'), 'the socket is closed');
});
