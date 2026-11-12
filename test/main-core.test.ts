// The core process wired as the service wires it, started in this process on a TimedClock (src/main-core.ts `startCore`): the route
// table holds the rotation routes, a rotation on a fresh box does not stop core, and stopping core leaves no timer of its own.
import assert from 'node:assert/strict';
import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { createConnection } from 'node:net';
import { DatabaseSync } from 'node:sqlite';
import { join } from 'node:path';
import { test } from 'node:test';
import type { TestContext } from 'node:test';
import type { KeyRow } from '../src/ports/meta.ts';
import { intentName } from '../src/pure/rotation-machine.ts';
import { hashToken, newToken } from '../src/pure/tokens.ts';
import { startCore } from '../src/main-core.ts';
import type { StartedCore } from '../src/main-core.ts';
import { openCore } from '../src/shell/core.ts';
import type { PlatformSource } from '../src/shell/rotation-ports.ts';
import { createRotationStore } from '../src/shell/rotation-store.ts';
import { FakePlatformWorld } from './fakes/platform.ts';
import { TimedClock, drive, lent, seededRandom, tempDir, waitUntil } from './kit/index.ts';

const DAY = 24 * 3600_000;

interface World {
  readonly core: StartedCore;
  readonly clock: TimedClock;
  readonly journal: string[];
  readonly token: string;
  readonly lendSocket: string;
  readonly stateDir: string;
  call(path: string, body?: unknown): Promise<{ status: number; body: string }>;
}

interface Options {
  readonly domain?: string;
  /** Written to the state directory before core starts. */
  readonly seed?: (state: { readonly meta: ReturnType<typeof openCore>['meta']; readonly db: ReturnType<typeof openCore>['db']; readonly clock: TimedClock; readonly rotation: ReturnType<typeof createRotationStore> }) => void;
  /** Core also listens on a lend socket, at `World.lendSocket`. */
  readonly lend?: boolean;
  /** The platform adapters rotation is given in place of the (empty) registry's. */
  readonly platforms?: PlatformSource;
  /** The egress host list core reads at its start, in place of deploy/egress-hosts.json. */
  readonly egressHostsFile?: URL;
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
  options.seed?.({ meta: prepared.meta, db: prepared.db, clock, rotation: createRotationStore(prepared.db, clock, prepared.hub) });
  prepared.close();
  const journal: string[] = [];
  const lendSocket = join(dir, 'lend.sock');
  const env: Record<string, string> = {
    KB_STATE_DIR: stateDir,
    KB_SOCKET: socket,
    KB_INSTALL_RESULTS: join(dir, 'results'),
    KB_CURRENT: join(dir, 'current'),
    ...(options.domain === undefined ? {} : { KB_DOMAIN: options.domain }),
    ...(options.lend === true ? { KB_LEND_SOCKET: lendSocket } : {}),
  };
  const core = await startCore(env, { clock, scheduler: clock, random, journal: (code) => void journal.push(code), ...(options.platforms === undefined ? {} : { platforms: options.platforms }), ...(options.egressHostsFile === undefined ? {} : { egressHostsFile: options.egressHostsFile }) });
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
  return { core, clock, journal, token, lendSocket, stateDir, call };
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

// --- rotation starts after the lend server and never holds the start or the stop (review N4) ---------------------------------------

/** Resolves once a connection to the unix socket is accepted; rejects when nothing listens there. */
const accepts = (path: string): Promise<void> =>
  new Promise((resolve, reject) => {
    const socket = createConnection(path);
    socket.once('connect', () => {
      socket.destroy();
      resolve();
    });
    socket.once('error', reject);
  });

test('KBOX-51 a platform call that hangs while a run resumes holds back neither the lend socket nor a graceful stop; the stores close once the call returns', { timeout: 20_000 }, async (t) => {
  const keyref = 'hang/shop/HANG_KEY';
  const runId = 'run_00000000000000a1';
  let release = (): void => undefined;
  const hanging = new Promise<'revoked'>((resolve) => {
    release = () => resolve('revoked');
  });
  let revoking = false;
  const caps = new FakePlatformWorld(seededRandom(4)).issuer.capabilities();
  const platforms: PlatformSource = {
    platform: (id) =>
      id === 'hang'
        ? {
            issuer: {
              platform: 'hang',
              capabilities: () => caps,
              issue: () => Promise.reject(new Error('not in this test')),
              revoke: () => {
                revoking = true;
                return hanging;
              },
            },
          }
        : undefined,
    destination: () => undefined,
    master: () => ({ ok: true, value: lent(Buffer.from('hang-master'), 'master:1') }),
    masters: () => [],
  };
  const w = await started(t, {
    domain: 'box.example',
    lend: true,
    platforms,
    seed: ({ meta, clock, rotation }) => {
      meta.putKey({ ...adminRow(keyref), platform: 'hang', name: 'HANG_KEY', class: 'ordinary', gen_current: 2 });
      rotation.putKeyInfo(keyref, { scopeItems: ['read'], location: {}, rotatedAt: clock.now(), markAdmin: false });
      rotation.putGen({ keyref, gen: 1, status: 'grace', platformKeyId: 'pk-1', location: {} });
      rotation.putGen({ keyref, gen: 2, status: 'current', platformKeyId: 'pk-2', location: {} });
      rotation.openRun({ runId, keyref, state: 'revoking', genOld: 1, genNew: 2, intentName: intentName(keyref, 2, runId), origin: 'schedule' });
    },
  });
  await waitUntil(() => revoking, 'the resumed run to call the platform');
  await accepts(w.lendSocket);
  assert.equal((await w.call('/api/meta')).status, 200, 'core answers while the run waits on the platform');
  await w.core.stop();
  await assert.rejects(accepts(w.lendSocket), 'the lend socket is closed');
  await assert.rejects(w.call('/api/meta'), 'the api socket is closed');
  release();
  await w.core.closed;
});

// --- the approvals sweep timer never ends with one throw ---------------------------------------------------------------------------

test('KBOX-28 a sweep that throws is audited as approvals.sweep_failed and the hourly sweep keeps running: it is not an uncaught exception, and the next sweep that works expires what is stale', async (t) => {
  const HOUR = 3600_000;
  const w = await started(t, {
    domain: 'box.example',
    seed: ({ meta, clock }) => meta.putApproval({ approval_id: 'ap_stale', kind: 'key_rotate', title: 'Rotate a key', slot: 'admin-1', opened_at: clock.now(), expires_at: clock.now() + HOUR / 2 }),
  });
  const audit = async (): Promise<readonly { action: string }[]> => (JSON.parse((await w.call('/api/audit?since=0&limit=500')).body) as { entries: { action: string }[] }).entries;
  const sweepFailures = async (): Promise<number> => (await audit()).filter((e) => e.action === 'approvals.sweep_failed').length;
  const pending = async (): Promise<number> => (JSON.parse((await w.call('/api/meta')).body) as { approvals: unknown[] }).approvals.length;
  // The database refuses every write to approvals (an I/O error stand-in), so the sweep's expiry write throws once the row is stale.
  const db = new DatabaseSync(join(w.stateDir, 'meta.db'));
  t.after(() => db.close());
  db.exec("CREATE TRIGGER refuse_expiry BEFORE UPDATE ON approvals BEGIN SELECT RAISE(ABORT, 'disk I/O error'); END");
  w.clock.advance(HOUR);
  assert.equal(await sweepFailures(), 1, 'the throw is audited, and advance did not throw');
  w.clock.advance(HOUR);
  assert.equal(await sweepFailures(), 2, 'the schedule went on after the throw');
  assert.equal(await pending(), 1, 'nothing was expired meanwhile');
  db.exec('DROP TRIGGER refuse_expiry');
  w.clock.advance(HOUR);
  assert.equal(await sweepFailures(), 2, 'a sweep that works audits no failure');
  assert.equal(await pending(), 0, 'and it expired the stale approval');
});

// --- the updater's settle timer never ends with one throw --------------------------------------------------------------------------

test('KBOX-6 a settle that throws is audited as update.settle_failed and the 5-second settle keeps running: it is not an uncaught exception, and a settle that works audits nothing', async (t) => {
  const SETTLE = 5_000;
  const w = await started(t, { domain: 'box.example' });
  const failures = async (): Promise<number> =>
    (JSON.parse((await w.call('/api/audit?since=0&limit=500')).body) as { entries: { action: string }[] }).entries.filter((e) => e.action === 'update.settle_failed').length;
  // Staging becomes a plain file (a disk fault stand-in): the settle's prune cannot list it and throws.
  const staging = join(w.stateDir, 'staging');
  rmSync(staging, { recursive: true });
  writeFileSync(staging, 'not a directory');
  w.clock.advance(SETTLE);
  assert.equal(await failures(), 1, 'the throw is audited, and advance did not throw');
  w.clock.advance(SETTLE);
  assert.equal(await failures(), 2, 'the schedule went on after the throw');
  rmSync(staging);
  mkdirSync(staging);
  w.clock.advance(SETTLE);
  assert.equal(await failures(), 2, 'a settle that works audits no failure');
});

// --- a failing audit cannot stop the schedule ---------------------------------------------------------------------------------------

const REFUSE_AUDIT = "CREATE TRIGGER refuse_audit BEFORE INSERT ON audit WHEN NEW.action IN ('approvals.sweep_failed', 'update.settle_failed') BEGIN SELECT RAISE(ABORT, 'disk full'); END";

test('KBOX-28 a sweep whose audit append also throws neither escapes the timer nor stops the hourly sweep: the journal says the failure could not be audited, and the next sweep that works expires what is stale', async (t) => {
  const HOUR = 3600_000;
  const w = await started(t, {
    domain: 'box.example',
    seed: ({ meta, clock }) => meta.putApproval({ approval_id: 'ap_stale', kind: 'key_rotate', title: 'Rotate a key', slot: 'admin-1', opened_at: clock.now(), expires_at: clock.now() + HOUR / 2 }),
  });
  const pending = async (): Promise<number> => (JSON.parse((await w.call('/api/meta')).body) as { approvals: unknown[] }).approvals.length;
  const db = new DatabaseSync(join(w.stateDir, 'meta.db'));
  t.after(() => db.close());
  db.exec("CREATE TRIGGER refuse_expiry BEFORE UPDATE ON approvals BEGIN SELECT RAISE(ABORT, 'disk I/O error'); END");
  db.exec(REFUSE_AUDIT);
  w.clock.advance(HOUR);
  w.clock.advance(HOUR);
  assert.equal(w.journal.filter((c) => c === 'audit_failed:approvals.sweep_failed').length, 2, 'each failure reached the journal, and the second sweep ran after the first');
  db.exec('DROP TRIGGER refuse_expiry');
  db.exec('DROP TRIGGER refuse_audit');
  w.clock.advance(HOUR);
  assert.equal(await pending(), 0, 'the schedule survived both throws');
});

test('KBOX-6 a settle whose audit append also throws neither escapes the timer nor stops the settle schedule', async (t) => {
  const SETTLE = 5_000;
  const w = await started(t, { domain: 'box.example' });
  const db = new DatabaseSync(join(w.stateDir, 'meta.db'));
  t.after(() => db.close());
  const staging = join(w.stateDir, 'staging');
  rmSync(staging, { recursive: true });
  writeFileSync(staging, 'not a directory');
  db.exec(REFUSE_AUDIT);
  w.clock.advance(SETTLE);
  w.clock.advance(SETTLE);
  assert.equal(w.journal.filter((c) => c === 'audit_failed:update.settle_failed').length, 2);
  db.exec('DROP TRIGGER refuse_audit');
  rmSync(staging);
  mkdirSync(staging);
  w.clock.advance(SETTLE);
  const entries = (JSON.parse((await w.call('/api/audit?since=0&limit=500')).body) as { entries: { action: string }[] }).entries;
  assert.equal(entries.filter((e) => e.action === 'update.settle_failed').length, 0, 'a settle that works audits nothing, and ran after the throws');
  assert.equal(w.journal.filter((c) => c === 'audit_failed:update.settle_failed').length, 2);
});

test('KBOX-28 KBOX-6 a first sweep and settle at start that throw, with a failing audit, do not stop core from starting, and the schedule runs on', async (t) => {
  const HOUR = 3600_000;
  const w = await started(t, {
    domain: 'box.example',
    seed: ({ meta, clock, db }) => {
      meta.putApproval({ approval_id: 'ap_stale', kind: 'key_rotate', title: 'Rotate a key', slot: 'admin-1', opened_at: clock.now() - HOUR, expires_at: clock.now() - HOUR / 2 });
      db.exec("CREATE TRIGGER refuse_expiry BEFORE UPDATE ON approvals BEGIN SELECT RAISE(ABORT, 'disk I/O error'); END");
      db.exec(REFUSE_AUDIT);
    },
  });
  assert.ok(w.journal.includes('audit_failed:approvals.sweep_failed'), 'the first sweep failed, could not be audited, and core still started');
  w.clock.advance(HOUR);
  assert.equal(w.journal.filter((c) => c === 'audit_failed:approvals.sweep_failed').length, 2, 'the schedule went on');
});

async function hostsFile(t: TestContext, text: string): Promise<URL> {
  const file = join(await tempDir(t), 'egress-hosts.json');
  writeFileSync(file, text);
  return new URL(`file://${file}`);
}

test('KBOX-47 a deploy/egress-hosts.json that does not parse stops core\'s start, whether it is not JSON, not the closed shape or names a bad host', async (t) => {
  for (const text of ['not json', '{"hosts":[{"host":"a.example.com"}]}', '{"hosts":[{"host":"*","purpose":"x","caller":"push"}]}', '{"hosts":[],"extra":1}', '']) {
    await assert.rejects(started(t, { egressHostsFile: await hostsFile(t, text) }), Error, text);
  }
});

test('KBOX-47 a list that parses starts core, and the list file is read at the start, not on the first call', async (t) => {
  const w = await started(t, { egressHostsFile: await hostsFile(t, '{"hosts":[{"host":"push.example.com","purpose":"a test push host","caller":"push"}]}') });
  assert.ok(w.core.routes.length > 0);
});
