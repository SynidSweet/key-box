// KBOX-23, KBOX-40, KBOX-34: core reads the registry it is started with. A bad registry stops the start; the shape of a registered platform
// (stated by a paste-only entry) reaches the share file; `add_key` is let through for a registered platform and refused for an unknown one,
// while the kinds whose executors do not exist yet stay refused.
import assert from 'node:assert/strict';
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import type { TestContext } from 'node:test';
import type { KeyRow } from '../src/ports/meta.ts';
import type { PlatformEntry } from '../src/ports/platform.ts';
import type { KeyShape } from '../src/ports/types.ts';
import type { Action } from '../src/pure/actions.ts';
import { RegistryRefused } from '../src/pure/profile.ts';
import { vetAction } from '../src/pure/proposal-vet.ts';
import { startCore } from '../src/main-core.ts';
import { openCore } from '../src/shell/core.ts';
import { hashToken, newToken } from '../src/pure/tokens.ts';
import { FakePlatformWorld } from './fakes/platform.ts';
import { fakeEntry, issuerWith, pasteOnlyEntry } from './fakes/platform-entry.ts';
import { TimedClock, drive, seededRandom, tempDir } from './kit/index.ts';

const SHAPE: KeyShape = { prefix: 'po-', alphabet: 'hex', coreLength: { min: 32, max: 32 }, random: true };
const VALUE = `po-${'c0ffee12'.repeat(4)}`;
const KEYREF = 'pasteonly/shop/PO_ADMIN';
const platform = new FakePlatformWorld(seededRandom(8));

const adminRow: KeyRow = {
  keyref: KEYREF,
  platform: 'pasteonly',
  name: 'PO_ADMIN',
  projects: ['shop'],
  class: 'admin',
  status: 'works',
  gen_current: 1,
  schedule: { rotate_every_days: 90, grace_hours: 24, next_due_at: null, expires_at: null },
  coverage: null,
  last_use_at: null,
};

async function started(t: TestContext, registry: readonly PlatformEntry[], seed = false) {
  const dir = await tempDir(t);
  const stateDir = join(dir, 'state');
  mkdirSync(join(dir, 'results'));
  const clock = new TimedClock(1_700_000_000_000);
  const random = seededRandom(9);
  const token = newToken(random);
  const prepared = openCore({ stateDir, clock, scheduler: clock, random });
  prepared.meta.addMachine({ label: 'mc', scope: 'control', tokenSha256: hashToken(token), enrolledAt: clock.now() });
  if (seed) {
    prepared.vault.put(KEYREF, 1, Buffer.from(VALUE));
    prepared.meta.putKey(adminRow);
  }
  prepared.close();
  const socket = join(dir, 'http.sock');
  const env = { KB_STATE_DIR: stateDir, KB_SOCKET: socket, KB_INSTALL_RESULTS: join(dir, 'results'), KB_CURRENT: join(dir, 'current'), KB_DOMAIN: 'box.example' };
  const core = await startCore(env, { clock, scheduler: clock, random, journal: () => undefined, registry });
  t.after(() => core.stop());
  const driver = drive(socket);
  const call = (path: string, body?: unknown) =>
    driver.request({
      path,
      method: body === undefined ? 'GET' : 'POST',
      headers: { 'x-kb-client-ip': '203.0.113.9', authorization: `Bearer ${token}`, ...(body === undefined ? {} : { 'content-type': 'application/json' }) },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
  return { core, call };
}

test('KBOX-23 a registry that fails its checks stops the start, loudly, naming the platform', async (t) => {
  const dir = await tempDir(t);
  const clock = new TimedClock(1_700_000_000_000);
  const env = { KB_STATE_DIR: join(dir, 'state'), KB_SOCKET: join(dir, 'http.sock'), KB_INSTALL_RESULTS: dir, KB_CURRENT: join(dir, 'current') };
  await assert.rejects(
    startCore(env, { clock, scheduler: clock, random: seededRandom(1), journal: () => undefined, registry: [fakeEntry(platform), fakeEntry(platform)] }),
    (e: unknown) => e instanceof RegistryRefused && e.code === 'duplicate_platform' && e.platform === 'fake',
  );
});

test('KBOX-40 KBOX-33 the shape a paste-only entry states reaches the share file: its admin key is watched; with no entry it is not', async (t) => {
  const tiers = async (registry: readonly PlatformEntry[]): Promise<string[]> => {
    const w = await started(t, registry, true);
    const reply = await w.call('/api/share');
    assert.equal(reply.status, 200, reply.body);
    const envelope = JSON.parse(reply.body) as { body_b64: string };
    const body = JSON.parse(Buffer.from(envelope.body_b64, 'base64').toString('utf8')) as { coverage: { name: string; tier: string }[] };
    return body.coverage.filter((c) => c.name === 'PO_ADMIN').map((c) => c.tier);
  };
  assert.deepEqual(await tiers([]), ['none']);
  const watched = await tiers([pasteOnlyEntry(platform, SHAPE)]);
  assert.equal(watched.length, 1);
  assert.notEqual(watched[0], 'none');
});

const addKey = (platformId: string): Action => ({ kind: 'add_key', platform: platformId, name: 'A_KEY', projects: ['shop'], scope: { items: ['admin'] } });

test('KBOX-23 the proposal check lets add_key through for a registered platform (with an issuer or paste-only) and refuses an unknown one', () => {
  const vet = vetAction([fakeEntry(platform), pasteOnlyEntry(platform, SHAPE)]);
  assert.equal(vet(addKey('fake')), 'ok');
  assert.equal(vet(addKey('pasteonly')), 'ok');
  assert.equal(vet(addKey('nobody')), 'rejected');
  assert.equal(vetAction([])(addKey('fake')), 'rejected');
});

test('KBOX-23 the kinds whose executors do not exist yet stay refused, whatever is registered; the rest are not the check\'s business', () => {
  const vet = vetAction([fakeEntry(platform)]);
  const refused: Action[] = [
    { kind: 'add_destination', keyref: 'k/k/K', destination: { kind: 'vercel_env', target: 'prj' } },
    { kind: 'set_allow_rules', keyref: 'k/k/K', rules: [] } as unknown as Action,
    { kind: 'vercel_set_domain' } as unknown as Action,
    { kind: 'vercel_set_team_setting' } as unknown as Action,
  ];
  for (const action of refused) assert.equal(vet(action), 'rejected', action.kind);
  assert.equal(vet({ kind: 'rotate_key', keyref: 'k/k/K' }), 'ok');
});

test('KBOX-34 over the real route, add_key of an admin key on a registered platform opens an approval', async (t) => {
  const entry = fakeEntry(platform, { issuer: issuerWith(platform.issuer, { classify: () => 'admin' }) });
  const w = await started(t, [entry]);
  const body = { platform: 'fake', name: 'FAKE_ADMIN', projects: ['shop'], scope: { items: ['admin'] }, destinations: [] };
  const opened = await w.call('/api/keys', body);
  assert.equal(opened.status, 202, opened.body);
  assert.match(opened.body, /approval_id/);
  const unknown = await w.call('/api/keys', { ...body, platform: 'nobody' });
  assert.ok(unknown.status >= 400 && unknown.status < 500, unknown.body);
});
